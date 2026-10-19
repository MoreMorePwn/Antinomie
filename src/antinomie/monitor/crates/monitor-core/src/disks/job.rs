// SPDX-License-Identifier: MIT
//! The disk job: measuring a VM's disk chain, flattening it into a scratch
//! image with `qemu-img convert` and opening it as the current-disk view, or
//! saving it as a dump (straight from the chain, or by promoting the open
//! view).
//!
//! The backend worker owns at most one [`Job`] (the lease on the VM's image:
//! see `backend::worker_disks`). The job runs on its own thread; the worker
//! polls [`Job::progress`] and [`Job::finish`] from its loop and can
//! [`Job::cancel`] it, which kills the converter and removes the scratch
//! folder.
use super::{
    CurrentDiskView, DiskJobProgress, DiskJobPurpose, DiskJobStage, DiskMeasure, DiskSourceRecord,
    EXTRACTED_DIR, Ext4State, IMAGE_FILE, SCRATCH_PREFIX,
    dump::{DiskDump, DiskImageFormat, PART_FILE, sha256_file, sweep_partial},
    measure, quota_error, read_state, scratch_dir, sweep_scratch, unix_ms,
};
use std::{
    fs::{self, File},
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Child, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

/// Everything a job needs, resolved by the backend worker while it still
/// owns the VM's state.
#[derive(Clone, Debug)]
pub struct JobSpec {
    pub qemu_img: PathBuf,
    pub vm_id: String,
    pub vm_dir: PathBuf,
    /// The writable top of the VM's chain (`snapshots::active_disk`).
    pub top: PathBuf,
    pub source: DiskSourceRecord,
    /// `<recording dir>/disks`.
    pub disks_dir: PathBuf,
    /// The recording quota figure: the per-dump ceiling (0 for none).
    pub quota: u64,
}

/// What a dump records beyond the chain, and what it computes.
#[derive(Clone, Debug, Default)]
pub struct DumpPlan {
    pub vm_name: String,
    /// "Linux 6.12.94 · Debian trixie", as the bundle names it.
    pub system: String,
    /// SHA-256 of the image (the Settings default: on).
    pub hash: bool,
    /// SHA-256 of each layer of the source chain (the Settings default: off).
    pub layer_digests: bool,
}

/// What a finished job produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobResult {
    Measured(DiskMeasure),
    Opened(CurrentDiskView),
    Dumped(Box<DiskDump>),
    /// A view promoted to a dump; the view now reads the dump's image.
    Kept(Box<DiskDump>, Box<CurrentDiskView>),
}

/// One running job and its lease on the VM's image.
pub struct Job {
    pub vm_id: String,
    pub purpose: DiskJobPurpose,
    started_ms: u64,
    estimate: Arc<AtomicU64>,
    stage: Arc<Mutex<DiskJobStage>>,
    cancel: Arc<AtomicBool>,
    done: Receiver<Result<JobResult, String>>,
    thread: Option<JoinHandle<()>>,
}

impl Job {
    /// Measure the chain: the allocation estimate, free space, sparse support.
    pub fn measure(spec: JobSpec) -> Result<Self, String> {
        Self::spawn(spec, DiskJobPurpose::Measure, |run, spec| {
            run.measure(spec).map(JobResult::Measured)
        })
    }

    /// Flatten the chain into a scratch image and open it.
    pub fn view(spec: JobSpec) -> Result<Self, String> {
        Self::spawn(spec, DiskJobPurpose::View, |run, spec| {
            run.view(spec).map(JobResult::Opened)
        })
    }

    /// Flatten the chain into a new dump of the recordings.
    pub fn dump(spec: JobSpec, plan: DumpPlan) -> Result<Self, String> {
        Self::spawn(spec, DiskJobPurpose::Dump, move |run, spec| {
            run.dump(spec, &plan)
                .map(|dump| JobResult::Dumped(Box::new(dump)))
        })
    }

    /// Promote the open view to a dump: no second conversion.
    pub fn keep(spec: JobSpec, plan: DumpPlan, view: CurrentDiskView) -> Result<Self, String> {
        Self::spawn(spec, DiskJobPurpose::Keep, move |run, spec| {
            run.keep(spec, &plan, &view)
                .map(|(dump, view)| JobResult::Kept(Box::new(dump), Box::new(view)))
        })
    }

    fn spawn(
        spec: JobSpec,
        purpose: DiskJobPurpose,
        work: impl FnOnce(&Run, &JobSpec) -> Result<JobResult, String> + Send + 'static,
    ) -> Result<Self, String> {
        let estimate = Arc::new(AtomicU64::new(0));
        let stage = Arc::new(Mutex::new(DiskJobStage::Measuring));
        let cancel = Arc::new(AtomicBool::new(false));
        let (sender, done) = mpsc::channel();
        let run = Run {
            estimate: estimate.clone(),
            stage: stage.clone(),
            cancel: cancel.clone(),
        };
        let vm_id = spec.vm_id.clone();
        let thread = thread::Builder::new()
            .name("antinomie-disk-job".into())
            .spawn(move || {
                let _ = sender.send(work(&run, &spec));
            })
            .map_err(|error| format!("disk job: {error}"))?;
        Ok(Self {
            vm_id,
            purpose,
            started_ms: unix_ms(),
            estimate,
            stage,
            cancel,
            done,
            thread: Some(thread),
        })
    }

    pub fn progress(&self) -> DiskJobProgress {
        DiskJobProgress {
            vm_id: self.vm_id.clone(),
            purpose: self.purpose,
            stage: self
                .stage
                .lock()
                .map_or(DiskJobStage::Measuring, |stage| stage.clone()),
            estimate: self.estimate.load(Ordering::Relaxed),
            started_ms: self.started_ms,
        }
    }

    /// Ask the job to stop: the converter is killed and the scratch folder
    /// removed; [`Self::finish`] then reports "cancelled".
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// The result, once the job ended.
    pub fn finish(&mut self) -> Option<Result<JobResult, String>> {
        let result = match self.done.try_recv() {
            Ok(result) => result,
            Err(mpsc::TryRecvError::Empty) => return None,
            Err(mpsc::TryRecvError::Disconnected) => {
                Err("the disk job stopped unexpectedly".into())
            }
        };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        Some(result)
    }
}

impl Drop for Job {
    /// The lease never outlives its owner: stop the converter and wait for it.
    fn drop(&mut self) {
        self.cancel();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A flattened image in its final place.
struct Flattened {
    image: PathBuf,
    fs_state: Ext4State,
    allocated: u64,
}

/// Move a scratch folder to its dump name. A rename is tried first; when it
/// fails because the two names are on different filesystems, `copy` fills the
/// new folder instead and the scratch folder stays. Returns whether the
/// folder was renamed.
pub(crate) fn promote(
    from: &Path,
    to: &Path,
    rename: impl FnOnce(&Path, &Path) -> io::Result<()>,
    copy: impl FnOnce(&Path) -> Result<(), String>,
) -> Result<bool, String> {
    match rename(from, to) {
        Ok(()) => {
            File::open(to.parent().unwrap_or(to))
                .and_then(|directory| directory.sync_all())
                .map_err(|error| error.to_string())?;
            Ok(true)
        }
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::XDEV.raw_os_error()) => {
            crate::storage::private_dir(to)
                .map_err(|error| format!("{}: {error}", to.display()))?;
            if let Err(error) = copy(to) {
                let _ = fs::remove_dir_all(to);
                return Err(error);
            }
            Ok(false)
        }
        Err(error) => Err(format!("{}: {error}", to.display())),
    }
}

struct Run {
    estimate: Arc<AtomicU64>,
    stage: Arc<Mutex<DiskJobStage>>,
    cancel: Arc<AtomicBool>,
}

impl Run {
    fn set_stage(&self, stage: DiskJobStage) {
        if let Ok(mut current) = self.stage.lock() {
            *current = stage;
        }
    }

    fn measure(&self, spec: &JobSpec) -> Result<DiskMeasure, String> {
        let mut measured = measure::measure(
            &spec.qemu_img,
            &spec.vm_id,
            &spec.vm_dir,
            &spec.top,
            spec.source.clone(),
            &spec.disks_dir,
        );
        measured.quota = spec.quota;
        self.estimate
            .store(measured.allocated_estimate, Ordering::Relaxed);
        if self.cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        Ok(measured)
    }

    fn cancelled(&self) -> Result<(), String> {
        if self.cancel.load(Ordering::Relaxed) {
            Err("cancelled".into())
        } else {
            Ok(())
        }
    }

    fn view(&self, spec: &JobSpec) -> Result<CurrentDiskView, String> {
        let measured = self.measure(spec)?;
        if let Some(error) = measured.error {
            return Err(error);
        }
        let view_id = crate::storage::unique_id();
        // Leftovers of an earlier crash are swept before a new scratch image.
        sweep_scratch(&spec.disks_dir, None);
        sweep_partial(&spec.disks_dir);
        let scratch = scratch_dir(&spec.disks_dir, &view_id);
        crate::storage::private_dir(&scratch)
            .map_err(|error| format!("{}: {error}", scratch.display()))?;
        let result = self
            .flatten(spec, &measured, &scratch)
            .map(|flat| CurrentDiskView {
                vm_id: spec.vm_id.clone(),
                extract_dir: spec.disks_dir.join(EXTRACTED_DIR).join(&view_id),
                view_id,
                image: flat.image,
                taken_ms: unix_ms(),
                source: measured.source.clone(),
                fs_state: flat.fs_state,
                logical_size: measured.logical_size,
                allocated_size: flat.allocated,
                kept_as: None,
            });
        if result.is_err() {
            let _ = fs::remove_dir_all(&scratch);
        }
        result
    }

    /// Convert the chain into `folder/root.ext4`: written as `.part`, synced,
    /// checked (size, ext4 magic and state) and only then renamed.
    fn flatten(
        &self,
        spec: &JobSpec,
        measured: &DiskMeasure,
        folder: &Path,
    ) -> Result<Flattened, String> {
        self.set_stage(DiskJobStage::Converting { percent: 0.0 });
        let part = folder.join(PART_FILE);
        let mut command = measure::qemu_img_command(&spec.qemu_img);
        // No `-U`: QEMU's own image lock stays the backstop against a VM that
        // somehow has the chain open.
        command
            .args(["convert", "-p", "-f", "qcow2", "-O", "raw"])
            .arg(&spec.top)
            .arg(&part)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| format!("qemu-img convert: {error}"))?;
        let outcome = self.wait(&mut child);
        outcome?;
        self.set_stage(DiskJobStage::Finalizing);
        self.finish_image(&part, measured.logical_size, folder)
    }

    /// Sync and check a finished `.part` image, then rename it into place.
    fn finish_image(
        &self,
        part: &Path,
        logical_size: u64,
        folder: &Path,
    ) -> Result<Flattened, String> {
        let file = File::open(part).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if metadata.len() != logical_size {
            return Err(format!(
                "the flattened image is {} bytes; the disk is {} bytes",
                metadata.len(),
                logical_size
            ));
        }
        let fs_state = read_state(part)?;
        let image = folder.join(IMAGE_FILE);
        fs::rename(part, &image).map_err(|error| error.to_string())?;
        File::open(folder)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())?;
        Ok(Flattened {
            image,
            fs_state,
            allocated: metadata.blocks().saturating_mul(512),
        })
    }

    /// SHA-256 of an image, shown as the Hashing stage.
    fn hash(&self, image: &Path) -> Result<String, String> {
        self.set_stage(DiskJobStage::Hashing { done: 0, total: 0 });
        sha256_file(image, &self.cancel, |done, total| {
            self.set_stage(DiskJobStage::Hashing { done, total });
        })
    }

    /// SHA-256 of every layer file of the chain the image was read from. A
    /// layer that changed since it was measured is an error: the digest would
    /// not describe what was read.
    fn digest_layers(&self, vm_dir: &Path, source: &mut DiskSourceRecord) -> Result<(), String> {
        for layer in &mut source.layers {
            let path = vm_dir.join(&layer.filename);
            let length = fs::metadata(&path)
                .map_err(|error| format!("{}: {error}", path.display()))?
                .len();
            if length != layer.size {
                return Err(format!("{} changed while it was read", path.display()));
            }
            layer.sha256 = Some(self.hash(&path)?);
        }
        Ok(())
    }

    /// Flatten the chain into `disks/<id>/root.ext4` and record it.
    fn dump(&self, spec: &JobSpec, plan: &DumpPlan) -> Result<DiskDump, String> {
        let started_ms = unix_ms();
        let measured = self.measure(spec)?;
        if let Some(error) = measured.error.clone().or_else(|| measured.quota_error()) {
            return Err(error);
        }
        sweep_partial(&spec.disks_dir);
        let id = crate::storage::unique_id();
        let folder = spec.disks_dir.join(&id);
        crate::storage::private_dir(&folder)
            .map_err(|error| format!("{}: {error}", folder.display()))?;
        let result = (|| {
            let flat = self.flatten(spec, &measured, &folder)?;
            let sha256 = plan.hash.then(|| self.hash(&flat.image)).transpose()?;
            let mut source = measured.source.clone();
            if plan.layer_digests {
                self.digest_layers(&spec.vm_dir, &mut source)?;
            }
            self.set_stage(DiskJobStage::Finalizing);
            self.cancelled()?;
            let dump = DiskDump {
                id: id.clone(),
                vm_id: spec.vm_id.clone(),
                vm_name: plan.vm_name.clone(),
                imported: false,
                file: IMAGE_FILE.into(),
                format: DiskImageFormat::RawExt4,
                fs_state: flat.fs_state,
                started_ms,
                finished_ms: Some(unix_ms()),
                logical_size: measured.logical_size,
                allocated_size: Some(flat.allocated),
                sha256,
                source,
                system: plan.system.clone(),
                error: None,
                dir: folder.clone(),
            };
            dump.save()?;
            Ok(dump)
        })();
        if result.is_err() {
            // A cancelled or failed dump leaves no folder and no record.
            let _ = fs::remove_dir_all(&folder);
        }
        result
    }

    /// Promote the open view's scratch folder to `disks/<id>/` by rename,
    /// hash it, and write the sidecar. The view keeps reading the same
    /// bytes, now at the dump's path.
    fn keep(
        &self,
        spec: &JobSpec,
        plan: &DumpPlan,
        view: &CurrentDiskView,
    ) -> Result<(DiskDump, CurrentDiskView), String> {
        let started_ms = unix_ms();
        if view.kept_as.is_some() {
            return Err("this view was already kept as a dump".into());
        }
        if let Some(error) = quota_error(view.allocated_size, spec.quota) {
            return Err(error);
        }
        let folder = view
            .image
            .parent()
            .filter(|folder| {
                folder.parent() == Some(spec.disks_dir.as_path())
                    && folder
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(SCRATCH_PREFIX))
            })
            .ok_or("the open view is not a scratch image of this VM's recordings")?
            .to_path_buf();
        let fs_state = read_state(&view.image)?;
        let length = fs::metadata(&view.image)
            .map_err(|error| format!("{}: {error}", view.image.display()))?
            .len();
        // Hashed in place, before the rename: the open view's reader keeps its
        // path until the image is final.
        let sha256 = plan.hash.then(|| self.hash(&view.image)).transpose()?;
        let mut source = view.source.clone();
        if plan.layer_digests {
            self.digest_layers(&spec.vm_dir, &mut source)?;
        }
        self.set_stage(DiskJobStage::Finalizing);
        self.cancelled()?;
        sweep_partial(&spec.disks_dir);
        let id = crate::storage::unique_id();
        let folder_after = spec.disks_dir.join(&id);
        let renamed = promote(
            &folder,
            &folder_after,
            |from, to| fs::rename(from, to),
            |to| {
                // Only when the rename crosses a filesystem: a sparse copy of
                // the scratch image (never of the chain).
                self.copy_raw(spec, &view.image, to, length)
            },
        )?;
        let image = folder_after.join(IMAGE_FILE);
        let allocated = fs::metadata(&image)
            .map(|metadata| metadata.blocks().saturating_mul(512))
            .map_err(|error| error.to_string())?;
        let dump = DiskDump {
            id: id.clone(),
            vm_id: spec.vm_id.clone(),
            vm_name: plan.vm_name.clone(),
            imported: false,
            file: IMAGE_FILE.into(),
            format: DiskImageFormat::RawExt4,
            fs_state,
            started_ms,
            finished_ms: Some(unix_ms()),
            logical_size: length,
            allocated_size: Some(allocated),
            sha256,
            source,
            system: plan.system.clone(),
            error: None,
            dir: folder_after.clone(),
        };
        if let Err(error) = dump.save() {
            // Put the view's folder back, or remove the copy.
            if renamed {
                let _ = fs::rename(&folder_after, &folder);
            } else {
                let _ = fs::remove_dir_all(&folder_after);
            }
            return Err(error);
        }
        let mut kept = view.clone();
        kept.kept_as = Some(id);
        if renamed {
            kept.image = image;
        }
        Ok((dump, kept))
    }

    /// `qemu-img convert -f raw -O raw`: a sparse copy of a raw image into
    /// `folder/root.ext4`.
    fn copy_raw(
        &self,
        spec: &JobSpec,
        image: &Path,
        folder: &Path,
        logical_size: u64,
    ) -> Result<(), String> {
        self.set_stage(DiskJobStage::Converting { percent: 0.0 });
        let part = folder.join(PART_FILE);
        let mut command = measure::qemu_img_command(&spec.qemu_img);
        command
            .args(["convert", "-p", "-f", "raw", "-O", "raw"])
            .arg(image)
            .arg(&part)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| format!("qemu-img convert: {error}"))?;
        self.wait(&mut child)?;
        self.finish_image(&part, logical_size, folder).map(|_| ())
    }

    /// Wait for the converter, feeding its progress to the stage and
    /// honouring cancel.
    fn wait(&self, child: &mut Child) -> Result<(), String> {
        let stdout = child.stdout.take().ok_or("qemu-img stdout unavailable")?;
        let stage = self.stage.clone();
        let progress = thread::spawn(move || read_progress(stdout, &stage));
        let mut stderr = child.stderr.take().ok_or("qemu-img stderr unavailable")?;
        let errors = thread::spawn(move || {
            let mut text = Vec::new();
            let _ = (&mut stderr).take(64 * 1024).read_to_end(&mut text);
            let _ = std::io::copy(&mut stderr, &mut std::io::sink());
            String::from_utf8_lossy(&text).into_owned()
        });
        let status = loop {
            if self.cancel.load(Ordering::Relaxed) {
                let _ = child.kill();
                let _ = child.wait();
                let _ = progress.join();
                let _ = errors.join();
                return Err("cancelled".into());
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => thread::sleep(Duration::from_millis(25)),
                Err(error) => return Err(error.to_string()),
            }
        };
        let _ = progress.join();
        let errors = errors.join().unwrap_or_default();
        if status.success() {
            Ok(())
        } else {
            Err(measure::qemu_failure(&errors))
        }
    }
}

/// Read `qemu-img -p` output into the stage. The tool rewrites one line with
/// carriage returns: `    (12.34/100%)`.
fn read_progress(mut stdout: impl Read, stage: &Mutex<DiskJobStage>) {
    let mut buffer = [0u8; 256];
    let mut line = Vec::new();
    while let Ok(count) = stdout.read(&mut buffer) {
        if count == 0 {
            break;
        }
        for &byte in &buffer[..count] {
            if byte == b'\r' || byte == b'\n' {
                if let Some(percent) = parse_progress(&String::from_utf8_lossy(&line))
                    && let Ok(mut stage) = stage.lock()
                    && matches!(*stage, DiskJobStage::Converting { .. })
                {
                    *stage = DiskJobStage::Converting { percent };
                }
                line.clear();
            } else if line.len() < 128 {
                line.push(byte);
            }
        }
    }
}

/// The percentage of a `    (12.34/100%)` progress line.
pub fn parse_progress(line: &str) -> Option<f32> {
    let inner = line.trim().strip_prefix('(')?.strip_suffix(')')?;
    let (done, total) = inner.split_once('/')?;
    let total = total.strip_suffix('%')?.trim().parse::<f32>().ok()?;
    let done = done.trim().parse::<f32>().ok()?;
    (total > 0.0 && done.is_finite()).then(|| (done / total * 100.0).clamp(0.0, 100.0))
}

#[cfg(test)]
mod tests;
