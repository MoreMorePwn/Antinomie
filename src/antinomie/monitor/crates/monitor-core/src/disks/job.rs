// SPDX-License-Identifier: MIT
//! The disk job: measuring a VM's disk chain, or flattening it into a scratch
//! image with `qemu-img convert` and opening it as the current-disk view.
//!
//! The backend worker owns at most one [`Job`] (the lease on the VM's image:
//! see `backend::worker_disks`). The job runs on its own thread; the worker
//! polls [`Job::progress`] and [`Job::finish`] from its loop and can
//! [`Job::cancel`] it, which kills the converter and removes the scratch
//! folder.
use super::{
    CurrentDiskView, DiskJobProgress, DiskJobPurpose, DiskJobStage, DiskMeasure, DiskSourceRecord,
    EXTRACTED_DIR, IMAGE_FILE, measure, read_state, scratch_dir, sweep_scratch, unix_ms,
};
use std::{
    fs::{self, File},
    io::Read,
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

/// Name of the image while `qemu-img` writes it.
const PART_FILE: &str = "root.ext4.part";

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
}

/// What a finished job produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobResult {
    Measured(DiskMeasure),
    Opened(CurrentDiskView),
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
        Self::spawn(spec, DiskJobPurpose::Measure)
    }

    /// Flatten the chain into a scratch image and open it.
    pub fn view(spec: JobSpec) -> Result<Self, String> {
        Self::spawn(spec, DiskJobPurpose::View)
    }

    fn spawn(spec: JobSpec, purpose: DiskJobPurpose) -> Result<Self, String> {
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
                let result = match purpose {
                    DiskJobPurpose::Measure => run.measure(&spec).map(JobResult::Measured),
                    DiskJobPurpose::View => run.view(&spec).map(JobResult::Opened),
                };
                let _ = sender.send(result);
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
        let measured = measure::measure(
            &spec.qemu_img,
            &spec.vm_id,
            &spec.vm_dir,
            &spec.top,
            spec.source.clone(),
            &spec.disks_dir,
        );
        self.estimate
            .store(measured.allocated_estimate, Ordering::Relaxed);
        if self.cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        Ok(measured)
    }

    fn view(&self, spec: &JobSpec) -> Result<CurrentDiskView, String> {
        let measured = self.measure(spec)?;
        if let Some(error) = measured.error {
            return Err(error);
        }
        let view_id = crate::storage::unique_id();
        // Leftovers of an earlier crash are swept before a new scratch image.
        sweep_scratch(&spec.disks_dir, None);
        let scratch = scratch_dir(&spec.disks_dir, &view_id);
        crate::storage::private_dir(&scratch)
            .map_err(|error| format!("{}: {error}", scratch.display()))?;
        let result = self.convert(spec, &measured, &scratch, view_id);
        if result.is_err() {
            let _ = fs::remove_dir_all(&scratch);
        }
        result
    }

    fn convert(
        &self,
        spec: &JobSpec,
        measured: &DiskMeasure,
        scratch: &Path,
        view_id: String,
    ) -> Result<CurrentDiskView, String> {
        self.set_stage(DiskJobStage::Converting { percent: 0.0 });
        let part = scratch.join(PART_FILE);
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
        let file = File::open(&part).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if metadata.len() != measured.logical_size {
            return Err(format!(
                "the flattened image is {} bytes; the disk is {} bytes",
                metadata.len(),
                measured.logical_size
            ));
        }
        let fs_state = read_state(&part)?;
        let image = scratch.join(IMAGE_FILE);
        fs::rename(&part, &image).map_err(|error| error.to_string())?;
        File::open(scratch)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())?;
        let disks_dir = scratch.parent().unwrap_or(&spec.disks_dir);
        Ok(CurrentDiskView {
            vm_id: spec.vm_id.clone(),
            extract_dir: disks_dir.join(EXTRACTED_DIR).join(&view_id),
            view_id,
            image,
            taken_ms: unix_ms(),
            source: measured.source.clone(),
            fs_state,
            logical_size: measured.logical_size,
            allocated_size: metadata.blocks().saturating_mul(512),
        })
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
