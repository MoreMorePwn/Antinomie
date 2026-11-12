// SPDX-License-Identifier: GPL-3.0-only
//! The library samples a run loaded into its program, copied out of the sample
//! library for the sandboxed YARA scan, which cannot read the library itself;
//! and, for a run with no guest static analysis, the run's own sample.
use super::*;

/// A library the run loaded, with the staged copy of its bytes when the
/// sample library could give them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(in crate::analysis::detection) struct StagedLibrary {
    pub reference: crate::samples::PreloadRef,
    pub file: Option<PathBuf>,
    /// Why there is no `file`.
    pub reason: String,
}

/// The library sample a run executed, staged for a run that has no guest
/// static analysis (an Auto-mode job launches without one): its specimen is
/// not in the run's `analysis/` folder, so YARA reads the sample's bytes from
/// the library instead.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(in crate::analysis::detection) struct StagedSample {
    pub sample: crate::samples::SampleRef,
    /// The program's path in the guest, shown as the input's path.
    pub path: String,
    pub file: Option<PathBuf>,
    /// Why there is no `file`.
    pub reason: String,
}

/// What staging reads of the run's `run.json`.
#[derive(Deserialize, Default)]
#[serde(default)]
struct Launch {
    request: Inner,
    analysis: Option<serde_json::Value>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Inner {
    path: String,
    sample: Option<crate::samples::SampleRef>,
    preloaded: Vec<crate::samples::PreloadRef>,
}

fn launch(request: &Request) -> Option<Launch> {
    let directory = &request.directory;
    let file = crate::archive_io::open_regular(directory, &directory.join("run.json")).ok()?;
    let mut text = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(file, 16 << 20), &mut text).ok()?;
    serde_json::from_slice::<Launch>(&text).ok()
}

/// Copy the library sample `sha256` (checked against the hash) to `target`.
fn copy_out(data_dir: &Path, sha256: &str, target: PathBuf) -> Result<PathBuf, String> {
    if data_dir.as_os_str().is_empty() {
        return Err("the scan has no sample library to read it from".into());
    }
    match crate::samples::archive_path(data_dir, sha256)
        .and_then(|archive| crate::samples::open_sample(&archive, sha256))
    {
        Err(error) => Err(format!("the library sample cannot be read ({error})")),
        Ok(data) if data.len() as u64 > 64 * 1024 * 1024 => {
            Err("over the 64 MiB file budget".into())
        }
        Ok(data) => match fs::write(&target, &data) {
            Ok(()) => Ok(target),
            Err(error) => Err(format!("cannot be staged ({error})")),
        },
    }
}

/// Libraries a run's launch recorded: those with a hash are read from the
/// sample library (checked against the hash) into `work`; a library named
/// without a hash, or one that cannot be read, is staged without a file and
/// with the reason.
pub(in crate::analysis::detection) fn stage_libraries(
    request: &Request,
    work: &Path,
) -> Vec<StagedLibrary> {
    let Some(launch) = launch(request) else {
        return vec![];
    };
    let data_dir = host_path(&request.settings.rules_root);
    let mut staged = Vec::new();
    for (index, reference) in launch.request.preloaded.into_iter().enumerate() {
        let mut library = StagedLibrary {
            reference,
            file: None,
            reason: String::new(),
        };
        if library.reference.sha256.is_empty() {
            library.reason = format!(
                "{}={} is not a library sample: {}",
                library.reference.via, library.reference.path, library.reference.note
            );
        } else {
            let sha256 = library.reference.sha256.clone();
            match copy_out(
                &data_dir,
                &sha256,
                work.join(format!("library-{index}.bin")),
            ) {
                Ok(file) => library.file = Some(file),
                Err(reason) => library.reason = reason,
            }
        }
        staged.push(library);
    }
    staged
}

/// The run's own library sample, for a run whose launch selected no guest
/// static analysis (its `run.json` has no analysis record) and that names the
/// library sample it executed. `None` for every other run: a run with a guest
/// analysis is scanned from the specimen that analysis kept, as before.
pub(in crate::analysis::detection) fn stage_sample(
    request: &Request,
    work: &Path,
) -> Option<StagedSample> {
    let launch = launch(request)?;
    if launch.analysis.is_some() {
        return None;
    }
    let sample = launch.request.sample.filter(|s| !s.sha256.is_empty())?;
    let data_dir = host_path(&request.settings.rules_root);
    let (file, reason) = match copy_out(&data_dir, &sample.sha256, work.join("sample.bin")) {
        Ok(file) => (Some(file), String::new()),
        Err(reason) => (None, reason),
    };
    Some(StagedSample {
        sample,
        path: launch.request.path,
        file,
        reason,
    })
}
