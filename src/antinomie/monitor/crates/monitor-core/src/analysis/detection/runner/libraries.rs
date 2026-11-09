// SPDX-License-Identifier: GPL-3.0-only
//! The library samples a run loaded into its program, copied out of the sample
//! library for the sandboxed YARA scan, which cannot read the library itself.
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

/// Libraries a run's launch recorded: those with a hash are read from the
/// sample library (checked against the hash) into `work`; a library named
/// without a hash, or one that cannot be read, is staged without a file and
/// with the reason.
pub(in crate::analysis::detection) fn stage_libraries(
    request: &Request,
    work: &Path,
) -> Vec<StagedLibrary> {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Launch {
        request: Inner,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Inner {
        preloaded: Vec<crate::samples::PreloadRef>,
    }
    let directory = &request.directory;
    let Ok(file) = crate::archive_io::open_regular(directory, &directory.join("run.json")) else {
        return vec![];
    };
    let mut text = Vec::new();
    if std::io::Read::read_to_end(&mut std::io::Read::take(file, 16 << 20), &mut text).is_err() {
        return vec![];
    }
    let Ok(launch) = serde_json::from_slice::<Launch>(&text) else {
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
        } else if data_dir.as_os_str().is_empty() {
            library.reason = "the scan has no sample library to read it from".into();
        } else {
            let sha256 = library.reference.sha256.clone();
            match crate::samples::archive_path(&data_dir, &sha256)
                .and_then(|archive| crate::samples::open_sample(&archive, &sha256))
            {
                Err(error) => {
                    library.reason = format!("the library sample cannot be read ({error})")
                }
                Ok(data) if data.len() as u64 > 64 * 1024 * 1024 => {
                    library.reason = "over the 64 MiB file budget".into()
                }
                Ok(data) => {
                    let target = work.join(format!("library-{index}.bin"));
                    match fs::write(&target, &data) {
                        Ok(()) => library.file = Some(target),
                        Err(error) => library.reason = format!("cannot be staged ({error})"),
                    }
                }
            }
        }
        staged.push(library);
    }
    staged
}
