// SPDX-License-Identifier: GPL-3.0-only
//! Where the host-side analysis of a library sample lives and how its bytes
//! reach the analysis job (`Command::AnalyzeSample`).
use std::{
    fs::File,
    io::{Seek, Write},
    path::{Path, PathBuf},
};

/// The folder of one analysis of a library sample: `<data>/analyses/<id>`.
/// It belongs to no VM and no recording, so it outlives both and a job runner
/// can address it by the report id. The layers unpacking finds are siblings.
pub fn sample_analysis_directory(data_dir: &Path, report_id: &str) -> PathBuf {
    data_dir.join("analyses").join(report_id)
}

/// `bytes` in an anonymous in-memory file, read from the start: the
/// decrypted sample reaches the job without a plain copy in a path of its own.
pub fn anonymous_copy(bytes: &[u8]) -> Result<File, String> {
    let fd = rustix::fs::memfd_create("sample", rustix::fs::MemfdFlags::CLOEXEC)
        .map_err(|error| format!("anonymous sample copy: {error}"))?;
    let mut file = File::from(fd);
    file.write_all(bytes)
        .and_then(|()| file.rewind())
        .map_err(|error| format!("anonymous sample copy: {error}"))?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn the_copy_reads_back_from_the_start_and_the_folder_is_under_the_data_directory() {
        let mut file = anonymous_copy(b"MZ sample bytes").unwrap();
        let mut back = Vec::new();
        file.read_to_end(&mut back).unwrap();
        assert_eq!(back, b"MZ sample bytes");
        assert_eq!(
            sample_analysis_directory(Path::new("/d"), "abc"),
            Path::new("/d/analyses/abc")
        );
    }
}
