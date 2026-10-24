// SPDX-License-Identifier: GPL-3.0-only
use super::{ANALYSIS_PREVIEW_MAX_SIZE, AnalysisReport, AnalysisSpecimenPage, AnalysisState};
use rustix::fs::{Mode, OFlags, openat};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, Metadata},
    io::{Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::Path,
};

/// Read exactly one bounded range from a retained, digest-verified specimen.
///
/// | Argument | Meaning |
/// |---|---|
/// | `directory` | Host-retained analysis directory; opens stay anchored to its descriptor. |
/// | `report_id` | Expected saved report identity. |
/// | `offset` | Absolute specimen file offset in octets. |
/// | `data_len` | Requested length, 1..=4096 octets. |
///
/// Returns an owned page, or an error for incomplete evidence, confinement,
/// range, digest, mutation or I/O failure. Call on a background archive reader.
pub fn read_specimen_range(
    directory: &Path,
    report_id: &str,
    offset: u64,
    data_len: usize,
) -> Result<AnalysisSpecimenPage, String> {
    if !(1..=ANALYSIS_PREVIEW_MAX_SIZE).contains(&data_len) {
        return Err("specimen preview length must be 1..4096 bytes".into());
    }
    read_verified_range(directory, report_id, offset, data_len)
}

/// Read a complete retained specimen for an isolated, bounded analysis worker.
pub(super) fn read_all(
    directory: &Path,
    report_id: &str,
) -> Result<(AnalysisReport, Vec<u8>), String> {
    let before = super::jobs::open_report(directory)?;
    if before.id != report_id {
        return Err("saved analysis report identity mismatch".into());
    }
    let len = before
        .specimen_len
        .ok_or("complete specimen length unavailable")?;
    if len > u64::from(crate::control::SPECIMEN_MAX_SIZE) {
        return Err("saved specimen exceeds 64 MiB bound".into());
    }
    let page = read_verified_range(directory, report_id, 0, len as usize)?;
    let after = super::jobs::open_report(directory)?;
    if before.id != after.id
        || before.specimen_sha256 != after.specimen_sha256
        || before.specimen_len != after.specimen_len
        || before.source_path != after.source_path
    {
        return Err("saved specimen identity changed during analysis".into());
    }
    Ok((before, page.data))
}

fn read_verified_range(
    directory: &Path,
    report_id: &str,
    offset: u64,
    data_len: usize,
) -> Result<AnalysisSpecimenPage, String> {
    let end = offset
        .checked_add(data_len as u64)
        .ok_or("specimen preview range overflow")?;
    let root = File::open(directory).map_err(|e| format!("analysis directory: {e}"))?;
    if !root.metadata().map_err(|e| e.to_string())?.is_dir() {
        return Err("analysis path is not a directory".into());
    }
    let mut report_file = open_member(&root, "report.json")?;
    let report_before = report_file.metadata().map_err(|e| e.to_string())?;
    if report_before.len() > super::worker::REPORT_MAX_SIZE as u64 {
        return Err("saved analysis report exceeds bound".into());
    }
    let mut encoded = Vec::new();
    (&mut report_file)
        .take((super::worker::REPORT_MAX_SIZE + 1) as u64)
        .read_to_end(&mut encoded)
        .map_err(|e| e.to_string())?;
    if encoded.len() > super::worker::REPORT_MAX_SIZE {
        return Err("saved analysis report changed beyond bound".into());
    }
    let report: AnalysisReport = serde_json::from_slice(&encoded)
        .map_err(|e| format!("saved analysis report malformed: {e}"))?;
    super::validation::validate_report(&report)?;
    if report.id != report_id {
        return Err("saved analysis report identity mismatch".into());
    }
    if report.state == AnalysisState::Acquiring {
        return Err("specimen acquisition is incomplete".into());
    }
    let total_len = report
        .specimen_len
        .ok_or("complete specimen length unavailable")?;
    if total_len > u64::from(crate::control::SPECIMEN_MAX_SIZE) {
        return Err("saved specimen exceeds 64 MiB bound".into());
    }
    if end > total_len {
        return Err("specimen preview range exceeds saved length".into());
    }
    let expected = report
        .specimen_sha256
        .as_ref()
        .ok_or("complete specimen digest unavailable")?;
    if expected.len() != 64 || !expected.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("saved specimen digest malformed".into());
    }
    let mut specimen = open_member(&root, "specimen")?;
    let before = specimen.metadata().map_err(|e| e.to_string())?;
    if before.len() != total_len {
        return Err("saved specimen length mismatch".into());
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 16384];
    let mut hashed_len = 0u64;
    loop {
        let count = specimen.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        hashed_len = hashed_len
            .checked_add(count as u64)
            .ok_or("specimen digest length overflow")?;
        if hashed_len > total_len {
            return Err("specimen grew during digest verification".into());
        }
        digest.update(&buffer[..count]);
    }
    if hashed_len != total_len || !format!("{:x}", digest.finalize()).eq_ignore_ascii_case(expected)
    {
        return Err("saved specimen digest mismatch".into());
    }
    specimen
        .seek(SeekFrom::Start(offset))
        .map_err(|e| e.to_string())?;
    let mut data = vec![0; data_len];
    specimen
        .read_exact(&mut data)
        .map_err(|e| format!("specimen range read: {e}"))?;
    let after = specimen.metadata().map_err(|e| e.to_string())?;
    let path_after = open_member(&root, "specimen")?
        .metadata()
        .map_err(|e| e.to_string())?;
    let report_after = report_file.metadata().map_err(|e| e.to_string())?;
    let report_path_after = open_member(&root, "report.json")?
        .metadata()
        .map_err(|e| e.to_string())?;
    if !same_metadata(&before, &after)
        || !same_metadata(&before, &path_after)
        || !same_metadata(&report_before, &report_after)
        || !same_metadata(&report_before, &report_path_after)
    {
        return Err("saved analysis evidence changed during preview verification".into());
    }
    Ok(AnalysisSpecimenPage {
        report_id: report.id,
        offset,
        total_len,
        data,
    })
}
fn open_member(root: &File, name: &str) -> Result<File, String> {
    let descriptor = openat(
        root,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|e| format!("analysis member {name}: {e}"))?;
    let file = File::from(descriptor);
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err(format!("analysis member {name} is not a regular file"));
    }
    Ok(file)
}
fn same_metadata(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        analysis::{AnalysisKind, AnalysisSection, AnalysisSectionState},
        storage,
    };
    struct Fixture {
        directory: std::path::PathBuf,
        report: AnalysisReport,
    }
    impl Fixture {
        fn new() -> Self {
            let directory =
                std::env::temp_dir().join(format!("ant-specimen-preview-{}", storage::unique_id()));
            storage::private_dir(&directory).unwrap();
            let specimen = b"verified archived specimen";
            std::fs::write(directory.join("specimen"), specimen).unwrap();
            let report = AnalysisReport {
                id: "report".into(),
                state: AnalysisState::Complete,
                source_path: "/guest/sample".into(),
                specimen_sha256: Some(format!("{:x}", Sha256::digest(specimen))),
                specimen_len: Some(specimen.len() as u64),
                reason: None,
                sections: vec![AnalysisSection {
                    kind: AnalysisKind::Metadata,
                    state: AnalysisSectionState::Complete,
                    summary: "saved".into(),
                    tools: Vec::new(),
                    listing: None,
                    entries: Vec::new(),
                }],
                layer: None,
                specimen_source: None,
            };
            let fixture = Self { directory, report };
            fixture.save();
            fixture
        }
        fn save(&self) {
            std::fs::write(
                self.directory.join("report.json"),
                serde_json::to_vec(&self.report).unwrap(),
            )
            .unwrap();
        }
        fn read(&self, offset: u64, len: usize) -> Result<AnalysisSpecimenPage, String> {
            read_specimen_range(&self.directory, "report", offset, len)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }
    #[test]
    fn retained_preview_checks_identity_bounds_complete_length_and_hash() {
        let mut fixture = Fixture::new();
        let page = fixture.read(9, 8).unwrap();
        assert_eq!(page.data, b"archived");
        assert_eq!(page.offset, 9);
        assert_eq!(page.report_id, "report");
        assert_eq!(page.total_len, 26);
        assert!(read_specimen_range(&fixture.directory, "wrong", 0, 1).is_err());
        for (offset, len) in [(0, 0), (0, 4097), (u64::MAX, 1), (26, 1)] {
            assert!(fixture.read(offset, len).is_err());
        }
        fixture.report.specimen_sha256 = Some("00".repeat(32));
        fixture.save();
        assert!(fixture.read(0, 1).is_err());
        fixture.report.specimen_sha256 = None;
        fixture.save();
        assert!(fixture.read(0, 1).is_err());
        fixture.report.specimen_len = Some(u64::from(crate::control::SPECIMEN_MAX_SIZE) + 1);
        fixture.save();
        assert!(fixture.read(0, 1).is_err());
        fixture.report.specimen_len = Some(27);
        fixture.report.specimen_sha256 = Some("00".repeat(32));
        fixture.save();
        assert!(fixture.read(0, 1).is_err());
        fixture.report.state = AnalysisState::Acquiring;
        fixture.save();
        assert!(fixture.read(0, 1).is_err());
    }
    #[test]
    fn preview_rejects_missing_nonregular_and_symlink_members_without_blocking() {
        let fixture = Fixture::new();
        std::fs::remove_file(fixture.directory.join("specimen")).unwrap();
        assert!(fixture.read(0, 1).is_err());
        std::os::unix::fs::symlink("report.json", fixture.directory.join("specimen")).unwrap();
        assert!(fixture.read(0, 1).is_err());
        std::fs::remove_file(fixture.directory.join("specimen")).unwrap();
        std::fs::create_dir(fixture.directory.join("specimen")).unwrap();
        assert!(fixture.read(0, 1).is_err());
        std::fs::remove_dir(fixture.directory.join("specimen")).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(fixture.directory.join("specimen"))
                .status()
                .unwrap()
                .success()
        );
        assert!(fixture.read(0, 1).is_err());
        std::fs::remove_file(fixture.directory.join("report.json")).unwrap();
        assert!(fixture.read(0, 1).is_err());
        std::os::unix::fs::symlink("specimen", fixture.directory.join("report.json")).unwrap();
        assert!(fixture.read(0, 1).is_err());
    }
    #[test]
    fn metadata_signature_detects_content_or_member_replacement() {
        let fixture = Fixture::new();
        let path = fixture.directory.join("specimen");
        let before = std::fs::metadata(&path).unwrap();
        std::fs::write(&path, b"mutated archived specimen!").unwrap();
        assert!(!same_metadata(&before, &std::fs::metadata(&path).unwrap()));
        assert!(fixture.read(0, 1).is_err());
        let file = open_member(&File::open(&fixture.directory).unwrap(), "specimen").unwrap();
        std::fs::rename(&path, fixture.directory.join("old-specimen")).unwrap();
        std::fs::write(&path, b"verified archived specimen").unwrap();
        assert!(!same_metadata(
            &file.metadata().unwrap(),
            &std::fs::metadata(&path).unwrap()
        ));
    }
}
