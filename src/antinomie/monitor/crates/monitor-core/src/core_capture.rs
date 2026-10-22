// SPDX-License-Identifier: GPL-3.0-only
//! Bounded metadata catalog for independently acquired, nonfatal process cores.
use crate::{ProcessCoreCapture, ProcessCoreRequest};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};
const METADATA_LIMIT: u64 = 64 * 1024;
/// Longest core file the guest reports, holes included (`ANTC_CORE_LOGICAL_MAX`);
/// the handle's `max_size` bounds the bytes stored, not this extent.
pub(crate) const LOGICAL_LIMIT: u64 = 16 * 1024 * 1024 * 1024;
pub(crate) const RECORD_LIMIT: usize = 4096;
pub(crate) const ACTIVE_LIMIT: usize = 4;
pub(crate) const LATEST_LIMIT: usize = 64;
pub(crate) fn validate_request(request: &ProcessCoreRequest) -> Result<(), String> {
    if request.vm_id.is_empty()
        || request.vm_id.len() > 128
        || request.target.boot_id.is_empty()
        || request.target.boot_id.len() > 128
        || request.target.task_cookie == 0
        || request.target.tgid == 0
        || request.max_size == 0
        || u64::from(request.max_size) > crate::core_limits::CORE_MAX_SUPPORTED
        || request.timeout_ms == 0
        || request.timeout_ms > crate::core_limits::CORE_TIMEOUT_MAX_MS
        || request
            .source_run_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > 128)
    {
        return Err("manual core request has invalid identity or limits".into());
    }
    Ok(())
}
/// Load one capture's metadata without reading or parsing its ELF payload.
/// Paths are derived from the retained directory rather than trusting JSON paths.
pub fn load(directory: &Path) -> Result<ProcessCoreCapture, String> {
    let file = crate::archive_io::open_regular(directory, Path::new("core.json"))
        .map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    file.take(METADATA_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > METADATA_LIMIT {
        return Err("manual core metadata exceeds 64 KiB".into());
    }
    let mut record: ProcessCoreCapture =
        serde_json::from_slice(&bytes).map_err(|error| format!("manual core metadata: {error}"))?;
    validate_request(&ProcessCoreRequest {
        vm_id: record.vm_id.clone(),
        target: record.target.clone(),
        source_run_id: record.source_run_id.clone(),
        max_size: record.max_size,
        timeout_ms: record.timeout_ms,
    })?;
    if record.format != 1
        || record.id.is_empty()
        || record.id.len() > 128
        || record.boot_id != record.target.boot_id
        || record.nonce == [0, 0]
        || record.guest_handle == Some(0)
        || record
            .restored_from_capture_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > 128)
        || record.stored_size > LOGICAL_LIMIT
        || record.guest_size.is_some_and(|size| size > LOGICAL_LIMIT)
        || record
            .requested_max_size
            .is_some_and(|requested| requested < record.max_size)
        || record
            .guest_max_size
            .is_some_and(|size| size > crate::core_limits::CORE_MAX_SUPPORTED)
        || [
            record.stored_bytes,
            record.expected_size,
            record.allocated_size,
        ]
        .into_iter()
        .flatten()
        .any(|size| size > LOGICAL_LIMIT)
        || record
            .reason
            .as_ref()
            .is_some_and(|reason| reason.text.len() > 2048)
        || record
            .issue
            .as_ref()
            .is_some_and(|issue| issue.len() > 4096)
        || record.sha256.as_ref().is_some_and(|hash| {
            hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        || (matches!(
            record.state,
            crate::RunArtifactState::Complete | crate::RunArtifactState::Partial
        ) && record.pause_released != Some(true))
        || (record.state == crate::RunArtifactState::Complete
            && (record.file.is_none()
                || record.stored_size < 64
                || record.guest_size != Some(record.stored_size)
                || record.sha256.is_none()))
    {
        return Err("manual core metadata has invalid identity or bounds".into());
    }
    record.directory = directory.to_path_buf();
    record.file = record.file.map(|_| directory.join("process.elf"));
    Ok(record)
}
/// Enumerate bounded metadata under selected boot roots. No ELF is opened.
pub fn list(roots: &[PathBuf], vm_id: Option<&str>) -> Result<Vec<ProcessCoreCapture>, String> {
    Ok(list_with_issues(roots, vm_id)?.records)
}
#[derive(Default)]
pub struct Catalog {
    pub records: Vec<ProcessCoreCapture>,
    pub issues: Vec<String>,
}
impl Catalog {
    fn issue(&mut self, issue: impl Into<String>) {
        if self.issues.len() < 16 {
            self.issues.push(issue.into().chars().take(2048).collect());
        }
    }
}
/// Keep valid evidence when individual metadata is malformed; report bounded
/// issues and truncation. Global resource budgets apply across selected roots.
pub fn list_with_issues(roots: &[PathBuf], vm_id: Option<&str>) -> Result<Catalog, String> {
    if roots.len() > RECORD_LIMIT {
        return Err("manual core catalog exceeds 4096 selected roots".into());
    }
    let mut catalog = Catalog::default();
    let mut entries_count = 0usize;
    let mut metadata_size = 0u64;
    'roots: for root in roots {
        let entries = match fs::read_dir(root.join("core-captures")) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                catalog.issue(format!("manual core catalog {}: {error}", root.display()));
                continue;
            }
        };
        for entry in entries {
            entries_count += 1;
            if entries_count > RECORD_LIMIT {
                catalog
                    .issue("manual core catalog exceeds 4096 records; select fewer boot folders");
                break 'roots;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    catalog.issue(error.to_string());
                    continue;
                }
            };
            if !match entry.file_type() {
                Ok(kind) => kind.is_dir(),
                Err(error) => {
                    catalog.issue(error.to_string());
                    false
                }
            } {
                continue;
            }
            let directory = entry.path();
            let size = match fs::symlink_metadata(directory.join("core.json")) {
                Ok(metadata) if metadata.is_file() => metadata.len(),
                Ok(_) => {
                    catalog.issue("manual core metadata is not a regular file");
                    continue;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    catalog.issue(error.to_string());
                    continue;
                }
            };
            metadata_size = metadata_size.saturating_add(size);
            if metadata_size > 32 * 1024 * 1024 {
                catalog.issue("manual core catalog exceeds 32 MiB; select fewer boot folders");
                break 'roots;
            }
            let record = match load(&directory) {
                Ok(record) => record,
                Err(error) => {
                    catalog.issue(format!("{}: {error}", directory.display()));
                    continue;
                }
            };
            if vm_id.is_none_or(|id| record.vm_id == id)
                && !catalog.records.iter().any(|old: &ProcessCoreCapture| {
                    old.id == record.id && old.boot_id == record.boot_id
                })
            {
                catalog.records.push(record);
            }
        }
    }
    catalog
        .records
        .sort_by(|left, right| right.id.cmp(&left.id));
    Ok(catalog)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GuestProcessIdentity, ProcessCorePhase, RunArtifactState};
    fn record(directory: PathBuf) -> ProcessCoreCapture {
        ProcessCoreCapture {
            format: 1,
            id: "capture".into(),
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            source_run_id: None,
            restored_from_capture_id: None,
            target: GuestProcessIdentity {
                boot_id: "boot".into(),
                task_cookie: 6,
                tgid: 7,
                start_boot_ns: 8,
            },
            directory,
            file: None,
            state: RunArtifactState::Queued,
            phase: ProcessCorePhase::Admission,
            stored_size: 0,
            guest_size: None,
            sha256: None,
            pause_released: None,
            max_size: 64 * 1024 * 1024,
            timeout_ms: 5000,
            nonce: [11, 12],
            guest_handle: None,
            guest_status: None,
            issue: None,
            requested_max_size: None,
            guest_max_size: None,
            stored_bytes: None,
            expected_size: None,
            allocated_size: None,
            reason: None,
        }
    }
    #[test]
    fn catalog_keeps_valid_records_and_reports_corrupt_metadata() {
        let root = std::env::temp_dir().join(format!(
            "ant-manual-catalog-{}",
            crate::storage::unique_id()
        ));
        let good = root.join("core-captures/good");
        let bad = root.join("core-captures/bad");
        fs::create_dir_all(&good).unwrap();
        fs::create_dir(&bad).unwrap();
        crate::storage::atomic_json(&good.join("core.json"), &record(good.clone())).unwrap();
        fs::write(bad.join("core.json"), b"broken JSON").unwrap();
        let report = list_with_issues(std::slice::from_ref(&root), Some("vm")).unwrap();
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.issues.len(), 1);
        assert!(report.issues[0].contains("manual core metadata"));
        assert_eq!(
            list(std::slice::from_ref(&root), Some("other"))
                .unwrap()
                .len(),
            0
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn sizes_and_reason_round_trip_and_an_older_sidecar_still_loads() {
        let root =
            std::env::temp_dir().join(format!("ant-core-size-{}", crate::storage::unique_id()));
        fs::create_dir(&root).unwrap();
        let mut value = record(root.clone());
        value.max_size = 128 << 20;
        value.requested_max_size = Some(256 << 20);
        value.guest_max_size = Some(128 << 20);
        value.stored_bytes = Some(100 << 20);
        value.expected_size = Some(134_660_096);
        value.allocated_size = Some(100 << 20);
        value.reason = Some(crate::core_limits::CoreReason::new(
            crate::core_limits::CoreReasonCode::Budget,
            Some(-27),
            "budget",
        ));
        crate::storage::atomic_json(&root.join("core.json"), &value).unwrap();
        let loaded = load(&root).unwrap();
        assert_eq!(loaded.requested_max_size, Some(256 << 20));
        assert_eq!(loaded.reason.unwrap().errno, Some(-27));
        value.requested_max_size = Some(64 << 20);
        crate::storage::atomic_json(&root.join("core.json"), &value).unwrap();
        assert!(load(&root).is_err(), "requested may not be below accepted");
        let mut old = serde_json::to_value(record(root.clone())).unwrap();
        for key in [
            "requested_max_size",
            "guest_max_size",
            "stored_bytes",
            "expected_size",
            "allocated_size",
            "reason",
        ] {
            old.as_object_mut().unwrap().remove(key);
        }
        fs::write(root.join("core.json"), serde_json::to_vec(&old).unwrap()).unwrap();
        assert!(load(&root).unwrap().reason.is_none());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn metadata_rejects_unreleased_complete_and_derives_file_namespace() {
        let root = std::env::temp_dir().join(format!(
            "ant-manual-metadata-{}",
            crate::storage::unique_id()
        ));
        fs::create_dir(&root).unwrap();
        let mut value = record(PathBuf::from("/foreign"));
        value.file = Some(PathBuf::from("/foreign/process.elf"));
        crate::storage::atomic_json(&root.join("core.json"), &value).unwrap();
        assert_eq!(load(&root).unwrap().file, Some(root.join("process.elf")));
        value.state = RunArtifactState::Complete;
        value.guest_size = Some(64);
        value.stored_size = 64;
        value.sha256 = Some("a".repeat(64));
        crate::storage::atomic_json(&root.join("core.json"), &value).unwrap();
        assert!(load(&root).is_err());
        value.pause_released = Some(true);
        crate::storage::atomic_json(&root.join("core.json"), &value).unwrap();
        assert!(load(&root).is_ok());
        value.target.boot_id = "stale".into();
        crate::storage::atomic_json(&root.join("core.json"), &value).unwrap();
        assert!(load(&root).is_err());
        fs::write(
            root.join("core.json"),
            vec![b' '; (METADATA_LIMIT + 1) as usize],
        )
        .unwrap();
        assert!(load(&root).unwrap_err().contains("64 KiB"));
        fs::remove_dir_all(root).unwrap();
    }
}
