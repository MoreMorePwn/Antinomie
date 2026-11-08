// SPDX-License-Identifier: GPL-3.0-only
//! `artifact.get` and `report.get` on the local socket (design 5.3, 2.5): the
//! artifact's metadata, its path (local-only), and optionally a byte range as
//! Base64.
//!
//! The path is resolved from the location the store recorded, relative to the
//! job's directory: an absolute location or one with `..` is refused, the
//! real path (symlinks followed) must still lie inside the job directory, and
//! it must be a regular file. A range is read through a descriptor opened
//! with `O_NOFOLLOW`. Sensitive kinds need `artifacts:sensitive` (5.8).

use super::service::{Service, to_value};
use crate::{
    api::{
        artifact::{Artifact, ArtifactKind},
        error::{ApiError, ErrorCode},
        ids::ArtifactId,
        ops::{ByteRange, Caller, ReportGetParams, Scope},
        spec::ReportFormat,
    },
    server::b64,
};
use serde_json::json;
use std::{
    io::{Read, Seek, SeekFrom},
    os::unix::fs::OpenOptionsExt,
    path::{Component, Path, PathBuf},
};

/// The largest range one `artifact.get` returns (it travels as Base64 in a
/// line of at most 2 MiB).
pub const MAX_RANGE: u64 = 1 << 20;

fn escape() -> ApiError {
    ApiError::new(
        ErrorCode::Internal,
        "the artifact's recorded location is outside its job directory; not served",
    )
}

/// The real path of `location` inside `job_dir`, or an error.
pub fn resolve(job_dir: &Path, location: &str) -> Result<PathBuf, ApiError> {
    let relative = Path::new(location);
    if location.is_empty()
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(escape());
    }
    let base = job_dir
        .canonicalize()
        .map_err(|_| ApiError::not_found("artifact file"))?;
    let full = base
        .join(relative)
        .canonicalize()
        .map_err(|_| ApiError::not_found("artifact file"))?;
    if !full.starts_with(&base) {
        return Err(escape());
    }
    let meta =
        std::fs::symlink_metadata(&full).map_err(|_| ApiError::not_found("artifact file"))?;
    if !meta.is_file() {
        return Err(escape());
    }
    Ok(full)
}

fn read_range(path: &Path, range: ByteRange, size: u64) -> Result<Vec<u8>, ApiError> {
    if range.len > MAX_RANGE {
        return Err(ApiError::payload_too_large(MAX_RANGE).with_field("range.len"));
    }
    if range.offset > size {
        return Err(ApiError::invalid_argument("range.offset", "past the end"));
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| ApiError::not_found("artifact file"))?;
    file.seek(SeekFrom::Start(range.offset))
        .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?;
    let mut bytes = Vec::new();
    file.take(range.len)
        .read_to_end(&mut bytes)
        .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?;
    Ok(bytes)
}

fn served(
    service: &Service,
    artifact: Artifact,
    location: &str,
    range: Option<ByteRange>,
    caller: &Caller,
) -> Result<serde_json::Value, ApiError> {
    if artifact.sensitive && !caller.has(Scope::ArtifactsSensitive) {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "this artifact is sensitive and needs the artifacts:sensitive scope",
        ));
    }
    let path = resolve(&service.store.job_dir(&artifact.job_id), location)?;
    let mut out = json!({ "artifact": to_value(&artifact)?, "path": path });
    if let Some(range) = range {
        let bytes = read_range(&path, range, artifact.size)?;
        out["range"] = json!({
            "offset": range.offset,
            "len": bytes.len(),
            "data": b64::encode(&bytes),
        });
    }
    Ok(out)
}

pub(super) fn get(
    service: &Service,
    id: &ArtifactId,
    range: Option<ByteRange>,
    caller: &Caller,
) -> Result<serde_json::Value, ApiError> {
    let (artifact, location) = service.store.artifact(id)?;
    served(service, artifact, &location, range, caller)
}

fn kind_of(format: ReportFormat) -> ArtifactKind {
    match format {
        ReportFormat::Html => ArtifactKind::ReportHtml,
        ReportFormat::Pdf => ArtifactKind::ReportPdf,
        ReportFormat::Json => ArtifactKind::ReportJson,
        ReportFormat::Misp => ArtifactKind::ReportMisp,
        ReportFormat::Stix => ArtifactKind::ReportStix,
        ReportFormat::Md => ArtifactKind::ReportMd,
    }
}

pub(super) fn report(
    service: &Service,
    request: &ReportGetParams,
    caller: &Caller,
) -> Result<serde_json::Value, ApiError> {
    let wanted = kind_of(request.format);
    let artifact = service
        .store
        .artifacts(&request.job_id)?
        .into_iter()
        .find(|a| a.kind == wanted)
        .ok_or_else(|| ApiError::not_found("report of that format"))?;
    get(service, &artifact.id, None, caller)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_location_must_stay_inside_the_job_directory() {
        let root = std::env::temp_dir().join(format!("ant-art-{}", std::process::id()));
        let job = root.join("job");
        std::fs::create_dir_all(job.join("artifacts")).unwrap();
        std::fs::write(job.join("artifacts/report.html"), b"<p>").unwrap();
        std::fs::write(root.join("secret"), b"x").unwrap();
        std::os::unix::fs::symlink(root.join("secret"), job.join("artifacts/link")).unwrap();
        std::fs::create_dir_all(job.join("artifacts/dir")).unwrap();

        assert!(
            resolve(&job, "artifacts/report.html")
                .unwrap()
                .ends_with("artifacts/report.html")
        );
        for bad in [
            "",
            "/etc/passwd",
            "../secret",
            "artifacts/../../secret",
            "./artifacts/report.html",
            "artifacts/link",
            "artifacts/dir",
        ] {
            assert!(resolve(&job, bad).is_err(), "{bad:?} was served");
        }
        assert_eq!(
            resolve(&job, "artifacts/missing").unwrap_err().code,
            ErrorCode::NotFound
        );
        let range = read_range(
            &job.join("artifacts/report.html"),
            ByteRange { offset: 1, len: 5 },
            3,
        )
        .unwrap();
        assert_eq!(range, b"p>");
        assert!(
            read_range(
                &job.join("artifacts/report.html"),
                ByteRange {
                    offset: 0,
                    len: MAX_RANGE + 1
                },
                3
            )
            .is_err()
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}
