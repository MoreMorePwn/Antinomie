// SPDX-License-Identifier: GPL-3.0-only
//! Intake (design 4.2, card P3-2b): every entry produces a library sample.
//! The common steps run inside `job.submit`, or in the watcher before it
//! submits:
//!
//! 1. open the staged file with `O_NOFOLLOW`, require a regular file, `fstat`
//!    its size;
//! 2. refuse above `min(MAX_SAMPLE, policy.max_sample_mib, specimen_ram_bound)`
//!    with `sample_too_large`;
//! 3. read at most that many bytes, detect the type and architecture, apply
//!    `accept_types` and `accept_arch` (`sample_type_denied`,
//!    `sample_arch_denied`);
//! 4. add to the library with origin `Added`, source `Automation`, and the
//!    caller as custody actor;
//! 5. (the store) dedupe by SHA-256, 4.2.2;
//! 6. remove the staged copy.
//!
//! A staged file never runs on the host.

pub mod mount;
pub mod staging;

use crate::{
    api::{failure::FailureCode, ids::Sha256Hex, job::JobSample, spec::SampleSource},
    config::LoadedPolicy,
    store::{IntakeError, SampleAdmission},
};
use antinomie_monitor_core::{
    samples::{self, Library, MAX_SAMPLE, NewOrigin, NewSample, OriginKind},
    specimen_ram_bound,
};
use staging::{StagingStore, open_nofollow};
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

/// The origin source every automated intake states.
pub const ORIGIN_SOURCE: &str = "Automation";

/// The intake of a service: the library of a data directory, the staging
/// store, and the RAM of the lane VM (an executable may be at most a quarter
/// of it).
pub struct Intake {
    data_dir: PathBuf,
    staging: Arc<StagingStore>,
    lane_ram_mib: Option<u32>,
}

fn deny(code: FailureCode, message: impl Into<String>) -> IntakeError {
    IntakeError {
        code,
        message: message.into(),
    }
}

/// The largest sample a job may carry: the minimum of `MAX_SAMPLE`, the
/// policy's `max_sample_mib` and the VM RAM bound (design 5.4.1). This is
/// `capabilities.max_sample_bytes` for the lane.
pub fn size_limit(policy_max_mib: u32, lane_ram_mib: Option<u32>) -> u64 {
    let mut limit = MAX_SAMPLE.min(u64::from(policy_max_mib) << 20);
    if let Some(ram) = lane_ram_mib {
        limit = limit.min(specimen_ram_bound(ram));
    }
    limit
}

/// What a file is, from its first bytes (never run, never unpacked).
fn classify(bytes: &[u8]) -> (&'static str, Option<&'static str>) {
    samples::detect_type(bytes)
}

fn check_type(policy: &LoadedPolicy, kind: &str, arch: Option<&str>) -> Result<(), IntakeError> {
    let sample = &policy.policy.sample;
    if !sample.accept_types.iter().any(|t| t == "any" || t == kind) {
        return Err(deny(
            FailureCode::SampleTypeDenied,
            format!("policy {} does not accept type {kind}", policy.name),
        ));
    }
    // A type with no architecture (a script) has nothing to check.
    if let Some(arch) = arch
        && !sample.accept_arch.iter().any(|a| a == "any" || a == arch)
    {
        return Err(deny(
            FailureCode::SampleArchDenied,
            format!("policy {} does not accept architecture {arch}", policy.name),
        ));
    }
    Ok(())
}

impl Intake {
    pub fn new(data_dir: &Path, staging: Arc<StagingStore>, lane_ram_mib: Option<u32>) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            staging,
            lane_ram_mib,
        }
    }

    pub fn staging(&self) -> &StagingStore {
        &self.staging
    }

    /// `capabilities.max_sample_bytes` for a policy.
    pub fn max_sample_bytes(&self, policy: &LoadedPolicy) -> u64 {
        size_limit(policy.policy.sample.max_sample_mib, self.lane_ram_mib)
    }

    fn library(&self) -> Result<Library, IntakeError> {
        Library::open(&self.data_dir).map_err(|e| {
            deny(
                FailureCode::SampleMissing,
                format!("the library cannot be opened: {e}"),
            )
        })
    }

    /// A sample already in the library.
    fn library_sample(
        &self,
        sha256: &Sha256Hex,
        policy: &LoadedPolicy,
    ) -> Result<JobSample, IntakeError> {
        let library = self.library()?;
        let record = library
            .get(sha256.as_str())
            .map_err(|e| deny(FailureCode::SampleMissing, e))?
            .filter(|record| record.removed_ms.is_none())
            .ok_or_else(|| deny(FailureCode::SampleMissing, "the library has no such sample"))?;
        let limit = self.max_sample_bytes(policy);
        if record.size > limit {
            return Err(deny(
                FailureCode::SampleTooLarge,
                format!("{} bytes is above the {limit} byte limit", record.size),
            ));
        }
        let arch = (!record.arch.is_empty()).then_some(record.arch.as_str());
        check_type(policy, &record.file_type, arch)?;
        Ok(JobSample {
            sha256: sha256.clone(),
            size: record.size,
            kind: record.file_type.clone(),
            architecture: arch.map(str::to_owned),
            name: record.name.clone(),
        })
    }

    /// Steps 1 to 4 for a file: staged, or a local path.
    fn file_sample(
        &self,
        path: &Path,
        shown_name: &str,
        name_hint: Option<&str>,
        policy: &LoadedPolicy,
        actor: &str,
    ) -> Result<JobSample, IntakeError> {
        let mut file = open_nofollow(path, false).map_err(|e| {
            deny(
                FailureCode::SampleMissing,
                format!("the file cannot be opened: {e}"),
            )
        })?;
        let info = file
            .metadata()
            .map_err(|e| deny(FailureCode::SampleMissing, e.to_string()))?;
        if !info.is_file() {
            return Err(deny(FailureCode::SampleMissing, "not a regular file"));
        }
        let limit = self.max_sample_bytes(policy);
        if info.len() > limit {
            return Err(deny(
                FailureCode::SampleTooLarge,
                format!("{} bytes is above the {limit} byte limit", info.len()),
            ));
        }
        let mut bytes = Vec::with_capacity(info.len() as usize);
        (&mut file)
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| deny(FailureCode::SampleMissing, e.to_string()))?;
        if bytes.len() as u64 > limit {
            return Err(deny(
                FailureCode::SampleTooLarge,
                "the file grew while it was read",
            ));
        }
        let (kind, arch) = classify(&bytes);
        check_type(policy, kind, arch)?;
        // Only the name goes into the origin, never the host path.
        let origin = NewOrigin {
            kind: OriginKind::Added,
            source: ORIGIN_SOURCE.into(),
            path: shown_name.to_owned(),
            name: shown_name.to_owned(),
            ..Default::default()
        };
        let new = NewSample {
            name: name_hint.unwrap_or_default().to_owned(),
            origin,
            ..Default::default()
        };
        let mut library = self.library()?;
        let added = library.add_bytes_as(&bytes, new, actor).map_err(|e| {
            deny(
                FailureCode::SampleMissing,
                format!("the library refused the sample: {e}"),
            )
        })?;
        let record = library
            .get(&added.sha256)
            .map_err(|e| deny(FailureCode::SampleMissing, e))?
            .ok_or_else(|| {
                deny(
                    FailureCode::SampleMissing,
                    "the sample vanished after it was added",
                )
            })?;
        Ok(JobSample {
            sha256: Sha256Hex::try_from(added.sha256)
                .map_err(|e| deny(FailureCode::SampleMissing, e.to_string()))?,
            size: record.size,
            kind: kind.to_owned(),
            architecture: arch.map(str::to_owned),
            name: record.name,
        })
    }
}

impl Intake {
    /// `sample.add` over the socket: store a finished upload of `client` in
    /// the library without running it. The type and architecture are read
    /// from the bytes; no policy applies (the sample is not a job), only
    /// `MAX_SAMPLE`. The staged copy goes away once the library holds the
    /// bytes. Returns the SHA-256 and whether the sample is new.
    pub fn add_upload(
        &self,
        client: &str,
        upload: &crate::api::ids::UploadId,
        name: Option<&str>,
        tags: Vec<samples::Tag>,
        actor: &str,
    ) -> Result<(String, bool), crate::api::error::ApiError> {
        use crate::api::error::{ApiError, ErrorCode};
        let staged = self.staging.sealed(client, upload)?;
        let mut file = open_nofollow(&staged.path, false)
            .map_err(|e| ApiError::new(ErrorCode::NotFound, format!("the upload: {e}")))?;
        let info = file
            .metadata()
            .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?;
        if !info.is_file() {
            return Err(ApiError::new(
                ErrorCode::NotFound,
                "the upload is not a file",
            ));
        }
        if info.len() > MAX_SAMPLE {
            return Err(ApiError::payload_too_large(MAX_SAMPLE).with_field("sample.upload_id"));
        }
        let mut bytes = Vec::with_capacity(info.len() as usize);
        (&mut file)
            .take(MAX_SAMPLE + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?;
        if bytes.len() as u64 > MAX_SAMPLE {
            return Err(ApiError::payload_too_large(MAX_SAMPLE).with_field("sample.upload_id"));
        }
        let shown = staged.name.clone().unwrap_or_else(|| "upload".into());
        let new = NewSample {
            name: name
                .or(staged.name.as_deref())
                .unwrap_or_default()
                .to_owned(),
            tags,
            origin: NewOrigin {
                kind: OriginKind::Added,
                source: "Daemon".into(),
                path: shown.clone(),
                name: shown,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut library = Library::open(&self.data_dir).map_err(crate::library::library_error)?;
        let added = library
            .add_bytes_as(&bytes, new, actor)
            .map_err(crate::library::library_error)?;
        self.staging.discard(upload);
        Ok((added.sha256, added.new))
    }
}

/// The last component of a host path, with control characters turned into
/// spaces (a name is data, never markup).
pub fn display_name(path: &Path) -> String {
    path.file_name()
        .map(|n| {
            n.to_string_lossy()
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .take(128)
                .collect()
        })
        .unwrap_or_default()
}

impl SampleAdmission for Intake {
    fn admit(
        &self,
        source: &SampleSource,
        name: Option<&str>,
        policy: &LoadedPolicy,
        actor: &str,
    ) -> Result<JobSample, IntakeError> {
        if let Some(sha256) = &source.sha256 {
            return self.library_sample(sha256, policy);
        }
        if let Some(upload) = &source.upload_id {
            let staged = self.staging.sealed(actor, upload).map_err(|e| {
                deny(
                    FailureCode::SampleMissing,
                    format!("upload {upload}: {}", e.message),
                )
            })?;
            let shown = staged.name.clone().unwrap_or_else(|| "upload".into());
            let sample = self.file_sample(
                &staged.path,
                &shown,
                name.or(staged.name.as_deref()),
                policy,
                actor,
            )?;
            // The library holds the only copy now.
            self.staging.discard(upload);
            return Ok(sample);
        }
        if let Some(path) = &source.path {
            let path = Path::new(path);
            return self.file_sample(path, &display_name(path), name, policy, actor);
        }
        Err(deny(FailureCode::SampleMissing, "the spec names no sample"))
    }
}
