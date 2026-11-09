// SPDX-License-Identifier: GPL-3.0-only
//! The staging store (design 4.2, 5.3 `upload.*`): sample bytes on their way
//! into the library. `inbox/uploads/<upload-id>/` holds the bytes (`data`) and
//! a small record (`meta.json`). Plain files, mode 0600 under a 0700
//! directory, never executed, deleted after intake or after 24 hours.

use super::mount::{self, Volume};
use crate::{
    api::{
        error::{ApiError, ErrorCode},
        ids::{Sha256Hex, UploadId},
        ops::{UploadBeginParams, UploadBegun, UploadFinished, UploadReceived},
    },
    clock::{Clock, new_upload_id},
};
use rustix::fs::OFlags;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

/// The longest chunk one `upload.put` carries.
pub const MAX_CHUNK: u64 = 1 << 20;
/// A staged upload is deleted after 24 hours (decided B-H17).
pub const UPLOAD_TTL_MS: u64 = 24 * 60 * 60 * 1000;
/// Open uploads one client may hold at a time.
pub const MAX_OPEN_PER_CLIENT: usize = 8;
const DATA: &str = "data";
const META: &str = "meta.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Sealed {
    sha256: String,
    size: u64,
    expires_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Meta {
    upload_id: String,
    client_id: String,
    name: Option<String>,
    size: u64,
    sha256: Option<String>,
    created_ms: u64,
    expires_ms: u64,
    sealed: Option<Sealed>,
}

/// A sealed upload ready for intake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedUpload {
    pub upload_id: UploadId,
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub name: Option<String>,
}

pub struct StagingStore {
    root: PathBuf,
    clock: Arc<dyn Clock>,
    /// The largest upload `upload.begin` accepts, in bytes.
    max_size: u64,
}

fn not_found() -> ApiError {
    ApiError::not_found("upload")
}

fn io(error: impl std::fmt::Display) -> ApiError {
    ApiError::new(ErrorCode::Internal, format!("upload staging: {error}"))
}

/// A name hint: 1 to 128 bytes, no `/`, no NUL and no control character.
pub fn valid_name(name: &str) -> bool {
    (1..=128).contains(&name.len()) && !name.contains('/') && !name.chars().any(char::is_control)
}

impl StagingStore {
    /// Open `<inbox>/uploads`, creating it, and check its volume against the
    /// data directory (design 4.2). `mountinfo` is the text of
    /// `/proc/self/mountinfo`.
    pub fn open_with_mounts(
        inbox: &Path,
        data_dir: &Path,
        clock: Arc<dyn Clock>,
        max_size: u64,
        mountinfo: &str,
    ) -> Result<(Self, Volume), String> {
        let root = inbox.join("uploads");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)
            .map_err(|e| format!("{}: {e}", root.display()))?;
        let volume = mount::check_staging_volume(&root, data_dir, mountinfo)?;
        Ok((
            Self {
                root,
                clock,
                max_size,
            },
            volume,
        ))
    }

    /// [`Self::open_with_mounts`] with the real mount table.
    pub fn open(
        inbox: &Path,
        data_dir: &Path,
        clock: Arc<dyn Clock>,
        max_size: u64,
    ) -> Result<(Self, Volume), String> {
        let mountinfo = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        Self::open_with_mounts(inbox, data_dir, clock, max_size, &mountinfo)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn dir(&self, id: &UploadId) -> PathBuf {
        self.root.join(id.as_str())
    }

    fn read_meta(&self, id: &UploadId) -> Result<Meta, ApiError> {
        let text = fs::read_to_string(self.dir(id).join(META)).map_err(|_| not_found())?;
        serde_json::from_str(&text).map_err(|_| not_found())
    }

    fn write_meta(&self, meta: &Meta) -> Result<(), ApiError> {
        let id = UploadId::try_from(meta.upload_id.clone()).map_err(io)?;
        let path = self.dir(&id).join(META);
        let temp = path.with_extension("tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp)
            .map_err(io)?;
        file.write_all(serde_json::to_string(meta).map_err(io)?.as_bytes())
            .map_err(io)?;
        file.sync_all().map_err(io)?;
        fs::rename(&temp, &path).map_err(io)
    }

    /// The upload of `client`, if it exists and has not expired. An upload of
    /// another client is `not_found`: its id is not a secret between clients
    /// of one node, but it is not theirs to use.
    fn live(&self, id: &UploadId, client: &str) -> Result<Meta, ApiError> {
        let meta = self.read_meta(id)?;
        let expires = meta
            .sealed
            .as_ref()
            .map_or(meta.expires_ms, |s| s.expires_ms);
        if meta.client_id != client || self.clock.now_ms() >= expires {
            return Err(not_found());
        }
        Ok(meta)
    }

    fn open_count(&self, client: &str) -> usize {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return 0;
        };
        entries
            .flatten()
            .filter_map(|entry| fs::read_to_string(entry.path().join(META)).ok())
            .filter_map(|text| serde_json::from_str::<Meta>(&text).ok())
            .filter(|meta| meta.client_id == client && meta.sealed.is_none())
            .count()
    }

    /// `upload.begin`.
    pub fn begin(&self, client: &str, params: &UploadBeginParams) -> Result<UploadBegun, ApiError> {
        if params.size == 0 {
            return Err(ApiError::invalid_argument(
                "size",
                "an upload has at least one byte",
            ));
        }
        if params.size > self.max_size {
            return Err(ApiError::new(
                ErrorCode::PayloadTooLarge,
                format!(
                    "{} bytes is above the {} byte limit",
                    params.size, self.max_size
                ),
            )
            .with_field("size"));
        }
        if let Some(name) = &params.name
            && !valid_name(name)
        {
            return Err(ApiError::invalid_argument(
                "name",
                "1 to 128 bytes, no `/`, no NUL, no control character",
            ));
        }
        if self.open_count(client) >= MAX_OPEN_PER_CLIENT {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "too many uploads in progress; finish or wait for them to expire",
            ));
        }
        let now = self.clock.now_ms();
        let id = new_upload_id(now);
        let dir = self.dir(&id);
        fs::DirBuilder::new().mode(0o700).create(&dir).map_err(io)?;
        File::create_new_private(&dir.join(DATA)).map_err(io)?;
        self.write_meta(&Meta {
            upload_id: id.to_string(),
            client_id: client.to_owned(),
            name: params.name.clone(),
            size: params.size,
            sha256: params.sha256.as_ref().map(ToString::to_string),
            created_ms: now,
            expires_ms: now + UPLOAD_TTL_MS,
            sealed: None,
        })?;
        Ok(UploadBegun {
            upload_id: id,
            max_chunk: MAX_CHUNK,
        })
    }

    /// `upload.put`: strictly sequential, `offset` must equal what was
    /// received.
    pub fn put(
        &self,
        client: &str,
        id: &UploadId,
        offset: u64,
        bytes: &[u8],
    ) -> Result<UploadReceived, ApiError> {
        let meta = self.live(id, client)?;
        if meta.sealed.is_some() {
            return Err(ApiError::new(ErrorCode::Conflict, "the upload is finished"));
        }
        if bytes.len() as u64 > MAX_CHUNK {
            return Err(ApiError::new(
                ErrorCode::PayloadTooLarge,
                format!("a chunk is at most {MAX_CHUNK} bytes"),
            )
            .with_field("data"));
        }
        let path = self.dir(id).join(DATA);
        let mut file = open_nofollow(&path, true).map_err(io)?;
        let received = file.metadata().map_err(io)?.len();
        if offset != received {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                format!("offset {offset} is not the {received} bytes received"),
            )
            .with_field("offset")
            .with_detail("received", received.into()));
        }
        if received + bytes.len() as u64 > meta.size {
            return Err(ApiError::new(
                ErrorCode::PayloadTooLarge,
                "more bytes than the size given at upload.begin",
            )
            .with_field("data"));
        }
        file.write_all(bytes).map_err(io)?;
        Ok(UploadReceived {
            received: received + bytes.len() as u64,
        })
    }

    /// `upload.finish`: all the bytes are there, the hash matches what was
    /// declared; the file is sealed (read-only) and its SHA-256 recorded. A
    /// second call returns the same answer.
    pub fn finish(&self, client: &str, id: &UploadId) -> Result<UploadFinished, ApiError> {
        let mut meta = self.live(id, client)?;
        let now = self.clock.now_ms();
        if let Some(sealed) = &meta.sealed {
            return Ok(finished(id, sealed));
        }
        let path = self.dir(id).join(DATA);
        let mut file = open_nofollow(&path, false).map_err(io)?;
        let info = file.metadata().map_err(io)?;
        if !info.is_file() {
            return Err(io("the staged file is not a regular file"));
        }
        if info.len() != meta.size {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                format!("{} of {} bytes received", info.len(), meta.size),
            ));
        }
        let mut hasher = Sha256::new();
        let mut block = vec![0u8; 1 << 16];
        loop {
            let read = file.read(&mut block).map_err(io)?;
            if read == 0 {
                break;
            }
            hasher.update(&block[..read]);
        }
        let sha256: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if let Some(declared) = &meta.sha256
            && *declared != sha256
        {
            return Err(ApiError::invalid_argument(
                "sha256",
                "the bytes do not match the SHA-256 given at upload.begin",
            ));
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).map_err(io)?;
        let sealed = Sealed {
            sha256,
            size: info.len(),
            expires_ms: now + UPLOAD_TTL_MS,
        };
        meta.sealed = Some(sealed.clone());
        self.write_meta(&meta)?;
        Ok(finished(id, &sealed))
    }

    /// A sealed upload of `client` for intake.
    pub fn sealed(&self, client: &str, id: &UploadId) -> Result<StagedUpload, ApiError> {
        let meta = self.live(id, client)?;
        let sealed = meta.sealed.ok_or_else(|| {
            ApiError::new(ErrorCode::PreconditionFailed, "the upload is not finished")
        })?;
        Ok(StagedUpload {
            upload_id: id.clone(),
            path: self.dir(id).join(DATA),
            sha256: sealed.sha256,
            size: sealed.size,
            name: meta.name,
        })
    }

    /// Delete an upload's directory (after intake).
    pub fn discard(&self, id: &UploadId) {
        let _ = fs::remove_dir_all(self.dir(id));
    }

    /// The upload folders past their time.
    fn expired_dirs(&self) -> Vec<PathBuf> {
        let now = self.clock.now_ms();
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Vec::new();
        };
        entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                let meta = fs::read_to_string(path.join(META))
                    .ok()
                    .and_then(|text| serde_json::from_str::<Meta>(&text).ok());
                meta.is_none_or(|meta| {
                    now >= meta
                        .sealed
                        .as_ref()
                        .map_or(meta.expires_ms, |s| s.expires_ms)
                })
            })
            .collect()
    }

    /// How many uploads are past their time (a dry run of [`Self::expire`]).
    pub fn expired_count(&self) -> usize {
        self.expired_dirs().len()
    }

    /// Delete uploads past their time. Returns how many.
    pub fn expire(&self) -> usize {
        self.expired_dirs()
            .into_iter()
            .filter(|path| fs::remove_dir_all(path).is_ok())
            .count()
    }
}

fn finished(id: &UploadId, sealed: &Sealed) -> UploadFinished {
    UploadFinished {
        upload_id: id.clone(),
        sha256: Sha256Hex::try_from(sealed.sha256.clone()).expect("a hex digest"),
        size: sealed.size,
        expires_ms: sealed.expires_ms,
    }
}

/// Open a file without following a symlink and without blocking on a FIFO.
pub(super) fn open_nofollow(path: &Path, append: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    if append {
        options.append(true);
    } else {
        options.read(true);
    }
    options
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC).bits() as i32)
        .open(path)
}

trait CreateNewPrivate {
    fn create_new_private(path: &Path) -> std::io::Result<File>;
}

impl CreateNewPrivate for File {
    fn create_new_private(path: &Path) -> std::io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
}
