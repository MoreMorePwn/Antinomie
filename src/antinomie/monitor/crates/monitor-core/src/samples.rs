// SPDX-License-Identifier: GPL-3.0-only
//! Malware samples from MalwareBazaar (abuse.ch) and MalShare, for running in
//! a VM.
//!
//! Antinomie hosts no samples: it searches a source with the user's own API
//! key and downloads a sample on request. MalwareBazaar serves an encrypted
//! archive (AES, password `infected`), kept as is in `<data>/samples`;
//! MalShare serves the file itself, which is held in memory only and written
//! straight into the same kind of archive. A sample is only ever decrypted in
//! memory, to check its SHA-256 and to stream it into a guest. It is never
//! written to, unpacked on or run on the host.
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
};

mod activity;
mod archive;
mod chain;
mod chain_check;
mod chain_export;
mod custody;
mod delete_run;
mod intake;
mod kept;
mod library;
mod lineage;
mod migrate;
mod notes;
pub mod promote;
mod rollup;
mod runlog;
mod similar;
mod summary;

pub use archive::Verification;
pub use chain::{ChainedEvents, CustodyQuery, GlobalRow, LibraryCheck};
pub use chain_check::{
    ChainCheck, Entry as CustodyEntry, EntryState, IndexCheck, IndexRecord, Problem, short,
};
pub use chain_export::{
    Exported, Format as ExportFormat, RecordCheck, SSH_NAMESPACE, SignWith, Signer, VERIFIER,
    VERIFIER_NAME, sign_file, verify_record,
};
pub use custody::{ActionKind, CustodyEvent, CustodySink, KINDS, NoCustody};
pub use delete_run::{
    Deleted as DeletedRun, PROCESS_TREE_FILE, Place as ArtifactPlace, PlanItem as RunPlanItem,
    RunPlan, SavedTree, delete as delete_run, plan as plan_run_deletion, saved_process_tree,
};
pub use intake::{Added, FileProbe, NewSample, detect_type};
pub use kept::{
    ArtifactKind, Fate as ArtifactFate, KeptArtifact, SAVED_FILE, SavedItem, SavedKind,
    artifact_sha256, record_saved, saved_items, short_hash,
};
pub use library::{
    Alias, CATEGORIES, EventRow, Library, NewOrigin, Origin, OriginKind, RunStats, SampleRecord,
    SeenRun, TAG_COLORS, Tag, TagKind, VERDICTS,
};
pub use lineage::{
    Edge as LineageEdge, EdgeKind, Graph as LineageGraph, Known, Link, Node as LineageNode,
    NodeKind, Options as LineageOptions, RunLineage, build as build_lineage, runs_label,
    system_path,
};
pub use notes::{
    MAX_NOTE, MAX_REFS, Note, NoteRef, RefKind, artifact_target, text_hash as note_text_hash,
};
pub use rollup::{
    CheckRow, EvasionRow, IndicatorRow, Rollup, RuleRow, RunInput, TacticRow, TechniqueRow, rollup,
    tactic_of,
};
pub use runlog::{RunLog, file_sha256};
pub use similar::{Shared, Similar};
pub use summary::{StringRow, defang, interesting_strings, regex_matches};

/// MalwareBazaar's API: every call is a POST with an `Auth-Key` header.
pub const BAZAAR_API: &str = "https://mb-api.abuse.ch/api/v1/";
/// Where a free API key is made.
pub const BAZAAR_KEYS: &str = "https://auth.abuse.ch/";
/// The password of MalwareBazaar's archives.
pub const ARCHIVE_PASSWORD: &str = "infected";
/// Samples larger than this are refused (decrypted in memory).
pub const MAX_SAMPLE: u64 = 256 * 1024 * 1024;

/// Where samples come from. Each takes the user's own API key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Source {
    #[default]
    MalwareBazaar,
    MalShare,
}

impl Source {
    pub const ALL: [Source; 2] = [Source::MalwareBazaar, Source::MalShare];
    pub fn label(self) -> &'static str {
        match self {
            Source::MalwareBazaar => "MalwareBazaar",
            Source::MalShare => "MalShare",
        }
    }
    /// Where a free API key is made.
    pub fn keys_url(self) -> &'static str {
        match self {
            Source::MalwareBazaar => BAZAAR_KEYS,
            Source::MalShare => crate::malshare::KEYS,
        }
    }
    /// One search box: empty lists the newest samples; see [`find`] and
    /// [`crate::malshare::find`].
    pub fn find(
        self,
        curl: &Path,
        key: &str,
        text: &str,
        limit: u32,
    ) -> Result<(String, Vec<SampleInfo>), String> {
        match self {
            Source::MalwareBazaar => find(curl, key, text, limit),
            Source::MalShare => crate::malshare::find(curl, key, text, limit),
        }
    }
    /// The newest samples of every type. MalwareBazaar lists its latest 100
    /// (without architectures); MalShare its last day's hashes.
    pub fn newest_all(
        self,
        curl: &Path,
        key: &str,
        limit: u32,
    ) -> Result<(String, Vec<SampleInfo>), String> {
        match self {
            Source::MalwareBazaar => Ok((
                "Newest uploads, all types (MalwareBazaar lists 100)".into(),
                search(curl, key, &Query::Recent, limit)?,
            )),
            Source::MalShare => crate::malshare::newest_all(curl, key, limit),
        }
    }
    /// Download one sample found in this source into the data folder.
    pub fn download(
        self,
        curl: &Path,
        key: &str,
        data_dir: &Path,
        info: &SampleInfo,
    ) -> Result<StoredSample, String> {
        match self {
            Source::MalwareBazaar => download(curl, key, data_dir, info),
            Source::MalShare => crate::malshare::download(curl, key, data_dir, info),
        }
    }
}

/// Folder of downloaded sample archives and their records.
pub fn samples_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("samples")
}

/// A MalwareBazaar search.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Query {
    /// The newest additions.
    Recent,
    Tag(String),
    /// Malware family, as MalwareBazaar names it (`Mirai`, `XorDDoS`).
    Signature(String),
    /// `elf`, `exe`, `sh`...
    FileType(String),
    /// SHA-256, SHA-1 or MD5.
    Hash(String),
}

impl Query {
    fn form(&self, limit: u32) -> Vec<(&'static str, String)> {
        let limit = limit.clamp(1, 1000).to_string();
        match self {
            Query::Recent => vec![("query", "get_recent".into()), ("selector", "100".into())],
            Query::Tag(tag) => vec![
                ("query", "get_taginfo".into()),
                ("tag", tag.trim().into()),
                ("limit", limit),
            ],
            Query::Signature(name) => vec![
                ("query", "get_siginfo".into()),
                ("signature", name.trim().into()),
                ("limit", limit),
            ],
            Query::FileType(kind) => vec![
                ("query", "get_file_type".into()),
                ("file_type", kind.trim().into()),
                ("limit", limit),
            ],
            Query::Hash(hash) => vec![("query", "get_info".into()), ("hash", hash.trim().into())],
        }
    }
}

/// A sample as MalwareBazaar lists it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SampleInfo {
    pub sha256_hash: String,
    /// Empty when an older saved record has no SHA-1.
    #[serde(default)]
    pub sha1_hash: String,
    pub md5_hash: String,
    pub file_name: String,
    pub file_size: u64,
    pub file_type: String,
    pub file_type_mime: String,
    /// Malware family.
    pub signature: Option<String>,
    #[serde(deserialize_with = "null_as_empty")]
    pub tags: Vec<String>,
    pub first_seen: String,
    pub reporter: String,
    /// CPU architecture (hash lookups only), such as `x86_64` or `ARM`.
    pub file_arch: Option<String>,
}

fn null_as_empty<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    Ok(Option::<Vec<String>>::deserialize(d)?.unwrap_or_default())
}

impl SampleInfo {
    /// An ELF file, as MalwareBazaar's file type says.
    pub fn is_elf(&self) -> bool {
        self.file_type.eq_ignore_ascii_case("elf")
    }
    /// A shell script (MalwareBazaar's `sh`): droppers and installers that
    /// fetch the real payload. It runs in the guests through /bin/sh.
    pub fn is_script(&self) -> bool {
        matches!(self.file_type.to_ascii_lowercase().as_str(), "sh" | "bash")
    }
    /// Runs in Antinomie's x86-64 guests: a shell script, an x86-64 ELF, or
    /// an ELF whose architecture the source does not list (checked after
    /// download).
    pub fn may_run(&self) -> bool {
        self.is_script()
            || self.is_elf()
                && self.file_arch.as_deref().is_none_or(|arch| {
                    matches!(
                        arch.to_ascii_lowercase().as_str(),
                        "x86_64" | "amd64" | "x86-64"
                    )
                })
    }
}

#[derive(Deserialize)]
struct Reply {
    query_status: String,
    /// The samples, or on an error MalwareBazaar's message.
    #[serde(default)]
    data: Option<serde_json::Value>,
}

/// What MalwareBazaar answered, in words.
fn status_text(status: &str) -> String {
    match status {
        "no_results" | "tag_not_found" | "signature_not_found" | "hash_not_found" => {
            "nothing found".into()
        }
        "unknown_auth_key" | "wrong_auth_key" | "user_blacklisted" | "missing_auth_key" => {
            "MalwareBazaar refused the API key".into()
        }
        "file_not_found" => "MalwareBazaar has no such sample".into(),
        "illegal_hash"
        | "illegal_sha256_hash"
        | "illegal_tag"
        | "illegal_signature"
        | "illegal_file_type" => format!("MalwareBazaar did not accept the search ({status})"),
        other => format!("MalwareBazaar: {other}"),
    }
}

/// Parse a search reply; "nothing found" is an empty list.
pub fn parse_reply(body: &[u8]) -> Result<Vec<SampleInfo>, String> {
    let reply: Reply = serde_json::from_slice(body).map_err(|e| {
        // Not JSON: an error page or a busy server. Show how it starts.
        let start: String = String::from_utf8_lossy(body)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .filter(|c| !c.is_control())
            .take(160)
            .collect();
        if start.is_empty() {
            "MalwareBazaar sent an empty reply; try again".to_string()
        } else {
            format!("MalwareBazaar reply is not JSON ({e}): {start}")
        }
    })?;
    match reply.query_status.as_str() {
        "ok" => match reply.data {
            Some(data) => {
                serde_json::from_value(data).map_err(|e| format!("MalwareBazaar reply: {e}"))
            }
            None => Ok(Vec::new()),
        },
        "no_results" | "tag_not_found" | "signature_not_found" | "hash_not_found" => Ok(Vec::new()),
        status => Err(match reply.data {
            // "Query execution time exceeded threshold. Try a different query."
            Some(serde_json::Value::String(message)) if !message.trim().is_empty() => {
                format!("MalwareBazaar: {}", message.trim())
            }
            _ => status_text(status),
        }),
    }
}

/// A curl POST to MalwareBazaar; the key is passed on stdin, never on the
/// command line where other processes could read it.
fn post(
    curl: &Path,
    key: &str,
    form: &[(&str, String)],
    output: Option<&Path>,
) -> Result<Vec<u8>, String> {
    crate::dependencies::require_tool(curl, "curl")?;
    if key.trim().is_empty() || key.contains(['\r', '\n']) {
        return Err("set a MalwareBazaar API key first".into());
    }
    // The reply carries its own status text, so HTTP errors are not failures.
    let mut command = crate::http_fetch::command(
        curl,
        &crate::http_fetch::Options {
            fail: false,
            ..crate::http_fetch::Options::new(300, MAX_SAMPLE + (1 << 20))
        },
    );
    command.args(["-X", "POST", "-H", "@-"]);
    for (name, value) in form {
        command
            .arg("--data-urlencode")
            .arg(format!("{name}={value}"));
    }
    if let Some(path) = output {
        command.arg("-o").arg(path);
    }
    let mut child = command
        .arg(BAZAAR_API)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("curl: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = writeln!(stdin, "Auth-Key: {}", key.trim());
    }
    let done = child.wait_with_output().map_err(|e| format!("curl: {e}"))?;
    if !done.status.success() {
        let message = String::from_utf8_lossy(&done.stderr);
        return Err(format!(
            "MalwareBazaar: {}",
            message.lines().last().unwrap_or("request failed").trim()
        ));
    }
    Ok(done.stdout)
}

/// Search MalwareBazaar (at most `limit` samples, 1 to 1000).
pub fn search(
    curl: &Path,
    key: &str,
    query: &Query,
    limit: u32,
) -> Result<Vec<SampleInfo>, String> {
    parse_reply(&post(curl, key, &query.form(limit), None)?)
}

/// A SHA-256, SHA-1 or MD5 in hex.
fn is_hash(text: &str) -> bool {
    matches!(text.len(), 32 | 40 | 64) && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// One search box: empty lists the newest ELF samples (what the guests run,
/// with their architectures), a hash looks that sample up, and a word is
/// tried as a family, then a tag, then a file type. Returns what was
/// searched, in words, and the samples.
pub fn find(
    curl: &Path,
    key: &str,
    text: &str,
    limit: u32,
) -> Result<(String, Vec<SampleInfo>), String> {
    let text = text.trim();
    if text.is_empty() {
        // What the guests run: ELF programs and shell scripts, newest first.
        // MalwareBazaar lists at most 100 per file type, whatever the limit;
        // families and tags go to 1000.
        let mut found = search(curl, key, &Query::FileType("elf".into()), limit)?;
        found.extend(search(curl, key, &Query::FileType("sh".into()), limit)?);
        found.sort_by(|a, b| b.first_seen.cmp(&a.first_seen));
        return Ok((
            "Newest Linux samples: ELF and shell scripts (MalwareBazaar lists 100 of each; \
             search a family for up to 1000)"
                .into(),
            found,
        ));
    }
    if is_hash(text) {
        return Ok((
            format!("Hash {text}"),
            search(curl, key, &Query::Hash(text.into()), limit)?,
        ));
    }
    let family = search(curl, key, &Query::Signature(text.into()), limit)?;
    if !family.is_empty() {
        return Ok((format!("Family {text}"), family));
    }
    // A tag as large as `elf` can be more than MalwareBazaar answers in time;
    // the file type may still answer.
    let tag = search(curl, key, &Query::Tag(text.into()), limit);
    if let Ok(found) = &tag
        && !found.is_empty()
    {
        return Ok((format!("Tag {text}"), found.clone()));
    }
    match search(curl, key, &Query::FileType(text.into()), limit) {
        Ok(found) if !found.is_empty() => Ok((format!("File type {text}"), found)),
        _ => tag.map(|found| (format!("{text}: no family, tag or file type"), found)),
    }
}

/// An architecture as people write it, from MalwareBazaar's names (`X86_64`,
/// `I386`, `PPC`) or [`elf_arch`]'s.
pub fn arch_label(arch: &str) -> String {
    match arch.to_ascii_lowercase().as_str() {
        "x86_64" | "x86-64" | "amd64" => "x86-64".into(),
        "i386" | "x86" | "i686" | "80386" => "x86".into(),
        "arm" => "ARM".into(),
        "aarch64" | "arm64" => "AArch64".into(),
        "mips" => "MIPS".into(),
        "ppc" | "powerpc" | "ppc64" => "PowerPC".into(),
        "sh" | "superh" => "SuperH".into(),
        "m68k" => "m68k".into(),
        "sparc" => "SPARC".into(),
        "risc-v" | "riscv" => "RISC-V".into(),
        _ => arch.into(),
    }
}

/// A sample as Tools › Malware samples lists it: its source's record, where
/// it came from and where it went. Read from the [`Library`]; records of
/// this shape made by earlier versions are migrated into it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StoredSample {
    pub info: SampleInfo,
    pub source: String,
    /// Milliseconds since the Unix epoch.
    pub downloaded_ms: u64,
    /// Every time it was sent into a VM.
    pub pushes: Vec<Push>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Push {
    pub vm_id: String,
    pub vm_name: String,
    pub path: String,
    pub at_ms: u64,
}

/// The library sample a run executed, as the run record names it. The SHA-256
/// is of the bytes the library archived before the program started.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SampleRef {
    pub sha256: String,
    /// The name the sample had when the run started.
    pub name: String,
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_millis() as u64)
}

fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Where the archive of a sample is: `samples/ab/<sha256>.zip`.
pub fn archive_path(data_dir: &Path, sha256: &str) -> Result<PathBuf, String> {
    archive::shard_path(&samples_dir(data_dir), sha256)
}

/// The sample inside an archive, decrypted in memory and checked against its
/// SHA-256; nothing is written to disk.
pub fn open_sample(archive: &Path, sha256: &str) -> Result<Vec<u8>, String> {
    use sha2::{Digest, Sha256};
    let file = fs::File::open(archive).map_err(|e| format!("{}: {e}", archive.display()))?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| format!("sample archive: {e}"))?;
    if zip.len() != 1 {
        return Err(format!(
            "the archive holds {} files, not one sample",
            zip.len()
        ));
    }
    let mut entry = zip
        .by_index_decrypt(0, ARCHIVE_PASSWORD.as_bytes())
        .map_err(|e| format!("sample archive: {e}"))?;
    if entry.size() > MAX_SAMPLE {
        return Err(format!(
            "the sample is larger than {} MiB",
            MAX_SAMPLE >> 20
        ));
    }
    let mut bytes = Vec::with_capacity(entry.size() as usize);
    entry
        .by_ref()
        .take(MAX_SAMPLE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("sample archive: {e}"))?;
    let digest: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if !digest.eq_ignore_ascii_case(sha256) {
        return Err("the sample does not match its SHA-256".into());
    }
    Ok(bytes)
}

/// The architecture an ELF header names, for the record.
pub fn elf_arch(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() < 20 || &bytes[..4] != b"\x7fELF" {
        return None;
    }
    let little = bytes[5] == 1;
    let machine = if little {
        u16::from_le_bytes([bytes[18], bytes[19]])
    } else {
        u16::from_be_bytes([bytes[18], bytes[19]])
    };
    Some(match machine {
        0x3e => "x86_64",
        0x03 => "x86",
        0x28 => "ARM",
        0xb7 => "AArch64",
        0x08 => "MIPS",
        0x14 | 0x15 => "PowerPC",
        0x2b => "SPARC",
        0xf3 => "RISC-V",
        0x2a => "SuperH",
        0x04 => "m68k",
        _ => "other",
    })
}

/// Download one sample's archive, check it and add it to the library.
pub fn download(
    curl: &Path,
    key: &str,
    data_dir: &Path,
    info: &SampleInfo,
) -> Result<StoredSample, String> {
    if !is_sha256(&info.sha256_hash) {
        return Err(format!("not a SHA-256: {:?}", info.sha256_hash));
    }
    let dir = samples_dir(data_dir);
    crate::storage::private_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let partial = dir.join(format!(
        "{}.zip.part",
        info.sha256_hash.to_ascii_lowercase()
    ));
    let form = [
        ("query", "get_file".to_owned()),
        ("sha256_hash", info.sha256_hash.to_ascii_lowercase()),
    ];
    let result = (|| {
        post(curl, key, &form, Some(&partial))?;
        let body = fs::read(&partial).map_err(|e| e.to_string())?;
        if body.first() == Some(&b'{') {
            // An error answered as JSON instead of the archive.
            return Err(parse_reply(&body)
                .err()
                .unwrap_or_else(|| "MalwareBazaar sent no archive".into()));
        }
        drop(body);
        let bytes = open_sample(&partial, &info.sha256_hash)?;
        store_bytes(data_dir, info, &bytes, "MalwareBazaar")
    })();
    let _ = fs::remove_file(&partial);
    result
}

/// Keep a sample held in memory (`bytes`, already checked against its
/// SHA-256) in the library as a download from `source`: an AES archive with
/// the password `infected`, owner-only, with its record. Nothing unencrypted
/// is written.
pub fn store_bytes(
    data_dir: &Path,
    info: &SampleInfo,
    bytes: &[u8],
    source: &str,
) -> Result<StoredSample, String> {
    let mut library = Library::open(data_dir)?;
    let mut info = info.clone();
    if let Some(arch) = elf_arch(bytes) {
        info.file_arch = Some(arch.into());
    }
    if info.file_size == 0 {
        info.file_size = bytes.len() as u64;
    }
    let added = library.add_bytes(
        bytes,
        NewSample {
            name: info.file_name.clone(),
            origin: NewOrigin {
                kind: OriginKind::Download,
                source: source.into(),
                name: info.file_name.clone(),
                ..NewOrigin::default()
            },
            info: Some(info),
            ..NewSample::default()
        },
    )?;
    library
        .get(&added.sha256)?
        .map(|record| stored_from(&library, record))
        .ok_or_else(|| "the sample was not kept".into())
}

/// A library entry as the Tools window lists it.
fn stored_from(library: &Library, record: SampleRecord) -> StoredSample {
    let origins = library.origins(&record.sha256).unwrap_or_default();
    let mut info = record.info.clone();
    info.sha256_hash = record.sha256.clone();
    info.sha1_hash.clone_from(&record.sha1);
    info.md5_hash.clone_from(&record.md5);
    info.file_name.clone_from(&record.name);
    info.file_size = record.size;
    if info.file_type.is_empty() {
        info.file_type.clone_from(&record.file_type);
    }
    if info.file_arch.is_none() && !record.arch.is_empty() {
        info.file_arch = Some(record.arch.clone());
    }
    if info.signature.is_none() && !record.family.is_empty() {
        info.signature = Some(record.family.clone());
    }
    StoredSample {
        source: origins
            .first()
            .map(|origin| {
                if origin.source.is_empty() {
                    origin.kind.label().to_owned()
                } else {
                    origin.source.clone()
                }
            })
            .unwrap_or_default(),
        downloaded_ms: record.added_ms,
        pushes: library.pushes(&record.sha256).unwrap_or_default(),
        info,
    }
}

/// The samples in the library that have an archive, newest first.
pub fn stored(data_dir: &Path) -> Vec<StoredSample> {
    let Ok(library) = Library::open(data_dir) else {
        return Vec::new();
    };
    let mut found: Vec<StoredSample> = library
        .list()
        .unwrap_or_default()
        .into_iter()
        .filter(|record| {
            record.removed_ms.is_none()
                && library
                    .archive_path(&record.sha256)
                    .is_ok_and(|path| path.is_file())
        })
        .map(|record| stored_from(&library, record))
        .collect();
    found.sort_by_key(|sample| std::cmp::Reverse(sample.downloaded_ms));
    found
}

/// Note that a sample was sent into a VM.
pub fn record_push(data_dir: &Path, sha256: &str, push: Push) -> Result<(), String> {
    Library::open(data_dir)?.record_push(sha256, push)
}

/// Remove a sample's archive. Its record, origins and events stay in the
/// library (see [`Library::remove`]).
pub fn delete(data_dir: &Path, sha256: &str) -> Result<(), String> {
    Library::open(data_dir)?.remove(sha256)
}

/// Bumped when the warning shown before first use says something new, so it
/// is shown again.
pub const WARNING_VERSION: u32 = 1;
const ACKNOWLEDGED_FILE: &str = "acknowledged.json";

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Acknowledged {
    version: u32,
    at_ms: u64,
}

/// The user accepted the current warning about live malware in this data folder.
pub fn acknowledged(data_dir: &Path) -> bool {
    fs::read(samples_dir(data_dir).join(ACKNOWLEDGED_FILE))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Acknowledged>(&bytes).ok())
        .is_some_and(|seen| seen.version >= WARNING_VERSION)
}

pub fn acknowledge(data_dir: &Path) -> Result<(), String> {
    let dir = samples_dir(data_dir);
    crate::storage::private_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    crate::storage::atomic_json(
        &dir.join(ACKNOWLEDGED_FILE),
        &Acknowledged {
            version: WARNING_VERSION,
            at_ms: unix_ms(),
        },
    )
}

/// A source's API key (see [`crate::api_keys`]), or an empty string.
pub fn source_key(data_dir: &Path, source: Source) -> String {
    crate::api_keys::get(data_dir, source_api_key(source))
        .expose()
        .to_owned()
}

/// The saved key that serves a source.
pub fn source_api_key(source: Source) -> crate::api_keys::ApiKey {
    match source {
        Source::MalwareBazaar => crate::api_keys::ApiKey::Abusech,
        Source::MalShare => crate::api_keys::ApiKey::MalShare,
    }
}

/// The MalwareBazaar API key (see [`source_key`]).
pub fn api_key(data_dir: &Path) -> String {
    source_key(data_dir, Source::MalwareBazaar)
}

pub fn save_api_key(data_dir: &Path, key: &str) -> Result<(), String> {
    save_source_key(data_dir, Source::MalwareBazaar, key)
}

pub fn save_source_key(data_dir: &Path, source: Source, key: &str) -> Result<(), String> {
    crate::api_keys::set(data_dir, source_api_key(source), key)
}

/// Searches worth trying for samples that run in the x86-64 guests.
pub const STARTERS: &[(&str, &str)] = &[
    (
        "XorDDoS",
        "DDoS botnet with a rootkit, x86-64 builds common",
    ),
    ("Kinsing", "cryptominer dropper attacking container hosts"),
    ("BPFDoor", "passive backdoor using a BPF socket filter"),
    (
        "Mirai",
        "IoT botnet; pick x86-64 builds, most are ARM or MIPS",
    ),
    ("Gafgyt", "IoT DDoS botnet; pick x86-64 builds"),
    ("Tsunami", "IRC DDoS bot (Kaiten)"),
    ("CoinMiner", "XMRig-based miners"),
];

#[cfg(test)]
mod chain_tests;
#[cfg(test)]
mod feature_tests;
#[cfg(test)]
mod library_tests;
#[cfg(test)]
mod runlog_tests;
#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "ant-samples-{name}-{}",
            crate::storage::unique_id()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn sha256(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// An archive as MalwareBazaar makes them: one AES-encrypted file.
    fn archive(path: &Path, name: &str, bytes: &[u8]) {
        use zip::write::SimpleFileOptions;
        let mut writer = zip::ZipWriter::new(fs::File::create(path).unwrap());
        writer
            .start_file(
                name,
                SimpleFileOptions::default()
                    .with_aes_encryption(zip::AesMode::Aes128, ARCHIVE_PASSWORD),
            )
            .unwrap();
        writer.write_all(bytes).unwrap();
        writer.finish().unwrap();
    }

    #[test]
    fn search_replies_are_parsed_with_missing_fields() {
        let body = br#"{"query_status":"ok","data":[{"sha256_hash":"ab","file_name":"x.elf",
            "file_size":12,"file_type":"elf","signature":"Mirai","tags":null,
            "first_seen":"2026-10-01 10:00:00","unknown":1}]}"#;
        let found = parse_reply(body).unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].tags.is_empty() && found[0].is_elf() && found[0].may_run());
        assert!(
            parse_reply(br#"{"query_status":"no_results"}"#)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            parse_reply(
                br#"{"query_status":"error","data":"Query execution time exceeded threshold. Try a different query."}"#
            ),
            Err(
                "MalwareBazaar: Query execution time exceeded threshold. Try a different query."
                    .into()
            )
        );
        assert!(
            parse_reply(br#"{"query_status":"unknown_auth_key"}"#)
                .unwrap_err()
                .contains("API key")
        );
        let arm = SampleInfo {
            file_type: "elf".into(),
            file_arch: Some("ARM".into()),
            ..SampleInfo::default()
        };
        assert!(!arm.may_run());
    }

    #[test]
    fn queries_become_bazaar_forms() {
        let form = Query::Signature(" XorDDoS ".into()).form(5000);
        assert_eq!(form[0], ("query", "get_siginfo".into()));
        assert_eq!(form[1], ("signature", "XorDDoS".into()));
        assert_eq!(form[2], ("limit", "1000".into()));
    }

    #[test]
    fn samples_are_opened_in_memory_and_checked() {
        let root = temp("open");
        let sample = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x02\0\x3e\0rest of a program";
        let path = root.join("a.zip");
        archive(&path, "a.elf", sample);
        assert_eq!(open_sample(&path, &sha256(sample)).unwrap(), sample);
        assert!(open_sample(&path, &"0".repeat(64)).is_err());
        assert_eq!(elf_arch(sample), Some("x86_64"));
        assert_eq!(elf_arch(b"MZ"), None);
        // Only the archive is on disk.
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stored_samples_keep_their_record_and_pushes() {
        let root = temp("stored");
        let bytes = b"sample";
        let hash = sha256(bytes);
        let info = SampleInfo {
            sha256_hash: hash.clone(),
            ..SampleInfo::default()
        };
        store_bytes(&root, &info, bytes, "MalwareBazaar").unwrap();
        record_push(
            &root,
            &hash,
            Push {
                vm_id: "vm".into(),
                path: "/tmp/s".into(),
                ..Push::default()
            },
        )
        .unwrap();
        let found = stored(&root);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].pushes[0].path, "/tmp/s");
        assert_eq!(found[0].source, "MalwareBazaar");
        assert!(archive_path(&root, "../x").is_err());
        delete(&root, &hash).unwrap();
        assert!(stored(&root).is_empty());
        save_api_key(&root, " key ").unwrap();
        save_source_key(&root, Source::MalShare, "share").unwrap();
        assert_eq!(api_key(&root), "key");
        assert_eq!(source_key(&root, Source::MalShare), "share");
        // A sample held in memory is kept encrypted, never as itself.
        let plain = b"\x7fELF\x02\x01\x01 not really a program".to_vec();
        let info = SampleInfo {
            sha256_hash: sha256(&plain),
            ..SampleInfo::default()
        };
        let kept = store_bytes(&root, &info, &plain, "MalShare").unwrap();
        assert_eq!(
            (kept.source.as_str(), kept.info.file_size),
            ("MalShare", plain.len() as u64)
        );
        let archive = archive_path(&root, &info.sha256_hash).unwrap();
        assert_eq!(
            archive.parent().unwrap().file_name().unwrap().to_str(),
            Some(&info.sha256_hash[..2])
        );
        let on_disk = fs::read(&archive).unwrap();
        assert!(!on_disk.windows(plain.len()).any(|window| window == plain));
        assert_eq!(open_sample(&archive, &info.sha256_hash).unwrap(), plain);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn shell_scripts_and_x86_64_programs_run_in_the_guests() {
        let sample = |kind: &str, arch: Option<&str>| SampleInfo {
            file_type: kind.into(),
            file_arch: arch.map(str::to_owned),
            ..SampleInfo::default()
        };
        assert!(sample("sh", None).may_run() && sample("sh", None).is_script());
        assert!(sample("elf", Some("X86_64")).may_run() && sample("elf", None).may_run());
        assert!(!sample("elf", Some("ARM")).may_run() && !sample("exe", None).may_run());
    }

    #[test]
    fn hashes_and_architectures_are_recognised() {
        assert!(is_hash(&"a".repeat(64)) && is_hash(&"0".repeat(32)));
        assert!(!is_hash("Mirai") && !is_hash(&"g".repeat(64)));
        for (raw, label) in [
            ("X86_64", "x86-64"),
            ("x86_64", "x86-64"),
            ("I386", "x86"),
            ("PPC", "PowerPC"),
            ("SH", "SuperH"),
            ("AARCH64", "AArch64"),
            ("VAX", "VAX"),
        ] {
            assert_eq!(arch_label(raw), label);
        }
    }

    #[test]
    fn the_warning_is_accepted_once_per_version() {
        let root = temp("warning");
        assert!(!acknowledged(&root));
        acknowledge(&root).unwrap();
        assert!(acknowledged(&root));
        // An older acceptance does not cover a newer warning.
        fs::write(
            samples_dir(&root).join(ACKNOWLEDGED_FILE),
            format!(r#"{{"version":{}}}"#, WARNING_VERSION - 1),
        )
        .unwrap();
        assert!(!acknowledged(&root));
        fs::remove_dir_all(root).unwrap();
    }
}
