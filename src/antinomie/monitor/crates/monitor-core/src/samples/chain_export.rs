// SPDX-License-Identifier: GPL-3.0-only
//! Exporting a sample's custody record, checking one, and signing it with
//! the analyst's own key.
//!
//! A JSON export carries the entries as stored (the event text is the text
//! that was hashed), the library index records about the sample, and the
//! result of the check at export time. `verify-custody.py`, written beside
//! it, recomputes everything from the entries alone. An HTML export is the
//! same JSON inside a readable page. A signature is made by the analyst's
//! own `minisign` or `ssh-keygen -Y sign` over the exported file; the app has
//! no key of its own, never reads the key file, and never asks for a
//! passphrase (a key that needs one must be loaded in an agent).
use super::{
    chain::row_of,
    chain_check::{ChainCheck, Entry, IndexRecord, check_record, short},
    custody::CustodyEvent,
    library::Library,
};
use serde_json::{Value, json};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// The python verifier bundled with every JSON export.
pub const VERIFIER: &str = include_str!("verify-custody.py");
/// The file name the verifier is written under.
pub const VERIFIER_NAME: &str = "verify-custody.py";
/// The namespace an SSH signature is made in.
pub const SSH_NAMESPACE: &str = "antinomie-custody";

const FORMAT: &str = "antinomie-custody-record";
const NOTICE: &str = "Tamper-evident, not tamper-proof. Editing, removing or reordering an \
entry is detected; someone who rewrites the whole chain and the library index together is not. \
Keep the head hash somewhere else, or sign the export, to rule that out.";
const HASH_RULE: &str = "SHA-256 over each field in order as <utf-8 byte length>:<field>\\n. \
Entry fields: antinomie-custody-entry-v1, sample sha256, seq, at_ms, by, kind, \
before_chain (0 or 1), detail, prev. Index fields: antinomie-custody-index-v1, seq, at_ms, \
kind, sha256, entry_seq, entry_hash, prev.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Json,
    Html,
}

impl Format {
    pub fn label(self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Html => "HTML",
        }
    }
    pub fn extension(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Html => "html",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signer {
    Minisign,
    Ssh,
}

/// The analyst's own key and the tool that signs with it.
#[derive(Clone, Debug)]
pub struct SignWith {
    pub signer: Signer,
    pub key: PathBuf,
}

/// What an export wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exported {
    pub path: PathBuf,
    pub verifier: Option<PathBuf>,
    pub signature: Option<PathBuf>,
    pub head: String,
    pub entries: u64,
    /// The chain verified when it was exported.
    pub verified: bool,
}

fn utc(ms: u64) -> String {
    let seconds = (ms / 1000) as i64;
    let (days, rest) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    // Civil date from a day count (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn entry_json(entry: &Entry) -> Value {
    json!({
        "seq": entry.seq, "at_ms": entry.at_ms, "by": entry.by, "kind": entry.kind,
        "before_chain": entry.before_chain, "detail": entry.detail,
        "prev": entry.prev, "hash": entry.hash,
    })
}

fn index_json(record: &IndexRecord) -> Value {
    json!({
        "seq": record.seq, "at_ms": record.at_ms, "kind": record.kind,
        "sha256": record.sha256, "entry_seq": record.entry_seq,
        "entry_hash": record.entry_hash, "prev": record.prev, "hash": record.hash,
    })
}

impl Library {
    /// The custody record of a sample as the value an export writes.
    pub fn custody_record(&self, sha256: &str) -> Result<(Value, ChainCheck), String> {
        let sha256 = sha256.to_ascii_lowercase();
        let record = self.get(&sha256)?;
        let entries = self.custody_entries(&sha256)?;
        let all = self.custody_index()?;
        let index: Vec<IndexRecord> = all
            .iter()
            .filter(|record| record.sha256 == sha256)
            .cloned()
            .collect();
        let check = self.custody_check(&sha256)?;
        let library = super::chain_check::check_index(&all);
        let (name, size, file_type) = record
            .map(|record| (record.name, record.size, record.file_type))
            .unwrap_or_default();
        let value = json!({
            "format": FORMAT,
            "version": 1,
            "notice": NOTICE,
            "hash_rule": HASH_RULE,
            "exported_ms": super::unix_ms(),
            "app": format!("Antinomie {}", crate::api::APP_VERSION),
            "sample": {"sha256": sha256, "name": name, "size": size, "file_type": file_type},
            "status": {
                "verified": check.ok(),
                "entries": check.entries,
                "head": check.head,
                "problem": check.problem,
            },
            "library_index": {
                "records": library.records,
                "head": library.head,
                "verified": library.problem.is_none(),
            },
            "entries": entries.iter().map(entry_json).collect::<Vec<_>>(),
            "index": index.iter().map(index_json).collect::<Vec<_>>(),
        });
        Ok((value, check))
    }

    /// Write the custody record of `sha256` to `dest` (a file path) in
    /// `format`, with the verifier beside a JSON export and a signature made
    /// with the analyst's own key when asked. The export is itself noted in
    /// the log, after the head it contains.
    pub fn export_custody(
        &mut self,
        sha256: &str,
        format: Format,
        dest: &Path,
        sign: Option<&SignWith>,
    ) -> Result<Exported, String> {
        let (value, check) = self.custody_record(sha256)?;
        let text = match format {
            Format::Json => serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?,
            Format::Html => render_html(&value, &check)?,
        };
        if let Some(dir) = dest.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        fs::write(dest, text).map_err(|e| format!("{}: {e}", dest.display()))?;
        let verifier = if format == Format::Json {
            let path = dest.with_file_name(VERIFIER_NAME);
            fs::write(&path, VERIFIER).map_err(|e| format!("{}: {e}", path.display()))?;
            Some(path)
        } else {
            None
        };
        let signature = match sign {
            Some(with) => match sign_file(with, dest, None) {
                Ok(path) => Some(path),
                Err(error) => {
                    // An unsigned file must not pass for a signed export.
                    let _ = fs::remove_file(dest);
                    return Err(error);
                }
            },
            None => None,
        };
        self.note(
            sha256,
            "analyst",
            CustodyEvent::Exported {
                format: format.label().into(),
                signed: match sign {
                    None => "unsigned".into(),
                    Some(with) => format!(
                        "signed with {}",
                        match with.signer {
                            Signer::Minisign => "minisign",
                            Signer::Ssh => "an SSH key",
                        }
                    ),
                },
                head: check.head.clone(),
            },
        )?;
        Ok(Exported {
            path: dest.to_path_buf(),
            verifier,
            signature,
            head: check.head.clone(),
            entries: check.entries,
            verified: check.ok(),
        })
    }
}

fn render_html(value: &Value, check: &ChainCheck) -> Result<String, String> {
    let entries: Vec<Entry> =
        serde_json::from_value(value["entries"].clone()).map_err(|e| e.to_string())?;
    let sample = &value["sample"];
    let mut rows = String::new();
    for entry in &entries {
        let state = match check.state_of(entry.seq) {
            super::chain_check::EntryState::Verified => "verified",
            super::chain_check::EntryState::Changed => "changed",
            super::chain_check::EntryState::Unverified => "unverified",
        };
        let (label, detail) = row_of(entry).map_or_else(
            || (entry.kind.clone(), entry.detail.clone()),
            |row| {
                (
                    row.event.label().to_owned(),
                    row.event.detail()
                        + if entry.before_chain {
                            " [recorded before the custody log]"
                        } else {
                            ""
                        },
                )
            },
        );
        rows.push_str(&format!(
            "<tr class=\"{state}\"><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
             <td>{state}</td><td class=\"mono\" title=\"previous {}\">{}</td></tr>\n",
            entry.seq,
            utc(entry.at_ms),
            escape(&label),
            escape(&entry.by),
            escape(&detail),
            escape(&entry.prev),
            escape(short(&entry.hash)),
        ));
    }
    let banner = match &check.problem {
        None => format!(
            "<p class=\"ok\"><b>Log verified when exported.</b> {} entries, every link matches. \
             Head <span class=\"mono\">{}</span></p>",
            check.entries,
            escape(&check.head)
        ),
        Some(problem) => format!(
            "<p class=\"bad\"><b>Log broken at entry {}.</b> {}. Entries from there on are \
             unverified.</p>",
            problem.at,
            escape(&problem.text)
        ),
    };
    // `<` as a JSON escape keeps the data from closing the script element.
    let json = serde_json::to_string(value)
        .map_err(|e| e.to_string())?
        .replace('<', "\\u003c");
    Ok(format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<title>Custody record {}</title>\n<style>\
body{{font:15px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:70rem;padding:0 1rem}}\
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #8884;padding:.3rem .5rem;\
text-align:left;vertical-align:top}}.mono{{font-family:ui-monospace,monospace}}\
.ok{{color:#176b2c}}.bad{{color:#b3261e}}tr.changed{{background:#b3261e22}}\
tr.unverified{{color:#8a5a00}}</style></head><body>\n\
<h1>Custody record: {}</h1>\n<p class=\"mono\">SHA-256 {}</p>\n{banner}\n\
<p><i>{}</i></p>\n\
<table><thead><tr><th>#</th><th>Time (UTC)</th><th>Event</th><th>By</th><th>Detail</th>\
<th>Check</th><th>Hash</th></tr></thead><tbody>\n{rows}</tbody></table>\n\
<p>The complete record is embedded below. Save it as a .json file, or give this page to \
<code>verify-custody.py</code>, to check it without Antinomie. Exported {} by {}.</p>\n\
<script type=\"application/json\" id=\"custody-record\">{json}</script>\n</body></html>\n",
        escape(sample["name"].as_str().unwrap_or("")),
        escape(sample["name"].as_str().unwrap_or("")),
        escape(sample["sha256"].as_str().unwrap_or("")),
        escape(NOTICE),
        utc(value["exported_ms"].as_u64().unwrap_or(0)),
        escape(value["app"].as_str().unwrap_or("Antinomie")),
    ))
}

/// What checking a record found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordCheck {
    pub sha256: String,
    pub check: ChainCheck,
}

/// Check an exported record (the JSON, or the HTML export) from its entries
/// alone, the way `verify-custody.py` does.
pub fn verify_record(text: &str) -> Result<RecordCheck, String> {
    const OPEN: &str = "<script type=\"application/json\" id=\"custody-record\">";
    let json = match text.find(OPEN) {
        Some(start) => {
            let rest = &text[start + OPEN.len()..];
            &rest[..rest
                .find("</script>")
                .ok_or("the embedded record is cut off")?]
        }
        None => text,
    };
    let value: Value = serde_json::from_str(json).map_err(|e| format!("not a record: {e}"))?;
    if value["format"] != FORMAT || value["version"] != 1 {
        return Err("not an Antinomie custody record (version 1)".into());
    }
    let sha256 = value["sample"]["sha256"]
        .as_str()
        .ok_or("the record names no sample")?
        .to_owned();
    let entries: Vec<Entry> =
        serde_json::from_value(value["entries"].clone()).map_err(|e| format!("entries: {e}"))?;
    let index: Vec<IndexRecord> =
        serde_json::from_value(value["index"].clone()).map_err(|e| format!("index: {e}"))?;
    Ok(RecordCheck {
        check: check_record(&sha256, &entries, &index),
        sha256,
    })
}

/// How long a signing tool may take before it is stopped.
const SIGN_TIMEOUT: Duration = Duration::from_secs(60);

/// Sign `file` with the analyst's own key by running their `minisign` or
/// `ssh-keygen`; `program` replaces the tool's name (tests). The signature is
/// written beside the file: `<file>.minisig` or `<file>.sig`.
pub fn sign_file(with: &SignWith, file: &Path, program: Option<&Path>) -> Result<PathBuf, String> {
    let (tool, extension) = match with.signer {
        Signer::Minisign => ("minisign", "minisig"),
        Signer::Ssh => ("ssh-keygen", "sig"),
    };
    let mut name = file.as_os_str().to_owned();
    name.push(format!(".{extension}"));
    let signature = PathBuf::from(name);
    let _ = fs::remove_file(&signature);
    if !with.key.is_file() {
        return Err(format!("the key {} does not exist", with.key.display()));
    }
    let mut command = Command::new(program.unwrap_or(Path::new(tool)));
    match with.signer {
        Signer::Minisign => command
            .arg("-S")
            .arg("-s")
            .arg(&with.key)
            .arg("-m")
            .arg(file)
            .arg("-x")
            .arg(&signature),
        Signer::Ssh => command
            .args(["-Y", "sign", "-n", SSH_NAMESPACE, "-f"])
            .arg(&with.key)
            .arg(file),
    };
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("SSH_ASKPASS_REQUIRE", "never")
        .spawn()
        .map_err(|e| format!("could not start {tool}: {e}"))?;
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < SIGN_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{tool} did not finish in {SIGN_TIMEOUT:?}"));
            }
            Err(error) => return Err(error.to_string()),
        }
    };
    if !status.success() || !signature.is_file() {
        let mut said = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            let _ = stderr.by_ref().take(2000).read_to_string(&mut said);
        }
        return Err(format!(
            "{tool} could not sign{}. A key that needs a passphrase must be loaded in an agent; \
             Antinomie never asks for it",
            if said.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", said.trim())
            }
        ));
    }
    Ok(signature)
}
