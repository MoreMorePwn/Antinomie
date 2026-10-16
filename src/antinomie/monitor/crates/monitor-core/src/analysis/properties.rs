// SPDX-License-Identifier: MIT
//! Offline properties of an exact digest-verified retained executable.
use super::{AnalysisReport, jobs, specimen, tools};
use object::Object;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::Duration,
};

pub const LABELS: &[&str] = &[
    "MD5",
    "SHA-1",
    "SHA-256",
    "vhash",
    "ssdeep",
    "TLSH",
    "File type",
    "Magic",
    "TrID",
    "Magika",
    "File size",
];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Property {
    pub label: String,
    /// A computed value, or the explicit reason it is unavailable.
    pub value: String,
    pub available: bool,
    pub source: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileProperties {
    pub report_id: String,
    pub source_path: String,
    pub sha256: String,
    pub fields: Vec<Property>,
    pub warnings: Vec<String>,
}

fn field(label: &str, value: impl Into<String>, available: bool, source: &str) -> Property {
    Property {
        label: label.into(),
        value: value.into(),
        available,
        source: source.into(),
    }
}

fn unavailable(label: &str, reason: impl Into<String>) -> Property {
    field(label, reason, false, "Local analysis")
}

fn optional_tool(label: &str, candidates: &[&'static str], args: &[&str]) -> Property {
    let Some(tool) = tools::find(candidates) else {
        return unavailable(label, "Local tool is not installed");
    };
    let timeout = Duration::from_secs(if label == "Magika" { 30 } else { 10 });
    match tools::run(tool, args, &[], timeout, 24 * 1024) {
        Ok(output) if output.success && !output.timed_out && !output.truncated => {
            field(label, output.stdout.trim(), true, tool)
        }
        Ok(output) => unavailable(
            label,
            if output.timed_out {
                "Local tool timed out"
            } else if output.truncated {
                "Local tool output exceeded its bound"
            } else {
                "Local tool failed or has no usable local definitions/model"
            },
        ),
        Err(error) => unavailable(label, error),
    }
}

fn ssdeep(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let hash = line.split(',').next()?.trim_matches('"');
        let parts: Vec<_> = hash.split(':').collect();
        (parts.len() == 3
            && parts[0].parse::<u64>().is_ok_and(|size| size > 0)
            && parts[1..].iter().all(|part| {
                part.len() <= 64
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
            }))
        .then(|| hash.into())
    })
}

fn tlsh(text: &str) -> Option<String> {
    let hash = text.split_whitespace().next()?;
    let hex = hash.strip_prefix("T1").unwrap_or(hash);
    (hex.len() == 70 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then(|| hash.into())
}

fn magika(text: &str) -> Option<String> {
    let result: serde_json::Value = serde_json::from_str(text).ok()?;
    let result = result
        .as_array()
        .and_then(|rows| rows.first())
        .unwrap_or(&result);
    let output = result
        .pointer("/prediction/output")
        .or_else(|| result.pointer("/result/output"))
        .or_else(|| result.get("output"))?;
    let label = output
        .get("label")
        .or_else(|| output.get("ct_label"))?
        .as_str()?;
    let description = output
        .get("description")
        .or_else(|| output.get("description_label"))
        .and_then(serde_json::Value::as_str);
    Some(description.map_or_else(
        || label.to_owned(),
        |description| format!("{label}: {description}"),
    ))
}

fn parsed(mut field: Property, parse: fn(&str) -> Option<String>) -> Property {
    if field.available {
        match parse(&field.value) {
            Some(value) => field.value = value,
            None => {
                field.available = false;
                field.value = "No usable result for this input or unsupported tool output".into();
            }
        }
    }
    field
}

fn compute(directory: &Path, report_id: &str, work: &Path) -> Result<FileProperties, String> {
    let (report, data) = specimen::read_all(directory, report_id)?;
    let sha256 = format!("{:x}", Sha256::digest(&data));
    if !report
        .specimen_sha256
        .as_ref()
        .is_some_and(|expected| expected.eq_ignore_ascii_case(&sha256))
    {
        return Err("retained specimen digest mismatch".into());
    }
    // Optional tools read this verified copy, never a filename supplied by the guest.
    let input = work.join("verified-specimen");
    fs::write(&input, &data).map_err(|error| error.to_string())?;
    let input = input.to_str().ok_or("property worker path is not UTF-8")?;
    let file_type = object::File::parse(data.as_slice())
        .map(|file| {
            field(
                "File type",
                format!(
                    "{:?} {:?} {:?}",
                    file.format(),
                    file.kind(),
                    file.architecture()
                ),
                true,
                "object 0.40",
            )
        })
        .unwrap_or_else(|_| {
            optional_tool(
                "File type",
                &["/usr/bin/file", "/bin/file"],
                &["-b", "--mime-type", "--", input],
            )
        });
    let mut trid = optional_tool("TrID", &["/usr/bin/trid", "/usr/local/bin/trid"], &[input]);
    if trid.available {
        let lines: Vec<_> = trid
            .value
            .lines()
            .filter(|line| line.contains('%'))
            .take(8)
            .collect();
        if lines.is_empty() {
            trid = unavailable("TrID", "No match from the installed local definitions");
        } else {
            trid.value = lines.join("\n");
        }
    }
    Ok(FileProperties {
        report_id: report.id,
        source_path: report.source_path,
        sha256: sha256.clone(),
        warnings: Vec::new(),
        fields: vec![
            field(
                "MD5",
                format!("{:x}", md5::Md5::digest(&data)),
                true,
                "Verified specimen / RustCrypto",
            ),
            field(
                "SHA-1",
                format!("{:x}", sha1::Sha1::digest(&data)),
                true,
                "Verified specimen / RustCrypto",
            ),
            field("SHA-256", sha256, true, "Verified specimen / RustCrypto"),
            unavailable(
                "vhash",
                "Provider-specific hash; local computation is unavailable. No online lookup is performed.",
            ),
            parsed(
                optional_tool(
                    "ssdeep",
                    &["/usr/bin/ssdeep", "/usr/local/bin/ssdeep"],
                    &["-b", input],
                ),
                ssdeep,
            ),
            parsed(
                optional_tool(
                    "TLSH",
                    &[
                        "/usr/bin/tlsh",
                        "/usr/local/bin/tlsh",
                        "/usr/bin/tlsh_unittest",
                    ],
                    &["-f", input],
                ),
                tlsh,
            ),
            file_type,
            optional_tool(
                "Magic",
                &["/usr/bin/file", "/bin/file"],
                &["-b", "--", input],
            ),
            trid,
            parsed(
                optional_tool(
                    "Magika",
                    &["/usr/bin/magika", "/usr/local/bin/magika"],
                    &["--json", input],
                ),
                magika,
            ),
            field(
                "File size",
                data.len().to_string(),
                true,
                "Verified captured octets",
            ),
        ],
    })
}

fn validate(result: &FileProperties, expected: &AnalysisReport) -> Result<(), String> {
    if result.report_id != expected.id
        || !expected
            .specimen_sha256
            .as_ref()
            .is_some_and(|digest| digest.eq_ignore_ascii_case(&result.sha256))
        || result.source_path != expected.source_path
        || result.fields.len() != LABELS.len()
        || result.warnings.len() > 4
        || result.warnings.iter().any(|warning| warning.len() > 1024)
    {
        return Err("property result identity or field set mismatch".into());
    }
    for (field, label) in result.fields.iter().zip(LABELS) {
        if field.label != *label
            || field.value.len() > 8192
            || field.source.len() > 512
            || (field.available && field.value.is_empty())
        {
            return Err("invalid property field".into());
        }
    }
    for (index, len) in [(0, 32), (1, 40), (2, 64)] {
        let field = &result.fields[index];
        if !field.available
            || field.value.len() != len
            || !field.value.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("invalid property digest".into());
        }
    }
    if result.fields[2].value != result.sha256
        || result.fields[10].value.parse::<u64>().ok() != expected.specimen_len
    {
        return Err("property digest/length mismatch".into());
    }
    Ok(())
}

/// Compute offline properties in the existing mandatory sandbox. Call on a worker.
///
/// | Argument | Purpose |
/// |---|---|
/// | `directory` | Retained analysis directory containing report.json and specimen. |
/// | `report_id` | Expected immutable analysis identity. |
/// | `cancel` | Cancels/reaps the sandbox on run change or view destruction. |
///
/// Returns verified values with explicit unavailable states and persistence warnings.
pub fn run(
    directory: &Path,
    report_id: &str,
    cancel: &AtomicBool,
) -> Result<FileProperties, String> {
    if cancel.load(std::sync::atomic::Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    let directory = directory
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let expected = jobs::open_report(&directory)?;
    if expected.id != report_id || expected.specimen_sha256.is_none() {
        return Err("complete retained specimen unavailable".into());
    }
    let work = std::env::temp_dir().join(format!("ant-properties-{}", crate::storage::unique_id()));
    crate::storage::private_dir(&work).map_err(|error| error.to_string())?;
    let result = (|| {
        let executable = std::env::current_exe().map_err(|error| error.to_string())?;
        let path_text = |path: &Path| {
            path.to_str()
                .map(str::to_owned)
                .ok_or("property path is not UTF-8")
        };
        let output = work.join("properties.json");
        jobs::run_sandboxed(
            &executable,
            &[
                "--antinomie-properties-worker".into(),
                path_text(&directory)?,
                report_id.into(),
                path_text(&output)?,
            ],
            &work,
            &[directory.clone(), executable.clone()],
            &[("ANTINOMIE_ISOLATED_WORKER", "1")],
            Duration::from_secs(120),
            cancel,
        )?;
        let file = crate::archive_io::open_regular(&work, Path::new("properties.json"))
            .map_err(|error| error.to_string())?;
        let mut encoded = Vec::new();
        file.take(64 * 1024 + 1)
            .read_to_end(&mut encoded)
            .map_err(|error| error.to_string())?;
        if encoded.len() > 64 * 1024 {
            return Err("property result exceeds 64 KiB".into());
        }
        let mut result: FileProperties =
            serde_json::from_slice(&encoded).map_err(|error| error.to_string())?;
        validate(&result, &expected)?;
        if let Err(error) = crate::storage::atomic_json(&directory.join("properties.json"), &result)
        {
            result
                .warnings
                .push(format!("Could not save properties: {error}"));
        }
        Ok(result)
    })();
    match (result, fs::remove_dir_all(&work)) {
        (Ok(mut result), Err(error)) => {
            result
                .warnings
                .push(format!("Temporary property output cleanup failed: {error}"));
            Ok(result)
        }
        (Err(error), Err(cleanup)) => Err(format!("{error}; temporary output cleanup: {cleanup}")),
        (result, Ok(())) => result,
    }
}

/// Internal process entry point; never starts a desktop or contacts a provider.
pub fn worker_main_if_requested() -> Option<i32> {
    let args: Vec<_> = std::env::args_os().collect();
    if args
        .get(1)
        .is_none_or(|arg| arg != "--antinomie-properties-worker")
    {
        return None;
    }
    let result = (|| {
        if args.len() != 5 || std::env::var("ANTINOMIE_ISOLATED_WORKER").as_deref() != Ok("1") {
            return Err("property worker requires isolation".into());
        }
        let directory = PathBuf::from(&args[2]);
        let report_id = args[3].to_str().ok_or("invalid report identity")?;
        let output = PathBuf::from(&args[4]);
        let result = compute(
            &directory,
            report_id,
            output.parent().ok_or("property output parent missing")?,
        )?;
        let encoded = serde_json::to_vec(&result).map_err(|error| error.to_string())?;
        if encoded.len() > 64 * 1024 {
            return Err("property output exceeds bound".into());
        }
        fs::write(output, encoded).map_err(|error| error.to_string())
    })();
    if let Err(error) = &result {
        eprintln!("property worker: {error}");
    }
    Some(i32::from(result.is_err()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_benign_specimen_properties_verify_bytes_and_reject_mutation() {
        let directory =
            std::env::temp_dir().join(format!("ant-property-test-{}", crate::storage::unique_id()));
        crate::storage::private_dir(&directory).unwrap();
        let report = AnalysisReport {
            id: "fixture".into(),
            state: super::super::AnalysisState::Complete,
            source_path: "/guest/fixture".into(),
            specimen_sha256: Some(format!("{:x}", Sha256::digest(b"abc"))),
            specimen_len: Some(3),
            reason: None,
            sections: vec![],
        };
        fs::write(directory.join("specimen"), b"abc").unwrap();
        crate::storage::atomic_json(&directory.join("report.json"), &report).unwrap();
        // Component test with known benign bytes; mandatory sandbox integration
        // is a separate environment-dependent check.
        let result = compute(&directory, "fixture", &directory).unwrap();
        validate(&result, &report).unwrap();
        assert_eq!(result.fields[0].value, "900150983cd24fb0d6963f7d28e17f72");
        assert!(!result.fields[3].available);
        let mut wrong = result.clone();
        wrong.report_id = "other".into();
        assert!(validate(&wrong, &report).is_err());
        fs::write(directory.join("specimen"), b"xyz").unwrap();
        assert!(
            compute(&directory, "fixture", &directory)
                .unwrap_err()
                .contains("digest mismatch")
        );
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn classifiers_accept_known_formats_and_reject_errors_and_unknown_json_layouts() {
        assert_eq!(
            ssdeep("ssdeep,1.1--blocksize:hash:hash,filename\n3:abc:def,\"specimen\"\n").as_deref(),
            Some("3:abc:def")
        );
        assert!(ssdeep("error: cannot read").is_none());
        assert!(tlsh("TNULL specimen").is_none());
        let hash = format!("T1{} specimen", "AB".repeat(35));
        assert_eq!(tlsh(&hash).unwrap().len(), 72);
        assert_eq!(
            magika(r#"[{"prediction":{"output":{"label":"elf","description":"ELF executable"}}}]"#)
                .as_deref(),
            Some("elf: ELF executable")
        );
        assert!(magika(r#"{"label":"guessed"}"#).is_none());
        assert_eq!(
            format!("{:x}", md5::Md5::digest(b"abc")),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            format!("{:x}", sha1::Sha1::digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }
}
