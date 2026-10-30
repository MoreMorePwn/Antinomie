// SPDX-License-Identifier: GPL-3.0-only
//! Offline properties of an exact digest-verified retained executable.
use super::{AnalysisReport, jobs, specimen, tools};
use crate::analysis_tools;
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
    "ssdeep",
    "TLSH",
    "File type",
    "Magic",
    "Magika",
    "File size",
];

/// TLSH needs at least this many octets (and some variety among them).
const TLSH_MIN_LEN: usize = 50;
/// Magika from the managed tools folder first, then the system's.
const MAGIKA: &[&str] = &[
    analysis_tools::MAGIKA_MANAGED,
    analysis_tools::MAGIKA_SYSTEM[0],
    analysis_tools::MAGIKA_SYSTEM[1],
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

fn optional_tool(
    label: &str,
    candidates: &[&'static str],
    args: &[&str],
    missing: &str,
) -> Property {
    let Some(tool) = tools::find(candidates) else {
        return unavailable(label, missing);
    };
    let timeout = Duration::from_secs(if label == "Magika" { 30 } else { 10 });
    match tools::run(tool, args, &[], timeout, 24 * 1024) {
        Ok(output) if output.success && !output.timed_out && !output.truncated => {
            field(label, output.stdout.trim(), true, tool)
        }
        Ok(output) => unavailable(
            label,
            if output.timed_out {
                format!(
                    "{label} ran out of time: it was stopped after {} seconds",
                    timeout.as_secs()
                )
            } else if output.truncated {
                format!("{label} printed more than the 24 KiB the analysis reads")
            } else {
                output.failure_text(label, timeout).unwrap_or_else(|| {
                    format!("{label} failed or has no usable local definitions or model")
                })
            },
        ),
        Err(error) => unavailable(label, error),
    }
}

/// ssdeep context-triggered piecewise hash, computed in process.
fn ssdeep(data: &[u8]) -> Property {
    field(
        "ssdeep",
        fuzzyhash::FuzzyHash::new(data).to_string(),
        true,
        "fuzzyhash 0.2 (ssdeep-compatible)",
    )
}

/// TLSH (128 buckets, 1 octet checksum, `T1` version), computed in process.
fn tlsh(data: &[u8]) -> Property {
    let mut builder = tlsh2::TlshDefaultBuilder::new();
    builder.update(data);
    match builder.build() {
        Some(hash) => field(
            "TLSH",
            String::from_utf8_lossy(&hash.hash()).into_owned(),
            true,
            "tlsh2 1.1",
        ),
        None if data.len() < TLSH_MIN_LEN => unavailable(
            "TLSH",
            format!("The file is too small: TLSH needs at least {TLSH_MIN_LEN} bytes"),
        ),
        None => unavailable(
            "TLSH",
            "The file has too little variety (too uniform or repetitive) for TLSH",
        ),
    }
}

fn magika(text: &str) -> Option<String> {
    let result: serde_json::Value = serde_json::from_str(text).ok()?;
    let result = result
        .as_array()
        .and_then(|rows| rows.first())
        .unwrap_or(&result);
    let output = result
        .pointer("/result/value/output")
        .or_else(|| result.pointer("/prediction/output"))
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
                "Local tool is not installed",
            )
        });
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
            ssdeep(&data),
            tlsh(&data),
            file_type,
            optional_tool(
                "Magic",
                &["/usr/bin/file", "/bin/file"],
                &["-b", "--", input],
                "Local tool is not installed",
            ),
            parsed(
                optional_tool(
                    "Magika",
                    MAGIKA,
                    &["--json", input],
                    "Magika is not installed (Tools > Analysis tools installs it)",
                ),
                magika,
            ),
            field(
                "File size",
                data.len().to_string(),
                true,
                "Verified captured bytes",
            ),
        ],
    })
}

/// Check a decoded result against its report. Fields this version no longer
/// computes (`vhash`, `TrID` in older saved files) are dropped, not rejected.
fn validate(result: &mut FileProperties, expected: &AnalysisReport) -> Result<(), String> {
    if result.report_id != expected.id
        || !expected
            .specimen_sha256
            .as_ref()
            .is_some_and(|digest| digest.eq_ignore_ascii_case(&result.sha256))
        || result.source_path != expected.source_path
        || result.warnings.len() > 4
        || result.warnings.iter().any(|warning| warning.len() > 1024)
    {
        return Err("property result identity or field set mismatch".into());
    }
    result
        .fields
        .retain(|field| LABELS.contains(&field.label.as_str()));
    result
        .fields
        .sort_by_key(|field| LABELS.iter().position(|label| *label == field.label));
    if result.fields.len() != LABELS.len()
        || result
            .fields
            .iter()
            .zip(LABELS)
            .any(|(field, label)| field.label != *label)
    {
        return Err("property result identity or field set mismatch".into());
    }
    for field in &result.fields {
        if field.value.len() > 8192
            || field.source.len() > 512
            || (field.available && field.value.is_empty())
        {
            return Err("invalid property field".into());
        }
    }
    let value = |label: &str| {
        result
            .fields
            .iter()
            .find(|field| field.label == label)
            .filter(|field| field.available)
            .map(|field| field.value.as_str())
    };
    for (label, len) in [("MD5", 32), ("SHA-1", 40), ("SHA-256", 64)] {
        if !value(label)
            .is_some_and(|hash| hash.len() == len && hash.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err("invalid property digest".into());
        }
    }
    if value("SHA-256") != Some(result.sha256.as_str())
        || value("File size").and_then(|size| size.parse::<u64>().ok()) != expected.specimen_len
    {
        return Err("property digest/length mismatch".into());
    }
    Ok(())
}

/// Parse and validate a worker result or a saved `properties.json`.
fn decode(encoded: &[u8], expected: &AnalysisReport) -> Result<FileProperties, String> {
    if encoded.len() > 64 * 1024 {
        return Err("property result exceeds 64 KiB".into());
    }
    let mut result: FileProperties =
        serde_json::from_slice(encoded).map_err(|error| error.to_string())?;
    validate(&mut result, expected)?;
    Ok(result)
}

/// Compute offline properties in the existing mandatory sandbox. Call on a worker.
///
/// | Argument | Purpose |
/// |---|---|
/// | `directory` | Retained analysis directory containing report.json and specimen. |
/// | `report_id` | Expected immutable analysis identity. |
/// | `tools_dir` | `<data>/tools`, mounted read-only for managed tools such as Magika. |
/// | `cancel` | Cancels/reaps the sandbox on run change or view destruction. |
///
/// Returns verified values with explicit unavailable states and persistence warnings.
pub fn run(
    directory: &Path,
    report_id: &str,
    tools_dir: Option<&Path>,
    cancel: &AtomicBool,
) -> Result<FileProperties, String> {
    if cancel.load(std::sync::atomic::Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    let directory = directory
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let expected = jobs::open_report(&directory)?;
    require_specimen(&expected, report_id)?;
    let work = std::env::temp_dir().join(format!("ant-properties-{}", crate::storage::unique_id()));
    crate::storage::private_dir(&work).map_err(|error| error.to_string())?;
    let result = (|| {
        let executable = jobs::worker_executable()?;
        let path_text = |path: &Path| {
            path.to_str()
                .map(str::to_owned)
                .ok_or("property path is not UTF-8")
        };
        let output = work.join("properties.json");
        let mounts = jobs::Mounts {
            paths: &[directory.clone(), executable.clone()],
            tools: tools_dir,
        };
        jobs::run_sandboxed_with(
            &executable,
            &[
                "--antinomie-properties-worker".into(),
                path_text(&directory)?,
                report_id.into(),
                path_text(&output)?,
            ],
            &work,
            &mounts,
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
        let mut result = decode(&encoded, &expected)?;
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

fn require_specimen(report: &AnalysisReport, report_id: &str) -> Result<(), String> {
    use super::AnalysisState;
    if report.id != report_id {
        return Err(format!(
            "Executable properties selected analysis {report_id}, but the saved report belongs to {}. Reopen the selected run.",
            report.id
        ));
    }
    if report.state == AnalysisState::Acquiring {
        return Err(format!(
            "Executable capture is still in progress for {}. Wait for acquisition to finish.",
            report.source_path
        ));
    }
    if report.specimen_sha256.is_some() && report.specimen_len.is_some() {
        return Ok(());
    }
    let state = match report.state {
        AnalysisState::Queued | AnalysisState::Running => {
            "Waiting for captured executable metadata"
        }
        AnalysisState::Cancelled => "Executable capture was cancelled",
        AnalysisState::Partial => "Executable capture is incomplete",
        _ => "No complete executable was retained",
    };
    let reason = report.reason.as_deref().unwrap_or(
        if matches!(report.state, AnalysisState::Queued | AnalysisState::Running) {
            "Wait for capture to be saved, then refresh properties."
        } else {
            "Start a new run with static analysis enabled."
        },
    );
    Err(format!("{state} for {}. {reason}", report.source_path))
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

    fn property<'a>(result: &'a FileProperties, label: &str) -> &'a Property {
        result
            .fields
            .iter()
            .find(|field| field.label == label)
            .unwrap()
    }

    /// Deterministic octets: a linear congruential generator, so a reference
    /// implementation can regenerate them.
    fn lcg(len: usize) -> Vec<u8> {
        let mut x: u32 = 12345;
        (0..len)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12345) & 0x7fff_ffff;
                (x >> 16) as u8
            })
            .collect()
    }

    fn words(count: u32) -> Vec<u8> {
        const WORDS: [&str; 8] = [
            "alpha", "beta", "gamma", "delta", "kernel", "sandbox", "trace", "syscall",
        ];
        let mut x: u32 = 99;
        let mut text = Vec::new();
        for index in 0..count {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345) & 0x7fff_ffff;
            if index > 0 {
                text.push(b' ');
            }
            text.extend_from_slice(WORDS[((x >> 16) % 8) as usize].as_bytes());
            text.extend_from_slice(((x >> 8) % 1000).to_string().as_bytes());
        }
        text
    }

    fn fixture_report(data: &[u8]) -> AnalysisReport {
        AnalysisReport {
            id: "fixture".into(),
            state: super::super::AnalysisState::Complete,
            source_path: "/guest/fixture".into(),
            specimen_sha256: Some(format!("{:x}", Sha256::digest(data))),
            specimen_len: Some(data.len() as u64),
            reason: None,
            sections: vec![],
            layer: None,
            specimen_source: None,
            time_limit_seconds: None,
        }
    }

    #[test]
    fn property_preflight_distinguishes_capture_progress_failure_and_identity() {
        use super::super::AnalysisState;
        let mut report = fixture_report(b"abc");
        assert!(require_specimen(&report, "fixture").is_ok());
        let error = require_specimen(&report, "another-run").unwrap_err();
        assert!(
            error.contains("another-run") && error.contains("fixture") && error.contains("Reopen")
        );
        report.specimen_sha256 = None;
        report.specimen_len = None;
        report.state = AnalysisState::Acquiring;
        assert!(
            require_specimen(&report, "fixture")
                .unwrap_err()
                .contains("still in progress")
        );
        report.state = AnalysisState::Running;
        assert!(
            require_specimen(&report, "fixture")
                .unwrap_err()
                .contains("Waiting for captured")
        );
        report.state = AnalysisState::Cancelled;
        assert!(
            require_specimen(&report, "fixture")
                .unwrap_err()
                .contains("was cancelled")
        );
        report.state = AnalysisState::Unavailable;
        report.reason = Some("guest executable could not be opened".into());
        let error = require_specimen(&report, "fixture").unwrap_err();
        assert!(
            error.contains("No complete executable")
                && error.contains("guest executable could not be opened")
                && error.contains("/guest/fixture")
        );
    }

    #[test]
    fn retained_benign_specimen_properties_verify_bytes_and_reject_mutation() {
        let directory =
            std::env::temp_dir().join(format!("ant-property-test-{}", crate::storage::unique_id()));
        crate::storage::private_dir(&directory).unwrap();
        let report = fixture_report(b"abc");
        fs::write(directory.join("specimen"), b"abc").unwrap();
        crate::storage::atomic_json(&directory.join("report.json"), &report).unwrap();
        // Component test with known benign bytes; mandatory sandbox integration
        // is a separate environment-dependent check.
        let mut result = compute(&directory, "fixture", &directory).unwrap();
        validate(&mut result, &report).unwrap();
        assert_eq!(
            result
                .fields
                .iter()
                .map(|f| f.label.as_str())
                .collect::<Vec<_>>(),
            LABELS
        );
        assert_eq!(
            property(&result, "MD5").value,
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(property(&result, "ssdeep").value, "3:uG:uG");
        assert!(!property(&result, "TLSH").available);
        let mut wrong = result.clone();
        wrong.report_id = "other".into();
        assert!(validate(&mut wrong, &report).is_err());
        fs::write(directory.join("specimen"), b"xyz").unwrap();
        assert!(
            compute(&directory, "fixture", &directory)
                .unwrap_err()
                .contains("digest mismatch")
        );
        fs::remove_dir_all(directory).unwrap();
    }

    // Digests below come from the reference implementations (ppdeep 20260221
    // and py-tlsh 5.0.0) on the same octets.
    #[test]
    fn ssdeep_and_tlsh_match_the_reference_implementations() {
        let fox = b"The quick brown fox jumps over the lazy dog. ".repeat(3);
        let cases: [(Vec<u8>, &str, &str); 4] = [
            (
                fox,
                "3:FJKKIUKacnAeKKIUKacnAeKKIUKacb:FHIG8NIG8NIGY",
                "T12DC0024A311C1794658A1888438D95B2D2C9C910612114116570604219482359CD8551",
            ),
            (
                lcg(4096),
                "96:b+8zEekwuxCkQw9cn8dHaI5Dt5/RSP+RuiNCmDJ:i3ekwunQmc0Ham/8wDJ",
                "T132816DEBA6257155CB37997812FD3AD5D2DFE72817CD7C8457048FD338351E05444085",
            ),
            (
                lcg(300_000),
                "6144:LeKzUBKIxz/gxiSe0ctvz1/ByTbbXGpNU3aw2AReU:CKgfgxev5/AXzYNU3mMeU",
                "T1545423838BE5268562E770F3C55818EE1AD7205969C6A7C68D720CDA6EC315208FFC6F",
            ),
            (
                words(900),
                "96:yVkh2rjxIOn4tfAJH1a3IzGw8clNmjBT+PUAh831rwxB01bywGRKM486dN2cc8G5:xu4EHQ4a6mV66lwxRwGwCEN2UU",
                "T17E020C1C85E943FC3D823A68655B749FB2CCEBF25E30D2BB87AB0785A2251D7B42044D",
            ),
        ];
        for (data, expected_ssdeep, expected_tlsh) in cases {
            let len = data.len();
            assert_eq!(
                ssdeep(&data).value,
                expected_ssdeep,
                "ssdeep of {len} octets"
            );
            let hash = tlsh(&data);
            assert!(hash.available);
            assert_eq!(hash.value, expected_tlsh, "TLSH of {len} octets");
        }
    }

    #[test]
    fn tlsh_explains_why_a_small_or_uniform_input_is_unavailable() {
        for (data, reason) in [
            (&b""[..], "too small"),
            (&b"abc"[..], "too small"),
            (&[0u8; 49][..], "too small"),
            (&[0u8; 5000][..], "too little variety"),
        ] {
            let hash = tlsh(data);
            assert!(!hash.available, "{} octets", data.len());
            assert!(hash.value.contains(reason), "{}", hash.value);
        }
        // ssdeep still has a (trivial) digest for the same inputs.
        assert_eq!(ssdeep(&[0u8; 5000]).value, "3::");
        assert_eq!(ssdeep(b"").value, "3::");
    }

    #[test]
    fn magika_reads_its_cli_json_and_rejects_other_layouts() {
        // Magika CLI 1.1.0 `--json` on an ELF executable.
        let cli = r#"[{"path":"/usr/bin/ls","result":{"status":"ok","value":{"dl":{"description":"ELF executable","extensions":["elf"],"group":"executable","is_text":false,"label":"elf","mime_type":"application/x-executable-elf"},"output":{"description":"ELF executable","extensions":["elf"],"group":"executable","is_text":false,"label":"elf","mime_type":"application/x-executable-elf"},"score":0.9990000128746033}}}]"#;
        assert_eq!(magika(cli).as_deref(), Some("elf: ELF executable"));
        assert_eq!(
            magika(r#"[{"prediction":{"output":{"label":"elf","description":"ELF executable"}}}]"#)
                .as_deref(),
            Some("elf: ELF executable")
        );
        assert!(magika(r#"[{"path":"x","result":{"status":"error"}}]"#).is_none());
        assert!(magika(r#"{"label":"guessed"}"#).is_none());
        assert!(magika("not json").is_none());
        assert_eq!(
            format!("{:x}", sha1::Sha1::digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn saved_results_with_removed_fields_still_load_and_incomplete_ones_do_not() {
        let data = b"abc";
        let report = fixture_report(data);
        let sha256 = report.specimen_sha256.clone().unwrap();
        let saved = |label: &str, value: &str, available: bool| Property {
            label: label.into(),
            value: value.into(),
            available,
            source: "Local analysis".into(),
        };
        // The 0.6.1 field set and order, with vhash and TrID.
        let old_fields = vec![
            saved("MD5", "900150983cd24fb0d6963f7d28e17f72", true),
            saved("SHA-1", "a9993e364706816aba3e25717850c26c9cd0d89d", true),
            saved("SHA-256", &sha256, true),
            saved("vhash", "Provider-specific hash is unavailable", false),
            saved("ssdeep", "Local tool is not installed", false),
            saved("TLSH", "Local tool is not installed", false),
            saved("File type", "Elf Dynamic X86_64", true),
            saved("Magic", "ELF 64-bit LSB shared object", true),
            saved("TrID", "Local tool is not installed", false),
            saved("Magika", "Local tool is not installed", false),
            saved("File size", "3", true),
        ];
        let encode = |fields: Vec<Property>| {
            serde_json::to_vec(&FileProperties {
                report_id: report.id.clone(),
                source_path: report.source_path.clone(),
                sha256: sha256.clone(),
                fields,
                warnings: vec![],
            })
            .unwrap()
        };
        let loaded = decode(&encode(old_fields.clone()), &report).unwrap();
        assert_eq!(
            loaded
                .fields
                .iter()
                .map(|f| f.label.as_str())
                .collect::<Vec<_>>(),
            LABELS
        );
        assert_eq!(property(&loaded, "File type").value, "Elf Dynamic X86_64");
        assert_eq!(property(&loaded, "File size").value, "3");
        // A required field missing, or the same one twice, is still an error.
        let mut missing = old_fields.clone();
        missing.retain(|field| field.label != "Magika");
        assert!(decode(&encode(missing), &report).is_err());
        let mut twice = old_fields;
        twice.push(saved("MD5", "900150983cd24fb0d6963f7d28e17f72", true));
        assert!(decode(&encode(twice), &report).is_err());
    }
}
