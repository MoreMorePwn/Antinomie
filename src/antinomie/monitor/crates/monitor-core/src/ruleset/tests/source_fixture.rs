// SPDX-License-Identifier: GPL-3.0-only
//! Local stand-ins for upstream downloads. No test here uses the network.
use super::*;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

pub(super) fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(super) fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ant-src-{label}-{}", crate::storage::unique_id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A zip archive holding `files`.
pub(super) fn zip_bytes(files: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut out));
        for (name, data) in files {
            writer
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(data.as_bytes()).unwrap();
        }
        writer.finish().unwrap();
    }
    out
}

/// Serves fixed bytes by URL and counts requests.
#[derive(Default)]
pub(super) struct Fixture {
    pub bodies: BTreeMap<String, Vec<u8>>,
    pub requests: Mutex<Vec<String>>,
}

impl Fixture {
    pub(super) fn with(mut self, url: &str, body: Vec<u8>) -> Self {
        self.bodies.insert(url.to_owned(), body);
        self
    }

    pub(super) fn requested(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

impl Fetcher for Fixture {
    fn fetch(
        &self,
        url: &str,
        dest: &Path,
        max_size: u64,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(u64),
    ) -> Result<(), String> {
        self.requests.lock().unwrap().push(url.to_owned());
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let body = self
            .bodies
            .get(url)
            .ok_or_else(|| format!("{url} answered HTTP 404"))?;
        if body.len() as u64 > max_size {
            return Err(format!("{url} sent more than the {max_size} bytes allowed"));
        }
        fs::write(dest, body).map_err(|error| error.to_string())?;
        progress(body.len() as u64);
        Ok(())
    }
}

pub(super) const FORGE_URL: &str = "https://github.com/example/forge/releases/download/1/pkg.zip";
pub(super) const FORGE_PATH: &str = "packages/core/rules.yar";

pub(super) fn rule(name: &str, license: Option<&str>, condition: &str) -> String {
    let license = license
        .map(|license| format!("\t\tlicense = \"{license}\"\n"))
        .unwrap_or_default();
    format!(
        "rule {name}\n{{\n\tmeta:\n\t\tdescription = \"{name}\"\n{license}\tstrings:\n\t\t$a = \"{name}\"\n\tcondition:\n\t\t{condition}\n}}\n"
    )
}

fn set(name: &str, repository: &str, license: &str, rules: &[String]) -> String {
    format!(
        "/*\n * YARA Rule Set\n * Repository Name: {name}\n * Repository: {repository}\n * Number of Rules: {}\n *\n * \n * LICENSE\n * \n * {license}\n */\n\n{}\n",
        rules.len(),
        rules.join("\n")
    )
}

/// A YARA-Forge style package with one open, one closed, one unlicensed-header
/// and one broken repository.
pub(super) fn forge_text() -> String {
    let mut text = String::from("/*\n * YARA-Forge YARA Rule Package\n */\n\nimport \"pe\"\n\n");
    text.push_str(&set(
        "Open",
        "https://github.com/example/open-rules",
        "BSD 2-Clause License. Redistribution and use in source and binary forms are permitted.",
        &[
            rule("Open_Plain", None, "$a"),
            rule("Open_Own", Some("MIT"), "$a"),
            rule("Open_Bad", Some("Proprietary EULA"), "$a"),
            rule(
                "Open_Pointer",
                Some("See license at https://github.com/example/open-rules/LICENSE"),
                "$a",
            ),
        ],
    ));
    text.push_str(&set(
        "Closed",
        "https://github.com/example/closed-rules",
        "NO LICENSE SET",
        &[
            rule("Closed_Plain", None, "$a"),
            rule("Closed_Own", Some("Apache License 2.0"), "$a"),
            rule("Closed_Bad", Some("Proprietary EULA"), "$a"),
        ],
    ));
    text.push_str(&set(
        "Broken",
        "https://github.com/example/broken-rules",
        "MIT License. Permission is hereby granted, free of charge.",
        &[
            rule("Broken_Fine", None, "$a"),
            rule("Broken_Syntax", None, "$undefined_string"),
            rule("Broken_Needs_It", None, "Broken_Syntax and $a"),
        ],
    ));
    // The package header does not recognise this repository's license file
    // (for example an UNLICENSE file); the catalog table, checked against the
    // repository, does.
    text.push_str(&set(
        "Stray",
        "https://github.com/example/stray-rules",
        "NO LICENSE SET",
        &[rule("Stray_Plain", None, "$a")],
    ));
    text.push_str(&set(
        "Unlisted",
        "https://github.com/example/unlisted-rules",
        "MIT License. Permission is hereby granted, free of charge.",
        &[rule("Unlisted_Plain", None, "$a")],
    ));
    text
}

pub(super) fn forge_filter() -> YaraForgeFilter {
    let license = |spdx: &str| RepositoryLicense {
        license: spdx.into(),
        url: String::new(),
    };
    YaraForgeFilter {
        allowed_licenses: ["MIT", "Apache License 2.0", "BSD 2-Clause"]
            .map(String::from)
            .to_vec(),
        allowed_repository_licenses: ["BSD-2-Clause", "MIT"].map(String::from).to_vec(),
        repository_licenses: BTreeMap::from([
            (
                "https://github.com/example/open-rules".into(),
                license("BSD-2-Clause"),
            ),
            (
                "https://github.com/example/broken-rules/".into(),
                license("MIT"),
            ),
            (
                "https://github.com/example/stray-rules".into(),
                license("MIT"),
            ),
            (
                "https://github.com/example/closed-rules".into(),
                license("none"),
            ),
        ]),
    }
}

/// A schema 2 YARA pack for [`forge_text`] with the matching download.
pub(super) fn forge_pack() -> (SourcePack, Fixture) {
    let text = forge_text();
    let archive = zip_bytes(&[(FORGE_PATH, text.as_str())]);
    let pack = SourcePack {
        id: "forge-core".into(),
        engine: "yara".into(),
        name: "Forge Core".into(),
        homepage: "https://github.com/example/forge".into(),
        license: "Per rule, or the source repository's license".into(),
        license_url: "https://github.com/example/forge/blob/main/LICENSE".into(),
        revision: "1".into(),
        revision_kind: "release".into(),
        app: ">=0.6.2".into(),
        engine_requirement: "YARA-X 1.21".into(),
        rules: 5,
        helpers: 0,
        evidence: vec!["sample".into()],
        limits: Vec::new(),
        sources: vec![SourceFetch {
            url: FORGE_URL.into(),
            format: "zip".into(),
            size: archive.len() as u64,
            sha256: sha(&archive),
            rolling: false,
            strip: 0,
            paths: vec!["packages/core/".into()],
            files: vec![SourceFile {
                path: FORGE_PATH.into(),
                sha256: sha(text.as_bytes()),
            }],
        }],
        filter: SourceFilter::YaraForge(forge_filter()),
        options: vec![SourceOption {
            id: "include-unlicensed".into(),
            label: "Include rules from repositories without a license".into(),
            default: false,
            warning: "All rights reserved; local use only.".into(),
        }],
        notices: Vec::new(),
    };
    (pack, Fixture::default().with(FORGE_URL, archive))
}

pub(super) fn no_cancel() -> AtomicBool {
    AtomicBool::new(false)
}
