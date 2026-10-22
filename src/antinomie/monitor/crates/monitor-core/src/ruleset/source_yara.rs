// SPDX-License-Identifier: GPL-3.0-only
//! The YARA-Forge filter: split a package by source repository, keep the
//! rules whose license allows local use and drop the ones that do not compile.
//!
//! A rule is kept when its own `license` meta is allowed. A rule without one
//! takes its source repository's license from the catalog table. Repositories
//! without a license file are dropped unless the person opted in to them.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

/// Meta key added to a kept rule that took its license from the repository.
pub const REPOSITORY_LICENSE_META: &str = "antinomie_repo_license";

const SET_MARKER: &str = "/*\n * YARA Rule Set\n";

/// One output file: the rules kept from one source repository.
pub(super) struct YaraFile {
    pub path: String,
    pub text: String,
}

#[derive(Default)]
pub(super) struct YaraForgeOutcome {
    pub files: Vec<YaraFile>,
    pub report: FilterReport,
}

/// Why a rule was kept or dropped, for the install summary.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Basis {
    OwnLicense,
    RepositoryLicense,
    Unlicensed,
}

struct Candidate {
    text: String,
    helper: bool,
    basis: Basis,
    failure: Option<String>,
}

struct RuleSet {
    name: String,
    repository: String,
    license_text: String,
    body: String,
}

/// `owner/name` of a repository URL, lowercase.
fn repository_key(url: &str) -> String {
    let url = url.trim().trim_end_matches('/').trim_end_matches(".git");
    url.to_ascii_lowercase()
}

fn repository_slug(url: &str) -> String {
    let key = repository_key(url);
    let mut parts: Vec<&str> = key.rsplit('/').take(2).collect();
    parts.reverse();
    parts.join("/")
}

fn split_sets(text: &str) -> Vec<RuleSet> {
    let starts: Vec<usize> = text.match_indices(SET_MARKER).map(|(at, _)| at).collect();
    let mut sets = Vec::new();
    for (index, start) in starts.iter().enumerate() {
        let end = starts.get(index + 1).copied().unwrap_or(text.len());
        let chunk = &text[*start..end];
        let Some(close) = chunk.find("\n */") else {
            continue;
        };
        let header = &chunk[..close];
        let body = &chunk[close + "\n */".len()..];
        let line = |key: &str| {
            header
                .lines()
                .find_map(|line| {
                    line.trim_start_matches([' ', '*'])
                        .strip_prefix(key)
                        .map(|value| value.trim().to_owned())
                })
                .unwrap_or_default()
        };
        let license_text = header
            .split_once("\n * LICENSE")
            .map(|(_, rest)| {
                rest.lines()
                    .map(|line| line.trim_start_matches([' ', '*']).trim())
                    .filter(|line| !line.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        sets.push(RuleSet {
            name: line("Repository Name:"),
            repository: line("Repository:"),
            license_text,
            body: body.to_owned(),
        });
    }
    sets
}

fn import_lines(text: &str) -> Vec<String> {
    let mut imports = BTreeSet::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("import \"") && trimmed.ends_with('"') && trimmed.len() < 80 {
            imports.insert(trimmed.to_owned());
        }
    }
    imports.into_iter().collect()
}

/// The rule's own `license` (or `malpedia_license`) meta, when it names one.
pub(super) fn own_license(body: &str) -> Option<String> {
    for line in body.lines() {
        let line = line.trim_start();
        let key_len = line
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(line.len());
        let (key, rest) = line.split_at(key_len);
        if key != "license" && key != "malpedia_license" {
            continue;
        }
        let Some(value) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').trim();
        let lower = value.to_ascii_lowercase();
        if value.is_empty() || matches!(lower.as_str(), "n/a" | "none" | "unknown" | "-") {
            return None;
        }
        return Some(value.to_owned());
    }
    None
}

fn first_line(text: &str) -> String {
    text.lines()
        .find(|line| line.trim_start().starts_with("error"))
        .or_else(|| text.lines().next())
        .unwrap_or("")
        .chars()
        .take(160)
        .collect()
}

/// Insert the repository license as meta so findings can show it.
fn with_repository_license(body: &str, label: &str) -> String {
    let label: String = label
        .chars()
        .filter(|c| !matches!(c, '"' | '\\' | '\n' | '\r'))
        .collect();
    let mut out = String::with_capacity(body.len() + label.len() + 40);
    let mut done = false;
    let mut lines = body.lines().peekable();
    while let Some(line) = lines.next() {
        out.push_str(line);
        out.push('\n');
        if !done && line.trim() == "meta:" {
            let indent: String = lines
                .peek()
                .map(|next| next.chars().take_while(|c| c.is_whitespace()).collect())
                .unwrap_or_else(|| "\t\t".into());
            out.push_str(&format!(
                "{indent}{REPOSITORY_LICENSE_META} = \"{label}\"\n"
            ));
            done = true;
        }
    }
    if out.ends_with('\n') && !body.ends_with('\n') {
        out.pop();
    }
    out
}

fn slug_of(name: &str) -> String {
    let mut slug = String::new();
    for c in name.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() {
            slug.push(c);
        } else if !slug.ends_with('-') && !slug.is_empty() {
            slug.push('-');
        }
    }
    let slug = slug.trim_matches('-').to_owned();
    if slug.is_empty() {
        "rules".into()
    } else {
        slug
    }
}

/// Mark the candidates YARA-X cannot compile. Rules are added in file order
/// to one namespace, so a rule that needs a dropped rule fails too.
fn mark_uncompilable(imports: &[String], candidates: &mut [Candidate], cancel: &AtomicBool) {
    let mut compiler = yara_x::Compiler::new();
    compiler.relaxed_re_syntax(true);
    compiler.new_namespace("check");
    let header = imports.join("\n");
    for (index, candidate) in candidates.iter_mut().enumerate() {
        if index % 64 == 0 && cancel.load(Ordering::Relaxed) {
            return;
        }
        let source = format!("{header}\n{}\n", candidate.text);
        let code = yara_x::SourceCode::from(source.as_str());
        if let Err(error) = compiler.add_source(code) {
            candidate.failure = Some(first_line(&error.to_string()));
        }
    }
}

pub(super) fn filter_yara_forge(
    text: &str,
    filter: &YaraForgeFilter,
    include_unlicensed: bool,
    cancel: &AtomicBool,
) -> Result<YaraForgeOutcome, String> {
    let text = text.replace("\r\n", "\n");
    let imports = import_lines(&text);
    let sets = split_sets(&text);
    if sets.is_empty() {
        return Err("the YARA-Forge package has no rule sets".into());
    }
    let table: BTreeMap<String, &RepositoryLicense> = filter
        .repository_licenses
        .iter()
        .map(|(url, license)| (repository_key(url), license))
        .collect();
    let mut outcome = YaraForgeOutcome::default();
    let mut used = BTreeSet::new();
    for set in sets {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        // The catalog's table decides: the package header misses license files
        // with unusual names, and the generator checks each entry against the
        // repository itself.
        let repository_license = table
            .get(&repository_key(&set.repository))
            .map(|entry| entry.license.as_str())
            .filter(|license| *license != "none");
        let repository_allowed = repository_license.filter(|license| {
            filter
                .allowed_repository_licenses
                .iter()
                .any(|allowed| allowed == license)
        });
        let slug = repository_slug(&set.repository);
        let mut candidates = Vec::new();
        let mut dropped_here = BTreeMap::<&str, u64>::new();
        for (_, body, helper) in yara_blocks(&set.body) {
            let own = own_license(&body);
            let basis = match &own {
                Some(license)
                    if filter
                        .allowed_licenses
                        .iter()
                        .any(|allowed| license.starts_with(allowed.as_str())) =>
                {
                    Some(Basis::OwnLicense)
                }
                // A pointer to the rule's own repository ("See license at <repository>/LICENSE")
                // is the repository's license, not a different one.
                Some(license)
                    if !slug.is_empty()
                        && license.to_ascii_lowercase().contains(&slug)
                        && repository_allowed.is_some() =>
                {
                    Some(Basis::RepositoryLicense)
                }
                Some(_) => {
                    *dropped_here
                        .entry("its own license is not an allowed one")
                        .or_default() += 1;
                    None
                }
                None if repository_allowed.is_some() => Some(Basis::RepositoryLicense),
                None if repository_license.is_none() && include_unlicensed => {
                    Some(Basis::Unlicensed)
                }
                None if repository_license.is_none() => {
                    *dropped_here
                        .entry("its repository has no license (all rights reserved)")
                        .or_default() += 1;
                    None
                }
                None => {
                    *dropped_here
                        .entry("its repository license is not an allowed one")
                        .or_default() += 1;
                    None
                }
            };
            let Some(basis) = basis else { continue };
            let text = match basis {
                Basis::OwnLicense => body,
                Basis::RepositoryLicense => with_repository_license(
                    &body,
                    &format!(
                        "{} (repository {})",
                        repository_allowed.unwrap_or_default(),
                        set.repository
                    ),
                ),
                Basis::Unlicensed => with_repository_license(
                    &body,
                    &format!(
                        "none: all rights reserved, local use only (repository {})",
                        set.repository
                    ),
                ),
            };
            candidates.push(Candidate {
                text,
                helper,
                basis,
                failure: None,
            });
        }
        for (reason, count) in dropped_here {
            outcome.report.omit(reason, count);
        }
        mark_uncompilable(&imports, &mut candidates, cancel);
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let mut kept = Vec::new();
        for candidate in candidates {
            if let Some(failure) = &candidate.failure {
                outcome.report.omit("it does not compile with YARA-X", 1);
                if outcome.report.examples.len() < 5 {
                    outcome.report.examples.push(failure.clone());
                }
                continue;
            }
            outcome.report.kept += u64::from(!candidate.helper);
            outcome.report.helpers += u64::from(candidate.helper);
            let label = match candidate.basis {
                Basis::OwnLicense => "its own license",
                Basis::RepositoryLicense => "the repository's license",
                Basis::Unlicensed => "the unlicensed-repository option",
            };
            *outcome.report.kept_by.entry(label.into()).or_default() += 1;
            kept.push(candidate.text);
        }
        if kept.is_empty() {
            continue;
        }
        let mut file = slug_of(if set.name.is_empty() {
            &set.repository
        } else {
            &set.name
        });
        while !used.insert(file.clone()) {
            file.push('x');
        }
        let license = repository_license.unwrap_or("none");
        let mut text = format!(
            "// Rules from {} ({}), repository license: {}.\n// Filtered by Antinomie from a YARA-Forge package; each rule keeps its author and source_url.\n",
            if set.name.is_empty() {
                "an unnamed set"
            } else {
                &set.name
            },
            set.repository,
            if set.license_text.is_empty() {
                "none stated".to_owned()
            } else {
                license.to_owned()
            },
        );
        if !imports.is_empty() {
            text.push_str(&imports.join("\n"));
            text.push_str("\n\n");
        }
        text.push_str(&kept.join("\n\n"));
        text.push('\n');
        outcome.files.push(YaraFile {
            path: format!("{file}.yar"),
            text,
        });
    }
    Ok(outcome)
}
