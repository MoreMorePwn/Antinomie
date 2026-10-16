// SPDX-License-Identifier: MIT
//! Rule matching with YARA-X and the rules selected in the rule manager.
use super::*;
use std::{fs, path::Path, time::Duration};

const ENGINE: &str = "YARA-X 1.21";

/// Compile selected sources. An empty selection is not a successful scan.
pub(super) fn compile_sources(
    sources: &[(String, String)],
    include: Option<&Path>,
) -> Result<yara_x::Rules, String> {
    if sources.is_empty() {
        return Err("No rules enabled".into());
    }
    let mut compiler = yara_x::Compiler::new();
    compiler.relaxed_re_syntax(true);
    if let Some(directory) = include {
        compiler.add_include_dir(directory);
    }
    for (index, (name, source)) in sources.iter().enumerate() {
        compiler.new_namespace(&format!("s{index}"));
        let code = yara_x::SourceCode::from(source.as_str()).with_origin(name);
        compiler
            .add_source(code)
            .map_err(|error| format!("{name}: {error}"))?;
    }
    Ok(compiler.build())
}

fn meta_text(value: &yara_x::MetaValue) -> Option<String> {
    match value {
        yara_x::MetaValue::String(text) => Some((*text).to_owned()),
        yara_x::MetaValue::Integer(number) => Some(number.to_string()),
        _ => None,
    }
}

/// Printable form of matched bytes: text when printable, hex otherwise.
fn matched_text(data: &[u8]) -> String {
    let data = &data[..data.len().min(48)];
    if data.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        format!("\"{}\"", String::from_utf8_lossy(data))
    } else {
        data.iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

pub(super) fn scan(section: &mut AnalysisSection, specimen: &[u8]) {
    section.state = AnalysisSectionState::Complete;
    let sources = selected_sources(Path::new("/input/rules"));
    if sources.is_empty() {
        section.state = AnalysisSectionState::Unavailable;
        section.summary = "No rules enabled".into();
        section.tools = vec![ENGINE.into()];
        return;
    }
    let rules = match compile_sources(&sources, Some(Path::new("/input/rules"))) {
        Ok(rules) => rules,
        Err(error) => {
            section.state = AnalysisSectionState::Unavailable;
            section.summary = format!("selected rules failed to compile: {error}");
            return;
        }
    };
    section.tools = vec![
        ENGINE.into(),
        format!("{} selected rule files", sources.len()),
    ];
    let mut scanner = yara_x::Scanner::new(&rules);
    scanner.set_timeout(Duration::from_secs(60));
    let results = match scanner.scan(specimen) {
        Ok(results) => results,
        Err(error) => {
            section.state = AnalysisSectionState::Unavailable;
            section.summary = format!("rule scan failed: {error}");
            return;
        }
    };
    let mut matched = 0usize;
    for rule in results.matching_rules() {
        matched += 1;
        let metadata: Vec<(String, String)> = rule
            .metadata()
            .filter_map(|(name, value)| meta_text(&value).map(|v| (name.to_owned(), v)))
            .collect();
        let meta = |key: &str| {
            metadata
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.clone())
        };
        let mut first = None;
        let mut evidence = Vec::new();
        for pattern in rule.patterns() {
            for found in pattern.matches().take(3) {
                let range = found.range();
                first.get_or_insert(range.clone());
                if evidence.len() < 8 {
                    evidence.push(format!(
                        "{} at 0x{:x}: {}",
                        pattern.identifier(),
                        range.start,
                        matched_text(found.data())
                    ));
                }
            }
        }
        let description = meta("description").unwrap_or_default();
        let value = if evidence.is_empty() {
            description.clone()
        } else if description.is_empty() {
            evidence.join("; ")
        } else {
            format!("{description} — {}", evidence.join("; "))
        };
        let namespace = rule.namespace().to_owned();
        let author = meta("author").unwrap_or_else(|| "unknown author".into());
        let license = meta("license")
            .or_else(|| meta("malpedia_license"))
            .unwrap_or_default();
        let ruleset = format!("{author}; {license}");
        let mut tags: Vec<String> = rule.tags().map(|t| t.identifier().to_owned()).collect();
        if let Some(category) = meta("category") {
            tags.insert(0, category);
        }
        super::worker::structured_entry(
            section,
            rule.identifier(),
            value,
            first.map(|range| AnalysisLocation {
                kind: AnalysisAddressKind::FileOffset,
                value: range.start as u64,
                file_range: Some(AnalysisRange {
                    offset: range.start as u64,
                    len: (range.end - range.start) as u64,
                }),
            }),
            AnalysisData::RuleMatch {
                rule: rule.identifier().to_owned(),
                namespace,
                tags,
                ruleset,
            },
        );
    }
    section.summary = format!("{matched} rules matched; a match is an indicator, not a verdict");
}

fn selected_sources(directory: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    let _ = collect_sources(directory, &mut files);
    files.sort();
    let mut sources = Vec::new();
    for path in files {
        if let Ok(text) = fs::read_to_string(&path) {
            sources.push((path.display().to_string(), text));
        }
    }
    sources
}

fn collect_sources(directory: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<(), String> {
    if !directory.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let meta = fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            collect_sources(&entry.path(), out)?;
        } else if meta.is_file()
            && entry
                .path()
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext == "yar" || ext == "yara")
        {
            out.push(entry.path());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn selected_community_core_compiles_with_yara_x() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/assets/rules/yara-forge-core.yar"
        );
        let source = std::fs::read_to_string(path).unwrap();
        super::compile_sources(&[("yara-forge-core.yar".into(), source)], None).unwrap();
    }
}
