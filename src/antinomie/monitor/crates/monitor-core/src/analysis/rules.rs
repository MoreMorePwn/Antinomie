// SPDX-License-Identifier: GPL-3.0-only
//! Rule matching with YARA-X and the rules selected in the rule manager.
use super::*;
use std::{fs, path::Path, time::Duration};

const ENGINE: &str = "YARA-X 1.21";

/// Compile selected sources. An empty selection is not a successful scan. A
/// file that does not compile is left out and named in the second value; the
/// others still scan. Only when none compiles is it an error (the first one).
pub(super) fn compile_sources(
    sources: &[(String, String)],
    include: Option<&Path>,
) -> Result<(yara_x::Rules, Vec<String>), String> {
    if sources.is_empty() {
        return Err(
            "No rules are turned on; enable some in Library > Detection rules to scan with them"
                .into(),
        );
    }
    let mut compiler = yara_x::Compiler::new();
    compiler.relaxed_re_syntax(true);
    if let Some(directory) = include {
        compiler.add_include_dir(directory);
    }
    let mut skipped = Vec::new();
    let mut first_error = None;
    for (index, (name, source)) in sources.iter().enumerate() {
        compiler.new_namespace(&format!("s{index}"));
        let code = yara_x::SourceCode::from(source.as_str()).with_origin(name);
        if let Err(error) = compiler.add_source(code) {
            let text = format!("{name}: {error}");
            first_error.get_or_insert_with(|| text.clone());
            skipped.push(text);
        }
    }
    if skipped.len() == sources.len() {
        return Err(first_error.unwrap_or_default());
    }
    Ok((compiler.build(), skipped))
}

/// [`compile_sources`], unless the host already compiled these sources in the
/// profile folder `include` (see `compiled_rules`): then the stored rules are
/// loaded, which takes a third of the time.
pub(super) fn compile_cached(
    sources: &[(String, String)],
    include: Option<&Path>,
) -> Result<(yara_x::Rules, Vec<String>), String> {
    if let Some(directory) = include
        && let Some(hit) = super::compiled_rules::load(directory, sources)
    {
        return Ok(hit);
    }
    compile_sources(sources, include)
}

/// The rule file a namespace `s<index>` stands for.
pub(super) fn namespace_source<'a>(namespace: &str, sources: &'a [(String, String)]) -> &'a str {
    namespace
        .strip_prefix('s')
        .and_then(|index| index.parse::<usize>().ok())
        .and_then(|index| sources.get(index))
        .map_or("", |(name, _)| name.as_str())
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
    scan_at(section, specimen, Path::new("/input/rules"));
}

/// Scan one explicitly selected rule directory; the sandbox entry uses `/input/rules`.
pub(super) fn scan_at(section: &mut AnalysisSection, specimen: &[u8], directory: &Path) {
    section.state = AnalysisSectionState::Complete;
    let sources = selected_sources(directory);
    if sources.is_empty() {
        section.state = AnalysisSectionState::Unavailable;
        section.summary =
            "No rules are turned on; enable some in Library > Detection rules to scan with them"
                .into();
        section.tools = vec![ENGINE.into()];
        return;
    }
    let (rules, skipped) = match compile_cached(&sources, Some(directory)) {
        Ok(compiled) => compiled,
        Err(error) => {
            section.state = AnalysisSectionState::Unavailable;
            section.summary = format!("The selected rules did not compile: {error}");
            return;
        }
    };
    section.tools = vec![
        ENGINE.into(),
        format!("{} selected rule files", sources.len()),
    ];
    let mut scanner = yara_x::Scanner::new(&rules);
    let timeout = super::limits::seconds_for(super::limits::TimedTool::Yara);
    scanner.set_timeout(Duration::from_secs(timeout));
    let results = match scanner.scan(specimen) {
        Ok(results) => results,
        Err(yara_x::errors::ScanError::Timeout) => {
            super::limits::time_out(
                section,
                "The rule scan",
                timeout,
                "The scan was stopped before it finished, so no matches are listed; a rule that matches very many patterns is slow on a large file.",
            );
            return;
        }
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
            crate::ruleset::meta_get(metadata.iter().map(|(n, v)| (n.as_str(), v.as_str())), key)
                .map(str::to_owned)
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
        let namespace = match namespace_source(rule.namespace(), &sources) {
            "" => rule.namespace().to_owned(),
            name => name.to_owned(),
        };
        let author = meta("author").unwrap_or_else(|| "unknown author".into());
        let license = meta("license")
            .or_else(|| meta("malpedia_license"))
            .or_else(|| meta("yarahub_license"))
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
    if !skipped.is_empty() {
        section.summary.push_str(&format!(
            "; {} rule file(s) did not compile and were left out: {}",
            skipped.len(),
            skipped.join(" | ")
        ));
    }
}

pub(super) fn selected_sources(directory: &Path) -> Vec<(String, String)> {
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

    #[test]
    fn one_file_that_does_not_compile_leaves_the_others_scanning() {
        let sources = vec![
            (
                "bad.yar".to_owned(),
                "rule broken { condition: nope }".to_owned(),
            ),
            (
                "good.yar".to_owned(),
                "rule fine { condition: true }".to_owned(),
            ),
        ];
        let (rules, skipped) = super::compile_sources(&sources, None).unwrap();
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].starts_with("bad.yar"));
        let mut scanner = yara_x::Scanner::new(&rules);
        let results = scanner.scan(b"x").unwrap();
        let hits: Vec<_> = results
            .matching_rules()
            .map(|r| (r.identifier().to_owned(), r.namespace().to_owned()))
            .collect();
        assert_eq!(hits, vec![("fine".to_owned(), "s1".to_owned())]);
        assert_eq!(super::namespace_source("s1", &sources), "good.yar");
        assert_eq!(super::namespace_source("antinomie", &sources), "");
        let only_bad = &sources[..1];
        assert!(super::compile_sources(only_bad, None).is_err());
    }
}
