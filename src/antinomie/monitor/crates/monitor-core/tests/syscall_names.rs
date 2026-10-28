// SPDX-License-Identifier: GPL-3.0-only
//! Rules and decoders key system calls by name. The number is what the wire
//! carries and only `syscalls.rs` (and its `syscalls/` helpers) may know what
//! it means; every other source file of both crates must not compare, match or
//! name a syscall number. Test code is exempt: it may build records by number.
use antinomie_monitor_core::syscalls;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if name != "tests" && name != "syscalls" && name != "target" {
                sources(&path, out);
            }
        } else if name.ends_with(".rs")
            && name != "syscalls.rs"
            && !name.contains("tests")
            && !name.contains("_test")
        {
            out.push(path);
        }
    }
}

/// The production part of a source file: up to its test module.
fn production(text: &str) -> String {
    let mut kept = String::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        if line.trim() == "#[cfg(test)]"
            && lines
                .peek()
                .is_some_and(|next| next.trim_start().starts_with("mod "))
        {
            break;
        }
        kept.push_str(line.split("//").next().unwrap_or(""));
        kept.push('\n');
    }
    kept
}

/// Lines of the `match` blocks whose scrutinee is a syscall number.
fn numeric_arms(text: &str) -> Vec<String> {
    let scrutinee = Regex::new(r"\bmatch\b[^{]*\b(syscall_nr|first_nr|nr)\b").unwrap();
    let arm = Regex::new(r"^\s*\(?\s*[0-9][0-9_]*\b[^;]*(=>|\|)").unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let mut found = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if !scrutinee.is_match(lines[index]) {
            index += 1;
            continue;
        }
        let mut depth = 0i32;
        let mut seen = false;
        let mut at = index;
        while at < lines.len() {
            if seen && arm.is_match(lines[at]) && depth == 1 {
                found.push(lines[at].trim().to_owned());
            }
            for byte in lines[at].bytes() {
                match byte {
                    b'{' => {
                        depth += 1;
                        seen = true;
                    }
                    b'}' => depth -= 1,
                    _ => {}
                }
            }
            if seen && depth <= 0 {
                break;
            }
            at += 1;
        }
        index += 1;
    }
    found
}

#[test]
fn no_source_outside_syscalls_names_a_syscall_number() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for member in ["monitor-core", "monitor-ui"] {
        for dir in ["src", "examples"] {
            sources(&crates.join(member).join(dir), &mut files);
        }
    }
    assert!(files.len() > 100, "found only {} sources", files.len());
    let compare = Regex::new(
        r"\b(syscall_nr|first_nr|nr)\b\s*(==|!=)\s*[0-9]|[0-9]\s*(==|!=)\s*[\w.]*\b(syscall_nr|first_nr|nr)\b",
    )
    .unwrap();
    let in_matches =
        Regex::new(r"matches!\(\s*[\w.]*\b(syscall_nr|first_nr|nr)\b\s*,[^)]*\b[0-9]").unwrap();
    let module = Regex::new(r"\bnr::[A-Z]").unwrap();
    let constant =
        Regex::new(r"\bconst\s+([A-Z][A-Z0-9_]*)\s*:\s*u(?:32|64)\s*=\s*([0-9]+)\s*;").unwrap();
    let mut found = Vec::new();
    for path in &files {
        let text = production(&fs::read_to_string(path).unwrap());
        let shown = path
            .strip_prefix(&crates)
            .unwrap_or(path)
            .display()
            .to_string();
        for (number, line) in text.lines().enumerate() {
            if compare.is_match(line) || in_matches.is_match(line) || module.is_match(line) {
                found.push(format!("{shown}:{}: {}", number + 1, line.trim()));
            }
            if let Some(caught) = constant.captures(line) {
                let value: u64 = caught[2].parse().unwrap();
                let named = caught[1].to_ascii_lowercase();
                if syscalls::number(&named) == Some(value) {
                    found.push(format!("{shown}:{}: {}", number + 1, line.trim()));
                }
            }
        }
        for arm in numeric_arms(&text) {
            found.push(format!(
                "{shown}: numeric arm in a match on a number: {arm}"
            ));
        }
    }
    assert!(
        found.is_empty(),
        "syscall numbers outside syscalls.rs:\n{}",
        found.join("\n")
    );
}

#[test]
fn the_detector_sees_what_it_forbids() {
    let sample = "match event.syscall_nr {\n    59 | 322 => 1,\n    _ => 0,\n}\n";
    assert_eq!(numeric_arms(sample).len(), 1);
    let named = "match event.syscall_name.as_str() {\n    \"execve\" => 1,\n    _ => 0,\n}\n";
    assert!(numeric_arms(named).is_empty());
    assert_eq!(syscalls::number("execve"), Some(59));
    assert_eq!(syscalls::number("open"), Some(2));
}
