// SPDX-License-Identifier: GPL-3.0-only
//! Report the rules of a YARA file that YARA-X cannot compile.
//!
//! usage: rules-check FILE.yar
//!
//! Prints one rule name per line (the rule around each compile error) and
//! exits 1 when any rule fails; used by scripts/refresh-yara-rules.py.

use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: rules-check FILE.yar");
        return ExitCode::FAILURE;
    };
    let source = match std::fs::read_to_string(&path) {
        Ok(source) => source,
        Err(error) => {
            eprintln!("{path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut compiler = yara_x::Compiler::new();
    compiler.relaxed_re_syntax(true);
    match compiler.add_source(source.as_str()) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            // The error names a line; report the rule that contains it.
            let text = error.to_string();
            let line = text
                .split("-->")
                .nth(1)
                .and_then(|rest| rest.split(':').nth(1))
                .and_then(|line| line.trim().parse::<usize>().ok());
            let rule = line.and_then(|line| {
                source
                    .lines()
                    .take(line)
                    .filter_map(|l| {
                        let l = l
                            .trim_start_matches("private ")
                            .trim_start_matches("global ");
                        l.strip_prefix("rule ").map(|r| {
                            r.split(|c: char| !c.is_alphanumeric() && c != '_')
                                .next()
                                .unwrap_or("")
                        })
                    })
                    .last()
                    .map(str::to_owned)
            });
            match rule {
                Some(rule) => println!("{rule}"),
                None => eprintln!("{text}"),
            }
            ExitCode::FAILURE
        }
    }
}
