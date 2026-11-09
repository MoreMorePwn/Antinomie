// SPDX-License-Identifier: GPL-3.0-only
//! Which files a run's launch names as libraries to load into another
//! program: the `LD_PRELOAD` and `LD_AUDIT` of its environment, the same
//! variables set inside a shell command line, and any other absolute path in
//! its arguments. Only names are read here; the library turns a name into a
//! sample by the hash it recorded when it sent the file into the VM.

/// A path the launch names and how: `(via, path)`, `via` being `LD_PRELOAD`,
/// `LD_AUDIT` or `argument`. First seen first, without repeats.
pub fn candidates(env: &[String], args: &[String]) -> Vec<(&'static str, String)> {
    let mut found: Vec<(&'static str, String)> = Vec::new();
    let mut add = |via: &'static str, path: &str| {
        let path = path.trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ';' | '(' | ')'));
        // A path built by the shell ($L, `ls ...`, a glob) is not a name yet.
        if path.starts_with('/')
            && !path.contains(['$', '`', '*', '?'])
            && !found.iter().any(|(v, p)| *v == via && p == path)
        {
            found.push((via, path.to_owned()));
        }
    };
    for variable in env {
        if let Some((name, value)) = variable.split_once('=') {
            let via = match name {
                "LD_PRELOAD" => "LD_PRELOAD",
                "LD_AUDIT" => "LD_AUDIT",
                _ => continue,
            };
            for path in value.split([':', ' ']).filter(|part| !part.is_empty()) {
                add(via, path);
            }
        }
    }
    for arg in args {
        let mut rest = arg.as_str();
        // `LD_PRELOAD=/tmp/a.so ls` inside a `-c` script, in any position.
        for (variable, via) in [("LD_PRELOAD=", "LD_PRELOAD"), ("LD_AUDIT=", "LD_AUDIT")] {
            let mut at = 0;
            while let Some(found_at) = rest[at..].find(variable) {
                let start = at + found_at + variable.len();
                let value = rest[start..]
                    .trim_start_matches(['"', '\''])
                    .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ';'))
                    .next()
                    .unwrap_or("");
                for path in value.split(':').filter(|part| !part.is_empty()) {
                    add(via, path);
                }
                at = start;
            }
        }
        rest = arg.as_str();
        for word in rest.split(|c: char| c.is_whitespace() || matches!(c, '=' | ':')) {
            add("argument", word);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn own(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn environment_variables_name_libraries_in_order() {
        let found = candidates(
            &own(&[
                "PATH=/bin",
                "LD_PRELOAD=/tmp/a.so:/tmp/b.so",
                "LD_AUDIT=/tmp/c.so",
            ]),
            &[],
        );
        assert_eq!(
            found,
            [
                ("LD_PRELOAD", "/tmp/a.so".to_owned()),
                ("LD_PRELOAD", "/tmp/b.so".to_owned()),
                ("LD_AUDIT", "/tmp/c.so".to_owned()),
            ]
        );
    }

    #[test]
    fn a_shell_command_line_sets_the_variable_inside_the_script() {
        let found = candidates(
            &[],
            &own(&["-c", "LD_PRELOAD=/tmp/lib.so ls; LD_AUDIT='/tmp/au.so' id"]),
        );
        assert!(
            found.contains(&("LD_PRELOAD", "/tmp/lib.so".to_owned())),
            "{found:?}"
        );
        assert!(
            found.contains(&("LD_AUDIT", "/tmp/au.so".to_owned())),
            "{found:?}"
        );
    }

    #[test]
    fn an_argument_path_is_named_as_an_argument_and_a_shell_expansion_is_not_a_name() {
        let found = candidates(
            &[],
            &own(&[
                "/tmp/helper.sh",
                "-c",
                "L=$(ls /tmp/40b5127c-*); LD_PRELOAD=$L ls",
            ]),
        );
        assert_eq!(found, [("argument", "/tmp/helper.sh".to_owned())]);
    }
}
