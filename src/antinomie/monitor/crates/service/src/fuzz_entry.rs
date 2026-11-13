// SPDX-License-Identifier: GPL-3.0-only
//! Entry points of the fuzz targets of card P5-2 (design 7.2 T10). Each takes
//! arbitrary bytes, must never panic or hang, and checks the invariants the
//! surface promises. The targets in `monitor/fuzz/fuzz_targets/` only call
//! these; `tests` below runs each over hostile and generated inputs in the
//! normal test run. The socket framing has its own entry,
//! [`crate::server::frame::fuzz_entry`].

use crate::{
    api::spec::RunRequest,
    config::validate,
    intake::staging::valid_name,
    verdict::{Expr, Facts},
    watch::{safety::looks_partial, settle::sanitize},
};
use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path};

/// `RunRequest` JSON as a socket client or the CLI sends it: parse, check the
/// shape, and a spec that parsed must survive a round trip unchanged.
pub fn job_spec(data: &[u8]) {
    let Ok(spec) = serde_json::from_slice::<RunRequest>(data) else {
        return;
    };
    let _ = spec.validate_shape();
    let text = serde_json::to_vec(&spec).expect("a spec encodes");
    let again: RunRequest = serde_json::from_slice(&text).expect("an encoded spec parses");
    assert_eq!(again, spec);
}

/// Preset and service TOML as an administrator's file: parse and run every
/// check; problems are data, never a panic. The same text as overrides of
/// Standard goes through the Custom rule.
pub fn config_toml(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (preset, problems) = validate::parse_preset("fuzz", "fuzz.toml", text);
    assert!(preset.is_some() || !problems.is_empty());
    if let Ok(serde_json::Value::Object(overrides)) =
        toml::from_str::<toml::Value>(text).map(|v| serde_json::to_value(v).unwrap_or_default())
        && let Some(standard) = crate::config::PresetLookup::get(
            &crate::config::PresetSet::built_in(),
            crate::config::builtin::DEFAULT_PRESET,
        )
        && let Ok(custom) = standard.apply(&overrides)
    {
        let _ = validate::check_options(&custom.preset);
        let _ = validate::reserved(&custom.preset);
    }
    let (service, problems) = validate::parse_service("service.toml", text);
    assert!(service.is_some() || !problems.is_empty());
}

/// The names a watch folder, an upload and a preset file bring: cut the
/// input at NUL and `/` into names and check each against the rules that keep
/// it from becoming a path, a command or markup.
pub fn watch_names(data: &[u8]) {
    for name in data.split(|b| *b == 0) {
        let safe = sanitize(name);
        assert!(!safe.is_empty() && safe.len() <= 100 && !safe.starts_with('.'));
        assert!(
            safe.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        );
        let _ = looks_partial(name);
        let shown = crate::intake::display_name(Path::new(OsStr::from_bytes(name)));
        assert!(shown.chars().count() <= 128 && !shown.chars().any(char::is_control));
        if let Ok(text) = std::str::from_utf8(name) {
            if valid_name(text) {
                assert!(!text.contains(['/', '\0']) && !text.chars().any(char::is_control));
            }
            let _ = validate::valid_preset_name(text);
        }
    }
}

/// The label expression grammar (`when` in the preset's verdict.rule): parse
/// arbitrary text and evaluate what parses against two extreme fact sets.
pub fn label_expr(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(expr) = Expr::parse(text) {
        let none = Facts::without_triage(None, 0);
        let _ = expr.eval(&none);
        let _ = expr.eval(&Facts::without_triage(None, 9));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random bytes (no dependency, same every run).
    fn generated(count: usize, len: usize) -> Vec<Vec<u8>> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        (0..count)
            .map(|_| {
                (0..len)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        state as u8
                    })
                    .collect()
            })
            .collect()
    }

    fn all(entry: fn(&[u8]), hostile: &[&[u8]]) {
        for input in hostile {
            entry(input);
        }
        for input in generated(500, 96) {
            entry(&input);
        }
    }

    /// Found by the `watch_names` target (ANT-T0387): a 100-byte name that
    /// starts with a dot got a `_` in front and came out 101 bytes long.
    #[test]
    fn a_long_dotted_name_is_still_at_most_100_bytes() {
        let name = [b".".as_slice(), &[b'n'; 150]].concat();
        let safe = sanitize(&name);
        assert_eq!(safe.len(), 100);
        assert!(safe.starts_with('_'));
        watch_names(&name);
        watch_names(&[b".".as_slice(), &[b'n'; 99]].concat());
    }

    #[test]
    fn every_entry_survives_hostile_and_generated_bytes() {
        let deep = "(".repeat(5000);
        let deep_not = "not ".repeat(5000);
        let hostile: Vec<&[u8]> = vec![
            b"",
            b"\0",
            b"{}",
            b"[]",
            b"null",
            br#"{"sample":{"sha256":null}}"#,
            br#"{"sample":{"path":"/x"},"labels":{"A":"b"},"overrides":{"program":{"run_time_s":4}}}"#,
            br#"{"sample":{"path":"/x"},"overrides":{"network":{"route":"vpn:x"},"program":{"environment":["x"]}}}"#,
            b"[vm]\nlane_vm = \"a\"\n[accepts]\ntypes = [1]\n",
            b"[program]\nrun_time_s = 4\n[network]\nroute = \"socks5:\"\n",
            b"[[verdict.rule]]\nwhen = \"((((\"\n",
            b"a\0..\0\x1b[31m\0\xff\xfe\0.part\0",
            b"x = ",
            deep.as_bytes(),
            deep_not.as_bytes(),
            b"true and (false or not true) and count(x) > 3",
            b"\xff\xfe",
        ];
        for entry in [job_spec, config_toml, watch_names, label_expr] {
            all(entry, &hostile);
        }
    }
}
