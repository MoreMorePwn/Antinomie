// SPDX-License-Identifier: GPL-3.0-only
//! `custody verify`: check a sample's tamper-evident chain, or the whole
//! library, and export the record of one sample (design 3.4.3). No engine lock.
use super::library::{library_error, open_existing, parse_sha256};
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    output::{Reply, block, table},
};
use antinomie_monitor_core::samples::{ChainCheck, ExportFormat, SignWith, Signer};
use clap::{Subcommand, ValueEnum};
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum Custody {
    /// Check one sample's custody chain, or every chain and the library index.
    Verify {
        /// One sample; default: the whole library.
        sha256: Option<String>,
        /// Write the custody record of the sample to this file (`.html` writes
        /// the readable page, anything else JSON with the verifier beside it).
        #[arg(long, value_name = "PATH")]
        export: Option<PathBuf>,
        /// Sign the export with your own key (needs --key).
        #[arg(long, value_enum, requires = "key", requires = "export")]
        sign: Option<SignerArg>,
        /// The key file `minisign -s` or `ssh-keygen -Y sign` uses; never read by Antinomie.
        #[arg(long, value_name = "PATH", requires = "sign")]
        key: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum SignerArg {
    Minisign,
    Ssh,
}

pub fn run(custody: &Custody, context: &Context) -> Result<Reply, CliError> {
    let Custody::Verify {
        sha256,
        export,
        sign,
        key,
    } = custody;
    let library = open_existing(context.data_dir())?;
    match sha256 {
        Some(sha256) => {
            let sha256 = parse_sha256(sha256)?;
            let signing = sign.zip(key.clone()).map(|(signer, key)| SignWith {
                signer: match signer {
                    SignerArg::Minisign => Signer::Minisign,
                    SignerArg::Ssh => Signer::Ssh,
                },
                key,
            });
            one(&sha256, export.as_deref(), signing.as_ref(), library)
        }
        None => {
            if export.is_some() {
                return Err(
                    CliError::invalid("--export needs the SHA-256 of one sample")
                        .with_field("export"),
                );
            }
            all(library)
        }
    }
}

fn problem_value(check: &ChainCheck) -> Value {
    serde_json::to_value(&check.problem).unwrap_or(Value::Null)
}

fn chain_value(sha256: &str, check: &ChainCheck) -> Value {
    json!({
        "sha256": sha256, "ok": check.ok(), "entries": check.entries,
        "head": check.head, "problem": problem_value(check),
    })
}

fn one(
    sha256: &str,
    export: Option<&std::path::Path>,
    sign: Option<&SignWith>,
    library: Option<antinomie_monitor_core::samples::Library>,
) -> Result<Reply, CliError> {
    let mut library = library.ok_or_else(|| {
        CliError::not_found(format!("sample {sha256} is not in the library")).with_field("sha256")
    })?;
    if !library.contains(sha256).map_err(library_error)? {
        return Err(
            CliError::not_found(format!("sample {sha256} is not in the library"))
                .with_field("sha256"),
        );
    }
    let check = library.custody_check(sha256).map_err(library_error)?;
    let mut value = chain_value(sha256, &check);
    if let Some(path) = export {
        let format = if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("html"))
        {
            ExportFormat::Html
        } else {
            ExportFormat::Json
        };
        let done = library
            .export_custody(sha256, format, path, sign)
            .map_err(|message| CliError::new(ErrorCode::Internal, message))?;
        value["export"] = json!({
            "path": done.path, "verifier": done.verifier, "signature": done.signature,
            "head": done.head, "entries": done.entries, "verified": done.verified,
        });
    }
    let text = block(&[
        ("sample", sha256.to_owned()),
        ("custody", check.summary()),
        ("verified", check.ok().to_string()),
    ]);
    if check.ok() {
        return Ok(Reply::value(value).with_human(text));
    }
    Err(
        CliError::new(ErrorCode::VerificationFailed, check.summary())
            .with_details(value)
            .with_human_output(text),
    )
}

fn all(library: Option<antinomie_monitor_core::samples::Library>) -> Result<Reply, CliError> {
    let Some(library) = library else {
        let empty =
            json!({"ok": true, "index": {"records": 0, "ok": true}, "samples": [], "broken": []});
        return Ok(Reply::value(empty).with_human("The library has no custody records.\n".into()));
    };
    let check = library.custody_check_all().map_err(library_error)?;
    let samples: Vec<Value> = check
        .samples
        .iter()
        .map(|(sha, c)| chain_value(sha, c))
        .collect();
    let broken: Vec<&str> = check.broken();
    let index_ok = check.index.problem.is_none();
    let ok = index_ok && broken.is_empty();
    let value = json!({
        "ok": ok,
        "index": {
            "records": check.index.records, "head": check.index.head, "ok": index_ok,
            "problem": serde_json::to_value(&check.index.problem).unwrap_or(Value::Null),
        },
        "samples": samples,
        "broken": broken,
    });
    let rows: Vec<Vec<String>> = check
        .samples
        .iter()
        .map(|(sha, c)| {
            vec![
                sha.clone(),
                c.entries.to_string(),
                if c.ok() {
                    "verified".into()
                } else {
                    c.summary()
                },
            ]
        })
        .collect();
    let mut text = format!(
        "library index: {} records, {}\n\n",
        check.index.records,
        if index_ok {
            "every link matches"
        } else {
            "DOES NOT VERIFY"
        }
    );
    text.push_str(&table(&["sha256", "entries", "chain"], &rows));
    if ok {
        return Ok(Reply::value(value).with_human(text));
    }
    Err(CliError::new(
        ErrorCode::VerificationFailed,
        format!(
            "custody check failed: {}{} sample chain(s) broken",
            if index_ok { "" } else { "library index, " },
            broken.len()
        ),
    )
    .with_details(value)
    .with_human_output(text))
}

#[cfg(test)]
mod tests {
    use crate::{
        app::{Environment, execute},
        exit::Exit,
    };
    use serde_json::Value;
    use std::{ffi::OsString, path::PathBuf};

    fn cli(data: &std::path::Path, args: &[&str]) -> (Exit, Value) {
        let mut all: Vec<OsString> = ["antinomie-cli", "-o", "json", "--data-dir"]
            .iter()
            .map(OsString::from)
            .collect();
        all.push(data.into());
        all.extend(args.iter().map(OsString::from));
        let environment = Environment {
            stdout_is_terminal: false,
            stderr_is_terminal: false,
            no_color: true,
            home: None,
        };
        let (exit, out) = execute(all, &environment);
        (
            exit,
            serde_json::from_str(&out.stdout).unwrap_or(Value::Null),
        )
    }

    fn scratch(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("ant-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn verify_export_and_tamper_detection() {
        let root = scratch("custody");
        let data = root.join("data");
        let file = root.join("s.bin");
        std::fs::write(&file, b"custody sample").unwrap();

        // No library yet: the whole-library check passes and creates nothing.
        let (exit, empty) = cli(&data, &["custody", "verify"]);
        assert_eq!(exit, Exit::Ok);
        assert_eq!(empty["result"]["ok"], true);
        assert!(!data.exists());

        let (_, added) = cli(&data, &["sample", "add", file.to_str().unwrap()]);
        let sha = added["result"]["items"][0]["sha256"]
            .as_str()
            .unwrap()
            .to_owned();

        let (exit, one) = cli(&data, &["custody", "verify", &sha]);
        assert_eq!(exit, Exit::Ok);
        assert_eq!(one["result"]["ok"], true);
        assert!(one["result"]["entries"].as_u64().unwrap() >= 1);
        let (exit, all) = cli(&data, &["custody", "verify"]);
        assert_eq!(exit, Exit::Ok);
        assert_eq!(all["result"]["samples"].as_array().unwrap().len(), 1);
        assert_eq!(all["result"]["index"]["ok"], true);

        // Export JSON (with the verifier beside it) and HTML.
        let json_out = root.join("export").join("custody.json");
        let (exit, exported) = cli(
            &data,
            &[
                "custody",
                "verify",
                &sha,
                "--export",
                json_out.to_str().unwrap(),
            ],
        );
        assert_eq!(exit, Exit::Ok, "{exported}");
        assert_eq!(exported["result"]["export"]["verified"], true);
        assert!(json_out.is_file() && json_out.with_file_name("verify-custody.py").is_file());
        let exported_text: Value =
            serde_json::from_str(&std::fs::read_to_string(&json_out).unwrap()).unwrap();
        assert_eq!(exported_text["sample"]["sha256"], sha.as_str());
        let html_out = root.join("export").join("custody.html");
        let (exit, _) = cli(
            &data,
            &[
                "custody",
                "verify",
                &sha,
                "--export",
                html_out.to_str().unwrap(),
            ],
        );
        assert_eq!(exit, Exit::Ok);
        assert!(
            std::fs::read_to_string(&html_out)
                .unwrap()
                .contains("<html")
        );

        // Argument rules.
        let (exit, _) = cli(
            &data,
            &["custody", "verify", "--export", json_out.to_str().unwrap()],
        );
        assert_eq!(exit.code(), 4);
        let (exit, _) = cli(&data, &["custody", "verify", &sha, "--sign", "ssh"]);
        assert_eq!(exit.code(), 2);
        let (exit, _) = cli(&data, &["custody", "verify", &"0".repeat(64)]);
        assert_eq!(exit.code(), 3);

        // Tamper with a stored entry: both checks fail with exit 1.
        let database = antinomie_monitor_core::samples::samples_dir(&data).join("library.sqlite");
        let connection = rusqlite::Connection::open(&database).unwrap();
        let changed = connection
            .execute(
                "UPDATE custody_entry SET detail = detail || ' x' WHERE seq = 1",
                [],
            )
            .unwrap();
        drop(connection);
        assert!(changed > 0);
        let (exit, broken) = cli(&data, &["custody", "verify", &sha]);
        assert_eq!(exit.code(), 1);
        assert_eq!(broken["error"]["code"], "verification_failed");
        assert_eq!(broken["error"]["details"]["ok"], false);
        let (exit, _) = cli(&data, &["custody", "verify"]);
        assert_eq!(exit.code(), 1);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
