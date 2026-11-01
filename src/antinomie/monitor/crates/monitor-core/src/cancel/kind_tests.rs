//! One test per kind of download: a cancel stops it within a second or two and
//! leaves no partial file, temporary folder or changed state. The `curl` here is
//! a script that writes a few bytes where it was told to and then waits, so
//! nothing touches the network.
use super::*;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ant-kinds-{tag}-{}-{}",
        std::process::id(),
        crate::storage::unique_id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A `curl` that answers `--version`, writes "partial" to its `-o` or
/// `--output` file and then sleeps.
fn hanging_curl(dir: &Path) -> PathBuf {
    let script = dir.join("hanging-curl.sh");
    fs::write(
        &script,
        "#!/bin/sh\n\
         [ \"$1\" = \"--version\" ] && { echo 'curl 8.0 (test)'; exit 0; }\n\
         out=\n\
         while [ $# -gt 0 ]; do case \"$1\" in -o|--output) out=\"$2\"; shift;; esac; shift; done\n\
         [ -n \"$out\" ] && [ \"$out\" != /dev/null ] && printf partial > \"$out\"\n\
         exec sleep 60\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    script
}

/// Run `job` with a flag that is set 500 ms later; it must end as a cancel,
/// well before the script's 60 s.
fn cancelled_soon<T>(job: impl FnOnce(&AtomicBool) -> Result<T, String>) -> String
where
    T: std::fmt::Debug,
{
    let token = CancelToken::new();
    let later = token.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(500));
        later.cancel();
    });
    let started = Instant::now();
    let error = job(&token).expect_err("a cancel is an error");
    assert!(is_cancelled(&error), "{error}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "stopped in {:?}",
        started.elapsed()
    );
    error
}

fn files_under(dir: &Path) -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
            let path = entry.path();
            out.push(path.display().to_string());
            if path.is_dir() {
                walk(&path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out
}

#[test]
fn a_cancelled_base_download_removes_its_staging_folder() {
    let dir = scratch("base");
    let curl = hanging_curl(&dir);
    let staging = dir.join("downloads").join("0".repeat(64));
    let base = crate::distribution::CatalogBase {
        identity: "0".repeat(64),
        label: "Test".into(),
        files: vec![crate::distribution::CatalogFile {
            name: "kernel".into(),
            size: 10_000_000,
            sha256: "a".repeat(64),
        }],
        ..Default::default()
    };
    cancelled_soon(|cancel| {
        crate::distribution::download_base(
            &curl,
            "https://example.invalid/resolve",
            &base,
            &staging,
            cancel,
            |_, _| {},
        )
        .map(|_| ())
    });
    assert!(!staging.exists(), "{:?}", files_under(&dir));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_cancelled_catalog_refresh_leaves_no_temp_file_and_no_catalog() {
    let dir = scratch("catalog");
    let curl = hanging_curl(&dir);
    let before: Vec<_> = temp_catalogs();
    cancelled_soon(|cancel| {
        crate::distribution::fetch_catalog(&curl, "https://example.invalid/resolve", cancel)
            .map(|_| ())
    });
    let after: Vec<_> = temp_catalogs();
    assert_eq!(before.len(), after.len().min(before.len()), "{after:?}");
    assert!(
        after.iter().all(|path| before.contains(path)),
        "no catalog file of this run: {after:?}"
    );
    fs::remove_dir_all(dir).unwrap();
}

fn temp_catalogs() -> Vec<PathBuf> {
    fs::read_dir(std::env::temp_dir())
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with(&format!("antinomie-catalog-{}-", std::process::id()))
                })
        })
        .collect()
}

#[test]
fn a_cancelled_tool_install_removes_its_downloads_and_keeps_the_installed_tool() {
    let dir = scratch("tool");
    let curl = hanging_curl(&dir);
    // A tool that is already installed stays exactly as it was.
    let package = crate::analysis_tools::package("capa").unwrap();
    let installed = crate::analysis_tools::tools_dir(&dir).join(package.id);
    fs::create_dir_all(&installed).unwrap();
    fs::write(
        installed.join("tool.json"),
        b"{\"id\":\"capa\",\"version\":\"0\"}",
    )
    .unwrap();
    cancelled_soon(|cancel| {
        crate::analysis_tools::install(&curl, &dir, "capa", cancel, |_, _, _| {})
    });
    let tools = crate::analysis_tools::tools_dir(&dir);
    assert!(
        !tools.join(".downloads").exists(),
        "{:?}",
        files_under(&tools)
    );
    assert!(!tools.join(".capa.partial").exists());
    assert_eq!(
        fs::read(installed.join("tool.json")).unwrap(),
        b"{\"id\":\"capa\",\"version\":\"0\"}"
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_cancelled_python_tool_install_removes_its_environment() {
    let dir = scratch("pip");
    // `sigma` is a pip install: the step is cancelled before pip is reached.
    let flag = AtomicBool::new(true);
    let error =
        crate::analysis_tools::install(Path::new("curl"), &dir, "sigma", &flag, |_, _, _| {})
            .unwrap_err();
    assert!(is_cancelled(&error), "{error}");
    let tools = crate::analysis_tools::tools_dir(&dir);
    assert!(
        !tools.join(".sigma.partial").exists() && !tools.join("sigma").exists(),
        "{:?}",
        files_under(&tools)
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_cancelled_plugin_install_removes_its_staging_folder() {
    let dir = scratch("plugin");
    let curl = hanging_curl(&dir);
    let plugin = crate::memory::community::catalog().unwrap().remove(0);
    let (plugins, staging) = (dir.join("plugins"), dir.join("staging"));
    fs::create_dir_all(&staging).unwrap();
    cancelled_soon(|cancel| {
        crate::memory::community::install(&curl, &plugins, &staging, &plugin, cancel, |_, _| {})
    });
    assert!(
        files_under(&staging).is_empty(),
        "{:?}",
        files_under(&staging)
    );
    assert!(!plugins.join(&plugin.id).exists());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_cancelled_kernel_source_download_removes_its_partial_file() {
    let dir = scratch("kit");
    let curl = hanging_curl(&dir);
    let inputs = dir.join("inputs");
    cancelled_soon(|cancel| crate::kit::fetch_orig(&curl, &inputs, cancel, |_, _| {}).map(|_| ()));
    assert!(
        files_under(&inputs).is_empty(),
        "{:?}",
        files_under(&inputs)
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_cancelled_sample_download_stores_nothing_and_leaves_no_part_file() {
    let dir = scratch("sample");
    let curl = hanging_curl(&dir);
    let info = crate::samples::SampleInfo {
        sha256_hash: "ab".repeat(32),
        file_name: "x.elf".into(),
        ..Default::default()
    };
    for source in [
        crate::samples::Source::MalwareBazaar,
        crate::samples::Source::MalShare,
    ] {
        cancelled_soon(|cancel| {
            source
                .download(&curl, "abc123def456", &dir, &info, cancel)
                .map(|_| ())
        });
    }
    assert!(crate::samples::stored(&dir).is_empty());
    let parts: Vec<_> = files_under(&dir)
        .into_iter()
        .filter(|path| path.ends_with(".part") || path.ends_with(".zip"))
        .collect();
    assert!(parts.is_empty(), "{parts:?}");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_cancelled_sample_search_returns_at_once() {
    let dir = scratch("search");
    let curl = hanging_curl(&dir);
    for source in [
        crate::samples::Source::MalwareBazaar,
        crate::samples::Source::MalShare,
    ] {
        cancelled_soon(|cancel| source.find(&curl, "abc123def456", "Mirai", 10, cancel));
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_cancelled_online_lookup_and_key_test_return_at_once() {
    use crate::ioc::online::{Body, CurlTransport, THREATFOX_API, Transport};
    let dir = scratch("online");
    let curl = hanging_curl(&dir);
    let transport = CurlTransport { curl: curl.clone() };
    let key = crate::api_keys::Secret::new("abc123def456");
    cancelled_soon(|cancel| transport.post(THREATFOX_API, Body::Json("{}"), &key, cancel));
    cancelled_soon(|cancel| {
        crate::api_keys::test(&curl, crate::api_keys::ApiKey::MalShare, &key, cancel)
    });
    cancelled_soon(|cancel| {
        crate::api_keys::test(&curl, crate::api_keys::ApiKey::Abusech, &key, cancel)
    });
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_cancelled_update_check_returns_at_once() {
    let dir = scratch("update");
    let curl = hanging_curl(&dir);
    cancelled_soon(|cancel| {
        crate::update_check::check(
            "0.8.0",
            &crate::update_check::CurlGet { curl: &curl },
            cancel,
        )
    });
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_cancelled_rule_download_leaves_no_staging_file() {
    use crate::ruleset::{Curl, Fetcher};
    let dir = scratch("rules");
    let curl = Curl::new(hanging_curl(&dir));
    let target = dir.join("download.bin");
    cancelled_soon(|cancel| {
        curl.fetch(
            "https://example.invalid/pack.zip",
            &target,
            1 << 20,
            cancel,
            &mut |_| {},
        )
    });
    assert!(!target.exists());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_cancelled_build_step_kills_what_the_build_started() {
    let dir = scratch("build");
    let pid_file = dir.join("helper.pid");
    let mut command = Command::new("sh");
    command.arg("-c").arg(format!(
        "sleep 60 & echo $! > '{}'; wait",
        pid_file.display()
    ));
    let token = CancelToken::new();
    let later = token.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(500));
        later.cancel();
    });
    let error = crate::build::run_streaming(&mut command, "test build", &token, |_| {})
        .expect_err("cancelled");
    assert_eq!(error, "build cancelled");
    let helper: u32 = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let waiting = Instant::now();
    let alive = |pid: u32| {
        fs::read_to_string(format!("/proc/{pid}/stat"))
            .is_ok_and(|stat| !stat.rsplit(") ").next().unwrap_or("").starts_with('Z'))
    };
    while alive(helper) && waiting.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!alive(helper), "the helper the build started is gone");
    fs::remove_dir_all(dir).unwrap();
}
