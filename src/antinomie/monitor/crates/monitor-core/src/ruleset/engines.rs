// SPDX-License-Identifier: MIT
//! What the scan engines on this host report about themselves.
//!
//! Requirements in the rules catalog are checked against these facts, and the
//! facts are part of the selection digest. The Sigma probe runs the same
//! interpreter the scan runs, so a pack is never qualified against a Python
//! the scan does not use. Results are cached per tool configuration and
//! refreshed in the background, so a tool installed during a session is picked
//! up without restarting the application.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard, OnceLock, atomic::AtomicBool},
    time::{Duration, Instant, UNIX_EPOCH},
};

/// Interpreter the Sigma scan runs when no interpreter is configured.
pub const DEFAULT_SIGMA_PYTHON: &str = "/usr/bin/python3";

/// How long a probe result is used before it is refreshed in the background.
const FRESH_FOR: Duration = Duration::from_secs(60);
/// Upper bound on one probe, including interpreter start-up.
const PROBE_TIMEOUT: Duration = Duration::from_secs(20);
/// Upper bound on the probe's stdout, in octets.
const PROBE_OUTPUT_SIZE: usize = 16 * 1024;
/// Number of tool configurations kept in the cache.
const CACHE_COUNT: usize = 16;

/// Reports the installed distributions by metadata, not module attributes:
/// pySigma 2 and its SQLite backend define no `__version__`.
const SIGMA_PROBE: &str = r#"import importlib.metadata as m, json
out = {}
for name in ("pysigma", "pysigma-backend-sqlite"):
    try:
        out[name] = m.version(name)
    except m.PackageNotFoundError:
        out[name] = None
    except Exception as error:
        out[name] = "error: %s" % type(error).__name__
try:
    from sigma.backends.sqlite import sqliteBackend
    out["backend_import"] = "ok"
except Exception as error:
    out["backend_import"] = ("%s: %s" % (type(error).__name__, error))[:300]
print(json.dumps(out))
"#;

/// The engine tools a selection is evaluated with. It must name what the
/// scan itself runs.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ToolConfig {
    pub sigma_python: PathBuf,
}

impl Default for ToolConfig {
    fn default() -> Self {
        Self::from_sigma_setting("")
    }
}

impl ToolConfig {
    /// `setting` is the detection settings' interpreter field; see [`sigma_interpreter`].
    pub fn from_sigma_setting(setting: &str) -> Self {
        Self {
            sigma_python: sigma_interpreter(setting),
        }
    }
}

/// The interpreter a Sigma scan runs for the settings field `setting`: the
/// configured path with `~/` expanded, or [`DEFAULT_SIGMA_PYTHON`] when empty.
/// No environment variable overrides a configured interpreter.
pub fn sigma_interpreter(setting: &str) -> PathBuf {
    let setting = setting.trim();
    if setting.is_empty() {
        return PathBuf::from(DEFAULT_SIGMA_PYTHON);
    }
    setting
        .strip_prefix("~/")
        .and_then(|tail| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(tail)))
        .unwrap_or_else(|| PathBuf::from(setting))
}

/// One probe result. Each variant maps to a different requirement status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolProbe {
    /// The tool runs. `version` is what requirements are compared against.
    Found { identity: String, version: String },
    /// The tool or a required package is not installed.
    Absent(String),
    /// The tool is installed but cannot do what a scan needs.
    Broken(String),
    /// The probe did not produce a usable answer.
    Unknown(String),
}

impl ToolProbe {
    /// Text recorded in digests and manifests.
    pub fn identity(&self) -> String {
        match self {
            Self::Found { identity, .. } => identity.clone(),
            Self::Absent(reason) => format!("absent: {reason}"),
            Self::Broken(reason) => format!("unusable: {reason}"),
            Self::Unknown(reason) => format!("unknown: {reason}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolFacts {
    pub app: String,
    pub yara: String,
    pub suricata: ToolProbe,
    pub sigma: ToolProbe,
    /// Interpreter the Sigma facts were read from.
    pub sigma_python: PathBuf,
}

impl ToolFacts {
    /// Text recorded as `engine_identity` in a selection manifest.
    pub fn identity(&self, engine: &str) -> String {
        match engine {
            "yara" => format!("yara-x {}", self.yara),
            "ids" => self.suricata.identity(),
            "sigma" => format!(
                "{} ({})",
                self.sigma.identity(),
                self.sigma_python.display()
            ),
            other => other.to_owned(),
        }
    }
}

/// Facts for `config`, probing whatever is not cached. Blocks for at most
/// two probe timeouts; call it from a worker, not a UI frame.
pub fn tool_facts(config: &ToolConfig) -> ToolFacts {
    let sigma_key = sigma_key(&config.sigma_python);
    let sigma = cached(&sigma_key, || probe_sigma(&config.sigma_python));
    let suricata = cached(SURICATA_KEY, probe_suricata);
    assemble(config, suricata, sigma)
}

/// Cached facts for `config` without blocking. When a probe is still needed
/// it starts in the background, this returns `None`, and `ready` runs once the
/// result is stored. Stale facts are returned while a refresh runs.
pub fn try_tool_facts(
    config: &ToolConfig,
    ready: impl Fn() + Send + Sync + 'static,
) -> Option<ToolFacts> {
    let ready = std::sync::Arc::new(ready);
    let sigma_key = sigma_key(&config.sigma_python);
    let python = config.sigma_python.clone();
    let notify = std::sync::Arc::clone(&ready);
    let sigma = peek(&sigma_key, move || probe_sigma(&python), move || notify());
    let notify = std::sync::Arc::clone(&ready);
    let suricata = peek(SURICATA_KEY, probe_suricata, move || notify());
    Some(assemble(config, suricata?, sigma?))
}

/// Forget every probe result, for example after the user installs a tool.
pub fn refresh_tool_facts() {
    cache().clear();
}

fn assemble(config: &ToolConfig, suricata: ToolProbe, sigma: ToolProbe) -> ToolFacts {
    ToolFacts {
        app: crate::api::APP_VERSION.into(),
        yara: yara_x::VERSION.into(),
        suricata,
        sigma,
        sigma_python: config.sigma_python.clone(),
    }
}

const SURICATA_KEY: &str = "suricata";

/// The interpreter path plus its file identity, so replacing the interpreter
/// at the same path is a different key.
fn sigma_key(python: &Path) -> String {
    let stamp = std::fs::metadata(python)
        .map(|meta| {
            let modified = meta
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |time| time.as_nanos());
            format!("{}:{modified}", meta.len())
        })
        .unwrap_or_else(|_| "missing".into());
    format!("sigma:{}:{stamp}", python.display())
}

struct Entry {
    /// `None` while the first probe for this key runs.
    probe: Option<ToolProbe>,
    probed_at: Instant,
    refreshing: bool,
}

fn cache() -> MutexGuard<'static, HashMap<String, Entry>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Entry>>> = OnceLock::new();
    CACHE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

fn store(key: &str, probe: ToolProbe) {
    let mut entries = cache();
    if entries.len() >= CACHE_COUNT
        && !entries.contains_key(key)
        && let Some(oldest) = entries
            .iter()
            .min_by_key(|(_, entry)| entry.probed_at)
            .map(|(key, _)| key.clone())
    {
        entries.remove(&oldest);
    }
    entries.insert(
        key.to_owned(),
        Entry {
            probe: Some(probe),
            probed_at: Instant::now(),
            refreshing: false,
        },
    );
}

fn cached(key: &str, probe: impl FnOnce() -> ToolProbe) -> ToolProbe {
    if let Some(entry) = cache().get(key)
        && entry.probed_at.elapsed() < FRESH_FOR
        && let Some(result) = &entry.probe
    {
        return result.clone();
    }
    let result = probe();
    store(key, result.clone());
    result
}

/// The cached result for `key`, starting a background probe when it is
/// missing or stale. `None` means no result exists yet.
fn peek(
    key: &str,
    probe: impl FnOnce() -> ToolProbe + Send + 'static,
    ready: impl FnOnce() + Send + 'static,
) -> Option<ToolProbe> {
    let (current, start) = {
        let mut entries = cache();
        match entries.get_mut(key) {
            Some(entry) if entry.probe.is_some() && entry.probed_at.elapsed() < FRESH_FOR => {
                return entry.probe.clone();
            }
            Some(entry) => {
                let start = !entry.refreshing;
                entry.refreshing = true;
                (entry.probe.clone(), start)
            }
            None => {
                entries.insert(
                    key.to_owned(),
                    Entry {
                        probe: None,
                        probed_at: Instant::now(),
                        refreshing: true,
                    },
                );
                (None, true)
            }
        }
    };
    if start {
        let owned = key.to_owned();
        let spawned = std::thread::Builder::new()
            .name("rules-tool-probe".into())
            .spawn(move || {
                store(&owned, probe());
                ready();
            });
        if spawned.is_err() {
            // The next call tries again.
            if let Some(entry) = cache().get_mut(key) {
                entry.refreshing = false;
            }
        }
    }
    current
}

fn probe_sigma(python: &Path) -> ToolProbe {
    let Some(path) = python.to_str() else {
        return ToolProbe::Broken(format!("{} is not a UTF-8 path", python.display()));
    };
    if !python.is_file() {
        return ToolProbe::Absent(format!("interpreter {path} does not exist"));
    }
    let run = match crate::analysis::tools::run_cancellable(
        path,
        &["-I", "-c", SIGMA_PROBE],
        &[],
        PROBE_TIMEOUT,
        PROBE_OUTPUT_SIZE,
        false,
        &AtomicBool::new(false),
    ) {
        Ok(run) => run,
        Err(error) => {
            return ToolProbe::Broken(format!("interpreter {path} did not start: {error}"));
        }
    };
    if run.timed_out {
        return ToolProbe::Unknown(format!(
            "interpreter {path} did not answer within {} s",
            PROBE_TIMEOUT.as_secs()
        ));
    }
    if !run.success {
        return ToolProbe::Broken(format!("interpreter {path} failed the package probe"));
    }
    if run.truncated {
        return ToolProbe::Unknown(format!("interpreter {path} printed too much"));
    }
    sigma_from_output(&run.stdout)
}

/// Classifies the probe's JSON line.
fn sigma_from_output(stdout: &str) -> ToolProbe {
    let Some(value) = stdout
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str::<serde_json::Value>(line.trim()).ok())
        .filter(serde_json::Value::is_object)
    else {
        return ToolProbe::Unknown("the package probe printed no result".into());
    };
    let package = |name: &str| -> Result<String, ToolProbe> {
        match value.get(name) {
            None => Err(ToolProbe::Unknown(format!(
                "the probe did not report {name}"
            ))),
            Some(serde_json::Value::Null) => {
                Err(ToolProbe::Absent(format!("{name} is not installed")))
            }
            Some(serde_json::Value::String(text)) if text.starts_with("error: ") => Err(
                ToolProbe::Unknown(format!("{name} metadata is unreadable ({})", &text[7..])),
            ),
            Some(serde_json::Value::String(text)) if !text.trim().is_empty() => {
                Ok(text.trim().to_owned())
            }
            Some(_) => Err(ToolProbe::Unknown(format!("{name} reports no version"))),
        }
    };
    let sigma = match package("pysigma") {
        Ok(version) => version,
        Err(probe) => return probe,
    };
    let backend = match package("pysigma-backend-sqlite") {
        Ok(version) => version,
        Err(probe) => return probe,
    };
    match value
        .get("backend_import")
        .and_then(serde_json::Value::as_str)
    {
        Some("ok") => ToolProbe::Found {
            identity: format!("pysigma {sigma} / sqlite {backend}"),
            version: sigma,
        },
        Some(error) => ToolProbe::Broken(format!("the SQLite backend does not import: {error}")),
        None => ToolProbe::Unknown("the probe did not report the backend import".into()),
    }
}

fn probe_suricata() -> ToolProbe {
    let mut paths = Vec::new();
    if let Some(path) = std::env::var_os("ANTINOMIE_SURICATA") {
        paths.push(PathBuf::from(path));
    }
    paths.extend(
        [
            "/usr/bin/suricata",
            "/usr/sbin/suricata",
            "/usr/local/bin/suricata",
        ]
        .map(PathBuf::from),
    );
    for path in paths.iter().filter(|path| path.is_file()) {
        let Some(text) = path.to_str() else {
            continue;
        };
        let Ok(run) = crate::analysis::tools::run_cancellable(
            text,
            &["-V"],
            &[],
            PROBE_TIMEOUT,
            PROBE_OUTPUT_SIZE,
            false,
            &AtomicBool::new(false),
        ) else {
            continue;
        };
        let line = run.stdout.lines().next().unwrap_or("").trim().to_owned();
        if !line.is_empty() {
            return ToolProbe::Found {
                identity: line.clone(),
                version: line,
            };
        }
    }
    ToolProbe::Absent("Suricata is not installed".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fake_python(dir: &Path, name: &str, body: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn probe_output_separates_absent_unknown_broken_and_found() {
        let found = sigma_from_output(
            r#"{"pysigma": "2.0.1", "pysigma-backend-sqlite": "2.1.0", "backend_import": "ok"}"#,
        );
        assert_eq!(
            found,
            ToolProbe::Found {
                identity: "pysigma 2.0.1 / sqlite 2.1.0".into(),
                version: "2.0.1".into()
            }
        );
        assert!(matches!(
            sigma_from_output(r#"{"pysigma": null, "pysigma-backend-sqlite": null, "backend_import": "x"}"#),
            ToolProbe::Absent(reason) if reason.contains("pysigma ")
        ));
        assert!(matches!(
            sigma_from_output(r#"{"pysigma": "2.0.1", "pysigma-backend-sqlite": null, "backend_import": "ModuleNotFoundError"}"#),
            ToolProbe::Absent(reason) if reason.contains("backend")
        ));
        assert!(matches!(
            sigma_from_output(
                r#"{"pysigma": "2.0.1", "pysigma-backend-sqlite": "2.1.0", "backend_import": "ImportError: boom"}"#
            ),
            ToolProbe::Broken(_)
        ));
        assert!(matches!(
            sigma_from_output(
                r#"{"pysigma": "error: ValueError", "pysigma-backend-sqlite": "2.1.0", "backend_import": "ok"}"#
            ),
            ToolProbe::Unknown(_)
        ));
        assert!(matches!(
            sigma_from_output(
                r#"{"pysigma": "", "pysigma-backend-sqlite": "2.1.0", "backend_import": "ok"}"#
            ),
            ToolProbe::Unknown(_)
        ));
        assert!(matches!(
            sigma_from_output("not json"),
            ToolProbe::Unknown(_)
        ));
    }

    #[test]
    fn the_probe_runs_the_configured_interpreter_and_sees_it_change() {
        let dir = std::env::temp_dir().join(format!("ant-probe-{}", crate::storage::unique_id()));
        let python = fake_python(
            &dir,
            "python",
            r#"echo '{"pysigma": null, "pysigma-backend-sqlite": null, "backend_import": "x"}'"#,
        );
        let config = ToolConfig::from_sigma_setting(python.to_str().unwrap());
        assert_ne!(config.sigma_python, PathBuf::from(DEFAULT_SIGMA_PYTHON));
        assert!(matches!(tool_facts(&config).sigma, ToolProbe::Absent(_)));
        // Installing the packages rewrites the interpreter here; a real venv
        // install is picked up when the cached result goes stale.
        fake_python(
            &dir,
            "python",
            r#"echo '{"pysigma": "2.0.1", "pysigma-backend-sqlite": "2.1.0", "backend_import": "ok"}'"#,
        );
        assert!(matches!(tool_facts(&config).sigma, ToolProbe::Found { .. }));
        let other =
            ToolConfig::from_sigma_setting(fake_python(&dir, "other", "exit 3").to_str().unwrap());
        assert!(matches!(tool_facts(&other).sigma, ToolProbe::Broken(_)));
        let missing = ToolConfig::from_sigma_setting(dir.join("none").to_str().unwrap());
        assert!(matches!(tool_facts(&missing).sigma, ToolProbe::Absent(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_background_probe_reports_ready_and_then_answers_without_blocking() {
        let dir = std::env::temp_dir().join(format!("ant-peek-{}", crate::storage::unique_id()));
        let python = fake_python(
            &dir,
            "python",
            r#"sleep 0.3; echo '{"pysigma": "2.0.1", "pysigma-backend-sqlite": "2.1.0", "backend_import": "ok"}'"#,
        );
        let config = ToolConfig::from_sigma_setting(python.to_str().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        let tx = Mutex::new(tx);
        let started = Instant::now();
        let first = try_tool_facts(&config, move || {
            let _ = tx.lock().unwrap().send(());
        });
        assert!(started.elapsed() < Duration::from_millis(250));
        if first.is_none() {
            rx.recv_timeout(Duration::from_secs(20)).unwrap();
            // Suricata may still be probing; wait for both.
            let deadline = Instant::now() + Duration::from_secs(20);
            while try_tool_facts(&config, || {}).is_none() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        let facts = try_tool_facts(&config, || {}).unwrap();
        assert!(matches!(facts.sigma, ToolProbe::Found { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[ignore = "needs the pySigma qualification venv"]
    fn the_real_pysigma_venv_qualifies() {
        let python = std::env::var("ANTINOMIE_TEST_SIGMA_PYTHON")
            .unwrap_or_else(|_| "/tmp/antinomie-sigma-venv/bin/python".into());
        let facts = tool_facts(&ToolConfig::from_sigma_setting(&python));
        assert_eq!(
            facts.sigma,
            ToolProbe::Found {
                identity: "pysigma 2.0.1 / sqlite 2.1.0".into(),
                version: "2.0.1".into()
            }
        );
    }
}
