//! Base builds (ANT-T0028): installer-style options, native or QEMU builder.
//!
//! The app carries its build kit (see `kit`), so a build needs no repository
//! checkout. Native mode runs the kit's orchestrator on this host and needs the
//! tool suite below; QEMU mode runs the same orchestrator inside a Debian
//! builder VM and needs only QEMU and curl. Missing tools are reported with an
//! install hint and nothing is installed automatically.

use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
};

pub use crate::build_choices::{KEYBOARD_LAYOUTS, KEYBOARD_VARIANTS, LOCALES, TIMEZONES};

/// Base families that can be built.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    BusyBox,
    DebianXfce,
}

/// A buildable base offered by "Build base".
pub struct BuildProfile {
    pub id: &'static str,
    pub label: &'static str,
    pub kind: Kind,
}

/// The buildable profiles, in menu order.
pub const BUILD_PROFILES: &[BuildProfile] = &[
    BuildProfile {
        id: "busybox",
        label: "BusyBox (minimal)",
        kind: Kind::BusyBox,
    },
    BuildProfile {
        id: "debian-xfce",
        label: "Debian 13 (Xfce)",
        kind: Kind::DebianXfce,
    },
];

/// Resolve a profile by its stable id.
pub fn profile(id: &str) -> Option<&'static BuildProfile> {
    BUILD_PROFILES.iter().find(|profile| profile.id == id)
}

/// Where a build runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum BuildMode {
    /// Native when every native tool is present, otherwise the QEMU builder.
    #[default]
    Automatic,
    /// On this Linux host (faster; needs the tool suite).
    Native,
    /// Inside a Debian builder VM (needs only QEMU and curl).
    Qemu,
}

/// Installer answers. Debian uses all of them; BusyBox only the hostname.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildOptions {
    pub hostname: String,
    pub locale: String,
    pub keyboard_layout: String,
    pub keyboard_variant: String,
    pub timezone: String,
    /// Debian's "standard system utilities" task (priority standard).
    pub standard: bool,
    pub mirror: String,
    /// Optional HTTP proxy for the build; not kept in the image.
    pub proxy: String,
}

pub const DEFAULT_MIRROR: &str = "http://deb.debian.org/debian";

impl BuildOptions {
    /// Defaults for a profile; the Debian locale, keyboard and time zone follow
    /// this host when it has a recognised value, as the Debian installer guesses.
    pub fn defaults(kind: Kind) -> Self {
        let host = HostLocale::detect();
        Self {
            hostname: match kind {
                Kind::BusyBox => "localhost".into(),
                Kind::DebianXfce => "antinomie".into(),
            },
            locale: host.locale.unwrap_or_else(|| "en_US.UTF-8".into()),
            keyboard_layout: host.layout.clone().unwrap_or_else(|| "us".into()),
            keyboard_variant: host.layout.and(host.variant).unwrap_or_default(),
            timezone: host.timezone.unwrap_or_else(|| "Etc/UTC".into()),
            standard: false,
            mirror: DEFAULT_MIRROR.into(),
            proxy: String::new(),
        }
    }
    /// Check the answers before a build; the build checks them again in the guest.
    pub fn validate(&self, kind: Kind) -> Result<(), String> {
        valid_hostname(&self.hostname)?;
        if kind == Kind::BusyBox {
            return Ok(());
        }
        if !LOCALES.iter().any(|(code, _)| *code == self.locale) {
            return Err(format!("unsupported locale {:?}", self.locale));
        }
        if !KEYBOARD_LAYOUTS
            .iter()
            .any(|(code, _)| *code == self.keyboard_layout)
        {
            return Err(format!(
                "unknown keyboard layout {:?}",
                self.keyboard_layout
            ));
        }
        if !self.keyboard_variant.is_empty()
            && !KEYBOARD_VARIANTS.iter().any(|(layout, code, _)| {
                *layout == self.keyboard_layout && *code == self.keyboard_variant
            })
        {
            return Err(format!(
                "unknown keyboard variant {:?} for layout {:?}",
                self.keyboard_variant, self.keyboard_layout
            ));
        }
        if !TIMEZONES.contains(&self.timezone.as_str()) {
            return Err(format!("unknown time zone {:?}", self.timezone));
        }
        valid_url(&self.mirror, "mirror")?;
        if !self.proxy.is_empty() {
            valid_url(&self.proxy, "proxy")?;
        }
        Ok(())
    }
    /// The orchestrator's job options for a profile (only the options it offers).
    pub(crate) fn job_options(&self, kind: Kind) -> serde_json::Value {
        match kind {
            Kind::BusyBox => serde_json::json!({ "hostname": self.hostname }),
            Kind::DebianXfce => serde_json::json!({
                "hostname": self.hostname,
                "locale": self.locale,
                "keyboard_layout": self.keyboard_layout,
                "keyboard_variant": self.keyboard_variant,
                "timezone": self.timezone,
                "standard": self.standard,
                "mirror": self.mirror,
                "proxy": self.proxy,
            }),
        }
    }
}

/// One lowercase RFC 1123 label, as the installer's hostname question takes.
pub fn valid_hostname(name: &str) -> Result<(), String> {
    let bytes = name.as_bytes();
    let ok = (1..=63).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        && bytes[0] != b'-'
        && bytes[bytes.len() - 1] != b'-';
    if ok {
        Ok(())
    } else {
        Err(format!(
            "invalid hostname {name:?}: use 1-63 of a-z, 0-9 and '-', not starting or ending with '-'"
        ))
    }
}

fn valid_url(value: &str, what: &str) -> Result<(), String> {
    let rest = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"));
    let ok = rest.is_some_and(|rest| {
        !rest.is_empty()
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._~:/?#@!$&()*+,;=%-".contains(&b))
    });
    if ok {
        Ok(())
    } else {
        Err(format!("invalid {what} URL {value:?}"))
    }
}

/// This host's locale, keyboard and time zone, when they are in the lists.
#[derive(Default)]
struct HostLocale {
    locale: Option<String>,
    layout: Option<String>,
    variant: Option<String>,
    timezone: Option<String>,
}
impl HostLocale {
    fn detect() -> Self {
        let locale = std::env::var("LANG").ok().and_then(|lang| {
            let (base, _) = lang.split_once('.')?;
            let code = format!("{base}.UTF-8");
            LOCALES.iter().any(|(c, _)| *c == code).then_some(code)
        });
        let keyboard = std::fs::read_to_string("/etc/default/keyboard").unwrap_or_default();
        let value = |key: &str| {
            keyboard.lines().find_map(|line| {
                let rest = line.strip_prefix(key)?.strip_prefix('=')?;
                let first = rest.trim().trim_matches('"').split(',').next()?.trim();
                (!first.is_empty()).then(|| first.to_string())
            })
        };
        let layout = value("XKBLAYOUT")
            .filter(|layout| KEYBOARD_LAYOUTS.iter().any(|(code, _)| code == layout));
        let variant = value("XKBVARIANT").filter(|variant| {
            KEYBOARD_VARIANTS
                .iter()
                .any(|(l, v, _)| Some(*l) == layout.as_deref() && v == variant)
        });
        let timezone = std::fs::read_to_string("/etc/timezone")
            .ok()
            .map(|zone| zone.trim().to_string())
            .or_else(|| {
                let link = std::fs::read_link("/etc/localtime").ok()?;
                let text = link.to_string_lossy().into_owned();
                text.split_once("zoneinfo/")
                    .map(|(_, zone)| zone.to_string())
            })
            .filter(|zone| TIMEZONES.contains(&zone.as_str()));
        Self {
            locale,
            layout,
            variant,
            timezone,
        }
    }
}

/// The kernel build profile a base kind uses (`build-monitor-kernel.sh`).
pub(crate) fn kernel_profile(kind: Kind) -> &'static str {
    match kind {
        Kind::BusyBox => "minimal",
        Kind::DebianXfce => "debian",
    }
}

/// Whether this app's kernel for `kind` is already built and cached, so a build
/// only assembles the image.
pub fn kernel_cached(data_dir: &Path, kind: Kind) -> bool {
    crate::kit::kernel_cache(&data_dir.join("build"), kernel_profile(kind))
        .is_ok_and(|path| path.is_file())
}

/// A build request from the wizard.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildRequest {
    pub profile: String,
    pub mode: BuildMode,
    pub options: BuildOptions,
}

/// A host tool a build mode needs, with its Debian/Ubuntu package hint. `path`
/// names a file to look for instead of a program on `PATH` (headers).
#[derive(Clone, Copy, Debug)]
pub struct ToolSpec {
    pub tool: &'static str,
    pub package: &'static str,
    pub path: Option<&'static str>,
}
const fn tool(tool: &'static str, package: &'static str) -> ToolSpec {
    ToolSpec {
        tool,
        package,
        path: None,
    }
}
const fn file(tool: &'static str, package: &'static str, path: &'static str) -> ToolSpec {
    ToolSpec {
        tool,
        package,
        path: Some(path),
    }
}

/// Native kernel source preparation and build, shared by every profile.
const KERNEL_TOOLS: &[ToolSpec] = &[
    tool("bash", "bash"),
    tool("python3", "python3"),
    tool("dpkg-source", "dpkg-dev"),
    tool("patch", "patch"),
    tool("make", "make"),
    tool("gcc", "gcc"),
    tool("bison", "bison"),
    tool("flex", "flex"),
    tool("bc", "bc"),
    tool("perl", "perl"),
    tool("openssl", "openssl"),
    file("libelf.h", "libelf-dev", "/usr/include/libelf.h"),
    file("openssl/ssl.h", "libssl-dev", "/usr/include/openssl/ssl.h"),
];

const BUSYBOX_TOOLS: &[ToolSpec] = &[
    tool("qemu-img", "qemu-utils"),
    tool("mkfs.ext4", "e2fsprogs"),
    tool("debugfs", "e2fsprogs"),
    tool("resize2fs", "e2fsprogs"),
    tool("cpio", "cpio"),
    tool("gzip", "gzip"),
    tool("busybox", "busybox-static"),
    tool("ldd", "libc-bin"),
];

const DEBIAN_TOOLS: &[ToolSpec] = &[
    tool("pahole", "dwarves"),
    tool("mmdebstrap", "mmdebstrap"),
    tool("newuidmap", "uidmap"),
    tool("qemu-img", "qemu-utils"),
    tool("mkfs.ext4", "e2fsprogs"),
    tool("debugfs", "e2fsprogs"),
    tool("resize2fs", "e2fsprogs"),
    tool("cpio", "cpio"),
    tool("gzip", "gzip"),
    tool("tar", "tar"),
    tool("busybox", "busybox-static"),
    tool("dpkg-query", "dpkg"),
];

/// The QEMU builder needs only the emulator, its image tool and curl.
const QEMU_TOOLS: &[ToolSpec] = &[
    tool("qemu-system-x86_64", "qemu-system-x86"),
    tool("qemu-img", "qemu-utils"),
    tool("curl", "curl"),
];

/// Host tools a profile needs in a mode (`Automatic` is not a mode to check).
pub fn tools(kind: Kind, mode: BuildMode) -> Vec<ToolSpec> {
    match mode {
        BuildMode::Qemu => QEMU_TOOLS.to_vec(),
        _ => {
            let mut all = KERNEL_TOOLS.to_vec();
            all.extend_from_slice(match kind {
                Kind::BusyBox => BUSYBOX_TOOLS,
                Kind::DebianXfce => DEBIAN_TOOLS,
            });
            all
        }
    }
}

/// Presence of one host tool.
#[derive(Clone, Copy, Debug)]
pub struct ToolStatus {
    pub tool: &'static str,
    pub package: &'static str,
    pub present: bool,
}

/// `PATH` lookup for a bare tool name.
pub fn which(tool: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(tool))
        .find(|candidate| candidate.is_file())
}

/// Status of every tool a profile needs in a mode.
pub fn status(kind: Kind, mode: BuildMode) -> Vec<ToolStatus> {
    tools(kind, mode)
        .into_iter()
        .map(|spec| ToolStatus {
            tool: spec.tool,
            package: spec.package,
            present: match spec.path {
                Some(path) => Path::new(path).is_file(),
                None => which(spec.tool).is_some(),
            },
        })
        .collect()
}

/// Missing tools for a profile in a mode.
pub fn missing(kind: Kind, mode: BuildMode) -> Vec<ToolStatus> {
    status(kind, mode)
        .into_iter()
        .filter(|tool| !tool.present)
        .collect()
}

/// Why native Debian builds cannot run here besides missing tools: rootless
/// mmdebstrap needs a subordinate UID range for this user.
pub fn native_obstacle(kind: Kind) -> Option<String> {
    if kind != Kind::DebianXfce {
        return None;
    }
    let user = std::env::var("USER").unwrap_or_default();
    let uid = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self")
            .map_or_else(|_| String::new(), |meta| meta.uid().to_string())
    };
    let ranges = std::fs::read_to_string("/etc/subuid").unwrap_or_default();
    let has_range = ranges.lines().any(|line| {
        let owner = line.split(':').next().unwrap_or_default();
        !owner.is_empty() && (owner == user || owner == uid)
    });
    (!has_range).then(|| {
        format!("no subordinate UID range for {user} in /etc/subuid (sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 {user})")
    })
}

/// A copy-paste install hint for missing tools (Debian/Ubuntu package names).
pub fn install_hint(missing: &[ToolStatus]) -> String {
    let mut packages: Vec<&str> = Vec::new();
    for tool in missing {
        if !packages.contains(&tool.package) {
            packages.push(tool.package);
        }
    }
    if packages.is_empty() {
        String::new()
    } else {
        format!("sudo apt install {}", packages.join(" "))
    }
}

/// Choose where a build runs: the requested mode, or for `Automatic` native
/// when it can run here and the QEMU builder otherwise.
pub fn resolve_mode(kind: Kind, mode: BuildMode) -> Result<BuildMode, String> {
    let ready = |mode: BuildMode| -> Result<(), String> {
        let missing = missing(kind, mode);
        if !missing.is_empty() {
            return Err(format!(
                "missing host tools: {} (install with: {})",
                missing
                    .iter()
                    .map(|tool| tool.tool)
                    .collect::<Vec<_>>()
                    .join(", "),
                install_hint(&missing)
            ));
        }
        if mode == BuildMode::Native
            && let Some(obstacle) = native_obstacle(kind)
        {
            return Err(obstacle);
        }
        Ok(())
    };
    match mode {
        BuildMode::Automatic => match ready(BuildMode::Native) {
            Ok(()) => Ok(BuildMode::Native),
            Err(native) => ready(BuildMode::Qemu)
                .map(|()| BuildMode::Qemu)
                .map_err(|qemu| format!("cannot build natively ({native}) or in QEMU ({qemu})")),
        },
        mode => ready(mode).map(|()| mode),
    }
}

/// Run one program, streaming stdout and stderr lines to `on_line`, until it
/// exits or `cancel` is set (the child is then killed).
pub(crate) fn run_streaming(
    command: &mut Command,
    label: &str,
    cancel: &AtomicBool,
    mut on_line: impl FnMut(&str),
) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("build cancelled".into());
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("{label}: cannot start: {error}"))?;
    let (sender, receiver) = mpsc::channel::<String>();
    let readers: Vec<_> = [
        child
            .stdout
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn std::io::Read + Send>),
        child
            .stderr
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn std::io::Read + Send>),
    ]
    .into_iter()
    .flatten()
    .map(|pipe| {
        let sender = sender.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                let _ = sender.send(line);
            }
        })
    })
    .collect();
    drop(sender);
    loop {
        match receiver.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(line) => on_line(&line),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("build cancelled".into());
        }
    }
    for reader in readers {
        let _ = reader.join();
    }
    let status = child.wait().map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{label} failed: {status}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn collect() -> (std::sync::Arc<Mutex<Vec<String>>>, impl FnMut(&str)) {
        let log = std::sync::Arc::new(Mutex::new(Vec::new()));
        let sink = log.clone();
        (log, move |line: &str| {
            sink.lock().unwrap().push(line.to_string());
        })
    }

    #[test]
    fn profiles_are_distinct_and_addressable() {
        assert!(profile("busybox").is_some());
        assert!(profile("debian-xfce").is_some());
        assert!(profile("nope").is_none());
        let ids: std::collections::HashSet<_> = BUILD_PROFILES.iter().map(|p| p.id).collect();
        assert_eq!(ids.len(), BUILD_PROFILES.len());
    }

    #[test]
    fn defaults_validate_and_bad_answers_are_named() {
        for kind in [Kind::BusyBox, Kind::DebianXfce] {
            BuildOptions::defaults(kind).validate(kind).unwrap();
        }
        let good = BuildOptions::defaults(Kind::DebianXfce);
        type Change = fn(&mut BuildOptions);
        let cases: [(Change, &str); 8] = [
            (|o| o.hostname = "Bad_Name".into(), "hostname"),
            (|o| o.hostname = "-x".into(), "hostname"),
            (|o| o.locale = "en_US.ISO-8859-1".into(), "locale"),
            (|o| o.keyboard_layout = "zz".into(), "keyboard layout"),
            (
                |o| o.keyboard_variant = "dvorak-nope".into(),
                "keyboard variant",
            ),
            (|o| o.timezone = "Mars/Olympus".into(), "time zone"),
            (|o| o.mirror = "ftp://deb.debian.org".into(), "mirror"),
            (|o| o.proxy = "http://proxy with space".into(), "proxy"),
        ];
        for (change, word) in cases {
            let mut options = good.clone();
            change(&mut options);
            let error = options.validate(Kind::DebianXfce).unwrap_err();
            assert!(error.contains(word), "{error}");
        }
        let mut busybox = BuildOptions::defaults(Kind::BusyBox);
        busybox.locale = "anything".into();
        busybox.validate(Kind::BusyBox).unwrap();
        assert_eq!(
            busybox.job_options(Kind::BusyBox),
            serde_json::json!({"hostname": "localhost"})
        );
        let mut variant = good.clone();
        variant.keyboard_layout = "us".into();
        variant.keyboard_variant = "dvorak".into();
        variant.validate(Kind::DebianXfce).unwrap();
        assert_eq!(
            good.job_options(Kind::DebianXfce)
                .as_object()
                .unwrap()
                .len(),
            8
        );
    }

    #[test]
    fn hostname_rules_match_the_recipes() {
        for good in ["a", "antinomie", "lab-01", &"x".repeat(63)] {
            valid_hostname(good).unwrap();
        }
        for bad in ["", "-a", "a-", "A", "a.b", "a_b", &"x".repeat(64)] {
            assert!(valid_hostname(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn qemu_mode_needs_only_qemu_and_curl() {
        let names: Vec<_> = tools(Kind::DebianXfce, BuildMode::Qemu)
            .iter()
            .map(|tool| tool.tool)
            .collect();
        assert_eq!(names, ["qemu-system-x86_64", "qemu-img", "curl"]);
        let native: Vec<_> = tools(Kind::DebianXfce, BuildMode::Native)
            .iter()
            .map(|tool| tool.tool)
            .collect();
        assert!(native.contains(&"mmdebstrap") && !native.contains(&"virt-builder"));
    }

    #[test]
    fn run_streams_output_and_stops_on_failure() {
        let (log, sink) = collect();
        run_streaming(
            Command::new("sh").args(["-c", "echo one; echo two 1>&2"]),
            "demo",
            &AtomicBool::new(false),
            sink,
        )
        .unwrap();
        let text = log.lock().unwrap().join("\n");
        assert!(text.contains("one") && text.contains("two"), "{text}");
        let (_log, sink) = collect();
        let error = run_streaming(
            Command::new("sh").args(["-c", "exit 4"]),
            "demo",
            &AtomicBool::new(false),
            sink,
        )
        .unwrap_err();
        assert!(error.contains("demo failed"), "{error}");
        let (_log, sink) = collect();
        assert!(
            run_streaming(
                &mut Command::new("antinomie-not-a-real-tool"),
                "demo",
                &AtomicBool::new(false),
                sink
            )
            .is_err()
        );
    }

    #[test]
    fn run_honours_cancel() {
        let (_log, sink) = collect();
        let error = run_streaming(
            Command::new("sh").args(["-c", "echo never"]),
            "demo",
            &AtomicBool::new(true),
            sink,
        )
        .unwrap_err();
        assert_eq!(error, "build cancelled");
    }

    #[test]
    fn install_hint_lists_each_missing_package_once() {
        let missing = [
            ToolStatus {
                tool: "x",
                package: "e2fsprogs",
                present: false,
            },
            ToolStatus {
                tool: "y",
                package: "e2fsprogs",
                present: false,
            },
            ToolStatus {
                tool: "z",
                package: "cpio",
                present: false,
            },
        ];
        assert_eq!(install_hint(&missing), "sudo apt install e2fsprogs cpio");
        assert_eq!(install_hint(&[]), "");
    }
}
