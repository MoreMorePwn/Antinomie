//! Base builds: installer-style options, built natively, in a container or in
//! the QEMU builder.
//!
//! The app carries its build kit (see `kit`), so a build needs no repository
//! checkout. Native mode runs the kit's orchestrator on this host and needs the
//! tool suite below; Podman and Docker modes run it in a pinned Debian 13
//! container (see `container`) and need only the engine; QEMU mode runs it
//! inside a Debian builder VM and needs only QEMU and curl. Missing tools are
//! reported with an install hint and nothing is installed automatically.

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
    /// Debian 13 with the installer desktop its options choose.
    DebianXfce,
    /// Debian 13 without a desktop: console login, APT and standard tools.
    DebianMinimal,
}
impl Kind {
    /// Built from Debian packages with mmdebstrap (the installer-style answers apply).
    pub fn is_debian(self) -> bool {
        matches!(self, Self::DebianXfce | Self::DebianMinimal)
    }
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
        id: "debian-minimal",
        label: "Debian 13 (minimal, console)",
        kind: Kind::DebianMinimal,
    },
    BuildProfile {
        id: "debian-xfce",
        label: "Debian 13 (desktop)",
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
    /// The first that can run here: Native (only with Debian 13's toolchain
    /// where the base needs it), then Podman, then Docker, then the QEMU
    /// builder.
    #[default]
    Automatic,
    /// On this Linux host (faster; needs the tool suite).
    Native,
    /// In a pinned Debian 13 container run by Podman (rootless preferred).
    Podman,
    /// In a pinned Debian 13 container run by Docker (root-equivalent access).
    Docker,
    /// Inside a Debian builder VM (needs only QEMU and curl).
    Qemu,
}

impl BuildMode {
    /// The manual choices, in dialog order.
    pub const MANUAL: [BuildMode; 4] = [Self::Native, Self::Podman, Self::Docker, Self::Qemu];

    /// The container engine of a container mode.
    pub fn engine(self) -> Option<crate::container::Engine> {
        match self {
            Self::Podman => Some(crate::container::Engine::Podman),
            Self::Docker => Some(crate::container::Engine::Docker),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Automatic => "Automatic",
            Self::Native => "Native",
            Self::Podman => "Podman",
            Self::Docker => "Docker",
            Self::Qemu => "QEMU builder",
        }
    }
}

/// A Debian installer desktop choice.
pub struct Desktop {
    pub id: &'static str,
    pub label: &'static str,
    /// Checked to build and boot with its login setup. All installer desktops
    /// are accepted (Xfce built and booted, GNOME built by the
    /// user, the rest accepted by the user without a test build); a desktop
    /// added later starts unverified and is offered as untested.
    pub verified: bool,
    /// `XDG_CURRENT_DESKTOP` names that identify it on the host.
    pub host_names: &'static [&'static str],
}

/// The desktops the Debian installer offers, in its order (the recipe's
/// `DESKTOPS` table in `build-debian-image.py` must match).
pub const DESKTOPS: &[Desktop] = &[
    Desktop {
        id: "gnome",
        label: "GNOME",
        verified: true,
        host_names: &["GNOME", "ubuntu:GNOME"],
    },
    Desktop {
        id: "xfce",
        label: "Xfce",
        verified: true,
        host_names: &["XFCE"],
    },
    Desktop {
        id: "gnome-flashback",
        label: "GNOME Flashback",
        verified: true,
        host_names: &["GNOME-Flashback:GNOME", "GNOME-Flashback"],
    },
    Desktop {
        id: "kde",
        label: "KDE Plasma",
        verified: true,
        host_names: &["KDE"],
    },
    Desktop {
        id: "cinnamon",
        label: "Cinnamon",
        verified: true,
        host_names: &["X-Cinnamon", "Cinnamon"],
    },
    Desktop {
        id: "mate",
        label: "MATE",
        verified: true,
        host_names: &["MATE"],
    },
    Desktop {
        id: "lxde",
        label: "LXDE",
        verified: true,
        host_names: &["LXDE"],
    },
    Desktop {
        id: "lxqt",
        label: "LXQt",
        verified: true,
        host_names: &["LXQt"],
    },
];

fn default_desktop() -> String {
    "xfce".into()
}

/// Installer answers. Debian uses all of them (the minimal base all but the
/// desktop); BusyBox only the hostname.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildOptions {
    /// Display name of the built base; empty for the automatic name.
    #[serde(default)]
    pub name: String,
    /// Debian desktop environment (`DESKTOPS` id).
    #[serde(default = "default_desktop")]
    pub desktop: String,
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
            name: String::new(),
            desktop: host.desktop.unwrap_or_else(default_desktop),
            // The Debian installer's own default: common on real machines,
            // unlike "localhost" or a sandbox's name.
            hostname: "debian".into(),
            locale: host.locale.unwrap_or_else(|| "en_US.UTF-8".into()),
            keyboard_layout: host.layout.clone().unwrap_or_else(|| "us".into()),
            keyboard_variant: host.layout.and(host.variant).unwrap_or_default(),
            timezone: host.timezone.unwrap_or_else(|| "Etc/UTC".into()),
            // The installer preselects the standard system utilities; the
            // console base is that installation with no desktop.
            standard: kind == Kind::DebianMinimal,
            mirror: DEFAULT_MIRROR.into(),
            proxy: String::new(),
        }
    }
    /// Check the answers before a build; the build checks them again in the guest.
    pub fn validate(&self, kind: Kind) -> Result<(), String> {
        valid_base_name(&self.name)?;
        valid_hostname(&self.hostname)?;
        if kind == Kind::BusyBox {
            return Ok(());
        }
        if kind == Kind::DebianXfce && !DESKTOPS.iter().any(|desktop| desktop.id == self.desktop) {
            return Err(format!("unknown desktop {:?}", self.desktop));
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
            Kind::BusyBox => serde_json::json!({
                "name": self.name.trim(),
                "hostname": self.hostname,
            }),
            Kind::DebianXfce => {
                let mut options = self.job_options(Kind::DebianMinimal);
                options["desktop"] = self.desktop.clone().into();
                options
            }
            // The orchestrator chooses the console base itself: no desktop answer.
            Kind::DebianMinimal => serde_json::json!({
                "name": self.name.trim(),
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
    /// The cached root filesystem these answers can reuse (`kit::image_cache`
    /// name), for the Debian kinds.
    pub(crate) fn rootfs_cache_name(&self, kind: Kind) -> Option<&str> {
        match kind {
            Kind::BusyBox => None,
            Kind::DebianXfce => Some(&self.desktop),
            Kind::DebianMinimal => Some("minimal"),
        }
    }
}

/// A base's display name: at most 64 printable characters (empty: automatic).
pub fn valid_base_name(name: &str) -> Result<(), String> {
    let name = name.trim();
    if name.chars().count() > 64 || name.chars().any(char::is_control) {
        Err("base name must be at most 64 printable characters".into())
    } else {
        Ok(())
    }
}

/// The name a base gets when none is chosen.
pub fn automatic_base_name(kind: Kind, desktop: &str) -> String {
    match kind {
        Kind::BusyBox => "BusyBox".into(),
        Kind::DebianMinimal => "Debian 13 (Minimal)".into(),
        Kind::DebianXfce => format!(
            "Debian 13 ({})",
            DESKTOPS
                .iter()
                .find(|d| d.id == desktop)
                .map_or(desktop, |d| d.label)
        ),
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

/// This host's locale, keyboard and time zone, when they are in the lists:
/// what the Debian installer would guess for this user.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostLocale {
    /// The desktop this computer runs (`DESKTOPS` id).
    pub desktop: Option<String>,
    pub locale: Option<String>,
    pub layout: Option<String>,
    pub variant: Option<String>,
    pub timezone: Option<String>,
}
impl HostLocale {
    pub fn detect() -> Self {
        // The session's language first (a menu launch may lack it), then the
        // system default.
        let locale = ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .filter_map(|name| std::env::var(name).ok())
            .chain(
                ["/etc/locale.conf", "/etc/default/locale"]
                    .iter()
                    .filter_map(|path| std::fs::read_to_string(path).ok())
                    .filter_map(|text| shell_value(&text, "LANG")),
            )
            .find_map(|value| Self::locale_code(&value));
        // The system keyboard setting, else the live X keyboard layout.
        let keyboard = std::fs::read_to_string("/etc/default/keyboard").unwrap_or_default();
        let (layout, variant) = match first_item(shell_value(&keyboard, "XKBLAYOUT")) {
            Some(layout) => (
                Some(layout),
                first_item(shell_value(&keyboard, "XKBVARIANT")),
            ),
            None => Self::x_keyboard(),
        };
        let layout =
            layout.filter(|layout| KEYBOARD_LAYOUTS.iter().any(|(code, _)| code == layout));
        let variant = variant.filter(|variant| {
            KEYBOARD_VARIANTS
                .iter()
                .any(|(l, v, _)| Some(*l) == layout.as_deref() && v == variant)
        });
        let timezone = std::fs::read_to_string("/etc/timezone")
            .ok()
            .map(|zone| zone.trim().to_string())
            .filter(|zone| TIMEZONES.contains(&zone.as_str()))
            .or_else(|| {
                let link = std::fs::read_link("/etc/localtime").ok()?;
                let text = link.to_string_lossy().into_owned();
                text.split_once("zoneinfo/")
                    .map(|(_, zone)| zone.to_string())
            })
            .filter(|zone| TIMEZONES.contains(&zone.as_str()));
        Self {
            desktop: Self::desktop(
                &std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default(),
                &std::env::var("DESKTOP_SESSION").unwrap_or_default(),
            ),
            locale,
            layout,
            variant,
            timezone,
        }
    }
    /// Map `XDG_CURRENT_DESKTOP` (or, without it, `DESKTOP_SESSION`) to a desktop.
    fn desktop(current: &str, session: &str) -> Option<String> {
        let by_name = DESKTOPS.iter().find(|desktop| {
            desktop
                .host_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case(current))
                || current.split(':').next().is_some_and(|first| {
                    desktop
                        .host_names
                        .iter()
                        .any(|n| n.eq_ignore_ascii_case(first))
                })
        });
        let by_session = || {
            let session = session.to_ascii_lowercase();
            DESKTOPS.iter().find(|desktop| {
                !session.is_empty()
                    && (session == desktop.id
                        || (desktop.id == "kde" && session.starts_with("plasma"))
                        || (desktop.id == "gnome"
                            && session.starts_with("gnome")
                            && !session.contains("flashback")))
            })
        };
        by_name
            .filter(|_| !current.is_empty())
            .or_else(by_session)
            .map(|desktop| desktop.id.to_string())
    }
    /// `de_DE.utf8`, `de_DE.UTF-8@euro` or `de_DE` → `de_DE.UTF-8` when offered.
    fn locale_code(value: &str) -> Option<String> {
        let base = value.split(['.', '@']).next()?.trim();
        if base.is_empty() || base == "C" || base == "POSIX" {
            return None;
        }
        let code = format!("{base}.UTF-8");
        LOCALES.iter().any(|(c, _)| *c == code).then_some(code)
    }
    fn x_keyboard() -> (Option<String>, Option<String>) {
        let Ok(output) = std::process::Command::new("setxkbmap")
            .arg("-query")
            .stderr(std::process::Stdio::null())
            .output()
        else {
            return (None, None);
        };
        let text = String::from_utf8_lossy(&output.stdout);
        let field = |name: &str| {
            text.lines().find_map(|line| {
                let value = line.strip_prefix(name)?.trim_start().strip_prefix(':')?;
                first_item(Some(value.trim().to_string()))
            })
        };
        (field("layout"), field("variant"))
    }
}

/// `KEY=value` or `KEY="value"` from a shell-style file.
fn shell_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let value = line.trim().strip_prefix(key)?.strip_prefix('=')?;
        Some(
            value
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string(),
        )
    })
}

/// The first of a comma-separated list, if not empty.
fn first_item(value: Option<String>) -> Option<String> {
    let first = value?.split(',').next()?.trim().to_string();
    (!first.is_empty()).then_some(first)
}

/// The first 12 hex digits of the kernel patch series this app builds.
pub fn series_short() -> String {
    crate::kit::series_hash()[..12].to_string()
}

/// The kernel build profile a base kind uses (`build-monitor-kernel.sh`). The
/// console-only Debian base shares BusyBox's kernel: everything it needs is
/// built in, so it carries no modules and reuses that cached kernel.
pub(crate) fn kernel_profile(kind: Kind) -> &'static str {
    match kind {
        Kind::BusyBox | Kind::DebianMinimal => "minimal",
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

/// Native kernel source preparation and build, shared by every profile
/// (`pahole` encodes the kernel's BTF, which both kernel profiles build).
const KERNEL_TOOLS: &[ToolSpec] = &[
    tool("bash", "bash"),
    tool("python3", "python3"),
    tool("pahole", "dwarves"),
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
    // The UEFI disk layout partitions with it.
    tool("sfdisk", "fdisk"),
];

/// The console Debian base: Debian's image tools, on the minimal kernel.
const DEBIAN_MINIMAL_TOOLS: &[ToolSpec] = &[
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
    // The UEFI disk layout partitions with it.
    tool("sfdisk", "fdisk"),
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
        BuildMode::Podman => vec![tool("podman", "podman")],
        BuildMode::Docker => vec![tool("docker", "docker.io")],
        _ => {
            let mut all = KERNEL_TOOLS.to_vec();
            all.extend_from_slice(match kind {
                Kind::BusyBox => BUSYBOX_TOOLS,
                Kind::DebianXfce => DEBIAN_TOOLS,
                Kind::DebianMinimal => DEBIAN_MINIMAL_TOOLS,
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

/// The first line of `program --version`, if it runs.
fn version_line(program: &str) -> Option<String> {
    let output = Command::new(program)
        .arg("--version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    Some(text.lines().next()?.trim().to_owned()).filter(|line| !line.is_empty())
}

/// The compiler and linker version lines a minimal-profile kernel built on
/// this host records in its banner (the kernel build script's choice:
/// Debian's `x86_64-linux-gnu-gcc-14` where present, else `gcc`), read once.
fn host_toolchain() -> &'static (Option<String>, Option<String>) {
    static TOOLCHAIN: std::sync::OnceLock<(Option<String>, Option<String>)> =
        std::sync::OnceLock::new();
    TOOLCHAIN.get_or_init(|| {
        let cc = if which("x86_64-linux-gnu-gcc-14").is_some() {
            "x86_64-linux-gnu-gcc-14"
        } else {
            "gcc"
        };
        (version_line(cc), version_line("ld"))
    })
}

/// Why this host's toolchain cannot build Debian Minimal's kernel: its banner
/// (`/proc/version`) must be Debian's own, compiler and linker versions
/// included, which only Debian 13's tools write.
fn toolchain_obstacle(
    host: &(Option<String>, Option<String>),
    debian: &(String, String),
) -> Option<String> {
    let (cc, ld) = host;
    let differs = |found: &Option<String>, wanted: &str| found.as_deref() != Some(wanted);
    if differs(cc, &debian.0) || differs(ld, &debian.1) {
        let found = |tool: &Option<String>| tool.clone().unwrap_or_else(|| "none".into());
        return Some(format!(
            "this host's kernel toolchain ({}; {}) is not Debian 13's ({}; {}), whose \
             versions Debian Minimal's kernel banner names: build in the QEMU builder",
            found(cc),
            found(ld),
            debian.0,
            debian.1
        ));
    }
    None
}

/// Why native Debian builds cannot run here besides missing tools: rootless
/// mmdebstrap needs a subordinate UID range for this user, and Debian
/// Minimal's kernel needs Debian 13's compiler and linker.
pub fn native_obstacle(kind: Kind) -> Option<String> {
    if !kind.is_debian() {
        return None;
    }
    if kind == Kind::DebianMinimal {
        match crate::kit::debian_toolchain() {
            Ok(debian) => {
                if let Some(obstacle) = toolchain_obstacle(host_toolchain(), &debian) {
                    return Some(obstacle);
                }
            }
            Err(error) => return Some(error),
        }
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

/// Why `mode` cannot build `kind` here, or None when it can. Containers are
/// asked only about the engine; the image is built when a build starts.
pub fn mode_obstacle(kind: Kind, mode: BuildMode) -> Option<String> {
    match mode {
        BuildMode::Automatic => None,
        BuildMode::Podman | BuildMode::Docker => {
            let engine = mode.engine()?;
            crate::container::cached_standing(engine).obstacle()
        }
        mode => {
            let missing = missing(kind, mode);
            if !missing.is_empty() {
                return Some(format!(
                    "missing host tools: {} (install with: {})",
                    missing
                        .iter()
                        .map(|tool| tool.tool)
                        .collect::<Vec<_>>()
                        .join(", "),
                    install_hint(&missing)
                ));
            }
            if mode == BuildMode::Native {
                return native_obstacle(kind);
            }
            None
        }
    }
}

/// [`mode_obstacle`] for Automatic's walk: a container engine whose image
/// could not be fetched a moment ago is skipped, with the reason.
fn automatic_obstacle(kind: Kind, mode: BuildMode) -> Option<String> {
    mode_obstacle(kind, mode).or_else(|| {
        mode.engine()
            .and(crate::container::recent_image_failure())
            .map(|reason| format!("the builder image is not available: {reason}"))
    })
}

/// Choose where a build runs: the requested mode, or for `Automatic` the first
/// of Native, Podman, Docker and the QEMU builder that can run here.
pub fn resolve_mode(kind: Kind, mode: BuildMode) -> Result<BuildMode, String> {
    resolve_with(
        mode,
        |mode| match mode_obstacle(kind, mode) {
            Some(obstacle) => Err(obstacle),
            None => Ok(()),
        },
        |mode| automatic_obstacle(kind, mode),
    )
}

/// The choice itself, over any way of asking whether a mode can run (`manual`
/// for a requested mode, `walk` for each step of Automatic).
fn resolve_with(
    requested: BuildMode,
    manual: impl Fn(BuildMode) -> Result<(), String>,
    walk: impl Fn(BuildMode) -> Option<String>,
) -> Result<BuildMode, String> {
    if requested != BuildMode::Automatic {
        return manual(requested).map(|()| requested);
    }
    let mut reasons = Vec::new();
    for mode in [
        BuildMode::Native,
        BuildMode::Podman,
        BuildMode::Docker,
        BuildMode::Qemu,
    ] {
        match walk(mode) {
            None => return Ok(mode),
            Some(reason) => reasons.push(format!("{}: {reason}", mode.label())),
        }
    }
    Err(format!("no way to build here ({})", reasons.join("; ")))
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
    fn automatic_takes_native_then_podman_then_docker_then_qemu() {
        let only = |ready: &'static [BuildMode]| {
            move |mode: BuildMode| (!ready.contains(&mode)).then(|| format!("{mode:?} is out"))
        };
        let pick = |ready: &'static [BuildMode]| {
            resolve_with(BuildMode::Automatic, |_| Ok(()), only(ready))
        };
        use BuildMode::*;
        assert_eq!(pick(&[Native, Podman, Docker, Qemu]), Ok(Native));
        assert_eq!(pick(&[Podman, Docker, Qemu]), Ok(Podman));
        assert_eq!(pick(&[Docker, Qemu]), Ok(Docker));
        assert_eq!(pick(&[Qemu]), Ok(Qemu));
        let none = pick(&[]).unwrap_err();
        for name in ["Native", "Podman", "Docker", "QEMU builder"] {
            assert!(none.contains(&format!("{name}:")), "{none}");
        }
        // A manual choice is that choice or its obstacle, never another mode.
        let refused = |mode| resolve_with(mode, |_| Err("no daemon".into()), |_| None);
        assert_eq!(refused(Docker), Err("no daemon".into()));
        assert_eq!(
            resolve_with(Podman, |_| Ok(()), |_| Some("walk".into())),
            Ok(Podman)
        );
    }

    #[test]
    fn container_modes_need_only_their_engine() {
        for (mode, tool) in [(BuildMode::Podman, "podman"), (BuildMode::Docker, "docker")] {
            let names: Vec<_> = tools(Kind::DebianMinimal, mode)
                .iter()
                .map(|t| t.tool)
                .collect();
            assert_eq!(names, [tool]);
            assert!(mode.engine().is_some());
        }
        assert_eq!(BuildMode::MANUAL.len(), 4);
        assert!(BuildMode::Native.engine().is_none() && BuildMode::Qemu.engine().is_none());
    }

    #[test]
    fn debian_minimal_needs_debian_13s_compiler_and_linker_natively() {
        let debian = (
            "x86_64-linux-gnu-gcc-14 (Debian 14.2.0-19) 14.2.0".to_owned(),
            "GNU ld (GNU Binutils for Debian) 2.44".to_owned(),
        );
        let trixie = (Some(debian.0.clone()), Some(debian.1.clone()));
        assert_eq!(toolchain_obstacle(&trixie, &debian), None);
        // A newer binutils (Kali, Debian testing) writes another linker version.
        let kali = (
            Some(debian.0.clone()),
            Some("GNU ld (GNU Binutils for Debian) 2.47".to_owned()),
        );
        let obstacle = toolchain_obstacle(&kali, &debian).unwrap();
        assert!(obstacle.contains("2.47") && obstacle.contains("QEMU builder"));
        assert!(toolchain_obstacle(&(None, trixie.1.clone()), &debian).is_some());
        // Only Debian Minimal carries Debian's /boot to compare the banner with.
        assert_eq!(native_obstacle(Kind::BusyBox), None);
    }

    #[test]
    fn profiles_are_distinct_and_addressable() {
        assert!(profile("busybox").is_some());
        assert!(profile("debian-xfce").is_some());
        assert_eq!(
            profile("debian-minimal").map(|profile| profile.kind),
            Some(Kind::DebianMinimal)
        );
        assert!(profile("nope").is_none());
        let ids: std::collections::HashSet<_> = BUILD_PROFILES.iter().map(|p| p.id).collect();
        assert_eq!(ids.len(), BUILD_PROFILES.len());
    }

    #[test]
    fn defaults_validate_and_bad_answers_are_named() {
        for kind in [Kind::BusyBox, Kind::DebianXfce, Kind::DebianMinimal] {
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
            serde_json::json!({"name": "", "hostname": "debian"})
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
            10
        );
    }

    #[test]
    fn debian_minimal_takes_the_installer_answers_but_no_desktop() {
        let mut options = BuildOptions::defaults(Kind::DebianMinimal);
        // The desktop answer is not asked and not checked.
        options.desktop = "anything".into();
        options.validate(Kind::DebianMinimal).unwrap();
        assert!(options.validate(Kind::DebianXfce).is_err());
        options.timezone = "Mars/Olympus".into();
        assert!(options.validate(Kind::DebianMinimal).is_err());
        let options = BuildOptions::defaults(Kind::DebianMinimal);
        assert!(options.standard && !BuildOptions::defaults(Kind::DebianXfce).standard);
        let minimal = options.job_options(Kind::DebianMinimal);
        let desktop = options.job_options(Kind::DebianXfce);
        assert_eq!(minimal.as_object().unwrap().len(), 9);
        assert!(minimal.get("desktop").is_none());
        let mut without = desktop.as_object().unwrap().clone();
        without.remove("desktop");
        assert_eq!(serde_json::Value::Object(without), minimal);
        assert_eq!(
            options.rootfs_cache_name(Kind::DebianMinimal),
            Some("minimal")
        );
        assert_eq!(
            options.rootfs_cache_name(Kind::DebianXfce),
            Some(options.desktop.as_str())
        );
        assert_eq!(options.rootfs_cache_name(Kind::BusyBox), None);
        assert_eq!(
            automatic_base_name(Kind::DebianMinimal, "xfce"),
            "Debian 13 (Minimal)"
        );
        // It shares BusyBox's kernel; every kernel build encodes BTF with pahole.
        assert_eq!(kernel_profile(Kind::DebianMinimal), "minimal");
        assert_eq!(kernel_profile(Kind::DebianXfce), "debian");
        let native: Vec<_> = tools(Kind::DebianMinimal, BuildMode::Native)
            .iter()
            .map(|tool| tool.tool)
            .collect();
        assert!(native.contains(&"mmdebstrap") && native.contains(&"newuidmap"));
        assert!(native.contains(&"pahole"));
        assert!(
            tools(Kind::BusyBox, BuildMode::Native)
                .iter()
                .any(|tool| tool.tool == "pahole")
        );
        assert!(Kind::DebianMinimal.is_debian() && !Kind::BusyBox.is_debian());
    }

    #[test]
    fn recipes_build_the_console_base_on_the_minimal_kernel() {
        let recipe = include_str!("../../../../../../scripts/build-debian-image.py");
        assert!(recipe.contains(
            r#"CONSOLE_PROFILE = {"id": "debian-minimal", "label": "Debian 13 (Minimal)","#
        ));
        assert!(recipe.contains(r#""requires_credentials": True, "graphical": False}"#));
        let orchestrator = include_str!("../../../../../../scripts/build-base.py");
        assert!(orchestrator.contains(r#""debian-minimal": ("minimal", "build-debian-image.py""#));
    }

    #[test]
    fn host_desktop_is_recognised() {
        let desktop = |current, session| HostLocale::desktop(current, session);
        assert_eq!(desktop("XFCE", "").as_deref(), Some("xfce"));
        assert_eq!(desktop("ubuntu:GNOME", "").as_deref(), Some("gnome"));
        assert_eq!(
            desktop("GNOME-Flashback:GNOME", "").as_deref(),
            Some("gnome-flashback")
        );
        assert_eq!(desktop("KDE", "plasma").as_deref(), Some("kde"));
        assert_eq!(desktop("X-Cinnamon", "").as_deref(), Some("cinnamon"));
        assert_eq!(desktop("", "plasmawayland").as_deref(), Some("kde"));
        assert_eq!(desktop("", "lxqt").as_deref(), Some("lxqt"));
        assert_eq!(desktop("", ""), None);
        assert_eq!(desktop("Hyprland", ""), None);
    }

    #[test]
    fn recipe_offers_the_same_desktops() {
        let recipe = include_str!("../../../../../../scripts/build-debian-image.py");
        for desktop in DESKTOPS {
            assert!(
                recipe.contains(&format!("\"{}\": (\"task-", desktop.id)),
                "{}",
                desktop.id
            );
        }
    }

    #[test]
    fn host_locale_values_are_normalised() {
        assert_eq!(
            HostLocale::locale_code("de_DE.utf8").as_deref(),
            Some("de_DE.UTF-8")
        );
        assert_eq!(
            HostLocale::locale_code("en_GB@euro").as_deref(),
            Some("en_GB.UTF-8")
        );
        assert_eq!(HostLocale::locale_code("C.UTF-8"), None);
        assert_eq!(HostLocale::locale_code("xx_YY.UTF-8"), None);
        let file = "XKBMODEL=\"pc105\"\nXKBLAYOUT=\"de,us\"\nXKBVARIANT=\"\"\n";
        assert_eq!(
            first_item(shell_value(file, "XKBLAYOUT")).as_deref(),
            Some("de")
        );
        assert_eq!(first_item(shell_value(file, "XKBVARIANT")), None);
        assert_eq!(
            shell_value("LANG='fr_FR.UTF-8'", "LANG").as_deref(),
            Some("fr_FR.UTF-8")
        );
    }

    #[test]
    fn base_names_are_optional_and_bounded() {
        valid_base_name("").unwrap();
        valid_base_name("Malware lab — Debian GNOME").unwrap();
        assert!(valid_base_name(&"x".repeat(65)).is_err());
        assert!(valid_base_name("bad\nname").is_err());
        assert_eq!(
            automatic_base_name(Kind::DebianXfce, "kde"),
            "Debian 13 (KDE Plasma)"
        );
        assert_eq!(automatic_base_name(Kind::BusyBox, "xfce"), "BusyBox");
        assert!(DESKTOPS.iter().all(|desktop| desktop.verified));
        let mut options = BuildOptions::defaults(Kind::DebianXfce);
        options.name = "  Lab  ".into();
        assert_eq!(options.job_options(Kind::DebianXfce)["name"], "Lab");
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
