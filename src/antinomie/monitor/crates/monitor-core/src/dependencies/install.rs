//! One install command for every missing host dependency. The package names
//! of every supported package manager live in [`PACKAGES`]; nothing is run.
use super::{Dependency, Report};
use std::{fs, path::Path};

/// A host package manager Antinomie can write an install command for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageManager {
    Apt,
    Dnf,
    Pacman,
    Zypper,
}

impl PackageManager {
    pub const ALL: [Self; 4] = [Self::Apt, Self::Dnf, Self::Pacman, Self::Zypper];

    pub fn name(self) -> &'static str {
        match self {
            Self::Apt => "apt",
            Self::Dnf => "dnf",
            Self::Pacman => "pacman",
            Self::Zypper => "zypper",
        }
    }

    /// The shell command that installs `packages` (empty: nothing to install).
    fn install(self, packages: &[&str]) -> String {
        let verb = match self {
            Self::Apt => "apt install",
            Self::Dnf => "dnf install",
            Self::Pacman => "pacman -S --needed",
            Self::Zypper => "zypper install",
        };
        format!("sudo {verb} {}", packages.join(" "))
    }

    fn column(self) -> usize {
        self as usize
    }

    /// The manager of a distribution from `/etc/os-release`: its `ID`, then
    /// each word of `ID_LIKE` (a derivative names its parent there).
    pub fn from_os_release(text: &str) -> Option<Self> {
        let value = |key: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
                .map(|value| value.trim().trim_matches(['"', '\'']).to_ascii_lowercase())
                .unwrap_or_default()
        };
        let words = format!("{} {}", value("ID"), value("ID_LIKE"));
        words.split_whitespace().find_map(|word| match word {
            "debian" | "ubuntu" => Some(Self::Apt),
            "fedora" | "rhel" | "centos" => Some(Self::Dnf),
            "arch" | "archlinux" => Some(Self::Pacman),
            "suse" | "opensuse" | "opensuse-leap" | "opensuse-tumbleweed" | "sles" => {
                Some(Self::Zypper)
            }
            _ => None,
        })
    }

    pub fn detect() -> Option<Self> {
        ["/etc/os-release", "/usr/lib/os-release"]
            .into_iter()
            .find_map(|path| fs::read_to_string(path).ok())
            .and_then(|text| Self::from_os_release(&text))
    }
}

/// Package names per dependency, in `PackageManager::ALL` order:
/// apt, dnf, pacman, zypper. KVM access is a group, not a package.
pub const PACKAGES: &[(Dependency, [&str; 4])] = &[
    (
        Dependency::Qemu,
        [
            "qemu-system-x86",
            "qemu-system-x86-core",
            "qemu-system-x86",
            "qemu-x86",
        ],
    ),
    (
        Dependency::QemuImg,
        ["qemu-utils", "qemu-img", "qemu-img", "qemu-tools"],
    ),
    (
        Dependency::Gtk,
        [
            "qemu-system-gui",
            "qemu-ui-gtk",
            "qemu-ui-gtk",
            "qemu-ui-gtk",
        ],
    ),
    (Dependency::Curl, ["curl", "curl", "curl", "curl"]),
    (
        Dependency::DebianAccount,
        [
            "libguestfs-tools",
            "guestfs-tools",
            "libguestfs",
            "guestfs-tools",
        ],
    ),
    (
        Dependency::Bubblewrap,
        ["bubblewrap", "bubblewrap", "bubblewrap", "bubblewrap"],
    ),
    (
        Dependency::Tshark,
        ["tshark", "wireshark-cli", "wireshark-cli", "wireshark"],
    ),
    (
        Dependency::Wireshark,
        ["wireshark", "wireshark", "wireshark-qt", "wireshark-ui-qt"],
    ),
    (
        Dependency::Prlimit,
        ["util-linux", "util-linux", "util-linux", "util-linux"],
    ),
    (
        Dependency::Suricata,
        ["suricata", "suricata", "suricata", "suricata"],
    ),
    (
        Dependency::PythonVenv,
        ["python3-venv", "python3", "python", "python3"],
    ),
    (
        Dependency::FileChooser,
        ["zenity", "zenity", "zenity", "zenity"],
    ),
];

/// The package that provides `dependency` under `manager`.
pub fn package(dependency: Dependency, manager: PackageManager) -> Option<&'static str> {
    PACKAGES
        .iter()
        .find(|(candidate, _)| *candidate == dependency)
        .map(|(_, names)| names[manager.column()])
}

/// What to do about `/dev/kvm`, from the way opening it failed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KvmAdvice {
    /// KVM opens, or its state is not known yet.
    #[default]
    Ready,
    /// There is no `/dev/kvm`: hardware virtualization is off or unsupported.
    NoDevice,
    /// The device exists and this user is not in the `kvm` group.
    AddToGroup,
    /// The user is in the `kvm` group already; a new sign-in applies it.
    SignInAgain,
    /// Opening failed for another reason.
    Other,
}

impl KvmAdvice {
    pub(super) fn classify(
        device_exists: bool,
        open_error: Option<std::io::ErrorKind>,
        member: bool,
    ) -> Self {
        match open_error {
            None => Self::Ready,
            Some(_) if !device_exists => Self::NoDevice,
            Some(std::io::ErrorKind::PermissionDenied) if member => Self::SignInAgain,
            Some(std::io::ErrorKind::PermissionDenied) => Self::AddToGroup,
            Some(_) => Self::Other,
        }
    }

    pub(super) fn probe() -> Self {
        let error = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .err();
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_default();
        let group = fs::read_to_string("/etc/group").unwrap_or_default();
        Self::classify(
            Path::new("/dev/kvm").exists(),
            error.map(|error| error.kind()),
            kvm_member(&group, &user),
        )
    }
}

/// `user` is listed in the `kvm` line of an `/etc/group` file.
pub fn kvm_member(group_file: &str, user: &str) -> bool {
    !user.is_empty()
        && group_file.lines().any(|line| {
            let mut fields = line.split(':');
            fields.next() == Some("kvm")
                && fields
                    .nth(2)
                    .is_some_and(|members| members.split(',').any(|name| name == user))
        })
}

/// The kvm-group command a user runs once, then signs in again.
pub const KVM_GROUP_COMMAND: &str = "sudo usermod -aG kvm $USER";

/// The command for everything missing and the packages it covers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InstallPlan {
    pub manager: Option<PackageManager>,
    pub packages: Vec<&'static str>,
    /// Whether the kvm-group step is part of the command.
    pub kvm_group: bool,
    /// A new sign-in is all KVM access needs.
    pub sign_in_again: bool,
    /// Missing dependencies that have no package for this manager.
    pub unmapped: Vec<Dependency>,
    /// The single command to copy, or `None` when nothing is missing.
    pub command: Option<String>,
}

impl Report {
    /// One command that installs only what this report found missing.
    pub fn install_plan(&self) -> InstallPlan {
        let mut plan = InstallPlan {
            manager: self.package_manager,
            sign_in_again: self.kvm == KvmAdvice::SignInAgain,
            kvm_group: self.kvm == KvmAdvice::AddToGroup,
            ..InstallPlan::default()
        };
        let mut steps = Vec::new();
        if let Some(manager) = self.package_manager {
            for check in self.checks.iter().filter(|check| check.problem.is_some()) {
                match package(check.dependency, manager) {
                    Some(name) if !plan.packages.contains(&name) => plan.packages.push(name),
                    Some(_) => {}
                    None => plan.unmapped.push(check.dependency),
                }
            }
            if !plan.packages.is_empty() {
                steps.push(manager.install(&plan.packages));
            }
        }
        if plan.kvm_group {
            steps.push(KVM_GROUP_COMMAND.to_owned());
        }
        plan.command = (!steps.is_empty()).then(|| steps.join(" && "));
        plan
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependencies::Check;

    fn report(missing: &[Dependency], manager: PackageManager, kvm: KvmAdvice) -> Report {
        let all = PACKAGES.iter().map(|(dependency, _)| *dependency);
        Report {
            checks: all
                .map(|dependency| Check {
                    dependency,
                    name: "test",
                    purpose: "test",
                    problem: missing.contains(&dependency).then(|| "missing".to_owned()),
                    hint: "",
                    optional: false,
                })
                .collect(),
            package_manager: Some(manager),
            kvm,
        }
    }

    #[test]
    fn os_release_selects_the_package_manager() {
        for (text, manager) in [
            ("ID=debian\n", PackageManager::Apt),
            ("ID=kali\nID_LIKE=debian\n", PackageManager::Apt),
            (
                "ID=ubuntu\nID_LIKE=\"ubuntu debian\"\n",
                PackageManager::Apt,
            ),
            ("ID=fedora\n", PackageManager::Dnf),
            (
                "ID=rocky\nID_LIKE=\"rhel centos fedora\"\n",
                PackageManager::Dnf,
            ),
            ("ID=arch\n", PackageManager::Pacman),
            ("ID=manjaro\nID_LIKE=arch\n", PackageManager::Pacman),
            (
                "NAME=x\nID=\"opensuse-tumbleweed\"\nID_LIKE=\"opensuse suse\"\n",
                PackageManager::Zypper,
            ),
        ] {
            assert_eq!(
                PackageManager::from_os_release(text),
                Some(manager),
                "{text}"
            );
        }
        assert_eq!(PackageManager::from_os_release("ID=nixos\n"), None);
        assert_eq!(PackageManager::from_os_release(""), None);
    }

    #[test]
    fn every_dependency_has_a_package_for_every_manager() {
        for (dependency, names) in PACKAGES {
            assert!(names.iter().all(|name| !name.is_empty()), "{dependency:?}");
            for manager in PackageManager::ALL {
                assert!(package(*dependency, manager).is_some());
            }
        }
        // KVM is a group step, not a package.
        assert!(package(Dependency::Kvm, PackageManager::Apt).is_none());
    }

    fn command_for(manager: PackageManager) -> String {
        let missing = [
            Dependency::Qemu,
            Dependency::Tshark,
            Dependency::FileChooser,
        ];
        report(&missing, manager, KvmAdvice::Ready)
            .install_plan()
            .command
            .unwrap()
    }

    #[test]
    fn apt_installs_exactly_the_missing_packages() {
        assert_eq!(
            command_for(PackageManager::Apt),
            "sudo apt install qemu-system-x86 tshark zenity"
        );
    }

    #[test]
    fn dnf_installs_exactly_the_missing_packages() {
        assert_eq!(
            command_for(PackageManager::Dnf),
            "sudo dnf install qemu-system-x86-core wireshark-cli zenity"
        );
    }

    #[test]
    fn pacman_installs_exactly_the_missing_packages() {
        assert_eq!(
            command_for(PackageManager::Pacman),
            "sudo pacman -S --needed qemu-system-x86 wireshark-cli zenity"
        );
    }

    #[test]
    fn zypper_installs_exactly_the_missing_packages() {
        assert_eq!(
            command_for(PackageManager::Zypper),
            "sudo zypper install qemu-x86 wireshark zenity"
        );
    }

    #[test]
    fn a_package_is_listed_once() {
        let mut twice = report(&[Dependency::Tshark], PackageManager::Apt, KvmAdvice::Ready);
        twice.checks.extend(twice.checks.clone());
        assert_eq!(twice.install_plan().packages, ["tshark"]);
    }

    #[test]
    fn nothing_missing_gives_no_command() {
        let plan = report(&[], PackageManager::Apt, KvmAdvice::Ready).install_plan();
        assert_eq!(plan.command, None);
        assert!(plan.packages.is_empty() && !plan.kvm_group);
    }

    #[test]
    fn the_kvm_group_step_appears_only_when_it_is_needed() {
        let missing = [Dependency::Curl];
        let with = |kvm| report(&missing, PackageManager::Apt, kvm).install_plan();
        assert_eq!(
            with(KvmAdvice::AddToGroup).command.as_deref(),
            Some("sudo apt install curl && sudo usermod -aG kvm $USER")
        );
        for kvm in [
            KvmAdvice::Ready,
            KvmAdvice::NoDevice,
            KvmAdvice::SignInAgain,
            KvmAdvice::Other,
        ] {
            let plan = with(kvm);
            assert!(!plan.kvm_group, "{kvm:?}");
            assert_eq!(plan.command.as_deref(), Some("sudo apt install curl"));
        }
        assert!(with(KvmAdvice::SignInAgain).sign_in_again);
        // The group step alone is a command too.
        let alone = report(&[], PackageManager::Dnf, KvmAdvice::AddToGroup).install_plan();
        assert_eq!(alone.command.as_deref(), Some(KVM_GROUP_COMMAND));
    }

    #[test]
    fn an_unknown_distribution_still_gets_the_kvm_step() {
        let mut unknown = report(
            &[Dependency::Curl],
            PackageManager::Apt,
            KvmAdvice::AddToGroup,
        );
        unknown.package_manager = None;
        let plan = unknown.install_plan();
        assert!(plan.packages.is_empty());
        assert_eq!(plan.command.as_deref(), Some(KVM_GROUP_COMMAND));
    }

    #[test]
    fn kvm_advice_follows_how_opening_failed() {
        use std::io::ErrorKind::{NotFound, PermissionDenied};
        assert_eq!(KvmAdvice::classify(true, None, false), KvmAdvice::Ready);
        assert_eq!(
            KvmAdvice::classify(false, Some(NotFound), false),
            KvmAdvice::NoDevice
        );
        assert_eq!(
            KvmAdvice::classify(true, Some(PermissionDenied), false),
            KvmAdvice::AddToGroup
        );
        assert_eq!(
            KvmAdvice::classify(true, Some(PermissionDenied), true),
            KvmAdvice::SignInAgain
        );
        assert_eq!(
            KvmAdvice::classify(true, Some(NotFound), false),
            KvmAdvice::Other
        );
    }

    #[test]
    fn group_membership_reads_the_kvm_line_only() {
        let file = "root:x:0:\nkvm:x:36:alice,bob\nadm:x:4:carol\nkvmx:x:5:dave\n";
        assert!(kvm_member(file, "alice") && kvm_member(file, "bob"));
        assert!(!kvm_member(file, "carol") && !kvm_member(file, "dave"));
        assert!(!kvm_member(file, "") && !kvm_member(file, "ali"));
    }
}
