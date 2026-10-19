// SPDX-License-Identifier: MIT
//! Where a path lives: one table of rules, applied to every file row.
//!
//! A path can fall in several classes (`/home/user/.ssh/authorized_keys` is both
//! persistence and credentials, and hidden). The class says where the file
//! is, not that anything bad happened to it.

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Location {
    Persistence,
    Credentials,
    System,
    Temp,
    PseudoFs,
    SelfPath,
    Hidden,
}

impl Location {
    /// Stable filter value, as in `file.location == "persistence"`.
    pub(super) fn tag(self) -> &'static str {
        match self {
            Self::Persistence => "persistence",
            Self::Credentials => "credentials",
            Self::System => "system",
            Self::Temp => "temp",
            Self::PseudoFs => "pseudo-fs",
            Self::SelfPath => "self",
            Self::Hidden => "hidden",
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Persistence => "Persistence",
            Self::Credentials => "Credentials",
            Self::System => "System binary/library",
            Self::Temp => "Temp/staging",
            Self::PseudoFs => "Pseudo-filesystem",
            Self::SelfPath => "Sample itself",
            Self::Hidden => "Hidden",
        }
    }
}

enum Rule {
    /// The text starts with this, so `/etc/cron` covers `/etc/crontab` and `/etc/cron.d/x`.
    Prefix(&'static str),
    /// The directory itself or anything under it.
    Under(&'static str),
    /// Under the first, but not under the second.
    UnderExcept(&'static str, &'static str),
    /// The whole path.
    Exact(&'static str),
    /// The last component.
    Name(&'static str),
    /// The text appears anywhere, for per-user directories.
    Contains(&'static str),
    /// Any component starts with a dot, other than `.` and `..`.
    DotComponent,
}

impl Rule {
    fn matches(&self, path: &str) -> bool {
        let under = |dir: &str| {
            path == dir
                || path
                    .strip_prefix(dir)
                    .is_some_and(|rest| rest.starts_with('/'))
        };
        match self {
            Self::Prefix(prefix) => path.starts_with(prefix),
            Self::Under(dir) => under(dir),
            Self::UnderExcept(dir, except) => under(dir) && !under(except),
            Self::Exact(whole) => path == *whole,
            Self::Name(name) => path.rsplit('/').next() == Some(*name),
            Self::Contains(part) => path.contains(part),
            Self::DotComponent => path
                .split('/')
                .any(|part| part.starts_with('.') && part != "." && part != ".."),
        }
    }
}

/// Every rule, in one place. A path takes each class one of its rules matches.
const RULES: &[(Location, Rule)] = &[
    (Location::Persistence, Rule::Prefix("/etc/cron")),
    (Location::Persistence, Rule::Under("/var/spool/cron")),
    (Location::Persistence, Rule::Under("/etc/systemd")),
    (
        Location::Persistence,
        Rule::Under("/usr/lib/systemd/system"),
    ),
    (Location::Persistence, Rule::Under("/lib/systemd/system")),
    (Location::Persistence, Rule::Under("/etc/init.d")),
    (Location::Persistence, Rule::Contains("/.config/autostart")),
    (
        Location::Persistence,
        Rule::Contains("/.config/systemd/user"),
    ),
    (Location::Persistence, Rule::Prefix("/etc/rc")),
    (Location::Persistence, Rule::Exact("/etc/profile")),
    (Location::Persistence, Rule::Under("/etc/profile.d")),
    (Location::Persistence, Rule::Exact("/etc/bash.bashrc")),
    (Location::Persistence, Rule::Exact("/etc/environment")),
    (Location::Persistence, Rule::Name(".bashrc")),
    (Location::Persistence, Rule::Name(".bash_profile")),
    (Location::Persistence, Rule::Name(".bash_login")),
    (Location::Persistence, Rule::Name(".bash_logout")),
    (Location::Persistence, Rule::Name(".profile")),
    (Location::Persistence, Rule::Name(".zshrc")),
    (Location::Persistence, Rule::Name(".zshenv")),
    (Location::Persistence, Rule::Name(".zprofile")),
    (Location::Persistence, Rule::Name(".zlogin")),
    (Location::Persistence, Rule::Prefix("/etc/ld.so.preload")),
    (Location::Persistence, Rule::Name("authorized_keys")),
    (Location::Persistence, Rule::Name("authorized_keys2")),
    (Location::Credentials, Rule::Prefix("/etc/shadow")),
    (Location::Credentials, Rule::Prefix("/etc/gshadow")),
    (Location::Credentials, Rule::Prefix("/etc/passwd")),
    (Location::Credentials, Rule::Exact("/etc/sudoers")),
    (Location::Credentials, Rule::Under("/etc/sudoers.d")),
    (Location::Credentials, Rule::Contains("/.ssh/")),
    (Location::Credentials, Rule::Name(".ssh")),
    (Location::Credentials, Rule::Contains("/keyrings/")),
    (Location::Credentials, Rule::Contains("/.gnupg")),
    (Location::Credentials, Rule::Contains("/.password-store")),
    (Location::Credentials, Rule::Name("login.keyring")),
    (Location::System, Rule::Under("/bin")),
    (Location::System, Rule::Under("/sbin")),
    (Location::System, Rule::Under("/usr/bin")),
    (Location::System, Rule::Under("/usr/sbin")),
    (Location::System, Rule::Under("/usr/local/bin")),
    (Location::System, Rule::Under("/usr/local/sbin")),
    (Location::System, Rule::Under("/lib")),
    (Location::System, Rule::Under("/lib32")),
    (Location::System, Rule::Under("/lib64")),
    (Location::System, Rule::Under("/libx32")),
    (Location::System, Rule::Under("/usr/lib")),
    (Location::System, Rule::Under("/usr/lib32")),
    (Location::System, Rule::Under("/usr/lib64")),
    (Location::System, Rule::Under("/usr/local/lib")),
    (Location::Temp, Rule::Under("/tmp")),
    (Location::Temp, Rule::Under("/dev/shm")),
    (Location::Temp, Rule::Under("/var/tmp")),
    (Location::PseudoFs, Rule::Under("/proc")),
    (Location::PseudoFs, Rule::Under("/sys")),
    (Location::PseudoFs, Rule::UnderExcept("/dev", "/dev/shm")),
    (Location::Hidden, Rule::DotComponent),
];

/// The classes of one path. `own` holds the sample's own image paths.
/// Memfd, relative and unresolved names get no class from the path rules.
pub(super) fn classify(path: &str, own: &[String]) -> Vec<Location> {
    let mut found = Vec::new();
    for (location, rule) in RULES {
        if !found.contains(location) && rule.matches(path) {
            found.push(*location);
        }
    }
    if own.iter().any(|image| image == path) {
        found.push(Location::SelfPath);
    }
    found.sort();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(path: &str) -> Vec<&'static str> {
        classify(path, &[]).into_iter().map(Location::tag).collect()
    }

    #[test]
    fn persistence_paths() {
        for path in [
            "/etc/crontab",
            "/etc/cron.d/job",
            "/var/spool/cron/crontabs/root",
            "/etc/systemd/system/x.service",
            "/home/user/.config/autostart/x.desktop",
            "/etc/rc.local",
            "/etc/rc3.d/S99x",
            "/root/.bashrc",
            "/home/user/.zshrc",
            "/etc/profile.d/x.sh",
            "/etc/ld.so.preload",
            "/home/user/.ssh/authorized_keys",
        ] {
            assert!(tags(path).contains(&"persistence"), "{path}");
        }
        assert!(!tags("/etc/crypttab").contains(&"persistence"));
        assert!(!tags("/home/user/bashrc").contains(&"persistence"));
    }

    #[test]
    fn credential_paths() {
        for path in [
            "/etc/shadow",
            "/etc/passwd",
            "/etc/passwd-",
            "/etc/sudoers.d/x",
            "/root/.ssh/id_rsa",
            "/home/user/.local/share/keyrings/login.keyring",
            "/home/user/.gnupg/pubring.kbx",
        ] {
            assert!(tags(path).contains(&"credentials"), "{path}");
        }
        assert!(!tags("/etc/group").contains(&"credentials"));
    }

    #[test]
    fn system_temp_and_pseudo_paths_respect_directory_boundaries() {
        assert_eq!(tags("/usr/bin/ls"), ["system"]);
        assert_eq!(tags("/lib/x86_64-linux-gnu/libc.so.6"), ["system"]);
        assert!(tags("/usr/binary/x").is_empty());
        assert!(tags("/libre/x").is_empty());
        assert_eq!(tags("/tmp/a"), ["temp"]);
        assert_eq!(tags("/tmp"), ["temp"]);
        assert!(tags("/tmpfoo/a").is_empty());
        assert_eq!(tags("/dev/shm/payload"), ["temp"]);
        assert_eq!(tags("/var/tmp/x"), ["temp"]);
        assert_eq!(tags("/proc/self/mem"), ["pseudo-fs"]);
        assert_eq!(tags("/sys/kernel/x"), ["pseudo-fs"]);
        assert_eq!(tags("/dev/null"), ["pseudo-fs"]);
    }

    #[test]
    fn hidden_paths_and_combined_classes() {
        assert_eq!(tags("/tmp/.x/payload"), ["temp", "hidden"]);
        assert!(tags("/home/user/.cache/a").contains(&"hidden"));
        assert!(tags("/home/user/a..b").is_empty());
        assert!(tags("/home/user/./a/../b").is_empty());
        let combined = tags("/home/user/.ssh/authorized_keys");
        for tag in ["persistence", "credentials", "hidden"] {
            assert!(combined.contains(&tag), "{tag}");
        }
    }

    #[test]
    fn the_sample_s_own_path_is_a_class_of_its_own() {
        let own = vec!["/tmp/sample".to_owned()];
        let found = classify("/tmp/sample", &own);
        assert!(found.contains(&Location::SelfPath) && found.contains(&Location::Temp));
        assert!(!classify("/tmp/other", &own).contains(&Location::SelfPath));
        assert!(classify("memfd:x", &[]).is_empty());
        assert!(classify("—", &[]).is_empty());
    }
}
