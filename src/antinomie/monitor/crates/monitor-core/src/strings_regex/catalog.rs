// SPDX-License-Identifier: GPL-3.0-only
//! The built-in patterns, by category. The id of a pattern is what the rule
//! manager stores when a pattern is switched off, so ids never change.
use super::{Category, checks::Check};

pub(super) struct Builtin {
    pub id: &'static str,
    pub category: Category,
    pub name: &'static str,
    pub regex: &'static str,
    pub check: Check,
    pub weak: bool,
}

const fn rule(
    id: &'static str,
    category: Category,
    name: &'static str,
    regex: &'static str,
    check: Check,
) -> Builtin {
    Builtin {
        id,
        category,
        name,
        regex,
        check,
        weak: false,
    }
}

/// A pattern that gives way to a stronger one over the same text.
const fn weak(
    id: &'static str,
    category: Category,
    name: &'static str,
    regex: &'static str,
    check: Check,
) -> Builtin {
    Builtin {
        weak: true,
        ..rule(id, category, name, regex, check)
    }
}

use Category::{Attribution, Behaviour, Crypto, Encoded, Keys, Network};

pub(super) const BUILTIN: &[Builtin] = &[
    // Network.
    weak(
        "net.ipv4",
        Network,
        "IPv4",
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        Check::Ipv4,
    ),
    weak(
        "net.ipv6",
        Network,
        "IPv6",
        r"(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f.:]{0,40}",
        Check::Ipv6,
    ),
    weak(
        "net.domain",
        Network,
        "Domain",
        r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\b",
        Check::Domain,
    ),
    rule(
        "net.url",
        Network,
        "URL",
        r#"(?i)\b(?:https?|ftps?|sftp|wss?|tcp|udp|ssh|irc|tftp|socks[45]h?)://[^\s"'<>\\^`{}|]+"#,
        Check::Url,
    ),
    rule(
        "net.email",
        Network,
        "Email",
        r"(?i)\b[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]+\.)+[a-z]{2,24}\b",
        Check::Email,
    ),
    rule(
        "net.onion",
        Network,
        "Onion address",
        r"(?i)\b(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion\b",
        Check::None,
    ),
    rule(
        "net.telegram",
        Network,
        "Telegram bot token",
        r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b",
        Check::Telegram,
    ),
    rule(
        "net.discord",
        Network,
        "Discord webhook",
        r"(?i)\bhttps://(?:(?:ptb|canary)\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[\w-]{20,100}",
        Check::None,
    ),
    rule(
        "net.paste",
        Network,
        "Paste site",
        r"(?i)\b(?:pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.\w+|rentry\.(?:co|org)|controlc\.com|ix\.io|0bin\.net|justpaste\.it|dpaste\.(?:org|com)|termbin\.com|transfer\.sh|gist\.githubusercontent\.com|raw\.githubusercontent\.com)(?:/[^\s]*)?",
        Check::None,
    ),
    rule(
        "net.tunnel",
        Network,
        "Tunnel service",
        r"(?i)\b[a-z0-9.-]*(?:ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|serveo\.net|localhost\.run|loca\.lt|localtunnel\.me|pagekite\.me|bore\.pub|tunnelto\.dev|playit\.gg|portmap\.io|pinggy\.io)\b",
        Check::None,
    ),
    rule(
        "net.stratum",
        Network,
        "Stratum pool",
        r"(?i)\bstratum\+(?:tcp|ssl|tls|udp)://[^\s]+",
        Check::None,
    ),
    // Crypto.
    rule(
        "crypto.btc",
        Crypto,
        "Bitcoin address",
        r"\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b",
        Check::Btc,
    ),
    rule(
        "crypto.btc_bech32",
        Crypto,
        "Bitcoin address",
        r"\b(?:bc|tb)1[ac-hj-np-z02-9]{11,87}\b",
        Check::Bech32,
    ),
    rule(
        "crypto.eth",
        Crypto,
        "Ethereum address",
        r"\b0x[0-9a-fA-F]{40}\b",
        Check::Eth,
    ),
    rule(
        "crypto.xmr",
        Crypto,
        "Monero address",
        r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}(?:[1-9A-HJ-NP-Za-km-z]{11})?\b",
        Check::Xmr,
    ),
    rule(
        "crypto.tox",
        Crypto,
        "Tox ID",
        r"\b[0-9A-Fa-f]{76}\b",
        Check::Tox,
    ),
    // Keys and tokens.
    rule(
        "keys.ssh",
        Keys,
        "SSH public key",
        r"\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com)\s+AAAA[0-9A-Za-z+/]{20,}={0,3}",
        Check::SshKey,
    ),
    rule(
        "keys.pem",
        Keys,
        "PEM block",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?(?:PRIVATE KEY|PUBLIC KEY|CERTIFICATE|PRIVATE KEY BLOCK|PUBLIC KEY BLOCK)-----",
        Check::None,
    ),
    rule(
        "keys.aws",
        Keys,
        "AWS access key id",
        r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b",
        Check::None,
    ),
    rule(
        "keys.github",
        Keys,
        "GitHub token",
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
        Check::None,
    ),
    rule(
        "keys.jwt",
        Keys,
        "JSON Web Token",
        r"\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b",
        Check::Jwt,
    ),
    // Linux behaviour.
    rule(
        "linux.cradle_pipe",
        Behaviour,
        "Download cradle",
        r"(?i)\b(?:curl|wget|fetch)\b[^\n\r|;]{0,300}\|\s*(?:sudo\s+)?(?:/(?:usr/)?bin/)?(?:ba|z|da|k|c)?sh\b",
        Check::None,
    ),
    rule(
        "linux.cradle_run",
        Behaviour,
        "Download cradle",
        r"(?i)\b(?:curl|wget|tftp|ftpget)\b[^\n\r]{0,300}?(?:-[Oo]|>)\s*\S+[^\n\r]{0,100}?chmod\s+(?:\+x|[0-7]{3,4})",
        Check::None,
    ),
    rule(
        "linux.cradle_tmp",
        Behaviour,
        "Download to a writable directory",
        r"(?i)\b(?:curl|wget|tftp|ftpget)\b[^\n\r]{0,200}?(?:/tmp/|/dev/shm/|/var/tmp/)\S+",
        Check::None,
    ),
    rule(
        "linux.reverse_shell",
        Behaviour,
        "Reverse shell",
        r"/dev/(?:tcp|udp)/[A-Za-z0-9.\-]+/\d{1,5}",
        Check::None,
    ),
    rule(
        "linux.persistence",
        Behaviour,
        "Persistence path",
        r"/etc/(?:cron(?:\.(?:d|daily|hourly|weekly|monthly))?(?:/\S+)?|crontab|rc\.local|rc\d?\.d/\S+|init\.d/\S+|profile(?:\.d/\S+)?|bash\.bashrc|ld\.so\.preload|ld\.so\.conf\.d/\S+|systemd/system/\S+|sudoers(?:\.d/\S+)?|update-motd\.d/\S+|xdg/autostart/\S+)|/var/spool/cron(?:/crontabs)?(?:/\S+)?|/usr/lib/systemd/(?:system|user)/\S+|\.config/(?:autostart|systemd/user)/\S+|\.ssh/authorized_keys2?\b|(?:^|[\s/~=:])\.(?:bashrc|bash_profile|bash_login|bash_logout|profile|zshrc|xinitrc|xprofile)\b",
        Check::None,
    ),
    rule(
        "linux.credentials",
        Behaviour,
        "Credential file",
        r"/etc/(?:shadow|gshadow)\b|\.aws/credentials|\.docker/config\.json|\.ssh/id_(?:rsa|dsa|ecdsa|ed25519)\b|\.git-credentials|\.netrc\b|\.kube/config",
        Check::None,
    ),
    rule(
        "linux.anti_analysis",
        Behaviour,
        "Anti-analysis",
        r"TracerPid|PTRACE_TRACEME|/proc/self/status|/proc/sys/kernel/(?:yama/ptrace_scope|randomize_va_space)|/sys/class/dmi/id/(?:product_name|sys_vendor|bios_vendor|board_vendor)|/proc/scsi/scsi|\bVBoxGuest\b|\bvboxsf\b|VMware|\bQEMU\b|\bKVMKVMKVM\b|\bfrida(?:-server|-agent|-gadget)?\b|\bstrace\b|\bltrace\b|\bLD_PRELOAD\b|/proc/self/exe",
        Check::None,
    ),
    rule(
        "linux.cloud_metadata",
        Behaviour,
        "Cloud metadata",
        r"(?i)169\.254\.169\.254|169\.254\.170\.2\b|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200|/latest/meta-data|/computeMetadata/v1|Metadata-Flavor",
        Check::None,
    ),
    // Attribution.
    rule(
        "attr.build_path",
        Attribution,
        "Build path",
        r"(?:/home|/Users)/[A-Za-z0-9._-]+/[^\s\x22':;]{3,}|/root/[^\s\x22':;]{3,}|/tmp/go-build\d+/\S+|/(?:builddir|build|buildbot|buildslave|workspace|usr/src|var/tmp/portage)/[^\s\x22':;]{3,}|[A-Za-z]:\\(?:Users|Documents and Settings)\\[^\s\x22':;]{3,}",
        Check::None,
    ),
    rule(
        "attr.go_path",
        Attribution,
        "Go path",
        r"(?:/go/pkg/mod|/go/src|/usr/(?:local/)?go/src)/[^\s\x22':;]{3,}|\bgithub\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|Go build ID: \S+|\bgo1\.\d{1,2}(?:\.\d{1,2})?\b",
        Check::None,
    ),
    rule(
        "attr.rust_path",
        Attribution,
        "Rust path",
        r"/rustc/[0-9a-f]{40}/\S+|\.cargo/registry/src/[^\s\x22':;]+|/rust/deps/[^\s\x22':;]+|\brustc \d+\.\d+\.\d+",
        Check::None,
    ),
    rule(
        "attr.packer",
        Attribution,
        "Packer marker",
        r"\$Info: This file is packed with the UPX|\$Id: UPX [^$]*\$|\bUPX!|\bPyInstaller\b|\b_MEIPASS\b|\bpyarmor\b|\bNuitka\b|\bkiteshield\b|\bgzexe\b|\bshc Version\b|\bMidgetPack\b|\bELFuck\b",
        Check::None,
    ),
    // Encoded data, decoded and scanned again.
    rule(
        "encoded.base64",
        Encoded,
        "base64",
        r"[A-Za-z0-9+/_-]{24,}={0,2}",
        Check::Base64,
    ),
    rule(
        "encoded.hex",
        Encoded,
        "hex",
        r"\b(?:[0-9a-fA-F]{2}){12,}\b",
        Check::Hex,
    ),
];
