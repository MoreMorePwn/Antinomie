// SPDX-License-Identifier: GPL-3.0-only
//! Which rule names name a family and which name a technique (ANT-T0556,
//! A48/A53), the rules known to match other programs, and the families
//! with no Linux variant.
//!
//! A family comes only from a rule that names one: a `family` meta, an
//! Elastic or Malpedia family rule, a known family's name in a curated rule,
//! or a curated vendor rule that says it is malware (`DITEKSHEN_MALWARE_..`).
//! A rule that names a technique (`ELF_Toriilike_persist`,
//! `NSVPS_Mirai_Busybox_Staging`, `ELF_Packer_Dropper_Fileless_Armhf`) or is
//! generic (`Suspicious_Golang_Binary`) gives tags, never a family, even when
//! its meta names one: "Torii-like persistence" is seen in Gafgyt and Mirai
//! builds alike.

/// Malware families (and C2 frameworks) seen on Linux and IoT, lower case,
/// that a rule name may carry as a word. A community rule's name gives a
/// family only when the word is one of these.
pub const KNOWN_FAMILIES: &[&str] = &[
    "mirai",
    "gafgyt",
    "bashlite",
    "tsunami",
    "kaiten",
    "xorddos",
    "mozi",
    "hajime",
    "kinsing",
    "rekoobe",
    "dofloo",
    "lightaidra",
    "vpnfilter",
    "satori",
    "okiru",
    "masuta",
    "ebury",
    "bpfdoor",
    "sliver",
    "merlin",
    "prometei",
    "torii",
    "symbiote",
    "winnti",
    "tinyshell",
    "rotajakiro",
    "hiddenwasp",
    "p2pinfect",
    "teamtnt",
    "ipstorm",
    "evilgnome",
    "fritzfrog",
    "xmrig",
    "ngioweb",
    "moobot",
    "zerobot",
    "kaiji",
    "rapperbot",
    "condi",
    "hailbot",
    "skidmap",
    "orbit",
    "facefish",
    "kobalos",
    "cyclopsblink",
    "enemybot",
    "fodcha",
    "muhstik",
    "momentum",
    "necro",
    "freakout",
    "lucifer",
    "outlaw",
    "shellbot",
    "sysrv",
    "watchdog",
    "dreambus",
    "headcrab",
    "gobrat",
    "reptile",
    "diamorphine",
    "azazel",
    "bedevil",
    "pupy",
    "vshell",
    "manjusaka",
    "cobaltstrike",
    "chaos",
    "aisuru",
    "gorilla",
    "pumakit",
    "melofee",
    "xnote",
    "darkiot",
    "matryosh",
    "zhtrap",
    "specter",
];

/// Words of a rule name that say it detects a technique, a packer or a
/// generic trait, not a family.
const TECHNIQUE_WORDS: &[&str] = &[
    "persist",
    "persistence",
    "staging",
    "stager",
    "dropper",
    "downloader",
    "packer",
    "packed",
    "fileless",
    "exploit",
    "commandinjection",
    "injection",
    "inject",
    "injector",
    "bruteforce",
    "brute",
    "scanner",
    "wget",
    "curl",
    "chmod",
    "execute",
    "cradle",
    "detect",
    "suspicious",
    "sus",
    "hunt",
    "generic",
    "test",
    "like",
    "cve",
    "webshell",
    "obfuscated",
    "upx",
];

/// Lower-case words of a rule name with the tag each gives.
const TAG_WORDS: &[(&str, &str)] = &[
    ("persist", "persistence"),
    ("persistence", "persistence"),
    ("staging", "staging"),
    ("stager", "staging"),
    ("dropper", "dropper"),
    ("downloader", "downloader"),
    ("packer", "packer"),
    ("packed", "packer"),
    ("upx", "UPX"),
    ("fileless", "fileless"),
    ("exploit", "exploit"),
    ("commandinjection", "command injection"),
    ("bruteforce", "brute force"),
    ("scanner", "scanner"),
    ("golang", "Go binary"),
    ("webshell", "web shell"),
    ("miner", "miner"),
    ("ddos", "DDoS"),
    ("proxy", "proxy"),
    ("cve", "exploit"),
];

/// Words that make a curated vendor rule say "this is malware":
/// `DITEKSHEN_MALWARE_Linux_Foobar`, `SIGNATURE_BASE_MAL_..`.
const MALWARE_WORDS: &[&str] = &[
    "mal",
    "malware",
    "backdoor",
    "trojan",
    "rat",
    "botnet",
    "ransomware",
    "rootkit",
    "implant",
];

fn tokens(name: &str) -> Vec<String> {
    name.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

/// A known family word, `Toriilike` gives `torii`.
fn known(token: &str) -> Option<&'static str> {
    let token = token.strip_suffix("like").unwrap_or(token);
    KNOWN_FAMILIES.iter().copied().find(|known| *known == token)
}

/// Whether a token is a known family's name.
pub fn is_known_family(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    KNOWN_FAMILIES.contains(&lower.as_str())
}

/// Whether a rule's name says it detects a technique or a generic trait
/// (see [`TECHNIQUE_WORDS`]; a word ending in `like`, as in `Toriilike`,
/// counts too). Such a rule gives tags, never a family.
pub fn is_technique_rule(rule: &str) -> bool {
    tokens(rule).iter().any(|token| {
        TECHNIQUE_WORDS.contains(&token.as_str()) || (token.len() > 4 && token.ends_with("like"))
    })
}

/// Whether a curated vendor rule's name says it detects malware.
pub fn says_malware(rule: &str) -> bool {
    tokens(rule)
        .iter()
        .any(|token| MALWARE_WORDS.contains(&token.as_str()))
}

/// The tags a technique or generic rule gives: what it detects
/// ("persistence", "staging", "Go binary"), and "Torii-like" for the family
/// its name or meta compares the sample to.
pub fn rule_tags(rule: &str, meta_family: &str) -> Vec<String> {
    let mut tags: Vec<String> = Vec::new();
    let mut add = |tag: String| {
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    };
    let words = tokens(rule);
    let like = words
        .iter()
        .find_map(|token| known(token))
        .map(str::to_owned)
        .or_else(|| {
            let meta = meta_family.trim();
            (!meta.is_empty()).then(|| meta.rsplit('.').next().unwrap_or(meta).to_owned())
        });
    if let Some(family) = like {
        add(format!("{}-like", super::pretty(&family)));
    }
    for token in &words {
        if let Some((_, tag)) = TAG_WORDS.iter().find(|(word, _)| word == token) {
            add((*tag).to_owned());
        }
    }
    tags
}

/// YARA rules known to match programs of other families, each with why. A
/// family only these name is "also named", never the run's family and never
/// family evidence (ANT-T0604). Keep this list short and give the evidence.
pub const DOUBTFUL_RULES: &[(&str, &str)] = &[
    // Its string $d5 "glibc.malloc.top" is the start of the glibc tunable
    // glibc.malloc.top_pad, in every statically linked glibc program, and the
    // rule matches on that one string. T0600: it matched Prometei 0f7149c0,
    // Rekoobe 1adee8d0 and Mirai 9a38b870 through $d5 alone.
    (
        "MIRAI_OHSHIT_payload",
        "its string \"glibc.malloc.top\" is part of a glibc setting name found in every statically linked glibc program",
    ),
    // Its own meta says "Lineage marker, not a family discriminator": it
    // matches Mirai's reserved address ranges ("119.0.0.0", "120.0.0.0"),
    // which Gafgyt builds copy. T0600: Gafgyt 62c5b21d.
    (
        "MIRAI_TELNETCURL_payload",
        "its author calls it a lineage marker, not a family discriminator; it matches address ranges Mirai's code shares with Gafgyt builds",
    ),
];

/// Why a rule is in [`DOUBTFUL_RULES`], when it is.
pub fn doubtful_rule(rule: &str) -> Option<&'static str> {
    DOUBTFUL_RULES
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(rule))
        .map(|(_, why)| *why)
}

/// Families with no Linux variant, lower case without separators: a rule
/// name, a meta or an IDS message that names one of these never names the
/// family of a Linux program (ANT-T0604: an abuse.ch YARAhub rule for
/// RemcosRAT matched "</script>" in the Go bot Chaos). Families with Linux
/// builds (Cobalt Strike's CrossC2, NetWire, Gh0st forks, the Gafgyt fork
/// QBot) are not listed.
const WINDOWS_ONLY: &[&str] = &[
    "remcos",
    "remcosrat",
    "agenttesla",
    "asyncrat",
    "njrat",
    "nanocore",
    "formbook",
    "xloader",
    "lokibot",
    "emotet",
    "trickbot",
    "qakbot",
    "dridex",
    "icedid",
    "redline",
    "redlinestealer",
    "raccoon",
    "vidar",
    "azorult",
    "darkcomet",
    "quasar",
    "quasarrat",
    "dcrat",
    "warzone",
    "warzonerat",
    "avemaria",
    "smokeloader",
    "guloader",
    "ursnif",
    "gozi",
    "zloader",
    "amadey",
    "lumma",
    "lummastealer",
    "stealc",
    "xworm",
    "bumblebee",
    "pikabot",
    "hancitor",
    "darkgate",
    "snakekeylogger",
    "valleyrat",
];

/// Whether a family has no Linux variant ([`WINDOWS_ONLY`]).
pub fn windows_only(family: &str) -> bool {
    let key: String = family
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    WINDOWS_ONLY.contains(&key.as_str())
}

/// Words that name a kind of rule, a platform or a date, not a family.
pub(super) const NOT_FAMILY: &[&str] = &[
    "mal",
    "malware",
    "elf",
    "linux",
    "lin",
    "lnx",
    "unix",
    "win",
    "windows",
    "apt",
    "hktl",
    "susp",
    "suspicious",
    "trojan",
    "backdoor",
    "rat",
    "botnet",
    "exploit",
    "webshell",
    "loader",
    "dropper",
    "generic",
    "crime",
    "crimeware",
    "ransom",
    "ransomware",
    "miner",
    "cryptominer",
    "coinminer",
    "tool",
    "pua",
    "x64",
    "x86",
    "arm",
    "arm64",
    "mips",
    "packer",
    "upx",
    "shell",
    "script",
    "file",
    "ioc",
    "ttp",
    "cve",
    "rule",
    "hacktool",
    "stealer",
    "worm",
    "virus",
    "agent",
    "family",
    "bot",
    "downloader",
    "implant",
    "strings",
    "string",
    "payload",
    "obfuscated",
    "encoded",
    "code",
    "command",
    "config",
    "sample",
    "general",
    "common",
    "possible",
    "potential",
    "detect",
    "detection",
    "indicator",
    "indicators",
    "keyword",
    "keywords",
    "hash",
    "hashes",
    "anomaly",
    "behavior",
    "behaviour",
    "encrypted",
    "golang",
    "go",
    "rust",
    "python",
    "java",
    "php",
    "pe",
    "dll",
    "exe",
    "base64",
    "heur",
    "hunt",
    "hunting",
    "test",
];

/// Tags MalwareBazaar gives that say a file type, an architecture, a packer or
/// a kind of malware, not a family.
pub(super) const GENERIC_TAGS: &[&str] = &[
    "elf",
    "exe",
    "dll",
    "sh",
    "bash",
    "py",
    "ps1",
    "js",
    "vbs",
    "bat",
    "msi",
    "apk",
    "pe",
    "upx",
    "x86",
    "x86-64",
    "x86_64",
    "x64",
    "amd64",
    "i386",
    "i686",
    "arm",
    "arm32",
    "arm64",
    "aarch64",
    "armv5",
    "armv6",
    "armv7",
    "mips",
    "mipsel",
    "mips64",
    "ppc",
    "powerpc",
    "riscv",
    "sparc",
    "sh4",
    "m68k",
    "32",
    "64",
    "32-bit",
    "64-bit",
    "ua-wget",
    "ua-curl",
    "opendir",
    "geofenced",
    "malware",
    "botnet",
    "trojan",
    "backdoor",
    "rat",
    "ddos",
    "miner",
    "coinminer",
    "cryptominer",
    "ransomware",
    "rootkit",
    "stealer",
    "loader",
    "dropper",
    "worm",
    "virus",
    "linux",
    "unix",
    "iot",
    "packed",
    "unpacked",
    "stripped",
    "golang",
    "go",
    "rust",
    "c2",
    "payload",
    "suspicious",
    "malicious",
    "shellcode",
    "script",
    "xz",
    "gz",
    "zip",
    "tar",
    "wget",
    "curl",
    "tor",
    "ssh",
    "telnet",
    "exploit",
    "cve",
    "scanner",
    "bruteforce",
    "cnc",
    "downloader",
];
