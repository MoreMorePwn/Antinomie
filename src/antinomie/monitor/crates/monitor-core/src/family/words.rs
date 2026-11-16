// SPDX-License-Identifier: GPL-3.0-only
//! Which rule names name a family and which name a technique (ANT-T0556,
//! A48/A53), and the families a run's own behaviour names.
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

/// What a run's own behaviour says about its family: files, services and
/// URL paths public reports tie to one family. Each entry is a family and
/// the markers any of which names it. Keep this list short and cite the
/// marker's source in the comment.
const BEHAVIOUR_SIGNATURES: &[(&str, &[&str])] = &[
    // Prometei's Linux bot installs itself as /usr/sbin/uplugplay with an
    // uplugplay systemd unit and polls /cgi-bin/p.cgi (Cisco Talos,
    // "Prometei botnet improves modules", 2023; seen in the 2026-11-16
    // x86-64 evaluation runs 21011aed, a5dbdaf2, 6bca3c88, ad28ddd7).
    (
        "Prometei",
        &[
            "/usr/sbin/uplugplay",
            "uplugplay.service",
            "/cgi-bin/p.cgi?r=",
        ],
    ),
];

/// The families the run's behaviour names: for each, the first marker seen
/// in `observed` (file paths, URLs and command lines of the run).
pub fn behaviour_families(observed: &[&str]) -> Vec<(String, String)> {
    BEHAVIOUR_SIGNATURES
        .iter()
        .filter_map(|(family, markers)| {
            markers
                .iter()
                .find(|marker| observed.iter().any(|seen| seen.contains(**marker)))
                .map(|marker| ((*family).to_owned(), (*marker).to_owned()))
        })
        .collect()
}
