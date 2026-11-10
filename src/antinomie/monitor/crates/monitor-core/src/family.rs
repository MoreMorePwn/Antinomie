// SPDX-License-Identifier: GPL-3.0-only
//! Which malware family a run's detections name, and how much a YARA match
//! says. Family candidates come first from rules that name a family on
//! purpose (an Elastic `Linux_Trojan_<Family>_<hash>` rule, a `family` meta,
//! Malpedia, the sample's MalwareBazaar record), and only then from fragments
//! of other rule names. Several rules naming one family raise it.
use crate::run_digest::DetectionHit;
use std::collections::BTreeMap;

/// A malware family a detection names, with where it said so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub name: String,
    pub source: String,
    /// How much the rules and records that name it add up to: an Elastic
    /// rule its score, a `family` meta 90, MalwareBazaar's signature 85.
    pub points: u32,
    /// A rule or record that names a family on purpose named it.
    pub strong: bool,
}

/// The candidates a report names as the family: the first, and any other
/// with at least half its points (MalwareBazaar's signature and tags may name
/// two). The rest are "also named". Both lists keep the candidates' order.
pub fn primary_families(candidates: &[Candidate]) -> (Vec<&Candidate>, Vec<&Candidate>) {
    let top = candidates.first().map_or(0, |c| c.points);
    let mut primary = Vec::new();
    let mut other = Vec::new();
    for (at, candidate) in candidates.iter().enumerate() {
        if at == 0 || candidate.points * 2 >= top {
            primary.push(candidate);
        } else {
            other.push(candidate);
        }
    }
    (primary, other)
}

/// The family one YARA or IDS match names, when it names one on purpose or
/// in its name: what [`family_candidates`] counts for this match.
pub fn rule_family(hit: &DetectionHit) -> Option<String> {
    hit_mentions(hit).into_iter().next().map(|m| m.name)
}

/// What MalwareBazaar says of the run's sample: its `signature` and `tags`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Bazaar<'a> {
    pub signature: Option<&'a str>,
    pub tags: &'a [String],
    /// The record was fetched by the sample's hash after the sample was
    /// imported from a file; the sources say so.
    pub looked_up: bool,
}

/// Fragments of rule names that never are a family, kept in this one place:
/// hunting and test rules (`TH_Generic_MassHunt_Linux_Malware`,
/// `ELF_IoT_Persistence_Hunt`, `LIN_Sample_Unique_<hash>`, `meth_stackstrings`,
/// `test_Malaysia`), the bare category `RANSOMWARE`, and pack prefixes. A
/// candidate is never taken from one of these, and a rule whose name carries
/// one is a generic match.
pub const GENERIC_FRAGMENTS: &[&str] = &[
    "masshunt",
    "unique",
    "base",
    "iot",
    "stackstrings",
    "generic",
    "sample",
    "unknown",
    "hunt",
    "test",
    "ransomware",
];

/// Prefixes and words of the packs' rule names that are no family but do not
/// make a rule generic (`SIGNATURE_BASE_EXT_HKTL_...`, `MULTI_Malware_...`).
const PACK_WORDS: &[&str] = &[
    "th",
    "multi",
    "signature",
    "ext",
    "nsvps",
    "dvr",
    "forgeauto",
    "threat",
    // The rule packs' vendors and authors name their rules `SEKOIA_...`,
    // `ESET_...`, `DITEKSHEN_...`: a vendor is never the family.
    "sekoia",
    "eset",
    "elastic",
    "ditekshen",
    "gcti",
    "malpedia",
    "fireeye",
    "rt",
    "cape",
    "volexity",
    "trellix",
    "arc",
    "loldrivers",
    "withsecurelabs",
    "blackberry",
    "elceef",
    "craiu",
    "cod3nym",
    "cadosecurity",
    "dr4k0nia",
    "synacktiv",
    "deadbits",
    "yarahub",
    "forge",
    "auto",
    "expl",
    "unidentified",
    "guid",
    "name",
];

/// Words that name a kind of rule, a platform or a date, not a family.
const NOT_FAMILY: &[&str] = &[
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

/// Families that Linux IDS signature names carry as a word.
const IDS_FAMILIES: &[&str] = &[
    "mirai",
    "gafgyt",
    "bashlite",
    "tsunami",
    "kaiten",
    "xorddos",
    "mozi",
    "hajime",
    "qbot",
    "kinsing",
    "xmrig",
    "rekoobe",
    "dofloo",
    "lightaidra",
    "vpnfilter",
    "satori",
    "okiru",
    "masuta",
    "hide and seek",
    "ebury",
    "bpfdoor",
    "tsunami",
];

/// A lower-case word of a rule name that is no family.
fn not_family(lower: &str) -> bool {
    NOT_FAMILY.contains(&lower) || GENERIC_FRAGMENTS.contains(&lower) || PACK_WORDS.contains(&lower)
}

/// Families whose usual spelling has inner capitals; rule names and tags often
/// give them in one case.
const SPELLINGS: &[&str] = &[
    "RotaJakiro",
    "BPFDoor",
    "XorDDoS",
    "HiddenWasp",
    "P2PInfect",
    "XMRig",
    "TeamTNT",
    "IPStorm",
    "EvilGnome",
    "FritzFrog",
    "VPNFilter",
    "OpenSSH",
    "Kinsing",
    "Sliver",
    "Merlin",
    "Tsunami",
    "Gafgyt",
    "Rekoobe",
    "Mirai",
    "Mozi",
    "Hajime",
    "Kaiten",
    "Prometei",
    "Torii",
    "Symbiote",
    "Winnti",
    "Tinyshell",
];

fn pretty(word: &str) -> String {
    if let Some(known) = SPELLINGS
        .iter()
        .find(|known| known.eq_ignore_ascii_case(word))
    {
        return (*known).to_owned();
    }
    if word.chars().any(char::is_uppercase) && word.chars().any(char::is_lowercase) {
        return word.to_owned();
    }
    let lower = word.to_lowercase();
    let mut chars = lower.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// The family a Malpedia-style or `family` meta value names: `elf.mirai` is
/// Mirai and `MIRAI_OHSHIT` is Mirai too (a family token, not the whole
/// value with its suffix glued on).
fn meta_family(value: &str) -> String {
    let value = value.trim();
    let last = value.rsplit('.').next().unwrap_or(value).trim();
    family_token(last).unwrap_or_else(|| pretty(last))
}

/// The family token of a name made of words: the first known family when one
/// is there (`Redmenshen_Bpfdoor` is BPFDoor), else the first word that is
/// no vendor, platform or category.
fn family_token(name: &str) -> Option<String> {
    let tokens: Vec<&str> = name
        .split(['_', '-', ' ', '.'])
        .filter(|token| {
            let lower = token.to_ascii_lowercase();
            !lower.is_empty() && !not_family(&lower) && !lower.chars().any(|c| c.is_ascii_digit())
        })
        .collect();
    let known = tokens.iter().find(|token| {
        SPELLINGS
            .iter()
            .chain(IDS_FAMILIES.iter())
            .any(|known| known.eq_ignore_ascii_case(token))
    });
    if let Some(token) = known {
        return Some(pretty(token));
    }
    let token = tokens.first()?;
    let humps = token
        .chars()
        .zip(token.chars().skip(1))
        .filter(|(a, b)| a.is_lowercase() && b.is_uppercase())
        .count();
    (token.len() >= 3 && humps < 2).then(|| pretty(token))
}

/// A rule's name without the `s123::` prefix the engine puts before its id.
pub fn plain_name(rule: &str) -> &str {
    match rule.split_once("::") {
        Some((prefix, name))
            if prefix.starts_with('s') && prefix[1..].chars().all(|c| c.is_ascii_digit()) =>
        {
            name
        }
        _ => rule,
    }
}

/// `Linux_Trojan_Gafgyt_ba2c1b10`: Elastic's `<Os>_<Category>_<Family>_<hash>`.
fn elastic_family(rule: &str) -> Option<String> {
    const OS: &[&str] = &["linux", "multi", "windows", "macos", "freebsd"];
    const CATEGORY: &[&str] = &[
        "trojan",
        "ransomware",
        "cryptominer",
        "backdoor",
        "rootkit",
        "exploit",
        "hacktool",
        "virus",
        "worm",
        "dropper",
        "shellcode",
        "infostealer",
        "adware",
        "downloader",
        "ransom",
    ];
    let mut tokens: Vec<&str> = rule.split('_').collect();
    if tokens
        .last()
        .is_some_and(|hash| hash.len() == 8 && hash.chars().all(|c| c.is_ascii_hexdigit()))
    {
        tokens.pop();
    }
    if tokens.len() < 3
        || !OS.contains(&tokens[0].to_ascii_lowercase().as_str())
        || !CATEGORY.contains(&tokens[1].to_ascii_lowercase().as_str())
    {
        return None;
    }
    let name = tokens[2..].concat();
    let lower = name.to_ascii_lowercase();
    if name.len() < 3
        || not_family(&lower)
        || lower.starts_with("cve")
        || name.chars().any(|c| c.is_ascii_digit())
    {
        return None;
    }
    Some(pretty(&name))
}

/// Whether a rule name has Elastic's shape: three or more words and an
/// eight-digit hexadecimal id at the end.
fn elastic_named(rule: &str) -> bool {
    rule.rsplit('_')
        .next()
        .is_some_and(|hash| hash.len() == 8 && hash.chars().all(|c| c.is_ascii_hexdigit()))
        && elastic_family(rule).is_some()
}

/// A fragment of a curated pack's rule name that may name a family:
/// `MAL_ELF_Mirai_Jan2020`, `elf_mirai` and `SEKOIA_Backdoor_Lin_Bpfdoor`
/// each carry one, `Suspicious_Strings` carries none. A name like
/// `DetectGoMethodSignatures` is a sentence, not a family.
fn family_in_rule_name(rule: &str) -> Option<String> {
    family_token(rule.strip_prefix("SIGNATURE_BASE_").unwrap_or(rule))
}

/// Tags MalwareBazaar gives that say a file type, an architecture, a packer or
/// a kind of malware, not a family.
const GENERIC_TAGS: &[&str] = &[
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

/// Whether a MalwareBazaar tag could name a family.
fn tag_is_family(tag: &str) -> bool {
    let lower = tag.trim().to_ascii_lowercase();
    lower.len() >= 3
        && !GENERIC_TAGS.contains(&lower.as_str())
        && !not_family(&lower)
        && !lower.contains([':', '.', '/', ' ', '='])
        && !lower.starts_with(|c: char| c.is_ascii_digit())
        && lower.chars().any(|c| c.is_ascii_alphabetic())
}

fn curated_pack(source: &str) -> bool {
    let lower = source.to_ascii_lowercase();
    ["malpedia", "forge", "yarahub"]
        .iter()
        .any(|pack| lower.contains(pack))
}

fn is_elastic(source: &str) -> bool {
    source.to_ascii_lowercase().contains("elastic")
}

fn is_yarahub(source: &str) -> bool {
    source.to_ascii_lowercase().contains("yarahub")
}

/// Elastic's score, the rule's severity when it is a number.
fn score(severity: &str) -> Option<u32> {
    severity.trim().parse().ok()
}

/// How much one YARA match says about the sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strength {
    /// An Elastic rule scored 70 or more, a rule with `family` meta, or a
    /// curated pack's rule that is not generic.
    Strong,
    /// An unscored community rule with no family meta, a generic rule, or an
    /// Elastic rule scored below 70.
    Weak,
    /// The rule's name says Windows, PE, a script or a web page; the sample is
    /// a Linux ELF.
    WrongPlatform,
}

/// Whether a rule's name is a generic or hunting rule (see
/// `GENERIC_FRAGMENTS`).
pub fn is_generic_rule(rule: &str) -> bool {
    let name = plain_name(rule);
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("test_") || lower == "ransomware" {
        return true;
    }
    let name = name.strip_prefix("SIGNATURE_BASE_").unwrap_or(name);
    // `RANSOMWARE` alone is generic; `Linux_Ransomware_Foo` is a category.
    name.split(['_', '-', ' ', '.'])
        .map(str::to_ascii_lowercase)
        .any(|token| token != "ransomware" && GENERIC_FRAGMENTS.contains(&token.as_str()))
}

/// Whether a rule's name says it is for another platform than a Linux ELF.
pub fn wrong_platform(rule: &str) -> bool {
    const OTHER: &[&str] = &[
        "windows",
        "win32",
        "win64",
        "win",
        "mac",
        "msil",
        "pe",
        "html",
        "js",
        "dll",
        "exe",
        "vba",
        "ps1",
        "powershell",
        "macos",
        "osx",
    ];
    let name = plain_name(rule).to_ascii_lowercase();
    let tokens: Vec<&str> = name
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect();
    if tokens.iter().any(|token| OTHER.contains(token)) {
        return true;
    }
    // A shell script is a fine sample on Linux.
    tokens.contains(&"script")
        && !tokens
            .iter()
            .any(|token| matches!(*token, "linux" | "shell" | "bash" | "sh" | "lin" | "elf"))
}

/// The strength of one YARA match: its rule name, severity (an Elastic score),
/// pack and `family` meta.
pub fn strength(rule: &str, severity: &str, source: &str, family: &str) -> Strength {
    if wrong_platform(rule) {
        return Strength::WrongPlatform;
    }
    let family = family.trim();
    if !family.is_empty() && !not_family(&meta_family(family).to_ascii_lowercase()) {
        return Strength::Strong;
    }
    if is_generic_rule(rule) {
        return Strength::Weak;
    }
    if is_elastic(source) || score(severity).is_some() {
        return match score(severity) {
            Some(score) if score >= 70 => Strength::Strong,
            _ => Strength::Weak,
        };
    }
    if is_yarahub(source) {
        Strength::Weak
    } else {
        Strength::Strong
    }
}

/// The families MalwareBazaar names for a sample, each with where it said so:
/// the `signature` first, then every tag that is not a generic one (a file
/// type, an architecture, a packer, a kind of malware) and not the signature
/// again. A sample with signature `Mirai` and tags `elf`, `Mirai`, `Prometei`
/// gives Mirai (signature) and Prometei (tag).
pub fn bazaar_families(signature: Option<&str>, tags: &[String]) -> Vec<(String, &'static str)> {
    let mut out: Vec<(String, &'static str)> = Vec::new();
    let add = |name: String, source: &'static str, out: &mut Vec<(String, &'static str)>| {
        if !out
            .iter()
            .any(|(known, _)| known.eq_ignore_ascii_case(&name))
        {
            out.push((name, source));
        }
    };
    if let Some(signature) = signature.map(str::trim).filter(|s| !s.is_empty())
        && !not_family(&signature.to_ascii_lowercase())
    {
        add(pretty(signature), "MalwareBazaar signature", &mut out);
    }
    for tag in tags.iter().filter(|tag| tag_is_family(tag)) {
        add(pretty(tag.trim()), "MalwareBazaar tag", &mut out);
    }
    out
}

/// One mention of a family.
struct Mention {
    name: String,
    points: u32,
    strong: bool,
    source: String,
}

/// The families the run's detection matches and the sample's MalwareBazaar
/// record name, strongest first, each with its source. A family named by an
/// Elastic family rule (its score counts), by `family` or Malpedia metadata or
/// by MalwareBazaar comes before the fragments of other rule names, and
/// several rules naming one family add up. MalwareBazaar's signature and its
/// tags may name different families; both are candidates.
pub fn family_candidates(hits: &[DetectionHit], bazaar: Bazaar<'_>) -> Vec<Candidate> {
    let mut mentions: Vec<Mention> = Vec::new();
    let yara = |hit: &&DetectionHit| hit.engine.eq_ignore_ascii_case("yara");
    // YARA first, then IDS: on a tie the earlier mention leads.
    mentions.extend(hits.iter().filter(yara).flat_map(hit_mentions));
    mentions.extend(
        hits.iter()
            .filter(|hit| hit.engine.eq_ignore_ascii_case("ids"))
            .flat_map(hit_mentions),
    );
    for (name, source) in bazaar_families(bazaar.signature, bazaar.tags) {
        mentions.push(Mention {
            name,
            points: if source.ends_with("signature") {
                85
            } else {
                60
            },
            strong: true,
            source: if bazaar.looked_up {
                format!("{source} (looked up by hash)")
            } else {
                source.into()
            },
        });
    }
    merge(mentions)
}

/// Points an IDS signature's `malware_family` metadata adds. Next to the
/// YARA mentions: below any strong one (an Elastic rule counts its score, 70
/// or more when it is strong; a `family` meta 90), above every weak one (a
/// curated pack's rule name 20, a word in a signature title 30).
const IDS_META_POINTS: u32 = 45;
/// Points the family in an `ET MALWARE <Family> ...` message adds.
const IDS_MESSAGE_POINTS: u32 = 35;
/// Points a known family word anywhere in an IDS title adds.
const IDS_WORD_POINTS: u32 = 30;
/// Points each family of a known-broad Elastic rule adds (see `BROAD_RULES`).
const BROAD_POINTS: u32 = 25;

/// Elastic rules known to match more than the family their name says: each
/// is listed with the families it is evidence for, the first one the sample
/// is more likely to be. The 2026-11-09 ARM evaluation: a Mirai build
/// matched `Linux_Trojan_Gafgyt_28a2fe0c` and no Mirai rule, because Mirai
/// and Gafgyt builds share code. Such a rule counts as weak evidence for
/// every family listed, so a more specific rule of either family outranks it
/// and, alone, it names the families together. Keep this list short and
/// give a reason for each entry.
const BROAD_RULES: &[(&str, &[&str])] = &[("Linux_Trojan_Gafgyt_28a2fe0c", &["Mirai", "Gafgyt"])];

/// What one YARA or IDS match says of the family: usually one mention, two
/// for a known-broad rule.
fn hit_mentions(hit: &DetectionHit) -> Vec<Mention> {
    let mut found = mentions_of(hit);
    if hit.layer {
        for mention in &mut found {
            mention.source.push_str(" (in the unpacked payload)");
        }
    }
    found
}

/// The IDS message `ET MALWARE <Family> ...` (`ET MALWARE Golang/Linux Kaiji
/// Variant Activity`) names a family when exactly one word before the
/// description is neither a platform, a language nor a category, or when
/// one of them is a known family. Anything unsure gives none.
fn ids_message_family(title: &str) -> Option<String> {
    const ACTIVITY: &[&str] = &[
        "activity",
        "variant",
        "cnc",
        "c2",
        "checkin",
        "check-in",
        "beacon",
        "beaconing",
        "botnet",
        "backdoor",
        "trojan",
        "download",
        "downloader",
        "inbound",
        "outbound",
        "dns",
        "http",
        "https",
        "tcp",
        "udp",
        "tls",
        "ssl",
        "domain",
        "query",
        "request",
        "response",
        "traffic",
        "connection",
        "attempt",
        "scan",
        "scanner",
        "exploit",
        "command",
        "payload",
        "malicious",
        "known",
        "observed",
        "possible",
        "suspected",
        "likely",
        "user-agent",
        "ua",
        "ip",
        "tor",
        "irc",
        "ssh",
        "telnet",
        "login",
        "target",
        "related",
        "reported",
        "agent",
        "stage",
        "generic",
        "and",
        "to",
        "from",
        "with",
        "in",
    ];
    let rest = title.trim().strip_prefix("ET MALWARE ")?;
    let mut tokens: Vec<&str> = Vec::new();
    for token in rest.split(|c: char| c.is_whitespace() || c == '/' || c == '(' || c == ')') {
        let token = token.trim_matches(|c: char| !c.is_ascii_alphanumeric());
        if token.is_empty() {
            continue;
        }
        let lower = token.to_ascii_lowercase();
        // The description starts at the first activity word: the family is
        // named before it, or not at all.
        if ACTIVITY.contains(&lower.as_str()) {
            break;
        }
        if wrong_platform(&lower) {
            // Another platform's malware is no family for a Linux sample.
            return None;
        }
        if not_family(&lower) {
            continue;
        }
        tokens.push(token);
    }
    let known = tokens.iter().find(|token| {
        SPELLINGS
            .iter()
            .chain(IDS_FAMILIES.iter())
            .any(|known| known.eq_ignore_ascii_case(token))
    });
    if let Some(token) = known {
        return Some(pretty(token));
    }
    match tokens.as_slice() {
        [only] if only.len() >= 3 && !only.chars().any(|c| c.is_ascii_digit()) => {
            Some(pretty(only))
        }
        _ => None,
    }
}

fn mentions_of(hit: &DetectionHit) -> Vec<Mention> {
    if hit.engine.eq_ignore_ascii_case("ids") {
        // The signature's own `malware_family` metadata first, then the
        // family its message names, then a known family word in the title.
        let family = hit.family.trim();
        if !family.is_empty() {
            let name = meta_family(family);
            if !not_family(&name.to_ascii_lowercase()) {
                return vec![Mention {
                    name,
                    points: IDS_META_POINTS,
                    strong: false,
                    source: format!("IDS metadata malware_family {family} \u{b7} {}", hit.title),
                }];
            }
        }
        if let Some(name) = ids_message_family(&hit.title) {
            return vec![Mention {
                name,
                points: IDS_MESSAGE_POINTS,
                strong: false,
                source: format!("IDS message \u{b7} {}", hit.title),
            }];
        }
        let title = hit.title.to_ascii_lowercase();
        return IDS_FAMILIES
            .iter()
            .find(|family| title.contains(**family))
            .map(|word| Mention {
                name: pretty(word),
                points: IDS_WORD_POINTS,
                strong: false,
                source: format!("IDS \u{b7} {}", hit.title),
            })
            .into_iter()
            .collect();
    }
    if !hit.engine.eq_ignore_ascii_case("yara") {
        return Vec::new();
    }
    let name = plain_name(&hit.rule_id);
    if let Some((_, families)) = BROAD_RULES.iter().find(|(rule, _)| *rule == name) {
        return families
            .iter()
            .enumerate()
            .map(|(at, family)| Mention {
                name: (*family).to_owned(),
                // The first family leads by one point.
                points: BROAD_POINTS + u32::from(at == 0),
                strong: false,
                source: format!(
                    "YARA \u{b7} Elastic rule {name} (known broad: it matches {})",
                    families.join(" and ")
                ),
            })
            .collect();
    }
    mention_of_yara(hit, name).into_iter().collect()
}

fn mention_of_yara(hit: &DetectionHit, name: &str) -> Option<Mention> {
    let name = if name.is_empty() {
        plain_name(&hit.title)
    } else {
        name
    };
    if !hit.family.is_empty() {
        let family = meta_family(&hit.family);
        if !not_family(&family.to_ascii_lowercase()) {
            return Some(Mention {
                name: family,
                points: 90,
                strong: true,
                source: format!("YARA \u{b7} {} meta {}", hit.source, hit.family),
            });
        }
    }
    // A static scan's match carries no pack: Elastic's `<Os>_<Category>_<Family>_<8 hex>`
    // names are told by the name alone.
    if is_elastic(&hit.source) || (hit.source.is_empty() && elastic_named(name)) {
        let family = elastic_family(name)?;
        return Some(Mention {
            name: family,
            points: score(&hit.severity).unwrap_or(60).min(100),
            strong: true,
            source: format!("YARA \u{b7} Elastic rule {name}"),
        });
    }
    if curated_pack(&hit.source) && !wrong_platform(name) && !is_generic_rule(name) {
        let family = family_in_rule_name(name)?;
        let malpedia = hit.source.to_ascii_lowercase().contains("malpedia");
        return Some(Mention {
            name: family,
            points: if malpedia { 70 } else { 20 },
            strong: malpedia,
            source: format!("YARA \u{b7} {} rule {name}", hit.source),
        });
    }
    None
}

/// One candidate per family: the points add up, the strongest mention gives the
/// name's spelling and the source, and the other kinds of source follow it.
fn merge(mentions: Vec<Mention>) -> Vec<Candidate> {
    struct Total {
        first: usize,
        points: u32,
        strong: bool,
        best: (u32, String, String),
        /// One source per kind (Elastic rule, a pack's rule, IDS, MalwareBazaar).
        kinds: Vec<(String, String)>,
        rules: usize,
    }
    let mut totals: BTreeMap<String, Total> = BTreeMap::new();
    for (at, mention) in mentions.into_iter().enumerate() {
        let total = totals
            .entry(mention.name.to_ascii_lowercase())
            .or_insert_with(|| Total {
                first: at,
                points: 0,
                strong: false,
                best: (0, mention.name.clone(), mention.source.clone()),
                kinds: Vec::new(),
                rules: 0,
            });
        total.points += mention.points;
        total.strong |= mention.strong;
        total.rules += 1;
        if mention.points > total.best.0 {
            total.best = (mention.points, mention.name.clone(), mention.source.clone());
        }
        let kind = mention
            .source
            .split(" rule ")
            .next()
            .unwrap_or_default()
            .to_owned();
        if !total.kinds.iter().any(|(known, _)| *known == kind) {
            total.kinds.push((kind, mention.source));
        }
    }
    let mut list: Vec<Total> = totals.into_values().collect();
    let has_strong = list.iter().any(|total| total.strong);
    // Fragments of community rule names are noise next to a family a strong
    // rule named; the curated packs' and the IDS names stay.
    list.retain(|total| {
        !(has_strong
            && !total.strong
            && total
                .kinds
                .iter()
                .all(|(_, source)| source.contains("yarahub")))
    });
    list.sort_by(|a, b| {
        b.strong
            .cmp(&a.strong)
            .then(b.points.cmp(&a.points))
            .then(a.first.cmp(&b.first))
    });
    list.into_iter()
        .map(|total| {
            let mut source = total.best.2.clone();
            if total.rules > 1 {
                let extra = total.rules - total.kinds.len().min(total.rules);
                if extra > 0 && !source.starts_with("MalwareBazaar") {
                    source = format!("{source} (+{extra} more)");
                }
                for (_, other) in &total.kinds {
                    if *other != total.best.2 {
                        source = format!("{source}; {other}");
                    }
                }
            }
            Candidate {
                name: total.best.1,
                source,
                points: total.points,
                strong: total.strong,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(engine: &str, rule: &str, severity: &str, family: &str, source: &str) -> DetectionHit {
        DetectionHit {
            engine: engine.into(),
            rule_id: rule.into(),
            title: rule.into(),
            severity: severity.into(),
            family: family.into(),
            source: source.into(),
            ..DetectionHit::default()
        }
    }

    fn names(found: &[Candidate]) -> Vec<&str> {
        found.iter().map(|c| c.name.as_str()).collect()
    }

    /// The detections of the 2026-11-07 evaluation runs (trimmed digests).
    fn runs() -> Vec<(String, String, Vec<DetectionHit>)> {
        #[derive(serde::Deserialize)]
        struct Run {
            run: String,
            expected: String,
            hits: Vec<DetectionHit>,
        }
        let runs: Vec<Run> =
            serde_json::from_str(include_str!("family_fixtures/runs.json")).unwrap();
        runs.into_iter()
            .map(|r| (r.run, r.expected, r.hits))
            .collect()
    }

    #[test]
    fn the_true_family_comes_first_in_every_evaluation_run() {
        for (run, expected, hits) in runs() {
            let found = family_candidates(&hits, Bazaar::default());
            let first = found.first().map(|c| c.name.as_str());
            // Kaiten's sample matched only Tsunami rules.
            let wanted = if expected == "Kaiten" {
                "Tsunami"
            } else {
                &expected
            };
            assert_eq!(first, Some(wanted), "{run}: {found:?}");
            for fragment in [
                "MassHunt",
                "IoT",
                "BASE",
                "Unique",
                "Stackstrings",
                "Hunt",
                "Lnx",
                "Sekoia",
                "Eset",
                "Mirai_ohshit",
            ] {
                assert!(
                    !found.iter().any(|c| c.name.eq_ignore_ascii_case(fragment)),
                    "{run}: {fragment} in {found:?}"
                );
            }
        }
    }

    #[test]
    fn vendors_and_actors_are_no_family_and_a_meta_gives_its_token() {
        let pack = "selection/pack/yara-forge-core/x.yar";
        for (rule, family) in [
            ("SEKOIA_Backdoor_Lin_Bpfdoor", Some("BPFDoor")),
            ("ESET_Ebury_V1_7_Crypto", Some("Ebury")),
            (
                "SIGNATURE_BASE_APT_MAL_LNX_Redmenshen_Bpfdoor_Controller_May22_1",
                Some("BPFDoor"),
            ),
            ("DITEKSHEN_MALWARE_Linux_Foobar", Some("Foobar")),
            ("GCTI_Linux_Generic", None),
            ("ELASTIC_LNX_Generic", None),
        ] {
            let found = family_candidates(
                &[hit("YARA", rule, "indicator", "", pack)],
                Bazaar::default(),
            );
            assert_eq!(
                found.first().map(|c| c.name.as_str()),
                family,
                "{rule}: {found:?}"
            );
        }
        assert_eq!(meta_family("MIRAI_OHSHIT"), "Mirai");
        assert_eq!(meta_family("elf.mirai"), "Mirai");
        assert_eq!(meta_family("win.cobalt_strike"), "Cobalt");
    }

    #[test]
    fn many_rules_for_one_family_outrank_one_rule_for_another() {
        let (_, _, hits) = runs().into_iter().find(|r| r.0 == "f47a73d4").unwrap();
        let found = family_candidates(&hits, Bazaar::default());
        assert_eq!(found[0].name, "Gafgyt");
        assert!(found[0].source.contains("Elastic") && found[0].source.contains("more"));
        let order = names(&found);
        assert!(
            order.contains(&"Mirai") && order.contains(&"Torii"),
            "{order:?}"
        );
    }

    #[test]
    fn elastic_names_give_the_family_and_generic_ones_none() {
        for (rule, family) in [
            ("Linux_Trojan_Tsunami_30c039e2", Some("Tsunami")),
            ("s1919::Multi_Trojan_Merlin_32643f4c", Some("Merlin")),
            ("Linux_Cryptominer_Xmrig_ab12cd34", Some("XMRig")),
            ("Linux_Ransomware_Hello_ab12cd34", Some("Hello")),
            ("Linux_Hacktool_Flooder_ab12cd34", Some("Flooder")),
            ("Linux_Generic_Threat_80aea077", None),
            ("Windows_Generic_Threat_820fe9c9", None),
            ("Linux_Exploit_CVE_2021_3156_ab12cd34", None),
            ("ELF_IoT_Persistence_Hunt", None),
        ] {
            assert_eq!(
                elastic_family(plain_name(rule)).as_deref(),
                family,
                "{rule}"
            );
        }
    }

    #[test]
    fn explicit_family_meta_outranks_name_fragments() {
        let found = family_candidates(
            &[
                hit(
                    "YARA",
                    "Fragmentname_Dropper_rule",
                    "indicator",
                    "",
                    "yara-forge-core",
                ),
                hit("YARA", "r", "indicator", "elf.mirai", "Malpedia"),
            ],
            Bazaar::default(),
        );
        assert_eq!(names(&found), ["Mirai", "Fragmentname"], "{found:?}");
        assert!(found[0].source.contains("meta"));
    }

    #[test]
    fn community_fragments_are_dropped_beside_a_strong_family_and_kept_alone() {
        let community = hit(
            "YARA",
            "ELF_Foobar_Dropper",
            "indicator",
            "",
            "abuse-ch-yarahub/x.yar",
        );
        let alone = family_candidates(std::slice::from_ref(&community), Bazaar::default());
        assert_eq!(names(&alone), ["Foobar"]);
        let beside = family_candidates(
            &[
                community,
                hit(
                    "YARA",
                    "Linux_Trojan_Mirai_b9a9d04b",
                    "100",
                    "",
                    "elastic-protections-yara/x.yar",
                ),
            ],
            Bazaar::default(),
        );
        assert_eq!(names(&beside), ["Mirai"]);
    }

    #[test]
    fn bazaar_signature_and_tags_both_become_candidates() {
        let tags = [
            "elf".to_owned(),
            "Mirai".into(),
            "Prometei".into(),
            "x86_64".into(),
            "upx".into(),
        ];
        let found = family_candidates(
            &[],
            Bazaar {
                signature: Some("Mirai"),
                tags: &tags,
                ..Bazaar::default()
            },
        );
        assert_eq!(names(&found), ["Mirai", "Prometei"], "{found:?}");
        assert_eq!(found[0].source, "MalwareBazaar signature");
        assert_eq!(found[1].source, "MalwareBazaar tag");
        let other = family_candidates(
            &[],
            Bazaar {
                signature: Some("Gafgyt"),
                tags: &["Mirai".to_owned()],
                ..Bazaar::default()
            },
        );
        assert_eq!(names(&other), ["Gafgyt", "Mirai"]);
        assert_eq!(other[0].source, "MalwareBazaar signature");
        assert_eq!(other[1].source, "MalwareBazaar tag");
    }

    #[test]
    fn a_looked_up_signature_says_how_it_was_found_and_ranks_the_same() {
        let tags = ["P2PInfect".to_owned()];
        let record = |looked_up| Bazaar {
            signature: Some("P2PInfect"),
            tags: &tags,
            looked_up,
        };
        let plain = family_candidates(&[], record(false));
        let looked = family_candidates(&[], record(true));
        assert_eq!(looked.len(), plain.len());
        assert_eq!(looked[0].name, "P2PInfect");
        assert_eq!(looked[0].points, plain[0].points);
        assert_eq!(
            looked[0].source,
            "MalwareBazaar signature (looked up by hash)"
        );
        assert_eq!(plain[0].source, "MalwareBazaar signature");
    }

    #[test]
    fn a_family_named_only_in_the_unpacked_payload_says_so() {
        let mut in_layer = hit("YARA", "Linux_Trojan_Gafgyt_6a510422", "80", "", "Elastic");
        in_layer.layer = true;
        let found = family_candidates(&[in_layer], Bazaar::default());
        assert_eq!(names(&found), ["Gafgyt"]);
        assert!(
            found[0].source.ends_with("(in the unpacked payload)"),
            "{found:?}"
        );
        let on_file = hit("YARA", "Linux_Trojan_Gafgyt_6a510422", "80", "", "Elastic");
        let found = family_candidates(&[on_file], Bazaar::default());
        assert!(!found[0].source.contains("unpacked"));
    }

    #[test]
    fn ids_names_give_a_family_once_whatever_the_case() {
        let found = family_candidates(
            &[
                hit("IDS", "1", "", "", ""),
                hit("YARA", "r", "indicator", "gafgyt", "x"),
            ],
            Bazaar::default(),
        );
        assert_eq!(names(&found), ["Gafgyt"]);
        let mut ids = hit("IDS", "1", "1", "", "");
        ids.title = "ET MALWARE Gafgyt Botnet CnC Checkin".into();
        let found = family_candidates(&[ids], Bazaar::default());
        assert_eq!(names(&found), ["Gafgyt"]);
        assert!(found[0].source.starts_with("IDS"));
        assert!(family_candidates(&[], Bazaar::default()).is_empty());
    }

    fn ids(title: &str, family: &str) -> DetectionHit {
        let mut found = hit("IDS", "1:2044667:1", "1", family, "Suricata");
        found.title = title.into();
        found
    }

    #[test]
    fn kaiji_is_named_by_the_ids_message_or_metadata() {
        // T0432: the ARM Kaiji runs had only this signature and a generic
        // Elastic rule; the family stayed unnamed.
        let generic = hit(
            "YARA",
            "s86::Linux_Generic_Threat_a40aaa96",
            "50",
            "",
            "elastic",
        );
        let title = "ET MALWARE Golang/Linux Kaiji Variant Activity";
        let found = family_candidates(&[generic.clone(), ids(title, "")], Bazaar::default());
        assert_eq!(names(&found), ["Kaiji"]);
        assert!(found[0].source.starts_with("IDS message"), "{found:?}");
        assert!(!found[0].strong);
        // The signature's own metadata is stronger than its message.
        let found = family_candidates(&[ids(title, "Kaiji")], Bazaar::default());
        assert_eq!(names(&found), ["Kaiji"]);
        assert!(
            found[0]
                .source
                .starts_with("IDS metadata malware_family Kaiji")
        );
        assert_eq!(found[0].points, IDS_META_POINTS);
    }

    #[test]
    fn ids_messages_name_a_family_only_when_sure() {
        for (title, want) in [
            ("ET MALWARE Gafgyt Botnet CnC Checkin", Some("Gafgyt")),
            ("ET MALWARE Linux/Mirai Variant CnC Activity", Some("Mirai")),
            (
                "ET MALWARE Linux/Tsunami Backdoor Activity",
                Some("Tsunami"),
            ),
            ("ET MALWARE Sliver Implant Checkin", Some("Sliver")),
            ("ET MALWARE Observed DNS Query to Known CnC Domain", None),
            ("ET MALWARE Suspicious User-Agent", None),
            ("ET MALWARE Win32/Agent.ABC Checkin", None),
            ("ET MALWARE Windows Evil Thing Activity", None),
            ("ET MALWARE Two Unknown Words Activity", None),
            (
                "ET DROP Spamhaus DROP Listed Traffic Inbound group 31",
                None,
            ),
            ("ET MALWARE", None),
        ] {
            assert_eq!(ids_message_family(title).as_deref(), want, "{title}");
        }
    }

    #[test]
    fn ids_weights_sit_between_strong_and_weak_yara() {
        let elastic = {
            let mut rule = hit(
                "YARA",
                "s1::Linux_Trojan_Mirai_b9a9d04b",
                "100",
                "",
                "elastic",
            );
            rule.title = rule.rule_id.clone();
            rule
        };
        let pack = hit("YARA", "MAL_ELF_Kaiten_Jan2020", "", "", "forge");
        let found = family_candidates(
            &[
                pack,
                ids("ET MALWARE Golang/Linux Kaiji Variant Activity", ""),
                ids("ET MALWARE Gafgyt Botnet CnC Checkin", "Gafgyt"),
                elastic,
            ],
            Bazaar::default(),
        );
        // Strong Elastic first, IDS metadata, IDS message, then the weak pack.
        assert_eq!(names(&found), ["Mirai", "Gafgyt", "Kaiji", "Kaiten"]);
    }

    #[test]
    fn a_known_broad_gafgyt_rule_names_mirai_and_a_specific_rule_wins() {
        // T0432: the ARM Mirai build matched only Linux_Trojan_Gafgyt_28a2fe0c.
        let broad = hit(
            "YARA",
            "s171::Linux_Trojan_Gafgyt_28a2fe0c",
            "100",
            "",
            "elastic",
        );
        let found = family_candidates(std::slice::from_ref(&broad), Bazaar::default());
        assert_eq!(names(&found), ["Mirai", "Gafgyt"]);
        assert!(found.iter().all(|c| !c.strong && c.points <= 26));
        assert!(found[0].source.contains("known broad"), "{found:?}");
        let (primary, _) = primary_families(&found);
        assert_eq!(primary.len(), 2);
        // A specific Mirai rule outranks it ...
        let mirai = hit(
            "YARA",
            "s197::Linux_Trojan_Mirai_b9a9d04b",
            "100",
            "",
            "elastic",
        );
        let found = family_candidates(&[broad.clone(), mirai], Bazaar::default());
        assert_eq!(found[0].name, "Mirai");
        assert!(found[0].strong);
        // ... and so does a specific Gafgyt one.
        let gafgyt = hit(
            "YARA",
            "s171::Linux_Trojan_Gafgyt_6a510422",
            "100",
            "",
            "elastic",
        );
        let found = family_candidates(&[broad, gafgyt], Bazaar::default());
        assert_eq!(found[0].name, "Gafgyt");
        assert!(found[0].strong);
        // The rule's own family column still says what its name says.
        let one = hit("YARA", "Linux_Trojan_Gafgyt_28a2fe0c", "100", "", "elastic");
        assert_eq!(rule_family(&one).as_deref(), Some("Mirai"));
    }

    #[test]
    fn the_gafgyt_sample_with_mirai_and_gafgyt_rules_keeps_both() {
        // T0432 / report 6389: two Gafgyt rules and a Mirai one.
        let hits = [
            hit(
                "YARA",
                "s171::Linux_Trojan_Gafgyt_6a510422",
                "100",
                "",
                "elastic",
            ),
            hit(
                "YARA",
                "s171::Linux_Trojan_Gafgyt_d2953f92",
                "100",
                "",
                "elastic",
            ),
            hit(
                "YARA",
                "s197::Linux_Trojan_Mirai_b9a9d04b",
                "100",
                "",
                "elastic",
            ),
            hit(
                "YARA",
                "s86::Linux_Generic_Threat_d2dca9e7",
                "50",
                "",
                "elastic",
            ),
        ];
        let found = family_candidates(&hits, Bazaar::default());
        assert_eq!(names(&found), ["Gafgyt", "Mirai"]);
    }

    #[test]
    fn a_static_scan_match_with_no_pack_names_an_elastic_family() {
        // Tsunami ARM32 and Kinsing never ran: the sample page has only the
        // static scan's matches, which carry the rule name and no pack.
        let hits = [
            hit("YARA", "Linux_Trojan_Tsunami_30c039e2", "", "", ""),
            hit("YARA", "Linux_Trojan_Tsunami_a2a2d9f3", "", "", ""),
            hit("YARA", "Linux_Trojan_Kinsing_3d4c1e0f", "", "", ""),
            hit("YARA", "ELF_IoT_Persistence_Hunt", "", "", ""),
            hit("YARA", "Some_Unknown_Rule_12345678", "", "", ""),
        ];
        let found = family_candidates(&hits, Bazaar::default());
        assert_eq!(names(&found), ["Tsunami", "Kinsing"]);
        assert!(found.iter().all(|c| c.strong));
        assert!(
            found[0]
                .source
                .contains("Elastic rule Linux_Trojan_Tsunami")
        );
    }

    #[test]
    fn merlin_has_one_strong_match_and_twelve_weak_ones() {
        let (_, _, hits) = runs().into_iter().find(|r| r.0 == "6d58d777").unwrap();
        let hits: Vec<&DetectionHit> = hits.iter().filter(|h| h.engine == "YARA").collect();
        let strong: Vec<&str> = hits
            .iter()
            .filter(|h| strength(&h.rule_id, &h.severity, &h.source, &h.family) == Strength::Strong)
            .map(|h| plain_name(&h.rule_id))
            .collect();
        assert_eq!(strong, ["Multi_Trojan_Merlin_32643f4c"]);
        assert_eq!(hits.len() - strong.len(), 12, "all other matches are weak");
    }

    #[test]
    fn strength_follows_score_family_pack_and_platform() {
        let s = |rule: &str, sev: &str, src: &str, fam: &str| strength(rule, sev, src, fam);
        assert_eq!(
            s(
                "Linux_Trojan_Gafgyt_a6a2adb9",
                "100",
                "elastic-protections-yara/y",
                ""
            ),
            Strength::Strong
        );
        assert_eq!(
            s(
                "Linux_Generic_Threat_80aea077",
                "50",
                "elastic-protections-yara/y",
                ""
            ),
            Strength::Weak
        );
        assert_eq!(
            s("Windows_Generic_Threat_820fe9c9", "50", "elastic", ""),
            Strength::WrongPlatform
        );
        assert_eq!(
            s("Windows_Trojan_Foo_abcd1234", "100", "elastic", ""),
            Strength::WrongPlatform
        );
        assert_eq!(
            s(
                "ELF_Toriilike_persist",
                "indicator",
                "abuse-ch-yarahub/x",
                "Torii"
            ),
            Strength::Strong
        );
        assert_eq!(
            s("ELF_Mirai", "indicator", "abuse-ch-yarahub/x", ""),
            Strength::Weak
        );
        assert_eq!(
            s("RANSOMWARE", "indicator", "yara-forge-core", ""),
            Strength::Weak
        );
        assert_eq!(
            s("test_Malaysia", "indicator", "abuse-ch-yarahub/x", ""),
            Strength::Weak
        );
        assert_eq!(
            s(
                "SUSP_HTML_XMLHTTP_Redirect_Kit",
                "indicator",
                "abuse-ch-yarahub/x",
                ""
            ),
            Strength::WrongPlatform
        );
        assert_eq!(
            s("SCRIPT_Dropper_Unknown_Script", "indicator", "yarahub", ""),
            Strength::WrongPlatform
        );
        assert_eq!(
            s(
                "SIGNATURE_BASE_EXT_HKTL_MAL_Tinyshell_Backdoor",
                "indicator",
                "selection/pack/yara-forge-core/signature-base.yar",
                ""
            ),
            Strength::Strong
        );
        assert_eq!(
            s(
                "LIN_Shell_Script_Dropper",
                "indicator",
                "yara-forge-core",
                ""
            ),
            Strength::Strong
        );
    }
}
