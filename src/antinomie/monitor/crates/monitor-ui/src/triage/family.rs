// SPDX-License-Identifier: GPL-3.0-only
//! Which malware family a run's detections name, and how much a YARA match
//! says. Family candidates come first from rules that name a family on
//! purpose (an Elastic `Linux_Trojan_<Family>_<hash>` rule, a `family` meta,
//! Malpedia, the sample's MalwareBazaar record), and only then from fragments
//! of other rule names. Several rules naming one family raise it.
use antinomie_monitor_core::run_digest::DetectionHit;
use std::collections::BTreeMap;

/// A malware family a detection names, with where it said so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub name: String,
    pub source: String,
}

/// What MalwareBazaar says of the run's sample: its `signature` and `tags`.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Bazaar<'a> {
    pub signature: Option<&'a str>,
    pub tags: &'a [String],
}

/// Fragments of rule names that never are a family, kept in this one place:
/// hunting and test rules (`TH_Generic_MassHunt_Linux_Malware`,
/// `ELF_IoT_Persistence_Hunt`, `LIN_Sample_Unique_<hash>`, `meth_stackstrings`,
/// `test_Malaysia`), the bare category `RANSOMWARE`, and pack prefixes. A
/// candidate is never taken from one of these, and a rule whose name carries
/// one is a generic match.
pub(crate) const GENERIC_FRAGMENTS: &[&str] = &[
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
pub(crate) fn plain_name(rule: &str) -> &str {
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
pub(crate) enum Strength {
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
pub(crate) fn is_generic_rule(rule: &str) -> bool {
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
pub(crate) fn wrong_platform(rule: &str) -> bool {
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
pub(crate) fn strength(rule: &str, severity: &str, source: &str, family: &str) -> Strength {
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
pub(crate) fn bazaar_families(
    signature: Option<&str>,
    tags: &[String],
) -> Vec<(String, &'static str)> {
    let mut out: Vec<(String, &'static str)> = Vec::new();
    let add = |name: String, source: &'static str, out: &mut Vec<(String, &'static str)>| {
        if !out
            .iter()
            .any(|(known, _)| known.eq_ignore_ascii_case(&name))
        {
            out.push((name, source));
        }
    };
    if let Some(signature) = signature.map(str::trim).filter(|s| !s.is_empty()) {
        if !not_family(&signature.to_ascii_lowercase()) {
            add(pretty(signature), "MalwareBazaar signature", &mut out);
        }
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
pub(crate) fn family_candidates(hits: &[DetectionHit], bazaar: Bazaar<'_>) -> Vec<Candidate> {
    let mut mentions: Vec<Mention> = Vec::new();
    let yara = |hit: &&DetectionHit| hit.engine.eq_ignore_ascii_case("yara");
    for hit in hits.iter().filter(yara) {
        let name = plain_name(&hit.rule_id);
        let name = if name.is_empty() {
            plain_name(&hit.title)
        } else {
            name
        };
        if !hit.family.is_empty() {
            let family = meta_family(&hit.family);
            if !not_family(&family.to_ascii_lowercase()) {
                mentions.push(Mention {
                    name: family,
                    points: 90,
                    strong: true,
                    source: format!("YARA \u{b7} {} meta {}", hit.source, hit.family),
                });
                continue;
            }
        }
        if is_elastic(&hit.source) {
            if let Some(family) = elastic_family(name) {
                mentions.push(Mention {
                    name: family,
                    points: score(&hit.severity).unwrap_or(60).min(100),
                    strong: true,
                    source: format!("YARA \u{b7} Elastic rule {name}"),
                });
            }
        } else if curated_pack(&hit.source) && !wrong_platform(name) && !is_generic_rule(name) {
            if let Some(family) = family_in_rule_name(name) {
                let malpedia = hit.source.to_ascii_lowercase().contains("malpedia");
                mentions.push(Mention {
                    name: family,
                    points: if malpedia { 70 } else { 20 },
                    strong: malpedia,
                    source: format!("YARA \u{b7} {} rule {name}", hit.source),
                });
            }
        }
    }
    for hit in hits
        .iter()
        .filter(|hit| hit.engine.eq_ignore_ascii_case("ids"))
    {
        let title = hit.title.to_ascii_lowercase();
        if let Some(word) = IDS_FAMILIES.iter().find(|family| title.contains(**family)) {
            mentions.push(Mention {
                name: pretty(word),
                points: 30,
                strong: false,
                source: format!("IDS \u{b7} {}", hit.title),
            });
        }
    }
    for (name, source) in bazaar_families(bazaar.signature, bazaar.tags) {
        mentions.push(Mention {
            name,
            points: if source.ends_with("signature") {
                85
            } else {
                60
            },
            strong: true,
            source: source.into(),
        });
    }
    merge(mentions)
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
            },
        );
        assert_eq!(names(&other), ["Gafgyt", "Mirai"]);
        assert_eq!(other[0].source, "MalwareBazaar signature");
        assert_eq!(other[1].source, "MalwareBazaar tag");
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
