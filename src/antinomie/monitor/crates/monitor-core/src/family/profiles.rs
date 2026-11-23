// SPDX-License-Identifier: GPL-3.0-only
//! Family profiles (ANT-T0604): data that names a malware family from what a
//! run did. A profile lists markers (a finding, a file path, a URL or domain,
//! a command line, a Sigma rule, a YARA tag) and a threshold ("at least 3
//! markers, at least 1 distinctive"). A profile whose threshold is met gives a
//! family candidate whose source lists the markers seen.
//!
//! The shipped profiles are `assets/rules/families/*.toml`, built into the
//! program. A user adds or replaces profiles with TOML files in
//! `<data>/rules/families/`; a user profile with the name of a shipped one
//! replaces it. The format is documented in `docs/family-profiles.md`.
use regex::Regex;
use serde::Deserialize;
use std::path::Path;

/// The shipped profile files, one per family.
const SHIPPED: &[(&str, &str)] = &[
    (
        "billgates.toml",
        include_str!("../../assets/rules/families/billgates.toml"),
    ),
    (
        "bpfdoor.toml",
        include_str!("../../assets/rules/families/bpfdoor.toml"),
    ),
    (
        "chaos.toml",
        include_str!("../../assets/rules/families/chaos.toml"),
    ),
    (
        "dofloo.toml",
        include_str!("../../assets/rules/families/dofloo.toml"),
    ),
    (
        "kaiji.toml",
        include_str!("../../assets/rules/families/kaiji.toml"),
    ),
    (
        "kinsing.toml",
        include_str!("../../assets/rules/families/kinsing.toml"),
    ),
    (
        "mettle.toml",
        include_str!("../../assets/rules/families/mettle.toml"),
    ),
    (
        "mirai.toml",
        include_str!("../../assets/rules/families/mirai.toml"),
    ),
    (
        "prometei.toml",
        include_str!("../../assets/rules/families/prometei.toml"),
    ),
    (
        "rotajakiro.toml",
        include_str!("../../assets/rules/families/rotajakiro.toml"),
    ),
    (
        "sliver.toml",
        include_str!("../../assets/rules/families/sliver.toml"),
    ),
    (
        "xmrig.toml",
        include_str!("../../assets/rules/families/xmrig.toml"),
    ),
    (
        "xorddos.toml",
        include_str!("../../assets/rules/families/xorddos.toml"),
    ),
    (
        "tsunami.toml",
        include_str!("../../assets/rules/families/tsunami.toml"),
    ),
    (
        "vpnfilter.toml",
        include_str!("../../assets/rules/families/vpnfilter.toml"),
    ),
];

/// The folder under the data directory that holds a user's own profiles.
pub const USER_DIR: &str = "rules/families";

/// Profile files larger than this are refused.
const MAX_FILE_BYTES: u64 = 256 * 1024;

/// Points a matched profile gives: a base and an amount per unit of matched
/// weight, capped. One distinctive marker of weight 4 gives 200, the points a
/// behaviour signature gave before profiles: what the run did outweighs one
/// or two rules that name another family (one strong rule is 90).
const BASE_POINTS: u32 = 100;
const POINTS_PER_WEIGHT: u32 = 25;
const MAX_POINTS: u32 = 300;

/// The most marker names a candidate's source lists before "+n more".
const LISTED: usize = 6;

/// One file of profiles as written: `[[profile]]` tables.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    profile: Vec<Written>,
}

/// A profile as written in TOML.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Written {
    name: String,
    #[serde(default = "linux")]
    platforms: Vec<String>,
    #[serde(default = "one")]
    min_markers: usize,
    #[serde(default = "one")]
    min_distinctive: usize,
    #[serde(default)]
    min_weight: u32,
    /// Public reports the markers come from.
    #[serde(default)]
    references: Vec<String>,
    #[serde(default, rename = "marker")]
    markers: Vec<WrittenMarker>,
}

fn linux() -> Vec<String> {
    vec!["linux".into()]
}

fn one() -> usize {
    1
}

fn weight_one() -> u32 {
    1
}

/// A marker as written: exactly one kind key, a weight and whether it is
/// distinctive.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WrittenMarker {
    finding: Option<String>,
    path: Option<String>,
    path_regex: Option<String>,
    url: Option<String>,
    url_regex: Option<String>,
    command: Option<String>,
    command_regex: Option<String>,
    sigma: Option<String>,
    yara_tag: Option<String>,
    yara_rule: Option<String>,
    #[serde(default = "weight_one")]
    weight: u32,
    #[serde(default)]
    distinctive: bool,
}

/// What a marker looks for.
#[derive(Clone, Debug)]
pub enum Kind {
    /// A behaviour finding's rule id, exactly (`evasion.watchdog_disable`).
    Finding(String),
    /// A file path the run touched that contains this text.
    Path(String),
    PathRegex(Regex),
    /// A URL, domain or endpoint the run contacted that contains this text
    /// (ASCII case ignored).
    Url(String),
    UrlRegex(Regex),
    /// A command line of a process of the run that contains this text.
    Command(String),
    CommandRegex(Regex),
    /// A Sigma rule's id that matched, exactly (case ignored).
    Sigma(String),
    /// A tag the run's YARA rules give (`Mirai-like`, `UPX`), case ignored.
    YaraTag(String),
    /// A YARA rule name that matched this pattern.
    YaraRule(Regex),
}

impl Kind {
    /// How the evidence names it: `path /usr/sbin/uplugplay`.
    pub fn label(&self) -> String {
        match self {
            Self::Finding(id) => id.clone(),
            Self::Path(text) => format!("path {text}"),
            Self::PathRegex(re) => format!("path ~ {re}"),
            Self::Url(text) => format!("URL {text}"),
            Self::UrlRegex(re) => format!("URL ~ {re}"),
            Self::Command(text) => format!("command {text}"),
            Self::CommandRegex(re) => format!("command ~ {re}"),
            Self::Sigma(id) => format!("Sigma {id}"),
            Self::YaraTag(tag) => format!("YARA tag {tag}"),
            Self::YaraRule(re) => format!("YARA rule ~ {re}"),
        }
    }
}

/// One marker of a profile.
#[derive(Clone, Debug)]
pub struct Marker {
    pub kind: Kind,
    pub weight: u32,
    pub distinctive: bool,
}

/// A checked profile, ready to match.
#[derive(Clone, Debug)]
pub struct Profile {
    pub name: String,
    pub platforms: Vec<String>,
    pub min_markers: usize,
    pub min_distinctive: usize,
    pub min_weight: u32,
    pub references: Vec<String>,
    pub markers: Vec<Marker>,
    /// Where it was loaded from: `shipped mirai.toml` or the user file.
    pub origin: String,
}

/// What a run did, as the profiles read it. Every list holds texts as the
/// report shows them; order does not matter.
#[derive(Clone, Debug, Default)]
pub struct Seen {
    /// The rule ids of the run's behaviour findings.
    pub findings: Vec<String>,
    /// File paths the run opened, read, wrote, created, executed or changed.
    pub paths: Vec<String>,
    /// URLs, domains and endpoints the run contacted.
    pub network: Vec<String>,
    /// Command lines of the run's processes.
    pub commands: Vec<String>,
}

impl Seen {
    /// Texts of unknown kind (the indicator values a caller had before
    /// profiles): each counts as a path, a URL and a command line.
    pub fn of_texts(texts: &[&str]) -> Self {
        let all: Vec<String> = texts.iter().map(|text| (*text).to_owned()).collect();
        Self {
            findings: Vec::new(),
            paths: all.clone(),
            network: all.clone(),
            commands: all,
        }
    }

    /// Each list sorted and without repeats, so that a long run's thousands
    /// of opens of one file are checked once.
    pub fn tidy(mut self) -> Self {
        for list in [
            &mut self.findings,
            &mut self.paths,
            &mut self.network,
            &mut self.commands,
        ] {
            list.retain(|text| !text.is_empty());
            list.sort_unstable();
            list.dedup();
        }
        self
    }
}

/// A profile whose threshold the run met.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Matched {
    pub family: String,
    pub points: u32,
    /// `behaviour profile Mirai · 4 of 7 markers: ...`.
    pub source: String,
}

fn checked(written: Written, origin: &str) -> Result<Profile, String> {
    let name = written.name.trim().to_owned();
    let at = |what: String| format!("{origin}: profile {name:?}: {what}");
    if name.is_empty() {
        return Err(format!("{origin}: a profile has no name"));
    }
    if written.markers.is_empty() {
        return Err(at("it has no marker".into()));
    }
    let mut markers = Vec::new();
    for (index, marker) in written.markers.into_iter().enumerate() {
        let number = index + 1;
        if marker.weight == 0 || marker.weight > 10 {
            return Err(at(format!("marker {number}: weight is 1 to 10")));
        }
        let regex =
            |text: &str| Regex::new(text).map_err(|error| at(format!("marker {number}: {error}")));
        let mut kinds = Vec::new();
        if let Some(id) = marker.finding {
            kinds.push(Kind::Finding(id));
        }
        if let Some(text) = marker.path {
            kinds.push(Kind::Path(text));
        }
        if let Some(text) = marker.path_regex {
            kinds.push(Kind::PathRegex(regex(&text)?));
        }
        if let Some(text) = marker.url {
            kinds.push(Kind::Url(text.to_ascii_lowercase()));
        }
        if let Some(text) = marker.url_regex {
            kinds.push(Kind::UrlRegex(regex(&text)?));
        }
        if let Some(text) = marker.command {
            kinds.push(Kind::Command(text));
        }
        if let Some(text) = marker.command_regex {
            kinds.push(Kind::CommandRegex(regex(&text)?));
        }
        if let Some(id) = marker.sigma {
            kinds.push(Kind::Sigma(id));
        }
        if let Some(tag) = marker.yara_tag {
            kinds.push(Kind::YaraTag(tag));
        }
        if let Some(text) = marker.yara_rule {
            kinds.push(Kind::YaraRule(regex(&text)?));
        }
        if kinds.len() != 1 {
            return Err(at(format!(
                "marker {number}: give exactly one of finding, path, path_regex, url, url_regex, command, command_regex, sigma, yara_tag, yara_rule"
            )));
        }
        let kind = kinds.remove(0);
        let empty = match &kind {
            Kind::Finding(text)
            | Kind::Path(text)
            | Kind::Url(text)
            | Kind::Command(text)
            | Kind::Sigma(text)
            | Kind::YaraTag(text) => text.trim().is_empty(),
            Kind::PathRegex(re)
            | Kind::UrlRegex(re)
            | Kind::CommandRegex(re)
            | Kind::YaraRule(re) => re.as_str().is_empty(),
        };
        if empty {
            return Err(at(format!("marker {number}: the value is empty")));
        }
        markers.push(Marker {
            kind,
            weight: marker.weight,
            distinctive: marker.distinctive,
        });
    }
    let distinctive = markers.iter().filter(|m| m.distinctive).count();
    // A family is never named on generic markers alone.
    if written.min_distinctive == 0 {
        return Err(at("min_distinctive is at least 1".into()));
    }
    if written.min_distinctive > distinctive {
        return Err(at(format!(
            "min_distinctive is {} but only {distinctive} marker(s) are distinctive",
            written.min_distinctive
        )));
    }
    if written.min_markers == 0 || written.min_markers > markers.len() {
        return Err(at(format!(
            "min_markers is 1 to the number of markers ({})",
            markers.len()
        )));
    }
    if written.min_markers < written.min_distinctive {
        return Err(at("min_markers is at least min_distinctive".into()));
    }
    Ok(Profile {
        name,
        platforms: written
            .platforms
            .iter()
            .map(|p| p.trim().to_ascii_lowercase())
            .collect(),
        min_markers: written.min_markers,
        min_distinctive: written.min_distinctive,
        min_weight: written.min_weight,
        references: written.references,
        markers,
        origin: origin.to_owned(),
    })
}

/// The profiles of one TOML text. `origin` names it in errors.
pub fn parse(text: &str, origin: &str) -> Result<Vec<Profile>, String> {
    let file: File = toml::from_str(text).map_err(|error| format!("{origin}: {error}"))?;
    file.profile
        .into_iter()
        .map(|written| checked(written, origin))
        .collect()
}

/// The shipped profiles. They are checked by the tests; one that does not
/// parse is left out.
pub fn shipped() -> Vec<Profile> {
    static PARSED: std::sync::OnceLock<Vec<Profile>> = std::sync::OnceLock::new();
    PARSED
        .get_or_init(|| {
            SHIPPED
                .iter()
                .flat_map(|(name, text)| {
                    parse(text, &format!("shipped {name}")).unwrap_or_default()
                })
                .collect()
        })
        .clone()
}

/// The shipped profiles and the user's own from `<data>/rules/families/*.toml`
/// (in name order), with a sentence for each user file that could not be
/// used. A user profile replaces a shipped or earlier one of the same name
/// (ASCII case ignored).
pub fn load(data_dir: Option<&Path>) -> (Vec<Profile>, Vec<String>) {
    let mut profiles = shipped();
    let mut problems = Vec::new();
    let Some(dir) = data_dir.map(|dir| dir.join(USER_DIR)) else {
        return (profiles, problems);
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return (profiles, problems);
    };
    let mut files: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    files.sort();
    for path in files {
        let origin = path.display().to_string();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(error) => {
                problems.push(format!("{origin}: {error}"));
                continue;
            }
        };
        if !meta.is_file() {
            problems.push(format!("{origin}: not a regular file"));
            continue;
        }
        if meta.len() > MAX_FILE_BYTES {
            problems.push(format!("{origin}: larger than {MAX_FILE_BYTES} bytes"));
            continue;
        }
        let parsed = std::fs::read_to_string(&path)
            .map_err(|error| format!("{origin}: {error}"))
            .and_then(|text| parse(&text, &origin));
        match parsed {
            Ok(list) => {
                for profile in list {
                    profiles.retain(|known| !known.name.eq_ignore_ascii_case(&profile.name));
                    profiles.push(profile);
                }
            }
            Err(problem) => problems.push(problem),
        }
    }
    (profiles, problems)
}

/// The detections a profile can read besides the run's behaviour: the Sigma
/// ids, the YARA rule names and the YARA tags.
#[derive(Clone, Debug, Default)]
pub struct Rules<'a> {
    pub sigma: Vec<&'a str>,
    pub yara: Vec<&'a str>,
    pub tags: Vec<String>,
}

fn holds(kind: &Kind, seen: &Seen, rules: &Rules<'_>) -> bool {
    match kind {
        Kind::Finding(id) => seen.findings.iter().any(|f| f == id),
        Kind::Path(text) => seen.paths.iter().any(|p| p.contains(text.as_str())),
        Kind::PathRegex(re) => seen.paths.iter().any(|p| re.is_match(p)),
        Kind::Url(text) => seen
            .network
            .iter()
            .any(|u| u.to_ascii_lowercase().contains(text.as_str())),
        Kind::UrlRegex(re) => seen.network.iter().any(|u| re.is_match(u)),
        Kind::Command(text) => seen.commands.iter().any(|c| c.contains(text.as_str())),
        Kind::CommandRegex(re) => seen.commands.iter().any(|c| re.is_match(c)),
        Kind::Sigma(id) => rules.sigma.iter().any(|s| s.eq_ignore_ascii_case(id)),
        Kind::YaraTag(tag) => rules.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)),
        Kind::YaraRule(re) => rules.yara.iter().any(|r| re.is_match(r)),
    }
}

impl Profile {
    /// Whether the profile is for programs of this platform.
    pub fn for_platform(&self, platform: &str) -> bool {
        self.platforms
            .iter()
            .any(|p| p == "any" || p.eq_ignore_ascii_case(platform))
    }

    /// The candidate this profile gives the run, when its threshold is met.
    pub fn matches(&self, seen: &Seen, rules: &Rules<'_>) -> Option<Matched> {
        let hit: Vec<&Marker> = self
            .markers
            .iter()
            .filter(|marker| holds(&marker.kind, seen, rules))
            .collect();
        let distinctive = hit.iter().filter(|m| m.distinctive).count();
        let weight: u32 = hit.iter().map(|m| m.weight).sum();
        if hit.len() < self.min_markers
            || distinctive < self.min_distinctive
            || weight < self.min_weight
        {
            return None;
        }
        // Distinctive markers first, then by weight, in the profile's order.
        let mut listed = hit.clone();
        listed.sort_by_key(|m| (!m.distinctive, std::cmp::Reverse(m.weight)));
        let mut names: Vec<String> = listed.iter().take(LISTED).map(|m| m.kind.label()).collect();
        if listed.len() > LISTED {
            names.push(format!("+{} more", listed.len() - LISTED));
        }
        Some(Matched {
            family: self.name.clone(),
            points: (BASE_POINTS + POINTS_PER_WEIGHT * weight).min(MAX_POINTS),
            source: format!(
                "behaviour profile {} \u{b7} {} of {} markers: {}",
                self.name,
                hit.len(),
                self.markers.len(),
                names.join(", ")
            ),
        })
    }
}

/// The profiles of `profiles` for a Linux program that the run matches.
pub fn matching(profiles: &[Profile], seen: &Seen, rules: &Rules<'_>) -> Vec<Matched> {
    profiles
        .iter()
        .filter(|profile| profile.for_platform("linux"))
        .filter_map(|profile| profile.matches(seen, rules))
        .collect()
}

#[cfg(test)]
#[path = "profiles_tests.rs"]
mod tests;
