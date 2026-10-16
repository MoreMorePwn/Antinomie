// SPDX-License-Identifier: MIT
//! Pack requirements and how they are checked against installed tools.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequirementStatus {
    Satisfied,
    Incompatible(String),
    Malformed(String),
    Unknown(String),
    Pending(String),
}

impl std::fmt::Display for RequirementStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Satisfied => formatter.write_str("satisfied"),
            Self::Pending(text) => write!(formatter, "validation pending: {text}"),
            Self::Incompatible(text) => write!(formatter, "incompatible: {text}"),
            Self::Malformed(text) => write!(formatter, "malformed requirement: {text}"),
            Self::Unknown(text) => write!(formatter, "unknown requirement: {text}"),
        }
    }
}

/// The selected version's retained requirements and their status on this
/// host. The registry copy is used, else the version's own manifest; the live
/// catalog is never consulted, so editing or losing it changes nothing here.
/// Without a retained requirement the status is unknown and the pack is not
/// evaluated.
pub(super) fn requirement_of(
    data_dir: &Path,
    pack: &InstalledPack,
    facts: &ToolFacts,
) -> (String, String, RequirementStatus) {
    let (app, requirement) = if pack.engine_requirement.is_empty() {
        match retained_entry(data_dir, &pack.engine, &pack.id, &pack.version) {
            Ok(entry) if !entry.engine_requirement.is_empty() => {
                (entry.app, entry.engine_requirement)
            }
            _ => {
                return (
                    String::new(),
                    String::new(),
                    RequirementStatus::Unknown(format!(
                        "no requirement was retained for {} {}",
                        pack.id, pack.version
                    )),
                );
            }
        }
    } else {
        (pack.app.clone(), pack.engine_requirement.clone())
    };
    let status = classify_requirement(&app, &requirement, &pack.engine, facts);
    (app, requirement, status)
}

/// `app_req` is `>=1.2.3` or empty. `engine_req` is `Name 1.2` or `Name 2.x`.
/// A bare version is a minimum. `N.x` requires that major and does not accept another.
pub fn classify_requirement(
    app_req: &str,
    engine_req: &str,
    engine: &str,
    facts: &ToolFacts,
) -> RequirementStatus {
    if let Err(error) = check_bound(app_req, &facts.app, true) {
        return error;
    }
    let Some((name, spec)) = engine_req.split_once(' ') else {
        return RequirementStatus::Malformed(format!(
            "engine requirement {engine_req:?} has no version"
        ));
    };
    let known = match engine {
        "yara" => name == "YARA-X",
        "ids" => name == "Suricata",
        "sigma" => name == "pySigma",
        _ => false,
    };
    if !known {
        return RequirementStatus::Unknown(format!("unknown engine requirement {engine_req}"));
    }
    let probe = match engine {
        "yara" => None,
        "ids" => Some(&facts.suricata),
        "sigma" => Some(&facts.sigma),
        _ => return RequirementStatus::Unknown(format!("unknown engine {engine}")),
    };
    let installed = match probe {
        None => facts.yara.as_str(),
        Some(ToolProbe::Found { version, .. }) => version.as_str(),
        Some(ToolProbe::Absent(reason)) => {
            return RequirementStatus::Pending(format!("{reason}; the pack is not validated"));
        }
        Some(ToolProbe::Broken(reason)) => {
            return RequirementStatus::Incompatible(format!("{name} is unusable: {reason}"));
        }
        Some(ToolProbe::Unknown(reason)) => {
            return RequirementStatus::Unknown(format!("{name} version: {reason}"));
        }
    };
    let spec = spec.split_whitespace().next().unwrap_or(spec);
    if let Some(major) = spec.strip_suffix(".x") {
        let Ok(major) = major.parse::<u64>() else {
            return RequirementStatus::Malformed(format!("{spec:?} is not a major version"));
        };
        let Some((have, _, _)) = parse_version(installed) else {
            return RequirementStatus::Malformed(format!(
                "installed version {installed:?} is not numeric"
            ));
        };
        return if have == major {
            RequirementStatus::Satisfied
        } else {
            RequirementStatus::Incompatible(format!("{name} {installed} is not major {major}"))
        };
    }
    match check_bound(&format!(">={spec}"), installed, false) {
        Ok(()) => RequirementStatus::Satisfied,
        Err(status) => status,
    }
}

fn check_bound(
    requirement: &str,
    installed: &str,
    allow_empty: bool,
) -> Result<(), RequirementStatus> {
    let requirement = requirement.trim();
    if requirement.is_empty() {
        return if allow_empty {
            Ok(())
        } else {
            Err(RequirementStatus::Malformed("empty requirement".into()))
        };
    }
    let (op, raw) = if let Some(rest) = requirement.strip_prefix(">=") {
        (">=", rest)
    } else if let Some(rest) = requirement.strip_prefix("<=") {
        ("<=", rest)
    } else if let Some(rest) = requirement.strip_prefix('>') {
        (">", rest)
    } else if let Some(rest) = requirement.strip_prefix('<') {
        ("<", rest)
    } else if let Some(rest) = requirement.strip_prefix('=') {
        ("=", rest)
    } else {
        (">=", requirement)
    };
    let Some(need) = parse_version(raw.trim()) else {
        return Err(RequirementStatus::Malformed(format!(
            "version {raw:?} is not numeric"
        )));
    };
    let Some(have) = parse_version(installed) else {
        return Err(RequirementStatus::Malformed(format!(
            "installed version {installed:?} is not numeric"
        )));
    };
    let ok = match op {
        ">=" => have >= need,
        ">" => have > need,
        "<=" => have <= need,
        "<" => have < need,
        "=" => have == need,
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(RequirementStatus::Incompatible(format!(
            "{installed} does not satisfy {requirement}"
        )))
    }
}

fn parse_version(text: &str) -> Option<(u64, u64, u64)> {
    let start = text.find(|ch: char| ch.is_ascii_digit())?;
    let rest = &text[start..];
    let end = rest
        .find(|ch: char| !ch.is_ascii_digit() && ch != '.')
        .unwrap_or(rest.len());
    let mut numbers = rest[..end].split('.');
    let major = numbers.next()?.parse().ok()?;
    let minor = numbers.next().unwrap_or("0").parse().ok()?;
    let patch = numbers.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}
