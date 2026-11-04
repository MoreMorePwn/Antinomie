// SPDX-License-Identifier: GPL-3.0-only
//! The choice of Antinomie's own copy of a tool the system has too (Library >
//! Analysis tools, Tools > App dependencies). Settings keeps it; the UI hands
//! it over every frame, and the analysis worker gets it through
//! `OWN_TOOLS_ENV`.
use std::collections::BTreeSet;
use std::sync::Mutex;

/// The tools whose Antinomie-installed copy is used even though the system has
/// one (Settings keeps the choice; the UI hands it over every frame).
static OWN_TOOLS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// The environment variable that carries the choice into the analysis worker:
/// the tool ids, comma separated.
pub const OWN_TOOLS_ENV: &str = "ANTINOMIE_OWN_TOOLS";

/// Use Antinomie's own copy of these tools instead of the system's.
pub fn set_own_tools(ids: &BTreeSet<String>) {
    if let Ok(mut own) = OWN_TOOLS.lock()
        && *own != *ids
    {
        *own = ids.clone();
    }
}

/// The tools set to Antinomie's own copy, as the worker is told.
pub fn own_tools_env() -> Option<String> {
    let own = OWN_TOOLS.lock().ok()?;
    (!own.is_empty()).then(|| own.iter().cloned().collect::<Vec<_>>().join(","))
}

/// Whether the copy Antinomie installed of `id` comes before the system's:
/// chosen in Settings (here, or in the worker through `OWN_TOOLS_ENV`), or
/// every tool through the older `ANTINOMIE_ANALYSIS_TOOLS=managed`.
pub fn prefers_own(id: &str) -> bool {
    if std::env::var("ANTINOMIE_ANALYSIS_TOOLS").as_deref() == Ok("managed") {
        return true;
    }
    if std::env::var(OWN_TOOLS_ENV).is_ok_and(|list| list.split(',').any(|item| item == id)) {
        return true;
    }
    OWN_TOOLS.lock().is_ok_and(|own| own.contains(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tool_set_to_its_own_copy_is_preferred_and_the_others_are_not() {
        set_own_tools(&BTreeSet::from(["capa".to_owned(), "tor".to_owned()]));
        assert!(prefers_own("capa") && prefers_own("tor"));
        assert!(!prefers_own("floss"));
        assert_eq!(own_tools_env().as_deref(), Some("capa,tor"));
        set_own_tools(&BTreeSet::new());
        assert!(!prefers_own("capa"));
        assert_eq!(own_tools_env(), None);
    }
}
