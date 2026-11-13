// SPDX-License-Identifier: GPL-3.0-only
//! Who a custody entry names as its actor (`by`).
//!
//! The GUI writes `app` (what the program did) or `analyst` (what a person
//! did to a guest). Headless mode gives every entry a run causes the actor
//! that caused the run: `auto:preset-<name>` for a watch folder or a preset,
//! `web:<user>` for a web caller, `local:<uid>` for the command line (design
//! 4.11, card P3-7).
//!
//! Entries are written by library calls (which take the actor explicitly) and
//! by an engine's own thread (the run log, the push record), which cannot be
//! handed one per call. For those each engine has its own [`ActorSlot`]
//! (`Backend::set_custody_actor`): `app` until its front end sets another. A
//! daemon runs one engine per lane and each lane one job at a time (decided
//! D4), so the slot of a lane's engine names that lane's job, whatever the
//! other lanes run. There is no process-wide actor.

use std::sync::RwLock;

/// The actor of everything the program does on its own.
pub const APP: &str = "app";
/// The actor of what a person does to a running guest.
pub const ANALYST: &str = "analyst";
/// The longest actor text the log keeps.
pub const MAX_ACTOR: usize = 128;

/// Whether `actor` is a name the log accepts: `app`, `analyst`, or one of
/// `auto:preset-<name>`, `web:<user>`, `local:<uid>` with a non-empty rest of
/// printable characters.
pub fn is_valid(actor: &str) -> bool {
    if actor.is_empty() || actor.len() > MAX_ACTOR || actor.chars().any(char::is_control) {
        return false;
    }
    if actor == APP || actor == ANALYST {
        return true;
    }
    let rest = |prefix: &str| {
        actor
            .strip_prefix(prefix)
            .filter(|rest| !rest.trim().is_empty())
    };
    if let Some(uid) = rest("local:") {
        return uid.bytes().all(|b| b.is_ascii_digit());
    }
    rest("auto:preset-").is_some() || rest("web:").is_some()
}

/// A slot holding the current actor of one engine.
pub struct ActorSlot(RwLock<Option<String>>);

impl ActorSlot {
    pub const fn new() -> Self {
        Self(RwLock::new(None))
    }

    /// Set the actor, or `None` to go back to `app`. An invalid name is
    /// refused and nothing changes.
    pub fn set(&self, actor: Option<&str>) -> Result<(), String> {
        if let Some(actor) = actor
            && !is_valid(actor)
        {
            return Err(format!("{actor:?} is not a custody actor"));
        }
        *self.0.write().unwrap_or_else(|p| p.into_inner()) = actor.map(str::to_owned);
        Ok(())
    }

    /// The actor set, or `app`.
    pub fn get(&self) -> String {
        self.0
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .unwrap_or_else(|| APP.to_owned())
    }
}

impl Default for ActorSlot {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_names_the_log_accepts() {
        for good in [
            "app",
            "analyst",
            "local:1000",
            "auto:preset-default",
            "web:alice",
            "web:a b",
        ] {
            assert!(is_valid(good), "{good}");
        }
        for bad in [
            "",
            "root",
            "local:",
            "local:abc",
            "auto:preset-",
            "web:",
            "web:  ",
            "a\nb",
            "local:1\n",
        ] {
            assert!(!is_valid(bad), "{bad:?}");
        }
        assert!(!is_valid(&format!("web:{}", "x".repeat(200))));
    }

    #[test]
    fn a_slot_defaults_to_app_and_refuses_bad_names() {
        let slot = ActorSlot::new();
        assert_eq!(slot.get(), "app");
        slot.set(Some("auto:preset-ci")).unwrap();
        assert_eq!(slot.get(), "auto:preset-ci");
        assert!(slot.set(Some("nobody")).is_err());
        assert_eq!(slot.get(), "auto:preset-ci");
        slot.set(None).unwrap();
        assert_eq!(slot.get(), "app");
    }
}
