// SPDX-License-Identifier: GPL-3.0-only
//! Who a custody entry names as its actor (`by`).
//!
//! The GUI writes `app` (what the program did) or `analyst` (what a person
//! did to a guest). Headless mode gives every entry a job causes the actor
//! that caused the job: `auto:policy-<name>` for a watch folder or a policy,
//! `web:<user>` for a web caller, `local:<uid>` for the command line (design
//! 4.11, card P3-7).
//!
//! Entries are written by library calls (which take the actor explicitly) and
//! by the engine's own threads (the run log, the push record), which cannot be
//! handed one per call. For those the process has one *current actor*. It is
//! `app` until a front end sets another. One lane runs one job at a time
//! (decided D4), so one slot is enough.

use std::sync::RwLock;

/// The actor of everything the program does on its own.
pub const APP: &str = "app";
/// The actor of what a person does to a running guest.
pub const ANALYST: &str = "analyst";
/// The longest actor text the log keeps.
pub const MAX_ACTOR: usize = 128;

/// Whether `actor` is a name the log accepts: `app`, `analyst`, or one of
/// `auto:policy-<name>`, `web:<user>`, `local:<uid>` with a non-empty rest of
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
    rest("auto:policy-").is_some() || rest("web:").is_some()
}

/// A slot holding the current actor.
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

static CURRENT: ActorSlot = ActorSlot::new();

/// Set the actor of this process's own custody entries (the run log, the push
/// record, library calls that take no actor). `None` restores `app`.
pub fn set_current(actor: Option<&str>) -> Result<(), String> {
    CURRENT.set(actor)
}

/// The actor of this process's own custody entries.
pub fn current() -> String {
    CURRENT.get()
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
            "auto:policy-default",
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
            "auto:policy-",
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
        slot.set(Some("auto:policy-ci")).unwrap();
        assert_eq!(slot.get(), "auto:policy-ci");
        assert!(slot.set(Some("nobody")).is_err());
        assert_eq!(slot.get(), "auto:policy-ci");
        slot.set(None).unwrap();
        assert_eq!(slot.get(), "app");
    }
}
