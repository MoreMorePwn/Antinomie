// SPDX-License-Identifier: MIT
//! What the debugger panel remembers between sessions and app restarts: the
//! signal table and the fork policy. They live in the app's saved settings, and
//! reading them never fails: a missing, empty, damaged or newer-than-known entry
//! gives gdb's defaults for that part only.
use antinomie_monitor_core::debug::{
    signal_policy::SignalTable,
    view::{FollowMode, ForkPolicy},
};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct DebuggerPrefs {
    /// Only the signals that differ from gdb's defaults.
    #[serde(deserialize_with = "lenient")]
    pub signals: SignalTable,
    /// `off`, `parent`, `child` or `ask`.
    #[serde(deserialize_with = "lenient_follow")]
    pub follow: String,
    #[serde(deserialize_with = "lenient_detach")]
    pub detach_other: bool,
}

impl Default for DebuggerPrefs {
    fn default() -> Self {
        let policy = ForkPolicy::default();
        Self {
            signals: SignalTable::default(),
            follow: follow_key(policy.follow).into(),
            detach_other: policy.detach_other,
        }
    }
}

impl DebuggerPrefs {
    pub fn fork_policy(&self) -> ForkPolicy {
        ForkPolicy {
            follow: follow_from_key(&self.follow),
            detach_other: self.detach_other,
        }
    }

    pub fn remember_policy(&mut self, policy: ForkPolicy) {
        self.follow = follow_key(policy.follow).into();
        self.detach_other = policy.detach_other;
    }

    /// The table with entries for signals that do not exist dropped.
    pub fn clean(mut self) -> Self {
        self.signals = self.signals.sanitized();
        self
    }
}

fn follow_key(mode: FollowMode) -> &'static str {
    match mode {
        FollowMode::Off => "off",
        FollowMode::Parent => "parent",
        FollowMode::Child => "child",
        FollowMode::Ask => "ask",
    }
}

/// An unknown word (from a newer version) is the default mode.
fn follow_from_key(key: &str) -> FollowMode {
    match key {
        "off" => FollowMode::Off,
        "child" => FollowMode::Child,
        "ask" => FollowMode::Ask,
        _ => FollowMode::Parent,
    }
}

/// A value that does not read as `T` becomes `T`'s default instead of failing
/// the whole settings file.
pub(crate) fn lenient<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned + Default,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(serde_json::from_value(value).unwrap_or_default())
}

fn lenient_follow<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let text: String = lenient(deserializer)?;
    Ok(if text.is_empty() {
        DebuggerPrefs::default().follow
    } else {
        text
    })
}

fn lenient_detach<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(value
        .as_bool()
        .unwrap_or(ForkPolicy::default().detach_other))
}

/// The whole entry, leniently: damage anywhere in it gives the defaults.
pub(crate) fn lenient_prefs<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<DebuggerPrefs, D::Error> {
    lenient::<D, DebuggerPrefs>(deserializer).map(DebuggerPrefs::clean)
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::debug::signal_policy::SignalAction;

    fn read(text: &str) -> DebuggerPrefs {
        #[derive(Deserialize)]
        struct Holder {
            #[serde(default, deserialize_with = "lenient_prefs")]
            debugger: DebuggerPrefs,
        }
        serde_json::from_str::<Holder>(text).unwrap().debugger
    }

    #[test]
    fn a_saved_choice_round_trips() {
        let mut prefs = DebuggerPrefs::default();
        prefs.signals.set(11, SignalAction::QUIET_PASS);
        prefs.remember_policy(ForkPolicy {
            follow: FollowMode::Ask,
            detach_other: false,
        });
        let text = serde_json::json!({ "debugger": prefs }).to_string();
        let back = read(&text);
        assert_eq!(back, prefs);
        assert_eq!(back.fork_policy().follow, FollowMode::Ask);
        assert!(!back.fork_policy().detach_other);
        assert_eq!(back.signals.action(11), SignalAction::QUIET_PASS);
    }

    #[test]
    fn missing_empty_or_damaged_gives_gdb_defaults() {
        for text in [
            "{}",
            r#"{"debugger":null}"#,
            r#"{"debugger":{}}"#,
            r#"{"debugger":"junk"}"#,
            r#"{"debugger":{"signals":42,"follow":7,"detach_other":"yes"}}"#,
        ] {
            let prefs = read(text);
            assert_eq!(prefs, DebuggerPrefs::default(), "{text}");
            assert!(prefs.signals.is_default());
            assert_eq!(prefs.fork_policy(), ForkPolicy::default());
        }
    }

    #[test]
    fn a_newer_file_keeps_what_it_can() {
        let prefs = read(
            r#"{"debugger":{"follow":"both","detach_other":false,"future":1,
            "signals":{"changed":{"11":{"stop":false,"print":false,"pass":true},
            "200":{"stop":true,"print":true,"pass":true},
            "17":{"stop":false,"print":false,"pass":true}}}}}"#,
        );
        assert_eq!(prefs.fork_policy().follow, FollowMode::Parent);
        assert!(!prefs.fork_policy().detach_other);
        assert_eq!(prefs.signals.changes().count(), 1, "only SIGSEGV differs");
    }
}
