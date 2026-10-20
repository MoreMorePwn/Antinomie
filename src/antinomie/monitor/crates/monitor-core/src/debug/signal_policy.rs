// SPDX-License-Identifier: MIT
//! What the in-app panel does when the program is about to receive a signal: gdb's
//! `handle` table, per signal, with gdb's own defaults. `stop` shows the signal as
//! a stop, `print` records it in the panel's signal log, `pass` gives it to the
//! program when it resumes (the table is for the panel; a gdb client keeps its own).
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One signal's handling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalAction {
    pub stop: bool,
    pub print: bool,
    pub pass: bool,
}
impl SignalAction {
    pub const STOP_PRINT_PASS: Self = Self {
        stop: true,
        print: true,
        pass: true,
    };
    pub const QUIET_PASS: Self = Self {
        stop: false,
        print: false,
        pass: true,
    };
    /// `stop print nopass`: the debugger's own kinds of signal.
    pub const STOP_PRINT_NOPASS: Self = Self {
        stop: true,
        print: true,
        pass: false,
    };
    /// The wording of gdb's `info signals` columns.
    pub fn label(self) -> String {
        let yes = |on: bool, word: &str| {
            if on {
                word.to_string()
            } else {
                format!("no{word}")
            }
        };
        format!(
            "{} {} {}",
            yes(self.stop, "stop"),
            yes(self.print, "print"),
            yes(self.pass, "pass")
        )
    }
}

/// The Linux signal numbers the table names, with their names.
const NAMES: [(u8, &str); 31] = [
    (1, "SIGHUP"),
    (2, "SIGINT"),
    (3, "SIGQUIT"),
    (4, "SIGILL"),
    (5, "SIGTRAP"),
    (6, "SIGABRT"),
    (7, "SIGBUS"),
    (8, "SIGFPE"),
    (9, "SIGKILL"),
    (10, "SIGUSR1"),
    (11, "SIGSEGV"),
    (12, "SIGUSR2"),
    (13, "SIGPIPE"),
    (14, "SIGALRM"),
    (15, "SIGTERM"),
    (16, "SIGSTKFLT"),
    (17, "SIGCHLD"),
    (18, "SIGCONT"),
    (19, "SIGSTOP"),
    (20, "SIGTSTP"),
    (21, "SIGTTIN"),
    (22, "SIGTTOU"),
    (23, "SIGURG"),
    (24, "SIGXCPU"),
    (25, "SIGXFSZ"),
    (26, "SIGVTALRM"),
    (27, "SIGPROF"),
    (28, "SIGWINCH"),
    (29, "SIGIO"),
    (30, "SIGPWR"),
    (31, "SIGSYS"),
];

/// The name of a Linux signal number, `SIG34` style for real-time ones.
pub fn signal_name(number: u8) -> String {
    NAMES
        .iter()
        .find(|(candidate, _)| *candidate == number)
        .map(|(_, name)| (*name).to_string())
        .unwrap_or_else(|| format!("SIG{number}"))
}

/// Every signal number the table can name, in order.
pub fn all_signals() -> impl Iterator<Item = u8> {
    1..=64u8
}

/// gdb's defaults: signals that are not errors (timers, child status, window
/// size, urgent data, I/O) do not stop or print and are passed; SIGTRAP and
/// SIGINT are the debugger's own and are not passed; the rest stop, print, pass.
pub fn default_action(number: u8) -> SignalAction {
    match number {
        // SIGALRM, SIGCHLD, SIGURG, SIGVTALRM, SIGPROF, SIGWINCH, SIGIO
        14 | 17 | 23 | 26 | 27 | 28 | 29 => SignalAction::QUIET_PASS,
        // SIGINT, SIGTRAP
        2 | 5 => SignalAction::STOP_PRINT_NOPASS,
        _ => SignalAction::STOP_PRINT_PASS,
    }
}

/// The user's table: only what differs from the defaults is kept, so a new
/// default in a later version reaches everyone who never changed that signal.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalTable {
    changed: BTreeMap<u8, SignalAction>,
}

impl SignalTable {
    pub fn action(&self, number: u8) -> SignalAction {
        self.changed
            .get(&number)
            .copied()
            .unwrap_or_else(|| default_action(number))
    }
    /// Set one signal; setting its default again forgets the change.
    pub fn set(&mut self, number: u8, action: SignalAction) {
        if !(1..=64).contains(&number) {
            return;
        }
        if action == default_action(number) {
            self.changed.remove(&number);
        } else {
            self.changed.insert(number, action);
        }
    }
    /// Back to gdb's defaults.
    pub fn reset(&mut self) {
        self.changed.clear();
    }
    pub fn is_default(&self) -> bool {
        self.changed.is_empty()
    }
    /// The signals that differ from the defaults.
    pub fn changes(&self) -> impl Iterator<Item = (u8, SignalAction)> + '_ {
        self.changed
            .iter()
            .map(|(number, action)| (*number, *action))
    }
    /// A table read from storage: entries for signals that do not exist are
    /// dropped, the rest kept.
    pub fn sanitized(mut self) -> Self {
        self.changed.retain(|number, action| {
            (1..=64).contains(number) && *action != default_action(*number)
        });
        self
    }
}

/// One line of the panel's signal log: a signal the table let through without a
/// stop (`print` set), or one that stopped the program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalNote {
    pub tid: u32,
    pub number: u8,
    pub passed: bool,
    pub stopped: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_gdbs() {
        for name in [
            "SIGCHLD",
            "SIGWINCH",
            "SIGALRM",
            "SIGPROF",
            "SIGURG",
            "SIGVTALRM",
            "SIGIO",
        ] {
            let number = NAMES.iter().find(|(_, n)| *n == name).unwrap().0;
            assert_eq!(
                default_action(number),
                SignalAction::QUIET_PASS,
                "{name} is nostop noprint pass"
            );
            assert_eq!(default_action(number).label(), "nostop noprint pass");
        }
        assert_eq!(default_action(11).label(), "stop print pass", "SIGSEGV");
        assert_eq!(default_action(5).label(), "stop print nopass", "SIGTRAP");
        assert_eq!(default_action(2).label(), "stop print nopass", "SIGINT");
        assert_eq!(
            default_action(40),
            SignalAction::STOP_PRINT_PASS,
            "real time"
        );
    }

    #[test]
    fn only_changes_are_kept_and_a_default_forgets_one() {
        let mut table = SignalTable::default();
        assert!(table.is_default());
        table.set(
            10,
            SignalAction {
                stop: false,
                print: true,
                pass: true,
            },
        );
        assert_eq!(table.action(10).label(), "nostop print pass");
        assert_eq!(table.action(11), SignalAction::STOP_PRINT_PASS);
        assert_eq!(table.changes().count(), 1);
        table.set(10, default_action(10));
        assert!(table.is_default());
        table.set(99, SignalAction::QUIET_PASS);
        assert!(
            table.is_default(),
            "a signal that does not exist is ignored"
        );
        table.set(11, SignalAction::QUIET_PASS);
        table.reset();
        assert!(table.is_default());
    }

    #[test]
    fn a_stored_table_round_trips_and_is_cleaned() {
        let mut table = SignalTable::default();
        table.set(11, SignalAction::QUIET_PASS);
        let text = serde_json::to_string(&table).unwrap();
        let back: SignalTable = serde_json::from_str(&text).unwrap();
        assert_eq!(back, table);
        let dirty: SignalTable = serde_json::from_str(
            r#"{"changed":{"17":{"stop":false,"print":false,"pass":true},"200":{"stop":true,"print":true,"pass":true},"11":{"stop":false,"print":false,"pass":true}}}"#,
        )
        .unwrap();
        let clean = dirty.sanitized();
        assert_eq!(
            clean, table,
            "the default and the impossible entry are dropped"
        );
        assert_eq!(signal_name(17), "SIGCHLD");
        assert_eq!(signal_name(34), "SIG34");
    }
}
