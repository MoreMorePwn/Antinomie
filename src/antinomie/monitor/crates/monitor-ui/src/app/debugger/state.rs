// SPDX-License-Identifier: MIT
//! The debugger panel's own state and how it talks to the backend: a request
//! carries an id and the stop it was made for; the backend's view says which
//! request it has handled, so the panel knows what is still in flight and shows
//! only data that belongs to the stop on screen.
use super::*;
use antinomie_monitor_core::{
    debug::view::{DebugRequest, WindowKind},
    decode_window, DecodedInstruction,
};
use std::{collections::BTreeMap, sync::Arc};

/// Instructions shown before the current one, and in all.
pub(super) const CODE_BEFORE_COUNT: usize = 6;
pub(super) const CODE_COUNT: usize = 40;
/// Requests whose backend command ids are remembered to learn of a refusal.
const INFLIGHT_LIMIT: usize = 64;

/// Decoded lines for one code window, kept until the window changes.
pub(super) struct CodeCache {
    pub key: (u32, u64, usize),
    pub lines: Vec<DecodedInstruction>,
}

#[derive(Default)]
pub(crate) struct DebuggerPanel {
    next_id: u64,
    /// Highest request id sent to the backend.
    last_sent: u64,
    /// Backend command id -> request id, to clear the spinner of a refusal.
    inflight: BTreeMap<u64, u64>,
    pub(super) breakpoint_input: String,
    pub(super) memory_input: String,
    /// Local problem with an input (the backend reports its own in the view).
    pub(super) input_error: Option<String>,
    pub(super) code: Option<CodeCache>,
    /// The last view epoch seen, to reset on a new session.
    seen_session: Option<u64>,
    /// A session began and the remembered choices are not yet sent.
    announce: bool,
    /// The fork prompt's "Let the other process run" is off.
    pub(super) prompt_hold_other: bool,
    /// The gdb console pane; gdb ends with the session.
    pub(crate) console: super::console::Console,
}

impl DebuggerPanel {
    pub(crate) fn waiting(&self, view: &DebugView) -> bool {
        self.last_sent > view.handled
    }

    /// A different session (or none) than the last frame's: forget the old one.
    pub(crate) fn track_session(&mut self, session: Option<u64>) {
        if self.seen_session != session {
            *self = Self::default();
            self.seen_session = session;
            self.announce = session.is_some();
        }
    }

    /// Whether the remembered choices are still to be sent; true once per session.
    pub(crate) fn take_announce(&mut self) -> bool {
        std::mem::take(&mut self.announce)
    }

    /// The decoded window for the code pane, decoding only when it changed.
    pub(super) fn disassembly(&mut self, view: &DebugView) -> &[DecodedInstruction] {
        let window = view.window(WindowKind::Code);
        let pc = view
            .registers
            .as_ref()
            .and_then(|registers| registers.get("rip"));
        let (Some(window), Some(pc)) = (window, pc) else {
            self.code = None;
            return &[];
        };
        let key = (window.sequence, window.address, window.bytes.len());
        if self.code.as_ref().is_none_or(|cache| cache.key != key) {
            self.code = Some(CodeCache {
                key,
                lines: decode_window(
                    window.address,
                    &window.bytes,
                    pc,
                    CODE_BEFORE_COUNT,
                    CODE_COUNT,
                ),
            });
        }
        self.code.as_ref().map_or(&[], |cache| &cache.lines)
    }

    /// A command result for a request: a refused one is not in flight any more.
    pub(crate) fn command_result(&mut self, id: u64, success: bool) {
        if let Some(request) = self.inflight.remove(&id) {
            if !success && request == self.last_sent {
                self.last_sent = request.saturating_sub(1);
            }
        }
    }

    /// The view moved on: forget requests it has handled.
    pub(super) fn prune(&mut self, view: &DebugView) {
        self.inflight.retain(|_, request| *request > view.handled);
    }
}

/// A hexadecimal address, with or without `0x`; underscores are ignored.
pub(super) fn parse_address(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text)
        .replace('_', "");
    if digits.is_empty() {
        return Err("Enter an address in hexadecimal.".into());
    }
    u64::from_str_radix(&digits, 16)
        .map_err(|_| format!("\"{text}\" is not a hexadecimal address."))
}

impl MonitorApp {
    /// The panel view of the backend, if a session has published one.
    pub(crate) fn debug_view(&self) -> Option<Arc<DebugView>> {
        self.snapshot.debug_view.clone()
    }

    #[cfg(test)]
    pub(crate) fn debugger_input_for_tests(&mut self, breakpoint: &str, memory: &str) {
        self.debugger.breakpoint_input = breakpoint.into();
        self.debugger.memory_input = memory.into();
    }

    /// Send one request for the stop on screen.
    pub(crate) fn debug_action(&mut self, view: &DebugView, action: DebugAction) {
        self.debug_request(view, action, true);
    }

    /// Send one request nobody waits for (the remembered choices at the start
    /// of a session): the panel stays usable while it is handled.
    pub(super) fn debug_action_quiet(&mut self, view: &DebugView, action: DebugAction) {
        self.debug_request(view, action, false);
    }

    fn debug_request(&mut self, view: &DebugView, action: DebugAction, track: bool) {
        let panel = &mut self.debugger;
        panel.next_id += 1;
        let id = panel.next_id;
        let request = DebugRequest {
            id,
            sequence: view.run.stopped_sequence().unwrap_or(0),
            action,
        };
        if panel.inflight.len() >= INFLIGHT_LIMIT {
            panel.inflight.clear();
        }
        if let Some(command) = self.send_request(Command::DebugUi(request)) {
            if track {
                self.debugger.inflight.insert(command, id);
                self.debugger.last_sent = id;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_parse_with_or_without_a_prefix() {
        assert_eq!(parse_address("0x401136"), Ok(0x401136));
        assert_eq!(parse_address("  401136 "), Ok(0x401136));
        assert_eq!(parse_address("0X7ffd_0000"), Ok(0x7ffd_0000));
        assert!(parse_address("").unwrap_err().contains("Enter"));
        assert!(parse_address("0x").unwrap_err().contains("Enter"));
        assert!(parse_address("main")
            .unwrap_err()
            .contains("not a hexadecimal"));
        assert!(parse_address("0x1_0000_0000_0000_0000").is_err());
    }
}
