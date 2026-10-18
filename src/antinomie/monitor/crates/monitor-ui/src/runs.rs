//! Presentation state for independent native program terminals.
use crate::terminal::Terminal;
use antinomie_monitor_core::{RunState, RunSummary};
use std::time::Instant;

pub(crate) struct RunTerminal {
    pub(crate) run: RunSummary,
    pub(crate) terminal: Terminal,
    pub(crate) open: bool,
    pub(crate) generation: u64,
    pub(crate) replay_offset: Option<u64>,
    pub(crate) replay_pending: bool,
    pub(crate) replay_error: Option<String>,
    pub(crate) sequence: u64,
    pub(crate) dirty: bool,
    pub(crate) snapshot_request: Option<u64>,
    pub(crate) snapshot_error: Option<String>,
    pub(crate) snapshot_started: Option<Instant>,
    /// When this view last painted. Replay keeps going while the tab is on
    /// screen even if `open` was cleared, and while it is hidden if still open.
    pub(crate) last_paint: Option<Instant>,
}

impl RunTerminal {
    pub(crate) fn new(run: RunSummary) -> Self {
        Self {
            run,
            terminal: Terminal::default(),
            open: true,
            generation: 0,
            replay_offset: None,
            replay_pending: false,
            replay_error: None,
            sequence: 0,
            dirty: false,
            snapshot_request: None,
            snapshot_error: None,
            snapshot_started: None,
            last_paint: None,
        }
    }

    pub(crate) fn close_view(&mut self) {
        self.open = false;
    }

    pub(crate) fn begin_replay(&mut self) {
        self.terminal = Terminal::default();
        self.generation = self.generation.wrapping_add(1);
        self.replay_offset = Some(0);
        self.replay_pending = false;
        self.replay_error = None;
        self.dirty = false;
        self.snapshot_request = None;
        self.snapshot_started = None;
        self.snapshot_error = None;
    }

    pub(crate) fn output(&mut self, sequence: u64, data: &[u8], eof: bool) {
        if sequence <= self.sequence {
            return;
        }
        if sequence != self.sequence.saturating_add(1) {
            self.dirty = true;
        }
        self.sequence = sequence;
        self.terminal.process(data);
        self.run.terminal_eof = eof;
    }

    pub(crate) fn screen(&mut self, sequence: u64, rows: u16, cols: u16, data: &[u8]) {
        if sequence < self.sequence {
            return;
        }
        self.terminal.replace_screen(rows, cols, data);
        self.sequence = sequence;
        self.dirty = false;
        self.snapshot_request = None;
        self.snapshot_started = None;
        self.snapshot_error = None;
    }

    pub(crate) fn interactive(&self) -> bool {
        !self.run.terminal_eof
            && matches!(self.run.state, RunState::Running | RunState::StopRequested)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::ExecRequest;

    #[test]
    fn closing_one_terminal_preserves_the_run_and_other_windows() {
        let run = RunSummary {
            started_ms: None,
            clock_anchor: None,
            id: "one".into(),
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            session_id: 1,
            root_task_cookie: 1,
            pid: 2,
            request: ExecRequest::default(),
            directory: "run".into(),
            terminal_eof: false,
            state: RunState::Running,
            notes: Vec::new(),
            recording_error: None,
            execution: None,
            analysis: None,
        };
        let mut first = RunTerminal::new(run.clone());
        let second = RunTerminal::new(run);
        first.close_view();
        assert!(!first.open);
        assert_eq!(first.run.state, RunState::Running);
        assert!(first.interactive() && second.open);
        first.open = true;
        assert!(first.interactive());
    }

    #[test]
    fn sequence_gap_resync_replaces_state_and_discards_old_packets() {
        let run = RunSummary {
            started_ms: None,
            clock_anchor: None,
            id: "one".into(),
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            session_id: 1,
            root_task_cookie: 1,
            pid: 2,
            request: ExecRequest::default(),
            directory: "run".into(),
            terminal_eof: false,
            state: RunState::Running,
            notes: Vec::new(),
            recording_error: None,
            execution: None,
            analysis: None,
        };
        let mut terminal = RunTerminal::new(run);
        terminal.output(1, b"before", false);
        terminal.close_view();
        terminal.output(3, b"gap", false);
        assert!(terminal.dirty);
        assert!(terminal.terminal.contents().contains("beforegap"));
        terminal.snapshot_request = Some(4);
        terminal.screen(3, 24, 80, b"restored");
        assert!(!terminal.dirty);
        assert_eq!(terminal.snapshot_request, None);
        assert_eq!(terminal.terminal.contents(), "restored");
        terminal.output(2, b"stale", false);
        terminal.output(3, b"duplicate", false);
        assert_eq!(terminal.terminal.contents(), "restored");
        terminal.output(4, b"!", false);
        assert_eq!(terminal.terminal.contents(), "restored!");
        terminal.screen(2, 24, 80, b"old snapshot");
        assert_eq!(terminal.terminal.contents(), "restored!");
    }
}
