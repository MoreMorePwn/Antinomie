// SPDX-License-Identifier: GPL-3.0-only
//! What the scan reads from the run's own records besides the calls: the
//! launch's hash, how a program that died before its first call ended, and
//! why a run has no capture.
use super::*;

/// The guest's SHA-256 of the launched program's image, from the launch's own
/// hash record: none for a script's interpreter or a file that changed while
/// it was read.
pub(crate) fn launch_sha256(
    launch: &antinomie_monitor_core::recording::LaunchRecord,
) -> Option<String> {
    use antinomie_monitor_core::kernel_notes::{self, HashKind};
    launch
        .notes
        .iter()
        .filter_map(kernel_notes::file_hash)
        .find(|hash| hash.kind == HashKind::Exec)
        .filter(|hash| hash.skipped().is_none())
        .and_then(|hash| hash.sha256_hex())
}

/// A program that died of a signal before its first recorded call has a
/// process row without an exit record: show the run's own end instead of
/// "running", the signal for the program and "ended with the run" for the
/// rest.
pub(crate) fn settle_crashed_start(process: &mut [ProcessNode], directory: &Path) {
    let Some(status) = root_exit_status(directory) else {
        return;
    };
    for node in process
        .iter_mut()
        .filter(|node| !node.thread && !node.state.starts_with("task exit"))
        .filter(|node| node.in_call.is_none())
    {
        if node.parent.is_none() || node.parent_missing || node.depth == 0 {
            node.state = format!("task exit, {}", crate::values::task_end(&status));
            if let antinomie_monitor_core::WaitStatus::Signaled { signal, .. } = status {
                node.end_signal = Some(signal);
            }
        } else {
            node.state = "task exit, ended with the run".into();
        }
    }
}

/// Why a run has no packet capture when the run's own record says it was not
/// to have one: its VM had no network, or Capture network was off. `None`
/// when the record does not say (a capture that failed or went missing).
pub(crate) fn no_capture_note(directory: &Path) -> Option<String> {
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("run.json")).ok()?).ok()?;
    let no_network = matches!(
        run.pointer("/environment/network").and_then(|v| v.as_str()),
        Some("Disconnected" | "Isolated")
    );
    let capture_off = run
        .pointer("/request/capture_network")
        .and_then(|v| v.as_bool())
        == Some(false);
    let why = if no_network {
        "This VM has no network"
    } else if capture_off {
        "Network capture was off for this run"
    } else {
        return None;
    };
    let fix = if no_network {
        "Give the VM a route (for example InetSim) and keep Capture network on to scan network traffic."
    } else {
        "Turn on Capture network in Run program to scan network traffic."
    };
    Some(format!(
        "{why}, so no network capture was recorded and the network (Suricata) rules did not run. {fix}"
    ))
}
