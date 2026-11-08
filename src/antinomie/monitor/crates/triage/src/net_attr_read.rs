// SPDX-License-Identifier: GPL-3.0-only
//! The run's network calls read straight from its recording, for a reader
//! that must write nothing into the run's folder (the service's
//! `recording.network.packets`). It walks the calls the way the Triage scan
//! does, follows the sockets the calls open, and keeps only the network calls
//! [`rules::ioc::observe_net`] names; no finding, journal or file table is made.
use super::*;
use crate::segments::{run_segments, segment_facts, walk_segments};

/// The run's network calls with host times, from the saved calls of `directory`
/// (every reconnect segment, oldest first). Writes nothing.
pub fn read_calls(
    directory: &Path,
    request: &ScanRequest,
    cancel: &Arc<AtomicBool>,
) -> Result<net_attr::NetAttribution, String> {
    let directory = std::fs::canonicalize(directory).map_err(|error| error.to_string())?;
    let segments = run_segments(&directory, request);
    let recordings: Vec<_> = segments
        .iter()
        .map(|segment| antinomie_monitor_core::recording::Recording::raw(&segment.directory))
        .collect();
    let scoped = archive_scan::stages::in_scope(request);
    let started_ms = request.started_ms;
    let mut clock = request.clock_anchor;
    let mut cookie_sets = std::collections::BTreeMap::new();
    let mut nodes = std::collections::BTreeMap::new();
    walk_segments(&recordings, cancel, |_, page| {
        let page: Vec<_> = page.iter().filter(&scoped).cloned().collect();
        if clock.is_none() {
            clock = started_ms
                .zip(
                    page.iter()
                        .filter_map(trace::representative)
                        .map(|event| event.timestamp_ns)
                        .min(),
                )
                .and_then(|(host_ms, guest_ns)| {
                    Some(antinomie_monitor_core::HostClockAnchor {
                        guest_ns,
                        host_us: host_ms.checked_mul(1000)?,
                    })
                });
        }
        note_cookie_sets(&mut cookie_sets, &page);
        observe_processes(&mut nodes, &page);
        Ok(())
    })?;
    let cookies = resolve_cookies(&cookie_sets);
    let mut files = FdState {
        settled_parents: process_tree::settled_parents(&nodes),
        ..FdState::default()
    };
    let mut log = rules::ioc::Log::default();
    walk_segments(&recordings, cancel, |segment, page| {
        let directory = recordings[segment].directory.as_path();
        for call in page.iter().filter(&scoped) {
            observe_processes(&mut files.process_images, std::slice::from_ref(call));
            let Some(event) = trace::representative(call) else {
                continue;
            };
            let cx = rules::ctx::Ctx::new(call, event, &files, Some(directory), false);
            rules::ioc::observe_net(&cx, &mut log);
            remember_open(&mut files, call, event);
            apply_dup(&mut files, call, event);
            forget_closed(&mut files, call, event);
            inherit_open_fds(&mut files, call, event, &cookies);
            sigma_events::track(&mut files, call, event);
        }
        Ok(())
    })?;
    let ended_ms = segment_facts(&segments, request)
        .ok()
        .flatten()
        .and_then(|facts| facts.ended_ms);
    Ok(net_attr::NetAttribution::from_log(&log.net, clock).within(started_ms, ended_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_with_no_recording_is_an_error_and_nothing_is_created() {
        let dir =
            std::env::temp_dir().join(format!("antinomie-netattr-read-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let found = read_calls(&dir, &ScanRequest::default(), &cancel);
        // An empty folder holds no calls: either an error or no attribution,
        // and never a file.
        if let Ok(found) = found {
            assert!(found.is_empty());
        }
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
