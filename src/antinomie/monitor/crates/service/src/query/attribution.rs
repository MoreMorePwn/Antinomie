// SPDX-License-Identifier: GPL-3.0-only
//! What made each packet (`made_by` of `recording.network.packets`): the run's
//! network calls matched to the capture's flows by Triage's `net_attr`, the
//! same matching the Network tab shows. The calls are read from the recording
//! without writing anything (`SavedRun::net_attribution`), so the first read of
//! a run is heavy; the result is kept per run folder and generation. The one
//! difference from the tab: the base image's apt traffic is told only by the
//! program that made it, since the capture's DNS answers are not read here.

use super::{cursor::Generation, scrub::Scrub, service::Opened, service::QueryService, types::*};
use antinomie_monitor_core::network::{NetworkPacket, Transport};
use antinomie_triage::net_attr::{NetAttribution, Source};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// Attributions kept, newest last.
const KEPT: usize = 4;

/// The last few attributions, by run folder and generation.
#[derive(Default)]
pub struct AttributionCache {
    entries: Vec<(PathBuf, Generation, Arc<NetAttribution>)>,
}

impl AttributionCache {
    fn get(&mut self, dir: &Path, generation: Generation) -> Option<Arc<NetAttribution>> {
        let at = self
            .entries
            .iter()
            .position(|(d, g, _)| d == dir && *g == generation)?;
        let entry = self.entries.remove(at);
        let found = Arc::clone(&entry.2);
        self.entries.push(entry);
        Some(found)
    }

    fn put(&mut self, dir: &Path, generation: Generation, found: Arc<NetAttribution>) {
        self.entries.retain(|(d, _, _)| d != dir);
        self.entries.push((dir.to_path_buf(), generation, found));
        if self.entries.len() > KEPT {
            self.entries.remove(0);
        }
    }
}

/// The `made_by` of one packet.
pub fn made_by(attribution: &NetAttribution, packet: &NetworkPacket, scrub: &Scrub) -> MadeBy {
    let source = match (packet.src_ip, packet.dst_ip, packet.transport) {
        (Some(from), Some(to), Some(transport)) => attribution.source_of_packet(
            matches!(transport, Transport::Udp),
            [
                (from, packet.src_port.unwrap_or(0)),
                (to, packet.dst_port.unwrap_or(0)),
            ],
            packet.time_us,
        ),
        // Frames with no ports (ICMP, ARP) are named by no call.
        _ => Source::Unattributed,
    };
    let (kind, first) = match &source {
        Source::Process(callers) => (MadeByKind::Process, callers.first()),
        Source::Background { .. } => (MadeByKind::Background, None),
        Source::Unattributed => (MadeByKind::Unattributed, None),
    };
    MadeBy {
        kind,
        label: scrub.text(&source.label()),
        process: first.map(|caller| scrub.text(&caller.name)),
        pid: first.map(|caller| caller.pid),
        tid: first.map(|caller| caller.tid),
        also: match &source {
            Source::Process(callers) => callers
                .iter()
                .skip(1)
                .map(|caller| scrub.text(&caller.label()))
                .collect(),
            _ => Vec::new(),
        },
    }
}

impl QueryService {
    /// The run's network calls with the capture's DNS names, from a Triage
    /// index of the run; `None` when the run cannot be indexed (the packets
    /// then carry no `made_by`).
    pub(super) fn attribution(&self, opened: &Opened) -> Option<Arc<NetAttribution>> {
        if let Some(found) = self
            .attributions
            .lock()
            .ok()
            .and_then(|mut cache| cache.get(&opened.dir, opened.generation))
        {
            return Some(found);
        }
        let saved = antinomie_triage::SavedRun::open(opened.run.clone(), &self.options).ok()?;
        let cancel = Arc::new(AtomicBool::new(false));
        // Read from the recording itself: a Triage scan would write its
        // journals into the run's folder, which a read never does.
        let found = Arc::new(saved.net_attribution(&cancel).ok()?);
        if cancel.load(Ordering::Relaxed) {
            return None;
        }
        if let Ok(mut cache) = self.attributions.lock() {
            cache.put(&opened.dir, opened.generation, Arc::clone(&found));
        }
        Some(found)
    }
}
