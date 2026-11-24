// SPDX-License-Identifier: GPL-3.0-only
//! What the live trace keeps between frames: the paired calls of the live
//! buffer, and the rows of the table as indexes into them.
use super::*;

/// The calls the table shows: the shared list of the trace and the indexes of
/// the rows the filter, the hidden categories and the sort keep, in order.
pub(super) struct ShownRows {
    pub(super) all: Arc<Vec<InvocationSummary>>,
    pub(super) order: Vec<usize>,
}

impl ShownRows {
    pub(super) fn len(&self) -> usize {
        self.order.len()
    }

    pub(super) fn get(&self, index: usize) -> Option<&InvocationSummary> {
        self.order.get(index).and_then(|&row| self.all.get(row))
    }
}

/// One call of the list and where it is in it, for sorting rows in place of
/// copies of them.
pub(super) struct Row<'a>(pub(super) usize, pub(super) &'a InvocationSummary);

impl std::borrow::Borrow<InvocationSummary> for Row<'_> {
    fn borrow(&self) -> &InvocationSummary {
        self.1
    }
}

/// What the pairing of the live buffer depends on. The events are compared by
/// a fingerprint of the fields that make a call (its identity, sequence,
/// phase, result and completeness), computed in a pass over the buffer that
/// costs a few microseconds where pairing costs milliseconds.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct PairKey {
    pub(super) events: u64,
    pub(super) process: Option<u32>,
    /// `None`: no run selected. `Some(None)`: the run is not in the list.
    pub(super) run_cookie: Option<Option<u64>>,
}

impl PairKey {
    pub(super) fn fingerprint(events: &[antinomie_monitor_core::EventSummary]) -> u64 {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64 ^ events.len() as u64;
        let mut mix = |value: u64| {
            hash = (hash ^ value).wrapping_mul(0x0000_0100_0000_01b3);
            hash ^= hash >> 29;
        };
        for event in events {
            mix(event.stream_id);
            mix(event.task_cookie);
            mix(event.call_id);
            mix(event.event_seq);
            mix(event.timestamp_ns);
            mix(event.root_task_cookie);
            mix(u64::from(event.pid) << 8 | u64::from(event.phase));
            mix(event.result.map_or(u64::MAX, |result| result as u64));
            mix(u64::from(event.complete) | (event.issues.len() as u64) << 1);
            mix(event.fields.len() as u64);
        }
        hash
    }
}

/// The last pairing of the live buffer, with the key it was made for.
#[derive(Default)]
pub(super) struct PairCache(std::sync::Mutex<Option<(PairKey, Arc<Vec<InvocationSummary>>)>>);

impl PairCache {
    pub(super) fn get(&self, key: &PairKey) -> Option<Arc<Vec<InvocationSummary>>> {
        let kept = self.0.lock().unwrap_or_else(|e| e.into_inner());
        kept.as_ref()
            .filter(|(known, _)| known == key)
            .map(|(_, pairs)| Arc::clone(pairs))
    }

    pub(super) fn put(&self, key: PairKey, pairs: Arc<Vec<InvocationSummary>>) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some((key, pairs));
    }
}
