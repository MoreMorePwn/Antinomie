// SPDX-License-Identifier: MIT
//! One nonblocking, correlated recorder statistics query per sampling interval.
use super::*;

const INTERVAL: Duration = Duration::from_secs(2);

#[derive(Default)]
pub(super) struct RecorderPoll {
    sent_at: Option<Instant>,
    pending: Option<(u64, Instant)>,
    late: VecDeque<(u64, Instant)>,
    applied_at: Option<Instant>,
}

impl RecorderPoll {
    pub(super) fn observe(&mut self, sent_at: Instant, counters: [u64; 10], health: &mut Health) {
        if self.applied_at.is_none_or(|applied| applied <= sent_at) {
            self.applied_at = Some(sent_at);
            health.recorder_stats = Some(counters);
            health.recorder_stats_error = None;
        }
    }

    fn due(&mut self, now: Instant, health: &mut Health) -> bool {
        if let Some((id, at)) = self.pending {
            if now.duration_since(at) >= INTERVAL {
                health.recorder_stats_error = Some(
                    "recorder statistics reply is overdue; retrying the read-only query".into(),
                );
                self.pending = None;
                if self.late.len() == 32 {
                    self.late.pop_front();
                }
                self.late.push_back((id, at));
            }
            return false;
        }
        self.sent_at
            .is_none_or(|at| now.duration_since(at) >= INTERVAL)
    }

    pub(super) fn reply(
        &mut self,
        id: u64,
        status: i32,
        payload: &[u8],
        health: &mut Health,
    ) -> bool {
        let sent_at = if self.pending.is_some_and(|(pending, _)| pending == id) {
            self.pending.take().map(|(_, at)| at)
        } else {
            self.late
                .iter()
                .position(|(pending, _)| *pending == id)
                .and_then(|index| self.late.remove(index))
                .map(|(_, at)| at)
        };
        let Some(sent_at) = sent_at else { return false };
        // Consume recognized old replies without replacing a newer observation/error.
        if self.applied_at.is_some_and(|applied| applied > sent_at) {
            return true;
        }
        let result = if status == 0 {
            decode_stats(payload)
        } else {
            Err(format!(
                "recorder statistics command failed with status {status}"
            ))
        };
        match result {
            Ok(counters) => {
                self.observe(sent_at, counters, health);
            }
            Err(error) => {
                self.applied_at = Some(sent_at);
                health.recorder_stats_error = Some(error);
            }
        }
        true
    }
}

impl Session {
    pub(super) fn poll_recorder_health(&mut self, snapshot: &mut Snapshot) {
        let now = Instant::now();
        if !self.recorder_poll.due(now, &mut snapshot.health) {
            return;
        }
        self.recorder_poll.sent_at = Some(now);
        match self.transport.send(control::STATS, &control::header(0)) {
            Ok(id) => self.recorder_poll.pending = Some((id, now)),
            Err(error) => {
                snapshot.health.recorder_stats_error =
                    Some(format!("recorder statistics request unavailable: {error}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stats_poll_keeps_late_reply_ownership_and_preserves_failure_evidence() {
        let now = Instant::now();
        let mut poll = RecorderPoll::default();
        let mut health = Health::default();
        assert!(poll.due(now, &mut health));
        poll.sent_at = Some(now);
        poll.pending = Some((7, now));
        assert!(!poll.due(now + INTERVAL, &mut health));
        assert!(health.recorder_stats_error.is_some());
        assert!(!poll.reply(8, 0, &[0; 80], &mut health));
        let mut payload = [0; 80];
        payload[48..56].copy_from_slice(&3209u64.to_le_bytes());
        assert!(poll.reply(7, 0, &payload, &mut health));
        assert_eq!(health.recorder_stats.unwrap()[6], 3209);
        assert!(health.recorder_stats_error.is_none());
        assert!(poll.due(now + INTERVAL, &mut health));
        poll.pending = Some((9, now + INTERVAL));
        poll.sent_at = Some(now + INTERVAL);
        assert!(poll.reply(9, 0, &[0; 3], &mut health));
        assert_eq!(health.recorder_stats.unwrap()[6], 3209);
        assert!(health.recorder_stats_error.is_some());
        assert!(!poll.due(now + INTERVAL, &mut health));
        assert!(poll.due(now + INTERVAL * 2, &mut health));
        let mut new_boot = RecorderPoll::default();
        assert!(!new_boot.reply(9, 0, &payload, &mut health));
    }

    #[test]
    fn retry_after_a_lost_stats_reply_is_bounded_and_old_replies_cannot_rewind_counters() {
        let now = Instant::now();
        let mut poll = RecorderPoll::default();
        let mut health = Health::default();
        for id in 1..=40 {
            let at = now + INTERVAL * id as u32;
            poll.sent_at = Some(at);
            poll.pending = Some((id, at));
            assert!(!poll.due(at + INTERVAL, &mut health));
            assert!(poll.due(at + INTERVAL, &mut health));
            assert!(poll.late.len() <= 32);
        }
        let newest = now + INTERVAL * 41;
        poll.pending = Some((41, newest));
        let mut payload = [0; 80];
        payload[48..56].copy_from_slice(&9u64.to_le_bytes());
        assert!(poll.reply(41, 0, &payload, &mut health));
        assert!(poll.reply(40, 0, &[0; 80], &mut health));
        assert_eq!(health.recorder_stats.unwrap()[6], 9);
        assert!(health.recorder_stats_error.is_none());
        let mut manual = [0; 10];
        manual[6] = 12;
        poll.observe(newest + Duration::from_secs(1), manual, &mut health);
        assert!(poll.reply(39, 0, &[0; 80], &mut health));
        assert_eq!(health.recorder_stats.unwrap()[6], 12);
    }
}
