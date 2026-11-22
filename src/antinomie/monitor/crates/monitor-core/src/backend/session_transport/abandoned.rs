// SPDX-License-Identifier: GPL-3.0-only
//! Requests whose wait ended in a timeout: their late replies are expected.
use std::collections::VecDeque;

/// How many timed-out request ids are remembered. A reply for an older one is
/// reported like any reply nobody asked for.
const KEPT: usize = 64;

/// The ids of commands that were given up on. The guest answers them anyway
/// when it gets to them; that is not a protocol fault.
#[derive(Default)]
pub(in crate::backend) struct AbandonedReplies(VecDeque<u64>);

impl AbandonedReplies {
    pub(in crate::backend) fn remember(&mut self, id: u64) {
        if self.0.len() == KEPT {
            self.0.pop_front();
        }
        self.0.push_back(id);
    }

    /// True once for an id that was given up on.
    pub(in crate::backend) fn take(&mut self, id: u64) -> bool {
        match self.0.iter().position(|&kept| kept == id) {
            Some(index) => {
                self.0.remove(index);
                true
            }
            None => false,
        }
    }
}

/// What `wait_reply` does for the rest of this pass when no reply is in.
#[derive(Debug, PartialEq)]
pub(super) enum IdleWait {
    /// Wait on the transport for up to this many milliseconds.
    Poll(i32),
    /// Sleep this many milliseconds: the transport reports telemetry that is
    /// not read while the recording writer is behind, so waiting on it would
    /// return at once and spin.
    Sleep(u64),
}

pub(super) fn idle_wait(writer_backlogged: bool, remaining_ms: u128) -> IdleWait {
    if writer_backlogged {
        IdleWait::Sleep(remaining_ms.clamp(1, 2) as u64)
    } else {
        IdleWait::Poll(remaining_ms.min(10) as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_given_up_reply_is_expected_once_and_old_ones_are_forgotten() {
        let mut abandoned = AbandonedReplies::default();
        abandoned.remember(7);
        assert!(abandoned.take(7));
        assert!(!abandoned.take(7));
        assert!(!abandoned.take(8));
        for id in 0..(KEPT as u64 + 1) {
            abandoned.remember(100 + id);
        }
        assert!(!abandoned.take(100));
        assert!(abandoned.take(101));
    }

    #[test]
    fn a_backlogged_writer_makes_the_wait_sleep_instead_of_poll() {
        assert_eq!(idle_wait(false, 500), IdleWait::Poll(10));
        assert_eq!(idle_wait(false, 3), IdleWait::Poll(3));
        assert_eq!(idle_wait(true, 500), IdleWait::Sleep(2));
        assert_eq!(idle_wait(true, 0), IdleWait::Sleep(1));
    }
}
