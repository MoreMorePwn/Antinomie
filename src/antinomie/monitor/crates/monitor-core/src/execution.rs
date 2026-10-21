// SPDX-License-Identifier: MIT
use crate::{
    api::{RunExecution, RunState, WaitStatus},
    parser::{u32_at, u64_at},
};

pub(crate) fn decode(
    reply: &[u8],
    cookie: u64,
    previous_generation: u64,
) -> Result<RunExecution, String> {
    if reply.len() != 64 {
        return Err("run status reply must be exactly 64 bytes".into());
    }
    let read64 = |offset| u64_at(reply, offset).map_err(|e| e.to_string());
    let flags = u32_at(reply, 32).map_err(|e| e.to_string())?;
    let generation = read64(8)?;
    let live_task_count = read64(16)?;
    let pending_async_count = read64(24)?;
    let total_task_count = read64(48)?;
    if cookie == 0
        || read64(0)? != cookie
        || read64(56)? != 0
        || flags & !63 != 0
        || generation < previous_generation
        || total_task_count == 0
        || live_task_count > total_task_count
        || (flags & 2 != 0) != (live_task_count == 0)
        || (flags & 8 != 0 && (pending_async_count != 0 || flags & 16 != 0))
    {
        return Err(format!(
            "inconsistent run status reply (cookie {:#x} generation {generation} live {live_task_count} async {pending_async_count} flags {flags:#x} total {total_task_count})",
            read64(0)?
        ));
    }
    let raw = u32_at(reply, 36).map_err(|e| e.to_string())? as i32;
    let root_exit = if flags & 1 != 0 {
        Some(wait_status(raw)?)
    } else {
        None
    };
    Ok(RunExecution {
        generation,
        live_task_count,
        pending_async_count,
        flags,
        root_wait_status: (flags & 1 != 0).then_some(raw),
        root_exit,
        async_loss_count: read64(40)?,
        total_task_count,
    })
}

fn wait_status(raw: i32) -> Result<WaitStatus, String> {
    u64::try_from(raw)
        .ok()
        .and_then(WaitStatus::from_raw)
        .ok_or_else(|| "root wait status is not an exit or terminating signal".into())
}

/// The run's state from the guest's status. Whether the program ended is one
/// fact and whether every async request was observed is another: a tree that
/// ended with no request outstanding is finished even when the guest says its
/// async observation was incomplete or lost records (`has_async_loss`), and
/// even when an older guest never recorded the root's wait status
/// (`root_status_missing`), which then stays unknown instead of read as 0.
pub(crate) fn state(execution: &RunExecution) -> RunState {
    let ended = execution.flags & 2 != 0 && execution.pending_async_count == 0;
    if ended {
        if execution.flags & 4 != 0
            && matches!(execution.root_exit, Some(WaitStatus::Signaled { .. }))
        {
            RunState::Stopped
        } else {
            RunState::Finished
        }
    } else if execution.flags & 4 != 0 {
        RunState::StopRequested
    } else {
        RunState::Running
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reply(flags: u32, live: u64, pending: u64, raw: i32) -> Vec<u8> {
        let mut data = vec![0; 64];
        for (offset, value) in [(0, 7u64), (8, 2), (16, live), (24, pending), (48, 3)] {
            data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        data[32..36].copy_from_slice(&flags.to_le_bytes());
        data[36..40].copy_from_slice(&raw.to_le_bytes());
        data
    }
    #[test]
    fn root_exit_descendants_async_and_stop_are_distinct() {
        let status = decode(&reply(1, 1, 1, 7 << 8), 7, 1).unwrap();
        assert_eq!(status.root_exit, Some(WaitStatus::Exited { code: 7 }));
        assert_eq!(state(&status), RunState::Running);
        assert_eq!(
            state(&decode(&reply(3, 0, 1, 0), 7, 1).unwrap()),
            RunState::Running
        );
        assert_eq!(
            state(&decode(&reply(15, 0, 0, 15), 7, 1).unwrap()),
            RunState::Stopped
        );
        assert_eq!(
            state(&decode(&reply(15, 0, 0, 0), 7, 1).unwrap()),
            RunState::Finished
        );
    }
    #[test]
    fn a_stop_that_needed_sigkill_says_so_and_names_the_signal() {
        // ROOT | TREE | STOP | ASYNC | KILL_ESCALATED, root killed by SIGKILL.
        let escalated = decode(&reply(47, 0, 0, 9), 7, 1).unwrap();
        assert!(escalated.kill_escalated());
        assert_eq!(
            escalated.root_exit,
            Some(WaitStatus::Signaled {
                signal: 9,
                core_dumped: false
            })
        );
        assert_eq!(state(&escalated), RunState::Stopped);
        // A root that obeyed SIGTERM ended the run without the escalation.
        let polite = decode(&reply(15, 0, 0, 15), 7, 1).unwrap();
        assert!(!polite.kill_escalated());
        assert_eq!(state(&polite), RunState::Stopped);
    }
    #[test]
    fn an_ended_tree_is_finished_whatever_the_async_observation_says() {
        // ROOT | TREE | OBSERVATION_INCOMPLETE, root exit 0: what every io_uring
        // run reports. The process ended; only the observation is partial.
        let incomplete = decode(&reply(19, 0, 0, 0), 7, 1).unwrap();
        assert_eq!(state(&incomplete), RunState::Finished);
        assert!(incomplete.observation_incomplete());
        assert_eq!(incomplete.root_exit, Some(WaitStatus::Exited { code: 0 }));
        // A stop of such a run, with the root killed by a signal, is Stopped.
        let stopped = decode(&reply(23, 0, 0, 15), 7, 1).unwrap();
        assert_eq!(state(&stopped), RunState::Stopped);
        // Requests still counted after the tree ended keep the run running.
        assert_eq!(
            state(&decode(&reply(3, 0, 2, 0), 7, 1).unwrap()),
            RunState::Running
        );
    }
    #[test]
    fn a_guest_that_lost_the_root_status_still_ends_the_run_without_inventing_it() {
        // TREE_EXITED without ROOT_EXITED: an io_uring worker was the last
        // thread of the root's group and an older guest did not count it.
        let missing = decode(&reply(2, 0, 0, 0), 7, 1).unwrap();
        assert!(missing.root_status_missing());
        assert_eq!(missing.root_exit, None);
        assert_eq!(missing.root_wait_status, None);
        assert_eq!(state(&missing), RunState::Finished);
        assert!(
            !decode(&reply(3, 0, 0, 0), 7, 1)
                .unwrap()
                .root_status_missing()
        );
        // The live count and the flag must still agree.
        assert!(decode(&reply(0, 0, 0, 0), 7, 1).is_err());
        assert!(decode(&reply(2, 1, 0, 0), 7, 1).is_err());
    }
    #[test]
    fn an_inconsistent_reply_names_every_field_it_rejected() {
        let error = decode(&reply(2, 5, 0, 0), 7, 1).unwrap_err();
        for part in [
            "cookie 0x7",
            "generation 2",
            "live 5",
            "flags 0x2",
            "total 3",
        ] {
            assert!(error.contains(part), "{error}");
        }
    }
    #[test]
    fn malformed_generation_flags_lengths_and_wait_status_are_rejected() {
        let valid = reply(11, 0, 0, 0);
        for len in 0..64 {
            assert!(decode(&valid[..len], 7, 0).is_err());
        }
        assert!(decode(&valid, 8, 0).is_err());
        assert!(decode(&valid, 7, 3).is_err());
        assert!(decode(&reply(64, 1, 0, 0), 7, 0).is_err());
        assert!(decode(&reply(11, 1, 0, 0), 7, 0).is_err());
        assert!(decode(&reply(11, 0, 1, 0), 7, 0).is_err());
        assert!(decode(&reply(27, 0, 0, 0), 7, 0).is_err());
        assert!(decode(&reply(11, 0, 0, 127), 7, 0).is_err());
        assert!(decode(&reply(11, 0, 0, -1), 7, 0).is_err());
        let mut reserved = valid;
        reserved[56] = 1;
        assert!(decode(&reserved, 7, 0).is_err());
    }
}
