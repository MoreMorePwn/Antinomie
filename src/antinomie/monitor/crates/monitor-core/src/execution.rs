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
        || flags & !31 != 0
        || generation < previous_generation
        || total_task_count == 0
        || live_task_count > total_task_count
        || (flags & 2 != 0) != (live_task_count == 0)
        || (flags & 2 != 0 && flags & 1 == 0)
        || (flags & 8 != 0 && (pending_async_count != 0 || flags & 16 != 0))
    {
        return Err("inconsistent run status reply".into());
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

pub(crate) fn state(execution: &RunExecution) -> RunState {
    if execution.flags & 2 != 0 && execution.flags & 8 != 0 && execution.flags & 16 == 0 {
        if execution.flags & 4 != 0
            && matches!(execution.root_exit, Some(WaitStatus::Signaled { .. }))
        {
            RunState::Stopped
        } else {
            RunState::Finished
        }
    } else if execution.flags & 4 != 0 {
        RunState::StopRequested
    } else if execution.live_task_count == 0 && execution.pending_async_count == 0 {
        RunState::Unknown
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
    fn malformed_generation_flags_lengths_and_wait_status_are_rejected() {
        let valid = reply(11, 0, 0, 0);
        for len in 0..64 {
            assert!(decode(&valid[..len], 7, 0).is_err());
        }
        assert!(decode(&valid, 8, 0).is_err());
        assert!(decode(&valid, 7, 3).is_err());
        assert!(decode(&reply(32, 1, 0, 0), 7, 0).is_err());
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
