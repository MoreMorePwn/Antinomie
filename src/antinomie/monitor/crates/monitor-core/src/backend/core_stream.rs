// SPDX-License-Identifier: GPL-3.0-only
//! Reading a finished process core: several `CORE_READ`s are sent for
//! consecutive offsets before the first reply is waited for, and the replies
//! are joined into one write. A guest buffer is immutable once terminal, so a
//! read is idempotent and a prediction that turns out wrong (a short reply at
//! the end of an extent, a hole) just discards the replies that followed it.
use super::*;

/// Reads in flight at once. The guest serves up to 16 per tick and its reply
/// ring holds 15 of the largest, so this leaves room.
pub(super) const READ_DEPTH: usize = 8;
const READ: u32 = 0x1061;
const BURST_TIMEOUT: Duration = Duration::from_millis(100);

/// What a burst of replies yields at the offset it started from.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Assembled {
    /// Contiguous stored bytes.
    Data(Vec<u8>),
    /// Zeros the guest never stored: a sparse range.
    Hole(u64),
}

/// Join the replies of reads issued for `requests` (offset, capacity) in order.
/// A reply counts only if the one before it ended exactly where it was asked to
/// start; everything after the first short reply or hole is discarded. A hole
/// after data is left for the next burst, which then starts on it.
pub(super) fn assemble(
    requests: &[(u64, u32)],
    replies: &[Vec<u8>],
    total: u64,
) -> Result<Assembled, String> {
    let mut data = Vec::new();
    let mut cursor = requests.first().map_or(0, |request| request.0);
    for (&(offset, capacity), reply) in requests.iter().zip(replies) {
        if offset != cursor {
            break;
        }
        match control::core_chunk(reply, offset, total, capacity)? {
            control::CoreChunk::Data(chunk) => {
                data.extend_from_slice(chunk);
                cursor += chunk.len() as u64;
                if chunk.len() < capacity as usize {
                    break;
                }
            }
            control::CoreChunk::Hole(len) => {
                if data.is_empty() {
                    return Ok(Assembled::Hole(len));
                }
                break;
            }
        }
    }
    if data.is_empty() {
        return Err("process-core read returned no data".into());
    }
    Ok(Assembled::Data(data))
}

/// The reads of one burst: `depth` consecutive pieces from `offset`, none past
/// `total` and none adding up to more than `quota` bytes.
pub(super) fn plan(offset: u64, total: u64, depth: usize, quota: u64) -> Vec<(u64, u32)> {
    let mut requests = Vec::with_capacity(depth);
    let (mut next, mut left) = (offset, quota);
    while requests.len() < depth && next < total && left > 0 {
        let capacity = (total - next)
            .min(u64::from(control::SPECIMEN_CHUNK_SIZE))
            .min(left) as u32;
        requests.push((next, capacity));
        next += u64::from(capacity);
        left -= u64::from(capacity);
    }
    requests
}

/// A warning, when the recording quota will cut a core of `need` stored bytes.
pub(super) fn quota_warning(available: u64, need: u64) -> Option<String> {
    (available < need).then(|| {
        format!(
            "recording quota: {} MiB remain; the core will be cut at {} of {} MiB stored",
            available / (1 << 20),
            available / (1 << 20),
            need.div_ceil(1 << 20)
        )
    })
}

/// Free bytes on the file system that holds `directory` (or the nearest
/// directory above it that exists).
fn free_space(directory: &std::path::Path) -> Option<u64> {
    let mut at = Some(directory);
    while let Some(path) = at {
        if let Ok(space) = rustix::fs::statvfs(path) {
            return Some(space.f_bavail.saturating_mul(space.f_frsize));
        }
        at = path.parent();
    }
    None
}

/// The refusal text when the host disk cannot hold `need` stored bytes with a
/// 64 MiB margin. An unreadable file system does not refuse: the write path
/// reports a full disk with the prefix it kept.
pub(super) fn host_space_refusal(directory: &std::path::Path, need: u64) -> Option<String> {
    let free = free_space(directory)?;
    (free < need.saturating_add(64 << 20)).then(|| {
        format!(
            "host disk: the core needs {} MiB on {} and {} MiB are free",
            need.div_ceil(1 << 20),
            directory.display(),
            free / (1 << 20)
        )
    })
}

impl Session {
    /// Send the planned reads and collect every reply, in request order. None
    /// when the guest did not answer in time and the transfer is still young.
    pub(super) fn core_read_burst(
        &mut self,
        core_id: u64,
        requests: &[(u64, u32)],
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
        last_activity: Instant,
    ) -> Result<Option<Vec<Vec<u8>>>, String> {
        let mut ids = Vec::with_capacity(requests.len());
        for &(offset, capacity) in requests {
            match self
                .transport
                .send(READ, &control::specimen_read(core_id, offset, capacity))
            {
                Ok(id) => ids.push(id),
                // A full request ring only shortens the burst.
                Err(_) if !ids.is_empty() => break,
                Err(error) => return Err(error),
            }
        }
        let mut replies: Vec<Option<Vec<u8>>> = vec![None; ids.len()];
        let deadline = Instant::now() + BURST_TIMEOUT;
        while replies.iter().any(Option::is_none) {
            self.pump(snapshot, sender)?;
            while let Some((reply_id, status, payload)) = self.transport.reply()? {
                let Some(slot) = ids.iter().position(|&id| id == reply_id) else {
                    self.other_reply(reply_id, status, &payload, None, snapshot, sender);
                    continue;
                };
                if status != 0 {
                    return Err(
                        match status
                            .checked_neg()
                            .filter(|errno| (1..=4095).contains(errno))
                        {
                            Some(errno) => format!(
                                "guest command 0x{READ:x}: {}",
                                std::io::Error::from_raw_os_error(errno)
                            ),
                            None => "invalid guest rejection errno".into(),
                        },
                    );
                }
                replies[slot] = Some(payload);
            }
            if replies.iter().all(Option::is_some) {
                break;
            }
            if self
                .process
                .child
                .try_wait()
                .map_err(|error| error.to_string())?
                .is_some()
            {
                return Err(VM_EXITED_WAITING_REPLY.into());
            }
            if Instant::now() >= deadline {
                return if last_activity.elapsed() < Duration::from_secs(120) {
                    Ok(None)
                } else {
                    Err("guest process-core reads timed out; outcome unknown".into())
                };
            }
            self.transport.poll(1)?;
        }
        Ok(Some(replies.into_iter().flatten().collect()))
    }

    /// Whether a process core is being copied to the host right now, so the
    /// worker should not sleep between passes.
    pub(super) fn core_transfer_active(&self) -> bool {
        self.run_artifacts
            .values()
            .any(|owner| owner.core.as_ref().is_some_and(|core| core.transferring()))
            || self.manual_cores.values().any(|owner| owner.transferring())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(offset: u64, total: u64, bytes: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        wire.extend(offset.to_le_bytes());
        wire.extend(total.to_le_bytes());
        wire.extend((bytes.len() as u32).to_le_bytes());
        wire.extend(0u32.to_le_bytes());
        wire.extend(bytes);
        wire
    }
    fn hole(offset: u64, total: u64, len: u32) -> Vec<u8> {
        let mut wire = data(offset, total, &[]);
        wire[16..20].copy_from_slice(&len.to_le_bytes());
        wire[20..24].copy_from_slice(&1u32.to_le_bytes());
        wire
    }

    #[test]
    fn plan_stays_inside_the_file_the_quota_and_the_depth() {
        let step = u64::from(control::SPECIMEN_CHUNK_SIZE);
        let all = plan(0, 100 * step, READ_DEPTH, u64::MAX);
        assert_eq!(all.len(), READ_DEPTH);
        assert_eq!(all[1].0, step);
        assert!(super::core_sink::WRITE_LIMIT >= all.iter().map(|r| r.1 as usize).sum::<usize>());
        let tail = plan(step, step + 10, READ_DEPTH, u64::MAX);
        assert_eq!(tail, vec![(step, 10)]);
        let quota = plan(0, 100 * step, READ_DEPTH, step + 5);
        assert_eq!(quota, vec![(0, step as u32), (step, 5)]);
        assert!(plan(0, 0, READ_DEPTH, 10).is_empty() && plan(0, 10, READ_DEPTH, 0).is_empty());
    }

    #[test]
    fn quota_and_disk_checks_name_the_shortfall() {
        assert!(quota_warning(10 << 20, 5 << 20).is_none());
        assert!(
            quota_warning(10 << 20, 20 << 20)
                .unwrap()
                .contains("cut at 10 of 20 MiB")
        );
        let dir = std::env::temp_dir();
        assert!(host_space_refusal(&dir.join("does-not-exist-yet"), 1).is_none());
        let refusal = host_space_refusal(&dir, u64::MAX / 2).unwrap();
        assert!(refusal.starts_with("host disk: the core needs"));
    }

    #[test]
    fn contiguous_replies_join_in_order() {
        let requests = [(0, 4), (4, 4), (8, 4)];
        let replies = [
            data(0, 12, b"abcd"),
            data(4, 12, b"efgh"),
            data(8, 12, b"ijkl"),
        ];
        assert_eq!(
            assemble(&requests, &replies, 12).unwrap(),
            Assembled::Data(b"abcdefghijkl".to_vec())
        );
    }

    #[test]
    fn a_short_reply_discards_the_replies_predicted_after_it() {
        // The extent ends after two bytes; the guest then answered the later
        // reads at offsets that are not contiguous with it.
        let requests = [(0, 4), (4, 4), (8, 4)];
        let replies = [
            data(0, 100, b"ab"),
            data(4, 100, b"efgh"),
            data(8, 100, b"ijkl"),
        ];
        assert_eq!(
            assemble(&requests, &replies, 100).unwrap(),
            Assembled::Data(b"ab".to_vec())
        );
    }

    #[test]
    fn a_hole_first_is_taken_and_a_hole_after_data_waits() {
        let requests = [(0, 4), (4, 4)];
        let first = [hole(0, 100, 50), data(4, 100, b"efgh")];
        assert_eq!(
            assemble(&requests, &first, 100).unwrap(),
            Assembled::Hole(50)
        );
        let later = [data(0, 100, b"abcd"), hole(4, 100, 50)];
        assert_eq!(
            assemble(&requests, &later, 100).unwrap(),
            Assembled::Data(b"abcd".to_vec())
        );
    }

    #[test]
    fn a_wrong_reply_at_a_predicted_offset_is_an_error() {
        let requests = [(0, 4), (4, 4)];
        let replies = [data(0, 100, b"abcd"), data(8, 100, b"efgh")];
        assert!(assemble(&requests, &replies, 100).is_err());
        assert!(assemble(&requests, &[], 100).is_err());
    }
}
