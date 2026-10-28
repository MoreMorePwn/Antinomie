use std::os::unix::ffi::OsStrExt;
use std::{
    ffi::{CString, c_char, c_int, c_uint, c_void},
    marker::PhantomData,
    path::Path,
    ptr::NonNull,
    rc::Rc,
};

#[repr(C)]
struct Backing {
    path: *const c_char,
    size: u64,
}
#[repr(C)]
struct Region {
    gpa: u64,
    size: u64,
    file_offset: u64,
    backing_index: u32,
}
#[repr(C)]
struct Options {
    backings: *const Backing,
    backing_count: usize,
    regions: *const Region,
    region_count: usize,
    ram_size: u64,
    bootstrap_gpa: u64,
    init_timeout_ms: c_int,
    health_timeout_ms: c_int,
    host_timeout_ms: u32,
    poll_mode: c_int,
    poll_sleep_us: u32,
    poll_spin_us: u32,
}
#[derive(Default)]
#[repr(C)]
pub(crate) struct Stats {
    pub attempted: u64,
    pub dropped: u64,
    pub bad_commands: u64,
    pub reply_stalls: u64,
    pub health: u32,
    pub queue_count: u32,
    pub live: u32,
    pub host_timeout_ms: u32,
    /// Sends that found their ring full and waited, and the total wait.
    pub waits: u64,
    pub wait_ns: u64,
    /// Transport ABI of the guest (7, 8 or 9), per-CPU ring bytes, send wait.
    pub abi: u32,
    pub ring_size: u32,
    pub send_wait_us: u32,
    reserved: u32,
}
#[derive(Default)]
#[repr(C)]
struct Limits {
    max_message_len: usize,
    max_command_len: usize,
    max_result_len: usize,
}
/// How a reconnect's guest acknowledgement went (see `reconnect_observed`).
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub(crate) struct ResumeWait {
    pub ack_ms: u64,
    /// Passes of the guest control worker during the wait; `None` if unread.
    pub guest_passes: Option<u64>,
}
/// New attachment identity and discarded command traffic; no automatic replay.
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub(crate) struct ResumeInfo {
    pub attachment: u64,
    pub sequence_floor: u64,
    pub discarded_request_bytes: u64,
    pub discarded_reply_bytes: u64,
}
const _: () = {
    assert!(std::mem::size_of::<Backing>() == 16);
    assert!(std::mem::size_of::<Region>() == 32);
    assert!(std::mem::offset_of!(Region, backing_index) == 24);
    assert!(std::mem::size_of::<Options>() == 72);
    assert!(std::mem::offset_of!(Options, ram_size) == 32);
    assert!(std::mem::offset_of!(Options, bootstrap_gpa) == 40);
    assert!(std::mem::offset_of!(Options, init_timeout_ms) == 48);
    assert!(std::mem::offset_of!(Options, poll_mode) == 60);
    assert!(std::mem::size_of::<Stats>() == 80);
    assert!(std::mem::offset_of!(Stats, waits) == 48);
    assert!(std::mem::offset_of!(Stats, health) == 32);
    assert!(std::mem::size_of::<Limits>() == 24);
    assert!(std::mem::size_of::<ResumeInfo>() == 32);
};
unsafe extern "C" {
    fn ant_init(options: *const Options, client: *mut *mut c_void) -> c_int;
    fn ant_open_pending(options: *const Options, client: *mut *mut c_void) -> c_int;
    fn ant_resume_begin(client: *mut c_void) -> c_int;
    fn ant_resume_finish(client: *mut c_void, timeout_ms: c_int, report: *mut ResumeInfo) -> c_int;
    fn ant_suspend_heartbeats(client: *mut c_void) -> c_int;
    fn ant_resume_heartbeats(client: *mut c_void) -> c_int;
    fn ant_close(client: *mut c_void);
    fn ant_poll(client: *mut c_void, timeout_ms: c_int) -> c_int;
    fn ant_read_ordered(
        client: *mut c_void,
        dst: *mut c_void,
        capacity: usize,
        len: *mut usize,
        key_offset: usize,
    ) -> c_int;
    fn ant_last_read(client: *mut c_void, cpu_id: *mut u32, wait_ns: *mut u64) -> c_int;
    fn ant_ring_state(
        client: *mut c_void,
        index: c_uint,
        cpu_id: *mut u32,
        size: *mut u32,
        head: *mut u64,
        tail: *mut u64,
    ) -> c_int;
    fn ant_command_send(
        client: *mut c_void,
        opcode: u32,
        args: *const c_void,
        len: usize,
        id: *mut u64,
    ) -> c_int;
    fn ant_result_read(
        client: *mut c_void,
        id: *mut u64,
        status: *mut i32,
        dst: *mut c_void,
        capacity: usize,
        len: *mut usize,
    ) -> c_int;
    fn ant_get_stats(client: *mut c_void, stats: *mut Stats) -> c_int;
    fn ant_get_limits(client: *mut c_void, limits: *mut Limits) -> c_int;
    fn ant_set_send_wait(client: *mut c_void, wait_us: u32) -> c_int;
    fn ant_set_host_timeout(client: *mut c_void, timeout_ms: u32) -> c_int;
    fn ant_heartbeat(client: *mut c_void) -> c_int;
    fn ant_set_guest_paused(client: *mut c_void, paused: c_int) -> c_int;
    fn ant_guest_heartbeat(client: *mut c_void, heartbeat: *mut u64) -> c_int;
}

thread_local! {
    /// The client the current (transport owner) thread holds, for heartbeats
    /// while it waits elsewhere.
    static OWNED: std::cell::Cell<*mut c_void> = const { std::cell::Cell::new(std::ptr::null_mut()) };
}

/// Keep the guest seeing a live host while this thread waits on something
/// else (the recording writer). Does nothing on other threads.
pub(crate) fn heartbeat_on_this_thread() {
    let client = OWNED.with(std::cell::Cell::get);
    if !client.is_null() {
        // SAFETY: Only the owner thread registers its live client, and it calls
        // this between its own transport calls, never during one.
        let _ = unsafe { ant_heartbeat(client) };
    }
}
fn check(code: i32) -> Result<i32, String> {
    if code < 0 {
        Err(format!(
            "transport: {}",
            std::io::Error::from_raw_os_error(-code)
        ))
    } else {
        Ok(code)
    }
}

/// Where an ANTT packet carries its guest timestamp (`timestamp_ns`, the
/// guest's monotonic clock, one clock for all its vCPUs).
const PACKET_TIMESTAMP_OFFSET: usize = 64;

/// The Rc marker deliberately prevents sending a live C client to another thread.
pub(crate) struct Transport {
    ptr: NonNull<c_void>,
    message: Vec<u8>,
    result: Vec<u8>,
    pub command_limit: usize,
    _owner: PhantomData<Rc<()>>,
}
impl Transport {
    pub fn open(path: &Path, ram: u64, bootstrap: u64) -> Result<Self, String> {
        Self::open_mode(path, ram, bootstrap, false)
    }
    /// Publish resume before continuing a paused incoming guest. Host
    /// heartbeats remain unregistered until `finish_resume` succeeds.
    pub fn open_pending(path: &Path, ram: u64, bootstrap: u64) -> Result<Self, String> {
        Self::open_mode(path, ram, bootstrap, true)
    }
    fn open_mode(path: &Path, ram: u64, bootstrap: u64, pending: bool) -> Result<Self, String> {
        let path =
            CString::new(path.as_os_str().as_bytes()).map_err(|_| "RAM path contains NUL")?;
        let backing = Backing {
            path: path.as_ptr(),
            size: ram,
        };
        let layout = crate::vm::RamLayout::q35(ram);
        let mut regions = vec![Region {
            gpa: 0,
            size: layout.low,
            file_offset: 0,
            backing_index: 0,
        }];
        if layout.high != 0 {
            regions.push(Region {
                gpa: crate::vm::HIGH_RAM_GPA,
                size: layout.high,
                file_offset: layout.low,
                backing_index: 0,
            });
        }
        let options = Options {
            backings: &backing,
            backing_count: 1,
            regions: regions.as_ptr(),
            region_count: regions.len(),
            ram_size: ram,
            bootstrap_gpa: bootstrap,
            init_timeout_ms: 20000,
            // A guest whose vCPUs get no host time (a host under heavy load:
            // a 17 s stall was seen with Capture All of a desktop) is not dead.
            health_timeout_ms: 30000,
            host_timeout_ms: 60000,
            poll_mode: 0,
            poll_sleep_us: 50,
            poll_spin_us: 20,
        };
        let mut ptr = std::ptr::null_mut();
        // SAFETY: All pointed inputs live through ant_init, which copies layout and opens the backing; out is writable.
        check(unsafe {
            if pending {
                ant_open_pending(&options, &mut ptr)
            } else {
                ant_init(&options, &mut ptr)
            }
        })?;
        let ptr = NonNull::new(ptr).ok_or("transport returned null client")?;
        let mut limits = Limits::default();
        // SAFETY: Client is initialized on this owner thread, and limits is a valid writable C layout.
        let code = unsafe { ant_get_limits(ptr.as_ptr(), &mut limits) };
        if let Err(error) = check(code) {
            // SAFETY: No other calls race this owned client.
            unsafe { ant_close(ptr.as_ptr()) };
            return Err(error);
        }
        if limits.max_message_len > 1024 * 1024 || limits.max_result_len > 1024 * 1024 {
            // SAFETY: No other calls race this owned client.
            unsafe { ant_close(ptr.as_ptr()) };
            return Err("transport limits exceed host bound".into());
        }
        if !pending {
            OWNED.with(|owned| owned.set(ptr.as_ptr()));
        }
        Ok(Self {
            ptr,
            message: vec![0; limits.max_message_len],
            result: vec![0; limits.max_result_len],
            command_limit: limits.max_command_len,
            _owner: PhantomData,
        })
    }
    /// Sole owner begins recovery; abandon unresolved command results.
    pub fn begin_resume(&mut self) -> Result<(), String> {
        // SAFETY: The live client remains on its sole owner thread; no call races it.
        check(unsafe { ant_resume_begin(self.ptr.as_ptr()) })?;
        OWNED.with(|owned| {
            if owned.get() == self.ptr.as_ptr() {
                owned.set(std::ptr::null_mut());
            }
        });
        Ok(())
    }
    /// Wait for guest acknowledgement. Timed-out side effects stay unknown;
    /// callers must clear pending operations without automatically replaying.
    pub fn finish_resume(&mut self, timeout_ms: i32) -> Result<ResumeInfo, String> {
        let mut report = ResumeInfo::default();
        // SAFETY: Sole owner holds the client; report is writable C layout.
        check(unsafe { ant_resume_finish(self.ptr.as_ptr(), timeout_ms, &mut report) })?;
        OWNED.with(|owned| owned.set(self.ptr.as_ptr()));
        Ok(report)
    }
    /// Reattach to the running guest, without replaying commands: an earlier
    /// handshake that still owns its nonce (EINPROGRESS) is waited for, not
    /// replaced. Also says how the guest got there: how long its
    /// acknowledgement took and how many passes its control worker made
    /// meanwhile. Passes without an acknowledgement mean the guest held it
    /// back (a fence); none mean its worker did not run (a command handler
    /// that sleeps, or a starved CPU).
    pub fn reconnect_observed(
        &mut self,
        timeout_ms: i32,
    ) -> Result<(ResumeInfo, ResumeWait), String> {
        let started = std::time::Instant::now();
        let deadline = started + std::time::Duration::from_millis(timeout_ms.max(0) as u64);
        let first = self.guest_heartbeat().ok();
        // SAFETY: Sole owner holds the client. EINPROGRESS means an earlier
        // handshake still owns its nonce; continue that wait without replaying
        // commands or publishing another attachment request.
        let code = unsafe { ant_resume_begin(self.ptr.as_ptr()) };
        if code != -rustix::io::Errno::INPROGRESS.raw_os_error() {
            check(code)?;
        }
        OWNED.with(|owned| {
            if owned.get() == self.ptr.as_ptr() {
                owned.set(std::ptr::null_mut());
            }
        });
        let timed_out = -rustix::io::Errno::TIMEDOUT.raw_os_error();
        loop {
            let slice = deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_millis()
                .clamp(1, 100) as i32;
            let mut report = ResumeInfo::default();
            // SAFETY: Sole owner holds the client; report is writable C layout.
            // A timed-out finish leaves the handshake pending for the next one.
            let code = unsafe { ant_resume_finish(self.ptr.as_ptr(), slice, &mut report) };
            if code == timed_out && std::time::Instant::now() < deadline {
                continue;
            }
            let wait = ResumeWait {
                ack_ms: started.elapsed().as_millis() as u64,
                guest_passes: first
                    .zip(self.guest_heartbeat().ok())
                    .map(|(first, last)| last.saturating_sub(first)),
            };
            check(code).map_err(|error| {
                format!(
                    "{error} after {} ms, guest control worker passes {:?}",
                    wait.ack_ms, wait.guest_passes
                )
            })?;
            OWNED.with(|owned| owned.set(self.ptr.as_ptr()));
            return Ok((report, wait));
        }
    }
    /// Disable both writer-wait heartbeats and ordinary transport RAM writes
    /// during shared-RAM serialization. Call resume even after QMP failure.
    pub fn suspend_heartbeats(&mut self) -> Result<(), String> {
        // SAFETY: Sole owner holds the live client; suspension never frees it.
        check(unsafe { ant_suspend_heartbeats(self.ptr.as_ptr()) })?;
        OWNED.with(|owned| {
            if owned.get() == self.ptr.as_ptr() {
                owned.set(std::ptr::null_mut());
            }
        });
        Ok(())
    }
    /// Refresh the explicit pause deadline without accepting heartbeat rewind,
    /// legacy reattachment, or any previously latched stale error.
    pub fn resume_heartbeats(&mut self) -> Result<(), String> {
        // SAFETY: Sole owner holds the client; C validates session/layout.
        check(unsafe { ant_resume_heartbeats(self.ptr.as_ptr()) })?;
        OWNED.with(|owned| owned.set(self.ptr.as_ptr()));
        Ok(())
    }
    pub fn poll(&mut self, timeout: i32) -> Result<i32, String> {
        // SAFETY: Client is live and this wrapper never leaves its sole owning thread.
        check(unsafe { ant_poll(self.ptr.as_ptr(), timeout) })
    }
    /// The next telemetry packet, oldest first: the guest's per-CPU rings
    /// are merged by the packets' guest timestamps, so records written on
    /// different vCPUs (a task that moved, a worker publishing for a call)
    /// arrive in the order they were made, not in the order the rings were
    /// visited.
    pub fn read(&mut self) -> Result<Option<&[u8]>, String> {
        let mut len = 0;
        // SAFETY: Buffer is writable for capacity bytes; len is writable; client remains solely owned.
        let code = unsafe {
            ant_read_ordered(
                self.ptr.as_ptr(),
                self.message.as_mut_ptr().cast(),
                self.message.len(),
                &mut len,
                PACKET_TIMESTAMP_OFFSET,
            )
        };
        if code == -11 {
            return Ok(None);
        }
        check(code)?;
        let slice = self
            .message
            .get(..len)
            .ok_or("transport message length out of bounds")?;
        Ok(Some(slice))
    }
    /// The ring (vCPU) the last `read` took its packet from, and how long that
    /// packet had been waiting at the head of the ring when it was taken.
    pub fn last_read(&self) -> (u32, u64) {
        let (mut cpu, mut wait) = (0, 0);
        // SAFETY: Both outputs are writable; the client is live and solely owned.
        if unsafe { ant_last_read(self.ptr.as_ptr(), &mut cpu, &mut wait) } == 0 {
            (cpu, wait)
        } else {
            (0, 0)
        }
    }
    /// Telemetry ring `index` (None past the last): its fill and running byte
    /// counts, for [`crate::read_gaps`]. Two loads on the host side.
    pub fn ring_state(&self, index: u32) -> Option<crate::read_gaps::RingState> {
        let (mut cpu, mut size, mut head, mut tail) = (0, 0, 0, 0);
        // SAFETY: The outputs are writable; the client is live and solely owned.
        let status = unsafe {
            ant_ring_state(
                self.ptr.as_ptr(),
                index,
                &mut cpu,
                &mut size,
                &mut head,
                &mut tail,
            )
        };
        (status == 0).then_some(crate::read_gaps::RingState {
            cpu,
            size,
            head,
            tail,
        })
    }
    pub fn send(&mut self, opcode: u32, args: &[u8]) -> Result<u64, String> {
        if args.len() > self.command_limit {
            return Err("command exceeds transport limit".into());
        }
        let mut id = 0;
        // SAFETY: Args is initialized for its length, id is writable; C copies args synchronously.
        check(unsafe {
            ant_command_send(
                self.ptr.as_ptr(),
                opcode,
                args.as_ptr().cast(),
                args.len(),
                &mut id,
            )
        })?;
        Ok(id)
    }
    pub fn reply(&mut self) -> Result<Option<(u64, i32, Vec<u8>)>, String> {
        let (mut id, mut status, mut len) = (0, 0, 0);
        // SAFETY: All outputs are writable; result buffer matches its advertised capacity.
        let code = unsafe {
            ant_result_read(
                self.ptr.as_ptr(),
                &mut id,
                &mut status,
                self.result.as_mut_ptr().cast(),
                self.result.len(),
                &mut len,
            )
        };
        if code == -11 {
            return Ok(None);
        }
        check(code)?;
        Ok(Some((
            id,
            status,
            self.result
                .get(..len)
                .ok_or("result length out of bounds")?
                .to_vec(),
        )))
    }
    pub fn stats(&mut self) -> Result<Stats, String> {
        let mut stats = Stats::default();
        // SAFETY: Stats has the C ABI layout and client remains live and exclusively owned.
        check(unsafe { ant_get_stats(self.ptr.as_ptr(), &mut stats) })?;
        Ok(stats)
    }
    /// Let guest sends wait up to `wait_us` for room in a full ring instead
    /// of dropping (0 drops). Older guests support only 0.
    pub fn set_send_wait(&mut self, wait_us: u32) -> Result<(), String> {
        // SAFETY: Client remains live and exclusively owned by this thread.
        check(unsafe { ant_set_send_wait(self.ptr.as_ptr(), wait_us) }).map(|_| ())
    }
    /// How long the guest keeps treating a silent host as live (1..=60000 ms).
    pub fn set_host_timeout(&mut self, timeout_ms: u32) -> Result<(), String> {
        // SAFETY: Client remains live and exclusively owned by this thread.
        check(unsafe { ant_set_host_timeout(self.ptr.as_ptr(), timeout_ms) }).map(|_| ())
    }
    /// The guest control worker's pass count: it moves while the worker runs
    /// (every 10 ms), not while a command handler sleeps or the guest's CPU
    /// is not scheduled. Readable while a resume is pending.
    pub fn guest_heartbeat(&mut self) -> Result<u64, String> {
        let mut heartbeat = 0u64;
        // SAFETY: Client remains live and exclusively owned by this thread; the
        // out pointer is a valid u64.
        check(unsafe { ant_guest_heartbeat(self.ptr.as_ptr(), &mut heartbeat) })?;
        Ok(heartbeat)
    }
    /// The guest is paused on purpose (a memory dump): its silence is not a
    /// dead guest. Resuming restarts the liveness window.
    pub fn set_guest_paused(&mut self, paused: bool) -> Result<(), String> {
        // SAFETY: Client remains live and exclusively owned by this thread.
        check(unsafe { ant_set_guest_paused(self.ptr.as_ptr(), c_int::from(paused)) }).map(|_| ())
    }
}
impl Drop for Transport {
    fn drop(&mut self) {
        OWNED.with(|owned| {
            if owned.get() == self.ptr.as_ptr() {
                owned.set(std::ptr::null_mut());
            }
        });
        // SAFETY: Rc marker and private pointer guarantee close happens on the owner after all calls.
        unsafe { ant_close(self.ptr.as_ptr()) };
    }
}

#[cfg(test)]
mod tests;
