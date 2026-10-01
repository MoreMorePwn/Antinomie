use std::os::unix::ffi::OsStrExt;
use std::{
    ffi::{CString, c_char, c_int, c_void},
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
}
#[derive(Default)]
#[repr(C)]
struct Limits {
    max_message_len: usize,
    max_command_len: usize,
    max_result_len: usize,
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
    assert!(std::mem::size_of::<Stats>() == 48);
    assert!(std::mem::offset_of!(Stats, health) == 32);
    assert!(std::mem::size_of::<Limits>() == 24);
};
unsafe extern "C" {
    fn ant_init(options: *const Options, client: *mut *mut c_void) -> c_int;
    fn ant_close(client: *mut c_void);
    fn ant_poll(client: *mut c_void, timeout_ms: c_int) -> c_int;
    fn ant_read(client: *mut c_void, dst: *mut c_void, capacity: usize, len: *mut usize) -> c_int;
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
        let path =
            CString::new(path.as_os_str().as_bytes()).map_err(|_| "RAM path contains NUL")?;
        let backing = Backing {
            path: path.as_ptr(),
            size: ram,
        };
        let region = Region {
            gpa: 0,
            size: ram,
            file_offset: 0,
            backing_index: 0,
        };
        let options = Options {
            backings: &backing,
            backing_count: 1,
            regions: &region,
            region_count: 1,
            ram_size: ram,
            bootstrap_gpa: bootstrap,
            init_timeout_ms: 20000,
            health_timeout_ms: 10000,
            host_timeout_ms: 60000,
            poll_mode: 0,
            poll_sleep_us: 50,
            poll_spin_us: 20,
        };
        let mut ptr = std::ptr::null_mut();
        // SAFETY: All pointed inputs live through ant_init, which copies layout and opens the backing; out is writable.
        check(unsafe { ant_init(&options, &mut ptr) })?;
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
        Ok(Self {
            ptr,
            message: vec![0; limits.max_message_len],
            result: vec![0; limits.max_result_len],
            command_limit: limits.max_command_len,
            _owner: PhantomData,
        })
    }
    pub fn poll(&mut self, timeout: i32) -> Result<i32, String> {
        // SAFETY: Client is live and this wrapper never leaves its sole owning thread.
        check(unsafe { ant_poll(self.ptr.as_ptr(), timeout) })
    }
    pub fn read(&mut self) -> Result<Option<&[u8]>, String> {
        let mut len = 0;
        // SAFETY: Buffer is writable for capacity bytes; len is writable; client remains solely owned.
        let code = unsafe {
            ant_read(
                self.ptr.as_ptr(),
                self.message.as_mut_ptr().cast(),
                self.message.len(),
                &mut len,
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
}
impl Drop for Transport {
    fn drop(&mut self) {
        // SAFETY: Rc marker and private pointer guarantee close happens on the owner after all calls.
        unsafe { ant_close(self.ptr.as_ptr()) };
    }
}
