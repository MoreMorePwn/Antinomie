// SPDX-License-Identifier: GPL-3.0-only
//! A compact RFB 3.8 client for the VM screen: QEMU's VNC display on a private
//! unix socket (security None, no TCP). A worker thread keeps one connection,
//! asks for incremental updates, and keeps the framebuffer as RGBA with the
//! rectangles changed since the app last took them. Encodings: Raw, CopyRect,
//! ZRLE; pseudo-encodings: DesktopSize, ExtendedDesktopSize, Cursor, QEMU
//! Extended Key Event and QEMU pointer type change.
mod zrle;

use std::{
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

/// The largest screen taken; QEMU's own limit is 16384 on each side.
const MAX_SIDE: usize = 16384;
/// A rectangle's raw bytes, at most (a 16384 x 16384 screen is far above any VM).
const MAX_RAW: usize = 512 * 1024 * 1024;
const WRITE_TIMEOUT: Duration = Duration::from_millis(500);

const ENC_RAW: i32 = 0;
const ENC_COPYRECT: i32 = 1;
const ENC_ZRLE: i32 = 16;
const ENC_CURSOR: i32 = -239;
const ENC_DESKTOP_SIZE: i32 = -223;
const ENC_EXT_DESKTOP_SIZE: i32 = -308;
const ENC_POINTER_TYPE: i32 = -257;
const ENC_EXT_KEY: i32 = -258;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Rect {
    pub x: usize,
    pub y: usize,
    pub w: usize,
    pub h: usize,
}

impl Rect {
    fn union(self, other: Rect) -> Rect {
        let x = self.x.min(other.x);
        let y = self.y.min(other.y);
        Rect {
            x,
            y,
            w: (self.x + self.w).max(other.x + other.w) - x,
            h: (self.y + self.h).max(other.y + other.h) - y,
        }
    }
}

/// The framebuffer: RGBA, opaque.
pub(crate) struct Fb {
    pub w: usize,
    pub h: usize,
    pub rgba: Vec<u8>,
}

impl Fb {
    fn new(w: usize, h: usize) -> Self {
        Self {
            w,
            h,
            rgba: [0, 0, 0, 255].repeat(w * h),
        }
    }
    pub(crate) fn set(&mut self, x: usize, y: usize, rgb: [u8; 3]) {
        if x < self.w && y < self.h {
            let at = (y * self.w + x) * 4;
            self.rgba[at..at + 4].copy_from_slice(&[rgb[0], rgb[1], rgb[2], 255]);
        }
    }
    pub(crate) fn fill(&mut self, x: usize, y: usize, w: usize, h: usize, rgb: [u8; 3]) {
        for row in y..(y + h).min(self.h) {
            for col in x..(x + w).min(self.w) {
                self.set(col, row, rgb);
            }
        }
    }
}

/// A pointer shape the guest asked the client to draw.
#[derive(Debug)]
pub struct Cursor {
    pub hotspot: (usize, usize),
    pub width: usize,
    pub height: usize,
    /// RGBA, transparent where the mask says so.
    pub rgba: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScreenStatus {
    Connecting,
    Connected,
    Disconnected(String),
}

/// How the guest takes the pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointerMode {
    /// A tablet: positions in framebuffer coordinates.
    Absolute,
    /// A PS/2 mouse: movements.
    Relative,
}

/// A changed rectangle with its pixels (RGBA).
pub struct RectPixels {
    pub x: usize,
    pub y: usize,
    pub w: usize,
    pub h: usize,
    pub rgba: Vec<u8>,
}

/// What changed since the last call of [`ScreenClient::take_update`].
pub struct Update {
    pub size: (usize, usize),
    /// The screen has a new size (or is new): the whole of it is in `rects`.
    pub resized: bool,
    pub rects: Vec<RectPixels>,
}

struct State {
    fb: Fb,
    dirty: Vec<Rect>,
    resized: bool,
    have_frame: bool,
    cursor: Option<Arc<Cursor>>,
    cursor_generation: u64,
    status: ScreenStatus,
    absolute: bool,
    ext_keys: bool,
    name: String,
}

struct Shared {
    state: Mutex<State>,
    writer: Mutex<Option<UnixStream>>,
    stop: AtomicBool,
    wake: Arc<dyn Fn() + Send + Sync>,
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn send(&self, bytes: &[u8]) -> bool {
        let mut writer = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        match writer.as_mut() {
            Some(stream) => stream.write_all(bytes).is_ok(),
            None => false,
        }
    }
}

/// The client of one VM's screen socket. Dropping it closes the connection and
/// ends the worker.
pub struct ScreenClient {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl ScreenClient {
    /// Connect (retrying until QEMU has made the socket) and keep the
    /// connection; `wake` is called when something new can be shown.
    pub fn start(socket: PathBuf, wake: Arc<dyn Fn() + Send + Sync>) -> Self {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                fb: Fb::new(0, 0),
                dirty: Vec::new(),
                resized: false,
                have_frame: false,
                cursor: None,
                cursor_generation: 0,
                status: ScreenStatus::Connecting,
                absolute: true,
                ext_keys: false,
                name: String::new(),
            }),
            writer: Mutex::new(None),
            stop: AtomicBool::new(false),
            wake,
        });
        let worker = shared.clone();
        let thread = thread::Builder::new()
            .name("antinomie-vm-screen".into())
            .spawn(move || worker_loop(&worker, &socket))
            .ok();
        Self { shared, thread }
    }

    pub fn status(&self) -> ScreenStatus {
        self.shared.state().status.clone()
    }

    /// The guest's name for the display, when it gave one.
    pub fn name(&self) -> String {
        self.shared.state().name.clone()
    }

    pub fn size(&self) -> Option<(usize, usize)> {
        let state = self.shared.state();
        state.have_frame.then_some((state.fb.w, state.fb.h))
    }

    pub fn pointer_mode(&self) -> PointerMode {
        if self.shared.state().absolute {
            PointerMode::Absolute
        } else {
            PointerMode::Relative
        }
    }

    /// The pointer shape and a number that changes with it.
    pub fn cursor(&self) -> (u64, Option<Arc<Cursor>>) {
        let state = self.shared.state();
        (state.cursor_generation, state.cursor.clone())
    }

    /// The rectangles changed since the last call, with their pixels.
    pub fn take_update(&self) -> Option<Update> {
        let mut state = self.shared.state();
        if !state.have_frame || (state.dirty.is_empty() && !state.resized) {
            return None;
        }
        let resized = std::mem::take(&mut state.resized);
        let (w, h) = (state.fb.w, state.fb.h);
        let dirty = std::mem::take(&mut state.dirty);
        let wanted = if resized {
            vec![Rect { x: 0, y: 0, w, h }]
        } else {
            dirty
        };
        let rects = wanted
            .into_iter()
            .map(|r| {
                let mut rgba = Vec::with_capacity(r.w * r.h * 4);
                for row in r.y..r.y + r.h {
                    let start = (row * w + r.x) * 4;
                    rgba.extend_from_slice(&state.fb.rgba[start..start + r.w * 4]);
                }
                RectPixels {
                    x: r.x,
                    y: r.y,
                    w: r.w,
                    h: r.h,
                    rgba,
                }
            })
            .collect();
        Some(Update {
            size: (w, h),
            resized,
            rects,
        })
    }

    /// The whole screen as it is now (RGBA), for a screenshot.
    pub fn frame(&self) -> Option<(usize, usize, Vec<u8>)> {
        let state = self.shared.state();
        (state.have_frame && state.fb.w > 0)
            .then(|| (state.fb.w, state.fb.h, state.fb.rgba.clone()))
    }

    /// A key: `scancode` is the PC (set 1) scancode, with 0x80 added for the
    /// extended (E0) keys; `keysym` is the X11 keysym, used by servers without
    /// the QEMU extended key event.
    pub fn key(&self, down: bool, keysym: u32, scancode: u32) {
        let ext = self.shared.state().ext_keys;
        let mut message = Vec::with_capacity(12);
        if ext {
            message.extend_from_slice(&[255, 0]);
            message.extend_from_slice(&u16::from(down).to_be_bytes());
            message.extend_from_slice(&keysym.to_be_bytes());
            message.extend_from_slice(&scancode.to_be_bytes());
        } else if keysym != 0 {
            message.extend_from_slice(&[4, u8::from(down), 0, 0]);
            message.extend_from_slice(&keysym.to_be_bytes());
        }
        if !message.is_empty() {
            self.shared.send(&message);
        }
    }

    /// The pointer: bit 0 left, 1 middle, 2 right, 3 wheel up, 4 wheel down.
    /// Absolute: framebuffer coordinates. Relative: 0x7fff plus the movement.
    pub fn pointer(&self, buttons: u8, x: u16, y: u16) {
        let mut message = vec![5, buttons];
        message.extend_from_slice(&x.to_be_bytes());
        message.extend_from_slice(&y.to_be_bytes());
        self.shared.send(&message);
    }
}

impl Drop for ScreenClient {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        if let Some(stream) = self
            .shared
            .writer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn pause(shared: &Shared, total: Duration) {
    let step = Duration::from_millis(50);
    let mut waited = Duration::ZERO;
    while waited < total && !shared.stop.load(Ordering::Relaxed) {
        thread::sleep(step);
        waited += step;
    }
}

fn worker_loop(shared: &Arc<Shared>, socket: &Path) {
    while !shared.stop.load(Ordering::Relaxed) {
        // The socket is private to the VM's folder; keep its mode owner-only.
        let _ = std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600));
        match UnixStream::connect(socket) {
            Ok(stream) => {
                let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
                let Ok(writer) = stream.try_clone() else {
                    pause(shared, Duration::from_millis(300));
                    continue;
                };
                *shared.writer.lock().unwrap_or_else(|e| e.into_inner()) = Some(writer);
                if shared.stop.load(Ordering::Relaxed) {
                    break;
                }
                let result = session(shared, stream);
                shared
                    .writer
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                let mut state = shared.state();
                state.status = ScreenStatus::Disconnected(match result {
                    Err(error) => error,
                    Ok(()) => "the screen connection closed".into(),
                });
                state.have_frame = false;
                drop(state);
                (shared.wake)();
            }
            Err(_) => shared.state().status = ScreenStatus::Connecting,
        }
        pause(shared, Duration::from_millis(300));
    }
}

fn read_u8(s: &mut impl Read) -> Result<u8, String> {
    let mut b = [0u8; 1];
    s.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(b[0])
}
fn read_u16(s: &mut impl Read) -> Result<u16, String> {
    let mut b = [0u8; 2];
    s.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(u16::from_be_bytes(b))
}
fn read_u32(s: &mut impl Read) -> Result<u32, String> {
    let mut b = [0u8; 4];
    s.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(u32::from_be_bytes(b))
}
fn read_vec(s: &mut impl Read, n: usize) -> Result<Vec<u8>, String> {
    if n > MAX_RAW {
        return Err("the screen sent more data than expected".into());
    }
    let mut v = vec![0u8; n];
    s.read_exact(&mut v).map_err(|e| e.to_string())?;
    Ok(v)
}

fn handshake(stream: &mut UnixStream) -> Result<(usize, usize, String), String> {
    let mut version = [0u8; 12];
    stream.read_exact(&mut version).map_err(|e| e.to_string())?;
    if !version.starts_with(b"RFB 003.") {
        return Err("not an RFB server".into());
    }
    stream
        .write_all(b"RFB 003.008\n")
        .map_err(|e| e.to_string())?;
    let count = read_u8(stream)?;
    if count == 0 {
        let len = read_u32(stream)? as usize;
        let reason = read_vec(stream, len.min(4096))?;
        return Err(String::from_utf8_lossy(&reason).into_owned());
    }
    let types = read_vec(stream, usize::from(count))?;
    if !types.contains(&1) {
        return Err("the screen needs a password".into());
    }
    stream.write_all(&[1]).map_err(|e| e.to_string())?;
    if read_u32(stream)? != 0 {
        return Err("the screen refused the connection".into());
    }
    stream.write_all(&[1]).map_err(|e| e.to_string())?;
    let width = usize::from(read_u16(stream)?);
    let height = usize::from(read_u16(stream)?);
    read_vec(stream, 16)?;
    let len = read_u32(stream)? as usize;
    let name = read_vec(stream, len.min(4096))?;
    Ok((width, height, String::from_utf8_lossy(&name).into_owned()))
}

fn setup_messages() -> Vec<u8> {
    // 32 bits, depth 24, little endian, true colour, R in the low byte.
    let mut m = vec![0, 0, 0, 0, 32, 24, 0, 1];
    m.extend_from_slice(&255u16.to_be_bytes());
    m.extend_from_slice(&255u16.to_be_bytes());
    m.extend_from_slice(&255u16.to_be_bytes());
    m.extend_from_slice(&[0, 8, 16, 0, 0, 0]);
    let encodings = [
        ENC_ZRLE,
        ENC_COPYRECT,
        ENC_RAW,
        ENC_CURSOR,
        ENC_DESKTOP_SIZE,
        ENC_EXT_DESKTOP_SIZE,
        ENC_EXT_KEY,
        ENC_POINTER_TYPE,
    ];
    m.extend_from_slice(&[2, 0]);
    m.extend_from_slice(&(encodings.len() as u16).to_be_bytes());
    for e in encodings {
        m.extend_from_slice(&e.to_be_bytes());
    }
    m
}

fn update_request(incremental: bool, w: usize, h: usize) -> Vec<u8> {
    let mut m = vec![3, u8::from(incremental), 0, 0, 0, 0];
    m.extend_from_slice(&(w as u16).to_be_bytes());
    m.extend_from_slice(&(h as u16).to_be_bytes());
    m
}

fn mark(state: &mut State, rect: Rect) {
    if rect.w == 0 || rect.h == 0 {
        return;
    }
    state.dirty.push(rect);
    if state.dirty.len() > 24 {
        let all = state.dirty.drain(..).reduce(Rect::union);
        state.dirty.extend(all);
    }
}

fn resize(state: &mut State, w: usize, h: usize) {
    if (state.fb.w, state.fb.h) != (w, h) {
        state.fb = Fb::new(w, h);
        state.resized = true;
        state.dirty.clear();
    }
}

fn session(shared: &Arc<Shared>, mut stream: UnixStream) -> Result<(), String> {
    let (w, h, name) = handshake(&mut stream)?;
    if w == 0 || h == 0 || w > MAX_SIDE || h > MAX_SIDE {
        return Err("the screen has no usable size".into());
    }
    let mut zrle = zrle::Zrle::new();
    {
        let mut state = shared.state();
        state.fb = Fb::new(w, h);
        state.dirty.clear();
        state.resized = true;
        state.have_frame = true;
        state.ext_keys = false;
        state.absolute = true;
        state.name = name;
        state.status = ScreenStatus::Connected;
    }
    let mut hello = setup_messages();
    hello.extend_from_slice(&update_request(false, w, h));
    shared.send(&hello);
    (shared.wake)();
    loop {
        match read_u8(&mut stream)? {
            0 => {
                read_u8(&mut stream)?;
                let rects = read_u16(&mut stream)?;
                let mut full = false;
                for _ in 0..rects {
                    full |= rect(shared, &mut stream, &mut zrle)?;
                }
                let (w, h) = {
                    let state = shared.state();
                    (state.fb.w, state.fb.h)
                };
                shared.send(&update_request(!full, w, h));
                (shared.wake)();
            }
            1 => {
                read_u8(&mut stream)?;
                read_u16(&mut stream)?;
                let n = usize::from(read_u16(&mut stream)?);
                read_vec(&mut stream, n * 6)?;
            }
            2 => {}
            3 => {
                read_vec(&mut stream, 3)?;
                let n = read_u32(&mut stream)? as usize;
                read_vec(&mut stream, n.min(1 << 20))?;
            }
            other => return Err(format!("unknown RFB message {other}")),
        }
    }
}

/// One rectangle of an update; true when the screen changed size (the server
/// then needs a full request).
fn rect(shared: &Shared, stream: &mut UnixStream, zrle: &mut zrle::Zrle) -> Result<bool, String> {
    let x = usize::from(read_u16(stream)?);
    let y = usize::from(read_u16(stream)?);
    let w = usize::from(read_u16(stream)?);
    let h = usize::from(read_u16(stream)?);
    let encoding = read_u32(stream)? as i32;
    let r = Rect { x, y, w, h };
    match encoding {
        ENC_RAW | ENC_ZRLE | ENC_COPYRECT => {
            {
                let state = shared.state();
                if x + w > state.fb.w || y + h > state.fb.h {
                    return Err("an update is outside the screen".into());
                }
            }
            match encoding {
                ENC_RAW => {
                    let data = read_vec(stream, w * h * 4)?;
                    let mut state = shared.state();
                    let fb_w = state.fb.w;
                    for row in 0..h {
                        let at = ((y + row) * fb_w + x) * 4;
                        let src = &data[row * w * 4..(row + 1) * w * 4];
                        state.fb.rgba[at..at + w * 4].copy_from_slice(src);
                        for px in 0..w {
                            state.fb.rgba[at + px * 4 + 3] = 255;
                        }
                    }
                    mark(&mut state, r);
                }
                ENC_COPYRECT => {
                    let sx = usize::from(read_u16(stream)?);
                    let sy = usize::from(read_u16(stream)?);
                    let mut state = shared.state();
                    if sx + w > state.fb.w || sy + h > state.fb.h {
                        return Err("a copy is outside the screen".into());
                    }
                    let fb_w = state.fb.w;
                    let mut copy = Vec::with_capacity(w * h * 4);
                    for row in 0..h {
                        let at = ((sy + row) * fb_w + sx) * 4;
                        copy.extend_from_slice(&state.fb.rgba[at..at + w * 4]);
                    }
                    for row in 0..h {
                        let at = ((y + row) * fb_w + x) * 4;
                        state.fb.rgba[at..at + w * 4]
                            .copy_from_slice(&copy[row * w * 4..(row + 1) * w * 4]);
                    }
                    mark(&mut state, r);
                }
                _ => {
                    let len = read_u32(stream)? as usize;
                    let data = read_vec(stream, len)?;
                    let mut state = shared.state();
                    zrle.decode(&data, r, &mut state.fb)?;
                    mark(&mut state, r);
                }
            }
            Ok(false)
        }
        ENC_DESKTOP_SIZE => {
            if w == 0 || h == 0 || w > MAX_SIDE || h > MAX_SIDE {
                return Err("the screen resized to an unusable size".into());
            }
            resize(&mut shared.state(), w, h);
            Ok(true)
        }
        ENC_EXT_DESKTOP_SIZE => {
            let screens = usize::from(read_u8(stream)?);
            read_vec(stream, 3 + screens * 16)?;
            // x: why (0 first update, 1 this client, 2 another); y: 0 when it worked.
            if y != 0 || w == 0 || h == 0 || w > MAX_SIDE || h > MAX_SIDE {
                return Ok(false);
            }
            let changed = {
                let state = shared.state();
                (state.fb.w, state.fb.h) != (w, h)
            };
            if changed {
                resize(&mut shared.state(), w, h);
            }
            Ok(changed)
        }
        ENC_EXT_KEY => {
            shared.state().ext_keys = true;
            Ok(false)
        }
        ENC_POINTER_TYPE => {
            // x-position: 1 absolute, 0 relative.
            shared.state().absolute = x == 1;
            Ok(false)
        }
        ENC_CURSOR => {
            let pixels = read_vec(stream, w * h * 4)?;
            let mask = read_vec(stream, w.div_ceil(8) * h)?;
            let mut rgba = pixels;
            for row in 0..h {
                for col in 0..w {
                    let set = mask[row * w.div_ceil(8) + col / 8] >> (7 - col % 8) & 1 == 1;
                    rgba[(row * w + col) * 4 + 3] = if set { 255 } else { 0 };
                }
            }
            let mut state = shared.state();
            state.cursor = (w > 0 && h > 0).then(|| {
                Arc::new(Cursor {
                    hotspot: (x, y),
                    width: w,
                    height: h,
                    rgba,
                })
            });
            state.cursor_generation += 1;
            Ok(false)
        }
        other => Err(format!("unsupported RFB encoding {other}")),
    }
}

/// A PNG (8-bit RGB) of an RGBA frame, for a screenshot of the VM screen.
pub fn encode_png(width: usize, height: usize, rgba: &[u8]) -> Result<Vec<u8>, String> {
    use flate2::{Compression, Crc, write::ZlibEncoder};
    if width == 0 || height == 0 || rgba.len() != width * height * 4 {
        return Err("the screen has no picture to save".into());
    }
    let mut raw = Vec::with_capacity(height * (width * 3 + 1));
    for row in rgba.chunks_exact(width * 4) {
        raw.push(0);
        for px in row.as_chunks::<4>().0.iter() {
            raw.extend_from_slice(&px[..3]);
        }
    }
    let mut zlib = ZlibEncoder::new(Vec::new(), Compression::fast());
    zlib.write_all(&raw).map_err(|e| e.to_string())?;
    let data = zlib.finish().map_err(|e| e.to_string())?;
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut chunk = |kind: &[u8; 4], body: &[u8]| {
        png.extend_from_slice(&(body.len() as u32).to_be_bytes());
        png.extend_from_slice(kind);
        png.extend_from_slice(body);
        let mut crc = Crc::new();
        crc.update(kind);
        crc.update(body);
        png.extend_from_slice(&crc.sum().to_be_bytes());
    };
    let mut header = Vec::with_capacity(13);
    header.extend_from_slice(&(width as u32).to_be_bytes());
    header.extend_from_slice(&(height as u32).to_be_bytes());
    header.extend_from_slice(&[8, 2, 0, 0, 0]);
    chunk(b"IHDR", &header);
    chunk(b"IDAT", &data);
    chunk(b"IEND", &[]);
    Ok(png)
}
