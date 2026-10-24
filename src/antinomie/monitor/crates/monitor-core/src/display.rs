use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use std::{
    io,
    os::unix::net::UnixStream,
    path::Path,
    process::Child,
    thread,
    time::{Duration, Instant},
};
use x11rb::reexports::x11rb_protocol::{
    parse_display::{ConnectAddress, parse_display},
    xauth::get_auth,
};
use x11rb::{
    connection::Connection,
    protocol::xproto::{AtomEnum, ConfigureWindowAux, ConnectionExt, MapState, Window},
    rust_connection::{DefaultStream, PollMode, RustConnection, Stream},
    utils::RawFdContainer,
};

const INITIAL_SIZE_TIMEOUT: Duration = Duration::from_secs(5);
const WINDOW_LIMIT: usize = 4096;

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "initial X11 window sizing timed out",
            )
        })
}

fn wait_fd(fd: &impl std::os::fd::AsFd, flags: PollFlags, deadline: Instant) -> io::Result<()> {
    loop {
        let duration = remaining(deadline)?;
        let timeout = Timespec {
            tv_sec: duration.as_secs() as _,
            tv_nsec: duration.subsec_nanos() as _,
        };
        match poll(&mut [PollFd::new(fd, flags)], Some(&timeout)) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "initial X11 window sizing timed out",
                ));
            }
            Ok(_) => return Ok(()),
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

struct DeadlineStream {
    stream: DefaultStream,
    deadline: Instant,
}
impl Stream for DeadlineStream {
    fn poll(&self, mode: PollMode) -> io::Result<()> {
        let mut flags = PollFlags::empty();
        if mode.readable() {
            flags |= PollFlags::IN;
        }
        if mode.writable() {
            flags |= PollFlags::OUT;
        }
        wait_fd(&self.stream, flags, self.deadline)
    }
    fn read(&self, buf: &mut [u8], fds: &mut Vec<RawFdContainer>) -> io::Result<usize> {
        remaining(self.deadline)?;
        self.stream.read(buf, fds)
    }
    fn write(&self, buf: &[u8], fds: &mut Vec<RawFdContainer>) -> io::Result<usize> {
        remaining(self.deadline)?;
        self.stream.write(buf, fds)
    }
}

fn connect_socket(address: &SocketAddrUnix, deadline: Instant) -> io::Result<UnixStream> {
    loop {
        remaining(deadline)?;
        let socket = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )?;
        match rustix::net::connect(&socket, address) {
            Ok(()) => return Ok(socket.into()),
            Err(rustix::io::Errno::INPROGRESS) => {
                wait_fd(&socket, PollFlags::OUT, deadline)?;
                rustix::net::sockopt::socket_error(&socket)??;
                return Ok(socket.into());
            }
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {
                thread::sleep(remaining(deadline)?.min(Duration::from_millis(20)));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn local_display(display: &str) -> Result<(String, usize, u16), String> {
    let parsed = parse_display(Some(display)).map_err(|error| error.to_string())?;
    let socket = parsed.connect_instruction().find_map(|address| match address {
        ConnectAddress::Socket(path) => Some(path),
        _ => None,
    }).ok_or("fixed fitted windows require a local X11/XWayland DISPLAY (for example :0); remote X11 is unsupported")?;
    Ok((socket, parsed.screen.into(), parsed.display))
}

fn check_authority_file() -> Result<(), String> {
    let path = std::env::var_os("XAUTHORITY")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| Path::new(&home).join(".Xauthority")));
    if let Some(path) = path {
        match std::fs::metadata(path) {
            Ok(metadata) if !metadata.is_file() || metadata.len() > 1024 * 1024 => {
                return Err("XAUTHORITY must be a regular file no larger than 1 MiB".into());
            }
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error.to_string()),
            _ => {}
        }
    }
    Ok(())
}

pub(crate) struct InitialWindowSize {
    connection: RustConnection<DeadlineStream>,
    screen: usize,
    deadline: Instant,
    pid_atom: u32,
}
impl InitialWindowSize {
    pub(crate) fn before_spawn(&self) -> Result<(), String> {
        remaining(self.deadline)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
    pub(crate) fn prepare() -> Result<Self, String> {
        let display = std::env::var("DISPLAY").map_err(|_| "fixed fitted windows require local X11/XWayland; set DISPLAY or disable Fit to window (pure Wayland is unsupported)".to_owned())?;
        Self::connect(&display, Instant::now() + INITIAL_SIZE_TIMEOUT)
            .map_err(|error| format!("initial QEMU window sizing: {error}; use local X11/XWayland or disable Fit to window"))
    }
    fn connect(display: &str, deadline: Instant) -> Result<Self, String> {
        let (path, screen, number) = local_display(display)?;
        check_authority_file()?;
        let abstract_address = SocketAddrUnix::new_abstract_name(path.as_bytes())
            .map_err(|error| error.to_string())?;
        let socket = connect_socket(&abstract_address, deadline)
            .or_else(|_| {
                let address = SocketAddrUnix::new(path.as_str())?;
                connect_socket(&address, deadline)
            })
            .map_err(|error| error.to_string())?;
        let (stream, (family, address)) =
            DefaultStream::from_unix_stream(socket).map_err(|error| error.to_string())?;
        let (auth_name, auth_data) = get_auth(family, &address, number)
            .or_else(|error| {
                // Like x11rb's default connector, let the X server decide
                // whether this local peer needs a cookie when none is readable.
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) {
                    Ok(None)
                } else {
                    Err(error)
                }
            })
            .map_err(|error| error.to_string())?
            .unwrap_or_default();
        let connection = RustConnection::connect_to_stream_with_auth_info(
            DeadlineStream { stream, deadline },
            screen,
            auth_name,
            auth_data,
        )
        .map_err(|error| error.to_string())?;
        let pid_atom = connection
            .intern_atom(false, b"_NET_WM_PID")
            .map_err(|error| error.to_string())?
            .reply()
            .map_err(|error| error.to_string())?
            .atom;
        Ok(Self {
            connection,
            screen,
            deadline,
            pid_atom,
        })
    }
    pub(crate) fn apply(self, child: &mut Child, width: u16, height: u16) -> Result<(), String> {
        self.apply_inner(child, width, height)
            .map_err(|error| format!("initial QEMU window sizing: {error}"))
    }
    fn apply_inner(&self, child: &mut Child, width: u16, height: u16) -> Result<(), String> {
        let screen = &self.connection.setup().roots[self.screen];
        let window = loop {
            remaining(self.deadline).map_err(|error| error.to_string())?;
            if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                return Err(format!("QEMU exited before creating its window ({status})"));
            }
            if let Some(window) = self.find_window(screen.root, child.id())? {
                break window;
            }
            thread::sleep(
                remaining(self.deadline)
                    .map_err(|error| error.to_string())?
                    .min(Duration::from_millis(20)),
            );
        };
        let frame_atom = self
            .connection
            .intern_atom(false, b"_NET_FRAME_EXTENTS")
            .map_err(|error| error.to_string())?
            .reply()
            .map_err(|error| error.to_string())?
            .atom;
        let frame = self
            .connection
            .get_property(false, window, frame_atom, AtomEnum::CARDINAL, 0, 4)
            .map_err(|error| error.to_string())?
            .reply()
            .map_err(|error| error.to_string())?;
        let mut extents = frame.value32().into_iter().flatten();
        let horizontal = extents
            .next()
            .unwrap_or(0)
            .saturating_add(extents.next().unwrap_or(0));
        let vertical = extents
            .next()
            .unwrap_or(0)
            .saturating_add(extents.next().unwrap_or(0));
        let (width, height) = clamped_size(
            width,
            height,
            screen
                .width_in_pixels
                .saturating_sub(horizontal.min(u32::from(u16::MAX)) as u16),
            screen
                .height_in_pixels
                .saturating_sub(vertical.min(u32::from(u16::MAX)) as u16),
        );
        self.connection
            .configure_window(
                window,
                &ConfigureWindowAux::new()
                    .width(u32::from(width))
                    .height(u32::from(height)),
            )
            .map_err(|error| error.to_string())?
            .check()
            .map_err(|error| error.to_string())?;
        self.connection.flush().map_err(|error| error.to_string())?;
        loop {
            remaining(self.deadline).map_err(|error| error.to_string())?;
            let geometry = self
                .connection
                .get_geometry(window)
                .map_err(|error| error.to_string())?
                .reply()
                .map_err(|error| error.to_string())?;
            if geometry.width == width && geometry.height == height {
                return Ok(());
            }
            if child
                .try_wait()
                .map_err(|error| error.to_string())?
                .is_some()
            {
                return Err("QEMU exited before window resize confirmation".into());
            }
            thread::sleep(
                remaining(self.deadline)
                    .map_err(|error| error.to_string())?
                    .min(Duration::from_millis(20)),
            );
        }
    }
    fn find_window(&self, root: Window, pid: u32) -> Result<Option<Window>, String> {
        let mut windows = vec![(root, 0)];
        let mut index = 0;
        while index < windows.len() {
            remaining(self.deadline).map_err(|error| error.to_string())?;
            let (window, depth) = windows[index];
            index += 1;
            let property = self
                .connection
                .get_property(false, window, self.pid_atom, AtomEnum::CARDINAL, 0, 1)
                .map_err(|error| error.to_string())?
                .reply();
            if let Ok(property) = property
                && property
                    .value32()
                    .is_some_and(|mut values| values.next() == Some(pid))
            {
                let class = self
                    .connection
                    .get_property(false, window, AtomEnum::WM_CLASS, AtomEnum::STRING, 0, 64)
                    .map_err(|error| error.to_string())?
                    .reply()
                    .map_err(|error| error.to_string())?;
                let attributes = self
                    .connection
                    .get_window_attributes(window)
                    .map_err(|error| error.to_string())?
                    .reply()
                    .map_err(|error| error.to_string())?;
                if qemu_class(&class.value) && attributes.map_state == MapState::VIEWABLE {
                    return Ok(Some(window));
                }
            }
            if depth < 4
                && let Ok(tree) = self
                    .connection
                    .query_tree(window)
                    .map_err(|error| error.to_string())?
                    .reply()
            {
                if windows.len() + tree.children.len() > WINDOW_LIMIT {
                    return Err("X11 window tree exceeds sizing limit".into());
                }
                windows.extend(tree.children.into_iter().map(|child| (child, depth + 1)));
            }
        }
        Ok(None)
    }
    #[cfg(test)]
    pub(crate) fn stalled_for_test(timeout: Duration) -> (Self, UnixStream) {
        let (client, server) = UnixStream::pair().unwrap();
        let (stream, _) = DefaultStream::from_unix_stream(client).unwrap();
        let deadline = Instant::now() + timeout;
        let setup = x11rb::protocol::xproto::Setup {
            resource_id_base: 0x100000,
            resource_id_mask: 0xfffff,
            maximum_request_length: u16::MAX,
            roots: vec![x11rb::protocol::xproto::Screen {
                root: 1,
                width_in_pixels: 1920,
                height_in_pixels: 1200,
                ..Default::default()
            }],
            ..Default::default()
        };
        let connection =
            RustConnection::for_connected_stream(DeadlineStream { stream, deadline }, setup)
                .unwrap();
        (
            Self {
                connection,
                screen: 0,
                deadline,
                pid_atom: 1,
            },
            server,
        )
    }
}

fn qemu_class(value: &[u8]) -> bool {
    value.split(|byte| *byte == 0).any(|part| {
        part.eq_ignore_ascii_case(b"qemu")
            || part
                .get(..5)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"qemu-"))
    })
}
fn clamped_size(width: u16, height: u16, screen_width: u16, screen_height: u16) -> (u16, u16) {
    (
        width.min(screen_width).max(1),
        height.min(screen_height).max(1),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires QEMU GTK and a local X11 display with an EWMH window manager"]
    fn native_qemu_largest_window_fits_decorated_screen() {
        let sizing = InitialWindowSize::prepare().unwrap();
        let mut child = std::process::Command::new("qemu-system-x86_64")
            .args([
                "-S",
                "-accel",
                "tcg",
                "-m",
                "256",
                "-smp",
                "4",
                "-nic",
                "none",
                "-vga",
                "none",
                "-device",
                "virtio-gpu-pci,edid=on,xres=2560,yres=1440",
                "-display",
                "gtk,zoom-to-fit=on,show-menubar=off,show-tabs=off",
                "-monitor",
                "none",
                "-serial",
                "none",
            ])
            .env("GDK_BACKEND", "x11")
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let result = (|| -> Result<(), String> {
            sizing.apply(&mut child, 2560, 1440)?;
            let probe = InitialWindowSize::prepare()?;
            let screen = &probe.connection.setup().roots[probe.screen];
            let window = probe
                .find_window(screen.root, child.id())?
                .ok_or("owned window missing")?;
            let geometry = probe
                .connection
                .get_geometry(window)
                .map_err(|e| e.to_string())?
                .reply()
                .map_err(|e| e.to_string())?;
            let atom = probe
                .connection
                .intern_atom(false, b"_NET_FRAME_EXTENTS")
                .map_err(|e| e.to_string())?
                .reply()
                .map_err(|e| e.to_string())?
                .atom;
            let frame = probe
                .connection
                .get_property(false, window, atom, AtomEnum::CARDINAL, 0, 4)
                .map_err(|e| e.to_string())?
                .reply()
                .map_err(|e| e.to_string())?;
            let extents: Vec<_> = frame.value32().ok_or("WM frame extents absent")?.collect();
            if extents.len() != 4 {
                return Err("incomplete WM frame extents".into());
            }
            let expected = clamped_size(
                2560,
                1440,
                screen
                    .width_in_pixels
                    .saturating_sub((extents[0] + extents[1]) as u16),
                screen
                    .height_in_pixels
                    .saturating_sub((extents[2] + extents[3]) as u16),
            );
            if (geometry.width, geometry.height) != expected {
                return Err(format!(
                    "drawable {:?} differs from decorated screen clamp {expected:?}",
                    (geometry.width, geometry.height)
                ));
            }
            println!(
                "WINDOW_CLAMP_PASS {}x{} frame={extents:?} screen={}x{}",
                geometry.width, geometry.height, screen.width_in_pixels, screen.height_in_pixels
            );
            Ok(())
        })();
        let killed = child.kill();
        let reaped = child.wait();
        killed.unwrap();
        reaped.unwrap();
        result.unwrap();
    }
    #[test]
    fn local_display_only_and_class_match_are_restricted() {
        assert!(local_display(":104").is_ok());
        assert!(local_display("remote.example:0").is_err());
        assert!(local_display("not a display").is_err());
        assert!(qemu_class(b"qemu-system-x86_64\0Qemu-system-x86_64\0"));
        assert!(!qemu_class(b"terminal\0Terminal\0"));
        assert!(!qemu_class(b"my-qemu-window\0"));
    }
    #[test]
    fn size_clamps_to_screen_without_padding() {
        assert_eq!(clamped_size(1280, 720, 1920, 1200), (1280, 720));
        assert_eq!(clamped_size(2560, 1440, 1920, 1200), (1920, 1200));
    }
    #[test]
    fn stalled_setup_obeys_deadline() {
        let (client, _server) = UnixStream::pair().unwrap();
        let (stream, _) = DefaultStream::from_unix_stream(client).unwrap();
        let start = Instant::now();
        let result = RustConnection::connect_to_stream(
            DeadlineStream {
                stream,
                deadline: start + Duration::from_millis(50),
            },
            0,
        );
        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_secs(30));
    }
    #[test]
    fn stalled_reply_and_missing_socket_are_bounded() {
        let (sizing, _server) = InitialWindowSize::stalled_for_test(Duration::from_millis(50));
        let start = Instant::now();
        assert!(
            sizing
                .connection
                .intern_atom(false, b"_NET_WM_PID")
                .unwrap()
                .reply()
                .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(30));
        let path = std::env::temp_dir().join(format!("ant-no-x11-{}", crate::storage::unique_id()));
        let address = SocketAddrUnix::new(path).unwrap();
        assert!(connect_socket(&address, Instant::now() + Duration::from_millis(50)).is_err());
    }
}
