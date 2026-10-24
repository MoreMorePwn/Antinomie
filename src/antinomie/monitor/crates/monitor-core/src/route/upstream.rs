// SPDX-License-Identifier: GPL-3.0-only
//! Dialing a guest connection's upstream side and moving bytes between it and
//! the gateway. A route never falls back to another: [`dial`] does what the
//! route's [`Egress`] says or fails.
use super::{
    config::{Egress, Sink},
    inetsim,
    socks::{self, Target},
};
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs},
    os::unix::net::UnixStream,
    sync::{
        Arc,
        mpsc::{Receiver, SyncSender, sync_channel},
    },
    thread,
    time::Duration,
};

const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const SINK_TIMEOUT: Duration = Duration::from_secs(3);
/// Chunks waiting for the writer / for the gateway, per connection.
const UP_QUEUE: usize = 32;
const DOWN_QUEUE: usize = 8;
const CHUNK: usize = 16 * 1024;

/// What a guest connection is addressed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Dest {
    Ip(Ipv4Addr, u16),
    /// A name the gateway's DNS gave out an address for.
    Name(String, u16),
}

impl Dest {
    pub fn port(&self) -> u16 {
        match self {
            Dest::Ip(_, port) | Dest::Name(_, port) => *port,
        }
    }
}

/// Why a destination is refused before anything is dialed.
pub(crate) fn destination_refusal(egress: &Egress, ip: Ipv4Addr) -> Option<&'static str> {
    if matches!(egress, Egress::Sink(_)) {
        return None;
    }
    let octets = ip.octets();
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || octets[0] == 0
        || octets[0] >= 240
    {
        return Some("a special-purpose address");
    }
    if let Egress::Direct { allow_lan: false } = egress
        && (ip.is_private() || (octets[0] == 100 && (octets[1] & 0xc0) == 64))
    {
        return Some("a private network address (allow it in Settings > Network routes)");
    }
    None
}

pub(crate) enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Stream {
    fn try_clone(&self) -> std::io::Result<Stream> {
        Ok(match self {
            Stream::Tcp(s) => Stream::Tcp(s.try_clone()?),
            Stream::Unix(s) => Stream::Unix(s.try_clone()?),
        })
    }

    fn shutdown(&self, how: Shutdown) {
        let _ = match self {
            Stream::Tcp(s) => s.shutdown(how),
            Stream::Unix(s) => s.shutdown(how),
        };
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.read(buf),
            Stream::Unix(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.write(buf),
            Stream::Unix(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Tcp(s) => s.flush(),
            Stream::Unix(s) => s.flush(),
        }
    }
}

/// The upstream connection for `dest` under `egress`.
pub(crate) fn dial(egress: &Egress, dest: &Dest) -> Result<Stream, String> {
    if let Dest::Ip(ip, _) = dest
        && let Some(why) = destination_refusal(egress, *ip)
    {
        return Err(format!("{ip} is {why}"));
    }
    match egress {
        Egress::Drop => Err("this route drops all traffic".into()),
        Egress::Direct { .. } => {
            let Dest::Ip(ip, port) = dest else {
                return Err("the Internet route cannot connect to a name".into());
            };
            let stream = TcpStream::connect_timeout(&SocketAddr::from((*ip, *port)), DIAL_TIMEOUT)
                .map_err(|e| format!("{ip}:{port}: {e}"))?;
            let _ = stream.set_nodelay(true);
            Ok(Stream::Tcp(stream))
        }
        Egress::Sink(sink) => dial_sink(sink, dest.port()),
        Egress::Socks(proxy) => {
            let target = match dest {
                Dest::Ip(ip, _) => Target::Ip(*ip),
                Dest::Name(name, _) => Target::Name(name.clone()),
            };
            socks::connect(proxy, &target, dest.port(), DIAL_TIMEOUT).map(Stream::Tcp)
        }
    }
}

fn dial_sink(sink: &Sink, port: u16) -> Result<Stream, String> {
    let Some((host, offset)) = &sink.external else {
        let (guest_side, service_side) =
            UnixStream::pair().map_err(|e| format!("built-in service: {e}"))?;
        inetsim::spawn(port, service_side)?;
        return Ok(Stream::Unix(guest_side));
    };
    let target = port
        .checked_add(*offset)
        .ok_or_else(|| format!("port {port} + offset {offset} is above 65535"))?;
    let address = (host.as_str(), target)
        .to_socket_addrs()
        .map_err(|e| format!("INetSim {host}:{target}: {e}"))?
        .next()
        .ok_or_else(|| format!("INetSim {host}:{target} has no address"))?;
    let stream = TcpStream::connect_timeout(&address, SINK_TIMEOUT)
        .map_err(|e| format!("INetSim {host}:{target}: {e}"))?;
    let _ = stream.set_nodelay(true);
    Ok(Stream::Tcp(stream))
}

/// Bytes for the upstream side.
pub(crate) enum UpMsg {
    Data(Vec<u8>),
    /// The guest finished sending.
    Shutdown,
}

/// Bytes from the upstream side.
pub(crate) enum Down {
    Data(Vec<u8>),
    Eof,
    Failed,
}

/// The two queues of one established connection. Dropping `up` closes the
/// upstream connection.
pub(crate) struct Pipes {
    pub up: SyncSender<UpMsg>,
    pub down: Receiver<Down>,
    closer: Stream,
}

impl Drop for Pipes {
    fn drop(&mut self) {
        // Ends both threads even when one is blocked in a read or write.
        self.closer.shutdown(Shutdown::Both);
    }
}

/// Starts the threads that move bytes. `notify` is called after each item is
/// queued for the gateway.
pub(crate) fn start_pipes(
    stream: Stream,
    notify: Arc<dyn Fn() + Send + Sync>,
) -> Result<Pipes, String> {
    let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
    let closer = stream.try_clone().map_err(|e| e.to_string())?;
    let mut reader = stream;
    let (up, up_rx) = sync_channel::<UpMsg>(UP_QUEUE);
    let (down_tx, down) = sync_channel::<Down>(DOWN_QUEUE);
    thread::Builder::new()
        .name("route-up".into())
        .spawn(move || {
            for message in up_rx {
                match message {
                    UpMsg::Data(bytes) => {
                        if writer.write_all(&bytes).is_err() {
                            break;
                        }
                    }
                    UpMsg::Shutdown => writer.shutdown(Shutdown::Write),
                }
            }
            // The gateway let go of the connection, or the write failed:
            // closing both ways also ends the reader.
            writer.shutdown(Shutdown::Both);
        })
        .map_err(|e| e.to_string())?;
    thread::Builder::new()
        .name("route-down".into())
        .spawn(move || {
            let mut buffer = vec![0u8; CHUNK];
            loop {
                let item = match reader.read(&mut buffer) {
                    Ok(0) => Down::Eof,
                    Ok(len) => Down::Data(buffer[..len].to_vec()),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => Down::Failed,
                };
                let last = !matches!(item, Down::Data(_));
                if down_tx.send(item).is_err() {
                    break;
                }
                notify();
                if last {
                    break;
                }
            }
            reader.shutdown(Shutdown::Both);
        })
        .map_err(|e| e.to_string())?;
    Ok(Pipes { up, down, closer })
}
