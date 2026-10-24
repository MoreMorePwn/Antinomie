//! A SOCKS5 server for the tests. It is also the destination: it never
//! dials out, it plays the far end itself.
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

/// What the far end does after the proxy says connected.
#[derive(Clone)]
pub enum FarEnd {
    /// Sends back what it receives.
    Echo,
    /// Sends this many bytes of a repeating pattern after the first byte
    /// it receives.
    Flood(usize),
}

#[derive(Clone, Default)]
pub struct Options {
    pub login: Option<(String, String)>,
    /// Host names or addresses the proxy refuses (reply 5).
    pub refuse: Vec<String>,
    /// Closes every connection right after the greeting.
    pub hang_up: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    /// 1 for an IPv4 address, 3 for a name.
    pub atyp: u8,
    pub host: String,
    pub port: u16,
    pub login: Option<(String, String)>,
}

pub struct FakeSocks {
    port: u16,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
}

impl FakeSocks {
    pub fn start(options: Options, far: FarEnd) -> FakeSocks {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen2, stop2) = (seen.clone(), stop.clone());
        thread::spawn(move || {
            while !stop2.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let (options, far, seen) = (options.clone(), far.clone(), seen2.clone());
                        thread::spawn(move || {
                            let _ = serve(stream, &options, &far, &seen);
                        });
                    }
                    Err(_) => thread::sleep(Duration::from_millis(10)),
                }
            }
        });
        FakeSocks { port, seen, stop }
    }

    pub fn echo() -> FakeSocks {
        FakeSocks::start(Options::default(), FarEnd::Echo)
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Connection requests that reached the far end, oldest first.
    pub fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for FakeSocks {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn byte(stream: &mut TcpStream) -> std::io::Result<u8> {
    let mut one = [0u8; 1];
    stream.read_exact(&mut one)?;
    Ok(one[0])
}

fn serve(
    mut stream: TcpStream,
    options: &Options,
    far: &FarEnd,
    seen: &Mutex<Vec<Seen>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    if byte(&mut stream)? != 5 {
        return Ok(());
    }
    let count = byte(&mut stream)?;
    let mut methods = vec![0u8; usize::from(count)];
    stream.read_exact(&mut methods)?;
    if options.hang_up {
        return Ok(());
    }
    let mut login = None;
    if let Some((user, password)) = &options.login {
        if !methods.contains(&2) {
            return stream.write_all(&[5, 0xff]);
        }
        stream.write_all(&[5, 2])?;
        byte(&mut stream)?;
        let ulen = usize::from(byte(&mut stream)?);
        let mut given_user = vec![0u8; ulen];
        stream.read_exact(&mut given_user)?;
        let plen = usize::from(byte(&mut stream)?);
        let mut given_pass = vec![0u8; plen];
        stream.read_exact(&mut given_pass)?;
        let given = (
            String::from_utf8_lossy(&given_user).into_owned(),
            String::from_utf8_lossy(&given_pass).into_owned(),
        );
        let ok = given == (user.clone(), password.clone());
        stream.write_all(&[1, u8::from(!ok)])?;
        if !ok {
            return Ok(());
        }
        login = Some(given);
    } else {
        stream.write_all(&[5, 0])?;
    }
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    let (atyp, host) = match head[3] {
        1 => {
            let mut address = [0u8; 4];
            stream.read_exact(&mut address)?;
            (1, std::net::Ipv4Addr::from(address).to_string())
        }
        3 => {
            let len = usize::from(byte(&mut stream)?);
            let mut name = vec![0u8; len];
            stream.read_exact(&mut name)?;
            (3, String::from_utf8_lossy(&name).into_owned())
        }
        _ => return stream.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port)?;
    let port = u16::from_be_bytes(port);
    seen.lock().unwrap().push(Seen {
        atyp,
        host: host.clone(),
        port,
        login,
    });
    if options.refuse.contains(&host) {
        return stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
    }
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    let mut buffer = [0u8; 8192];
    match far {
        FarEnd::Echo => loop {
            let len = stream.read(&mut buffer)?;
            if len == 0 {
                return Ok(());
            }
            stream.write_all(&buffer[..len])?;
        },
        FarEnd::Flood(total) => {
            let _ = stream.read(&mut buffer)?;
            let pattern: Vec<u8> = (0..*total).map(|n| (n % 251) as u8).collect();
            stream.write_all(&pattern)?;
            stream.shutdown(std::net::Shutdown::Write)?;
            while stream.read(&mut buffer)? != 0 {}
            Ok(())
        }
    }
}
