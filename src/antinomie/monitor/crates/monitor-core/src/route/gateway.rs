// SPDX-License-Identifier: GPL-3.0-only
//! The gateway: QEMU's `-netdev stream` for the guest's NIC connects to a
//! local socket owned by this thread, which is the guest's router, DHCP and
//! DNS server and TCP endpoint. What happens to the guest's traffic is the
//! current route (see the module documentation). The thread starts on the
//! Drop route and a route only changes through [`Gateway::claim`], which
//! checks it first.
use super::{
    Counters, RouteKind, RouteStats,
    config::{Egress, RouteSpec},
    dhcp::{self, Lease},
    dns,
    frame::{self, BROADCAST, ETHERTYPE_ARP, ETHERTYPE_IPV4, Mac, TcpOut},
    managed::{self, Managed},
    names::FakeIps,
    probe,
    tcp::{Conn, Seg},
    upstream::{self, Dest, Pipes},
};
use std::{
    collections::{HashMap, VecDeque},
    hash::{BuildHasher, Hasher},
    io::{Read, Write},
    net::Ipv4Addr,
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{Receiver, Sender, channel},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// Connections the gateway carries at once.
const MAX_CONNECTIONS: usize = 256;
/// Frames waiting to be written to QEMU, bytes; later ones are dropped (TCP
/// sends them again).
const OUT_LIMIT: usize = 8 << 20;
const MAX_FRAME: usize = 65_536;
const DNS_TTL: u32 = 60;
const DNS_IN_FLIGHT: usize = 16;
const TICK: Duration = Duration::from_millis(100);
/// How long a wireproxy start may take before the route is called down.
const MANAGED_WAIT: Duration = Duration::from_secs(15);

/// The addresses the gateway uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatewayNet {
    pub network: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Ipv4Addr,
    pub dns: Ipv4Addr,
    pub guest: Ipv4Addr,
}

impl GatewayNet {
    /// QEMU's user-mode defaults, or the profile's NAT network.
    pub fn from_nat(nat: &crate::stealth::NatNetwork) -> Result<Self, String> {
        let (network, prefix, gateway, dns, guest) = nat.lease_plan()?;
        Ok(Self {
            network,
            prefix,
            gateway,
            dns,
            guest,
        })
    }

    fn mask(&self) -> u32 {
        u32::MAX << (32 - u32::from(self.prefix))
    }

    fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask() == u32::from(self.network)
    }

    fn lease(&self) -> Lease {
        Lease {
            guest: self.guest,
            gateway: self.gateway,
            dns: self.dns,
            mask: Ipv4Addr::from(self.mask()),
            broadcast: Ipv4Addr::from(u32::from(self.network) | !self.mask()),
        }
    }

    /// The gateway's own addresses: the router and the DNS server.
    fn is_local(&self, ip: Ipv4Addr) -> bool {
        ip == self.gateway || ip == self.dns
    }
}

/// The route in force and what keeps it running.
struct Active {
    spec: RouteSpec,
    _managed: Option<Managed>,
}

#[derive(Default)]
struct Claims {
    /// Runs using the route now.
    runs: Vec<String>,
    checked_ms: u64,
}

struct Shared {
    route: RwLock<Arc<Active>>,
    generation: AtomicU64,
    stop: AtomicBool,
    /// QEMU's NIC is connected to the socket.
    linked: AtomicBool,
    counters: Counters,
    claims: Mutex<Claims>,
    waker: Waker,
}

struct Waker(UnixStream);

impl Waker {
    fn wake(&self) {
        let _ = (&self.0).write(&[1]);
    }
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// What a run learns from claiming a route.
#[derive(Clone, Copy, Debug)]
pub struct Claimed {
    /// When the route was checked up (host Unix milliseconds).
    pub checked_ms: u64,
}

pub struct Gateway {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
    socket: PathBuf,
    work_dir: PathBuf,
}

impl Gateway {
    /// Listens on `<dir>/net.sock` for QEMU and starts the gateway thread on
    /// the Drop route. `dir` is also where helper programs write their logs.
    pub fn start(dir: &Path, net: GatewayNet) -> Result<Gateway, String> {
        let socket = dir.join("net.sock");
        if socket.as_os_str().len() > 100 {
            return Err("the network socket path is too long".into());
        }
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).map_err(|e| format!("network socket: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("network socket: {e}"))?;
        let (wake_rx, wake_tx) = UnixStream::pair().map_err(|e| format!("network wake: {e}"))?;
        wake_rx.set_nonblocking(true).map_err(|e| e.to_string())?;
        wake_tx.set_nonblocking(true).map_err(|e| e.to_string())?;
        let shared = Arc::new(Shared {
            route: RwLock::new(Arc::new(Active {
                spec: RouteSpec::drop_all(),
                _managed: None,
            })),
            generation: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            linked: AtomicBool::new(false),
            counters: Counters::default(),
            claims: Mutex::new(Claims::default()),
            waker: Waker(wake_tx),
        });
        let (events_tx, events) = channel();
        let state = Loop::new(shared.clone(), net, events, events_tx, wake_rx);
        let thread = thread::Builder::new()
            .name("route-gateway".into())
            .spawn(move || state.run(listener))
            .map_err(|e| format!("network gateway: {e}"))?;
        Ok(Gateway {
            shared,
            thread: Some(thread),
            socket,
            work_dir: dir.to_path_buf(),
        })
    }

    /// The socket QEMU's `-netdev stream` connects to.
    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    /// The `-netdev` value for the guest's NIC `net0`.
    pub fn netdev_option(&self) -> Result<String, String> {
        let path = self
            .socket
            .to_str()
            .filter(|path| !path.contains([',', '\n']))
            .ok_or("the network socket path cannot be given to QEMU")?;
        Ok(format!(
            "stream,id=net0,server=off,addr.type=unix,addr.path={path}"
        ))
    }

    /// QEMU has connected the guest's NIC to the gateway.
    pub fn linked(&self) -> bool {
        self.shared.linked.load(Ordering::SeqCst)
    }

    pub fn kind(&self) -> RouteKind {
        self.shared.current().spec.kind
    }

    pub fn stats(&self) -> RouteStats {
        self.shared.counters.snapshot()
    }

    /// Uses `spec` for run `run`. The first run to claim a route starts what
    /// it needs (wireproxy) and checks that it is up; a failure leaves the
    /// gateway on Drop and is the run's error. Runs that overlap must use
    /// the same route.
    pub fn claim(&self, run: &str, spec: RouteSpec) -> Result<Claimed, String> {
        let mut claims = self
            .shared
            .claims
            .lock()
            .map_err(|_| "route state is unusable")?;
        let current = self.shared.current();
        if !claims.runs.is_empty() {
            if current.spec.kind == spec.kind && current.spec.label == spec.label {
                if !claims.runs.iter().any(|r| r == run) {
                    claims.runs.push(run.to_owned());
                }
                return Ok(Claimed {
                    checked_ms: claims.checked_ms,
                });
            }
            return Err(format!(
                "another run in this VM is using the route \"{}\"; a VM has one route at a \
                 time. Wait for it to end, or use the same route",
                current.spec.label
            ));
        }
        let managed = match &spec.wireproxy {
            Some(launch) => {
                let socks = match &spec.egress {
                    Egress::Socks(proxy) => (proxy.host.clone(), proxy.port),
                    _ => return Err("VPN route without a SOCKS port".into()),
                };
                Some(managed::start_wireproxy(
                    launch,
                    (&socks.0, socks.1),
                    &self.work_dir,
                    MANAGED_WAIT,
                )?)
            }
            None => None,
        };
        // On failure `managed` is dropped here, which stops wireproxy.
        probe::check(&spec)?;
        let checked_ms = unix_ms();
        self.shared.install(Active {
            spec,
            _managed: managed,
        });
        claims.runs.push(run.to_owned());
        claims.checked_ms = checked_ms;
        Ok(Claimed { checked_ms })
    }

    /// Run `run` no longer needs its route; the last one out puts the
    /// gateway back on Drop and stops what the route started.
    pub fn release(&self, run: &str) {
        let Ok(mut claims) = self.shared.claims.lock() else {
            return;
        };
        claims.runs.retain(|r| r != run);
        if claims.runs.is_empty() {
            self.shared.install(Active {
                spec: RouteSpec::drop_all(),
                _managed: None,
            });
        }
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.waker.wake();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.socket);
    }
}

impl Shared {
    fn current(&self) -> Arc<Active> {
        self.route
            .read()
            .map(|route| route.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
    }

    /// Makes `active` the route and has the gateway reset every connection
    /// made under the old one.
    fn install(&self, active: Active) {
        let old = {
            let mut route = self
                .route
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::replace(&mut *route, Arc::new(active))
        };
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.waker.wake();
        drop(old);
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct Flow {
    guest_ip: Ipv4Addr,
    guest_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

enum Event {
    /// The upstream of connection `id` has bytes (or ended).
    Readable(u64),
    Dialed(u64, Result<Pipes, String>),
    /// A frame built off the loop (a resolved DNS answer).
    Frame(Vec<u8>),
}

/// The MAC address QEMU's user network gives an address of its own:
/// `52:55:` and the four bytes of the address.
fn mac_of(ip: Ipv4Addr) -> Mac {
    let octets = ip.octets();
    [0x52, 0x55, octets[0], octets[1], octets[2], octets[3]]
}

struct Loop {
    shared: Arc<Shared>,
    net: GatewayNet,
    mac: Mac,
    guest_mac: Option<Mac>,
    events: Receiver<Event>,
    events_tx: Sender<Event>,
    wake_rx: UnixStream,
    qemu: Option<UnixStream>,
    input: Vec<u8>,
    output: VecDeque<Vec<u8>>,
    output_pos: usize,
    output_len: usize,
    conns: HashMap<Flow, (u64, Conn)>,
    flows: HashMap<u64, Flow>,
    next_id: u64,
    seen_generation: u64,
    /// The generation the connections were last checked against.
    swept_generation: u64,
    fake: FakeIps,
    dns_in_flight: Arc<AtomicUsize>,
    seed: std::collections::hash_map::RandomState,
}

impl Loop {
    fn new(
        shared: Arc<Shared>,
        net: GatewayNet,
        events: Receiver<Event>,
        events_tx: Sender<Event>,
        wake_rx: UnixStream,
    ) -> Self {
        Loop {
            shared,
            net,
            mac: mac_of(net.gateway),
            guest_mac: None,
            events,
            events_tx,
            wake_rx,
            qemu: None,
            input: Vec::new(),
            output: VecDeque::new(),
            output_pos: 0,
            output_len: 0,
            conns: HashMap::new(),
            flows: HashMap::new(),
            next_id: 1,
            seen_generation: 0,
            swept_generation: 0,
            fake: FakeIps::default(),
            dns_in_flight: Arc::new(AtomicUsize::new(0)),
            seed: Default::default(),
        }
    }

    /// The route generation now. The names handed out under an older route
    /// are forgotten the first time a newer one is seen, before anything is
    /// answered or connected under it.
    fn sync_generation(&mut self) -> u64 {
        let generation = self.shared.generation.load(Ordering::SeqCst);
        if generation != self.seen_generation {
            self.seen_generation = generation;
            self.fake.clear();
        }
        generation
    }

    fn random(&self) -> u32 {
        let mut hasher = self.seed.build_hasher();
        hasher.write_u64(self.next_id);
        hasher.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        );
        hasher.finish() as u32
    }

    fn run(mut self, listener: UnixListener) {
        if !self.accept(&listener) {
            return;
        }
        drop(listener);
        self.shared.linked.store(true, Ordering::SeqCst);
        let mut last_tick = Instant::now();
        while !self.shared.stop.load(Ordering::SeqCst) {
            if !self.wait_for_work() {
                break;
            }
            let mut wake = [0u8; 64];
            while matches!((&self.wake_rx).read(&mut wake), Ok(n) if n > 0) {}
            if !self.read_frames() {
                break;
            }
            self.handle_events();
            let now = Instant::now();
            if now.duration_since(last_tick) >= TICK
                || self.swept_generation != self.shared.generation.load(Ordering::SeqCst)
            {
                last_tick = now;
                self.tick(now);
            }
            if !self.flush() {
                break;
            }
        }
        self.shared.linked.store(false, Ordering::SeqCst);
    }

    /// Waits for QEMU's connection; false when the gateway is stopped first.
    fn accept(&mut self, listener: &UnixListener) -> bool {
        while !self.shared.stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    if stream.set_nonblocking(true).is_err() {
                        return false;
                    }
                    self.qemu = Some(stream);
                    return true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    let mut fds = [
                        rustix::event::PollFd::new(listener, rustix::event::PollFlags::IN),
                        rustix::event::PollFd::new(&self.wake_rx, rustix::event::PollFlags::IN),
                    ];
                    let _ = rustix::event::poll(
                        &mut fds,
                        Some(&rustix::event::Timespec {
                            tv_sec: 1,
                            tv_nsec: 0,
                        }),
                    );
                    let mut wake = [0u8; 64];
                    while matches!((&self.wake_rx).read(&mut wake), Ok(n) if n > 0) {}
                }
                Err(_) => return false,
            }
        }
        false
    }

    fn wait_for_work(&mut self) -> bool {
        let Some(qemu) = &self.qemu else { return false };
        let mut flags = rustix::event::PollFlags::IN;
        if !self.output.is_empty() {
            flags |= rustix::event::PollFlags::OUT;
        }
        let mut fds = [
            rustix::event::PollFd::new(qemu, flags),
            rustix::event::PollFd::new(&self.wake_rx, rustix::event::PollFlags::IN),
        ];
        match rustix::event::poll(
            &mut fds,
            Some(&rustix::event::Timespec {
                tv_sec: 0,
                tv_nsec: TICK.as_nanos() as _,
            }),
        ) {
            Ok(_) | Err(rustix::io::Errno::INTR) => true,
            Err(_) => false,
        }
    }

    /// Reads and handles QEMU's frames; false when QEMU closed the socket.
    fn read_frames(&mut self) -> bool {
        let mut chunk = vec![0u8; 64 * 1024];
        for _ in 0..16 {
            let Some(qemu) = self.qemu.as_mut() else {
                return false;
            };
            match qemu.read(&mut chunk) {
                Ok(0) => return false,
                Ok(len) => self.input.extend_from_slice(&chunk[..len]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return false,
            }
        }
        let mut at = 0;
        while self.input.len() - at >= 4 {
            let len = u32::from_be_bytes([
                self.input[at],
                self.input[at + 1],
                self.input[at + 2],
                self.input[at + 3],
            ]) as usize;
            if len > MAX_FRAME {
                return false;
            }
            if self.input.len() - at < 4 + len {
                break;
            }
            let frame = self.input[at + 4..at + 4 + len].to_vec();
            at += 4 + len;
            self.frame(&frame);
        }
        self.input.drain(..at);
        true
    }

    /// Writes queued frames; false when the socket failed.
    fn flush(&mut self) -> bool {
        let Some(qemu) = self.qemu.as_mut() else {
            return false;
        };
        while let Some(front) = self.output.front() {
            match qemu.write(&front[self.output_pos..]) {
                Ok(len) => {
                    self.output_pos += len;
                    if self.output_pos == front.len() {
                        self.output_len -= front.len();
                        self.output_pos = 0;
                        self.output.pop_front();
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return false,
            }
        }
        true
    }

    fn send(&mut self, frame: &[u8]) {
        if self.output_len + frame.len() > OUT_LIMIT {
            return;
        }
        let mut queued = Vec::with_capacity(4 + frame.len());
        queued.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        queued.extend_from_slice(frame);
        self.output_len += queued.len();
        self.output.push_back(queued);
    }

    fn count(&self, counter: &AtomicU64) {
        Counters::add(counter, 1);
    }

    fn frame(&mut self, bytes: &[u8]) {
        let Some(eth) = frame::parse_eth(bytes) else {
            self.count(&self.shared.counters.other_dropped);
            return;
        };
        // Frames for another station on the guest's link are not ours.
        if eth.dst != self.mac && eth.dst != mac_of(self.net.dns) && eth.dst[0] & 1 == 0 {
            return;
        }
        if eth.src != BROADCAST && eth.src[0] & 1 == 0 {
            self.guest_mac = Some(eth.src);
        }
        match eth.ethertype {
            ETHERTYPE_ARP => self.arp(eth.payload),
            ETHERTYPE_IPV4 => self.ipv4(eth.payload),
            _ => self.count(&self.shared.counters.other_dropped),
        }
    }

    fn arp(&mut self, payload: &[u8]) {
        let Some(request) = frame::parse_arp(payload) else {
            return;
        };
        if request.operation == 1
            && !request.sender_ip.is_unspecified()
            && self.net.is_local(request.target_ip)
        {
            let reply = frame::build_arp_reply(
                mac_of(request.target_ip),
                request.target_ip,
                request.sender_mac,
                request.sender_ip,
            );
            self.send(&reply);
        }
    }

    fn frame_to_guest(&mut self, src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) {
        let mac = if dst == Ipv4Addr::BROADCAST {
            BROADCAST
        } else if let Some(mac) = self.guest_mac {
            mac
        } else {
            BROADCAST
        };
        let packet = frame::build_ipv4(src, dst, protocol, payload);
        let frame = frame::build_eth(mac, self.mac, ETHERTYPE_IPV4, &packet);
        self.send(&frame);
    }

    fn ipv4(&mut self, payload: &[u8]) {
        let Some(ip) = frame::parse_ipv4(payload) else {
            self.count(&self.shared.counters.other_dropped);
            return;
        };
        if ip.fragment {
            self.count(&self.shared.counters.other_dropped);
            return;
        }
        match ip.protocol {
            frame::PROTO_UDP => {
                let Some(udp) = frame::parse_udp(ip.payload) else {
                    self.count(&self.shared.counters.other_dropped);
                    return;
                };
                if udp.dst_port == 67 && udp.src_port == 68 {
                    if let Some(reply) = dhcp::reply(udp.payload, &self.net.lease()) {
                        let datagram =
                            frame::build_udp(self.net.gateway, Ipv4Addr::BROADCAST, 67, 68, &reply);
                        self.frame_to_guest(
                            self.net.gateway,
                            Ipv4Addr::BROADCAST,
                            frame::PROTO_UDP,
                            &datagram,
                        );
                    }
                } else if udp.dst_port == 53 {
                    self.dns_query(&ip, &udp);
                } else {
                    self.count(&self.shared.counters.udp_dropped);
                }
            }
            frame::PROTO_TCP => {
                if let Some(tcp) = frame::parse_tcp(ip.payload) {
                    self.tcp(&ip, &tcp);
                } else {
                    self.count(&self.shared.counters.other_dropped);
                }
            }
            frame::PROTO_ICMP => {
                if self.net.is_local(ip.dst)
                    && let Some(reply) = frame::build_icmp_echo_reply(ip.payload)
                {
                    self.frame_to_guest(ip.dst, ip.src, frame::PROTO_ICMP, &reply);
                } else {
                    self.count(&self.shared.counters.icmp_dropped);
                }
            }
            _ => self.count(&self.shared.counters.other_dropped),
        }
    }

    fn dns_query(&mut self, ip: &frame::Ipv4<'_>, udp: &frame::Udp<'_>) {
        self.sync_generation();
        let counters = &self.shared.counters;
        Counters::add(&counters.dns_queries, 1);
        let route = self.shared.current();
        let Some(query) = dns::parse_query(udp.payload) else {
            Counters::add(&counters.dns_unanswered, 1);
            return;
        };
        let answer = match &route.spec.egress {
            Egress::Drop => None,
            Egress::Sink(sink) if query.qtype == dns::TYPE_A => {
                Some(dns::answer_a(&query, &[sink.address], DNS_TTL))
            }
            Egress::Socks(_) if query.qtype == dns::TYPE_A => {
                let fake = self.fake.address_for(&query.name);
                Some(dns::answer_a(&query, &[fake], DNS_TTL))
            }
            Egress::Direct { .. } if query.qtype == dns::TYPE_A => {
                self.resolve_on_host(ip, udp, query);
                return;
            }
            // AAAA and every other type: the name exists, there is no
            // such record.
            Egress::Sink(_) | Egress::Socks(_) | Egress::Direct { .. } => {
                Some(dns::answer_empty(&query))
            }
        };
        match answer {
            Some(answer) => {
                let datagram = frame::build_udp(ip.dst, ip.src, 53, udp.src_port, &answer);
                self.frame_to_guest(ip.dst, ip.src, frame::PROTO_UDP, &datagram);
            }
            None => Counters::add(&counters.dns_unanswered, 1),
        }
    }

    /// The Internet route resolves with the host's resolver on a thread.
    fn resolve_on_host(&mut self, ip: &frame::Ipv4<'_>, udp: &frame::Udp<'_>, query: dns::Query) {
        if self.dns_in_flight.fetch_add(1, Ordering::SeqCst) >= DNS_IN_FLIGHT {
            self.dns_in_flight.fetch_sub(1, Ordering::SeqCst);
            Counters::add(&self.shared.counters.dns_unanswered, 1);
            return;
        }
        let (server, guest, port) = (ip.dst, ip.src, udp.src_port);
        let (mac, guest_mac) = (self.mac, self.guest_mac.unwrap_or(BROADCAST));
        let (tx, shared) = (self.events_tx.clone(), self.shared.clone());
        let spawned = thread::Builder::new()
            .name("route-dns".into())
            .spawn(move || {
                use std::net::ToSocketAddrs;
                let addresses: Vec<Ipv4Addr> = (query.name.as_str(), 0)
                    .to_socket_addrs()
                    .map(|found| {
                        found
                            .filter_map(|a| match a.ip() {
                                std::net::IpAddr::V4(v4) => Some(v4),
                                std::net::IpAddr::V6(_) => None,
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let answer = if addresses.is_empty() {
                    Counters::add(&shared.counters.dns_unanswered, 1);
                    dns::answer_nxdomain(&query)
                } else {
                    dns::answer_a(&query, &addresses, DNS_TTL)
                };
                let datagram = frame::build_udp(server, guest, 53, port, &answer);
                let packet = frame::build_ipv4(server, guest, frame::PROTO_UDP, &datagram);
                let _ = tx.send(Event::Frame(frame::build_eth(
                    guest_mac,
                    mac,
                    ETHERTYPE_IPV4,
                    &packet,
                )));
                shared.waker.wake();
            });
        if spawned.is_err() {
            Counters::add(&self.shared.counters.dns_unanswered, 1);
        }
        // The slot is freed when the answer is handled.
    }

    fn tcp(&mut self, ip: &frame::Ipv4<'_>, tcp: &frame::Tcp<'_>) {
        let flow = Flow {
            guest_ip: ip.src,
            guest_port: tcp.src_port,
            dst_ip: ip.dst,
            dst_port: tcp.dst_port,
        };
        let now = Instant::now();
        if let Some((_, conn)) = self.conns.get_mut(&flow) {
            let mut out = Vec::new();
            conn.segment(tcp, now, &mut out);
            self.after(flow, out);
            return;
        }
        if tcp.flags & frame::SYN != 0 && tcp.flags & (frame::ACK | frame::RST) == 0 {
            self.new_connection(flow, tcp, now);
        } else if tcp.flags & frame::RST == 0 {
            // A segment of no connection of ours.
            let seg = if tcp.flags & frame::ACK != 0 {
                Seg {
                    seq: tcp.ack,
                    ack: 0,
                    flags: frame::RST,
                    window: 0,
                    mss: None,
                    payload: Vec::new(),
                }
            } else {
                let consumed = tcp.payload.len() as u32
                    + u32::from(tcp.flags & frame::SYN != 0)
                    + u32::from(tcp.flags & frame::FIN != 0);
                Seg {
                    seq: 0,
                    ack: tcp.seq.wrapping_add(consumed),
                    flags: frame::RST | frame::ACK,
                    window: 0,
                    mss: None,
                    payload: Vec::new(),
                }
            };
            self.emit(&flow, vec![seg]);
        }
    }

    fn refuse(&mut self, flow: Flow, tcp: &frame::Tcp<'_>) {
        Counters::add(&self.shared.counters.tcp_blocked, 1);
        let seg = Seg {
            seq: 0,
            ack: tcp.seq.wrapping_add(1),
            flags: frame::RST | frame::ACK,
            window: 0,
            mss: None,
            payload: Vec::new(),
        };
        self.emit(&flow, vec![seg]);
    }

    fn new_connection(&mut self, flow: Flow, syn: &frame::Tcp<'_>, now: Instant) {
        // The generation is read before the route: a route installed in
        // between makes this connection look old, and it is reset (never the
        // other way round).
        let generation = self.sync_generation();
        let route = self.shared.current();
        let egress = route.spec.egress.clone();
        if matches!(egress, Egress::Drop) {
            // Dropped without an answer, like a firewall: the SYN is in the
            // capture and the sample keeps retrying.
            Counters::add(&self.shared.counters.tcp_blocked, 1);
            return;
        }
        if self.conns.len() >= MAX_CONNECTIONS {
            Counters::add(&self.shared.counters.tcp_blocked, 1);
            return;
        }
        let sink = matches!(egress, Egress::Sink(_));
        // The router's own addresses and the guest's network are never
        // connected to (QEMU's NAT would reach the host's loopback there).
        if !sink && (self.net.is_local(flow.dst_ip) || self.net.contains(flow.dst_ip)) {
            self.refuse(flow, syn);
            return;
        }
        let dest = if let Some(name) = self.fake.name_for(flow.dst_ip) {
            Dest::Name(name.to_owned(), flow.dst_port)
        } else if FakeIps::is_fake(flow.dst_ip) && !sink {
            self.refuse(flow, syn);
            return;
        } else {
            Dest::Ip(flow.dst_ip, flow.dst_port)
        };
        if matches!(dest, Dest::Name(..)) && !matches!(egress, Egress::Socks(_)) {
            self.refuse(flow, syn);
            return;
        }
        if let Dest::Ip(ip, _) = &dest
            && upstream::destination_refusal(&egress, *ip).is_some()
        {
            self.refuse(flow, syn);
            return;
        }
        let id = self.next_id;
        self.next_id += 1;
        let mut conn = Conn::new(syn, self.random(), now);
        conn.generation = generation;
        self.conns.insert(flow, (id, conn));
        self.flows.insert(id, flow);
        let (tx, shared) = (self.events_tx.clone(), self.shared.clone());
        let notify_tx = tx.clone();
        let notify_shared = shared.clone();
        let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            let _ = notify_tx.send(Event::Readable(id));
            notify_shared.waker.wake();
        });
        let spawned = thread::Builder::new()
            .name("route-dial".into())
            .spawn(move || {
                let result = upstream::dial(&egress, &dest)
                    .and_then(|stream| upstream::start_pipes(stream, notify));
                let _ = tx.send(Event::Dialed(id, result));
                shared.waker.wake();
            });
        if spawned.is_err() {
            self.forget(flow);
            Counters::add(&self.shared.counters.tcp_failed, 1);
            self.refuse(flow, syn);
        }
    }

    fn forget(&mut self, flow: Flow) {
        if let Some((id, _)) = self.conns.remove(&flow) {
            self.flows.remove(&id);
        }
    }

    /// Sends what a connection produced and forgets it when it is over.
    fn after(&mut self, flow: Flow, out: Vec<Seg>) {
        let mut dead = false;
        if let Some((_, conn)) = self.conns.get_mut(&flow) {
            let (up, down) = conn.take_counts();
            Counters::add(&self.shared.counters.up_len, up);
            Counters::add(&self.shared.counters.down_len, down);
            dead = conn.dead;
        }
        self.emit(&flow, out);
        if dead {
            self.forget(flow);
        }
    }

    fn emit(&mut self, flow: &Flow, segments: Vec<Seg>) {
        for seg in segments {
            let tcp = frame::build_tcp(
                flow.dst_ip,
                flow.guest_ip,
                &TcpOut {
                    src_port: flow.dst_port,
                    dst_port: flow.guest_port,
                    seq: seg.seq,
                    ack: seg.ack,
                    flags: seg.flags,
                    window: seg.window,
                    mss: seg.mss,
                    payload: &seg.payload,
                },
            );
            self.frame_to_guest(flow.dst_ip, flow.guest_ip, frame::PROTO_TCP, &tcp);
        }
    }

    fn handle_events(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            let now = Instant::now();
            match event {
                Event::Frame(frame) => {
                    self.dns_in_flight.fetch_sub(1, Ordering::SeqCst);
                    self.send(&frame);
                }
                Event::Readable(id) => {
                    let Some(flow) = self.flows.get(&id).copied() else {
                        continue;
                    };
                    let mut out = Vec::new();
                    if let Some((_, conn)) = self.conns.get_mut(&flow) {
                        conn.pump(now, &mut out);
                    }
                    self.after(flow, out);
                }
                Event::Dialed(id, result) => {
                    let Some(flow) = self.flows.get(&id).copied() else {
                        continue;
                    };
                    let mut out = Vec::new();
                    if let Some((_, conn)) = self.conns.get_mut(&flow) {
                        match result {
                            Ok(pipes) => {
                                Counters::add(&self.shared.counters.tcp_connections, 1);
                                conn.dialed(pipes, now, &mut out);
                            }
                            Err(_) => {
                                Counters::add(&self.shared.counters.tcp_failed, 1);
                                conn.dial_failed(&mut out);
                            }
                        }
                    }
                    self.after(flow, out);
                }
            }
        }
    }

    fn tick(&mut self, now: Instant) {
        let generation = self.sync_generation();
        self.swept_generation = generation;
        let flows: Vec<Flow> = self.conns.keys().copied().collect();
        for flow in flows {
            let mut out = Vec::new();
            if let Some((_, conn)) = self.conns.get_mut(&flow) {
                if conn.generation == generation {
                    conn.tick(now, &mut out);
                } else {
                    // Made under a route that is gone: it does not carry on.
                    conn.reset(&mut out);
                }
            }
            self.after(flow, out);
        }
    }
}
