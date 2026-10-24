//! A scripted guest: Ethernet frames over the socket QEMU would use (each
//! frame behind a 4-byte big-endian length), a small TCP client with
//! go-back-N retransmission, DNS and DHCP.
use super::{DNS, GUEST, WAIT};
use crate::route::{
    dns,
    frame::{self, ACK, BROADCAST, ETHERTYPE_ARP, ETHERTYPE_IPV4, FIN, Mac, PSH, RST, SYN, TcpOut},
};
use std::{
    io::{Read, Write},
    net::Ipv4Addr,
    os::unix::net::UnixStream,
    path::Path,
    time::{Duration, Instant},
};

pub const GUEST_MAC: Mac = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
pub const GATEWAY_MAC: Mac = [0x52, 0x55, 10, 0, 2, 2];
pub const DNS_MAC: Mac = [0x52, 0x55, 10, 0, 2, 3];

pub struct Guest {
    sock: UnixStream,
    buf: Vec<u8>,
    next_port: u16,
}

impl Guest {
    pub fn connect(path: &Path) -> Guest {
        let deadline = Instant::now() + WAIT;
        loop {
            match UnixStream::connect(path) {
                Ok(sock) => {
                    sock.set_read_timeout(Some(Duration::from_millis(20)))
                        .unwrap();
                    return Guest {
                        sock,
                        buf: Vec::new(),
                        next_port: 40_000,
                    };
                }
                Err(error) => {
                    assert!(Instant::now() < deadline, "gateway socket: {error}");
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }

    pub fn send(&mut self, frame: &[u8]) {
        let mut out = (frame.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(frame);
        self.sock.write_all(&out).unwrap();
    }

    /// The next frame, or `None` after `wait`.
    pub fn recv(&mut self, wait: Duration) -> Option<Vec<u8>> {
        let deadline = Instant::now() + wait;
        loop {
            if self.buf.len() >= 4 {
                let len = u32::from_be_bytes(self.buf[..4].try_into().unwrap()) as usize;
                if self.buf.len() >= 4 + len {
                    let frame = self.buf[4..4 + len].to_vec();
                    self.buf.drain(..4 + len);
                    return Some(frame);
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            let mut chunk = [0u8; 65_536];
            match self.sock.read(&mut chunk) {
                Ok(0) => return None,
                Ok(len) => self.buf.extend_from_slice(&chunk[..len]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => panic!("gateway socket: {error}"),
            }
        }
    }

    pub fn send_ip(&mut self, dst: Ipv4Addr, protocol: u8, payload: &[u8]) {
        let packet = frame::build_ipv4(GUEST, dst, protocol, payload);
        let mac = if dst == Ipv4Addr::BROADCAST {
            BROADCAST
        } else {
            GATEWAY_MAC
        };
        self.send(&frame::build_eth(mac, GUEST_MAC, ETHERTYPE_IPV4, &packet));
    }

    pub fn send_udp(&mut self, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) {
        let datagram = frame::build_udp(GUEST, dst, sport, dport, payload);
        self.send_ip(dst, frame::PROTO_UDP, &datagram);
    }

    /// A UDP datagram from `from_port` addressed to the guest, within `wait`.
    pub fn recv_udp(&mut self, from_port: u16, wait: Duration) -> Option<Vec<u8>> {
        let deadline = Instant::now() + wait;
        while let Some(frame) = self.recv(deadline.saturating_duration_since(Instant::now())) {
            let Some(eth) = frame::parse_eth(&frame) else {
                continue;
            };
            if eth.ethertype != ETHERTYPE_IPV4 {
                continue;
            }
            let Some(ip) = frame::parse_ipv4(eth.payload) else {
                continue;
            };
            if ip.protocol != frame::PROTO_UDP {
                continue;
            }
            if let Some(udp) = frame::parse_udp(ip.payload)
                && udp.src_port == from_port
            {
                return Some(udp.payload.to_vec());
            }
        }
        None
    }

    /// Asks the gateway's DNS server; the answer's raw bytes.
    pub fn dns(&mut self, name: &str, qtype: u16, wait: Duration) -> Option<Vec<u8>> {
        let query = dns::build_query(0x4242, name, qtype);
        self.send_udp(DNS, 5353, 53, &query);
        self.recv_udp(53, wait)
    }

    /// The A records of an answer.
    pub fn answer_addresses(answer: &[u8]) -> Vec<Ipv4Addr> {
        // The question is copied from the query, so the answers follow it.
        let mut at = 12;
        while answer[at] != 0 {
            at += 1 + usize::from(answer[at]);
        }
        at += 5;
        let count = usize::from(u16::from_be_bytes([answer[6], answer[7]]));
        let mut found = Vec::new();
        for _ in 0..count {
            // Name pointer (2), type, class, ttl (8), length (2).
            let len = usize::from(u16::from_be_bytes([answer[at + 10], answer[at + 11]]));
            if len == 4 {
                found.push(Ipv4Addr::new(
                    answer[at + 12],
                    answer[at + 13],
                    answer[at + 14],
                    answer[at + 15],
                ));
            }
            at += 12 + len;
        }
        found
    }

    pub fn rcode(answer: &[u8]) -> u8 {
        answer[3] & 15
    }

    /// DHCP DISCOVER and REQUEST; the lease the gateway ends up giving.
    pub fn dhcp(&mut self) -> Option<Vec<u8>> {
        let mut message = vec![0u8; 240];
        message[0] = 1;
        message[1] = 1;
        message[2] = 6;
        message[4..8].copy_from_slice(&[9, 9, 9, 9]);
        message[28..34].copy_from_slice(&GUEST_MAC);
        message[236..240].copy_from_slice(&[99, 130, 83, 99]);
        message.extend_from_slice(&[53, 1, 1, 255]);
        let datagram =
            frame::build_udp(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST, 68, 67, &message);
        let packet = frame::build_ipv4(
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            frame::PROTO_UDP,
            &datagram,
        );
        self.send(&frame::build_eth(
            BROADCAST,
            GUEST_MAC,
            ETHERTYPE_IPV4,
            &packet,
        ));
        self.recv_udp(67, WAIT)
    }

    /// ARP who-has `target`; the MAC in the reply.
    pub fn arp(&mut self, target: Ipv4Addr) -> Option<Mac> {
        let mut request = vec![0, 1, 8, 0, 6, 4, 0, 1];
        request.extend_from_slice(&GUEST_MAC);
        request.extend_from_slice(&GUEST.octets());
        request.extend_from_slice(&[0; 6]);
        request.extend_from_slice(&target.octets());
        self.send(&frame::build_eth(
            BROADCAST,
            GUEST_MAC,
            ETHERTYPE_ARP,
            &request,
        ));
        let deadline = Instant::now() + Duration::from_secs(1);
        while let Some(frame) = self.recv(deadline.saturating_duration_since(Instant::now())) {
            let eth = frame::parse_eth(&frame)?;
            if eth.ethertype == ETHERTYPE_ARP
                && let Some(reply) = frame::parse_arp(eth.payload)
                && reply.operation == 2
            {
                return Some(reply.sender_mac);
            }
        }
        None
    }

    pub fn new_port(&mut self) -> u16 {
        self.next_port += 1;
        self.next_port
    }
}

/// How a connection attempt ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Connect {
    Open,
    Refused,
    /// Nothing came back.
    Silent,
}

/// One TCP connection from the guest.
pub struct Tcp {
    dst: Ipv4Addr,
    dport: u16,
    sport: u16,
    iss: u32,
    /// Next sequence number to send, and the oldest unacknowledged one.
    seq: u32,
    una: u32,
    /// Next sequence number expected from the gateway.
    ack: u32,
    pub received: Vec<u8>,
    pub fin: bool,
    pub reset: bool,
    synack: bool,
}

impl Tcp {
    pub fn start(guest: &mut Guest, dst: Ipv4Addr, dport: u16) -> Tcp {
        let sport = guest.new_port();
        let mut tcp = Tcp {
            dst,
            dport,
            sport,
            iss: 1000 + u32::from(sport),
            seq: 0,
            una: 0,
            ack: 0,
            received: Vec::new(),
            fin: false,
            reset: false,
            synack: false,
        };
        tcp.seq = tcp.iss;
        tcp.segment(guest, SYN, tcp.iss, 0, &[], Some(1460));
        tcp.seq = tcp.iss.wrapping_add(1);
        tcp.una = tcp.iss;
        tcp
    }

    /// Opens a connection and waits for the gateway's answer.
    pub fn open(guest: &mut Guest, dst: Ipv4Addr, dport: u16, wait: Duration) -> (Tcp, Connect) {
        let mut tcp = Tcp::start(guest, dst, dport);
        let deadline = Instant::now() + wait;
        while !tcp.synack && !tcp.reset && Instant::now() < deadline {
            tcp.pump(guest, Duration::from_millis(50));
        }
        let state = if tcp.synack {
            Connect::Open
        } else if tcp.reset {
            Connect::Refused
        } else {
            Connect::Silent
        };
        (tcp, state)
    }

    fn segment(
        &self,
        guest: &mut Guest,
        flags: u8,
        seq: u32,
        ack: u32,
        payload: &[u8],
        mss: Option<u16>,
    ) {
        let tcp = frame::build_tcp(
            GUEST,
            self.dst,
            &TcpOut {
                src_port: self.sport,
                dst_port: self.dport,
                seq,
                ack,
                flags,
                window: 65_535,
                mss,
                payload,
            },
        );
        guest.send_ip(self.dst, frame::PROTO_TCP, &tcp);
    }

    /// Handles frames for up to `wait`; true when one belonged to this flow.
    pub fn pump(&mut self, guest: &mut Guest, wait: Duration) -> bool {
        let Some(bytes) = guest.recv(wait) else {
            return false;
        };
        let Some(eth) = frame::parse_eth(&bytes) else {
            return true;
        };
        if eth.ethertype != ETHERTYPE_IPV4 {
            return true;
        }
        let Some(ip) = frame::parse_ipv4(eth.payload) else {
            return true;
        };
        if ip.protocol != frame::PROTO_TCP || ip.src != self.dst {
            return true;
        }
        let Some(seg) = frame::parse_tcp(ip.payload) else {
            return true;
        };
        if seg.dst_port != self.sport || seg.src_port != self.dport {
            return true;
        }
        if seg.flags & RST != 0 {
            self.reset = true;
            return true;
        }
        if seg.flags & SYN != 0 && seg.flags & ACK != 0 && !self.synack {
            self.synack = true;
            self.ack = seg.seq.wrapping_add(1);
            self.una = self.iss.wrapping_add(1);
            self.segment(guest, ACK, self.seq, self.ack, &[], None);
            return true;
        }
        if seg.flags & ACK != 0 && (seg.ack.wrapping_sub(self.una) as i32) > 0 {
            self.una = seg.ack;
        }
        let mut reply = false;
        if !seg.payload.is_empty() || seg.flags & FIN != 0 {
            if seg.seq == self.ack {
                self.received.extend_from_slice(seg.payload);
                self.ack = self.ack.wrapping_add(seg.payload.len() as u32);
                if seg.flags & FIN != 0 {
                    self.fin = true;
                    self.ack = self.ack.wrapping_add(1);
                }
            }
            reply = true;
        }
        if reply {
            self.segment(guest, ACK, self.seq, self.ack, &[], None);
        }
        true
    }

    /// Sends `data` and waits until the gateway has acknowledged it,
    /// sending again what it did not take.
    pub fn send_all(&mut self, guest: &mut Guest, data: &[u8]) {
        let start = self.seq;
        let end = start.wrapping_add(data.len() as u32);
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut next = start;
        let mut last_progress = Instant::now();
        let mut last_una = self.una;
        while self.una != end {
            assert!(Instant::now() < deadline && !self.reset, "upload stalled");
            // Up to 20 segments past what is acknowledged.
            while next != end && next.wrapping_sub(self.una) < 20 * 1400 {
                let offset = next.wrapping_sub(start) as usize;
                let take = (data.len() - offset).min(1400);
                self.segment(
                    guest,
                    ACK | PSH,
                    next,
                    self.ack,
                    &data[offset..offset + take],
                    None,
                );
                next = next.wrapping_add(take as u32);
            }
            self.pump(guest, Duration::from_millis(20));
            if self.una != last_una {
                last_una = self.una;
                last_progress = Instant::now();
            } else if last_progress.elapsed() > Duration::from_millis(400) {
                // Go back to the first unacknowledged byte.
                next = self.una;
                last_progress = Instant::now();
            }
        }
        self.seq = end;
    }

    /// Reads until `len` bytes came in, the peer finished or `wait` passed.
    pub fn read(&mut self, guest: &mut Guest, len: usize, wait: Duration) -> Vec<u8> {
        let deadline = Instant::now() + wait;
        while self.received.len() < len && !self.fin && !self.reset && Instant::now() < deadline {
            self.pump(guest, Duration::from_millis(20));
        }
        self.received.clone()
    }

    /// Reads until the peer finishes (or resets).
    pub fn read_to_end(&mut self, guest: &mut Guest, wait: Duration) -> Vec<u8> {
        let deadline = Instant::now() + wait;
        while !self.fin && !self.reset && Instant::now() < deadline {
            self.pump(guest, Duration::from_millis(20));
        }
        self.received.clone()
    }

    pub fn close(&mut self, guest: &mut Guest) {
        self.segment(guest, FIN | ACK, self.seq, self.ack, &[], None);
        self.seq = self.seq.wrapping_add(1);
    }

    /// Waits for a reset from the gateway.
    pub fn wait_reset(&mut self, guest: &mut Guest, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        while !self.reset && Instant::now() < deadline {
            self.pump(guest, Duration::from_millis(20));
        }
        self.reset
    }
}

/// Re-exported for the tests that look at the lease.
pub fn lease_address(reply: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(reply[16], reply[17], reply[18], reply[19])
}

pub fn lease_options(reply: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut found = Vec::new();
    let mut rest = &reply[240..];
    while let Some((&code, tail)) = rest.split_first() {
        match code {
            0 => rest = tail,
            255 => break,
            _ => {
                let len = usize::from(tail[0]);
                found.push((code, tail[1..1 + len].to_vec()));
                rest = &tail[1 + len..];
            }
        }
    }
    found
}
