// SPDX-License-Identifier: GPL-3.0-only
//! The fake TFTP server of UDP port 69 (RFC 1350, with the blksize and tsize
//! options of RFC 2348/2349): a read request gets a stand-in or the fake file,
//! a write request is kept for the run. It runs on the gateway's loop: each
//! datagram in gives the datagrams to send back, from the transfer's own
//! port as TFTP does.
use super::{
    log::Transfer,
    services::{Services, Upload, now_ms},
    stand_in,
};
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    time::{Duration, Instant},
};

pub(crate) const PORT: u16 = 69;
const RRQ: u16 = 1;
const WRQ: u16 = 2;
const DATA: u16 = 3;
const ACK: u16 = 4;
const ERROR: u16 = 5;
const OACK: u16 = 6;
/// Transfers at once; more requests get an error.
const MAX_TRANSFERS: usize = 64;
/// A transfer the guest stopped answering is ended after this.
const IDLE: Duration = Duration::from_secs(30);
/// The transfer ports the server answers from.
const FIRST_TID: u16 = 50_000;

/// A datagram for the guest: from `(server address, port)` to its port.
pub(crate) struct Reply {
    pub from: (Ipv4Addr, u16),
    pub to_port: u16,
    pub payload: Vec<u8>,
}

struct Active {
    guest_port: u16,
    name: String,
    block_size: usize,
    /// The last block sent (read) or received (write).
    block: u16,
    /// Read: what is sent; `done` once the last block was acknowledged.
    data: Vec<u8>,
    served: String,
    upload: Option<Upload>,
    /// The last datagram sent, sent again on a repeat.
    last: Vec<u8>,
    at: Instant,
    generation: u64,
}

#[derive(Default)]
pub(crate) struct Server {
    active: HashMap<(Ipv4Addr, u16), Active>,
    next_tid: u16,
}

fn packet(opcode: u16, rest: &[u8]) -> Vec<u8> {
    let mut out = opcode.to_be_bytes().to_vec();
    out.extend_from_slice(rest);
    out
}

fn error(code: u16, text: &str) -> Vec<u8> {
    let mut rest = code.to_be_bytes().to_vec();
    rest.extend_from_slice(text.as_bytes());
    rest.push(0);
    packet(ERROR, &rest)
}

impl Active {
    /// Block `block` of a read transfer.
    fn data_block(&self, block: u16) -> Vec<u8> {
        let start = (usize::from(block).saturating_sub(1)) * self.block_size;
        let end = (start + self.block_size).min(self.data.len());
        let mut rest = block.to_be_bytes().to_vec();
        rest.extend_from_slice(self.data.get(start..end).unwrap_or(&[]));
        packet(DATA, &rest)
    }

    fn blocks(&self) -> usize {
        self.data.len() / self.block_size + 1
    }
}

impl Server {
    /// Whether a datagram to `(ip, port)` is TFTP's.
    pub fn wants(&self, ip: Ipv4Addr, port: u16) -> bool {
        port == PORT || self.active.contains_key(&(ip, port))
    }

    /// Forgets every transfer (the route changed).
    pub fn clear(&mut self) {
        self.active.clear();
    }

    /// A datagram from the guest's `guest_port` to `(ip, port)`.
    pub fn handle(
        &mut self,
        services: &Services,
        guest_port: u16,
        (ip, port): (Ipv4Addr, u16),
        payload: &[u8],
    ) -> Option<Reply> {
        if payload.len() < 4 {
            return None;
        }
        let opcode = u16::from_be_bytes([payload[0], payload[1]]);
        if port == PORT {
            return self.request(services, guest_port, ip, opcode, &payload[2..]);
        }
        let key = (ip, port);
        let reply = |payload| {
            Some(Reply {
                from: key,
                to_port: guest_port,
                payload,
            })
        };
        let Some(active) = self.active.get_mut(&key) else {
            return None;
        };
        if active.guest_port != guest_port {
            return reply(error(5, "Unknown transfer ID"));
        }
        active.at = Instant::now();
        let number = u16::from_be_bytes([payload[2], payload[3]]);
        match opcode {
            ACK if active.upload.is_none() => {
                if number == active.block {
                    if usize::from(number) >= active.blocks() {
                        self.finish(services, key);
                        return None;
                    }
                    active.block = number.wrapping_add(1);
                    active.last = active.data_block(active.block);
                }
                reply(active.last.clone())
            }
            DATA if active.upload.is_some() => {
                let expected = active.block.wrapping_add(1);
                if number == expected {
                    let block = &payload[4..];
                    if let Some(upload) = &mut active.upload {
                        upload.write(block);
                    }
                    active.block = expected;
                    active.last = packet(ACK, &expected.to_be_bytes());
                    let last = active.last.clone();
                    if block.len() < active.block_size {
                        self.finish(services, key);
                    }
                    return reply(last);
                }
                reply(active.last.clone())
            }
            ERROR => {
                self.finish(services, key);
                None
            }
            _ => reply(error(4, "Illegal TFTP operation")),
        }
    }

    fn request(
        &mut self,
        services: &Services,
        guest_port: u16,
        ip: Ipv4Addr,
        opcode: u16,
        rest: &[u8],
    ) -> Option<Reply> {
        let mut fields = rest
            .split(|b| *b == 0)
            .map(|f| String::from_utf8_lossy(f).into_owned());
        let name: String = fields.next()?.chars().take(512).collect();
        let _mode = fields.next()?;
        let mut options = Vec::new();
        while let (Some(key), Some(value)) = (fields.next(), fields.next()) {
            if !key.is_empty() {
                options.push((key.to_ascii_lowercase(), value));
            }
        }
        // A repeated request from the same port is the same transfer.
        if let Some((key, active)) = self
            .active
            .iter()
            .find(|(k, a)| k.0 == ip && a.guest_port == guest_port && a.block <= 1)
        {
            return Some(Reply {
                from: *key,
                to_port: guest_port,
                payload: active.last.clone(),
            });
        }
        let tid = self.tid(ip);
        let from = (ip, tid);
        if self.active.len() >= MAX_TRANSFERS || !matches!(opcode, RRQ | WRQ) {
            return Some(Reply {
                from,
                to_port: guest_port,
                payload: error(0, "Server busy"),
            });
        }
        let view = services.view();
        let block_size = options
            .iter()
            .find(|(k, _)| k == "blksize")
            .and_then(|(_, v)| v.parse::<usize>().ok())
            .map(|size| size.clamp(8, 1428));
        let (data, served, upload) = if opcode == RRQ {
            let (data, served) = stand_in::serve(&name, view.arch, view.options.stand_ins);
            (data, served, None)
        } else {
            (
                Vec::new(),
                String::new(),
                Some(services.upload(view.generation, &name)),
            )
        };
        let mut acked = Vec::new();
        if let Some(size) = block_size {
            acked.push(("blksize".to_owned(), size.to_string()));
        }
        if options.iter().any(|(k, _)| k == "tsize") {
            let size = if opcode == RRQ {
                data.len().to_string()
            } else {
                options
                    .iter()
                    .find(|(k, _)| k == "tsize")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default()
            };
            acked.push(("tsize".to_owned(), size));
        }
        let mut active = Active {
            guest_port,
            name,
            block_size: block_size.unwrap_or(512),
            block: 0,
            data,
            served,
            upload,
            last: Vec::new(),
            at: Instant::now(),
            generation: view.generation,
        };
        active.last = if !acked.is_empty() {
            let mut rest = Vec::new();
            for (k, v) in &acked {
                rest.extend_from_slice(k.as_bytes());
                rest.push(0);
                rest.extend_from_slice(v.as_bytes());
                rest.push(0);
            }
            packet(OACK, &rest)
        } else if opcode == RRQ {
            active.block = 1;
            active.data_block(1)
        } else {
            packet(ACK, &[0, 0])
        };
        let payload = active.last.clone();
        self.active.insert(from, active);
        Some(Reply {
            from,
            to_port: guest_port,
            payload,
        })
    }

    /// A free transfer port on `ip`.
    fn tid(&mut self, ip: Ipv4Addr) -> u16 {
        loop {
            self.next_tid = (self.next_tid + 1) % 10_000;
            let tid = FIRST_TID + self.next_tid;
            if !self.active.contains_key(&(ip, tid)) {
                return tid;
            }
        }
    }

    /// Logs a transfer that ended (or was given up on).
    fn finish(&mut self, services: &Services, key: (Ipv4Addr, u16)) {
        let Some(active) = self.active.remove(&key) else {
            return;
        };
        let endpoint = format!("{}:{PORT}", key.0);
        let transfer = Transfer {
            ms: now_ms(),
            protocol: "tftp".into(),
            endpoint,
            host: key.0.to_string(),
            name: active.name.clone(),
            url: format!("tftp://{}/{}", key.0, active.name.trim_start_matches('/')),
            ..Transfer::default()
        };
        let transfer = match active.upload {
            Some(upload) => {
                let done = upload.finish();
                services.uploaded(active.generation, done.kept);
                Transfer {
                    direction: "upload".into(),
                    size: done.size,
                    sha256: done.sha256,
                    artifact: done.artifact,
                    truncated: done.truncated,
                    ..transfer
                }
            }
            None => Transfer {
                direction: "download".into(),
                size: active.data.len() as u64,
                sha256: crate::storage::sha256_hex(&active.data),
                served: active.served,
                ..transfer
            },
        };
        services.transfer(active.generation, transfer);
    }

    /// Ends the transfers the guest stopped answering.
    pub fn sweep(&mut self, services: &Services, now: Instant) {
        let idle: Vec<_> = self
            .active
            .iter()
            .filter(|(_, a)| now.duration_since(a.at) >= IDLE)
            .map(|(k, _)| *k)
            .collect();
        for key in idle {
            self.finish(services, key);
        }
    }
}
