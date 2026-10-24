// SPDX-License-Identifier: GPL-3.0-only
//! One guest TCP connection as the gateway sees it: the gateway is the
//! server end of the guest's connection and relays the bytes over an
//! upstream connection it dials for the guest.
//!
//! The link to the guest is QEMU's local socket, which neither loses nor
//! reorders frames, so this is a small TCP: no window scaling or SACK,
//! segments accepted only in order (anything else gets a duplicate ACK), a
//! constant receive window, a fixed send window cap and go-back-N
//! retransmission. Backpressure from a slow upstream is a segment that is not
//! acknowledged, which the guest retransmits.
use super::{
    frame::{ACK, FIN, MSS, PSH, RST, SYN, Tcp},
    upstream::{Down, Pipes, UpMsg},
};
use std::{
    collections::VecDeque,
    sync::mpsc::{TryRecvError, TrySendError},
    time::{Duration, Instant},
};

/// Receive window advertised to the guest (no scaling).
pub(crate) const WINDOW: u16 = 65_535;
/// Most unacknowledged bytes sent to the guest.
const MAX_FLIGHT: u32 = 65_535;
const DIAL_LIMIT: Duration = Duration::from_secs(90);
const IDLE_LIMIT: Duration = Duration::from_secs(600);
const TIME_WAIT: Duration = Duration::from_secs(2);
const SYN_ACK_RETRIES: u32 = 5;
const DATA_RETRIES: u32 = 8;

/// A segment for the guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Seg {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    pub payload: Vec<u8>,
}

fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Dialing,
    SynAckSent,
    Established,
    TimeWait(Instant),
}

struct Flight {
    seq: u32,
    data: Vec<u8>,
    fin: bool,
}

impl Flight {
    fn end(&self) -> u32 {
        self.seq
            .wrapping_add(self.data.len() as u32)
            .wrapping_add(u32::from(self.fin))
    }
}

pub(crate) struct Conn {
    state: State,
    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    snd_wnd: u32,
    mss: usize,
    rcv_nxt: u32,
    pipes: Option<Pipes>,
    inflight: VecDeque<Flight>,
    leftover: Vec<u8>,
    leftover_pos: usize,
    down_eof: bool,
    fin_sent: bool,
    guest_fin: bool,
    shutdown_sent: bool,
    created: Instant,
    last_activity: Instant,
    last_send: Instant,
    retries: u32,
    up_len: u64,
    down_len: u64,
    /// The connection is over and can be forgotten.
    pub dead: bool,
    /// The route generation it was made under.
    pub generation: u64,
}

impl Conn {
    /// A connection for the guest's SYN; the upstream is still being dialed.
    pub fn new(syn: &Tcp, iss: u32, now: Instant) -> Self {
        Conn {
            state: State::Dialing,
            iss,
            snd_una: iss,
            snd_nxt: iss.wrapping_add(1),
            snd_wnd: u32::from(syn.window),
            mss: usize::from(syn.mss.unwrap_or(536)).clamp(64, MSS),
            rcv_nxt: syn.seq.wrapping_add(1),
            pipes: None,
            inflight: VecDeque::new(),
            leftover: Vec::new(),
            leftover_pos: 0,
            down_eof: false,
            fin_sent: false,
            guest_fin: false,
            shutdown_sent: false,
            created: now,
            last_activity: now,
            last_send: now,
            retries: 0,
            up_len: 0,
            down_len: 0,
            dead: false,
            generation: 0,
        }
    }

    /// Payload bytes moved since the last call: (from the guest, to the guest).
    pub fn take_counts(&mut self) -> (u64, u64) {
        (
            std::mem::take(&mut self.up_len),
            std::mem::take(&mut self.down_len),
        )
    }

    fn syn_ack(&self) -> Seg {
        Seg {
            seq: self.iss,
            ack: self.rcv_nxt,
            flags: SYN | ACK,
            window: WINDOW,
            mss: Some(MSS as u16),
            payload: Vec::new(),
        }
    }

    fn ack_seg(&self) -> Seg {
        Seg {
            seq: self.snd_nxt,
            ack: self.rcv_nxt,
            flags: ACK,
            window: WINDOW,
            mss: None,
            payload: Vec::new(),
        }
    }

    fn rst_seg(&self) -> Seg {
        Seg {
            flags: RST | ACK,
            window: 0,
            ..self.ack_seg()
        }
    }

    fn abort(&mut self, out: &mut Vec<Seg>) {
        if !self.dead && self.state != State::Dialing {
            out.push(self.rst_seg());
        }
        self.dead = true;
        self.pipes = None;
    }

    /// The upstream connection is up: answer the guest's SYN.
    pub fn dialed(&mut self, pipes: Pipes, now: Instant, out: &mut Vec<Seg>) {
        if self.state != State::Dialing || self.dead {
            return;
        }
        self.pipes = Some(pipes);
        self.state = State::SynAckSent;
        self.last_send = now;
        out.push(self.syn_ack());
    }

    /// The upstream could not be reached: refuse the guest's SYN.
    pub fn dial_failed(&mut self, out: &mut Vec<Seg>) {
        if self.state == State::Dialing {
            out.push(Seg {
                seq: 0,
                ack: self.rcv_nxt,
                flags: RST | ACK,
                window: 0,
                mss: None,
                payload: Vec::new(),
            });
        }
        self.dead = true;
    }

    /// Ends the connection with a reset (the route changed, or the gateway
    /// is stopping).
    pub fn reset(&mut self, out: &mut Vec<Seg>) {
        if self.state == State::Dialing {
            self.dial_failed(out);
        } else {
            self.abort(out);
        }
    }

    pub fn segment(&mut self, tcp: &Tcp, now: Instant, out: &mut Vec<Seg>) {
        self.last_activity = now;
        if tcp.flags & RST != 0 {
            self.dead = true;
            self.pipes = None;
            return;
        }
        match self.state {
            State::Dialing => return,
            State::SynAckSent => {
                if tcp.flags & SYN != 0 && tcp.flags & ACK == 0 {
                    out.push(self.syn_ack());
                    return;
                }
                if tcp.flags & ACK != 0 && tcp.ack == self.iss.wrapping_add(1) {
                    self.state = State::Established;
                    self.snd_una = tcp.ack;
                    self.retries = 0;
                } else {
                    out.push(Seg {
                        seq: tcp.ack,
                        ack: 0,
                        flags: RST,
                        window: 0,
                        mss: None,
                        payload: Vec::new(),
                    });
                    self.dead = true;
                    self.pipes = None;
                    return;
                }
            }
            State::Established => {}
            State::TimeWait(_) => {
                if tcp.flags & FIN != 0 {
                    out.push(self.ack_seg());
                }
                return;
            }
        }
        if tcp.flags & ACK != 0 {
            self.on_ack(tcp.ack, tcp.window, now);
        }
        self.on_data(tcp, out);
        self.pump(now, out);
        self.finish(now);
    }

    fn on_ack(&mut self, ack: u32, window: u16, now: Instant) {
        self.snd_wnd = u32::from(window);
        if !seq_lt(self.snd_una, ack) || seq_lt(self.snd_nxt, ack) {
            return;
        }
        while let Some(front) = self.inflight.front_mut() {
            if seq_le(front.end(), ack) {
                self.inflight.pop_front();
            } else {
                if seq_lt(front.seq, ack) {
                    let acked = ack.wrapping_sub(front.seq) as usize;
                    front.data.drain(..acked.min(front.data.len()));
                    front.seq = ack;
                }
                break;
            }
        }
        self.snd_una = ack;
        self.retries = 0;
        self.last_send = now;
    }

    fn on_data(&mut self, tcp: &Tcp, out: &mut Vec<Seg>) {
        let fin = tcp.flags & FIN != 0;
        if tcp.payload.is_empty() && !fin {
            return;
        }
        let mut data = tcp.payload;
        let mut seq = tcp.seq;
        let end = seq
            .wrapping_add(data.len() as u32)
            .wrapping_add(u32::from(fin));
        if seq_le(end, self.rcv_nxt) {
            out.push(self.ack_seg());
            return;
        }
        if seq_lt(seq, self.rcv_nxt) {
            let skip = self.rcv_nxt.wrapping_sub(seq) as usize;
            data = &data[skip.min(data.len())..];
            seq = self.rcv_nxt;
        }
        if seq != self.rcv_nxt || self.guest_fin {
            out.push(self.ack_seg());
            return;
        }
        if !data.is_empty() {
            let Some(pipes) = &self.pipes else {
                self.abort(out);
                return;
            };
            match pipes.up.try_send(UpMsg::Data(data.to_vec())) {
                Ok(()) => {
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(data.len() as u32);
                    self.up_len += data.len() as u64;
                }
                // Not taken: no ACK, the guest sends it again.
                Err(TrySendError::Full(_)) => return,
                Err(TrySendError::Disconnected(_)) => {
                    self.abort(out);
                    return;
                }
            }
        }
        if fin {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.guest_fin = true;
        }
        out.push(self.ack_seg());
    }

    /// Sends what the upstream has for the guest, as far as its window allows.
    pub fn pump(&mut self, now: Instant, out: &mut Vec<Seg>) {
        if self.state != State::Established || self.dead {
            return;
        }
        if self.guest_fin
            && !self.shutdown_sent
            && let Some(pipes) = &self.pipes
            && pipes.up.try_send(UpMsg::Shutdown).is_ok()
        {
            self.shutdown_sent = true;
        }
        loop {
            let in_flight = self.snd_nxt.wrapping_sub(self.snd_una);
            let limit = self.snd_wnd.min(MAX_FLIGHT);
            if in_flight >= limit {
                break;
            }
            if self.leftover_pos >= self.leftover.len() {
                self.leftover.clear();
                self.leftover_pos = 0;
                if self.down_eof {
                    break;
                }
                let Some(pipes) = &self.pipes else { break };
                match pipes.down.try_recv() {
                    Ok(Down::Data(bytes)) => self.leftover = bytes,
                    Ok(Down::Eof) | Err(TryRecvError::Disconnected) => {
                        self.down_eof = true;
                        break;
                    }
                    Ok(Down::Failed) => {
                        self.abort(out);
                        return;
                    }
                    Err(TryRecvError::Empty) => break,
                }
            }
            let room = (limit - in_flight) as usize;
            let take = room
                .min(self.mss)
                .min(self.leftover.len() - self.leftover_pos);
            let payload = self.leftover[self.leftover_pos..self.leftover_pos + take].to_vec();
            self.leftover_pos += take;
            if self.inflight.is_empty() {
                self.last_send = now;
            }
            self.last_activity = now;
            self.down_len += take as u64;
            out.push(Seg {
                seq: self.snd_nxt,
                ack: self.rcv_nxt,
                flags: ACK | PSH,
                window: WINDOW,
                mss: None,
                payload: payload.clone(),
            });
            self.inflight.push_back(Flight {
                seq: self.snd_nxt,
                data: payload,
                fin: false,
            });
            self.snd_nxt = self.snd_nxt.wrapping_add(take as u32);
        }
        if self.down_eof && !self.fin_sent {
            if self.inflight.is_empty() {
                self.last_send = now;
            }
            out.push(Seg {
                flags: FIN | ACK,
                ..self.ack_seg()
            });
            self.inflight.push_back(Flight {
                seq: self.snd_nxt,
                data: Vec::new(),
                fin: true,
            });
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            self.fin_sent = true;
        }
    }

    fn finish(&mut self, now: Instant) {
        if self.state == State::Established
            && self.guest_fin
            && self.fin_sent
            && self.snd_una == self.snd_nxt
        {
            self.state = State::TimeWait(now + TIME_WAIT);
            self.pipes = None;
        }
    }

    fn rto(&self) -> Duration {
        Duration::from_millis(500) * (1u32 << self.retries.min(4))
    }

    /// Timers: retransmission, idle and dial limits.
    pub fn tick(&mut self, now: Instant, out: &mut Vec<Seg>) {
        if self.dead {
            return;
        }
        match self.state {
            State::Dialing => {
                if now.duration_since(self.created) > DIAL_LIMIT {
                    self.dial_failed(out);
                }
            }
            State::SynAckSent => {
                if now.duration_since(self.last_send) > Duration::from_secs(1) {
                    if self.retries >= SYN_ACK_RETRIES {
                        self.abort(out);
                    } else {
                        self.retries += 1;
                        self.last_send = now;
                        out.push(self.syn_ack());
                    }
                }
            }
            State::Established => {
                self.pump(now, out);
                if !self.inflight.is_empty() && now.duration_since(self.last_send) > self.rto() {
                    if self.retries >= DATA_RETRIES {
                        self.abort(out);
                        return;
                    }
                    self.retries += 1;
                    self.last_send = now;
                    for flight in &self.inflight {
                        out.push(Seg {
                            seq: flight.seq,
                            ack: self.rcv_nxt,
                            flags: ACK | if flight.fin { FIN } else { PSH },
                            window: WINDOW,
                            mss: None,
                            payload: flight.data.clone(),
                        });
                    }
                }
                if now.duration_since(self.last_activity) > IDLE_LIMIT {
                    self.abort(out);
                    return;
                }
                self.finish(now);
            }
            State::TimeWait(until) => {
                if now >= until {
                    self.dead = true;
                }
            }
        }
    }
}
