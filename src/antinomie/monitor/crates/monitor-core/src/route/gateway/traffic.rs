// SPDX-License-Identifier: GPL-3.0-only
//! The gateway loop's DNS and TCP handling and its tick (moved out of `gateway`).
use super::*;

impl Loop {
    pub(super) fn dns_query(&mut self, ip: &frame::Ipv4<'_>, udp: &frame::Udp<'_>) {
        self.sync_generation();
        let counters = &self.shared.counters;
        Counters::add(&counters.dns_queries, 1);
        let route = self.shared.current();
        let Some(query) = dns::parse_query(udp.payload) else {
            Counters::add(&counters.dns_unanswered, 1);
            return;
        };
        // The provider's metadata name resolves to its link-local address
        // on every route, as it does on the provider's own network.
        let metadata_name = self
            .metadata
            .as_ref()
            .filter(|metadata| !metadata.name().is_empty() && metadata.name() == query.name);
        let answer = match &route.spec.egress {
            _ if metadata_name.is_some() && query.qtype == dns::TYPE_A => {
                metadata_name.map(|metadata| dns::answer_a(&query, &[metadata.ip()], DNS_TTL))
            }
            Egress::Drop => None,
            // The run time limit ended: no more names for a live route.
            _ if route.filter().is_some() && route.expired(Instant::now()) => None,
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
    pub(super) fn resolve_on_host(
        &mut self,
        ip: &frame::Ipv4<'_>,
        udp: &frame::Udp<'_>,
        query: dns::Query,
    ) {
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

    pub(super) fn tcp(&mut self, ip: &frame::Ipv4<'_>, tcp: &frame::Tcp<'_>) {
        let flow = Flow {
            guest_ip: ip.src,
            guest_port: tcp.src_port,
            dst_ip: ip.dst,
            dst_port: tcp.dst_port,
        };
        let now = Instant::now();
        if let Some((_, conn)) = self.conns.get_mut(&flow) {
            if !tcp.payload.is_empty()
                && let Some(metadata) = &self.metadata
                && flow.dst_ip != metadata.ip()
            {
                metadata.scan_outbound(&format!("{}:{}", flow.dst_ip, flow.dst_port), tcp.payload);
            }
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

    pub(super) fn refuse(&mut self, flow: Flow, tcp: &frame::Tcp<'_>) {
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

    pub(super) fn new_connection(&mut self, flow: Flow, syn: &frame::Tcp<'_>, now: Instant) {
        // The generation is read before the route: a route installed in
        // between makes this connection look old, and it is reset (never the
        // other way round).
        let generation = self.sync_generation();
        let route = self.shared.current();
        let egress = route.spec.egress.clone();
        // The cloud metadata service is the provider's own, not a route's
        // destination: it answers whatever the route is.
        let metadata = self
            .metadata
            .clone()
            .filter(|metadata| metadata.ip() == flow.dst_ip && flow.dst_port == 80);
        // Another provider's metadata address has no host on this network:
        // the connection goes unanswered, as it would on the provider's own.
        if let Some(ours) = &self.metadata
            && ours.ip() != flow.dst_ip
            && crate::stealth::CLOUDS
                .iter()
                .any(|provider| provider.metadata_ip.parse() == Ok(flow.dst_ip))
        {
            Counters::add(&self.shared.counters.tcp_blocked, 1);
            return;
        }
        if matches!(egress, Egress::Drop) && metadata.is_none() {
            // Dropped without an answer, like a firewall: the SYN is in the
            // capture and the sample keeps retrying.
            Counters::add(&self.shared.counters.tcp_blocked, 1);
            return;
        }
        if self.conns.len() >= MAX_CONNECTIONS {
            Counters::add(&self.shared.counters.tcp_blocked, 1);
            return;
        }
        let sink = matches!(egress, Egress::Sink(_)) || metadata.is_some();
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
            && metadata.is_none()
            && upstream::destination_refusal(&egress, *ip).is_some()
        {
            self.refuse(flow, syn);
            return;
        }
        if metadata.is_none() && !self.egress_admits(&route, generation, &dest, now) {
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
                let dialed = match &metadata {
                    Some(metadata) => metadata.connect().map(upstream::Stream::Unix),
                    None => upstream::dial(&egress, &dest),
                };
                let result = dialed.and_then(|stream| upstream::start_pipes(stream, notify));
                let _ = tx.send(Event::Dialed(id, result));
                shared.waker.wake();
            });
        if spawned.is_err() {
            self.forget(flow);
            Counters::add(&self.shared.counters.tcp_failed, 1);
            self.refuse(flow, syn);
        }
    }

    pub(super) fn forget(&mut self, flow: Flow) {
        if let Some((id, _)) = self.conns.remove(&flow) {
            self.flows.remove(&id);
        }
    }

    /// Sends what a connection produced and forgets it when it is over.
    pub(super) fn after(&mut self, flow: Flow, out: Vec<Seg>) {
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

    pub(super) fn emit(&mut self, flow: &Flow, segments: Vec<Seg>) {
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

    pub(super) fn handle_events(&mut self) {
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

    pub(super) fn tick(&mut self, now: Instant) {
        let generation = self.sync_generation();
        self.swept_generation = generation;
        let flows: Vec<Flow> = self.conns.keys().copied().collect();
        let route = self.shared.current();
        let expired = route.expired(now) && route.filter().is_some();
        for flow in flows {
            let mut out = Vec::new();
            if let Some((_, conn)) = self.conns.get_mut(&flow) {
                if conn.generation == generation && expired {
                    // The run time limit ended: forwarding stops, open
                    // connections are reset.
                    if !conn.dead {
                        Counters::add(&self.shared.counters.filter_time, 1);
                        Counters::add(&self.shared.counters.tcp_blocked, 1);
                    }
                    conn.reset(&mut out);
                } else if conn.generation == generation {
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
