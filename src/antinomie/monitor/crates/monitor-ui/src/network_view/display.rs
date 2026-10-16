// SPDX-License-Identifier: MIT
//! Applying the display filter and refreshing the packet list.
use super::*;

impl NetworkView {
    pub(super) fn reconstruction(&self) -> Option<antinomie_monitor_core::network::Reconstruction> {
        let frames = self
            .payloads
            .as_ref()
            .filter(|cache| !cache.frames.is_empty())
            .map(|cache| cache.frames.clone())?;
        let captured: Vec<_> = self
            .list
            .packets
            .iter()
            .zip(frames.iter())
            .map(
                |(packet, bytes)| antinomie_monitor_core::network::CapturedFrame {
                    number: packet.number,
                    time_us: packet.time_us,
                    bytes,
                },
            )
            .collect();
        Some(antinomie_monitor_core::network::reconstruct(&captured))
    }

    pub(super) fn refresh_payloads(&mut self) {
        const LIMIT: usize = 128;
        let Some(path) = self.list.path.clone() else {
            self.payloads = None;
            return;
        };
        let offsets: Vec<u64> = self
            .list
            .packets
            .iter()
            .take(LIMIT)
            .map(|packet| packet.offset)
            .collect();
        if self
            .payloads
            .as_ref()
            .is_some_and(|cache| cache.path == path && cache.offsets == offsets)
        {
            return;
        }
        let mut frames = Vec::with_capacity(offsets.len());
        for offset in &offsets {
            match antinomie_monitor_core::network::frame(&path, *offset) {
                Ok(bytes) => frames.push(bytes),
                Err(error) => {
                    self.payloads = Some(PayloadCache {
                        path,
                        offsets,
                        frames: Vec::new(),
                        note: Some(format!("Request reconstruction is unavailable: {error}")),
                    });
                    return;
                }
            }
        }
        let note = if self.list.packets.len() > LIMIT {
            Some(format!(
                "Reconstruction uses the first {LIMIT} loaded packets, not the whole capture."
            ))
        } else if frames.is_empty() {
            Some(
                "Request reconstruction is unavailable for this view: the loaded packet list has no payload."
                    .into(),
            )
        } else {
            None
        };
        self.payloads = Some(PayloadCache {
            path,
            offsets,
            frames,
            note,
        });
    }

    /// Keep the last valid filter. A display expression that does not parse,
    /// including an unknown dotted field, does not become a text search.
    pub(super) fn apply_filter(&mut self) {
        let text = self.filter.trim();
        if self.applied_filter != text
            && self
                .list
                .selected
                .as_ref()
                .is_some_and(|packet| !Filter::parse(text).matches(packet))
        {
            self.list.selected = None;
            self.list.frame = None;
            self.list.layers.clear();
            self.list.field = None;
            self.display_jump_note = Some(
                "The quick search hides the previously selected frame. Select a visible packet."
                    .into(),
            );
        }
        self.applied_filter = text.to_owned();
        self.filter_error = None;
        if self.display_index.is_some() {
            let parsed = Filter::parse(text);
            self.list.rows = self
                .display_page
                .iter()
                .enumerate()
                .filter_map(|(i, packet)| parsed.matches(packet).then_some(i))
                .collect();
            self.list.rows_for = None;
        } else {
            self.list.filter_rows(&self.applied_filter);
        }
    }

    pub(super) fn refresh_display(&mut self, live: bool, ctx: &egui::Context) {
        if self.display_worker.is_none() && self.display_worker_error.is_none() {
            match PacketFilterWorker::new() {
                Ok(worker) => self.display_worker = Some(worker),
                Err(error) => self.display_worker_error = Some(error),
            }
        }
        let Some(worker) = &self.display_worker else {
            return;
        };
        if let Some(event) = worker.poll() {
            match event {
                PacketFilterEvent::Evaluated {
                    generation,
                    identity,
                    expression,
                    result,
                } if generation == self.display_generation
                    && self
                        .display_requested
                        .as_ref()
                        .is_some_and(|(requested, query, _)| {
                            requested == &identity && query == &expression
                        }) =>
                {
                    self.display_pending = false;
                    match result {
                        Ok(index) => {
                            remember_filter(&mut self.display_history, &expression);
                            if self
                                .display_identity
                                .as_ref()
                                .is_some_and(|current| identity.permits_append(current))
                            {
                                let changed = self
                                    .display_index
                                    .as_ref()
                                    .is_none_or(|prior| prior.expression != expression);
                                let page_start = if live
                                    && self.display_follow_live
                                    && self.list.selected.is_none()
                                {
                                    index.matching_count.saturating_sub(1) / PAGE_SIZE as u64
                                        * PAGE_SIZE as u64
                                } else if changed {
                                    0
                                } else {
                                    self.display_page_start.min(
                                        index.matching_count.saturating_sub(1) / PAGE_SIZE as u64
                                            * PAGE_SIZE as u64,
                                    )
                                };
                                self.display_generation =
                                    worker.request_page(Arc::clone(&index), page_start);
                                self.display_pending = true;
                                self.display_next_index = Some(index);
                                if expression == self.display_filter.trim() {
                                    self.display_error = None;
                                    self.display_rejected = None;
                                }
                            }
                        }
                        Err(error) => {
                            self.display_error = Some(error);
                            self.display_rejected = Some(expression);
                        }
                    }
                }
                PacketFilterEvent::Page {
                    generation,
                    start,
                    result,
                } if generation == self.display_generation => {
                    self.display_pending = false;
                    match result {
                        Ok(packets) => {
                            self.display_page = packets;
                            self.display_page_start = start;
                            if let Some(index) = self.display_next_index.take() {
                                if self
                                    .display_index
                                    .as_ref()
                                    .is_some_and(|prior| prior.expression != index.expression)
                                {
                                    self.display_jump =
                                        self.list.selected.as_ref().map(|packet| packet.number);
                                    self.display_validate_selection = self.display_jump.is_some();
                                }
                                self.display_index = Some(index);
                            }
                            self.list.rows_for = None;
                        }
                        Err(error) => self.display_error = Some(error),
                    }
                }
                PacketFilterEvent::Frame {
                    generation,
                    number,
                    result,
                } if generation == self.display_generation => {
                    self.display_pending = false;
                    match result {
                        Ok((packet, position)) => {
                            if self.display_validate_selection && position.is_none() {
                                self.list.selected = None;
                                self.list.frame = None;
                                self.list.layers.clear();
                                self.list.field = None;
                                self.display_validate_selection = false;
                                self.display_jump_note = Some(format!("The display filter hides frame {number}. Select a visible packet."));
                            } else {
                                self.display_validate_selection = false;
                                self.list.selected = Some(packet.clone());
                                self.list.frame = None;
                                self.list.field = None;
                                self.display_jump_note = if position.is_none() {
                                    Some(format!("Frame {number} is selected in Details and hidden by the current display filter."))
                                } else if !Filter::parse(&self.filter).matches(&packet) {
                                    Some(format!("Frame {number} is selected in Details and hidden by the current quick search."))
                                } else {
                                    Some(format!("Selected frame {number}"))
                                };
                                if let (Some(position), Some(index)) =
                                    (position, &self.display_index)
                                {
                                    let start = position / PAGE_SIZE as u64 * PAGE_SIZE as u64;
                                    if start != self.display_page_start {
                                        self.display_generation =
                                            worker.request_page(Arc::clone(index), start);
                                        self.display_pending = true;
                                    }
                                }
                            }
                        }
                        Err(error) => self.display_jump_note = Some(error),
                    }
                }
                _ => {}
            }
        }
        if !self.display_pending {
            if let (Some(number), Some(index)) = (self.display_jump, &self.display_index) {
                self.display_jump = None;
                self.display_generation = worker.request_frame(Arc::clone(index), number);
                self.display_pending = true;
            }
        }
        if self
            .display_identity_checked
            .is_none_or(|at| at.elapsed() >= Duration::from_secs(1))
        {
            self.display_identity_checked = Some(Instant::now());
            if let Some(path) = &self.list.path {
                match CaptureIdentity::read(path) {
                    Ok(identity) => {
                        if self
                            .display_identity
                            .as_ref()
                            .is_some_and(|previous| !previous.permits_append(&identity))
                        {
                            worker.cancel();
                            self.display_pending = false;
                            self.display_index = None;
                            self.display_next_index = None;
                            self.display_page.clear();
                            self.display_requested = None;
                            self.list.selected = None;
                            self.list.frame = None;
                            self.list.packets.clear();
                            self.list.next_offset = 0;
                            self.list.next_number = 0;
                            self.list.truncated = false;
                            self.list.rows_for = None;
                            self.list.counts = None;
                            self.list.last_read = None;
                            self.payloads = None;
                        }
                        self.display_identity = Some(identity);
                    }
                    Err(error) => {
                        self.display_error = Some(error);
                        worker.cancel();
                        self.display_pending = false;
                    }
                }
            }
        }
        if matches!(worker.fields(), FieldRegistry::Ready(_))
            && !self.display_pending
            && self
                .display_edited
                .is_none_or(|at| at.elapsed() >= Duration::from_millis(350))
        {
            if let Some(identity) = self
                .display_identity
                .as_ref()
                .filter(|identity| identity.file_size >= 24)
            {
                let expression = self.display_filter.trim().to_owned();
                // Invalid edited expressions are only retried on a new edit. Live
                // updates continue evaluating the prior valid expression instead.
                if self.display_rejected.as_deref() == Some(expression.as_str())
                    && self.display_index.is_none()
                {
                    return;
                }
                let expression = if self.display_rejected.as_deref() == Some(expression.as_str()) {
                    self.display_index
                        .as_ref()
                        .map_or(expression.clone(), |index| index.expression.clone())
                } else {
                    expression
                };
                let request = (identity.clone(), expression.clone(), live);
                if self.display_requested.as_ref() != Some(&request) {
                    self.display_generation = worker.request(identity.clone(), expression, live);
                    self.display_requested = Some(request);
                    self.display_pending = true;
                }
            }
        }
        if self.display_pending || matches!(worker.fields(), FieldRegistry::Loading) {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
        if self.display_jump.is_some() && self.display_index.is_none() && !self.display_pending {
            let error = match worker.fields() {
                FieldRegistry::Unavailable(error) => Some(error),
                _ => self.display_error.clone(),
            };
            if let Some(error) = error {
                self.display_jump = None;
                self.display_jump_note = Some(format!("frame navigation is unavailable: {error}"));
            }
        }
        if let Some(at) = self
            .display_edited
            .filter(|at| at.elapsed() < Duration::from_millis(350))
        {
            ctx.request_repaint_after(Duration::from_millis(350).saturating_sub(at.elapsed()));
        }
    }

    pub(super) fn scan(&mut self, recordings: Option<&Path>, recording_roots: &[PathBuf]) {
        self.captures = capture_history(recordings, recording_roots);
        self.captures_for = Some((recordings.map(Path::to_path_buf), recording_roots.to_vec()));
    }
}

pub(super) fn counts(packets: &[NetworkPacket]) -> Counts {
    fn sorted<K: Ord>(map: HashMap<K, usize>) -> Vec<(K, usize)> {
        let mut entries: Vec<_> = map.into_iter().collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        entries
    }
    let (mut ports, mut addresses, mut protocols) = (
        HashMap::new(),
        HashMap::new(),
        HashMap::<&str, usize>::new(),
    );
    for packet in packets {
        // A packet counts once for a value it carries on both sides.
        for port in [
            packet.src_port,
            packet.dst_port.filter(|p| Some(*p) != packet.src_port),
        ]
        .into_iter()
        .flatten()
        {
            *ports.entry(port).or_default() += 1;
        }
        for address in [
            packet.src_ip,
            packet.dst_ip.filter(|a| Some(*a) != packet.src_ip),
        ]
        .into_iter()
        .flatten()
        {
            *addresses.entry(address).or_default() += 1;
        }
        *protocols.entry(packet.protocol.as_str()).or_default() += 1;
    }
    Counts {
        ports: sorted(ports),
        addresses: sorted(addresses),
        protocols: sorted(protocols)
            .into_iter()
            .map(|(protocol, count)| (protocol.to_owned(), count))
            .collect(),
    }
}
