// SPDX-License-Identifier: MIT
//! Applying the display filter and refreshing the packet list.
use super::*;

impl NetworkView {
    /// Whether TShark cannot run, and why. Without it the list holds raw
    /// frames only and nothing is decoded.
    pub(super) fn tshark_unavailable(&self) -> Option<String> {
        match &self.display_worker {
            Some(worker) => match worker.fields() {
                FieldRegistry::Unavailable(error) => Some(error),
                _ => None,
            },
            None => self.display_worker_error.clone(),
        }
    }

    /// Packets of the open capture the list can show: TShark's count of the
    /// frames it has parsed, or the raw frames read without it.
    pub(super) fn loaded_count(&self) -> usize {
        match (&self.display_index, self.raw_frames()) {
            (Some(index), false) => index.rows().done_count() as usize,
            _ => self.list.packets.len(),
        }
    }

    /// The list shows raw frames read from the pcap (TShark is unavailable).
    pub(super) fn raw_frames(&self) -> bool {
        self.tshark_unavailable().is_some()
    }

    pub(super) fn clear_detail(&mut self) {
        self.detail = None;
        self.detail_node = None;
        if let Some(worker) = &self.display_worker {
            worker.cancel_detail();
        }
    }

    /// Take TShark's answer about the selected packet, when it has come.
    pub(super) fn poll_detail(&mut self) {
        let Some(worker) = &self.display_worker else {
            return;
        };
        if let Some(PacketFilterEvent::Detail {
            generation,
            number,
            result,
        }) = worker.poll_detail()
        {
            if let Some(detail) = self
                .detail
                .as_mut()
                .filter(|detail| detail.generation == generation && detail.number == number)
            {
                detail.state = match result {
                    Ok(ready) => DetailState::Ready(ready),
                    Err(error) => DetailState::Failed(error),
                };
            }
        }
    }

    /// Ask TShark for the details of the selected packet, once per selection.
    pub(super) fn request_detail(&mut self, number: u64, ctx: &egui::Context) {
        if self
            .detail
            .as_ref()
            .is_some_and(|detail| detail.number == number)
        {
            if self
                .detail
                .as_ref()
                .is_some_and(|detail| matches!(detail.state, DetailState::Loading))
            {
                ctx.request_repaint_after(Duration::from_millis(50));
            }
            return;
        }
        let (Some(worker), Some(index)) = (&self.display_worker, &self.display_index) else {
            return;
        };
        if self.tshark_unavailable().is_some() {
            return;
        }
        let generation = worker.request_detail(Arc::clone(index), number);
        self.detail = Some(DetailView {
            number,
            generation,
            state: DetailState::Loading,
        });
        self.detail_node = None;
        ctx.request_repaint_after(Duration::from_millis(50));
    }

    /// Keep the last valid filter. A display expression that does not parse,
    /// including an unknown dotted field, does not become a text search.
    pub(super) fn apply_filter(&mut self) {
        let text = self.filter.trim().to_owned();
        let text = text.as_str();
        if self.applied_filter != text
            && self
                .list
                .selected
                .as_ref()
                .is_some_and(|packet| !Filter::parse(text).matches(packet))
        {
            self.list.selected = None;
            self.list.frame = None;
            self.clear_detail();
            self.display_jump_note = Some(
                "The quick search hides the previously selected frame. Select a visible packet."
                    .into(),
            );
        }
        self.applied_filter = text.to_owned();
        self.filter_error = None;
        if !self.raw_frames() {
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
                    rows_done,
                    result,
                } if generation == self.display_generation => {
                    self.display_pending = false;
                    match result {
                        Ok(packets) => {
                            self.display_page = packets;
                            self.display_page_start = start;
                            self.display_page_progress = rows_done;
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
                                self.detail = None;
                                self.detail_node = None;
                                worker.cancel_detail();
                                self.display_validate_selection = false;
                                self.display_jump_note = Some(format!("The display filter hides frame {number}. Select a visible packet."));
                            } else {
                                self.display_validate_selection = false;
                                self.list.selected = Some(packet.clone());
                                self.capture_details = None;
                                self.list.frame = None;
                                self.detail = None;
                                self.detail_node = None;
                                worker.cancel_detail();
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
        // Rows TShark printed after the page on screen was read.
        if !self.display_pending {
            if let Some(index) = self.display_index.clone() {
                let expected = index
                    .matching_count
                    .saturating_sub(self.display_page_start)
                    .min(PAGE_SIZE as u64);
                if (self.display_page.len() as u64) < expected
                    && index.rows().done_count() > self.display_page_progress
                {
                    self.display_generation = worker.request_page(index, self.display_page_start);
                    self.display_pending = true;
                }
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
        if self
            .display_index
            .as_ref()
            .is_some_and(|index| index.rows().status() == ParseStatus::Parsing)
        {
            ctx.request_repaint_after(Duration::from_millis(250));
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
        // The quick-filter lists show this many; the rest would only be kept
        // in memory (one entry per distinct port and address in the capture).
        entries.truncate(QUICK_ENTRIES);
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
