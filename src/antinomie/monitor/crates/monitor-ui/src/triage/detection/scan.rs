// SPDX-License-Identifier: GPL-3.0-only
//! Scan scheduling for the Detection tab: digests, the registry and engine launches (moved out of `detection`).
use super::*;

impl View {
    /// Size and modification time of a regular file, `None` if it is not one.
    /// Read from the disk at most once per [`STAT_KEEP`].
    pub(super) fn stat(&mut self, id: &str, path: &Path) -> Option<(u64, u128)> {
        if let Some((at, found)) = self.stats.get(id) {
            if at.elapsed() < STAT_KEEP {
                return *found;
            }
        }
        let found = std::fs::metadata(path)
            .ok()
            .filter(|meta| meta.is_file())
            .map(|meta| {
                let modified = meta
                    .modified()
                    .ok()
                    .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|time| time.as_nanos())
                    .unwrap_or(0);
                (meta.len(), modified)
            });
        self.stats.insert(id.to_owned(), (Instant::now(), found));
        found
    }
    pub(super) fn cached_file_digest(
        &mut self,
        ctx: &egui::Context,
        path: &Path,
    ) -> Option<String> {
        let id = path.display().to_string();
        let Some((len, modified)) = self.stat(&id, path) else {
            return Some("missing".into());
        };
        if let Some(cached) = self.digests.get(&id) {
            if cached.len == len && cached.modified == modified {
                return Some(cached.digest.clone());
            }
        }
        if self.digest_rx.is_none() {
            let path = path.to_path_buf();
            let (tx, rx) = mpsc::sync_channel(1);
            let ctx = ctx.clone();
            if std::thread::Builder::new()
                .name("triage-evidence-hash".into())
                .spawn(move || {
                    let digest = antinomie_monitor_core::storage::sha256_file_hex(&path)
                        .unwrap_or_else(|_| "unreadable".into());
                    let _ = tx.send((id, len, modified, digest));
                    ctx.request_repaint_of(egui::ViewportId::ROOT);
                })
                .is_ok()
            {
                self.digest_rx = Some(rx);
            }
        }
        None
    }
    pub(super) fn evidence_identity(
        &mut self,
        ctx: &egui::Context,
        engine: Engine,
        input: &TriageInput<'_>,
    ) -> String {
        match engine {
            Engine::Yara => {
                let Some(analysis) = input.analysis else {
                    return "wait:sample".into();
                };
                let archive = match input.archive {
                    Some(archive) => {
                        let artifacts =
                            self.cached_file_digest(ctx, &archive.join("artifacts.json"));
                        let journal =
                            self.cached_file_digest(ctx, &archive.join(engine::JOURNAL_FILE));
                        match (artifacts, journal) {
                            (Some(artifacts), Some(journal)) => format!("{artifacts}:{journal}"),
                            _ => return "wait:digest".into(),
                        }
                    }
                    None => "no-archive".into(),
                };
                format!(
                    "ready:yara:{}:{}:{archive}:mem={}:recovered={}",
                    analysis.id,
                    analysis.specimen_sha256.as_deref().unwrap_or(""),
                    self.settings.scan_memory,
                    self.settings.scan_recovered
                )
            }
            Engine::Ids => match (input.pcap, input.pcap_open) {
                (None, _) => "missing:pcap".into(),
                (Some(_), true) => "wait:pcap".into(),
                (Some(path), false) => {
                    let Some(digest) = self.cached_file_digest(ctx, path) else {
                        return "wait:digest".into();
                    };
                    format!(
                        "ready:pcap:{}:{digest}:{}",
                        path.display(),
                        input.run_id.unwrap_or("")
                    )
                }
            },
            Engine::Sigma => {
                if !input.run_finished {
                    return "wait:journal".into();
                }
                let Some(archive) = input.archive else {
                    return format!("ready:journal:{}:no-archive", input.run_id.unwrap_or(""));
                };
                let Some(digest) =
                    self.cached_file_digest(ctx, &archive.join(engine::JOURNAL_FILE))
                else {
                    return "wait:digest".into();
                };
                format!("ready:journal:{}:{digest}", input.run_id.unwrap_or(""))
            }
        }
    }
    pub(super) fn consider_auto(&mut self, ctx: &egui::Context, input: &TriageInput<'_>) {
        if self.seen_generation != self.rules_generation {
            self.seen_generation = self.rules_generation;
            self.digest_generation = u64::MAX;
        }
        for (index, engine) in ENGINES.iter().enumerate() {
            let key = self.evidence_identity(ctx, *engine, input);
            self.ready_key[index] = key.clone();
            self.notes[index] = header::evidence_note(&key);
            let digest = self.current_digest(ctx, index);
            if digest == "preparing" {
                // Saved results stay on screen while the rule sets are
                // checked again in the background: no bar over them.
                if !matches!(self.results[index], Some(Ok(_))) {
                    self.phase[index] = "preparing".into();
                }
                continue;
            }
            if key.starts_with("ready:") {
                self.budgets[index].observe(&format!("{key}|{digest}"));
            }
            let saved_matches = match &self.results[index] {
                Some(Ok(report)) => {
                    !report.selection.is_empty()
                        && report.selection == digest
                        && report.evidence_key == key
                }
                _ => false,
            };
            if saved_matches && self.auto_key[index].is_empty() {
                self.auto_key[index] = key;
                self.scanned_generation[index] = self.rules_generation;
                continue;
            }
            if !self.automatic || self.rx.is_some() || !key.starts_with("ready:") {
                continue;
            }
            // An engine tool that has not answered yet (a busy machine) is
            // asked again by the probe; scanning now would only record that
            // nothing could be evaluated.
            if self.tool_unanswered(index) {
                continue;
            }
            let now = std::time::Instant::now();
            if !self.budgets[index].allow(now) {
                if let Some(at) = self.budgets[index].ready_at {
                    if let Some(wait) = at.checked_duration_since(now) {
                        ctx.request_repaint_after(wait);
                    }
                }
                continue;
            }
            if self.auto_key[index] == key
                && self.scanned_generation[index] == self.rules_generation
            {
                continue;
            }
            match self.start_engine(ctx, *engine, None, false, &key, true) {
                Admit::Started => {
                    self.auto_key[index] = key;
                    self.scanned_generation[index] = self.rules_generation;
                    self.budgets[index].admit(now);
                }
                Admit::Preparing => {}
                Admit::Failed => {
                    self.budgets[index].admit(now);
                }
            }
            break;
        }
    }
    /// Whether the probe of the tool behind engine `index` has no answer.
    pub(super) fn tool_unanswered(&self, index: usize) -> bool {
        use antinomie_monitor_core::ruleset::ToolProbe;
        self.digest_facts.as_ref().is_some_and(|facts| {
            matches!(
                [None, Some(&facts.suricata), Some(&facts.sigma)][index],
                Some(ToolProbe::Unknown(_))
            )
        })
    }
    pub(super) fn fresh_registry(&self) -> Option<&antinomie_monitor_core::ruleset::Registry> {
        self.registry
            .as_ref()
            .filter(|_| self.registry_for == self.rules_generation)
    }
    pub(super) fn request_registry(&mut self, ctx: &egui::Context) {
        if self.registry_rx.is_some() || self.settings.rules_root.is_empty() {
            return;
        }
        let dir = PathBuf::from(&self.settings.rules_root);
        let epoch = self.epoch;
        let (tx, rx) = mpsc::sync_channel(1);
        let ctx = ctx.clone();
        match std::thread::Builder::new()
            .name("triage-rules-registry".into())
            .spawn(move || {
                let result = (|| {
                    antinomie_monitor_core::ruleset::migrate_indexes(&dir)?;
                    let registry = antinomie_monitor_core::ruleset::load_registry(&dir)?;
                    let sets = ["yara", "ids", "sigma"].map(|engine| {
                        antinomie_monitor_core::ruleset::engine_sets(&dir, &registry, engine)
                    });
                    Ok(RegistryPayload { registry, sets })
                })();
                let _ = tx.send(RegistryMsg { epoch, result });
                ctx.request_repaint_of(egui::ViewportId::ROOT);
            }) {
            Ok(_) => self.registry_rx = Some(rx),
            Err(error) => {
                self.phase = ["failed".into(), "failed".into(), "failed".into()];
                self.results[0] = Some(Err(error.to_string()));
            }
        }
    }
    pub(super) fn start(&mut self, ctx: &egui::Context, digest: Option<String>, partial: bool) {
        let index = ENGINES
            .iter()
            .position(|candidate| *candidate == self.selected)
            .unwrap_or(0);
        let key = self.ready_key[index].clone();
        let _ = self.start_engine(ctx, self.selected, digest, partial, &key, false);
    }
    pub(super) fn start_engine(
        &mut self,
        ctx: &egui::Context,
        engine: Engine,
        digest: Option<String>,
        partial: bool,
        evidence_key: &str,
        automatic: bool,
    ) -> Admit {
        let index = ENGINES
            .iter()
            .position(|candidate| *candidate == engine)
            .unwrap_or(0);
        let pending = PendingScan {
            engine,
            digest: digest.clone(),
            partial,
            evidence_key: evidence_key.to_owned(),
            automatic,
            generation: self.rules_generation,
            epoch: self.epoch,
        };
        if self.rx.is_some() {
            self.pending = Some(pending);
            self.phase[index] = "queued".into();
            return Admit::Preparing;
        }
        self.settings.partial = partial;
        self.settings.evidence_key = evidence_key.to_owned();
        let Some(request) = self.request(engine, digest) else {
            self.phase[index] = "failed".into();
            return Admit::Failed;
        };
        if request.settings.rules_root.is_empty() {
            return self.launch(ctx, request, None, index, automatic);
        }
        let Some(registry) = self.fresh_registry().cloned() else {
            self.pending = Some(pending);
            self.phase[index] = "preparing".into();
            self.request_registry(ctx);
            return Admit::Preparing;
        };
        self.launch(ctx, request, Some(registry), index, automatic)
    }
    pub(super) fn launch(
        &mut self,
        ctx: &egui::Context,
        mut request: engine::Request,
        registry: Option<antinomie_monitor_core::ruleset::Registry>,
        index: usize,
        automatic: bool,
    ) -> Admit {
        self.auto_started[index] = automatic;
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let (tx, rx) = mpsc::sync_channel(1);
        let (progress_tx, progress_rx) = mpsc::channel();
        let ctx = ctx.clone();
        let epoch = self.epoch;
        let generation = self.rules_generation;
        let root = request.settings.rules_root.clone();
        let tools = antinomie_monitor_core::ruleset::ToolConfig::from_sigma_setting(
            &request.settings.effective_sigma_python(),
        );
        let engine_name = engine_key(request.engine).to_owned();
        match std::thread::Builder::new()
            .name("triage-detector".into())
            .spawn(move || {
                let result = (|| {
                    if !root.is_empty() {
                        let registry =
                            registry.ok_or_else(|| "rules registry was not captured".to_owned())?;
                        let data_dir = Path::new(&root);
                        let _ = antinomie_monitor_core::ruleset::reap_staging(
                            data_dir,
                            Duration::from_secs(3600),
                        );
                        if worker_cancel.load(Ordering::Relaxed) {
                            return Err("cancelled".into());
                        }
                        let facts = antinomie_monitor_core::ruleset::tool_facts(&tools);
                        let snap = antinomie_monitor_core::ruleset::snapshot_from(
                            data_dir,
                            &engine_name,
                            &registry,
                            &facts,
                            Some(&worker_cancel),
                        )?;
                        request.frozen = Some(engine::FrozenSelection {
                            digest: snap.digest,
                            directory: snap.directory,
                            enabled_rules: snap.enabled_rules,
                            excluded_rules: snap.excluded_rules,
                            warnings: snap.warnings,
                        });
                    }
                    engine::run_with_progress(request, &worker_cancel, Some(progress_tx))
                })();
                let _ = tx.send(Reply::Scanned {
                    epoch,
                    generation,
                    index,
                    result: Box::new(result),
                });
                ctx.request_repaint_of(egui::ViewportId::ROOT);
            }) {
            Ok(_) => {
                self.rx = Some(rx);
                self.progress_rx = Some(progress_rx);
                self.progress[index] = None;
                self.cancel = Some(cancel);
                self.busy = Some(index);
                self.phase[index] = "running".into();
                Admit::Started
            }
            Err(error) => {
                self.phase[index] = "failed".into();
                self.results[index] = Some(Err(error.to_string()));
                Admit::Failed
            }
        }
    }
    pub(super) fn read_bytes(&mut self, ctx: &egui::Context, evidence: Evidence) {
        if self.byte_rx.is_some() {
            self.pending_byte = Some(evidence);
            return;
        }
        let Some(request) = self.request(Engine::Yara, None) else {
            return;
        };
        let (tx, rx) = mpsc::sync_channel(1);
        let ctx = ctx.clone();
        self.bytes = None;
        match std::thread::Builder::new()
            .name("triage-match-bytes".into())
            .spawn(move || {
                let result =
                    engine::read_evidence(&request, &evidence).map(|data| (evidence, data));
                let _ = tx.send(result);
                ctx.request_repaint_of(egui::ViewportId::ROOT);
            }) {
            Ok(_) => self.byte_rx = Some(rx),
            Err(error) => self.bytes = Some(Err(error.to_string())),
        }
    }
    pub(super) fn drain_progress(&mut self) {
        let mut latest = None;
        let mut dead = false;
        if let Some(rx) = &self.progress_rx {
            loop {
                match rx.try_recv() {
                    Ok(progress) => latest = Some(progress),
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        dead = true;
                        break;
                    }
                }
            }
        }
        if dead {
            self.progress_rx = None;
        }
        if let Some(progress) = latest {
            if let Some(index) = self.busy {
                self.progress[index] = Some(progress);
            }
        }
    }
}
