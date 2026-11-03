// SPDX-License-Identifier: GPL-3.0-only
//! Building the app from the creation context and saved state (moved out of `app`).
use super::*;

impl MonitorApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        mut options: BackendOptions,
        smoke: Option<Duration>,
        restore_bundle: bool,
    ) -> Self {
        theme::install(&cc.egui_ctx);
        let mut settings: Settings = cc
            .storage
            .and_then(|storage| eframe::get_value(storage, "settings"))
            .unwrap_or_default();
        if settings.bundle.is_empty() || !restore_bundle {
            settings.bundle = options.bundle_dir.to_string_lossy().into_owned();
        }
        settings.migrate();
        crate::tzone::choose(&settings.time_zone);
        settings.font_size = settings.font_size.clamp(12.0, 24.0);
        theme::apply_theme(&cc.egui_ctx, settings.active_theme());
        theme::set_compact(&cc.egui_ctx, settings.compact);
        theme::text_size(&cc.egui_ctx, settings.font_size);
        options.bundle_dir = crate::folders::user_path(&settings.bundle);
        options.capture_quota_size = u64::from(settings.quota_gib) * 1024 * 1024 * 1024;
        options.shutdown_timeout = Duration::from_secs(settings.timeout);
        settings.start = if settings.start.validate().is_ok() {
            settings.start
        } else {
            Default::default()
        };
        options.start = settings.start;
        // Before the backend starts: it finishes layers an earlier process left.
        antinomie_monitor_core::file_before_store::set_limits(settings.before_limits());
        let (backend, start_error) = match start_error::start_backend(&options, &cc.egui_ctx) {
            Ok(backend) => (Some(backend), None),
            Err(error) => (None, Some(error)),
        };
        let status = String::new();
        let exec = ExecRequest::default();
        let env = exec.env.join("\n");
        let dependencies =
            crate::dependencies_window::DependenciesWindow::start(&options, &cc.egui_ctx);
        let mut folder_picker = FolderPicker::new();
        folder_picker.refresh(&cc.egui_ctx);
        let mut explorer_browser = upload_browser::Browser::default();
        if let Some(root) = settings.explorer_root.clone() {
            explorer_browser.reset(root);
        }
        let routes = route_settings::RouteSettings::load(&options.data_dir);
        let mut app = Self {
            performance: crate::ui_performance::Performance::new(cc.gl.as_deref()),
            last_frame_start: None,
            backend,
            start_error,
            catalog_feedback: Default::default(),
            snapshot: Snapshot::default(),
            selected: None,
            selected_base: None,
            settings,
            options,
            settings_open: false,
            settings_focus: None,
            settings_focus_rebuild: false,
            settings_page: Default::default(),
            create_open: false,
            config_open: false,
            launch_open: false,
            upload_open: false,
            launch_source: Default::default(),
            draft: VmConfig::default(),
            draft_generation: 0,
            folder_picker,
            credentials: CredentialForm::default(),
            import_open: false,
            import_directory: String::new(),
            download_open: false,
            build_open: false,
            about_open: false,
            library_requests: Vec::new(),
            rules_ui: crate::rules_window::Model::default(),
            rules_summary: String::new(),
            rules_generation: 0,
            vm_snapshots: crate::snapshots::SnapshotManager::default(),
            summary_snapshots_asked: None,
            samples: crate::samples_view::SamplesView::default(),
            samples_page: samples_page::SamplesPage::default(),
            api_keys: Default::default(),
            dependencies,
            updates: Default::default(),
            getting_started: Default::default(),
            show_older_bases: false,
            build_wizard: build_wizard::BuildWizard::default(),
            confirm: None,
            clipboard_request: None,
            pending_kill: None,
            name_action: None,
            status,
            filter: String::new(),
            applied_filter: String::new(),
            trace_sort: None,
            selected_event: None,
            trace_evidence: None,
            selected_run: None,
            selected_capture: None,
            selected_process: None,
            transport_open: false,
            stealth_open: false,
            network_view: Default::default(),
            memory_view: Default::default(),
            disk_view: Default::default(),
            core_view: Default::default(),
            triage: Default::default(),
            cpu_history: Default::default(),
            triage_pcap: Default::default(),
            run_labels: Default::default(),
            routes,
            run_tree: None,
            run_tree_pending: None,
            archive_total: None,
            archive_source_total: None,
            evidence_jobs: Default::default(),
            details_follow: Default::default(),
            archived_processes: None,
            capture_history: Vec::new(),
            capture_tab: false,
            process_picker: captures::ProcessPicker::default(),
            debugger: debugger::DebuggerPanel::default(),
            pending_observer: None,
            pending_core: None,
            pending_network: None,
            pending_deletions: Vec::new(),
            selected_analysis: None,
            analysis_windows: BTreeMap::new(),
            analysis_directories: BTreeMap::new(),
            pending_analysis_sections: Vec::new(),
            pending_static_row: None,
            pending_sub_tab: None,
            analysis_views: BTreeMap::new(),
            analysis_generation: 0,
            archive_selected: false,
            history_generation: 0,
            run_filter: RunFilter::All,
            run_query: String::new(),
            applied_run_query: String::new(),
            terminals: BTreeMap::new(),
            archive: None,
            pending_archive: None,
            history: Vec::new(),
            history_sync: Default::default(),
            archive_generation: 0,
            archive_page_generation: 0,
            archive_page: Vec::new(),
            archive_offset: 0,
            trace_paging: Default::default(),
            archive_next: None,
            archive_previous: Vec::new(),
            archive_pending: false,
            archive_error: None,
            archive_read_cancel: None,
            archive_hidden_categories: Vec::new(),
            inspector: Inspector::default(),
            data_windows: crate::data_view::DataWindows::default(),
            layout: WorkspaceLayout::restore(crate::workspace::load_layout(cc.storage)),
            focus_panel: None,
            shortcut_ui: Default::default(),
            activity: crate::activity::Journal::restore(cc.storage),
            activity_notices_due: true,
            jobs: Default::default(),
            quit_confirmed: false,
            status_notice: None,
            exec,
            args: String::new(),
            env,
            source: String::new(),
            destination: "/tmp/program".into(),
            // The Upload dialog starts with both options on.
            executable: true,
            overwrite: true,
            upload_browser: Default::default(),
            explorer_browser,
            pending_upload: None,
            uploaded: None,
            pending_launch: None,
            pending_launch_context: None,
            pending_sessions: BTreeMap::new(),
            stale_command_ids: VecDeque::new(),
            backend_disconnected: false,
            run_list_cache: None,
            run_selector_cache: Default::default(),
            started: Instant::now(),
            smoke,
            closing: false,
            #[cfg(test)]
            submitted: Vec::new(),
            #[cfg(test)]
            launch_action_rects: None,
        };
        app.configure_detection();
        match ArchiveWorker::new(Some(cc.egui_ctx.clone())) {
            Ok(worker) => {
                app.archive = Some(worker);
                app.refresh_history();
            }
            Err(error) => app.status = format!("Archive worker: {error}"),
        }
        app.layout.validate();
        if !app.status.is_empty() {
            app.log("ERROR", app.status.clone());
        }
        app
    }
}
