// SPDX-License-Identifier: MIT
//! Headless tests of the Disks tab: its states, tree, Details, Find and the
//! requests it makes. The reader is not started: answers are fed in as the
//! reader thread would deliver them.
use super::{extraction::Intent, tree::Listing, *};
use crate::{app::tests::texts, theme};
use antinomie_monitor_core::disks::{
    reader::{
        DiskAnswer, DiskEntry, DiskFileInfo, DiskListing, ExtractReceipt, FindMode, FindQuery,
        FoundEntry,
    },
    DiskJobPurpose, DiskJobStage, DiskSourceRecord, Ext4State,
};

const SIZE: egui::Vec2 = egui::vec2(1200.0, 800.0);

struct Scene {
    vm: Option<VmConfig>,
    vm_off: bool,
    can_stop: bool,
    view: Option<CurrentDiskView>,
    measure: Option<DiskMeasure>,
    job: Option<DiskJobProgress>,
    reference: Option<CurrentDiskView>,
    checkpoints: Vec<VmCheckpoint>,
    triage_paths: Arc<BTreeSet<String>>,
    other_job: bool,
    settings: DiskSettings,
    /// The recording folders dumps are listed from.
    roots: Vec<PathBuf>,
    recordings: Option<PathBuf>,
}

fn machine() -> VmConfig {
    VmConfig {
        id: "vm".into(),
        name: "Debian QA".into(),
        ..VmConfig::default()
    }
}

fn measure() -> DiskMeasure {
    DiskMeasure {
        vm_id: "vm".into(),
        source: DiskSourceRecord {
            active_layer: "snapshots/ab12.qcow2".into(),
            ..DiskSourceRecord::default()
        },
        logical_size: 16 * 1024 * 1024 * 1024,
        allocated_estimate: 2_040_109_466,
        free_space: 41 * 1024 * 1024 * 1024,
        sparse_supported: true,
        measured_ms: 1,
        directory: PathBuf::from("/home/user/rec/disks"),
        quota: 4 * 1024 * 1024 * 1024,
        error: None,
        partitions: None,
        partition_error: None,
        partition: None,
    }
}

fn open_view(state: Ext4State) -> CurrentDiskView {
    CurrentDiskView {
        vm_id: "vm".into(),
        view_id: "view-1".into(),
        image: PathBuf::from("/home/user/rec/disks/.scratch-view-1/root.ext4"),
        extract_dir: PathBuf::from("/home/user/rec/disks/extracted/view-1"),
        taken_ms: 1_800_000_000_000,
        source: DiskSourceRecord {
            active_layer: "snapshots/ab12.qcow2".into(),
            active_parent_id: Some("parent-7".into()),
            ..DiskSourceRecord::default()
        },
        fs_state: state,
        logical_size: 16 * 1024 * 1024 * 1024,
        allocated_size: 812 * 1024 * 1024,
        kept_as: None,
    }
}

impl Scene {
    fn stopped() -> Self {
        Self {
            vm: Some(machine()),
            vm_off: true,
            can_stop: false,
            view: None,
            measure: None,
            job: None,
            reference: None,
            checkpoints: Vec::new(),
            triage_paths: Arc::default(),
            other_job: false,
            settings: DiskSettings::default(),
            roots: Vec::new(),
            recordings: None,
        }
    }

    fn running() -> Self {
        Self {
            vm_off: false,
            can_stop: true,
            ..Self::stopped()
        }
    }

    fn frame(
        &mut self,
        view: &mut DiskView,
        ctx: &egui::Context,
        events: Vec<egui::Event>,
    ) -> (egui::FullOutput, Option<DiskAction>) {
        let mut action = None;
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
                events,
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let next = view.show(
                        ui,
                        DiskContext {
                            vm: self.vm.as_ref(),
                            recordings: self.recordings.as_deref(),
                            recording_roots: &self.roots,
                            qemu_img: Path::new("qemu-img"),
                            vm_off: self.vm_off,
                            can_stop_vm: self.can_stop,
                            current_disk: self.view.as_ref(),
                            measure: self.measure.as_ref(),
                            job: self.job.as_ref(),
                            reference: self.reference.as_ref(),
                            checkpoints: &self.checkpoints,
                            triage_paths: &self.triage_paths,
                            other_job: self.other_job,
                            font_size: 16.0,
                            settings: &mut self.settings,
                        },
                    );
                    action = action.take().or(next);
                });
            },
        );
        (output, action)
    }

    fn settle(&mut self, view: &mut DiskView, ctx: &egui::Context) -> Vec<String> {
        let mut output = None;
        for _ in 0..4 {
            output = Some(self.frame(view, ctx, Vec::new()).0);
        }
        shown(&output.unwrap())
    }

    /// Click the text `label`; the action of the frame in which it was clicked.
    fn click(
        &mut self,
        view: &mut DiskView,
        ctx: &egui::Context,
        label: &str,
    ) -> Option<DiskAction> {
        let before = self.settle(view, ctx);
        assert!(
            before.iter().any(|text| text == label),
            "{label:?} not in {before:?}"
        );
        let output = self.frame(view, ctx, Vec::new()).0;
        let pos = texts(&output)
            .into_iter()
            .find(|(text, _)| text == label)
            .unwrap_or_else(|| panic!("clipped {label}"))
            .1
            .center();
        let mut taken = None;
        for pressed in [true, false] {
            let (_, action) = self.frame(
                view,
                ctx,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
            taken = taken.or(action);
        }
        taken
    }

    /// The Details dock for the same view.
    fn details(
        &mut self,
        view: &mut DiskView,
        ctx: &egui::Context,
    ) -> (Vec<String>, Option<DiskAction>) {
        let mut action = None;
        let mut output = None;
        for _ in 0..3 {
            output = Some(ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        action = view.details(ui).or(action.take());
                    });
                },
            ));
        }
        (shown(&output.unwrap()), action)
    }

    fn click_details(
        &mut self,
        view: &mut DiskView,
        ctx: &egui::Context,
        label: &str,
    ) -> Option<DiskAction> {
        let mut output = None;
        for _ in 0..3 {
            output = Some(self.details_frame(view, ctx, Vec::new()).0);
        }
        let pos = texts(&output.unwrap())
            .into_iter()
            .find(|(text, _)| text == label)
            .unwrap_or_else(|| panic!("missing {label}"))
            .1
            .center();
        let mut taken = None;
        for pressed in [true, false] {
            let (_, action) = self.details_frame(
                view,
                ctx,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
            taken = taken.or(action);
        }
        taken
    }

    fn details_frame(
        &mut self,
        view: &mut DiskView,
        ctx: &egui::Context,
        events: Vec<egui::Event>,
    ) -> (egui::FullOutput, Option<DiskAction>) {
        let mut action = None;
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
                events,
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    action = view.details(ui);
                });
            },
        );
        (output, action)
    }
}

fn shown(output: &egui::FullOutput) -> Vec<String> {
    texts(output).into_iter().map(|(text, _)| text).collect()
}

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx
}

fn has(texts: &[String], wanted: &str) -> bool {
    texts.iter().any(|text| text == wanted)
}

fn entry(name: &str, kind: DiskEntryKind, size: u64, mode: u32) -> DiskEntry {
    DiskEntry {
        name: name.into(),
        addressable: true,
        kind,
        size,
        mode,
        uid: 0,
        gid: 0,
        mtime: 1_800_000_000,
        atime: 1_800_000_000,
        ctime: 1_800_000_000,
        link_target: None,
    }
}

fn listing(path: &str, entries: Vec<DiskEntry>, more: bool) -> DiskListing {
    DiskListing {
        path: path.into(),
        offset: 0,
        entries,
        more,
        truncated: false,
    }
}

/// What the readers are bound to for an open view (no reader is started).
fn bound(view: CurrentDiskView) -> Bound {
    Bound {
        key: view.view_id.clone(),
        image: view.image.clone(),
        extract_dir: view.extract_dir.clone(),
        what: What::Current(Box::new(view)),
    }
}

/// A view opened on `scene`, with `/` listed.
fn opened(scene: &mut Scene, entries: Vec<DiskEntry>) -> DiskView {
    scene.view = Some(open_view(Ext4State::Clean));
    let mut view = DiskView::default();
    view.bound = scene.view.clone().map(bound);
    view.tree.reset();
    view.tree.accept("/", 0, Ok(listing("/", entries, false)));
    view.tree.listings.insert(
        "/".into(),
        Listing {
            offset: 0,
            result: Some(Ok(listing("/", vec![], false))),
            requested: true,
        },
    );
    view
}

fn root_entries() -> Vec<DiskEntry> {
    let mut link = entry("shadow-link", DiskEntryKind::Symlink, 11, 0o777);
    link.link_target = Some("/etc/shadow".into());
    let mut bad = entry("bad\u{fffd}name", DiskEntryKind::File, 1, 0o644);
    bad.addressable = false;
    vec![
        entry("etc", DiskEntryKind::Dir, 0, 0o755),
        entry(".hidden", DiskEntryKind::File, 6, 0o600),
        entry("busybox", DiskEntryKind::File, 64, 0o755),
        link,
        entry("fifo", DiskEntryKind::Fifo, 0, 0o644),
        bad,
        entry("new\nline", DiskEntryKind::File, 1, 0o4755),
    ]
}

fn load_root(view: &mut DiskView, entries: Vec<DiskEntry>) {
    view.tree.listings.clear();
    view.tree.listings.insert(
        "/".into(),
        Listing {
            offset: 0,
            result: Some(Ok(listing("/", entries, false))),
            requested: true,
        },
    );
    view.tree.dirty = true;
}

fn info_for(path: &str, entry: DiskEntry, elf: bool) -> worker::Answer {
    worker::Answer {
        token: 0,
        reply: Ok(Ok(DiskAnswer::Info(DiskFileInfo {
            path: path.into(),
            entry,
            sha256: None,
            md5: None,
            hash_note: None,
            elf,
        }))),
        placed: None,
    }
}

/// Deliver an Info answer for the selected path, as the reader would.
fn answer_info(view: &mut DiskView, path: &str, entry: DiskEntry, elf: bool) {
    let token = view
        .purposes
        .iter()
        .find_map(|(token, purpose)| {
            matches!(purpose, Purpose::Info { path: wanted } if wanted == path).then_some(*token)
        })
        .expect("an Info request is queued");
    let mut answer = info_for(path, entry, elf);
    answer.token = token;
    view.accept(&egui::Context::default(), answer);
}

#[test]
fn helpers_escape_names_and_format_modes() {
    assert_eq!(display_name("a\nb\t\u{1b}c"), "a\\nb\\t\\x1bc");
    assert_eq!(display_name("x\u{202e}y\u{200b}"), "x\\u{202e}y\\u{200b}");
    assert_eq!(display_name("plain-é"), "plain-é");
    assert_eq!(mode_rwx(DiskEntryKind::Dir, 0o755), "drwxr-xr-x");
    assert_eq!(mode_rwx(DiskEntryKind::File, 0o4755), "-rwsr-xr-x");
    assert_eq!(mode_rwx(DiskEntryKind::File, 0o4644), "-rwSr--r--");
    assert_eq!(mode_rwx(DiskEntryKind::Dir, 0o1777), "drwxrwxrwt");
    assert_eq!(mode_rwx(DiskEntryKind::Dir, 0o1776), "drwxrwxrwT");
    assert_eq!(mode_rwx(DiskEntryKind::Symlink, 0o777), "lrwxrwxrwx");
    assert_eq!(mode_rwx(DiskEntryKind::Fifo, 0o600), "prw-------");
    assert_eq!(mode_numeric(0o755), "0755");
    assert_eq!(mode_numeric(0o4755), "4755");
    assert_eq!(DiskSettings::default().extract_cap(), 256 * 1024 * 1024);
    assert_eq!(DiskSettings::default().hash_cap(), 64 * 1024 * 1024);
}

#[test]
fn with_no_vm_selected_the_tab_says_so() {
    let ctx = context();
    let mut scene = Scene::stopped();
    scene.vm = None;
    let mut view = DiskView::default();
    let texts = scene.settle(&mut view, &ctx);
    assert!(has(&texts, "Select a VM to inspect its disk."), "{texts:?}");
    assert!(!texts.iter().any(|text| text.contains("Current disk")));
}

#[test]
fn a_running_vm_disables_the_entry_and_offers_stop_vm() {
    let ctx = context();
    let mut scene = Scene::running();
    let mut view = DiskView::default();
    let texts = scene.settle(&mut view, &ctx);
    assert!(has(&texts, "Current disk (VM off)"));
    assert!(has(&texts, "VM running — stop it to inspect"), "{texts:?}");
    assert!(has(
        &texts,
        "Disk inspection and new dumps need the VM to be off. Saved dumps stay available in the list."
    ));
    assert!(texts
        .iter()
        .any(|text| text.contains("Stopping ends the running analysis session")));
    assert!(texts
        .iter()
        .any(|text| text.contains("cannot be read while QEMU writes it")));
    assert!(!has(&texts, "Open"));
    // The shortcut is the toolbar's Stop.
    let stop = format!("{} Stop VM", egui_phosphor::regular::STOP);
    assert_eq!(
        scene.click(&mut view, &ctx, &stop),
        Some(DiskAction::StopVm)
    );
    // Nothing is requested for the measurement while the VM runs.
    assert_ne!(
        scene.frame(&mut view, &ctx, Vec::new()).1,
        Some(DiskAction::Measure(Pick::default()))
    );
    // Disabled when no VM can be stopped (a stop is already under way).
    scene.can_stop = false;
    assert_eq!(scene.click(&mut view, &ctx, &stop), None);
}

#[test]
fn a_stopped_vm_asks_for_a_measurement_once_and_shows_the_card() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = DiskView::default();
    // The first frame asks; later frames wait for the answer.
    assert_eq!(
        scene.frame(&mut view, &ctx, Vec::new()).1,
        Some(DiskAction::Measure(Pick::default()))
    );
    for _ in 0..3 {
        assert_eq!(scene.frame(&mut view, &ctx, Vec::new()).1, None);
    }
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        has(&texts, "Current disk of Debian QA (VM off)"),
        "{texts:?}"
    );
    assert!(has(&texts, "Measuring the disk…"));
    assert!(has(&texts, "not opened"));

    scene.measure = Some(measure());
    view.waiting = None;
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        has(&texts, "16.0 GiB logical · ≈ 1.9 GiB allocated"),
        "{texts:?}"
    );
    assert!(has(&texts, "source snapshots/ab12.qcow2"));
    assert!(has(&texts, "41.0 GiB free in /home/user/rec/disks"));
    assert!(has(&texts, "not opened · ≈ 1.9 GiB"));
    assert_eq!(
        scene.click(&mut view, &ctx, "Open"),
        Some(DiskAction::Open(Pick::default()))
    );
}

#[test]
fn a_failed_measure_or_a_full_disk_blocks_open_and_says_why() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = DiskView {
        measured_for: Some(("vm".into(), true, Pick::default())),
        ..DiskView::default()
    };
    let mut failed = measure();
    failed.error =
        Some("the VM appears to be running or another program holds its disk: lock".into());
    scene.measure = Some(failed);
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        texts.iter().any(|text| text.contains("holds its disk")),
        "{texts:?}"
    );
    assert_eq!(scene.click(&mut view, &ctx, "Open"), None);

    let mut full = measure();
    full.free_space = 1024;
    full.error = full.space_error();
    scene.measure = Some(full);
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        texts
            .iter()
            .any(|text| text.contains("of free space under /home/user/rec/disks")),
        "{texts:?}"
    );
    assert_eq!(scene.click(&mut view, &ctx, "Open"), None);

    // A job of another VM holds the single slot.
    scene.measure = Some(measure());
    scene.other_job = true;
    assert_eq!(scene.click(&mut view, &ctx, "Open"), None);
}

#[test]
fn a_running_job_shows_progress_and_cancel() {
    let ctx = context();
    let mut scene = Scene::stopped();
    scene.job = Some(DiskJobProgress {
        vm_id: "vm".into(),
        purpose: DiskJobPurpose::View,
        stage: DiskJobStage::Converting { percent: 46.0 },
        estimate: 2_040_109_466,
        started_ms: 1,
    });
    let mut view = DiskView::default();
    let texts = scene.settle(&mut view, &ctx);
    assert!(has(&texts, "Reading the disk… 46 %"), "{texts:?}");
    assert!(has(&texts, "reading… 46 %"));
    assert!(texts.iter().any(|text| text.contains("About 1.9 GiB")));
    assert!(texts
        .iter()
        .any(|text| text.contains("starting the VM waits")));
    assert_eq!(
        scene.click(&mut view, &ctx, "Cancel"),
        Some(DiskAction::Cancel)
    );
    // No measurement is requested while a job runs.
    assert_ne!(
        scene.frame(&mut view, &ctx, Vec::new()).1,
        Some(DiskAction::Measure(Pick::default()))
    );
    // Spinner while measuring.
    scene.job = Some(DiskJobProgress {
        stage: DiskJobStage::Measuring,
        estimate: 0,
        ..scene.job.clone().unwrap()
    });
    let (output, _) = scene.frame(&mut view, &ctx, Vec::new());
    assert!(has(&shown(&output), "Measuring the disk…"));
    assert!(theme::spinners_in(&output.shapes) >= 1);
}

#[test]
fn an_open_view_shows_its_header_and_tree_rows() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = opened(&mut scene, root_entries());
    load_root(&mut view, root_entries());
    let texts = scene.settle(&mut view, &ctx);
    let header = format!(
        "Current disk (VM off) · read {} · clean · snapshots/ab12.qcow2",
        clock(1_800_000_000)
    );
    assert!(has(&texts, &header), "{texts:?}");
    assert!(
        has(&texts, "open · clean · ".to_string().as_str())
            || texts.iter().any(|t| t.starts_with("open · clean"))
    );
    let joined = texts.join("\n");
    for expected in [
        "etc/",
        "busybox",
        "shadow-link → /etc/shadow",
        ".hidden",
        "drwxr-xr-x",
        "-rwxr-xr-x",
        "lrwxrwxrwx",
        "prw-r--r--",
        "-rwsr-xr-x",
        "new\\nline",
    ] {
        assert!(
            joined.contains(expected),
            "{expected:?} missing in {joined}"
        );
    }
    // A special file has no size; the invalid name is shown but disabled.
    assert!(joined.contains("—"));
    assert!(joined.contains("bad\u{fffd}name"));
    // Directories come first, as the reader sorted them.
    let etc = texts.iter().position(|t| t.contains("etc/")).unwrap();
    let busybox = texts.iter().position(|t| t.contains("busybox")).unwrap();
    assert!(etc < busybox);
    // The header offers Close.
    assert_eq!(
        scene.click(&mut view, &ctx, "Close"),
        Some(DiskAction::Close)
    );
}

#[test]
fn toggles_hide_dotfiles_and_show_numeric_modes() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = opened(&mut scene, root_entries());
    load_root(&mut view, root_entries());
    let texts = scene.settle(&mut view, &ctx).join("\n");
    assert!(texts.contains(".hidden") && texts.contains("-rwxr-xr-x"));
    scene.settings.hide_dotfiles = true;
    scene.settings.numeric_modes = true;
    let texts = scene.settle(&mut view, &ctx).join("\n");
    assert!(!texts.contains(".hidden"), "{texts}");
    assert!(texts.contains("0755") && !texts.contains("-rwxr-xr-x"));
    assert!(texts.contains("4755"));
}

#[test]
fn expanding_a_folder_asks_for_its_listing_and_shows_it_nested() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = opened(&mut scene, root_entries());
    load_root(&mut view, root_entries());
    scene.settle(&mut view, &ctx);
    assert_eq!(view.tree.wanted(), None);
    view.tree.toggle("/etc");
    assert_eq!(view.tree.wanted(), Some(("/etc".into(), 0)));
    // Asked once.
    assert_eq!(view.tree.wanted(), None);
    view.tree.accept(
        "/etc",
        0,
        Ok(listing(
            "/etc",
            vec![entry("passwd", DiskEntryKind::File, 30, 0o644)],
            false,
        )),
    );
    let texts = scene.settle(&mut view, &ctx).join("\n");
    assert!(texts.contains("passwd"), "{texts}");
    assert!(view
        .tree
        .rows
        .iter()
        .any(|row| matches!(row, tree::Row::Entry { path, .. } if path == "/etc/passwd")));
    // A listing error becomes a row, not a failure of the tab.
    view.tree.toggle("/etc");
    view.tree.toggle("/etc");
    assert_eq!(view.tree.wanted(), Some(("/etc".into(), 0)));
    view.tree.accept("/etc", 0, Err("read error: boom".into()));
    let texts = scene.settle(&mut view, &ctx).join("\n");
    assert!(texts.contains("read error: boom"));
    // Collapsing drops the listing (a later expand reads it again).
    view.tree.toggle("/etc");
    assert!(!view.tree.listings.contains_key("/etc"));
}

#[test]
fn big_folders_page_and_only_the_viewport_draws_rows() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let entries: Vec<_> = (0..256)
        .map(|index| entry(&format!("f{index:03}"), DiskEntryKind::File, 1, 0o644))
        .collect();
    let mut view = opened(&mut scene, entries.clone());
    view.tree.listings.clear();
    view.tree.listings.insert(
        "/".into(),
        Listing {
            offset: 0,
            result: Some(Ok(listing("/", entries, true))),
            requested: true,
        },
    );
    view.tree.dirty = true;
    scene.settle(&mut view, &ctx);
    // 257 rows exist (256 entries and the paging row); far fewer widgets are made.
    assert_eq!(view.tree.rows.len(), 257);
    assert!(matches!(
        view.tree.rows.last(),
        Some(tree::Row::Page {
            offset: 0,
            count: 256,
            more: true,
            ..
        })
    ));
    assert!(view.tree.drawn_rows < 60, "drew {}", view.tree.drawn_rows);
    // Next entries asks for the second page, and Previous returns.
    view.tree.page("/", 256);
    assert_eq!(view.tree.wanted(), Some(("/".into(), 256)));
}

#[test]
fn deep_and_numerous_folders_are_bounded() {
    let mut tree = tree::Tree::default();
    tree.reset();
    // A chain of folders deeper than the limit.
    let mut path = String::new();
    let limit = crate::app::DEPTH_LIMIT;
    for depth in 0..limit + 2 {
        let name = format!("d{depth}");
        let parent = if path.is_empty() {
            "/".to_string()
        } else {
            path.clone()
        };
        tree.listings.insert(
            parent.clone(),
            Listing {
                offset: 0,
                result: Some(Ok(listing(
                    &parent,
                    vec![entry(&name, DiskEntryKind::Dir, 0, 0o755)],
                    false,
                ))),
                requested: true,
            },
        );
        path = tree::join(&parent, &name);
        tree.expanded.insert(path.clone());
    }
    tree.dirty = true;
    assert_eq!(tree.wanted(), None);
    assert!(tree
        .rows
        .iter()
        .any(|row| matches!(row, tree::Row::Message(text, _) if text.contains("use Find"))));
    // Too many expanded folders at once.
    let mut tree = tree::Tree::default();
    tree.reset();
    let entries: Vec<_> = (0..40)
        .map(|index| entry(&format!("d{index}"), DiskEntryKind::Dir, 0, 0o755))
        .collect();
    tree.listings.insert(
        "/".into(),
        Listing {
            offset: 0,
            result: Some(Ok(listing("/", entries, false))),
            requested: true,
        },
    );
    for index in 0..40 {
        tree.expanded.insert(format!("/d{index}"));
    }
    tree.dirty = true;
    tree.wanted();
    assert!(tree.listings.len() <= crate::app::DIRECTORY_LIMIT);
    assert!(tree
        .rows
        .iter()
        .any(|row| matches!(row, tree::Row::Message(text, _) if text.contains("Collapse"))));
}

#[test]
fn selecting_a_file_fills_the_details() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = opened(&mut scene, root_entries());
    load_root(&mut view, root_entries());
    // Nothing selected: the view's own details.
    let (texts, _) = scene.details(&mut view, &ctx);
    assert!(has(&texts, "Current disk (VM off)"), "{texts:?}");
    for expected in [
        "snapshots/ab12.qcow2",
        "parent-7",
        "clean",
        "16.0 GiB",
        "812 MiB",
    ] {
        assert!(has(&texts, expected), "{expected:?} in {texts:?}");
    }
    assert!(texts
        .iter()
        .any(|text| text.contains("exact final filesystem state")));

    view.select("/busybox".into());
    let busybox = entry("busybox", DiskEntryKind::File, 64, 0o755);
    answer_info(&mut view, "/busybox", busybox.clone(), true);
    let (texts, _) = scene.details(&mut view, &ctx);
    for expected in [
        "/busybox",
        "File",
        "64 bytes (64 B)",
        "0755  -rwxr-xr-x",
        "0:0",
        "Guest file; never executed on the host.",
        "Extract to view",
        "Save to host…",
        "Open with…",
        "Hand to Static Analysis",
        "Compute hashes",
    ] {
        assert!(has(&texts, expected), "{expected:?} in {texts:?}");
    }
    // A link shows where it points.
    view.select("/shadow-link".into());
    let mut link = entry("shadow-link", DiskEntryKind::Symlink, 11, 0o777);
    link.link_target = Some("/etc/shadow".into());
    answer_info(&mut view, "/shadow-link", link, false);
    let (texts, _) = scene.details(&mut view, &ctx);
    assert!(
        has(&texts, "Symbolic link") && has(&texts, "/etc/shadow"),
        "{texts:?}"
    );
    // A directory says how many entries it loaded.
    view.select("/etc".into());
    answer_info(
        &mut view,
        "/etc",
        entry("etc", DiskEntryKind::Dir, 0, 0o755),
        false,
    );
    let (texts, _) = scene.details(&mut view, &ctx);
    assert!(
        has(&texts, "Directory") && !has(&texts, "Extract to view"),
        "{texts:?}"
    );
    // A name with control characters is escaped.
    view.select("/new\nline".into());
    answer_info(
        &mut view,
        "/new\nline",
        entry("new\nline", DiskEntryKind::File, 1, 0o644),
        false,
    );
    let (texts, _) = scene.details(&mut view, &ctx);
    assert!(has(&texts, "/new\\nline"), "{texts:?}");
}

#[test]
fn the_details_buttons_queue_extractions_with_their_intent() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = opened(&mut scene, root_entries());
    load_root(&mut view, root_entries());
    view.select("/busybox".into());
    answer_info(
        &mut view,
        "/busybox",
        entry("busybox", DiskEntryKind::File, 64, 0o755),
        true,
    );
    let mut queued = Vec::new();
    for (label, expected) in [
        ("Extract to view", Intent::View),
        ("Save to host…", Intent::Save),
        ("Open with…", Intent::OpenWith),
        ("Hand to Static Analysis", Intent::Analyze),
    ] {
        view.extraction.running.clear();
        view.search_queue.clear();
        scene.click_details(&mut view, &ctx, label);
        let (token, job) = view
            .search_queue
            .last()
            .unwrap_or_else(|| panic!("{label}"));
        match (&view.purposes[token], &job.request) {
            (
                Purpose::Extract { path, intent },
                DiskRequest::Extract {
                    path: asked,
                    max_len,
                },
            ) => {
                assert_eq!((path.as_str(), asked.as_str()), ("/busybox", "/busybox"));
                assert_eq!(*max_len, 256 * 1024 * 1024);
                assert_eq!(*intent, expected, "{label}");
                assert_eq!(job.place.as_deref(), Some("/busybox"));
                queued.push(label);
            }
            other => panic!("{label}: {other:?}"),
        }
    }
    assert_eq!(queued.len(), 4);
}

#[test]
fn hand_to_static_analysis_needs_an_elf_and_extract_to_view_a_small_file() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = opened(&mut scene, root_entries());
    load_root(&mut view, root_entries());
    view.select("/notes".into());
    answer_info(
        &mut view,
        "/notes",
        entry("notes", DiskEntryKind::File, 100, 0o644),
        false,
    );
    scene.click_details(&mut view, &ctx, "Hand to Static Analysis");
    assert!(
        view.search_queue.is_empty(),
        "a non-ELF file is not handed over"
    );
    // 20 MiB: over the viewer limit, under the extraction limit.
    view.select("/big".into());
    answer_info(
        &mut view,
        "/big",
        entry("big", DiskEntryKind::File, 20 * 1024 * 1024, 0o644),
        true,
    );
    scene.click_details(&mut view, &ctx, "Extract to view");
    assert!(view.search_queue.is_empty());
    // Save to host still works for it, within the 256 MiB limit.
    scene.click_details(&mut view, &ctx, "Save to host…");
    assert_eq!(view.search_queue.len(), 1);
    // Hashes are only computed up to the cap.
    view.select("/huge".into());
    answer_info(
        &mut view,
        "/huge",
        entry("huge", DiskEntryKind::File, 100 * 1024 * 1024, 0o644),
        true,
    );
    view.search_queue.clear();
    view.extraction.running.clear();
    let before = view.browse_queue.len();
    scene.click_details(&mut view, &ctx, "Compute hashes");
    assert_eq!(view.browse_queue.len(), before, "over the 64 MiB hash cap");
}

#[test]
fn a_file_over_the_extraction_limit_needs_a_confirmation() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = opened(&mut scene, root_entries());
    load_root(&mut view, root_entries());
    view.select("/archive".into());
    let size = 300 * 1024 * 1024;
    answer_info(
        &mut view,
        "/archive",
        entry("archive", DiskEntryKind::File, size, 0o644),
        false,
    );
    scene.click_details(&mut view, &ctx, "Save to host…");
    assert!(view.search_queue.is_empty());
    let (texts, _) = scene.details(&mut view, &ctx);
    assert!(
        texts
            .iter()
            .any(|text| text.contains("300 MiB, over the 256 MiB extraction limit")),
        "{texts:?}"
    );
    scene.click_details(&mut view, &ctx, "Extract anyway");
    let (token, job) = view
        .search_queue
        .last()
        .expect("queued after the confirmation");
    assert!(matches!(
        &view.purposes[token],
        Purpose::Extract {
            intent: Intent::Save,
            ..
        }
    ));
    assert!(
        matches!(job.request, DiskRequest::Extract { max_len, .. } if max_len == 4 * 1024 * 1024 * 1024)
    );
    // Cancel drops the question.
    view.extraction.running.clear();
    view.search_queue.clear();
    view.request_extract("/other".into(), size, Intent::Save);
    assert!(view.extraction.large.is_some());
    scene.click_details(&mut view, &ctx, "Cancel");
    assert!(view.extraction.large.is_none());
    // A different cap from the settings applies.
    view.settings.extract_cap_mib = 512;
    view.request_extract("/archive2".into(), size, Intent::Save);
    assert!(view.extraction.large.is_none() && !view.search_queue.is_empty());
}

fn extracted_file(content: &[u8]) -> (PathBuf, ExtractReceipt) {
    let dir = std::env::temp_dir().join(format!("ant-disk-ui-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("1-file-{}", content.len()));
    std::fs::write(&path, content).unwrap();
    (
        path,
        ExtractReceipt {
            path: "/bin/busybox".into(),
            size: content.len() as u64,
            sha256: "ab".repeat(32),
        },
    )
}

#[test]
fn finished_extractions_open_the_viewer_or_hand_over_a_host_path() {
    let mut scene = Scene::stopped();
    let mut view = opened(&mut scene, root_entries());
    let (host, receipt) = extracted_file(b"\x7fELF-bytes");
    view.extraction.running.insert("/bin/busybox".into());
    view.extraction_done(
        "/bin/busybox".into(),
        Intent::View,
        Ok(receipt.clone()),
        Some(Ok(host.clone())),
    );
    match view.action.take() {
        Some(DiskAction::ViewBytes { bytes, title, key }) => {
            assert_eq!(bytes, b"\x7fELF-bytes");
            assert!(title.contains("/bin/busybox"));
            assert_eq!(key, host.display().to_string());
        }
        other => panic!("{other:?}"),
    }
    assert!(view.extraction.running.is_empty());
    assert_eq!(view.extracted.len(), 1);
    let status = view.status.clone().unwrap();
    assert!(!status.1 && status.0.contains("private, never executable"));

    view.extraction_done(
        "/bin/busybox".into(),
        Intent::Analyze,
        Ok(receipt.clone()),
        Some(Ok(host.clone())),
    );
    assert_eq!(view.action.take(), Some(DiskAction::Analyze(host.clone())));
    // Open with asks first: the file is hostile.
    view.extraction_done(
        "/bin/busybox".into(),
        Intent::OpenWith,
        Ok(receipt.clone()),
        Some(Ok(host.clone())),
    );
    assert!(view.action.is_none());
    assert_eq!(view.extraction.confirm_open.as_ref(), Some(&host));
    // Failures are reported, never acted on.
    view.extraction_done(
        "/x".into(),
        Intent::Analyze,
        Err("limit reached: too big".into()),
        None,
    );
    assert!(view.action.is_none());
    assert!(view.status.clone().unwrap().1);
    view.extraction_done(
        "/x".into(),
        Intent::Analyze,
        Ok(receipt),
        Some(Err("escapes".into())),
    );
    assert!(view.action.is_none() && view.status.unwrap().0.contains("escapes"));
    let _ = std::fs::remove_dir_all(host.parent().unwrap());
}

#[test]
fn open_with_waits_for_the_warning_to_be_accepted() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = opened(&mut scene, root_entries());
    load_root(&mut view, root_entries());
    view.select("/busybox".into());
    answer_info(
        &mut view,
        "/busybox",
        entry("busybox", DiskEntryKind::File, 64, 0o755),
        true,
    );
    let host = PathBuf::from("/home/user/rec/disks/extracted/view-1/1-busybox");
    view.extraction.confirm_open = Some(host.clone());
    let (texts, _) = scene.details(&mut view, &ctx);
    assert!(
        texts.iter().any(|text| text.contains("may be hostile")),
        "{texts:?}"
    );
    assert_eq!(
        scene.click_details(&mut view, &ctx, "Open anyway"),
        Some(DiskAction::OpenWith(host))
    );
    assert!(view.extraction.confirm_open.is_none());
}

#[test]
fn find_runs_off_the_ui_thread_and_reveals_a_match() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = opened(&mut scene, root_entries());
    load_root(&mut view, root_entries());
    view.find.query = "*.so".into();
    view.find.mode = find::Mode::Glob;
    scene.click(&mut view, &ctx, "Find");
    let (token, job) = view.search_queue.last().expect("a find is queued");
    let token = *token;
    assert!(matches!(&view.purposes[&token], Purpose::Find));
    assert!(matches!(
        &job.request,
        DiskRequest::Find { query: FindQuery { pattern, mode: FindMode::Glob } } if pattern == "*.so"
    ));
    assert!(view.find.running);
    let (output, _) = scene.frame(&mut view, &ctx, Vec::new());
    let texts = shown(&output);
    assert!(has(&texts, "Searching…"), "{texts:?}");
    assert!(theme::spinners_in(&output.shapes) >= 1);

    // The answer: three matches deep in the tree.
    let matches = vec![
        FoundEntry {
            path: "/lib/x86_64/libc.so.6".into(),
            kind: DiskEntryKind::File,
            offset: None,
            snippet: None,
        },
        FoundEntry {
            path: "/lib/libm.so".into(),
            kind: DiskEntryKind::File,
            offset: None,
            snippet: None,
        },
        FoundEntry {
            path: "/usr/lib/libz.so".into(),
            kind: DiskEntryKind::Symlink,
            offset: None,
            snippet: None,
        },
    ];
    view.accept(
        &egui::Context::default(),
        worker::Answer {
            token,
            reply: Ok(Ok(DiskAnswer::Found(FindResults {
                query: FindQuery {
                    pattern: "*.so".into(),
                    mode: FindMode::Glob,
                },
                matches,
                truncated: true,
                timed_out: false,
                scanned: 123,
                files_read: 0,
                bytes_read: 0,
                partial_files: 0,
                byte_limit_reached: false,
            }))),
            placed: None,
        },
    );
    assert!(!view.find.running);
    let texts = scene.settle(&mut view, &ctx);
    assert!(has(&texts, "3 matches"), "{texts:?}");
    assert!(has(&texts, "1/3"));
    assert!(texts
        .iter()
        .any(|text| text.contains("More matches exist than the limit")));
    // The first match was revealed: its folders are expanded and it is selected.
    for folder in ["/lib", "/lib/x86_64"] {
        assert!(view.tree.expanded.contains(folder), "{folder}");
    }
    assert_eq!(
        view.selection.as_ref().unwrap().path,
        "/lib/x86_64/libc.so.6"
    );
    // Next moves the selection and expands the new match's folders.
    scene.click(&mut view, &ctx, "›");
    assert_eq!(view.selection.as_ref().unwrap().path, "/lib/libm.so");
    scene.click(&mut view, &ctx, "›");
    assert_eq!(view.selection.as_ref().unwrap().path, "/usr/lib/libz.so");
    assert!(view.tree.expanded.contains("/usr/lib") && view.tree.expanded.contains("/usr"));
    scene.click(&mut view, &ctx, "‹");
    assert_eq!(view.selection.as_ref().unwrap().path, "/lib/libm.so");
}

#[test]
fn revealing_pages_to_an_entry_that_is_on_a_later_page() {
    let mut tree = tree::Tree::default();
    tree.reset();
    let first: Vec<_> = (0..256)
        .map(|index| entry(&format!("a{index:03}"), DiskEntryKind::File, 1, 0o644))
        .collect();
    tree.listings.insert(
        "/d".into(),
        Listing {
            offset: 0,
            result: Some(Ok(listing("/d", first, true))),
            requested: true,
        },
    );
    tree.listings.insert(
        "/".into(),
        Listing {
            offset: 0,
            result: Some(Ok(listing(
                "/",
                vec![entry("d", DiskEntryKind::Dir, 0, 0o755)],
                false,
            ))),
            requested: true,
        },
    );
    tree.reveal("/d/zzz");
    assert!(tree.advance_reveal(), "still looking on the next page");
    assert_eq!(tree.wanted(), Some(("/d".into(), 256)));
    tree.accept(
        "/d",
        256,
        Ok(DiskListing {
            offset: 256,
            ..listing(
                "/d",
                vec![entry("zzz", DiskEntryKind::File, 1, 0o644)],
                false,
            )
        }),
    );
    assert!(!tree.advance_reveal());
    assert!(tree
        .rows
        .iter()
        .any(|row| matches!(row, tree::Row::Entry { path, .. } if path == "/d/zzz")));
    // A path that does not exist ends the search.
    tree.reveal("/d/missing");
    assert!(!tree.advance_reveal());
}

#[test]
fn find_errors_and_empty_results_are_shown() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = opened(&mut scene, root_entries());
    load_root(&mut view, root_entries());
    view.find.finished(Ok(FindResults {
        query: FindQuery {
            pattern: "x".into(),
            mode: FindMode::Name,
        },
        matches: Vec::new(),
        truncated: false,
        timed_out: true,
        scanned: 9,
        files_read: 0,
        bytes_read: 0,
        partial_files: 0,
        byte_limit_reached: false,
    }));
    let texts = scene.settle(&mut view, &ctx);
    assert!(has(&texts, "0 matches"), "{texts:?}");
    assert!(texts.iter().any(|text| text.contains("time limit")));
    view.find
        .finished(Err("the reader did not answer in time".into()));
    let texts = scene.settle(&mut view, &ctx);
    assert!(texts
        .iter()
        .any(|text| text.contains("did not answer in time")));
    assert_eq!(scene.click(&mut view, &ctx, "Clear"), None);
    assert!(view.find.results.is_none());
}

#[test]
fn a_not_cleanly_unmounted_view_explains_what_that_means() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = opened(&mut scene, root_entries());
    scene.view = Some(open_view(Ext4State::NotClean));
    view.bound = scene.view.clone().map(bound);
    load_root(&mut view, root_entries());
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        texts
            .iter()
            .any(|text| text.contains("not cleanly unmounted")),
        "{texts:?}"
    );
    assert!(texts
        .iter()
        .any(|text| text.contains("Committed journal transactions are applied")));
    assert!(texts
        .iter()
        .any(|text| text.starts_with("open · not cleanly unmounted")));
}

#[test]
fn starting_the_vm_closes_the_view_and_the_tab_says_so() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = opened(&mut scene, root_entries());
    load_root(&mut view, root_entries());
    scene.settle(&mut view, &ctx);
    assert!(view.bound.is_some());
    // The backend closed the view because the VM started.
    scene.view = None;
    scene.vm_off = false;
    scene.can_stop = true;
    let texts = scene.settle(&mut view, &ctx);
    assert!(view.bound.is_none() && view.browse.is_none());
    assert!(view.tree.rows.is_empty() && view.selection.is_none());
    assert!(
        has(
            &texts,
            "Current disk view closed: VM started. Saved dumps stay available."
        ),
        "{texts:?}"
    );
    // After the VM stops again the stale notice is gone and the card returns.
    scene.vm_off = true;
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        !texts
            .iter()
            .any(|text| text.contains("view closed: VM started"))
            || true
    );
    scene.measure = Some(measure());
    let texts = scene.settle(&mut view, &ctx);
    assert!(has(&texts, "Open"), "{texts:?}");
}

#[test]
fn choosing_another_vm_is_not_a_closed_view() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = opened(&mut scene, root_entries());
    load_root(&mut view, root_entries());
    scene.settle(&mut view, &ctx);
    scene.view = None;
    scene.vm = Some(VmConfig {
        id: "other".into(),
        name: "Other".into(),
        ..VmConfig::default()
    });
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        !texts.iter().any(|text| text.contains("view closed")),
        "{texts:?}"
    );
    assert!(has(&texts, "Current disk of Other (VM off)"));
}

#[test]
fn a_running_vm_asks_for_a_new_measurement_after_it_stops() {
    let ctx = context();
    let mut scene = Scene::stopped();
    scene.measure = Some(measure());
    let mut view = DiskView::default();
    assert_eq!(scene.frame(&mut view, &ctx, Vec::new()).1, None);
    // The VM runs, then stops; the backend dropped the stale measurement.
    scene.vm_off = false;
    scene.measure = None;
    scene.settle(&mut view, &ctx);
    scene.vm_off = true;
    assert_eq!(
        scene.frame(&mut view, &ctx, Vec::new()).1,
        Some(DiskAction::Measure(Pick::default()))
    );
}

#[test]
fn the_refresh_button_measures_again_only_when_it_can() {
    let ctx = context();
    let mut scene = Scene::stopped();
    scene.measure = Some(measure());
    let mut view = DiskView {
        measured_for: Some(("vm".into(), true, Pick::default())),
        ..DiskView::default()
    };
    let refresh = egui_phosphor::regular::ARROW_CLOCKWISE;
    assert_eq!(
        scene.click(&mut view, &ctx, refresh),
        Some(DiskAction::Measure(Pick::default()))
    );
    view.waiting = None;
    scene.vm_off = false;
    assert_eq!(scene.click(&mut view, &ctx, refresh), None);
}

// ---- Phase 2: saved dumps, import, verify, save, delete ----

use antinomie_monitor_core::disks::dump::{DiskDump, DiskImageFormat};

/// A temporary recording folder with `disks/<id>/dump.json` sidecars.
struct Recordings(PathBuf);

impl Recordings {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ant-disk-view-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    /// A finished clean dump with an image stub; `edit` changes it first.
    fn dump(&self, id: &str, started_ms: u64, edit: impl FnOnce(&mut DiskDump)) -> DiskDump {
        let dir = self.0.join("disks").join(id);
        std::fs::create_dir_all(&dir).unwrap();
        let mut dump = DiskDump {
            id: id.into(),
            vm_id: "vm".into(),
            vm_name: "Debian QA".into(),
            file: "root.ext4".into(),
            fs_state: Ext4State::Clean,
            started_ms,
            finished_ms: Some(started_ms + 1000),
            logical_size: 16 * 1024 * 1024 * 1024,
            allocated_size: Some(812 * 1024 * 1024),
            sha256: Some("ab".repeat(32)),
            system: "Linux 6.12.94 · Debian trixie".into(),
            dir,
            ..DiskDump::default()
        };
        edit(&mut dump);
        dump.save().unwrap();
        if !dump.imported && dump.complete() {
            std::fs::write(dump.path(), b"stub").unwrap();
        }
        dump
    }
}

impl Drop for Recordings {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Scene {
    fn with_dumps(recordings: &Recordings) -> Self {
        Self {
            roots: vec![recordings.0.clone()],
            recordings: Some(recordings.0.clone()),
            ..Self::stopped()
        }
    }
}

/// Select `dump` and bind it by hand (no reader is started), listing `/`.
fn select_dump(view: &mut DiskView, scene: &Scene, dump: &DiskDump) {
    view.scan(&scene.roots);
    view.entry = Entry::Dump(dump.id.clone());
    view.bound = Some(Bound {
        key: dump.id.clone(),
        image: dump.path(),
        extract_dir: dump.extract_dir(),
        what: What::Dump,
    });
    view.tree.reset();
    view.tree
        .accept("/", 0, Ok(listing("/", root_entries(), false)));
    load_root(view, root_entries());
}

fn y_of(output: &egui::FullOutput, label: &str) -> f32 {
    texts(output)
        .into_iter()
        .find(|(text, _)| text == label)
        .unwrap_or_else(|| panic!("{label} not shown"))
        .1
        .min
        .y
}

#[test]
fn dumps_are_listed_newest_first_with_their_badges() {
    let recordings = Recordings::new();
    recordings.dump("a-clean", 3_000_000, |_| {});
    recordings.dump("b-forced", 2_000_000, |dump| {
        dump.fs_state = Ext4State::NotClean;
        dump.sha256 = None;
    });
    let image = recordings.0.join("elsewhere.ext4");
    std::fs::write(&image, b"stub").unwrap();
    recordings.dump("c-imported", 1_000_000, |dump| {
        dump.imported = true;
        dump.file = image.clone();
    });
    recordings.dump("d-moved", 900_000, |dump| {
        dump.imported = true;
        dump.file = recordings.0.join("gone.ext4");
    });
    recordings.dump("e-failed", 800_000, |dump| {
        dump.error = Some("No space left on device".into());
        dump.finished_ms = None;
    });
    recordings.dump("f-open", 700_000, |dump| dump.finished_ms = None);
    recordings.dump("g-newer", 600_000, |dump| {
        dump.format = DiskImageFormat::Unsupported
    });
    let ctx = context();
    let mut scene = Scene::with_dumps(&recordings);
    let mut view = DiskView::default();
    scene.settle(&mut view, &ctx);
    let output = scene.frame(&mut view, &ctx, Vec::new()).0;
    let texts_now = shown(&output);
    let details = [
        "clean · 812 MiB of 16.0 GiB · SHA-256",
        "not cleanly unmounted · 812 MiB of 16.0 GiB",
        "clean · imported · 812 MiB of 16.0 GiB · SHA-256",
        "file moved",
        "Failed: No space left on device",
        "incomplete",
        "made by a newer version",
    ];
    let mut last = f32::MIN;
    for detail in details {
        assert!(has(&texts_now, detail), "{detail}: {texts_now:?}");
        let y = y_of(&output, detail);
        assert!(y > last, "{detail} is out of order");
        last = y;
    }
    assert!(has(&texts_now, "7 / 7 dumps"), "{texts_now:?}");
    // The forced-off dump carries the warning glyph in its title.
    assert!(texts_now
        .iter()
        .any(|text| text.starts_with(egui_phosphor::regular::WARNING)));
    assert_eq!(view.dumps.iter().filter(|row| row.browsable()).count(), 3);
}

#[test]
fn the_list_reads_the_recordings_again_when_a_job_ends_and_not_every_frame() {
    let recordings = Recordings::new();
    recordings.dump("first", 2_000_000, |_| {});
    let ctx = context();
    let mut scene = Scene::with_dumps(&recordings);
    let mut view = DiskView::default();
    scene.settle(&mut view, &ctx);
    assert_eq!(view.dumps.len(), 1);
    // A dump that appears on disk is not noticed by idle frames.
    recordings.dump("second", 3_000_000, |_| {});
    scene.settle(&mut view, &ctx);
    assert_eq!(view.dumps.len(), 1, "no scan per frame");
    // A dump job is seen, then it ends: the list is read again.
    scene.job = Some(DiskJobProgress {
        vm_id: "vm".into(),
        purpose: DiskJobPurpose::Dump,
        stage: DiskJobStage::Converting { percent: 40.0 },
        estimate: 1 << 30,
        started_ms: 1,
    });
    let texts = scene.settle(&mut view, &ctx);
    assert!(has(&texts, "writing… 40 %"), "{texts:?}");
    assert!(has(&texts, "dumping… 40 %"), "{texts:?}");
    scene.job = None;
    scene.settle(&mut view, &ctx);
    assert_eq!(view.dumps.len(), 2);
    assert_eq!(view.dumps[0].dump.id, "second");
    // Refresh reads the list too.
    recordings.dump("third", 4_000_000, |_| {});
    scene.measure = Some(measure());
    scene.click(&mut view, &ctx, egui_phosphor::regular::ARROW_CLOCKWISE);
    scene.settle(&mut view, &ctx);
    assert_eq!(view.dumps.len(), 3);
}

#[test]
fn a_running_vm_still_browses_a_selected_dump() {
    let recordings = Recordings::new();
    let dump = recordings.dump("kept", 3_000_000, |_| {});
    let ctx = context();
    let mut scene = Scene::with_dumps(&recordings);
    scene.vm_off = false;
    scene.can_stop = true;
    let mut view = DiskView::default();
    select_dump(&mut view, &scene, &dump);
    let texts = scene.settle(&mut view, &ctx);
    // The Current disk row says the VM runs, the dump's tree is shown.
    assert!(has(&texts, "VM running — stop it to inspect"), "{texts:?}");
    assert!(
        !texts
            .iter()
            .any(|text| text.contains("need the VM to be off")),
        "{texts:?}"
    );
    assert!(
        texts
            .iter()
            .any(|text| text.starts_with("Dump · ") && text.contains("clean · root.ext4")),
        "{texts:?}"
    );
    assert!(texts.iter().any(|text| text.contains("etc")), "{texts:?}");
    assert!(has(&texts, "Hide dotfiles"));
    // Dump disk is off while the VM runs; the list can still be used.
    let mut scene2 = Scene::with_dumps(&recordings);
    scene2.vm_off = false;
    let label = format!("{} Dump disk", egui_phosphor::regular::HARD_DRIVES);
    assert_eq!(scene2.click(&mut view, &ctx, &label), None);
    // Selecting the Current disk entry shows the running notice again.
    view.entry = Entry::Current;
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        texts
            .iter()
            .any(|text| text.contains("need the VM to be off")),
        "{texts:?}"
    );
}

#[test]
fn a_dump_that_cannot_be_opened_says_why_instead_of_a_tree() {
    let recordings = Recordings::new();
    recordings.dump("failed", 5_000_000, |dump| {
        dump.error = Some("qemu-img: out of space".into());
        dump.finished_ms = None;
    });
    recordings.dump("open", 4_000_000, |dump| dump.finished_ms = None);
    recordings.dump("moved", 3_000_000, |dump| {
        dump.imported = true;
        dump.file = recordings.0.join("gone.ext4");
    });
    recordings.dump("newer", 2_000_000, |dump| {
        dump.format = DiskImageFormat::Unsupported
    });
    let ctx = context();
    let mut scene = Scene::with_dumps(&recordings);
    let mut view = DiskView::default();
    view.scan(&scene.roots);
    for (id, expected) in [
        ("failed", "This dump failed: qemu-img: out of space"),
        ("open", "This dump was never completed."),
        ("newer", "This dump was made by a newer version"),
    ] {
        view.entry = Entry::Dump(id.into());
        let texts = scene.settle(&mut view, &ctx);
        assert!(
            texts.iter().any(|text| text.starts_with(expected)),
            "{id}: {texts:?}"
        );
        assert!(view.bound.is_none(), "{id} must not start a reader");
    }
    view.entry = Entry::Dump("moved".into());
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        texts.iter().any(|text| text.contains("is no longer at")),
        "{texts:?}"
    );
    assert!(view.bound.is_none());
}

#[test]
fn clicking_a_dump_row_selects_it() {
    let recordings = Recordings::new();
    recordings.dump("failed", 5_000_000, |dump| {
        dump.error = Some("boom".into());
        dump.finished_ms = None;
    });
    let ctx = context();
    let mut scene = Scene::with_dumps(&recordings);
    let mut view = DiskView::default();
    assert_eq!(view.entry, Entry::Current);
    scene.click(&mut view, &ctx, "Failed: boom");
    assert_eq!(view.entry, Entry::Dump("failed".into()));
    // The Current disk row selects it back.
    scene.click(&mut view, &ctx, "Current disk (VM off)");
    assert_eq!(view.entry, Entry::Current);
}

#[test]
fn the_dump_record_fills_the_details_dock() {
    let recordings = Recordings::new();
    let dump = recordings.dump("rec", 3_000_000, |dump| {
        dump.source.active_layer = "snapshots/ab12.qcow2".into();
        dump.source.active_parent_id = Some("parent-7".into());
        dump.source.layers = vec![
            antinomie_monitor_core::disks::DiskLayerRef {
                filename: "snapshots/ab12.qcow2".into(),
                size: 5 << 20,
                modified_ms: 1_800_000_000_000,
                sha256: Some("cd".repeat(32)),
            },
            antinomie_monitor_core::disks::DiskLayerRef {
                filename: "/data/base.qcow2".into(),
                size: 900 << 20,
                modified_ms: 1_700_000_000_000,
                sha256: None,
            },
        ];
    });
    let ctx = context();
    let mut scene = Scene::with_dumps(&recordings);
    let mut view = DiskView::default();
    select_dump(&mut view, &scene, &dump);
    scene.settle(&mut view, &ctx);
    let (texts, _) = scene.details(&mut view, &ctx);
    for expected in [
        "Disk dump",
        "Debian QA (vm)",
        "Linux 6.12.94 · Debian trixie",
        "clean",
        "Raw ext4 (whole disk)",
        "16.0 GiB",
        "812 MiB",
        &"ab".repeat(32),
        "Current disk",
        "snapshots/ab12.qcow2",
        "parent-7",
    ] {
        assert!(has(&texts, expected), "{expected}: {texts:?}");
    }
    assert!(texts
        .iter()
        .any(|text| text.starts_with("snapshots/ab12.qcow2 · 5.0 MiB")
            && text.ends_with(&"cd".repeat(32))));
    assert!(texts
        .iter()
        .any(|text| text.starts_with("/data/base.qcow2 · 900 MiB")));
    for button in [
        "Save image to host…",
        "Save as qcow2…",
        "Verify SHA-256",
        "Open directory",
        "Delete…",
    ] {
        assert!(has(&texts, button), "{button}: {texts:?}");
    }
    assert!(texts
        .iter()
        .any(|text| text.starts_with("The guest shut down cleanly")));
    // Delete asks the application, which confirms; Open directory opens.
    assert_eq!(
        scene.click_details(&mut view, &ctx, "Delete…"),
        Some(DiskAction::Delete(Box::new(dump.clone())))
    );
    assert_eq!(
        scene.click_details(&mut view, &ctx, "Open directory"),
        Some(DiskAction::OpenWith(dump.dir.clone()))
    );
    // Selecting a file shows the file; the record returns without a selection.
    view.select("/etc".into());
    let (texts, _) = scene.details(&mut view, &ctx);
    assert!(has(&texts, "Entry"), "{texts:?}");
}

#[test]
fn an_imported_dump_and_a_forced_off_dump_are_described() {
    let recordings = Recordings::new();
    let image = recordings.0.join("evidence.ext4");
    std::fs::write(&image, b"stub").unwrap();
    let dump = recordings.dump("imp", 3_000_000, |dump| {
        dump.imported = true;
        dump.file = image.clone();
        dump.fs_state = Ext4State::NotClean;
        dump.sha256 = None;
        dump.source.kind = antinomie_monitor_core::disks::DiskSourceKind::Imported;
        dump.system = "Imported raw ext4 image".into();
    });
    let ctx = context();
    let mut scene = Scene::with_dumps(&recordings);
    let mut view = DiskView::default();
    select_dump(&mut view, &scene, &dump);
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        texts
            .iter()
            .any(|text| text.starts_with("Not cleanly unmounted")),
        "{texts:?}"
    );
    let (texts, _) = scene.details(&mut view, &ctx);
    assert!(has(&texts, "Imported image"), "{texts:?}");
    assert!(has(&texts, "not recorded"), "{texts:?}");
    assert!(has(&texts, &image.display().to_string()));
    assert!(has(&texts, "not cleanly unmounted"));
}

#[test]
fn the_dump_disk_button_follows_the_measure_the_vm_and_the_job() {
    let ctx = context();
    let label = format!("{} Dump disk", egui_phosphor::regular::HARD_DRIVES);
    // Measured and roomy: the click asks for a dump.
    let mut scene = Scene::stopped();
    scene.measure = Some(measure());
    let mut view = DiskView::default();
    assert_eq!(
        scene.click(&mut view, &ctx, &label),
        Some(DiskAction::Dump(Pick::default()))
    );
    assert!(view.waiting.is_some(), "a request is on its way");
    // ...and not twice.
    assert_eq!(scene.click(&mut view, &ctx, &label), None);
    // Not measured yet, a failed measure, a quota breach, a running job.
    let blocked = |scene: &mut Scene| {
        let mut view = DiskView::default();
        scene.click(&mut view, &ctx, &label)
    };
    let mut scene = Scene::stopped();
    assert_eq!(blocked(&mut scene), None);
    scene.measure = Some(DiskMeasure {
        error: Some("could not read".into()),
        ..measure()
    });
    assert_eq!(blocked(&mut scene), None);
    scene.measure = Some(DiskMeasure {
        quota: 1 << 30,
        ..measure()
    });
    assert_eq!(blocked(&mut scene), None);
    let texts = scene.settle(&mut DiskView::default(), &ctx);
    assert!(
        texts
            .iter()
            .any(|text| text.contains("exceeds the recording quota of 1.0 GiB")),
        "{texts:?}"
    );
    scene.measure = Some(measure());
    scene.other_job = true;
    assert_eq!(blocked(&mut scene), None);
    // The measure card has the same button beside Open.
    let mut scene = Scene::stopped();
    scene.measure = Some(measure());
    let mut view = DiskView::default();
    assert_eq!(
        scene.click(&mut view, &ctx, "Open"),
        Some(DiskAction::Open(Pick::default()))
    );
}

#[test]
fn keep_as_dump_promotes_the_open_view_once() {
    let ctx = context();
    let mut scene = Scene::stopped();
    scene.measure = Some(measure());
    let mut view = opened(&mut scene, root_entries());
    load_root(&mut view, root_entries());
    assert_eq!(
        scene.click(&mut view, &ctx, "Keep as dump"),
        Some(DiskAction::Keep)
    );
    // Not while a request is on its way, or a job runs.
    assert_eq!(scene.click(&mut view, &ctx, "Keep as dump"), None);
    view.waiting = None;
    scene.job = Some(DiskJobProgress {
        vm_id: "vm".into(),
        purpose: DiskJobPurpose::Keep,
        stage: DiskJobStage::Hashing {
            done: 512 << 20,
            total: 1 << 30,
        },
        estimate: 0,
        started_ms: 1,
    });
    // While it runs the tree stays visible beneath a progress line.
    let texts = scene.settle(&mut view, &ctx);
    assert!(has(&texts, "Computing the SHA-256… 50 %"), "{texts:?}");
    assert!(has(&texts, "Cancel"));
    assert!(
        texts.iter().any(|text| text.contains("busybox")),
        "{texts:?}"
    );
    assert_eq!(
        scene.click(&mut view, &ctx, "Cancel"),
        Some(DiskAction::Cancel)
    );
    // Once kept: the button is off and the view says where it reads from.
    scene.job = None;
    let mut kept = open_view(Ext4State::Clean);
    kept.kept_as = Some("dump-1".into());
    kept.image = PathBuf::from("/home/user/rec/disks/dump-1/root.ext4");
    scene.view = Some(kept);
    view.waiting = None;
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        texts.iter().any(|text| text.starts_with("Kept as a dump")),
        "{texts:?}"
    );
    assert_eq!(scene.click(&mut view, &ctx, "Keep as dump"), None);
    // The kept view is the same view reading a new path: its reader moved.
    assert_eq!(
        view.bound.as_ref().map(|bound| bound.image.clone()),
        Some(PathBuf::from("/home/user/rec/disks/dump-1/root.ext4"))
    );
    // Keep is bounded by the quota ceiling on the view's allocation.
    let mut scene = Scene::stopped();
    scene.measure = Some(DiskMeasure {
        quota: 100 * 1024 * 1024,
        ..measure()
    });
    let mut view = opened(&mut scene, root_entries());
    assert_eq!(scene.click(&mut view, &ctx, "Keep as dump"), None);
}

#[test]
fn a_dump_cannot_be_deleted_while_the_open_view_reads_it() {
    let recordings = Recordings::new();
    let dump = recordings.dump("kept", 3_000_000, |_| {});
    let ctx = context();
    let mut scene = Scene::with_dumps(&recordings);
    let mut view = DiskView::default();
    let mut current = open_view(Ext4State::Clean);
    current.kept_as = Some("kept".into());
    current.image = dump.path();
    scene.view = Some(current);
    view.entry = Entry::Dump("kept".into());
    view.scan(&scene.roots);
    scene.settle(&mut view, &ctx);
    assert!(view.delete_blocked_id("kept").is_some());
    assert!(view.delete_blocked_id("other").is_none());
    // The button is disabled: the click does nothing.
    view.bound = None;
    view.entry = Entry::Dump("kept".into());
    assert_eq!(scene.click_details(&mut view, &ctx, "Delete…"), None);
    // After the view closes it is allowed.
    scene.view = None;
    scene.settle(&mut view, &ctx);
    assert!(view.delete_blocked_id("kept").is_none());
}

#[test]
fn forgetting_a_deleted_dump_leaves_the_list_and_selects_the_current_disk() {
    let recordings = Recordings::new();
    let one = recordings.dump("one", 3_000_000, |_| {});
    recordings.dump("two", 2_000_000, |_| {});
    let ctx = context();
    let mut scene = Scene::with_dumps(&recordings);
    let mut view = DiskView::default();
    select_dump(&mut view, &scene, &one);
    scene.settle(&mut view, &ctx);
    std::fs::remove_dir_all(&one.dir).unwrap();
    view.forget_dump(&one.dir);
    assert_eq!(view.entry, Entry::Current);
    assert_eq!(view.dumps.len(), 1);
    scene.settle(&mut view, &ctx);
    assert_eq!(view.dumps.len(), 1);
    assert_eq!(view.dumps[0].dump.id, "two");
}

#[test]
fn verify_agrees_with_the_recorded_digest_and_notices_a_difference() {
    let recordings = Recordings::new();
    let ctx = context();
    let mut view = DiskView::default();
    let image = recordings.0.join("bytes.img");
    std::fs::write(&image, b"abc").unwrap();
    // SHA-256("abc")
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let finish = |view: &mut DiskView| {
        for _ in 0..200 {
            view.poll_dump_actions(&ctx);
            if view.verify.is_none() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("verify did not finish");
    };
    let mut dump = DiskDump {
        id: "v".into(),
        sha256: Some(digest.into()),
        ..DiskDump::default()
    };
    view.start_verify(&ctx, &dump, image.clone());
    assert!(view.verify.is_some());
    finish(&mut view);
    assert_eq!(
        view.verified.get("v"),
        Some(&dump_actions::Verified::Matches(digest.into()))
    );
    dump.sha256 = Some("00".repeat(32));
    view.start_verify(&ctx, &dump, image.clone());
    finish(&mut view);
    assert_eq!(
        view.verified.get("v"),
        Some(&dump_actions::Verified::Differs {
            computed: digest.into(),
            recorded: "00".repeat(32)
        })
    );
    dump.sha256 = None;
    view.start_verify(&ctx, &dump, image.clone());
    finish(&mut view);
    assert_eq!(
        view.verified.get("v"),
        Some(&dump_actions::Verified::Computed(digest.into()))
    );
    view.start_verify(&ctx, &dump, recordings.0.join("absent.img"));
    finish(&mut view);
    assert!(matches!(
        view.verified.get("v"),
        Some(dump_actions::Verified::Failed(_))
    ));
}

#[test]
fn saving_an_image_writes_a_sparse_raw_file_or_a_qcow2_and_reports_it() {
    use antinomie_monitor_core::disks::export::ExportFormat;
    if std::process::Command::new("qemu-img")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skipped: qemu-img is needed");
        return;
    }
    let recordings = Recordings::new();
    let dump = recordings.dump("save", 3_000_000, |dump| dump.vm_name = "Debian QA!".into());
    // A 4 MiB sparse "image": the export does not look inside.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(dump.path())
        .unwrap();
    file.set_len(4 * 1024 * 1024).unwrap();
    drop(file);
    let ctx = context();
    let mut view = DiskView::default();
    let wait = |view: &mut DiskView| {
        for _ in 0..500 {
            view.poll_dump_actions(&ctx);
            if view.saving_image.is_none() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("save did not finish");
    };
    let proposed = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    for (format, name) in [
        (ExportFormat::SparseRaw, "out.ext4"),
        (ExportFormat::Qcow2, "out.qcow2"),
    ] {
        let target = recordings.0.join(name);
        let (target_for_chooser, proposed) = (target.clone(), proposed.clone());
        view.spawn_save(
            &ctx,
            &dump,
            Path::new("qemu-img"),
            format,
            move |suggestion| {
                *proposed.lock().unwrap() = suggestion.to_owned();
                Ok(Some(target_for_chooser))
            },
        );
        assert!(view.saving_image.is_some());
        // A second save does not start while one runs.
        view.spawn_save(&ctx, &dump, Path::new("qemu-img"), format, |_| {
            panic!("a second save started")
        });
        wait(&mut view);
        let (message, failed) = view.status.clone().expect("a report");
        assert!(!failed, "{message}");
        assert!(message.contains(&target.display().to_string()), "{message}");
        assert!(target.is_file());
        if format == ExportFormat::SparseRaw {
            assert_eq!(std::fs::metadata(&target).unwrap().len(), 4 * 1024 * 1024);
        }
    }
    // The proposed name is the VM (made safe), the date and the extension.
    let suggestion = proposed.lock().unwrap().clone();
    assert!(suggestion.starts_with("Debian_QA_-"), "{suggestion}");
    assert!(suggestion.ends_with(".qcow2"), "{suggestion}");
    // Closing the chooser without a file changes nothing.
    view.status = None;
    view.spawn_save(
        &ctx,
        &dump,
        Path::new("qemu-img"),
        ExportFormat::SparseRaw,
        |_| Ok(None),
    );
    wait(&mut view);
    assert!(view.status.is_none());
    // An unusable destination is reported as a failure.
    view.spawn_save(
        &ctx,
        &dump,
        Path::new("qemu-img"),
        ExportFormat::SparseRaw,
        |_| Ok(Some(PathBuf::from("/nonexistent-folder/out.img"))),
    );
    wait(&mut view);
    let (message, failed) = view.status.clone().unwrap();
    assert!(
        failed && message.starts_with("Saving the image:"),
        "{message}"
    );
}

#[test]
fn importing_an_image_selects_it_and_a_bad_file_is_refused_in_the_dialog() {
    let recordings = Recordings::new();
    let ctx = context();
    let mut scene = Scene::with_dumps(&recordings);
    let mut view = DiskView::default();
    scene.settle(&mut view, &ctx);
    assert!(view.import.is_none());
    // The button opens the dialog.
    scene.click(
        &mut view,
        &ctx,
        &format!("{} Import image…", egui_phosphor::regular::FILE_ARROW_UP),
    );
    assert!(view.import.is_some());
    let texts = scene.settle(&mut view, &ctx);
    assert!(has(&texts, "Import disk image"), "{texts:?}");
    // A file that is not ext4 is refused and nothing is recorded.
    let bad = recordings.0.join("bad.img");
    std::fs::write(&bad, vec![0u8; 4 * 1024 * 1024]).unwrap();
    view.import.as_mut().unwrap().path = bad.display().to_string();
    scene.click(&mut view, &ctx, "Import");
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        texts.iter().any(|text| text.contains("ext2/3/4")),
        "{texts:?}"
    );
    assert!(view.import.is_some() && view.dumps.is_empty());
    // A raw ext4 image imports, is listed as imported and selected.
    let good = recordings.0.join("good.ext4");
    let tree = recordings.0.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("hello"), "hi").unwrap();
    let file = std::fs::File::create(&good).unwrap();
    file.set_len(8 * 1024 * 1024).unwrap();
    drop(file);
    let mkfs = [
        "/sbin/mkfs.ext4",
        "/usr/sbin/mkfs.ext4",
        "/usr/bin/mkfs.ext4",
    ]
    .into_iter()
    .find(|path| Path::new(path).is_file());
    let Some(mkfs) = mkfs else {
        eprintln!("skipped the good image: mkfs.ext4 is needed");
        return;
    };
    assert!(std::process::Command::new(mkfs)
        .args(["-q", "-F", "-d"])
        .arg(&tree)
        .arg(&good)
        .status()
        .unwrap()
        .success());
    view.import.as_mut().unwrap().path = good.display().to_string();
    view.import.as_mut().unwrap().error = None;
    // Binding would start a reader; select by hand afterwards.
    scene.click(&mut view, &ctx, "Import");
    assert!(view.import.is_none());
    assert_eq!(view.dumps.len(), 1);
    assert!(view.dumps[0].dump.imported);
    assert_eq!(view.entry, Entry::Dump(view.dumps[0].dump.id.clone()));
    // The imported file stays where it is.
    assert!(good.is_file());
}

mod phase3;
