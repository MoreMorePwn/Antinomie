// SPDX-License-Identifier: GPL-3.0-only
//! Native fixture for the Run line of Core dumps and Memory. Needs an X11
//! display; exits by itself. The recordings live in ANTINOMIE_QA_DATA (a
//! throwaway folder).
//!
//! ANTINOMIE_QA_SCENE = cores | memory, ANTINOMIE_QA_THIS_RUN = 1 (This run
//! only on), ANTINOMIE_QA_THEME = dark | light | blue,
//! ANTINOMIE_QA_SIZE = 1280x820, ANTINOMIE_QA_SECONDS = 25.
use super::*;
use crate::theme::Theme;
use antinomie_monitor_core::{memory::PluginRun, provenance::Provenance, RunState, VmLocations};

const BPFDOOR: &str = "f9c3d854547992ccfc7f6670b3cc7866";
const REKOOBE: &str = "469c1c9b34fe60cabbaed8d668019d61";
const LADVIX: &str = "6815842f2b0a4c5e8d1f3a7b9c0e2d46";

/// A VM with three finished runs and the evidence they left, in `root`:
/// BPFDoor's trigger core (Core dump on exit off), Ladvix's exit core, a core
/// taken by hand and one imported; a trigger memory dump, a by-hand dump taken
/// while two runs were live, one while none was, and one from before the field.
fn seed(app: &mut MonitorApp, root: &std::path::Path) {
    for (id, path, started) in [
        (BPFDOOR, "/tmp/bpfdoor.elf", 1_794_047_000_000u64),
        (REKOOBE, "/tmp/rekoobe.elf", 1_794_046_000_000),
        (LADVIX, "/tmp/ladvix.elf", 1_794_045_000_000),
    ] {
        let mut run = run(id);
        run.state = RunState::Finished;
        run.request.path = path.into();
        run.started_ms = Some(started);
        run.vm_id = "vm".into();
        app.history.push(run);
    }
    app.selected = Some("vm".into());
    app.selected_run = Some(BPFDOOR.into());
    app.snapshot.vm_locations = vec![VmLocations {
        vm_id: "vm".into(),
        disk_directory: root.join("disk"),
        recording_directory: root.to_owned(),
        recording_directories: vec![root.to_owned()],
    }];
    let write = |path: std::path::PathBuf, bytes: Vec<u8>| {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    };
    // BPFDoor: exit core off, one trigger core.
    let capture = root.join("core-captures/01794047896049-7e9a");
    write(capture.join("process.elf"), b"\x7fELF partial".to_vec());
    let artifacts = serde_json::json!({
        "run_id": BPFDOOR, "vm_id": "vm", "boot_id": "boot", "core_state": "disabled",
        "trigger_dumps": [
            {"at_ms": 1, "finding": {"rule": "c2.bpf_backdoor", "summary": "", "tier": "high",
                "pid": 1352, "tid": 1352, "task_cookie": 2, "stream_id": 1, "call_id": 19,
                "guest_ns": 1, "syscall": "setsockopt"},
             "core": {"state": "partial", "path": capture.join("process.elf"),
                "capture_id": "7e9a", "size": 115_608}},
            {"at_ms": 2, "finding": {"rule": "evasion.process_rename", "summary": "", "tier": "medium",
                "pid": 1360, "tid": 1360, "task_cookie": 3, "stream_id": 1, "call_id": 30,
                "guest_ns": 2, "syscall": "prctl"},
             "memory": {"state": "complete", "path": root.join("memory/trig"), "size": 1_073_741_824}}
        ]
    });
    write(
        root.join("runs").join(BPFDOOR).join("artifacts.json"),
        serde_json::to_vec(&artifacts).unwrap(),
    );
    // Ladvix: Core dump on exit, partial.
    let exit_core = root.join("runs").join(LADVIX).join("core/process.elf");
    write(exit_core.clone(), b"\x7fELF exit".to_vec());
    let ladvix = serde_json::json!({
        "run_id": LADVIX, "vm_id": "vm", "boot_id": "boot", "core_state": "partial",
        "core_dump": exit_core, "core_saved_size": 173_000, "core_logical_size": 173_000
    });
    write(
        root.join("runs").join(LADVIX).join("artifacts.json"),
        serde_json::to_vec(&ladvix).unwrap(),
    );
    // Memory dumps.
    let dump = |id: &str, started: u64, provenance: Option<Provenance>| {
        let mut dump = antinomie_monitor_core::memory::MemoryDump {
            id: id.into(),
            vm_id: "vm".into(),
            vm_name: "Debian".into(),
            boot_id: Some("boot".into()),
            file: "memory.elf".into(),
            started_ms: started,
            finished_ms: Some(started + 9_000),
            bytes: Some(1_073_741_824),
            ram_mib: 1024,
            system: "Linux 6.12.94".into(),
            provenance,
            ..Default::default()
        };
        dump.dir = root.join("memory").join(id);
        std::fs::create_dir_all(&dump.dir).unwrap();
        std::fs::write(dump.dir.join("memory.elf"), b"ELF").unwrap();
        dump.save().unwrap();
    };
    let finding = serde_json::from_value(serde_json::json!({
        "rule": "evasion.process_rename", "summary": "", "tier": "medium", "pid": 1360, "tid": 1360,
        "task_cookie": 3, "stream_id": 1, "call_id": 30, "guest_ns": 2, "syscall": "prctl"
    }))
    .unwrap();
    dump(
        "trig",
        1_794_047_100_000,
        Some(Provenance::trigger(
            "vm",
            "boot",
            BPFDOOR,
            &finding,
            1_794_047_100_000,
        )),
    );
    dump(
        "by-hand-live",
        1_794_047_200_000,
        Some(Provenance::by_hand(
            "vm",
            "boot",
            None,
            vec![BPFDOOR.into(), REKOOBE.into()],
            1_794_047_200_000,
        )),
    );
    dump(
        "by-hand-idle",
        1_794_044_000_000,
        Some(Provenance::by_hand(
            "vm",
            "boot",
            None,
            Vec::new(),
            1_794_044_000_000,
        )),
    );
    dump("before-the-field", 1_794_043_000_000, None);
}

#[test]
#[ignore = "requires X11 native rendering; exits after the given seconds"]
fn native_run_link_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct QaApp {
        app: MonitorApp,
        deadline: Instant,
        frames: u32,
        shot: String,
    }
    impl eframe::App for QaApp {
        fn ui(&mut self, root: &mut egui::Ui, frame: &mut eframe::Frame) {
            let ctx = &root.ctx().clone();
            if Instant::now() >= self.deadline {
                self.app.snapshot.active_vm = None;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            eframe::App::ui(&mut self.app, root, frame);
            // ANTINOMIE_QA_SHOT = <file.ppm>: save one frame after 4 s.
            self.frames += 1;
            if self.frames == 20 && !self.shot.is_empty() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(Default::default()));
            }
            let image = ctx.input(|input| {
                input.events.iter().find_map(|event| match event {
                    egui::Event::Screenshot { image, .. } => Some(image.clone()),
                    _ => None,
                })
            });
            if let Some(image) = image {
                let mut out =
                    format!("P6\n{} {}\n255\n", image.size[0], image.size[1]).into_bytes();
                for pixel in &image.pixels {
                    out.extend_from_slice(&[pixel.r(), pixel.g(), pixel.b()]);
                }
                let _ = std::fs::write(&self.shot, out);
            }
            ctx.request_repaint_after(Duration::from_millis(200));
        }
    }
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    let scene = var("ANTINOMIE_QA_SCENE");
    let theme_choice = match var("ANTINOMIE_QA_THEME").as_str() {
        "light" => Theme::Light,
        "blue" => Theme::Blue,
        _ => Theme::Dark,
    };
    let (width, height) = var("ANTINOMIE_QA_SIZE")
        .split_once('x')
        .and_then(|(w, h)| Some((w.parse::<f32>().ok()?, h.parse::<f32>().ok()?)))
        .unwrap_or((1280.0, 820.0));
    let seconds = var("ANTINOMIE_QA_SECONDS").parse::<u64>().unwrap_or(25);
    let data = PathBuf::from(var("ANTINOMIE_QA_DATA"));
    assert!(
        !data.as_os_str().is_empty(),
        "set ANTINOMIE_QA_DATA to a throwaway folder"
    );
    std::fs::create_dir_all(&data).unwrap();
    eframe::run_native(
        "Antinomie run link QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([width, height]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11();
                builder.with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            let mut app = analysis_setup_fixture();
            app.launch_open = false;
            app.settings.set_theme(theme_choice);
            theme::apply_theme(&cc.egui_ctx, theme_choice);
            seed(&mut app, &data);
            app.focus_panel = Some(match scene.as_str() {
                "memory" => crate::workspace::Panel::Memory,
                // A plugin run that has ended, with the Memory tab never drawn.
                "bgjob" => crate::workspace::Panel::Jobs,
                _ => crate::workspace::Panel::CoreDump,
            });
            if scene == "bgjob" {
                app.memory_view.push_ended_run_for_qa(PluginRun {
                    id: "r1".into(),
                    plugin: "linux.pslist.PsList".into(),
                    dump_id: "by-hand-live".into(),
                    state: antinomie_monitor_core::memory::RunState::Finished,
                    rows: 3,
                    ..PluginRun::default()
                });
            }
            if var("ANTINOMIE_QA_THIS_RUN") == "1" {
                app.core_view.set_this_run_only(true);
                app.memory_view.set_this_run_only(true);
            }
            Ok(Box::new(QaApp {
                app,
                deadline: Instant::now() + Duration::from_secs(seconds),
                frames: 0,
                shot: var("ANTINOMIE_QA_SHOT"),
            }))
        }),
    )
    .expect("native run link fixture");
}
