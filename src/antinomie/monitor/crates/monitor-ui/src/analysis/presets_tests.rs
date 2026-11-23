// SPDX-License-Identifier: GPL-3.0-only
//! The Preset dropdown of the Run program form (ANT-T0605): each built-in
//! preset fills the form as the service would run it, a user file is listed,
//! a broken one is listed disabled with its error, a changed field reads
//! Custom, and the program is kept.
use super::presets::*;
use super::*;
use antinomie_monitor_core::{route::RouteKind, VmNetwork};
use antinomie_service::{
    config::{form, preset::LoadedPreset, PresetLookup, PresetSet},
    stages::plan,
};
use std::{path::PathBuf, time::Duration};

fn capabilities(core: bool, screen: bool, network: VmNetwork) -> LaunchCapabilities {
    LaunchCapabilities {
        graphical: false,
        core_on_exit: core,
        debug_on_start: false,
        core_limits: None,
        core_default_mib: 256,
        route: crate::route_ui::RouteChoice::fixed(network),
        guest_arch: Default::default(),
        screen,
    }
}

fn full() -> LaunchCapabilities {
    capabilities(true, true, VmNetwork::Routed)
}

fn scratch(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "ant-ui-presets-{name}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(root.join("presets")).unwrap();
    root
}

fn frame(
    ctx: &egui::Context,
    state: &mut PresetForm,
    request: &mut ExecRequest,
    args: &mut String,
    env: &mut String,
    capabilities: LaunchCapabilities,
) {
    let _ = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(900.0, 700.0),
            )),
            ..Default::default()
        },
        |root| {
            egui::CentralPanel::default().show(root, |ui| {
                dropdown(ui, state, request, args, env, capabilities);
                // What the form's sections enforce on the request.
                super::run_options::settle_capture(request, capabilities);
                settled(ui, state, request, args, env);
            });
        },
    );
}

fn options(name: &str) -> form::FormOptions {
    form::built_in()
        .into_iter()
        .find(|entry| entry.name == name)
        .and_then(|entry| entry.options.ok())
        .unwrap()
}

#[test]
fn the_six_built_in_presets_are_the_services_own() {
    let set = PresetSet::built_in();
    let listed = form::built_in();
    let names: Vec<_> = listed.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "standard",
            "simulated-network",
            "quick-look",
            "deep",
            "interactive",
            "live-network"
        ]
    );
    for entry in &listed {
        let service: std::sync::Arc<LoadedPreset> = set.get(&entry.name).unwrap();
        assert_eq!(
            entry.options.as_ref().unwrap().loaded,
            service,
            "{}",
            entry.name
        );
    }
}

#[test]
fn each_built_in_fills_the_form_as_the_service_would_run_it() {
    // (name, run time in seconds, route, deep checks)
    let expected = [
        ("standard", 300, RouteKind::Drop),
        ("simulated-network", 300, RouteKind::InetSim),
        ("quick-look", 120, RouteKind::Drop),
        ("deep", 900, RouteKind::InetSim),
        ("interactive", 600, RouteKind::Drop),
        ("live-network", 600, RouteKind::Tor),
    ];
    for (name, seconds, route) in expected {
        let options = options(name);
        let mut request = ExecRequest::default();
        let (mut args, mut env) = (String::new(), String::new());
        fill(&options, &mut request, &mut args, &mut env, true);
        let run = plan::effective(options.preset(), Default::default());
        assert_eq!(run.run_limit, Duration::from_secs(seconds), "{name}");
        assert_eq!(request.route, Some(route), "{name}");
        assert_eq!(request.route, run.request.route, "{name}");
        assert_eq!(
            request.capture_network, run.request.capture_network,
            "{name}"
        );
        assert_eq!(
            request.memory_dump_on_exit, run.request.memory_dump_on_exit,
            "{name}"
        );
        assert_eq!(
            request.core_dump_on_exit, run.request.core_dump_on_exit,
            "{name}"
        );
        assert_eq!(request.core_max_size, run.request.core_max_size, "{name}");
        assert_eq!(request.dump_trigger, run.request.dump_trigger, "{name}");
        assert_eq!(
            request.screenshot_every_s, run.request.screenshot_every_s,
            "{name}"
        );
        assert_eq!(
            request.analysis.enabled,
            options.preset().static_analysis.enabled
        );
        assert_eq!(
            request.analysis.checks,
            plan::hosted(options.preset()).static_checks
        );
        assert_eq!(
            (request.uid, request.gid),
            (run.request.uid, run.request.gid)
        );
        assert_eq!(request.cwd, run.request.cwd, "{name}");
    }
    // What the three that differ from Standard fill, in the words of the form.
    let mut request = ExecRequest::default();
    let (mut args, mut env) = (String::new(), String::new());
    fill(&options("deep"), &mut request, &mut args, &mut env, true);
    assert!(request.core_dump_on_exit && !request.memory_dump_on_exit);
    let trigger = request.dump_trigger.as_ref().unwrap();
    assert!(trigger.core && trigger.memory);
    assert_eq!(trigger.min_tier.label(), "Medium");
    assert!(request.analysis.checks.contains(&AnalysisKind::Floss));
    assert!(request.analysis.checks.contains(&AnalysisKind::Disassembly));
    fill(
        &options("quick-look"),
        &mut request,
        &mut args,
        &mut env,
        true,
    );
    assert!(!request.core_dump_on_exit && request.dump_trigger.is_none());
    assert_eq!(request.analysis.checks.len(), 5);
    assert_eq!(env, "");
    fill(
        &options("standard"),
        &mut request,
        &mut args,
        &mut env,
        true,
    );
    assert_eq!(env, "PATH=/bin:/sbin:/usr/bin:/usr/sbin\nTERM=xterm");
}

#[test]
fn a_user_file_is_listed_and_fills_the_form() {
    let data = scratch("user");
    std::fs::write(
        data.join("presets/mine.toml"),
        "title = \"My lab\"\n[program]\narguments = [\"-v\", \"--fast\"]\n[dumps]\nmemory_dump_on_exit = true\n[record]\nscreenshot_every_s = 15\n",
    )
    .unwrap();
    let list = form::list(&data);
    assert_eq!(list.len(), 7);
    let mine = list.iter().find(|entry| entry.name == "mine").unwrap();
    assert_eq!(mine.title, "My lab");
    assert!(!mine.built_in);
    let options = mine.options.as_ref().unwrap();
    let mut request = ExecRequest::default();
    let (mut args, mut env) = (String::new(), "KEEP=1".to_owned());
    fill(options, &mut request, &mut args, &mut env, true);
    assert!(request.memory_dump_on_exit);
    assert_eq!(request.screenshot_every_s, Some(15));
    assert_eq!(args, "-v\n--fast");
    // The file does not write the environment: the user's stays.
    assert_eq!(env, "KEEP=1");
    let _ = std::fs::remove_dir_all(&data);
}

#[test]
fn a_broken_file_is_listed_disabled_with_its_error_and_nothing_crashes() {
    let data = scratch("broken");
    std::fs::write(
        data.join("presets/typo.toml"),
        "[program]\nrun_time_s = \"long\"\n",
    )
    .unwrap();
    std::fs::write(
        data.join("presets/tor.toml"),
        "[network]\nroute = \"tor\"\n",
    )
    .unwrap();
    std::fs::write(data.join("presets/standard.toml"), "title = \"x\"\n").unwrap();
    std::fs::write(data.join("presets/binary.toml"), [0xff, 0xfe, 0x00]).unwrap();
    let list = form::list(&data);
    for name in ["typo", "tor", "standard", "binary"] {
        let entries: Vec<_> = list.iter().filter(|entry| entry.name == name).collect();
        let entry = entries.last().unwrap();
        if name == "standard" {
            // The file named like a built-in preset is the file's error; the
            // built-in one stays.
            assert!(list.iter().any(|e| e.name == name && e.built_in));
        }
        let error = entry
            .options
            .as_ref()
            .err()
            .unwrap_or_else(|| panic!("{name} usable"));
        assert!(error.contains(&format!("{name}.toml")), "{error}");
    }
    let typo = list.iter().find(|e| e.name == "typo").unwrap();
    assert!(
        typo.options.as_ref().unwrap_err().contains(":2"),
        "{:?}",
        typo.options
    );
    let mut state = PresetForm::new(data.clone());
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut request = ExecRequest::default();
    let (mut args, mut env) = (String::new(), String::new());
    for _ in 0..3 {
        frame(&ctx, &mut state, &mut request, &mut args, &mut env, full());
    }
    assert_eq!(state.base(), Some("standard"));
    // A broken file cannot be chosen.
    assert!(!state.choose(&ctx, "typo", &mut request, &mut args, &mut env));
    assert_eq!(state.base(), Some("standard"));
    let _ = std::fs::remove_dir_all(&data);
}

#[test]
fn what_this_vm_cannot_honour_is_disabled_with_the_reason() {
    let live = unavailable(&options("live-network"), &full(), &ExecRequest::default()).unwrap();
    assert!(live.contains("route.tor"), "{live}");
    let deep = options("deep");
    let request = ExecRequest::default();
    let no_core = capabilities(false, true, VmNetwork::Routed);
    assert!(unavailable(&deep, &no_core, &request)
        .unwrap()
        .contains("newer guest base"));
    assert_eq!(unavailable(&deep, &full(), &request), None);
    let simulated = options("simulated-network");
    assert!(unavailable(&simulated, &no_core, &request)
        .unwrap()
        .contains("newer guest base"));
    assert_eq!(unavailable(&simulated, &full(), &request), None);
    let isolated = capabilities(true, true, VmNetwork::Isolated);
    assert!(unavailable(&deep, &isolated, &request)
        .unwrap()
        .contains("Routed"));
    for name in ["standard", "quick-look", "interactive"] {
        assert_eq!(
            unavailable(&options(name), &no_core, &request),
            None,
            "{name}"
        );
    }
    let mut shots = options("standard");
    let mut preset = shots.loaded.as_ref().clone();
    preset.preset.record.screenshot_every_s = 10;
    shots.loaded = std::sync::Arc::new(preset);
    let blind = capabilities(true, false, VmNetwork::Routed);
    assert!(unavailable(&shots, &blind, &request)
        .unwrap()
        .contains("VM screen"));
}

#[test]
fn the_first_open_is_standard_and_editing_a_field_reads_custom() {
    let data = scratch("custom");
    let mut state = PresetForm::new(data.clone());
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut request = ExecRequest::default();
    let (mut args, mut env) = (String::new(), String::new());
    for _ in 0..4 {
        frame(&ctx, &mut state, &mut request, &mut args, &mut env, full());
    }
    assert_eq!(state.base(), Some("standard"));
    assert!(request.analysis.enabled && request.capture_network);
    let now = || Covered::of(&request, &args, &env);
    assert!(!state.is_custom(&now()));
    // A box of the options.
    request.memory_dump_on_exit = true;
    frame(&ctx, &mut state, &mut request, &mut args, &mut env, full());
    assert!(state.is_custom(&Covered::of(&request, &args, &env)));
    // Back to what the preset says: it is the preset again.
    request.memory_dump_on_exit = false;
    frame(&ctx, &mut state, &mut request, &mut args, &mut env, full());
    assert!(!state.is_custom(&Covered::of(&request, &args, &env)));
    // A check, an argument.
    request.analysis.checks.pop();
    assert!(state.is_custom(&Covered::of(&request, &args, &env)));
    request.analysis.checks = plan::hosted(options("standard").preset()).static_checks;
    args.push('x');
    assert!(state.is_custom(&Covered::of(&request, &args, &env)));
    // Choosing a preset makes the form that preset's.
    assert!(state.choose(&ctx, "quick-look", &mut request, &mut args, &mut env));
    frame(&ctx, &mut state, &mut request, &mut args, &mut env, full());
    assert_eq!(state.base(), Some("quick-look"));
    assert!(!state.is_custom(&Covered::of(&request, &args, &env)));
    assert_eq!(request.analysis.checks.len(), 5);
    let _ = std::fs::remove_dir_all(&data);
}

#[test]
fn a_preset_that_a_vm_cannot_fully_run_does_not_start_as_custom() {
    // Standard captures the network; a VM with no card clears that. The form
    // is still Standard, not Custom.
    let data = scratch("settled");
    let mut state = PresetForm::new(data.clone());
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut request = ExecRequest::default();
    let (mut args, mut env) = (String::new(), String::new());
    let caps = capabilities(false, false, VmNetwork::Disconnected);
    for _ in 0..3 {
        frame(&ctx, &mut state, &mut request, &mut args, &mut env, caps);
    }
    assert!(!request.capture_network);
    assert!(!state.is_custom(&Covered::of(&request, &args, &env)));
    let _ = std::fs::remove_dir_all(&data);
}

#[test]
fn a_preset_never_clears_the_program() {
    let data = scratch("program");
    let mut state = PresetForm::new(data.clone());
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut request = ExecRequest {
        path: "/tmp/df11f34c-sample".into(),
        host_copy: Some("/home/me/sample".into()),
        sample: Some(antinomie_monitor_core::samples::SampleRef {
            sha256: "ab".repeat(32),
            name: "sample".into(),
        }),
        ..ExecRequest::default()
    };
    let kept = (
        request.path.clone(),
        request.host_copy.clone(),
        request.sample.clone(),
    );
    let (mut args, mut env) = ("-v".to_owned(), String::new());
    for _ in 0..3 {
        frame(&ctx, &mut state, &mut request, &mut args, &mut env, full());
    }
    // The first open fills the options only: the arguments stay too.
    assert_eq!(args, "-v");
    for name in [
        "standard",
        "quick-look",
        "deep",
        "interactive",
        "live-network",
    ] {
        assert!(state.choose(&ctx, name, &mut request, &mut args, &mut env));
        assert_eq!(
            (
                request.path.clone(),
                request.host_copy.clone(),
                request.sample.clone()
            ),
            kept,
            "{name}"
        );
    }
    // Quick look does not write the arguments, Standard writes none.
    args = "-v".into();
    assert!(state.choose(&ctx, "quick-look", &mut request, &mut args, &mut env));
    assert_eq!(args, "-v");
    assert!(state.choose(&ctx, "standard", &mut request, &mut args, &mut env));
    assert_eq!(args, "");
    let _ = std::fs::remove_dir_all(&data);
}
