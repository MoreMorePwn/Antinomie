// SPDX-License-Identifier: GPL-3.0-only
//! A click in the VM screen captures the keyboard and says so; the capture
//! ends with the window's focus, a hidden tab or Ctrl+Alt. The screen is a
//! fake RFB server on a socket, so the real tab is drawn.
use super::*;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;

/// An RFB server that shows a 160x100 picture and then reads what it is sent.
pub(super) fn fake_screen(socket: &std::path::Path) {
    let listener = UnixListener::bind(socket).expect("fake screen socket");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            std::thread::spawn(move || {
                let (w, h) = (160u16, 100u16);
                let mut sink = [0u8; 4096];
                let mut hello = || -> std::io::Result<()> {
                    stream.write_all(b"RFB 003.008\n")?;
                    let mut buf = [0u8; 12];
                    stream.read_exact(&mut buf)?;
                    stream.write_all(&[1, 1])?;
                    stream.read_exact(&mut buf[..1])?;
                    stream.write_all(&0u32.to_be_bytes())?;
                    stream.read_exact(&mut buf[..1])?;
                    let mut init = Vec::new();
                    init.extend_from_slice(&w.to_be_bytes());
                    init.extend_from_slice(&h.to_be_bytes());
                    init.extend_from_slice(&[0; 16]);
                    let name = b"fake";
                    init.extend_from_slice(&(name.len() as u32).to_be_bytes());
                    init.extend_from_slice(name);
                    stream.write_all(&init)?;
                    // One raw rectangle of the whole picture: a login prompt's colours.
                    let mut update = vec![0, 0, 0, 1];
                    for value in [0u16, 0, w, h] {
                        update.extend_from_slice(&value.to_be_bytes());
                    }
                    update.extend_from_slice(&0i32.to_be_bytes());
                    for y in 0..h {
                        for x in 0..w {
                            let shade = (40 + y / 2) as u8;
                            update.extend_from_slice(&[shade, shade / 2 + (x % 8) as u8, 90, 0]);
                        }
                    }
                    stream.write_all(&update)?;
                    loop {
                        if stream.read(&mut sink)? == 0 {
                            return Ok(());
                        }
                    }
                };
                let _ = hello();
            });
        }
    });
}

fn captured_texts(output: &egui::FullOutput) -> usize {
    texts(output)
        .iter()
        .filter(|(text, _)| text == crate::vm_screen::CAPTURED)
        .count()
}

/// An app showing a connected fake VM screen; returns it with its egui context.
pub(super) fn app_with_screen(name: &str) -> (MonitorApp, egui::Context, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("ant-vmscreen-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("vnc.sock");
    fake_screen(&socket);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    app.snapshot.active_vm = Some("vm".into());
    app.snapshot.state = VmState::Running;
    app.snapshot.vm_screen = Some(socket);
    let size = egui::vec2(1280.0, 900.0);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let output = render(&mut app, &ctx, size);
        if texts(&output).iter().any(|(text, _)| text == "160 x 100") {
            break;
        }
        assert!(Instant::now() < deadline, "the fake screen never connected");
        std::thread::sleep(Duration::from_millis(50));
    }
    (app, ctx, dir)
}

fn click(app: &mut MonitorApp, ctx: &egui::Context, at: egui::Pos2) -> egui::FullOutput {
    let mut last = None;
    for pressed in [None, Some(true), Some(false)] {
        let mut input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1280.0, 900.0),
            )),
            ..Default::default()
        };
        input.events.push(match pressed {
            None => egui::Event::PointerMoved(at),
            Some(pressed) => egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: Default::default(),
            },
        });
        last = Some(draw_input(app, ctx, input));
    }
    last.unwrap()
}

fn idle(app: &mut MonitorApp, ctx: &egui::Context, frames: usize) -> egui::FullOutput {
    let mut last = None;
    for _ in 0..frames {
        last = Some(render(app, ctx, egui::vec2(1280.0, 900.0)));
    }
    last.unwrap()
}

#[test]
fn a_click_in_the_vm_screen_captures_the_keyboard_and_a_banner_says_so() {
    let (mut app, ctx, dir) = app_with_screen("banner");
    let before = idle(&mut app, &ctx, 2);
    assert!(!app.vm_screen.is_captured());
    assert_eq!(captured_texts(&before), 0);
    assert!(!texts(&before).iter().any(|(t, _)| t == "Keyboard captured"));
    // The hint invites the click.
    assert!(texts(&before)
        .iter()
        .any(|(t, _)| t.starts_with("Click the screen")));
    click(&mut app, &ctx, egui::pos2(640.0, 400.0));
    let after = idle(&mut app, &ctx, 2);
    assert!(app.vm_screen.is_captured(), "the click captures");
    // The toolbar says so, and the banner over the picture says how to release.
    assert!(captured_texts(&after) >= 1, "{:?}", texts(&after));
    assert!(texts(&after).iter().any(|(t, _)| t == "Keyboard captured"));
    let banner = texts(&after)
        .into_iter()
        .find(|(text, _)| text == crate::vm_screen::CAPTURED)
        .unwrap()
        .1;
    // The banner sits on the screen, below the toolbar.
    let toolbar = texts(&after)
        .into_iter()
        .find(|(text, _)| text == "Ctrl+Alt+Del")
        .unwrap()
        .1;
    assert!(banner.top() > toolbar.bottom(), "{banner:?} {toolbar:?}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_capture_ends_when_the_window_loses_focus() {
    let (mut app, ctx, dir) = app_with_screen("window");
    click(&mut app, &ctx, egui::pos2(640.0, 400.0));
    idle(&mut app, &ctx, 2);
    assert!(app.vm_screen.is_captured());
    let input = egui::RawInput {
        screen_rect: Some(egui::Rect::from_min_size(
            egui::Pos2::ZERO,
            egui::vec2(1280.0, 900.0),
        )),
        focused: false,
        events: vec![egui::Event::WindowFocused(false)],
        ..Default::default()
    };
    let output = draw_input(&mut app, &ctx, input);
    let output = if app.vm_screen.is_captured() {
        idle(&mut app, &ctx, 1)
    } else {
        output
    };
    assert!(!app.vm_screen.is_captured());
    assert_eq!(captured_texts(&output), 0);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_capture_ends_when_another_tab_is_shown() {
    let (mut app, ctx, dir) = app_with_screen("tab");
    click(&mut app, &ctx, egui::pos2(640.0, 400.0));
    idle(&mut app, &ctx, 2);
    assert!(app.vm_screen.is_captured());
    // Another tab of the same pane comes to the front.
    let other = app
        .layout
        .tabs_beside(&Panel::VmScreen)
        .into_iter()
        .next()
        .expect("a tab beside the VM screen");
    app.layout.focus(other);
    let output = idle(&mut app, &ctx, 3);
    assert!(
        !app.vm_screen.is_captured(),
        "a hidden tab keeps no capture"
    );
    assert_eq!(captured_texts(&output), 0);
    // Back on the tab, the keyboard is not captured until clicked again.
    app.layout.focus(Panel::VmScreen);
    let output = idle(&mut app, &ctx, 3);
    assert!(!app.vm_screen.is_captured());
    assert_eq!(captured_texts(&output), 0);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn ctrl_alt_gives_the_keyboard_back() {
    let (mut app, ctx, dir) = app_with_screen("ctrlalt");
    click(&mut app, &ctx, egui::pos2(640.0, 400.0));
    idle(&mut app, &ctx, 2);
    assert!(app.vm_screen.is_captured());
    let input = egui::RawInput {
        screen_rect: Some(egui::Rect::from_min_size(
            egui::Pos2::ZERO,
            egui::vec2(1280.0, 900.0),
        )),
        events: vec![egui::Event::ModifiersChanged(egui::Modifiers {
            ctrl: true,
            alt: true,
            ..Default::default()
        })],
        ..Default::default()
    };
    draw_input(&mut app, &ctx, input);
    let held = ctx.input(|input| input.modifiers);
    let during = app.vm_screen.is_captured();
    let output = idle(&mut app, &ctx, 2);
    assert!(
        !app.vm_screen.is_captured(),
        "modifiers {held:?}, captured right after the frame: {during}"
    );
    assert_eq!(captured_texts(&output), 0);
    let _ = std::fs::remove_dir_all(dir);
}

/// The VM screen tab on a fake screen, for the capture banner's screenshots.
/// Click the picture to capture the keyboard. Needs an X11 display.
/// ANTINOMIE_QA_THEME = dark | light | blue, ANTINOMIE_QA_SIZE = 1280x820,
/// ANTINOMIE_QA_SECONDS = 25.
#[test]
#[ignore = "requires X11 native rendering; exits after the given seconds"]
fn native_vm_screen_capture_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct QaApp {
        app: MonitorApp,
        deadline: Instant,
        seeded: bool,
    }
    impl eframe::App for QaApp {
        fn ui(&mut self, root: &mut egui::Ui, frame: &mut eframe::Frame) {
            let ctx = &root.ctx().clone();
            if Instant::now() >= self.deadline {
                self.app.snapshot.active_vm = None;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            if !self.seeded {
                self.seeded = true;
                self.app.focus_panel = Some(Panel::VmScreen);
            }
            eframe::App::ui(&mut self.app, root, frame);
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    let theme_choice = match var("ANTINOMIE_QA_THEME").as_str() {
        "light" => theme::Theme::Light,
        "blue" => theme::Theme::Blue,
        _ => theme::Theme::Dark,
    };
    let (width, height) = var("ANTINOMIE_QA_SIZE")
        .split_once('x')
        .and_then(|(w, h)| Some((w.parse::<f32>().ok()?, h.parse::<f32>().ok()?)))
        .unwrap_or((1280.0, 820.0));
    let seconds = var("ANTINOMIE_QA_SECONDS").parse::<u64>().unwrap_or(25);
    eframe::run_native(
        "Antinomie VM screen QA",
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
            theme::apply_theme(&cc.egui_ctx, theme_choice);
            let dir = std::env::temp_dir().join(format!("ant-vmscreen-qa-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let socket = dir.join("vnc.sock");
            fake_screen(&socket);
            let mut app = app();
            app.settings.set_theme(theme_choice);
            app.snapshot.active_vm = Some("vm".into());
            app.snapshot.state = VmState::Running;
            app.snapshot.vm_screen = Some(socket);
            Ok(Box::new(QaApp {
                app,
                deadline: Instant::now() + Duration::from_secs(seconds),
                seeded: false,
            }))
        }),
    )
    .expect("native vm screen fixture");
}
