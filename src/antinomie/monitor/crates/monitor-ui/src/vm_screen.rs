// SPDX-License-Identifier: GPL-3.0-only
//! The "VM screen" tab: the VM's display from QEMU's private VNC socket, drawn
//! from a texture that only changed rectangles update. A click on the screen
//! captures the keyboard for the guest (Ctrl+Alt gives it back); while it is
//! captured no app shortcut fires, the same rule as the terminal's.
mod keys;

use crate::{activity::Level, theme, toasts};
use antinomie_monitor_core::vnc::{PointerMode, ScreenClient, ScreenStatus};
use eframe::egui::{self, Color32, CursorIcon, Pos2, Rect, Sense, TextureOptions, Vec2};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

/// What the tab asks the app to do.
pub(crate) enum Request {
    /// Type the host clipboard into the VM (the existing QMP path).
    TypeClipboard,
}

#[derive(Default)]
pub(crate) struct VmScreenView {
    client: Option<(PathBuf, ScreenClient)>,
    texture: Option<egui::TextureHandle>,
    cursor: Option<(u64, egui::TextureHandle)>,
    actual_size: bool,
    grabbed: bool,
    /// Keys and modifiers sent as pressed, as (scancode, keysym).
    down: Vec<(u32, u32)>,
    buttons: u8,
    last_pointer: Option<(u8, u16, u16)>,
    /// The socket of the boot the app last saw, to tell a new boot.
    seen: Option<PathBuf>,
    /// Screenshots saved so far; the Screenshots page reads the folders again
    /// when it grows.
    saved: u64,
}

impl VmScreenView {
    /// Keep the connection in step with the VM: one client for the socket of
    /// the running boot while the tab is open, none otherwise.
    pub(crate) fn sync(&mut self, ctx: &egui::Context, socket: Option<&Path>, open: bool) {
        self.seen = socket.map(Path::to_path_buf);
        let wanted = socket.filter(|_| open);
        if self.client.as_ref().map(|(path, _)| path.as_path()) == wanted {
            return;
        }
        self.release_all();
        self.grabbed = false;
        self.texture = None;
        self.cursor = None;
        self.client = wanted.map(|path| {
            let ctx = ctx.clone();
            let wake: Arc<dyn Fn() + Send + Sync> = Arc::new(move || ctx.request_repaint());
            (
                path.to_path_buf(),
                ScreenClient::start(path.to_path_buf(), wake),
            )
        });
    }

    /// Whether `socket` is a boot this view has not seen yet.
    pub(crate) fn is_new_boot(&self, socket: Option<&Path>) -> bool {
        self.seen.as_deref() != socket
    }

    fn send_key(&mut self, down: bool, key: (u32, u32)) {
        let Some((_, client)) = &self.client else {
            return;
        };
        if down {
            client.key(true, key.1, key.0);
            if !self.down.contains(&key) {
                self.down.push(key);
            }
        } else if let Some(at) = self.down.iter().position(|held| *held == key) {
            self.down.remove(at);
            client.key(false, key.1, key.0);
        }
    }

    /// Let go of every key and button the guest believes is held.
    fn release_all(&mut self) {
        if let Some((_, client)) = &self.client {
            for (scancode, keysym) in self.down.drain(..).rev() {
                client.key(false, keysym, scancode);
            }
            if self.buttons != 0
                && let Some((_, x, y)) = self.last_pointer
            {
                client.pointer(0, x, y);
            }
        }
        self.down.clear();
        self.buttons = 0;
        self.last_pointer = None;
    }

    /// Make the guest's Shift, Ctrl and Alt match the host's.
    fn sync_modifiers(&mut self, modifiers: egui::Modifiers) {
        for (wanted, key) in [
            (modifiers.ctrl, keys::CTRL),
            (modifiers.shift, keys::SHIFT),
            (modifiers.alt, keys::ALT),
        ] {
            let held = self.down.contains(&key);
            if wanted != held {
                self.send_key(wanted, key);
            }
        }
    }

    fn ctrl_alt_del(&mut self) {
        for (down, key) in [
            (true, keys::CTRL),
            (true, keys::ALT),
            (true, (0xd3, 0xffff)),
            (false, (0xd3, 0xffff)),
            (false, keys::ALT),
            (false, keys::CTRL),
        ] {
            self.send_key(down, key);
        }
    }

    fn refresh_texture(&mut self, ctx: &egui::Context) {
        let Some((_, client)) = &self.client else {
            return;
        };
        let Some(update) = client.take_update() else {
            return;
        };
        let options = TextureOptions::LINEAR;
        let (w, h) = update.size;
        let current = self
            .texture
            .as_ref()
            .is_some_and(|texture| texture.size() == [w, h]);
        if update.resized || !current {
            let Some((w, h, rgba)) = client.frame() else {
                return;
            };
            let image = egui::ColorImage::from_rgba_unmultiplied([w, h], &rgba);
            self.texture = Some(ctx.load_texture("vm-screen", image, options));
        } else if let Some(texture) = &mut self.texture {
            for rect in update.rects {
                let image = egui::ColorImage::from_rgba_unmultiplied([rect.w, rect.h], &rect.rgba);
                texture.set_partial([rect.x, rect.y], image, options);
            }
        }
    }

    fn refresh_cursor(&mut self, ctx: &egui::Context) -> Option<(egui::TextureId, Vec2, Vec2)> {
        let (_, client) = self.client.as_ref()?;
        let (generation, shape) = client.cursor();
        let Some(shape) = shape else {
            self.cursor = None;
            return None;
        };
        if self
            .cursor
            .as_ref()
            .is_none_or(|(known, _)| *known != generation)
        {
            let image =
                egui::ColorImage::from_rgba_unmultiplied([shape.width, shape.height], &shape.rgba);
            let texture = ctx.load_texture("vm-screen-cursor", image, TextureOptions::NEAREST);
            self.cursor = Some((generation, texture));
        }
        let ppp = ctx.pixels_per_point();
        let (_, texture) = self.cursor.as_ref()?;
        Some((
            texture.id(),
            Vec2::new(shape.width as f32, shape.height as f32) / ppp,
            Vec2::new(shape.hotspot.0 as f32, shape.hotspot.1 as f32) / ppp,
        ))
    }

    /// The tab: its bar, then the screen.
    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        shots: Option<&Path>,
        can_type: bool,
    ) -> Option<Request> {
        let ctx = ui.ctx().clone();
        self.refresh_texture(&ctx);
        let mut request = None;
        let status = self.client.as_ref().map(|(_, client)| client.status());
        let size = self.client.as_ref().and_then(|(_, client)| client.size());
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.actual_size, false, "Fit");
            ui.selectable_value(&mut self.actual_size, true, "1:1");
            ui.separator();
            let live = status == Some(ScreenStatus::Connected);
            if ui
                .add_enabled(live, egui::Button::new("Ctrl+Alt+Del"))
                .on_hover_text("Send Ctrl+Alt+Delete to the guest")
                .clicked()
            {
                self.ctrl_alt_del();
            }
            if ui
                .add_enabled(live && shots.is_some(), egui::Button::new("Screenshot"))
                .on_hover_text("Save the screen as a PNG in the VM's recording folder")
                .clicked()
            {
                if let Some(dir) = shots {
                    self.screenshot(&ctx, dir);
                }
            }
            if ui
                .add_enabled(can_type, egui::Button::new("Type clipboard"))
                .on_hover_text("Type the host clipboard into the VM, as key presses")
                .clicked()
            {
                request = Some(Request::TypeClipboard);
            }
            ui.separator();
            let hint = if self.grabbed {
                "Keyboard captured. Ctrl+Alt gives it back."
            } else {
                "Click the screen to type into the VM."
            };
            ui.colored_label(theme::muted(), hint);
            if let Some((w, h)) = size {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.colored_label(theme::muted(), format!("{w} x {h}"));
                });
            }
        });
        ui.separator();
        match (&self.texture, &status) {
            (Some(_), Some(ScreenStatus::Connected)) => {}
            (_, status) => {
                let text = match status {
                    Some(ScreenStatus::Disconnected(why)) => format!("VM screen closed: {why}"),
                    _ => "Connecting to the VM screen...".into(),
                };
                ui.centered_and_justified(|ui| ui.colored_label(theme::muted(), text));
                self.release_all();
                self.grabbed = false;
                return request;
            }
        }
        self.screen(ui);
        request
    }

    pub(crate) fn screenshots_saved(&self) -> u64 {
        self.saved
    }

    fn screenshot(&mut self, ctx: &egui::Context, shots: &Path) {
        let Some((_, client)) = &self.client else {
            return;
        };
        let result = (|| {
            let (w, h, rgba) = client.frame().ok_or("the screen has no picture yet")?;
            let png = antinomie_monitor_core::vnc::encode_png(w, h, &rgba)?;
            let dir = shots.join("screenshots");
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let name = format!(
                "vm-screen-{}.png",
                chrono::Local::now().format("%Y%m%d-%H%M%S")
            );
            let path = dir.join(name);
            std::fs::write(&path, png).map_err(|e| e.to_string())?;
            Ok::<_, String>(path)
        })();
        match result {
            Ok(path) => {
                self.saved += 1;
                toasts::notify(
                    ctx,
                    Level::Info,
                    format!("Screenshot saved: {}", path.display()),
                );
            }
            Err(error) => toasts::notify(ctx, Level::Error, format!("Screenshot failed: {error}")),
        }
    }

    fn screen(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let Some(texture) = self.texture.clone() else {
            return;
        };
        let [fw, fh] = texture.size();
        let ppp = ctx.pixels_per_point();
        let native = Vec2::new(fw as f32, fh as f32) / ppp;
        let cursor = self.refresh_cursor(&ctx);
        let draw = |ui: &mut egui::Ui, this: &mut Self, area: Vec2, fit: bool| {
            let (outer, response) = ui.allocate_exact_size(area, Sense::click_and_drag());
            let image = if fit {
                let scale = (area.x / native.x).min(area.y / native.y).max(0.01);
                Rect::from_center_size(outer.center(), native * scale)
            } else {
                Rect::from_min_size(outer.min, native)
            };
            ui.painter().rect_filled(outer, 0.0, Color32::BLACK);
            ui.painter().image(
                texture.id(),
                image,
                Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)),
                Color32::WHITE,
            );
            this.input(ui, &response, image, (fw, fh));
            if let Some((id, size, hotspot)) = cursor
                && let Some(pos) = response.hover_pos()
            {
                ui.ctx().set_cursor_icon(CursorIcon::None);
                ui.painter().image(
                    id,
                    Rect::from_min_size(pos - hotspot, size),
                    Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)),
                    Color32::WHITE,
                );
            }
        };
        if self.actual_size {
            egui::ScrollArea::both()
                .auto_shrink(false)
                .scroll(!self.grabbed)
                .show(ui, |ui| {
                    draw(ui, self, native, false);
                });
        } else {
            let area = ui.available_size();
            draw(ui, self, area, true);
        }
    }

    /// Keyboard and pointer of the screen, for the guest.
    fn input(
        &mut self,
        ui: &mut egui::Ui,
        response: &egui::Response,
        image: Rect,
        fb: (usize, usize),
    ) {
        let ctx = ui.ctx().clone();
        if response.clicked() || response.drag_started() {
            response.request_focus();
            self.grabbed = true;
        }
        let focused = ui.memory(|memory| memory.has_focus(response.id));
        let window_focused = ctx.input(|input| input.focused);
        if self.grabbed && (!focused || !window_focused) {
            self.release_all();
            self.grabbed = false;
        }
        let modifiers = ctx.input(|input| input.modifiers);
        if self.grabbed && modifiers.ctrl && modifiers.alt {
            self.release_all();
            self.grabbed = false;
            ui.memory_mut(|memory| memory.surrender_focus(response.id));
            return;
        }
        if self.grabbed {
            crate::typing::mark_terminal(&ctx, response.id);
            ui.memory_mut(|memory| {
                memory.set_focus_lock_filter(
                    response.id,
                    egui::EventFilter {
                        tab: true,
                        horizontal_arrows: true,
                        vertical_arrows: true,
                        escape: true,
                    },
                );
            });
            self.keyboard(&ctx, modifiers);
        }
        self.pointer(&ctx, response, image, fb);
    }

    fn keyboard(&mut self, ctx: &egui::Context, now: egui::Modifiers) {
        let events = ctx.input(|input| input.events.clone());
        for event in events {
            match event {
                egui::Event::Key {
                    key,
                    physical_key,
                    pressed,
                    modifiers,
                    ..
                } => {
                    let Some(code) = physical_key.and_then(keys::of).or_else(|| keys::of(key))
                    else {
                        continue;
                    };
                    if pressed {
                        self.sync_modifiers(modifiers);
                    }
                    self.send_key(pressed, code);
                }
                // egui turns Ctrl+C, Ctrl+X and Ctrl+V into these instead of
                // key events; the guest gets the key.
                egui::Event::Copy | egui::Event::Cut | egui::Event::Paste(_) => {
                    let key = match event {
                        egui::Event::Copy => egui::Key::C,
                        egui::Event::Cut => egui::Key::X,
                        _ => egui::Key::V,
                    };
                    if let Some(code) = keys::of(key) {
                        self.sync_modifiers(now);
                        self.send_key(true, code);
                        self.send_key(false, code);
                    }
                }
                _ => {}
            }
        }
        self.sync_modifiers(now);
    }

    fn pointer(
        &mut self,
        ctx: &egui::Context,
        response: &egui::Response,
        image: Rect,
        fb: (usize, usize),
    ) {
        let Some((_, client)) = &self.client else {
            return;
        };
        let mut buttons = 0u8;
        // Asked of the response before `ctx.input` takes its lock: a response
        // reads the context itself, and nesting the two can deadlock.
        let active = response.hovered() || response.dragged();
        let hovered = response.hovered();
        let hover = response.interact_pointer_pos().or(response.hover_pos());
        let wheel = ctx.input(|input| {
            let mut wheel = 0i32;
            if hovered {
                for event in &input.events {
                    if let egui::Event::MouseWheel { unit, delta, .. } = event {
                        let notches = match unit {
                            egui::MouseWheelUnit::Line => delta.y.abs().round(),
                            _ => (delta.y.abs() / 40.0).round(),
                        };
                        wheel += (notches.clamp(0.0, 5.0) as i32).max(i32::from(delta.y != 0.0))
                            * delta.y.signum() as i32;
                    }
                }
            }
            for (button, bit) in [
                (egui::PointerButton::Primary, 1),
                (egui::PointerButton::Middle, 2),
                (egui::PointerButton::Secondary, 4),
            ] {
                if active && input.pointer.button_down(button) {
                    buttons |= bit;
                }
            }
            wheel
        });
        match client.pointer_mode() {
            PointerMode::Absolute => {
                let Some(pos) = hover else {
                    return;
                };
                let x = ((pos.x - image.min.x) / image.width() * fb.0 as f32)
                    .clamp(0.0, fb.0 as f32 - 1.0) as u16;
                let y = ((pos.y - image.min.y) / image.height() * fb.1 as f32)
                    .clamp(0.0, fb.1 as f32 - 1.0) as u16;
                if self.last_pointer != Some((buttons, x, y)) {
                    client.pointer(buttons, x, y);
                    self.last_pointer = Some((buttons, x, y));
                }
                self.buttons = buttons;
                scroll(client, wheel, buttons, x, y);
            }
            PointerMode::Relative => {
                // A PS/2 mouse takes movements, so only a captured screen moves
                // it: 0x7fff plus the movement, in guest pixels.
                if !self.grabbed {
                    return;
                }
                let delta = ctx.input(|input| input.pointer.delta());
                let scale = image.width() / fb.0 as f32;
                let step = |d: f32| (0x7fff as f32 + d / scale).round().clamp(1.0, 65534.0) as u16;
                if delta != Vec2::ZERO || self.last_pointer.map(|(b, ..)| b) != Some(buttons) {
                    client.pointer(buttons, step(delta.x), step(delta.y));
                    self.last_pointer = Some((buttons, 0, 0));
                }
                self.buttons = buttons;
                scroll(client, wheel, buttons, 0x7fff, 0x7fff);
            }
        }
    }
}

/// Wheel notches are presses of buttons 4 and 5 (bits 3 and 4).
fn scroll(client: &ScreenClient, wheel: i32, buttons: u8, x: u16, y: u16) {
    let bit = if wheel > 0 { 8 } else { 16 };
    for _ in 0..wheel.abs() {
        client.pointer(buttons | bit, x, y);
        client.pointer(buttons, x, y);
    }
}
