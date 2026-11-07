// SPDX-License-Identifier: GPL-3.0-only
//! The Summary's thumbnail of the run's last screenshot: decoded on a thread,
//! drawn small, a click opens it in the Screenshots page.
use eframe::egui;
use std::{
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver},
};

/// The longest side the thumbnail is decoded to.
const SIDE: usize = 480;
/// How wide it is drawn.
pub(super) const WIDTH: f32 = 168.0;

#[derive(Default)]
pub(in crate::triage) struct Thumb {
    path: Option<PathBuf>,
    texture: Option<egui::TextureHandle>,
    rx: Option<Receiver<Result<egui::ColorImage, String>>>,
    failed: bool,
}

impl Thumb {
    /// Draw the picture at `path`; true when it was clicked.
    pub(super) fn show(&mut self, ui: &mut egui::Ui, path: &Path) -> bool {
        if self.path.as_deref() != Some(path) {
            *self = Self::default();
            self.path = Some(path.to_owned());
            let (tx, rx) = mpsc::channel();
            let owned = path.to_owned();
            std::thread::spawn(move || {
                let _ = tx.send(crate::app::screenshots_page::decode::load(&owned, SIDE));
            });
            self.rx = Some(rx);
        }
        if let Some(rx) = &self.rx {
            match rx.try_recv() {
                Ok(Ok(image)) => {
                    self.texture = Some(ui.ctx().load_texture(
                        "summary-screenshot",
                        image,
                        Default::default(),
                    ));
                    self.rx = None;
                }
                Ok(Err(_)) | Err(mpsc::TryRecvError::Disconnected) => {
                    self.failed = true;
                    self.rx = None;
                }
                Err(mpsc::TryRecvError::Empty) => ui.ctx().request_repaint(),
            }
        }
        match &self.texture {
            Some(texture) => {
                let size = texture.size_vec2();
                let scale = (WIDTH / size.x).min(1.0);
                ui.add(
                    egui::Image::new(texture)
                        .fit_to_exact_size(size * scale)
                        .sense(egui::Sense::click()),
                )
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .on_hover_text("Open this screenshot")
                .clicked()
            }
            None if self.failed => {
                ui.weak("The screenshot could not be read.");
                false
            }
            None => {
                crate::theme::spinner(ui);
                false
            }
        }
    }
}
