// SPDX-License-Identifier: GPL-3.0-only
//! A job on its own thread whose result a view picks up on a later frame.
//!
//! The same shape the file-activity pane uses (`Arc<Mutex<Option<T>>>` filled
//! by the worker, which then asks the context for a repaint). Use it for work
//! that can take long on a slow disk or an external program, so a click or a
//! frame never waits for it.
use eframe::egui;
use std::sync::{Arc, Mutex};

pub(crate) struct Task<T>(Arc<Mutex<Option<T>>>);

impl<T: Send + 'static> Task<T> {
    pub(crate) fn spawn(ctx: &egui::Context, work: impl FnOnce() -> T + Send + 'static) -> Self {
        let slot = Arc::new(Mutex::new(None));
        let (out, ctx) = (Arc::clone(&slot), ctx.clone());
        std::thread::spawn(move || {
            let done = work();
            if let Ok(mut slot) = out.lock() {
                *slot = Some(done);
            }
            ctx.request_repaint();
        });
        Self(slot)
    }

    /// The result once the worker has finished; it is taken, so ask until it
    /// comes and then drop the task.
    pub(crate) fn done(&self) -> Option<T> {
        self.0.lock().ok().and_then(|mut slot| slot.take())
    }
}
