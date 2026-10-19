// SPDX-License-Identifier: MIT
//! The async observations of a call: the preview a row carries, and the
//! saved ones past it, read a page at a time off the interface thread.
use super::{key, note_row, section_row, Inspector, InvocationKey, Prefix};
use crate::{archive::ASYNC_PAGE, theme};
use antinomie_monitor_core::{AsyncPage, EventSummary, FieldSummary, InvocationSummary};
use eframe::egui;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

/// What the browser holds for the selected call: one page, the cursors back
/// to the earlier ones, and the read in flight. Memory follows one page.
struct Browse {
    key: InvocationKey,
    /// Cursors of the pages before the one shown.
    earlier: Vec<u64>,
    /// Cursor of the page shown, or being read.
    from: u64,
    page: Option<AsyncPage>,
    error: Option<String>,
    cancel: Arc<AtomicBool>,
}

/// A page the app should read for the browser.
pub(crate) struct AsyncRead {
    pub(crate) generation: u64,
    pub(crate) call: InvocationKey,
    pub(crate) from: u64,
    pub(crate) cancel: Arc<AtomicBool>,
}

#[derive(Default)]
pub(crate) struct State {
    browse: Option<Browse>,
    wanted: Option<AsyncRead>,
    /// Newer than any answer to an earlier read.
    generation: u64,
    can_read: bool,
}

impl State {
    /// Whether the selected call's recording can be read for more pages.
    pub(super) fn allow_reads(&mut self, can_read: bool) {
        self.can_read = can_read;
    }
}

/// "1,234": the count with thousands separators.
fn grouped(count: u64) -> String {
    let digits = count.to_string();
    let mut grouped = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

/// What a row says about its async observations when the preview is partial.
pub(super) fn partial_note(invocation: &InvocationSummary) -> Option<String> {
    let omitted = invocation.async_omitted();
    (omitted > 0).then(|| {
        format!(
            "{} of {} async observations shown",
            grouped(invocation.async_events.len() as u64),
            grouped(invocation.async_saved)
        )
    })
}

impl Inspector {
    /// A page the app should read now, if the user asked for one.
    pub(crate) fn take_async_read(&mut self) -> Option<AsyncRead> {
        self.observations.wanted.take()
    }

    /// A read for the browser ended. An answer to a superseded read is dropped.
    pub(crate) fn async_answer(
        &mut self,
        generation: u64,
        call: InvocationKey,
        result: Result<AsyncPage, String>,
    ) {
        let Some(browse) = self
            .observations
            .browse
            .as_mut()
            .filter(|browse| browse.key == call && generation == self.observations.generation)
        else {
            return;
        };
        match result {
            Ok(page) => {
                browse.page = Some(page);
                browse.error = None;
            }
            Err(error) => browse.error = Some(error),
        }
    }

    /// The read could not run or was dropped; the browser says so.
    pub(crate) fn fail_async(&mut self, generation: u64, message: &str) {
        if generation == self.observations.generation {
            self.observations.wanted = None;
            if let Some(browse) = &mut self.observations.browse {
                browse.error = Some(message.to_owned());
            }
        }
    }

    /// Leave the browser, ending a read in flight.
    pub(crate) fn end_async(&mut self) {
        if let Some(browse) = self.observations.browse.take() {
            browse.cancel.store(true, Ordering::Relaxed);
        }
        self.observations.wanted = None;
        self.observations.generation = self.observations.generation.wrapping_add(1);
    }

    /// Start browsing the saved async observations of a call.
    pub(crate) fn begin_async(&mut self, call: InvocationKey) {
        self.read_async(call, 0, Vec::new());
    }

    /// The browser's error, if its last read failed.
    #[cfg(test)]
    pub(crate) fn async_error(&self) -> Option<String> {
        self.observations.browse.as_ref()?.error.clone()
    }

    /// Read the page at `from` of the call, keeping the way back.
    fn read_async(&mut self, call: InvocationKey, from: u64, earlier: Vec<u64>) {
        if let Some(old) = self.observations.browse.take() {
            old.cancel.store(true, Ordering::Relaxed);
        }
        let cancel = Arc::new(AtomicBool::new(false));
        self.observations.generation = self.observations.generation.wrapping_add(1);
        self.observations.browse = Some(Browse {
            key: call,
            earlier,
            from,
            page: None,
            error: None,
            cancel: Arc::clone(&cancel),
        });
        self.observations.wanted = Some(AsyncRead {
            generation: self.observations.generation,
            call,
            from,
            cancel,
        });
    }

    /// An observation of the call: on the browsed page or in the preview.
    pub(crate) fn find_async<'a>(
        &'a self,
        invocation: &'a InvocationSummary,
        event_seq: u64,
    ) -> Option<&'a EventSummary> {
        self.observations
            .browse
            .as_ref()
            .filter(|browse| browse.key == key(invocation))
            .and_then(|browse| browse.page.as_ref())
            .into_iter()
            .flat_map(|page| &page.events)
            .chain(&invocation.async_events)
            .find(|event| event.event_seq == event_seq)
    }

    /// The selected observation field when only the browsed page holds it.
    pub(crate) fn browsed_field(&self, invocation: &InvocationSummary) -> Option<FieldSummary> {
        let super::Selection::AsyncCaptured {
            event_seq,
            object_id,
        } = self.selection.as_ref()?
        else {
            return None;
        };
        self.find_async(invocation, *event_seq)?
            .fields
            .iter()
            .find(|field| field.object_id == *object_id)
            .cloned()
    }

    /// The "Async" section of the decoded call. A partial preview says how
    /// many saved observations it leaves out and offers to browse them.
    pub(super) fn async_section(
        &mut self,
        ui: &mut egui::Ui,
        invocation: &InvocationSummary,
        root: &Prefix,
    ) {
        let call = key(invocation);
        if self
            .observations
            .browse
            .as_ref()
            .is_some_and(|browse| browse.key != call)
        {
            self.end_async();
        }
        // The page is lifted out while its rows draw, which need `self`.
        let browsed = self
            .observations
            .browse
            .as_mut()
            .and_then(|browse| browse.page.take());
        let first = self
            .observations
            .browse
            .as_ref()
            .map_or(0, |browse| browse.earlier.len() * ASYNC_PAGE);
        let shown: &[EventSummary] = browsed
            .as_ref()
            .map_or(&invocation.async_events, |page| &page.events);
        let title = match &browsed {
            Some(page) => format!(
                "Async ({}–{} of {} saved)",
                grouped(first as u64 + 1),
                grouped((first + shown.len()) as u64),
                grouped(page.total)
            ),
            None if invocation.async_omitted() > 0 => format!(
                "Async ({} of {} saved)",
                grouped(shown.len() as u64),
                grouped(invocation.async_saved)
            ),
            None => format!("Async ({})", shown.len()),
        };
        if section_row(ui, ui.id().with((call, "async")), &title, false) {
            // Above the rows: a page can have hundreds, and the way to the
            // rest must not wait at the end of them.
            self.browser_controls(
                ui,
                invocation,
                &root.child(shown.is_empty()),
                browsed.as_ref(),
            );
            if shown.is_empty() {
                note_row(
                    ui,
                    &root.child(true),
                    "No correlated async observations",
                    theme::muted(),
                );
            }
            let count = shown.len();
            for (index, event) in shown.iter().enumerate() {
                self.async_event(ui, invocation, event, root.child(index + 1 == count));
            }
        }
        if let (Some(page), Some(browse)) = (browsed, self.observations.browse.as_mut()) {
            browse.page = Some(page);
        }
    }

    /// Notes and buttons under the observations: the omitted count and the
    /// way into the browser, or its position, errors and paging.
    fn browser_controls(
        &mut self,
        ui: &mut egui::Ui,
        invocation: &InvocationSummary,
        branch: &Prefix,
        page: Option<&AsyncPage>,
    ) {
        let call = key(invocation);
        let Some(browse) = &self.observations.browse else {
            let omitted = invocation.async_omitted();
            if omitted == 0 {
                return;
            }
            let remark = format!("{} more saved observations not shown", grouped(omitted));
            note_row(ui, branch, &remark, theme::warn());
            let browse = ui.add_enabled(
                self.observations.can_read,
                egui::Button::new("Browse all saved observations"),
            );
            if browse.clicked() {
                self.begin_async(call);
            }
            return;
        };
        let (from, earlier) = (browse.from, browse.earlier.clone());
        let busy = page.is_none() && browse.error.is_none();
        if let Some(error) = &browse.error {
            note_row(ui, branch, error, theme::warn());
        }
        if busy {
            note_row(ui, branch, "Reading saved observations...", theme::muted());
        }
        for issue in page.iter().flat_map(|page| &page.issues).take(4) {
            note_row(ui, branch, issue, theme::warn());
        }
        let next = page.and_then(|page| page.next_event_seq);
        let mut go = None;
        let mut leave = false;
        ui.horizontal(|ui| {
            ui.add_space(8.0);
            let back = !earlier.is_empty() && !busy;
            if ui
                .add_enabled(back, egui::Button::new("Previous page"))
                .clicked()
            {
                let mut earlier = earlier.clone();
                go = earlier.pop().map(|previous| (previous, earlier));
            }
            if ui
                .add_enabled(next.is_some() && !busy, egui::Button::new("Next page"))
                .clicked()
            {
                let mut earlier = earlier.clone();
                earlier.push(from);
                go = next.map(|next| (next, earlier));
            }
            leave = ui.button("Back to preview").clicked();
        });
        if leave {
            self.end_async();
        } else if let Some((from, earlier)) = go {
            self.read_async(call, from, earlier);
        }
    }
}
