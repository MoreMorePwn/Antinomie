// SPDX-License-Identifier: GPL-3.0-only
//! The option sections of the Run program form beside the program fields:
//! Dumps, Network, Timed Screenshot and Debugging, each a section that folds
//! (item 18). What a section enforces on the request (a choice this VM
//! cannot honour is cleared) is applied whether the section is open or not.
use super::*;

/// A section of the Run form that folds: its title in the section style, open
/// at first. Whether it is open is kept with the window's state (egui's
/// memory, which the app saves), so it stays as the user left it.
pub(super) fn folding_section<R>(
    ui: &mut egui::Ui,
    title: &str,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> Option<R> {
    if ui.min_rect().height() > 1.0 {
        ui.add_space(8.0);
    }
    egui::CollapsingHeader::new(crate::theme::section_title(ui, title))
        .id_salt(("run-form-section", title))
        .default_open(true)
        .show(ui, add_contents)
        .body_returned
}

/// What the Dumps and Network sections enforce on `request`, open or not.
pub(super) fn settle_capture(request: &mut ExecRequest, capabilities: LaunchCapabilities) {
    let core_supported = capabilities.core_on_exit;
    if !(core_supported && request.run_in == RunIn::AppTerminal) {
        request.core_dump_on_exit = false;
    }
    if let Some(plan) = request.dump_trigger.as_mut()
        && !core_supported
    {
        plan.core = false;
    }
    let trigger_core = request.dump_trigger.as_ref().is_some_and(|plan| plan.core);
    if !trigger_core
        || !capabilities
            .core_limits
            .is_some_and(|limits| limits.nonresident)
    {
        request.core_nonresident = false;
    }
    if request.core_dump_on_exit || trigger_core {
        settle_budget(request, capabilities);
    } else {
        request.core_max_size = None;
        request.core_timeout_ms = None;
    }
    if capabilities.route.network == antinomie_monitor_core::VmNetwork::Disconnected {
        request.capture_network = false;
    }
    if capabilities.route.network != antinomie_monitor_core::VmNetwork::Routed {
        request.route = None;
    }
}

pub(super) fn capture_selection(
    ui: &mut egui::Ui,
    request: &mut ExecRequest,
    capabilities: LaunchCapabilities,
    outcome: &mut LaunchOutcome,
) {
    settle_capture(request, capabilities);
    let core_supported = capabilities.core_on_exit;
    folding_section(ui, "Dumps", |ui| {
        // The trigger comes first; the dumps taken when the program exits sit
        // below its options.
        trigger_selection(ui, request, capabilities);
        ui.add_space(6.0);
        ui.checkbox(&mut request.memory_dump_on_exit, "Memory Dump on Exit")
            .on_hover_text("Dump VM RAM after the process tree exits. This is post-exit VM memory, not a process core.");
        let core_enabled = core_supported && request.run_in == RunIn::AppTerminal;
        ui.add_enabled(
            core_enabled,
            egui::Checkbox::new(&mut request.core_dump_on_exit, "Core Dump on Exit"),
        )
        .on_hover_text("Capture the launched root process before exit, including thread registers and selected memory. Native programs on x86-64 and arm64 guests, and 32-bit ARM programs on an arm64 guest (an ia32 or x32 program on an x86-64 guest gets no core); memory is filtered and bounded by the budget below, so captures may be partial. Some fatal exits, including SIGKILL, may leave register context unavailable. Thread synchronization and page faults may delay exit.")
        .on_disabled_hover_text(core_unavailable_reason(core_supported));
        if core_enabled && request.core_dump_on_exit {
            core_budget_row(ui, request, capabilities);
        }
        if !core_enabled {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(core_unavailable_reason(core_supported)).weak(),
                )
                .wrap(),
            );
        }
    });
    settle_capture(request, capabilities);
    folding_section(ui, "Network", |ui| {
        // A VM without a network card has nothing to capture: the box is off
        // and says what to change, rather than a run that cannot start.
        let card = capabilities.route.network != antinomie_monitor_core::VmNetwork::Disconnected;
        ui.add_enabled(
            card,
            egui::Checkbox::new(&mut request.capture_network, "Capture network from start until tree exits"),
        )
        .on_hover_text("Record VM network packets during this run. Packets are VM-wide, not attributed to this process.")
        .on_disabled_hover_text(NO_NETWORK_CARD);
        if !card {
            ui.horizontal_wrapped(|ui| {
                ui.add(egui::Label::new(egui::RichText::new(NO_NETWORK_CARD).weak()).wrap());
                outcome.open_vm_settings = ui
                    .button("VM settings…")
                    .on_hover_text(
                        "Open this VM's settings (its network changes while it is stopped)",
                    )
                    .clicked();
            });
        }
        crate::route_ui::selector(ui, request, &capabilities.route);
    });
}

/// Why the Run form offers no network capture.
pub(super) const NO_NETWORK_CARD: &str =
    "This VM has no network card, so there is nothing to capture. \
     Set its network to Isolated, NAT or Routed and restart it.";

/// The budget and deadline the request's cores use, put into the request
/// once the guest has said what it accepts. Until then the request keeps the
/// contract every guest has: 64 MiB and 5 s.
fn settle_budget(request: &mut ExecRequest, capabilities: LaunchCapabilities) -> (u32, u32) {
    let limits = capabilities.core_limits;
    let mut budget = request.core_max_size.unwrap_or_else(|| {
        crate::core_budget::initial(limits.as_ref(), capabilities.core_default_mib)
    });
    let mut timeout = request.core_timeout_ms.unwrap_or_else(|| {
        crate::core_budget::default_timeout_ms(limits.as_ref(), u64::from(budget))
    });
    if let Some(limits) = limits.as_ref()
        && u64::from(budget) > limits.max_size
    {
        budget = limits.effective_budget(budget >> 20);
        timeout = crate::core_budget::default_timeout_ms(Some(limits), u64::from(budget));
    }
    if limits.is_some() {
        request.core_max_size = Some(budget);
        request.core_timeout_ms = Some(timeout);
    }
    (budget, timeout)
}

/// Budget and deadline of the run's cores, with what the guest accepts.
fn core_budget_row(ui: &mut egui::Ui, request: &mut ExecRequest, capabilities: LaunchCapabilities) {
    let limits = capabilities.core_limits;
    let (mut budget, mut timeout) = settle_budget(request, capabilities);
    ui.indent("core-budget", |ui| {
        if let Some(picked) =
            crate::core_budget::show(ui, "run-core", &mut budget, &mut timeout, limits.as_ref())
        {
            ui.data_mut(|data| data.insert_temp(remembered_budget_id(), picked));
        }
        let (text, warn) = crate::core_budget::caption(limits.as_ref(), None, u64::from(budget));
        let text = egui::RichText::new(text);
        ui.add(
            egui::Label::new(if warn {
                text.color(crate::theme::warn())
            } else {
                text.weak()
            })
            .wrap(),
        );
    });
    if limits.is_some() {
        request.core_max_size = Some(budget);
        request.core_timeout_ms = Some(timeout);
    }
}

/// Dump on suspicious activity: the Triage tier, then the core and the memory
/// dump, each its own box with its own settings under it (item 29).
pub(super) fn trigger_selection(
    ui: &mut egui::Ui,
    request: &mut ExecRequest,
    capabilities: LaunchCapabilities,
) {
    use antinomie_monitor_core::dump_trigger::{DumpTrigger, TriggerTier};
    let mut on = request.dump_trigger.is_some();
    ui.checkbox(&mut on, "Dump when suspicious activity is seen")
        .on_hover_text("While the program runs, the Triage rules judge each call as it arrives. The first match at or above the chosen tier takes the dumps you pick below, each within its own count. The program is not stopped; a memory dump pauses the VM while QEMU writes it.");
    if !on {
        request.dump_trigger = None;
        request.core_nonresident = false;
        return;
    }
    let core_ok = capabilities.core_on_exit;
    let nonresident = capabilities
        .core_limits
        .is_some_and(|limits| limits.nonresident);
    let count = |ui: &mut egui::Ui, value: &mut u32, what: &str| {
        ui.horizontal_wrapped(|ui| {
            ui.label("At most");
            ui.add(egui::DragValue::new(value).range(1..=DumpTrigger::MAX_DUMPS));
            ui.label(format!("{what} per run"));
        });
    };
    let mut show_budget = false;
    ui.indent("dump-trigger", |ui| {
        let plan = request
            .dump_trigger
            .get_or_insert_with(DumpTrigger::default);
        ui.horizontal_wrapped(|ui| {
            ui.label("Minimum tier");
            egui::ComboBox::from_id_salt("dump-trigger-tier")
                .selected_text(plan.min_tier.label())
                .show_ui(ui, |ui| {
                    for tier in TriggerTier::ALL {
                        ui.selectable_value(&mut plan.min_tier, tier, tier.label());
                    }
                })
                .response
                .on_hover_text("The lowest Triage tier that takes a dump: this tier and every tier above it. Triage tiers are Low, Medium and High; there is nothing above High.");
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("At least");
            ui.add(
                egui::DragValue::new(&mut plan.cooldown_secs)
                    .range(0..=3600)
                    .suffix(" s"),
            );
            ui.label("between two dumps");
        });
        ui.add_enabled(
            core_ok,
            egui::Checkbox::new(&mut plan.core, "Core of the process that triggered it"),
        )
        .on_hover_text("A core of the process whose call matched, taken while it runs. Native programs on x86-64 and arm64 guests, and 32-bit ARM programs on an arm64 guest (not ia32 or x32 on an x86-64 guest); bounded by the budget. The guest copies only pages that are in memory when it reads them (not swapped-out or untouched ones) unless Read non-resident pages is ticked; a core that lacks only those pages is complete, and its note says how many were left out. On a revision-22 base a process that ends is held at its exit for up to 50 ms, so one that exits right after the match still has its core taken; on an older base it can be gone first, and the run says so.")
        .on_disabled_hover_text(core_unavailable_reason(core_ok));
        if plan.core {
            ui.indent("dump-trigger-core", |ui| {
                count(ui, &mut plan.max_cores, "core(s)");
                ui.add_enabled(
                    nonresident,
                    egui::Checkbox::new(&mut request.core_nonresident, "Read non-resident pages"),
                )
                .on_hover_text("Also read the pages of the process that are not in memory (swapped out, or file pages the kernel dropped) into the core, as an exit core does. Reading from swap or disk takes longer and is bounded by the budget and the deadline; pages the process never touched hold nothing and stay out.")
                .on_disabled_hover_text("Needs a base of guest contract revision 22: this guest copies only the pages that are in memory.");
            });
            // The exit core's budget row is the same budget: shown once.
            show_budget = !request.core_dump_on_exit;
        }
        let plan = request
            .dump_trigger
            .get_or_insert_with(DumpTrigger::default);
        ui.checkbox(&mut plan.memory, "Memory dump")
            .on_hover_text("Dump the VM's RAM. Skipped when the VM has more RAM than the cap below or the disk is too full.");
        if plan.memory {
            ui.indent("dump-trigger-memory", |ui| {
                count(ui, &mut plan.max_memory_dumps, "memory dump(s)");
                ui.horizontal_wrapped(|ui| {
                    ui.label("Only if the VM has at most");
                    ui.add(
                        egui::DragValue::new(&mut plan.memory_max_mib)
                            .range(256..=65536)
                            .speed(64.0)
                            .suffix(" MiB"),
                    );
                });
            });
        }
        if !plan.memory && !plan.core {
            ui.colored_label(crate::theme::warn(), "Pick a memory dump, a core, or both.");
        }
    });
    if show_budget {
        core_budget_row(ui, request, capabilities);
    }
}

/// Why the Run form offers no timed screenshots.
pub(super) const NO_SCREEN: &str = "Timed screenshots read the VM's screen in the app. Set VM screen to \"In the app (VNC)\" in the VM's settings; it applies at the next start of the VM.";

/// Timed Screenshot: a picture of the VM screen every N seconds during the
/// run, kept in the run's own folder (ANT-T0487), within limits the run sets
/// (item 19). The interval and the limits show before the box is ticked.
pub(super) fn screenshot_selection(ui: &mut egui::Ui, request: &mut ExecRequest, available: bool) {
    use antinomie_monitor_core::timed_shots as shots;
    if !available {
        request.screenshot_every_s = None;
    }
    if request.screenshot_every_s.is_none() {
        request.screenshot_max_pictures = None;
        request.screenshot_max_mib = None;
    }
    folding_section(ui, "Timed Screenshot", |ui| {
        // The interval shown while the box is off, used when it is ticked.
        let draft_id = egui::Id::new("run-screenshot-every");
        let mut every = request.screenshot_every_s.unwrap_or_else(|| {
            ui.data(|data| data.get_temp::<u32>(draft_id))
                .unwrap_or(shots::DEFAULT_INTERVAL_S)
        });
        let mut on = request.screenshot_every_s.is_some();
        ui.horizontal(|ui| {
            ui.add_enabled(available, egui::Checkbox::new(&mut on, "Take screenshots"))
                .on_hover_text("Save the VM screen as a picture at this interval while the run goes, with the run-relative time in its name, in the run's own folder. A screen that has not changed since the last picture is skipped.")
                .on_disabled_hover_text(NO_SCREEN);
            ui.add_enabled_ui(available && on, |ui| {
                ui.label("every");
                ui.add(
                    egui::DragValue::new(&mut every)
                        .range(shots::MIN_INTERVAL_S..=shots::MAX_INTERVAL_S)
                        .suffix(" s"),
                )
                .on_hover_text(format!(
                    "{} to {} seconds",
                    shots::MIN_INTERVAL_S,
                    shots::MAX_INTERVAL_S
                ));
            });
        });
        ui.data_mut(|data| data.insert_temp(draft_id, every));
        request.screenshot_every_s = (available && on).then_some(every);
        let default = shots::Bounds::default();
        let mut pictures = request
            .screenshot_max_pictures
            .unwrap_or(default.pictures as u32);
        let mut mib = request
            .screenshot_max_mib
            .unwrap_or((default.bytes >> 20) as u32);
        ui.indent("timed-screenshot-limits", |ui| {
            ui.add_enabled_ui(available && on, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label("At most");
                    ui.add(egui::DragValue::new(&mut pictures).range(shots::PICTURES_RANGE))
                        .on_hover_text(format!(
                            "{} to {} pictures; the series ends with a note when it is reached",
                            shots::PICTURES_RANGE.start(),
                            shots::PICTURES_RANGE.end()
                        ));
                    ui.label("pictures and");
                    ui.add(
                        egui::DragValue::new(&mut mib)
                            .range(shots::MIB_RANGE)
                            .speed(16.0)
                            .suffix(" MiB"),
                    )
                    .on_hover_text(format!(
                        "{} to {} MiB of pictures",
                        shots::MIB_RANGE.start(),
                        shots::MIB_RANGE.end()
                    ));
                    ui.label("per run");
                });
            });
        });
        if request.screenshot_every_s.is_some() {
            // The default is left out of the request, as before the limits
            // could be set.
            request.screenshot_max_pictures =
                (u64::from(pictures) != default.pictures).then_some(pictures);
            request.screenshot_max_mib = (u64::from(mib) != default.bytes >> 20).then_some(mib);
        }
        if !available {
            ui.add(egui::Label::new(egui::RichText::new(NO_SCREEN).weak()).wrap());
        }
    });
}

pub(super) fn debugger_selection(ui: &mut egui::Ui, request: &mut ExecRequest, supported: bool) {
    let enabled = supported && request.run_in == RunIn::AppTerminal;
    if !enabled {
        request.debug_on_start = false;
    }
    let reason = if supported {
        "Debug on start requires Run in: App terminal."
    } else {
        "Debug on start requires a base built for Antinomie 0.7.0."
    };
    folding_section(ui, "Debugging", |ui| {
        ui.add_enabled(
            enabled,
            egui::Checkbox::new(&mut request.debug_on_start, "Debug on start"),
        )
        .on_hover_text("Stop the program before its first instruction (the loader's, for a dynamic program) and open the debugger on it. The run shows the gdb command to attach with; the program waits until a debugger continues it. Nothing runs in the guest for this.")
        .on_disabled_hover_text(reason);
        if !enabled {
            ui.add(egui::Label::new(egui::RichText::new(reason).weak()).wrap());
        }
    });
}

pub(super) fn core_unavailable_reason(core_supported: bool) -> &'static str {
    if core_supported {
        "Core capture requires Run in: App terminal; desktop launchers run a shell wrapper."
    } else {
        "Core capture needs a newer guest base. Rebuild or download a newer base image (Library > Base images)."
    }
}
