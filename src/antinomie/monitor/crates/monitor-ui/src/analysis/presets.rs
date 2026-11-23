// SPDX-License-Identifier: GPL-3.0-only
//! The Preset dropdown at the top of the Run program form's options column
//! (ANT-T0605). It offers the five built-in presets and the files of
//! `<data>/presets`, read by the service's own parser
//! (`antinomie_service::config::form`), so a preset means the same here, on
//! the command line and in Auto mode. Choosing one fills the options the
//! window has; the program path, the picked sample and the guest path are
//! never touched. Changing a field afterwards shows Custom.
use super::*;
use antinomie_monitor_core::route::RouteKind;
use antinomie_service::{
    api::spec::Route,
    config::{
        builtin::DEFAULT_PRESET,
        form::{self, FormOptions, FormPreset},
    },
    stages::plan,
};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

/// How long the listing of the data folder's files is kept before the form
/// reads the folder again.
const REFRESH: Duration = Duration::from_secs(2);

/// The fields a preset covers, as the form holds them. Two equal values mean
/// the form still is the preset.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Covered {
    analysis: bool,
    checks: Vec<&'static str>,
    capture_network: bool,
    route: Option<RouteKind>,
    memory_dump: bool,
    core_dump: bool,
    core_budget: (Option<u32>, Option<u32>),
    trigger: Option<antinomie_monitor_core::dump_trigger::DumpTrigger>,
    nonresident: bool,
    screenshots: (Option<u32>, Option<u32>, Option<u32>),
    args: String,
    cwd: String,
    env: String,
    user: (u32, u32),
}

impl Covered {
    pub(crate) fn of(request: &ExecRequest, args: &str, env: &str) -> Self {
        let mut checks: Vec<&'static str> = request
            .analysis
            .checks
            .iter()
            .map(|kind| kind.label())
            .collect();
        checks.sort_unstable();
        Self {
            analysis: request.analysis.enabled,
            checks,
            capture_network: request.capture_network,
            route: request.route,
            memory_dump: request.memory_dump_on_exit,
            core_dump: request.core_dump_on_exit,
            core_budget: (request.core_max_size, request.core_timeout_ms),
            trigger: request.dump_trigger.clone(),
            nonresident: request.core_nonresident,
            screenshots: (
                request.screenshot_every_s,
                request.screenshot_max_pictures,
                request.screenshot_max_mib,
            ),
            args: args.to_owned(),
            cwd: request.cwd.clone(),
            env: env.to_owned(),
            user: (request.uid, request.gid),
        }
    }
}

/// The Preset dropdown's state: the list, the choice and what the form was
/// when the choice filled it.
pub(crate) struct PresetForm {
    dir: PathBuf,
    list: Vec<FormPreset>,
    read: Option<Instant>,
    /// The name of the preset the form was last filled from.
    chosen: Option<String>,
    /// The form as that preset left it, taken when the frame ended.
    applied: Option<Covered>,
    /// A preset filled the form this frame; the form is taken once every
    /// section has settled what this VM cannot do.
    settle: bool,
    /// The remembered choice (or Standard) filled the form once.
    started: bool,
    /// Whether the dropdown showed Custom this frame.
    shown_custom: bool,
    /// The VM runs, so the form takes input and the capabilities are known.
    pub(crate) ready: bool,
}

impl PresetForm {
    pub(crate) fn new(data_dir: PathBuf) -> Self {
        Self {
            dir: data_dir,
            list: Vec::new(),
            read: None,
            chosen: None,
            applied: None,
            settle: false,
            shown_custom: false,
            started: false,
            ready: true,
        }
    }

    /// Tests that set the form themselves: the first open does not fill it.
    #[cfg(test)]
    pub(crate) fn keep_the_form(&mut self) {
        self.started = true;
    }

    fn refresh(&mut self, force: bool) {
        if force || self.read.is_none_or(|at| at.elapsed() > REFRESH) {
            self.list = form::list(&self.dir);
            self.read = Some(Instant::now());
        }
    }

    fn entry(&self, name: &str) -> Option<&FormPreset> {
        self.list.iter().find(|entry| entry.name == name)
    }

    /// The preset the form was filled from, whatever was changed since.
    #[cfg(test)]
    pub(crate) fn base(&self) -> Option<&str> {
        self.chosen.as_deref()
    }

    /// The form no longer is what the preset filled in.
    pub(crate) fn is_custom(&self, now: &Covered) -> bool {
        self.applied.as_ref().is_some_and(|applied| applied != now)
    }

    /// The user chose `name`: fill the form, program fields included.
    pub(crate) fn choose(
        &mut self,
        ctx: &egui::Context,
        name: &str,
        request: &mut ExecRequest,
        args: &mut String,
        env: &mut String,
    ) -> bool {
        let Some(Ok(options)) = self.entry(name).map(|entry| entry.options.as_ref()) else {
            return false;
        };
        fill(options, request, args, env, true);
        ctx.data_mut(|data| {
            data.remove::<RouteKind>(egui::Id::new("run-route-filled"));
            data.insert_persisted(remembered_id(), name.to_owned());
        });
        self.chosen = Some(name.to_owned());
        self.settle = true;
        true
    }

    fn label(&self, custom: bool) -> String {
        let Some(name) = self.chosen.as_deref() else {
            return "None".into();
        };
        let title = self.entry(name).map_or(name, |entry| entry.title.as_str());
        if custom {
            format!("Custom (from {title})")
        } else {
            title.to_owned()
        }
    }
}

fn remembered_id() -> egui::Id {
    egui::Id::new("run-preset-remembered")
}

/// What stops this VM from running `options`, or `None`.
pub(crate) fn unavailable(
    options: &FormOptions,
    capabilities: &LaunchCapabilities,
    request: &ExecRequest,
) -> Option<String> {
    if !options.unavailable.is_empty() {
        return Some(options.unavailable.join(" "));
    }
    let preset = options.preset();
    let dumps = &preset.dumps;
    let core_wanted = dumps.core_dump_on_exit || dumps.trigger().is_some_and(|plan| plan.core);
    if core_wanted && !capabilities.core_on_exit {
        return Some(core_unavailable_reason(false).to_owned());
    }
    if core_wanted && dumps.core_dump_on_exit && request.run_in != RunIn::AppTerminal {
        return Some(core_unavailable_reason(true).to_owned());
    }
    if preset.record.screenshot_every_s > 0 && !capabilities.screen {
        return Some(NO_SCREEN.to_owned());
    }
    if let Some(kind) = route_kind(&preset.network.route)
        && kind != RouteKind::Drop
    {
        if capabilities.route.network != antinomie_monitor_core::VmNetwork::Routed {
            return Some(format!(
                "Route {} needs a Routed VM; this VM's network is fixed.",
                kind.label()
            ));
        }
        if let Some(problem) = capabilities.route.problem(kind) {
            return Some(problem.to_owned());
        }
    }
    None
}

fn route_kind(route: &Route) -> Option<RouteKind> {
    Some(match route {
        Route::Drop => RouteKind::Drop,
        Route::Internet => RouteKind::Internet,
        Route::InetSim => RouteKind::InetSim,
        Route::Tor => RouteKind::Tor,
        Route::Vpn(_) => RouteKind::Vpn,
        Route::Socks5(_) => RouteKind::Socks5,
        Route::Nat => return None,
    })
}

/// Fill the fields `options` covers. The program's path, sample and guest
/// path are never touched; the arguments, working directory, environment and
/// user are filled when `program` is set and the preset writes them out.
pub(crate) fn fill(
    options: &FormOptions,
    request: &mut ExecRequest,
    args: &mut String,
    env: &mut String,
    program: bool,
) {
    let preset = options.preset();
    let run = plan::effective(preset, Default::default());
    let eff = &run.request;
    request.analysis.enabled = preset.static_analysis.enabled;
    request.analysis.checks = plan::hosted(preset).static_checks.into_iter().collect();
    request.capture_network = eff.capture_network;
    request.route = eff.route;
    request.memory_dump_on_exit = eff.memory_dump_on_exit;
    request.core_dump_on_exit = eff.core_dump_on_exit;
    request.core_max_size = eff.core_max_size;
    request.core_timeout_ms = eff.core_timeout_ms;
    request.dump_trigger = eff.dump_trigger.clone();
    request.core_nonresident = eff.core_nonresident;
    request.screenshot_every_s = eff.screenshot_every_s;
    request.screenshot_max_pictures = eff.screenshot_max_pictures;
    request.screenshot_max_mib = eff.screenshot_max_mib;
    if program {
        let written = options.written;
        if written.arguments {
            *args = eff.args.join("\n");
        }
        if written.working_directory {
            request.cwd = eff.cwd.clone();
        }
        if written.environment {
            *env = eff.env.join("\n");
        }
        if written.user {
            (request.uid, request.gid) = (eff.uid, eff.gid);
        }
    }
}

/// The dropdown, and the first fill of the form. Called with the options
/// column's `ui`, before the sections.
pub(crate) fn dropdown(
    ui: &mut egui::Ui,
    state: &mut PresetForm,
    request: &mut ExecRequest,
    args: &mut String,
    env: &mut String,
    capabilities: LaunchCapabilities,
) {
    state.refresh(false);
    if !state.started && state.ready {
        state.started = true;
        let name =
            ui.ctx()
                .data_mut(|data| data.get_persisted::<String>(remembered_id()))
                .filter(|name| {
                    state.entry(name).is_some_and(|entry| {
                        entry.options.as_ref().is_ok_and(|options| {
                            unavailable(options, &capabilities, request).is_none()
                        })
                    })
                })
                .unwrap_or_else(|| DEFAULT_PRESET.to_owned());
        if let Some(Ok(options)) = state.entry(&name).map(|entry| entry.options.as_ref()) {
            // The program fields are the user's until they pick a preset.
            fill(options, request, args, env, false);
            state.chosen = Some(name);
            state.settle = true;
        }
    }
    let custom = state.is_custom(&Covered::of(request, args, env));
    state.shown_custom = custom;
    let mut picked = None;
    let mut open = false;
    ui.horizontal(|ui| {
        let label = ui.label("Preset");
        let response = egui::ComboBox::from_id_salt("run-preset")
            .selected_text(state.label(custom))
            .width(ui.text_style_height(&egui::TextStyle::Body) * 16.0)
            // The five and a few files without a scroll bar.
            .height(ui.text_style_height(&egui::TextStyle::Body) * 22.0)
            .show_ui(ui, |ui| {
                open = true;
                for (position, entry) in state.list.iter().enumerate() {
                    if position == 5 {
                        ui.separator();
                    }
                    let reason = match &entry.options {
                        Ok(options) => unavailable(options, &capabilities, request),
                        Err(error) => Some(error.clone()),
                    };
                    let selected = state.chosen.as_deref() == Some(entry.name.as_str()) && !custom;
                    let clicked = crate::widgets::hover_help_or(
                        ui,
                        entry.description.as_str(),
                        reason.as_deref().unwrap_or_default(),
                        |ui| {
                            ui.add_enabled(
                                reason.is_none(),
                                egui::Button::selectable(selected, entry.title.as_str()),
                            )
                        },
                    )
                    .clicked();
                    if clicked {
                        picked = Some(entry.name.clone());
                    }
                }
            });
        crate::widgets::hover_help(
            ui,
            "Fills the options below; change one and it reads Custom",
            |_ui| response.response.labelled_by(label.id),
        );
    });
    if open {
        state.refresh(true);
    }
    if let Some(name) = picked {
        state.choose(ui.ctx(), &name, request, args, env);
    }
    if let Some(entry) = state.chosen.as_deref().and_then(|name| state.entry(name))
        && !entry.description.is_empty()
    {
        // The column reaches under the scroll bar: keep the words clear of it.
        ui.scope(|ui| {
            ui.set_max_width((ui.available_width() - 16.0).max(80.0));
            ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                ui.add(egui::Label::new(egui::RichText::new(&entry.description).weak()).wrap());
            });
        });
    }
}

/// After the sections: take the form as the preset left it once they settled
/// what this VM cannot do, and ask for another frame when the label changes.
pub(crate) fn settled(
    ui: &egui::Ui,
    state: &mut PresetForm,
    request: &ExecRequest,
    args: &str,
    env: &str,
) {
    let now = Covered::of(request, args, env);
    if state.settle {
        state.settle = false;
        state.applied = Some(now);
        ui.ctx().request_repaint();
    } else if state.is_custom(&now) != state.shown_custom {
        ui.ctx().request_repaint();
    }
}
