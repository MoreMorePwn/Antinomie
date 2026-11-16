// SPDX-License-Identifier: GPL-3.0-only
//! VM configuration > Device profile: the hardware identity a VM shows its
//! guest. A preset fills every entry; editing one makes the profile Custom.
use super::*;
use crate::scroll_contain::ScrollContained as _;
use crate::widgets::Tip as _;
mod arm64;
mod cloud;
mod presets;
mod uptime;
use antinomie_monitor_core::stealth::{
    base_supporting, chassis_label, disk_bus_unavailable, firmware_unavailable, host_cpu_vendor,
    BaseSupport, DiskBus, DiskMedia, Fallback, FallbackSetting, Firmware, HostSupport,
    MachineIdentity, NatNetwork, NicModel, Pointer, RtcClock, SmbiosEntry, StealthPreset,
    StealthProfile, VmView, CHASSIS, CLOUDS, CPU_MODELS, MACHINES,
};
use antinomie_monitor_core::GuestArch;
pub(super) use cloud::launch_advice;
use presets::{preset_combo, preset_list, provider_list};
use uptime::uptime;

/// What the host offers (OVMF, clean SMT), read once.
pub(super) fn host_support() -> &'static HostSupport {
    HostSupport::cached()
}

/// What the host offers a VM of `arch`: AAVMF for an arm64 VM's UEFI.
fn host_for(arch: GuestArch) -> &'static HostSupport {
    if arch == GuestArch::AARCH64 {
        HostSupport::cached_arm64()
    } else {
        host_support()
    }
}

/// The app's help icon (shared: `widgets::help`).
pub(super) use crate::widgets::help;

/// A combo box whose unavailable choices are shown disabled with the reason.
fn choice<T: Copy + PartialEq>(
    ui: &mut egui::Ui,
    id: &str,
    value: &mut T,
    options: &[T],
    label: impl Fn(T) -> &'static str,
    unavailable: impl Fn(T) -> Option<String>,
) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(label(*value))
        .width(260.0)
        .truncate()
        .show_ui(ui, |ui| {
            for &option in options {
                let reason = unavailable(option);
                let response = ui.add_enabled(
                    reason.is_none(),
                    egui::Button::selectable(*value == option, label(option)),
                );
                if let Some(reason) = reason {
                    response.reason_tip(reason);
                } else if response.clicked() {
                    *value = option;
                }
            }
        });
}

impl MonitorApp {
    /// What a VM's device profile asks for that its base or this host cannot
    /// give: the settings that fall back when it starts.
    pub(crate) fn stealth_fallbacks_of(&self, vm: &VmConfig) -> Vec<Fallback> {
        antinomie_monitor_core::stealth::vm_fallbacks(vm, &self.snapshot.bases, host_support())
    }

    /// The Device profile window for Getting started's first VM draft.
    pub(super) fn profile_details_window(&mut self, ctx: &egui::Context, draft: &mut VmConfig) {
        let selected = selected_base(&self.snapshot, draft.base_identity.as_deref());
        let mut fit = Fit::new(&draft.stealth, draft, &self.snapshot.bases, selected);
        let size = VmSize::of(draft);
        window(
            ctx,
            &mut self.getting_started.profile_open,
            &mut draft.stealth,
            &mut fit,
            size,
            true,
            true,
        );
        if let Some(base) = fit.switch.take() {
            let old = draft.base_identity.replace(base);
            super::vm::follow_base_arch(&self.snapshot, draft, old.as_deref());
        }
    }

    pub(super) fn draft_stealth_fallbacks(&self) -> Vec<Fallback> {
        self.stealth_fallbacks_of(&self.draft)
    }
}

/// What the VM's base and this host cannot give of the profile, for the
/// window: each difference is shown on its own setting, with a switch to an
/// installed base that supports it.
pub(super) struct Fit<'a> {
    pub base: BaseSupport,
    /// The VM's settings beside the profile (architecture, network,
    /// display), which the Still visible list reads.
    view: VmView,
    /// What this host offers the base's architecture.
    host: &'static HostSupport,
    fallbacks: Vec<Fallback>,
    bases: &'a [BaseSummary],
    current: Option<&'a str>,
    /// A base the user chose to switch the VM to.
    pub switch: Option<String>,
}

impl<'a> Fit<'a> {
    /// The fit of `vm`'s profile `profile` (being edited) on its base.
    pub(super) fn new(
        profile: &StealthProfile,
        vm: &VmConfig,
        bases: &'a [BaseSummary],
        current: Option<&'a BaseSummary>,
    ) -> Self {
        let arch = current.map_or_else(Default::default, BaseSummary::arch);
        let host = host_for(arch);
        let base = current.map_or(BaseSupport::all(), |base| {
            BaseSupport::from_list(&base.stealth_support)
        });
        let mut fallbacks = profile.arch_fallbacks(arch);
        fallbacks.extend(profile.for_arch(arch).fallbacks(&base, host));
        Self {
            fallbacks,
            base,
            view: VmView::of(vm, current, host.ovmf.is_ok()),
            host,
            bases,
            current: current.map(|base| base.id.as_str()),
            switch: None,
        }
    }

    /// The VM's base runs Debian's own modules (systemd).
    pub(super) fn debian(&self) -> bool {
        self.current
            .and_then(|id| self.bases.iter().find(|base| base.id == id))
            .is_some_and(|base| base.guest.is_some())
    }

    /// The line on a setting that fell back, in a form grid: under the setting.
    fn row(&mut self, ui: &mut egui::Ui, profile: &StealthProfile, setting: FallbackSetting) {
        if self
            .fallbacks
            .iter()
            .all(|fallback| fallback.setting != setting)
        {
            return;
        }
        ui.label("");
        ui.vertical(|ui| {
            // As wide as the setting's list: wrapped at the cell's width,
            // the line widened the window (Firmware's on arm64).
            ui.set_max_width(300.0);
            self.line(ui, profile, setting);
        });
        ui.end_row();
    }

    /// The same line outside a grid.
    fn line(&mut self, ui: &mut egui::Ui, profile: &StealthProfile, setting: FallbackSetting) {
        let Some(fallback) = self.fallbacks.iter().find(|f| f.setting == setting) else {
            return;
        };
        ui.add(
            egui::Label::new(
                RichText::new(format!(
                    "{} {}",
                    egui_phosphor::regular::WARNING,
                    fallback.summary
                ))
                .color(theme::warn()),
            )
            .wrap(),
        );
        ui.add(
            egui::Label::new(
                RichText::new(&fallback.reason)
                    .small()
                    .color(theme::muted()),
            )
            .wrap(),
        );
        if let Some(base) = base_supporting(profile, setting, self.current, self.bases, self.host)
            && crate::widgets::with_help(
                ui,
                "Switch this VM to an installed base that supports the setting",
                |ui| ui.button(format!("Use base {}", base.label)),
            )
            .clicked()
        {
            self.switch = Some(base.id.clone());
        }
    }

    fn arm64(&self) -> bool {
        self.view.arch == GuestArch::AARCH64
    }

    /// The Still visible section: what the profile, as this VM starts it,
    /// leaves visible, then what it cannot apply and the VM's size.
    fn still_visible(&self, ui: &mut egui::Ui, profile: &StealthProfile, size: VmSize) {
        let started = profile.for_arch(self.view.arch);
        let (fitted, notes) = started.fitted(&self.base, self.host);
        for giveaway in fitted.still_visible(&self.view) {
            ui.label(format!("• {giveaway}"));
        }
        for note in notes {
            ui.colored_label(theme::warn(), format!("• {note}"));
        }
        // The VM's own settings, which pafish-style checks read, against the
        // machines the profile makes it look like.
        for hint in antinomie_monitor_core::stealth::resource_hints(
            &started,
            size.cpus,
            size.ram_mib,
            size.disk_gib,
        ) {
            ui.colored_label(theme::warn(), format!("• The VM's size: {hint}"));
        }
    }

    /// Under an IoT preset: BusyBox is the base it suggests (a device runs no
    /// desktop and no systemd), with a switch to an installed arm64 BusyBox
    /// base when the VM is on another.
    fn iot_base(&mut self, ui: &mut egui::Ui, profile: &StealthProfile) {
        if profile.preset != StealthPreset::Iot || !self.arm64() {
            return;
        }
        let busybox = |base: &BaseSummary| base.arch == GuestArch::AARCH64 && base.guest.is_none();
        let on_busybox = self
            .current
            .and_then(|id| self.bases.iter().find(|base| base.id == id))
            .is_some_and(busybox);
        if on_busybox {
            return;
        }
        ui.horizontal_wrapped(|ui| {
            ui.colored_label(
                theme::muted(),
                "Suggested base: BusyBox (arm64), as a device runs no desktop.",
            );
            if let Some(base) = self.bases.iter().find(|base| busybox(base))
                && ui
                    .add_enabled(
                        ui.is_enabled(),
                        egui::Button::new(format!("Use base {}", base.label)),
                    )
                    .clicked()
            {
                self.switch = Some(base.id.clone());
            }
        });
    }

    /// The arm64 VM boots UEFI: its base supports it and AAVMF is here.
    fn uefi(&self) -> bool {
        self.base.uefi && self.host.ovmf.is_ok()
    }

    /// The top of the window: every setting that will not be applied, where it
    /// is not hidden in a closed section.
    fn summary(&self, ui: &mut egui::Ui) {
        if self.fallbacks.is_empty() {
            return;
        }
        let count = self.fallbacks.len();
        if count == 1 {
            crate::activity::warning(
                ui,
                format!(
                    "1 setting will not be applied as chosen:\n• {}",
                    self.fallbacks[0].summary
                ),
            );
            return;
        }
        egui::CollapsingHeader::new(
            RichText::new(format!(
                "{count} setting{} will not be applied as chosen",
                if count == 1 { "" } else { "s" }
            ))
            .color(theme::warn()),
        )
        .id_salt("vm_stealth_fallbacks")
        .default_open(false)
        .show(ui, |ui| {
            for fallback in &self.fallbacks {
                ui.colored_label(theme::warn(), format!("• {}", fallback.summary));
            }
        });
    }
}

/// The row in the VM dialog: the preset and the window.
pub(super) fn preset_row(
    ui: &mut egui::Ui,
    profile: &mut StealthProfile,
    open: &mut bool,
    fallbacks: &[Fallback],
    details_label: &str,
    arch: GuestArch,
) {
    // The provider's list has a row of its own, so the form keeps the width
    // of one list whichever profile is chosen.
    ui.horizontal_wrapped(|ui| {
        ui.label("Device profile");
        help(
            ui,
            "Could be helpful for handling anti-VM or anti-sandbox checks.",
        );
    });
    preset_list(ui, profile, "vm_stealth_preset", arch);
    ui.end_row();
    if profile.preset == StealthPreset::CloudVps {
        ui.label("");
        provider_list(ui, profile, "vm_stealth_preset", arch);
        ui.end_row();
    }
    ui.label("");
    ui.horizontal_wrapped(|ui| {
        ui.weak(profile.preset.description());
        if crate::widgets::with_help(
            ui,
            "Machine identity, CPU, network card and devices",
            |ui| ui.button(details_label),
        )
        .clicked()
        {
            *open = !*open;
        }
        if !fallbacks.is_empty() {
            ui.colored_label(
                theme::warn(),
                format!(
                    "{} {} {}",
                    egui_phosphor::regular::WARNING,
                    fallbacks.len(),
                    if fallbacks.len() == 1 {
                        "setting falls back"
                    } else {
                        "settings fall back"
                    }
                ),
            );
            help(
                ui,
                fallbacks
                    .iter()
                    .map(|fallback| format!("- {}", fallback.summary))
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
        }
    });
    ui.end_row();
}

/// A muted note that wraps at the width it has (outside a grid: a grid cell
/// does not wrap, and a long note there widened the window to the screen's
/// edge, the arm64 one under Firmware and ACPI).
fn note(ui: &mut egui::Ui, text: &str) {
    // At most the window's opening width: wrapped at the scroll area's
    // width, the note still came out a scroll bar wider than the window.
    ui.scope(|ui| {
        ui.set_max_width(ui.available_width().min(NOTE_WIDTH));
        ui.add(egui::Label::new(RichText::new(text).color(theme::muted())).wrap());
    });
}

/// The widest a note in the window is laid out.
const NOTE_WIDTH: f32 = 440.0;

/// The window's content width when it opens, and its least.
const WINDOW_WIDTH: f32 = 520.0;

fn text_row(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.label(label);
    ui.add(egui::TextEdit::singleline(value).desired_width(crate::theme::plain_edit_width(260.0)));
    ui.end_row();
}

fn identity_fields(ui: &mut egui::Ui, identity: &mut MachineIdentity) {
    egui::Grid::new("vm_stealth_fields")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            text_row(ui, "BIOS vendor", &mut identity.bios_vendor);
            text_row(ui, "BIOS version", &mut identity.bios_version);
            text_row(ui, "BIOS date", &mut identity.bios_date);
            text_row(ui, "System maker", &mut identity.system_manufacturer);
            text_row(ui, "Product", &mut identity.system_product);
            text_row(ui, "Version", &mut identity.system_version);
            text_row(ui, "Family", &mut identity.system_family);
            text_row(ui, "SKU", &mut identity.system_sku);
            text_row(ui, "Serial", &mut identity.system_serial);
            text_row(ui, "UUID", &mut identity.system_uuid);
            text_row(ui, "Board maker", &mut identity.board_manufacturer);
            text_row(ui, "Board", &mut identity.board_product);
            text_row(ui, "Board serial", &mut identity.board_serial);
            text_row(ui, "Chassis serial", &mut identity.chassis_serial);
            text_row(ui, "Memory maker", &mut identity.memory_manufacturer);
            text_row(ui, "Memory part", &mut identity.memory_part);
            text_row(ui, "Memory serial", &mut identity.memory_serial);
        });
}

/// SMBIOS type 11 strings, one per line.
fn oem_strings(ui: &mut egui::Ui, identity: &mut MachineIdentity) {
    ui.label("OEM strings");
    let mut text = identity.oem_strings.join("\n");
    if crate::widgets::with_help(
        ui,
        "SMBIOS type 11, one string per line; PC firmware fills it, QEMU does not",
        |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut text)
                    .desired_rows(3)
                    .desired_width(crate::theme::plain_edit_width(260.0)),
            )
        },
    )
    .changed()
    {
        identity.oem_strings = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect();
    }
    ui.end_row();
}

fn hardware(ui: &mut egui::Ui, profile: &mut StealthProfile) {
    egui::Grid::new("vm_stealth_machine")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Machine");
            let current = if profile.identity_enabled {
                MACHINES
                    .iter()
                    .find(|machine| machine.id == profile.identity.profile)
                    .map(|machine| machine.label)
                    .or_else(|| profile.cloud_provider().map(|provider| provider.label))
                    .unwrap_or("Custom fields")
            } else {
                "QEMU default"
            };
            egui::ComboBox::from_id_salt("vm_stealth_machine_combo")
                .selected_text(current)
                .width(260.0)
                .truncate()
                .show_ui(ui, |ui| {
                    for machine in MACHINES {
                        let label = format!(
                            "{} ({})",
                            machine.label,
                            if machine.cpu_vendor == "AuthenticAMD" {
                                "AMD"
                            } else {
                                "Intel"
                            }
                        );
                        if ui
                            .selectable_label(
                                profile.identity_enabled && profile.identity.profile == machine.id,
                                label,
                            )
                            .clicked()
                        {
                            profile.use_machine(machine);
                        }
                    }
                    if ui
                        .selectable_label(!profile.identity_enabled, "QEMU default")
                        .clicked()
                    {
                        profile.identity_enabled = false;
                    }
                });
            ui.end_row();
            if !profile.identity_enabled {
                ui.label("");
                ui.label("No device profile: the guest looks like QEMU");
                ui.end_row();
            }
            if profile.identity_enabled {
                ui.label("Chassis");
                let chassis = chassis_label(profile.identity.chassis_type);
                egui::ComboBox::from_id_salt("vm_stealth_chassis")
                    .selected_text(chassis)
                    .width(260.0)
                    .truncate()
                    .show_ui(ui, |ui| {
                        for (kind, label) in CHASSIS {
                            ui.selectable_value(&mut profile.identity.chassis_type, *kind, *label);
                        }
                    });
                ui.end_row();
                text_row(ui, "Serial", &mut profile.identity.system_serial);
            }
        });
    if profile.identity_enabled {
        ui.horizontal(|ui| {
            if crate::widgets::with_help(
                ui,
                "New serials, UUID, disk serial and MAC address",
                |ui| ui.button("Randomize serials"),
            )
            .clicked()
            {
                profile.identity.rerandomize();
                profile.new_mac();
            }
        });
        let host = host_cpu_vendor();
        if let Some(machine) = MACHINES
            .iter()
            .find(|machine| machine.id == profile.identity.profile)
        {
            if !host.is_empty() && machine.cpu_vendor != host && profile.cpu_passthrough {
                ui.colored_label(
                    theme::warn(),
                    "This machine never shipped with the host's CPU vendor, which passthrough shows.",
                );
            }
        }
        egui::CollapsingHeader::new("Edit fields…")
            .id_salt("vm_stealth_edit_fields")
            .show(ui, |ui| identity_fields(ui, &mut profile.identity));
    }
}

fn firmware(ui: &mut egui::Ui, profile: &mut StealthProfile, fit: &mut Fit) {
    let base = fit.base;
    if fit.arm64() {
        ui.horizontal(|ui| {
            ui.label("Firmware");
            choice(
                ui,
                "vm_stealth_firmware_kind",
                &mut profile.firmware,
                Firmware::ALL,
                Firmware::label,
                |firmware| firmware_unavailable(firmware, &base, fit.host),
            );
        });
        fit.line(ui, profile, FallbackSetting::Firmware);
        // The machine's own tables replace the PC fields and devices. Below
        // the row, where it wraps at the window's width (in a grid cell it
        // widened the window to the screen's edge).
        note(
            ui,
            "On arm64, UEFI is AAVMF and BIOS boots the kernel on a device tree. \
             The machine's ACPI IDs and SMBIOS tables are filled from the catalog; \
             the PC devices (HPET, VMware port, ICH9 USB, SMM) do not apply.",
        );
        return;
    }
    // The two grids share their label column's width, so their rows line up.
    let labels = 110.0;
    egui::Grid::new("vm_stealth_firmware")
        .num_columns(2)
        .min_col_width(labels)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Firmware");
            choice(
                ui,
                "vm_stealth_firmware_kind",
                &mut profile.firmware,
                Firmware::ALL,
                Firmware::label,
                |firmware| firmware_unavailable(firmware, &base, fit.host),
            );
            ui.end_row();
            fit.row(ui, profile, FallbackSetting::Firmware);
        });
    // Below the grid, where it wraps at the window's width.
    if profile.firmware == Firmware::UefiSecureBoot {
        note(
            ui,
            "OVMF finds the kernel unsigned and starts it with its legacy loader; \
             the guest sees Secure Boot on",
        );
    }
    egui::Grid::new("vm_stealth_firmware_tables")
        .num_columns(2)
        .min_col_width(labels)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            if profile.identity_enabled {
                text_row(ui, "ACPI OEM ID", &mut profile.identity.acpi_oem_id);
                text_row(ui, "ACPI table ID", &mut profile.identity.acpi_table_id);
                ui.label("SMBIOS entry");
                ui.horizontal(|ui| {
                    ui.radio_value(
                        &mut profile.smbios_entry,
                        SmbiosEntry::Bits64,
                        "64-bit (3.x)",
                    );
                    ui.radio_value(
                        &mut profile.smbios_entry,
                        SmbiosEntry::Bits32,
                        "32-bit (2.x)",
                    );
                });
                ui.end_row();
                oem_strings(ui, &mut profile.identity);
            }
            ui.label("Devices");
            ui.checkbox(&mut profile.hpet, "HPET timer");
            ui.end_row();
            ui.label("");
            crate::widgets::with_help(ui, "Only VMware VMs have it; real PCs do not", |ui| {
                ui.checkbox(&mut profile.vmport, "VMware backdoor port")
            });
            ui.end_row();
            ui.label("");
            crate::widgets::with_help(ui, "Every PC has USB; QEMU adds none by default", |ui| {
                ui.checkbox(&mut profile.usb, "Intel ICH9 USB controllers")
            });
            ui.end_row();
            ui.label("");
            let secure_boot = profile.firmware == Firmware::UefiSecureBoot;
            let mut smm = profile.smm || secure_boot;
            let editable = ui.is_enabled();
            crate::widgets::with_help_or(
                ui,
                "PCs have SMM; Secure Boot firmware needs it",
                if editable {
                    "Secure Boot firmware keeps its variables in SMM"
                } else {
                    ""
                },
                |ui| {
                    ui.add_enabled(
                        !secure_boot,
                        egui::Checkbox::new(&mut smm, "System management mode"),
                    )
                },
            );
            if !secure_boot {
                profile.smm = smm;
            }
            ui.end_row();
        });
}

fn cpu(ui: &mut egui::Ui, profile: &mut StealthProfile, fit: &mut Fit) {
    if fit.arm64() {
        arm64::cpu(ui, profile, fit.uefi());
        return;
    }
    crate::widgets::with_help(
        ui,
        "Needs KVM; without it the model is named after the host CPU",
        |ui| {
            ui.checkbox(
                &mut profile.cpu_passthrough,
                "Pass the host CPU through (its real name and features)",
            )
        },
    );
    if !profile.cpu_passthrough {
        egui::Grid::new("vm_stealth_cpu_model")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.label("Model");
                let host = host_cpu_vendor();
                let current = if profile.cpu_model.is_empty() {
                    "The VM's CPU model setting".to_owned()
                } else {
                    profile.cpu_model.clone()
                };
                egui::ComboBox::from_id_salt("vm_stealth_cpu_named")
                    .selected_text(current)
                    .width(260.0)
                    .truncate()
                    .show_ui(ui, |ui| {
                        if ui
                            .selectable_label(
                                profile.cpu_model.is_empty(),
                                "The VM's CPU model setting",
                            )
                            .clicked()
                        {
                            profile.cpu_model.clear();
                            profile.cpu_brand.clear();
                        }
                        for model in CPU_MODELS
                            .iter()
                            .filter(|model| host.is_empty() || model.cpu_vendor == host)
                        {
                            if crate::widgets::with_help(ui, model.brand, |ui| {
                                ui.selectable_label(profile.cpu_model == model.model, model.model)
                            })
                            .clicked()
                            {
                                profile.cpu_model = model.model.into();
                                profile.cpu_brand = model.brand.into();
                            }
                        }
                    });
                ui.end_row();
                text_row(ui, "Brand string", &mut profile.cpu_brand);
                ui.label("");
                crate::widgets::with_help(
                    ui,
                    "Its real cache layout and an L3 instead of QEMU's legacy one",
                    |ui| {
                        ui.add_enabled(
                            !profile.cpu_model.is_empty(),
                            egui::Checkbox::new(
                                &mut profile.model_cache_info,
                                "The model's own caches",
                            ),
                        )
                    },
                );
                ui.end_row();
            });
    }
    ui.checkbox(&mut profile.hide_hypervisor, "Hide the hypervisor CPU flag");
    crate::widgets::with_help(
        ui,
        "The guest then uses its TSC instead of kvm-clock: a small timekeeping cost",
        |ui| ui.checkbox(&mut profile.hide_kvm, "Hide the KVM signature"),
    );
    let editable = ui.is_enabled();
    crate::widgets::with_help_or(
        ui,
        "The guest's clock source while the KVM signature is shown",
        if editable {
            "Hiding the KVM signature also hides kvm-clock"
        } else {
            ""
        },
        |ui| {
            ui.add_enabled(
                !profile.hide_kvm,
                egui::Checkbox::new(&mut profile.kvm_clock, "kvm-clock"),
            )
        },
    );
    ui.checkbox(&mut profile.pmu, "Performance counters");
    ui.checkbox(&mut profile.realistic_topology, "One socket with N cores");
    let smt = &fit.host.smt;
    let reason = match (editable, smt) {
        (false, _) => String::new(),
        (true, Err(reason)) => reason.clone(),
        (true, Ok(())) => "Needs one socket with N cores".to_owned(),
    };
    let usable = profile.realistic_topology && smt.is_ok();
    crate::widgets::with_help_or(
        ui,
        "As a CPU with SMT: N/2 cores of two threads (an even CPU count)",
        reason,
        |ui| {
            ui.add_enabled(
                usable,
                egui::Checkbox::new(&mut profile.smt, "Two threads per core"),
            )
        },
    );
    fit.line(ui, profile, FallbackSetting::Smt);
    crate::widgets::with_help(
        ui,
        "QEMU otherwise reports its own cache sizes; passthrough only",
        |ui| {
            ui.add_enabled(
                profile.cpu_passthrough,
                egui::Checkbox::new(&mut profile.host_cache_info, "The host's cache sizes"),
            )
        },
    );
}

fn network(ui: &mut egui::Ui, profile: &mut StealthProfile, fit: &mut Fit) {
    egui::Grid::new("vm_stealth_network")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Card");
            let before = profile.nic;
            egui::ComboBox::from_id_salt("vm_stealth_nic")
                .selected_text(profile.nic.label())
                .width(260.0)
                .truncate()
                .show_ui(ui, |ui| {
                    for &nic in NicModel::ALL {
                        ui.selectable_value(&mut profile.nic, nic, nic.label());
                    }
                });
            if profile.nic != before && !profile.mac.is_empty() {
                profile.new_mac();
            }
            ui.end_row();
            ui.label("MAC address");
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut profile.mac)
                        .desired_width(crate::theme::plain_edit_width(150.0))
                        .hint_text(crate::theme::placeholder(ui, "52:54:00:12:34:56")),
                );
                if crate::widgets::with_help(
                    ui,
                    "A random address with the card's vendor prefix",
                    |ui| ui.button("Random"),
                )
                .clicked()
                {
                    profile.new_mac();
                }
                if crate::widgets::with_help(
                    ui,
                    "A random locally administered address, which names no vendor",
                    |ui| ui.button("Local"),
                )
                .clicked()
                {
                    profile.new_local_mac();
                }
                if ui.button("QEMU default").clicked() {
                    profile.mac.clear();
                }
            });
            ui.end_row();
        });
    ui.colored_label(
        theme::muted(),
        "A network card exists only when the VM's network is Isolated, NAT or Routed. The guest network applies to NAT and Routed.",
    );
    egui::Grid::new("vm_stealth_nat")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            if profile.identity_enabled && profile.nic == NicModel::E1000e {
                ui.label("Card subsystem");
                crate::widgets::with_help(
                    ui,
                    "A board's own card carries its maker's PCI subsystem IDs",
                    |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut profile.identity.nic_subsystem)
                                .desired_width(crate::theme::plain_edit_width(150.0))
                                .hint_text(crate::theme::placeholder(ui, "8086:0000")),
                        )
                    },
                );
                ui.end_row();
            }
            ui.label("Guest network");
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut profile.nat.network)
                        .desired_width(crate::theme::plain_edit_width(150.0))
                        .hint_text(crate::theme::placeholder(ui, "10.0.2.0/24")),
                );
                if crate::widgets::with_help(ui, "192.168.1.0/24 behind a router at .1", |ui| {
                    ui.button("Home")
                })
                .clicked()
                {
                    profile.nat = NatNetwork::home();
                }
                if crate::widgets::with_help(
                    ui,
                    "10.0.2.0/24, which QEMU and VirtualBox share",
                    |ui| ui.button("QEMU default"),
                )
                .clicked()
                {
                    profile.nat = NatNetwork::default();
                }
            });
            ui.end_row();
            if !profile.nat.network.is_empty() {
                text_row(ui, "Gateway", &mut profile.nat.gateway);
                text_row(ui, "DNS server", &mut profile.nat.dns);
                text_row(ui, "DHCP start", &mut profile.nat.dhcp_start);
                fit.row(ui, profile, FallbackSetting::Nat);
            }
        });
    if !profile.nat.network.is_empty() {
        ui.colored_label(
            theme::muted(),
            "The guest learns them by DHCP. QEMU needs the DNS server apart from the gateway; \
             an isolated VM's guest uses the gateway for both.",
        );
    }
}

fn storage(ui: &mut egui::Ui, profile: &mut StealthProfile, fit: &mut Fit) {
    let base = fit.base;
    egui::Grid::new("vm_stealth_storage")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Disk bus");
            choice(
                ui,
                "vm_stealth_disk_bus",
                &mut profile.disk_bus,
                DiskBus::ALL,
                DiskBus::label,
                |bus| disk_bus_unavailable(bus, &base).map(str::to_owned),
            );
            ui.end_row();
            fit.row(ui, profile, FallbackSetting::DiskBus);
            if profile.disk_bus == DiskBus::Sata {
                ui.label("Disk kind");
                ui.horizontal(|ui| {
                    ui.radio_value(&mut profile.disk_media, DiskMedia::Ssd, "SSD");
                    ui.radio_value(
                        &mut profile.disk_media,
                        DiskMedia::Hdd,
                        "Hard disk (7,200 rpm)",
                    );
                });
                ui.end_row();
            }
            if profile.identity_enabled {
                if profile.disk_bus == DiskBus::Sata {
                    text_row(ui, "Disk model", &mut profile.identity.disk_model);
                    text_row(ui, "Disk firmware", &mut profile.identity.disk_firmware);
                    text_row(ui, "Disk WWN", &mut profile.identity.disk_wwn);
                }
                text_row(ui, "Disk serial", &mut profile.identity.disk_serial);
            }
            ui.label("CD-ROM");
            crate::widgets::with_help(
                ui,
                "Desktops with an optical drive have one; QEMU's answers \
                     \"QEMU DVD-ROM\" to the SCSI inquiry whatever its model",
                |ui| ui.checkbox(&mut profile.cdrom, "An empty SATA CD-ROM drive"),
            );
            ui.end_row();
            if profile.identity_enabled && profile.cdrom {
                text_row(ui, "CD-ROM model", &mut profile.identity.cdrom_model);
            }
        });
    if profile.disk_bus == DiskBus::Nvme {
        ui.colored_label(
            theme::muted(),
            "QEMU's NVMe controller names itself \"QEMU NVMe Ctrl\" with QEMU's version as \
             firmware and an org.qemu subsystem name; only its serial and PCI vendor (Intel's) \
             can be set.",
        );
    }
    ui.colored_label(
        theme::muted(),
        "The disk's size is the VM's (pafish flags under 60 GiB).",
    );
}

fn display(ui: &mut egui::Ui, profile: &mut StealthProfile, fit: &mut Fit) {
    let editable = ui.is_enabled();
    ui.label("Pointer");
    for &pointer in Pointer::ALL {
        let usable = pointer != Pointer::UsbTablet || profile.usb;
        ui.add_enabled_ui(usable, |ui| {
            let response = ui.radio_value(&mut profile.pointer, pointer, pointer.label());
            if editable {
                response.reason_tip("Needs the Intel ICH9 USB controllers");
            }
            ui.label(RichText::new(pointer.cost()).small().color(theme::muted()));
        });
    }
    fit.line(ui, profile, FallbackSetting::Pointer);
    ui.add_space(4.0);
    ui.colored_label(
        theme::muted(),
        "Display: virtio-gpu when the VM has a fixed resolution (Antinomie sizes its window \
         through it), QEMU's standard VGA otherwise. Both name a VM vendor.",
    );
}

fn clock(ui: &mut egui::Ui, profile: &mut StealthProfile, fit: &mut Fit) {
    uptime(ui, profile, fit.debian(), fit.view.arch);
    fit.line(ui, profile, FallbackSetting::Uptime);
    ui.add_space(4.0);
    crate::widgets::with_help(
        ui,
        "Linux PCs keep it in UTC and Linux guests read it as UTC; Windows PCs in local time",
        |ui| ui.checkbox(&mut profile.rtc_localtime, "Real-time clock in local time"),
    );
    ui.horizontal(|ui| {
        ui.label("Driven by");
        crate::widgets::with_help(ui, "Wall time goes on while the VM is paused", |ui| {
            ui.radio_value(&mut profile.rtc_clock, RtcClock::Host, "the host's clock")
        });
        crate::widgets::with_help(
            ui,
            "Stops while the VM is paused, as if it had been off",
            |ui| ui.radio_value(&mut profile.rtc_clock, RtcClock::Vm, "the VM's clock"),
        );
    });
    crate::widgets::with_help(
        ui,
        "For guests that count RTC interrupts (Windows); Linux does not need it",
        |ui| ui.checkbox(&mut profile.rtc_driftfix, "Catch up on missed clock ticks"),
    );
}

/// A preset applied this frame stays that preset; any other edit is Custom.
/// The uptime is not one of those edits: each preset draws one per VM, and a
/// typed or redrawn one keeps the machine the preset made (and its range).
pub(super) fn settle_preset(before: &StealthProfile, profile: &mut StealthProfile) {
    let mut other = profile.clone();
    other.boot_age_s = before.boot_age_s;
    if other != *before
        && profile.preset == before.preset
        && profile.preset != StealthPreset::Custom
    {
        profile.preset = StealthPreset::Custom;
    }
}

/// The VM's size, which the Still visible list reads against the profile.
#[derive(Clone, Copy)]
pub(super) struct VmSize {
    pub cpus: u16,
    pub ram_mib: u32,
    pub disk_gib: u32,
}

impl VmSize {
    pub(super) fn of(vm: &VmConfig) -> Self {
        Self {
            cpus: vm.cpus,
            ram_mib: vm.ram_mib,
            disk_gib: vm.disk_gib,
        }
    }
}

/// The Device profile window beside the VM dialog.
pub(super) fn window(
    ctx: &egui::Context,
    open: &mut bool,
    profile: &mut StealthProfile,
    fit: &mut Fit,
    size: VmSize,
    editable: bool,
    creating: bool,
) {
    let mut closed = false;
    crate::widgets::window("Device profile")
        .id(egui::Id::new("vm_stealth"))
        .pivot(egui::Align2::CENTER_TOP)
        .default_pos(egui::pos2(ctx.content_rect().center().x, 60.0))
        .open(open)
        .collapsible(false)
        .resizable(true)
        .default_width(WINDOW_WIDTH)
        // Never narrower than it opens: the widest section (Firmware and
        // ACPI's fields) fits, so opening one does not widen the window.
        .min_width(WINDOW_WIDTH)
        .max_height((ctx.content_rect().height() - 100.0).max(200.0))
        .show(ctx, |ui| {
            let before = profile.clone();
            // Read-only (a running VM): the entries are disabled, but the
            // sections still open and their hints still show.
            ui.add_enabled_ui(editable, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Preset");
                    preset_combo(ui, profile, "vm_stealth_window_preset", fit.view.arch);
                });
            });
            fit.iot_base(ui, profile);
            fit.summary(ui);
            egui::ScrollArea::vertical()
                .id_salt("vm_stealth_scroll")
                // The bar's room is kept whether the list scrolls or not: a
                // section that made it scroll widened the window by the bar.
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                .max_height((ctx.content_rect().height() - 330.0).max(120.0))
                .show_contained(ui, |ui| {
                    let section = |ui: &mut egui::Ui, add: &mut dyn FnMut(&mut egui::Ui)| {
                        ui.add_enabled_ui(editable, |ui| add(ui));
                    };
                    egui::CollapsingHeader::new("Hardware identity")
                        .default_open(true)
                        .show(ui, |ui| {
                            section(ui, &mut |ui| {
                                if fit.arm64() {
                                    arm64::hardware(ui, profile, fit.uefi());
                                } else {
                                    hardware(ui, profile);
                                }
                            })
                        });
                    egui::CollapsingHeader::new("Firmware and ACPI").show(ui, |ui| {
                        section(ui, &mut |ui| firmware(ui, profile, fit));
                    });
                    egui::CollapsingHeader::new("CPU").show(ui, |ui| {
                        section(ui, &mut |ui| cpu(ui, profile, fit));
                    });
                    egui::CollapsingHeader::new("Network").show(ui, |ui| {
                        section(ui, &mut |ui| network(ui, profile, fit));
                    });
                    egui::CollapsingHeader::new("Storage and devices").show(ui, |ui| {
                        section(ui, &mut |ui| {
                            storage(ui, profile, fit);
                            ui.add_space(6.0);
                            display(ui, profile, fit);
                        });
                    });
                    egui::CollapsingHeader::new("Clock").show(ui, |ui| {
                        section(ui, &mut |ui| clock(ui, profile, fit));
                    });
                    egui::CollapsingHeader::new("Still visible")
                        .show(ui, |ui| fit.still_visible(ui, profile, size));
                });
            settle_preset(&before, profile);
            if let Err(error) = profile.validate() {
                ui.colored_label(theme::error(), error);
            }
            if !editable {
                crate::activity::info(ui, "Stop the VM to change its hardware.");
            } else if !creating {
                crate::activity::warning(
                    ui,
                    "Snapshots saved with other hardware may not restore after a change.",
                );
            }
            let mut close = false;
            dialog_footer(ui, |ui| {
                close = ui.button("Done").clicked();
                ui.label(
                    RichText::new("Save the VM configuration to apply.").color(theme::muted()),
                );
            });
            closed = close;
        });
    if closed {
        *open = false;
    }
}
