// SPDX-License-Identifier: GPL-3.0-only
use crate::{
    api::{BackendOptions, VmConfig, VmCpuModel, VmLaunchOptions, VmNetwork},
    storage::{Bundle, private_dir, unique_id, vm_dir},
};
use rustix::fs::MemfdFlags;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::{fs::OpenOptionsExt, net::UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

/// The i440FX machine type lays guest RAM out like q35 only below 0xb0000000
/// bytes, which is all the transport's address translation knows
/// ([`RamLayout`]); a larger VM keeps q35. Returns the start log line when
/// the profile's machine type was changed.
fn effective_machine(
    stealth: &mut crate::stealth::StealthProfile,
    ram_size: u64,
) -> Option<String> {
    let (machine, note) = stealth.machine.for_ram(ram_size);
    stealth.machine = machine;
    note.map(|note| format!("Device profile setting not applied: {note}"))
}

/// The QEMU user-mode network of a VM. A Routed VM has none: its card is
/// wired to the route gateway instead.
fn user_network_backend(vm: &VmConfig) -> Option<&'static str> {
    match vm.network() {
        VmNetwork::Isolated => Some("user,id=net0,restrict=on"),
        VmNetwork::Nat => Some("user,id=net0"),
        VmNetwork::Routed | VmNetwork::Disconnected => None,
    }
}

/// What a full-snapshot identity adds for the network: nothing for NAT and
/// Disconnected, which older checkpoints were taken with.
fn network_identity_key(vm: &VmConfig) -> Option<&'static str> {
    if vm.isolated_network {
        Some("isolated_network")
    } else if vm.routed {
        Some("routed")
    } else {
        None
    }
}

struct UnstartedRuntime {
    path: PathBuf,
    started: bool,
}
impl Drop for UnstartedRuntime {
    fn drop(&mut self) {
        if !self.started {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
mod machine;
mod qmp;
mod state_transfer;
pub(crate) use machine::*;
use qmp::*;
mod virt;
/// Delete guest RAM files that no process holds open: an app that exits
/// without stopping its VM leaves `runtime/<run>/shared-ram` behind, several
/// GiB each. A running VM's QEMU keeps its file open, so it is kept.
pub(crate) fn remove_stale_guest_ram(options: &BackendOptions, vm_ids: &[&str]) -> u64 {
    let open: std::collections::HashSet<PathBuf> = std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|process| std::fs::read_dir(process.path().join("fd")).ok())
        .flat_map(|fds| {
            fds.flatten()
                .filter_map(|fd| std::fs::read_link(fd.path()).ok())
        })
        .collect();
    let mut freed = 0;
    for id in vm_ids {
        let Ok(runtime) = vm_dir(options, id)
            .and_then(|dir| std::fs::canonicalize(dir.join("runtime")).map_err(|e| e.to_string()))
        else {
            continue;
        };
        for run in std::fs::read_dir(runtime).into_iter().flatten().flatten() {
            let ram = run.path().join("shared-ram");
            if let Ok(metadata) = std::fs::symlink_metadata(&ram)
                && metadata.is_file()
                && !open.contains(&ram)
                && std::fs::remove_file(&ram).is_ok()
            {
                freed += std::os::unix::fs::MetadataExt::blocks(&metadata) * 512;
            }
        }
    }
    freed
}
/// Create guest RAM. It lives in memory (a memfd that QEMU and the transport
/// open through /proc) unless `ANTINOMIE_GUEST_RAM=file` or it would not fit
/// in half of memory plus swap. A file on the data disk works too, but the
/// host then writes guest memory back to disk, which stalls the guest and the
/// telemetry drain.
fn guest_ram(file: PathBuf, size: u64) -> Result<(PathBuf, Option<OwnedFd>), String> {
    let room = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .map(|meminfo| {
            meminfo
                .lines()
                .filter(|line| line.starts_with("MemTotal:") || line.starts_with("SwapTotal:"))
                .filter_map(|line| line.split_whitespace().nth(1)?.parse::<u64>().ok())
                .sum::<u64>()
                * 1024
        })
        .unwrap_or(0);
    if std::env::var("ANTINOMIE_GUEST_RAM").as_deref() != Ok("file")
        && size <= room / 2
        && let Ok(memory) = rustix::fs::memfd_create("antinomie-guest-ram", MemfdFlags::CLOEXEC)
        && rustix::fs::ftruncate(&memory, size).is_ok()
    {
        let path = PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            memory.as_raw_fd()
        ));
        return Ok((path, Some(memory)));
    }
    let ram = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&file)
        .map_err(|e| e.to_string())?;
    ram.set_len(size).map_err(|e| e.to_string())?;
    Ok((file, None))
}
fn qemu_path(path: &Path) -> Result<String, String> {
    Ok(path
        .to_str()
        .ok_or("QEMU composite paths must be UTF-8")?
        .replace(',', ",,"))
}
/// Whether the VM gets QEMU's VNC display for the in-app screen tab; QEMU's
/// own window and No screen run with `-display` alone.
fn in_app_screen(options: &BackendOptions, launch: &VmLaunchOptions) -> bool {
    !options.headless && launch.screen == crate::api::VmScreen::InApp
}
fn initial_size(options: &BackendOptions, launch: &VmLaunchOptions) -> Option<(u16, u16)> {
    (!options.headless
        && launch.screen == crate::api::VmScreen::QemuWindow
        && !launch.fullscreen
        && launch.fit_to_window)
        .then(|| launch.resolution.dimensions())
        .flatten()
}

/// The kernel command line for one VM's disk: a base that names its root by
/// filesystem UUID (`root=UUID=`, Debian Minimal) names the UUID provisioning
/// gave this VM's disk; a disk provisioned before that keeps the base's.
pub(crate) fn vm_kernel_append(append: &str, root_uuid: Option<&str>) -> String {
    let Some(uuid) = root_uuid else {
        return append.to_owned();
    };
    append
        .split(' ')
        .map(|word| {
            if word.starts_with("root=UUID=") {
                format!("root=UUID={uuid}")
            } else {
                word.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[allow(clippy::too_many_arguments)]
fn apply_launch_settings(
    command: &mut Command,
    options: &BackendOptions,
    launch: &VmLaunchOptions,
    accel: &crate::accel::Choice,
    stealth: &crate::stealth::StealthProfile,
    cpus: u16,
    bundle: &Bundle,
    bootstrap: u64,
) -> Result<(), String> {
    launch.validate_for(options)?;
    let acceleration = accel.accelerator.qemu_name();
    command.args(["-accel", acceleration]);
    let cpu = match launch.cpu_model {
        VmCpuModel::Default => None,
        VmCpuModel::Qemu64 => Some("qemu64"),
        VmCpuModel::Host => Some("host"),
        VmCpuModel::Max => Some("max"),
    };
    // Hiding the hypervisor needs a model to add flags to; QEMU's default
    // model is named after QEMU, so a profile that hides it brings its own.
    let base = cpu.or((stealth.hide_hypervisor || stealth.pmu).then_some("max"));
    if let Some(cpu) = crate::stealth::cpu_option(stealth, base, acceleration == "kvm", cpus) {
        command.arg("-cpu").arg(cpu);
    }
    let mut append = format!(
        "{} antinomie_boot_gpa=0x{bootstrap:x}",
        bundle.kernel_append
    );
    // The VM's boot age, as the profile fitted to the base keeps it (0 on a
    // base whose kernel does not take it). The guest takes antinomie_*
    // options out of its command line before anything can read it.
    if stealth.boot_age_s > 0 {
        append.push_str(&format!(
            " antinomie_boot_age={}:{}",
            stealth.boot_age_s,
            stealth.boot_clock(bundle.runs_debian_modules())
        ));
    }
    if let Some((width, height)) = launch.resolution.dimensions() {
        // virtio-gpu provides a hardware cursor, so the guest does not paint
        // its own cursor into the framebuffer. The fixed mode is selected by
        // video=Virtual-1:WxH; the virtio-gpu DRM logs a user-defined-mode
        // notice but the mode applies (the EDID alone leaves 640x480).
        command.args(["-vga", "none", "-device"]);
        command.arg(format!("virtio-gpu-pci,edid=on,xres={width},yres={height}"));
        append.push_str(&format!(" video=Virtual-1:{width}x{height}"));
    } else if bundle.guest.as_ref().is_some_and(|guest| guest.graphical) {
        command.args(["-vga", "virtio"]);
    }
    command.arg("-append").arg(append);
    // The VNC display of the in-app screen is added by the launch, which
    // knows its socket; the guest sees the same devices in every mode.
    let window = !options.headless && launch.screen == crate::api::VmScreen::QemuWindow;
    let mut display = if window { "gtk" } else { "none" }.to_owned();
    if window {
        if launch.fullscreen {
            display.push_str(",full-screen=on");
        }
        if launch.fit_to_window {
            display.push_str(",zoom-to-fit=on");
        } else {
            display.push_str(",zoom-to-fit=off");
        }
        if initial_size(options, launch).is_some() {
            display.push_str(",show-menubar=off,show-tabs=off");
            command.env("GDK_BACKEND", "x11");
        }
    }
    if !options.headless {
        // An absolute pointer keeps the GTK display from grabbing and
        // recentering the host cursor. The guest kernel already binds
        // CONFIG_VIRTIO_INPUT, so no additional controller is required; the
        // profile may choose the USB tablet or only the PS/2 mouse instead.
        command.args(crate::stealth::pointer_args(stealth));
    }
    command.arg("-display").arg(display);
    Ok(())
}

/// The accelerator of a launch on `machine`: an arm64 VM runs under TCG on
/// every host (no KVM for a foreign architecture), an x86-64 one as
/// [`crate::accel::choose`] decides.
fn launch_accel(
    options: &BackendOptions,
    launch: &VmLaunchOptions,
    machine: Machine,
) -> Result<crate::accel::Choice, String> {
    if machine == Machine::Virt {
        return Ok(crate::accel::Choice {
            accelerator: crate::accel::Accelerator::Tcg,
            fallback: None,
        });
    }
    crate::accel::choose(options, launch)
}

pub(crate) struct VmProcess {
    pub child: Child,
    pub ram_path: PathBuf,
    /// Keeps in-memory guest RAM alive; `ram_path` then names it through /proc.
    _ram_memory: Option<OwnedFd>,
    pub runtime_dir: PathBuf,
    pub bootstrap: u64,
    /// Where QEMU maps the RAM file on this VM's machine.
    pub ram_layout: RamLayout,
    pub machine: Machine,
    pub qmp_path: PathBuf,
    /// The private unix socket of QEMU's VNC display, when the VM's screen
    /// shows in the app.
    pub screen_socket: Option<PathBuf>,
    /// The route gateway of a Routed VM; it ends with the process.
    pub gateway: Option<crate::route::Gateway>,
    /// Folder holding the gateway's socket when it is not in `runtime_dir`
    /// (the path would be too long for a socket); removed on drop.
    net_dir: Option<PathBuf>,
    /// What the device profile asked for and the base or host could not give,
    /// one line each, for the start log and the run notes.
    pub stealth_fallbacks: Vec<String>,
    /// The accelerator this process runs with, and why it is TCG when KVM was
    /// wanted.
    pub accel: crate::accel::Choice,
    /// The waits of this process, scaled for its accelerator and the host load.
    pub waits: crate::accel::Waits,
}
/// The QEMU command. Through util-linux `setpriv`, when installed, QEMU gets
/// SIGKILL if the app dies, instead of running on with the VM's disk locked
/// (the next Start would then fail on that lock).
/// The `-name` value: an explicit `guest=` so a name holding `=` is not read
/// as a sub-option, and commas doubled like every QEMU option value.
fn name_option(name: &str) -> String {
    format!("guest={}", crate::stealth::escape(name))
}

pub(crate) fn qemu_command(qemu: &Path) -> Command {
    match crate::dependencies::executable(Path::new("setpriv")) {
        Some(setpriv) => {
            let mut command = Command::new(setpriv);
            command.args(["--pdeathsig", "KILL", "--"]).arg(qemu);
            command
        }
        None => Command::new(qemu),
    }
}

/// The end of `qemu.log`, where QEMU says why it stopped (for example that
/// another process holds the disk's write lock).
fn qemu_log_hint(runtime_dir: &Path) -> String {
    const TAIL: u64 = 2048;
    let Ok(mut file) = File::open(runtime_dir.join("qemu.log")) else {
        return String::new();
    };
    let len = file.metadata().map_or(0, |metadata| metadata.len());
    let _ = file.seek(SeekFrom::Start(len.saturating_sub(TAIL)));
    let mut tail = String::new();
    let _ = file.take(TAIL).read_to_string(&mut tail);
    match tail.lines().rev().find(|line| !line.trim().is_empty()) {
        Some(line) => format!("; QEMU said: {}", line.trim()),
        None => String::new(),
    }
}

/// Whether the first word of the bootstrap page at `bootstrap` in the RAM file
/// is nonzero. The page lies in the RAM region that contains its address.
fn bootstrap_magic_written(ram_path: &Path, layout: &RamLayout, bootstrap: u64) -> bool {
    use std::os::unix::fs::FileExt;
    let Some(offset) = layout
        .expected()
        .into_iter()
        .find(|&(gpa, size, _)| bootstrap >= gpa && bootstrap - gpa < size)
        .map(|(gpa, _, offset)| offset + (bootstrap - gpa))
    else {
        return false;
    };
    let mut magic = [0u8; 4];
    File::open(ram_path)
        .and_then(|file| file.read_exact_at(&mut magic, offset))
        .is_ok()
        && magic != [0; 4]
}

/// The one-minute load average, for messages.
pub(crate) fn host_load() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|text| text.split_whitespace().next().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

/// Why a start is slow and what the user can do about it, for the end of a
/// timeout message; empty at KVM speed on an idle host.
pub(crate) fn slow_hint(accel: &crate::accel::Choice, waits: &crate::accel::Waits) -> String {
    if accel.is_tcg() {
        format!(
            ". TCG is software emulation, 10 to 50 times slower than KVM, and a loaded host slows it more (waits are stretched {:.0} times now). Give it longer in Tools > Settings > Advanced > VM start and guest connection timeouts (TCG multiplier), reduce the load on this host, or use KVM",
            waits.factor()
        )
    } else {
        String::new()
    }
}

/// A QMP connection, past the greeting and capability negotiation.
pub(crate) mod keyboard;

impl VmProcess {
    /// What to add to a timeout message when the waits were stretched or ought
    /// to be: why it is slow and what to do.
    pub fn slow_hint(&self) -> String {
        slow_hint(&self.accel, &self.waits)
    }
    /// Whether the guest has published its transport bootstrap page: its
    /// first word is written last-but-not-least, so nonzero means the kernel
    /// reached the telemetry driver.
    pub fn bootstrap_published(&self) -> bool {
        bootstrap_magic_written(&self.ram_path, &self.ram_layout, self.bootstrap)
    }

    /// Waits until the guest publishes its transport, QEMU exits, or the
    /// scaled limit passes. `tick(elapsed, limit)` runs about once a second so
    /// the caller can show that a slow boot is being waited for (or cancel it
    /// by returning an error).
    pub fn wait_for_guest(
        &mut self,
        mut tick: impl FnMut(Duration, Duration) -> Result<(), String>,
    ) -> Result<(), String> {
        let limit = self.waits.guest_connect();
        let started = std::time::Instant::now();
        let mut last_tick = None::<std::time::Instant>;
        loop {
            if self.bootstrap_published() {
                return Ok(());
            }
            if let Some(status) = self.child.try_wait().map_err(|e| e.to_string())? {
                return Err(format!(
                    "QEMU exited ({status}) before the guest connected{}",
                    qemu_log_hint(&self.runtime_dir)
                ));
            }
            let elapsed = started.elapsed();
            if elapsed >= limit {
                let accelerator = if self.accel.is_tcg() {
                    "TCG software emulation"
                } else {
                    "KVM"
                };
                return Err(format!(
                    "the guest did not connect within {} s ({accelerator}; host load {}){}",
                    limit.as_secs(),
                    host_load(),
                    self.slow_hint()
                ));
            }
            if last_tick.is_none_or(|at| at.elapsed() >= Duration::from_secs(1)) {
                last_tick = Some(std::time::Instant::now());
                tick(elapsed, limit)?;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    pub fn launch(
        options: &BackendOptions,
        vm: &VmConfig,
        bundle: &Bundle,
    ) -> Result<Self, String> {
        let disk = crate::snapshots::active_disk(options, vm)?;
        Self::launch_disk(options, vm, bundle, &disk, false)
    }
    pub fn launch_incoming(
        options: &BackendOptions,
        vm: &VmConfig,
        bundle: &Bundle,
        disk: &Path,
    ) -> Result<Self, String> {
        Self::launch_disk(options, vm, bundle, disk, true)
    }
    fn launch_disk(
        options: &BackendOptions,
        vm: &VmConfig,
        bundle: &Bundle,
        disk: &Path,
        incoming: bool,
    ) -> Result<Self, String> {
        let machine = Machine::of(bundle.arch)?;
        machine.check_ram(vm.ram_mib)?;
        let qemu = machine.qemu(&options.qemu);
        let virt = machine == Machine::Virt;
        if !virt {
            vm.launch.validate_for(options)?;
        }
        let accel = launch_accel(options, &vm.launch, machine)?;
        let waits = crate::accel::Waits::new(&accel, &options.start);
        if virt {
            crate::dependencies::require_virt(options, &vm.launch, &qemu)?;
        } else {
            crate::dependencies::require_vm(options, &vm.launch)?;
        }
        crate::storage::validate_boot_display(vm, bundle)?;
        // An arm64 VM's window keeps QEMU's own size.
        let initial_size = initial_size(options, &vm.launch)
            .filter(|_| !virt)
            .map(|dimensions| {
                crate::display::InitialWindowSize::prepare().map(|sizing| (sizing, dimensions))
            })
            .transpose()?;
        let runtime_dir = vm_dir(options, &vm.id)?.join("runtime").join(unique_id());
        private_dir(&runtime_dir).map_err(|e| e.to_string())?;
        let mut cleanup = UnstartedRuntime {
            path: runtime_dir.clone(),
            started: false,
        };
        let ram_path = runtime_dir.join("shared-ram");
        let ram_size = u64::from(vm.ram_mib) * 1024 * 1024;
        let layout = machine.ram_layout(ram_size);
        let bootstrap = options
            .bootstrap_gpa
            .unwrap_or_else(|| layout.default_bootstrap());
        if !layout.bootstrap_fits(bootstrap) {
            return Err("bootstrap GPA must be page aligned and inside VM RAM below 4 GiB".into());
        }
        let (ram_path, ram_memory) = guest_ram(ram_path, ram_size)?;
        // The profile as this base and host can boot it.
        let base_support = crate::stealth::BaseSupport::from_list(&bundle.stealth_support);
        let host_support = if virt {
            crate::stealth::HostSupport::detect_arm64(&options.qemu)
        } else {
            crate::stealth::HostSupport::detect(&options.qemu)
        };
        let (mut stealth, fallbacks) = vm.stealth.fitted_with(&base_support, &host_support);
        let mut fallbacks: Vec<String> = fallbacks
            .iter()
            .map(crate::stealth::Fallback::log_line)
            .collect();
        if let Some(note) = effective_machine(&mut stealth, ram_size) {
            fallbacks.push(note);
        }
        let mut qmp_path = runtime_dir.join("qmp.sock");
        let mut socket_cleanup = None;
        if qmp_path.as_os_str().len() > 100 {
            let socket_dir = std::env::temp_dir().join(format!("ant-{}", unique_id()));
            private_dir(&socket_dir).map_err(|e| e.to_string())?;
            qmp_path = socket_dir.join("qmp.sock");
            socket_cleanup = Some(UnstartedRuntime {
                path: socket_dir,
                started: false,
            });
        }
        let cloud = stealth.cloud_provider().filter(|_| !virt);
        if virt && stealth.cloud_provider().is_some() {
            fallbacks.push(
                "Cloud VPS on arm64: the VM is shown as an AWS Graviton2 instance, without \
                 the x86 provider's metadata service or instance state."
                    .into(),
            );
        }
        // A Routed VM's gateway listens before QEMU starts, on the Drop
        // route: nothing leaves until a run claims a route.
        let mut gateway = None;
        let mut net_dir = None;
        let mut net_cleanup = None;
        if vm.network() == VmNetwork::Routed {
            crate::route::require_qemu_support(&options.qemu)?;
            let mut dir = runtime_dir.clone();
            if dir.join("net.sock").as_os_str().len() > 100 {
                dir = std::env::temp_dir().join(format!("ant-{}", unique_id()));
                private_dir(&dir).map_err(|e| e.to_string())?;
                net_cleanup = Some(UnstartedRuntime {
                    path: dir.clone(),
                    started: false,
                });
                net_dir = Some(dir.clone());
            }
            let net = crate::route::GatewayNet::from_nat(&stealth.nat)?;
            // A cloud profile's gateway also answers the provider's metadata
            // address (x86 providers; an arm64 VM is an AWS instance).
            let metadata = cloud.map(|provider| {
                let id = provider.instance_id(&stealth.identity.system_uuid);
                crate::route::MetadataService::new(provider, &id, &provider.hostname(&id))
            });
            gateway =
                Some(crate::route::Gateway::start_with(&dir, net, metadata)?.with_tor_slot(&vm.id));
        }
        if cloud.is_some() && vm.network() != VmNetwork::Routed {
            fallbacks.push(
                "Cloud metadata service is off: it needs a Routed network. Set Network to Routed \
                 to turn it on."
                    .into(),
            );
        }
        // On a cloud instance a NAT guest reaches the provider's real metadata
        // service; a plain note, not a failure.
        if vm.network() == VmNetwork::Nat
            && let Some(provider) = crate::host_cloud::host_cloud_provider()
        {
            fallbacks.push(crate::host_cloud::nat_note(provider));
        }
        // A cloud profile's lived-in state goes into the VM's disk once; a
        // failure leaves the VM plain and is said in the start log.
        if let Some(provider) = cloud
            && let Err(error) = crate::guest_account::ensure_cloud_state(
                disk,
                &vm_dir(options, &vm.id)?,
                provider,
                &stealth.identity.system_uuid,
                stealth.boot_age_s,
            )
        {
            fallbacks.push(format!(
                "Cloud instance state could not be set up ({error}); the VM starts without it."
            ));
        }
        let serial = File::create(runtime_dir.join("serial.log")).map_err(|e| e.to_string())?;
        let stderr = File::create(runtime_dir.join("qemu.log")).map_err(|e| e.to_string())?;
        let mut cmd = qemu_command(&qemu);
        // The arm64 machine the profile presents (MA-17); it boots UEFI.
        let mut arm_machine = if virt {
            crate::stealth::arm_machine(&stealth)
        } else {
            None
        };
        if virt {
            // UEFI when the profile asks for it or presents an arm64 machine
            // and the base boots it; AAVMF missing: the device tree.
            let wants_uefi = (stealth.firmware.is_uefi()
                || arm_machine.is_some_and(|machine| machine.tree.is_none()))
                && base_support.uefi;
            let uefi = if wants_uefi {
                match crate::stealth::aavmf_files(&options.qemu, &vm_dir(options, &vm.id)?) {
                    Ok(files) => Some(files),
                    Err(error) => {
                        fallbacks.push(format!(
                            "UEFI firmware: {error}; the VM boots its kernel directly."
                        ));
                        None
                    }
                }
            } else {
                None
            };
            // A UEFI machine without UEFI: a board on its device tree.
            if uefi.is_none() && arm_machine.is_some_and(|machine| machine.tree.is_none()) {
                arm_machine = crate::stealth::arm64::board_for(&stealth);
                if let Some(board) = arm_machine {
                    fallbacks.push(format!(
                        "The arm64 server, workstation and cloud machines boot UEFI; without \
                         it the VM is shown as a {} on its device tree.",
                        board.label
                    ));
                }
            }
            let identity = arm_machine.map(|machine| {
                stealth =
                    crate::stealth::arm64::arm_profile(&stealth, machine, vm.cpus, vm.ram_mib);
                virt::VirtIdentity {
                    cpu: crate::stealth::arm64::cpu_option(machine),
                    machine: if machine.tree.is_some() {
                        String::new()
                    } else {
                        crate::stealth::arm64::machine_options(&stealth.identity)
                    },
                }
            });
            cmd.arg("-name").arg(name_option(&vm.name));
            virt::machine_args(
                &mut cmd,
                vm.ram_mib,
                &qemu_path(&ram_path)?,
                vm.cpus,
                uefi.as_ref()
                    .map(|(code, vars)| (code.as_path(), vars.as_path())),
                identity.as_ref(),
            )?;
            if let Some(machine) = arm_machine.filter(|machine| machine.tree.is_some()) {
                let dtb = runtime_dir.join("board.dtb");
                crate::stealth::arm64::board_dtb(
                    &qemu,
                    machine,
                    vm.cpus,
                    vm.ram_mib,
                    &stealth.identity.system_uuid,
                    &dtb,
                )?;
                cmd.arg("-dtb").arg(&dtb);
            } else if let Some(machine) = arm_machine {
                crate::stealth::arm64::apply(
                    &mut cmd,
                    &stealth,
                    machine,
                    &runtime_dir,
                    vm.ram_mib,
                    vm.cpus,
                )?;
            }
            cmd.arg("-kernel")
                .arg(&bundle.kernel)
                .args(virt::disk_args(&stealth, &qemu_path(disk)?))
                .arg("-qmp")
                .arg(format!("unix:{},server=on,wait=off", qemu_path(&qmp_path)?))
                .args(["-monitor", "none", "-serial", "stdio"])
                .stdin(Stdio::null())
                .stdout(Stdio::from(serial))
                .stderr(Stdio::from(stderr));
        } else {
            cmd.arg("-name")
                .arg(name_option(&vm.name))
                .arg("-machine")
                .arg(format!(
                    "{},memory-backend=shared,max-ram-below-4g=4G{}",
                    stealth.machine.qemu(),
                    crate::stealth::machine_options(&stealth)
                ))
                .arg("-object")
                .arg(format!(
                    "memory-backend-file,id=shared,size={}M,mem-path={},share=on",
                    vm.ram_mib,
                    qemu_path(&ram_path)?
                ))
                .arg("-m")
                .arg(vm.ram_mib.to_string())
                .arg("-smp")
                .arg(crate::stealth::smp_option(&stealth, vm.cpus))
                .arg("-kernel")
                .arg(&bundle.kernel)
                .args(crate::stealth::disk_args(&stealth, &qemu_path(disk)?))
                .arg("-qmp")
                .arg(format!("unix:{},server=on,wait=off", qemu_path(&qmp_path)?))
                .args(["-monitor", "none", "-serial", "stdio"])
                .stdin(Stdio::null())
                .stdout(Stdio::from(serial))
                .stderr(Stdio::from(stderr));
        }
        if incoming {
            cmd.args(["-S", "-incoming", "defer"]);
        }
        // Guests from revision 13 (Antinomie 0.3.0) size their telemetry rings
        // from the kernel command line; older guests keep 256 KiB rings.
        let mut boot = bundle.clone();
        let account = if bundle
            .guest
            .as_ref()
            .is_some_and(|guest| guest.requires_credentials)
        {
            crate::guest_account::GuestAccount::load(&vm_dir(options, &vm.id)?).ok()
        } else {
            None
        };
        if let Some(account) = &account {
            boot.kernel_append = vm_kernel_append(&boot.kernel_append, account.root_uuid());
        }
        // A base that names its NIC by slot: the slot of the interface its
        // disk configures (provisioning and a profile change write it).
        let nic_slot = base_support.onboard_nic.then(|| {
            account
                .as_ref()
                .and_then(|account| crate::stealth::NicSlot::from_interface(account.interface()))
                .unwrap_or_default()
        });
        let console = format!("console={}", machine.console());
        if options.serial_console && !boot.kernel_append.contains(&console) {
            boot.kernel_append
                .push_str(&format!(" console=tty0 {console}"));
        }
        if bundle
            .antinomie_revision
            .is_some_and(|revision| revision >= 13)
        {
            boot.kernel_append
                .push_str(&format!(" antinomie_ring_kib={}", vm.transport.ring_kib));
        }
        // The guest facade of a desktop or laptop machine profile, for a base
        // whose kernel has it (its built-in hooks only on Debian's modules).
        if base_support.facade && !virt {
            for option in crate::stealth::facade_options(&stealth, bundle.runs_debian_modules()) {
                boot.kernel_append.push(' ');
                boot.kernel_append.push_str(&option);
            }
        }
        if virt {
            let mut append = virt::append(&boot.kernel_append, bootstrap, vm.launch.fast_emulation);
            virt::display_args(
                &mut cmd,
                virt::VirtDisplay {
                    headless: options.headless,
                    window: vm.launch.screen == crate::api::VmScreen::QemuWindow,
                    resolution: vm.launch.resolution.dimensions(),
                    fullscreen: vm.launch.fullscreen,
                    fit_to_window: vm.launch.fit_to_window,
                },
                &mut append,
            );
            cmd.arg("-append").arg(append);
        } else {
            apply_launch_settings(
                &mut cmd, options, &vm.launch, &accel, &stealth, vm.cpus, &boot, bootstrap,
            )?;
        }
        // The in-app screen: VNC on a unix socket next to the QMP socket (a
        // private folder), never TCP. The display backend itself is `none`.
        // lock-key-sync=off: the app sends the key (with Shift held), not a
        // keysym's case, so QEMU must not fix Caps Lock to match a keysym.
        let screen_socket =
            in_app_screen(options, &vm.launch).then(|| qmp_path.with_file_name("vnc.sock"));
        if let Some(socket) = &screen_socket {
            cmd.arg("-vnc").arg(format!(
                "unix:{},lossy=off,lock-key-sync=off",
                qemu_path(socket)?
            ));
        }
        if !virt {
            crate::stealth::apply(&mut cmd, &stealth, &runtime_dir, vm.ram_mib, vm.cpus)?;
            crate::stealth::firmware_args(
                &mut cmd,
                &stealth,
                &options.qemu,
                &vm_dir(options, &vm.id)?,
            )?;
        }
        if let Some(initrd) = &bundle.initrd {
            cmd.arg("-initrd").arg(initrd);
        }
        // An arm64 machine's card sits where the disk's configuration names
        // it too, on a base that names its NIC by slot (Debian).
        let nic = match (arm_machine, nic_slot) {
            (Some(_), Some(slot)) => {
                format!(
                    "{},{}",
                    crate::stealth::arm64::nic_option(&stealth),
                    slot.address()
                )
            }
            (Some(_), None) => crate::stealth::arm64::nic_option(&stealth),
            (None, _) => crate::stealth::nic_option_for(&stealth, nic_slot),
        };
        if let Some(netdev) = user_network_backend(vm) {
            // Network captures attach a filter-dump to net0 over QMP.
            cmd.arg("-netdev")
                .arg(crate::stealth::netdev_option(netdev, &stealth))
                .arg("-device")
                .arg(nic);
        } else if let Some(gateway) = &gateway {
            cmd.arg("-netdev")
                .arg(gateway.netdev_option()?)
                .arg("-device")
                .arg(nic);
        } else {
            cmd.args(["-nic", "none"]);
        }
        if let Some((sizing, _)) = &initial_size {
            sizing.before_spawn()?;
        }
        let child = cmd.spawn().map_err(|e| format!("QEMU launch: {e}"))?;
        let mut process = Self {
            child,
            ram_path,
            _ram_memory: ram_memory,
            runtime_dir,
            bootstrap,
            ram_layout: layout,
            machine,
            qmp_path,
            screen_socket,
            gateway,
            net_dir,
            stealth_fallbacks: fallbacks,
            accel,
            waits,
        };
        if let Some((sizing, (width, height))) = initial_size {
            process.set_initial_window_size(sizing, width, height)?;
        }
        cleanup.started = true;
        if let Some(cleanup) = socket_cleanup.as_mut() {
            cleanup.started = true;
        }
        if let Some(cleanup) = net_cleanup.as_mut() {
            cleanup.started = true;
        }
        Ok(process)
    }
    fn set_initial_window_size(
        &mut self,
        sizing: crate::display::InitialWindowSize,
        width: u16,
        height: u16,
    ) -> Result<(), String> {
        if let Err(error) = sizing.apply(&mut self.child, width, height) {
            if self
                .child
                .try_wait()
                .map_err(|e| format!("{error}; QEMU status: {e}"))?
                .is_none()
            {
                self.child
                    .kill()
                    .map_err(|e| format!("{error}; QEMU cleanup: {e}"))?;
            }
            self.child
                .wait()
                .map_err(|e| format!("{error}; QEMU reap: {e}"))?;
            return Err(error);
        }
        Ok(())
    }
    /// Confirms over QMP that QEMU placed guest RAM where the transport maps it.
    pub fn verify_ram_layout(&self) -> Result<(), String> {
        // The socket is created before machine and display setup. On a busy
        // host that work runs well past a few seconds, so the greeting wait
        // has to cover startup rather than only the listen backlog.
        // A TCG guest on a loaded host can stall QEMU's main loop past one
        // reply wait; the question is read only, so ask again before
        // taking QEMU for dead.
        let mut attempt = 1;
        let mut qmp = loop {
            match Qmp::connect_with(
                &self.qmp_path,
                self.waits.qmp_startup(),
                self.waits.qmp_reply(),
            ) {
                Ok(qmp) => break qmp,
                Err(error) if is_timeout(&error) && attempt < QMP_ATTEMPTS => attempt += 1,
                Err(error) => {
                    return Err(format!(
                        "QMP connect for RAM layout: {error}{}{}",
                        qemu_log_hint(&self.runtime_dir),
                        self.slow_hint()
                    ));
                }
            }
        };
        // q35 maps the backend through aliases (`info mtree`); virt maps the
        // backend region itself, which the flat view shows at its address.
        let command = match self.machine {
            Machine::Pc => "info mtree",
            Machine::Virt => "info mtree -f",
        };
        let request = format!(
            "{}\n",
            serde_json::json!({"execute":"human-monitor-command","arguments":{"command-line":command}})
        );
        let mut attempt = 1;
        let mtree = loop {
            match qmp.reply(&request) {
                Ok(reply) => break reply,
                Err(error) if is_timeout(&error) && attempt < QMP_ATTEMPTS => attempt += 1,
                Err(error) => return Err(format!("{error}{}", self.slow_hint())),
            }
        };
        let mtree = mtree["return"]
            .as_str()
            .ok_or("QMP memory map is not text")?;
        let layout = self.ram_layout;
        let found = match self.machine {
            Machine::Pc => RamLayout::from_mtree(mtree)?,
            Machine::Virt => RamLayout::from_flat_mtree(mtree)?,
        };
        if found != layout.expected() {
            return Err(format!(
                "QEMU placed guest RAM at {found:x?}, expected {:x?}",
                layout.expected()
            ));
        }
        Ok(())
    }
    /// Runs one QMP command (a `{"execute": ...}` object) and returns its
    /// return value.
    pub fn qmp(&self, command: &serde_json::Value) -> Result<serde_json::Value, String> {
        // Questions, stop and cont can be asked again after a timeout; other
        // commands that change something are sent once (a timeout leaves their
        // outcome unknown), but wait longer for their reply.
        let repeatable = repeatable(command);
        let attempts = if repeatable { QMP_ATTEMPTS } else { 1 };
        let mut attempt = 1;
        loop {
            let result = Qmp::connect_retrying(
                &self.qmp_path,
                self.waits.qmp_connect(),
                self.waits.qmp_reply(),
                QMP_ATTEMPTS,
            )
            .map_err(|error| {
                format!(
                    "QMP connect: {error}{}{}",
                    qemu_log_hint(&self.runtime_dir),
                    self.slow_hint()
                )
            })
            .and_then(|mut qmp| {
                if !repeatable {
                    qmp.set_reply_wait(self.waits.qmp_command())?;
                }
                qmp.reply(&format!("{command}\n"))
            });
            match result {
                Ok(reply) => return Ok(reply.get("return").cloned().unwrap_or_default()),
                Err(error) if is_timeout(&error) && attempt < attempts => attempt += 1,
                Err(error) => return Err(error),
            }
        }
    }
    /// Bytes the guest has written to its disks since QEMU started
    /// (`query-blockstats`, every device), or `None` when QMP does not answer.
    pub fn disk_written(&self) -> Option<u64> {
        let stats = self
            .qmp(&serde_json::json!({"execute":"query-blockstats"}))
            .ok()?;
        Some(
            stats
                .as_array()?
                .iter()
                .filter_map(|device| device["stats"]["wr_bytes"].as_u64())
                .sum(),
        )
    }
    /// Stops execution and reports whether it was previously running.
    pub fn pause(&self) -> Result<bool, String> {
        let status = self.qmp(&serde_json::json!({"execute":"query-status"}))?;
        let running = status["running"]
            .as_bool()
            .ok_or("QMP run status is missing")?;
        if running {
            self.qmp(&serde_json::json!({"execute":"stop"}))?;
        }
        if self.qmp(&serde_json::json!({"execute":"query-status"}))?["running"].as_bool()
            != Some(false)
        {
            return Err("QEMU failed to pause guest execution".into());
        }
        Ok(running)
    }
    pub fn resume(&self) -> Result<(), String> {
        self.qmp(&serde_json::json!({"execute":"cont"}))?;
        if self.qmp(&serde_json::json!({"execute":"query-status"}))?["running"].as_bool()
            != Some(true)
        {
            return Err("QEMU failed to resume guest execution".into());
        }
        Ok(())
    }
    /// Pivots the stable virtio frontend to a precreated writable child.
    pub fn pivot_disk(&self, child: &Path) -> Result<(), String> {
        let blocks = self.qmp(&serde_json::json!({"execute":"query-block"}))?;
        let block = blocks
            .as_array()
            .ok_or("QMP block list is missing")?
            .iter()
            .find(|block| block["device"].as_str() == Some("osdisk"))
            .ok_or("QMP stable VM disk is missing")?;
        let node = block["inserted"]["node-name"]
            .as_str()
            .ok_or("QMP current disk node is missing")?;
        // QEMU block node names must fit its 32-byte field, including NUL.
        let child_node = format!("ant-{}", unique_id().chars().take(24).collect::<String>());
        let child = child.to_str().ok_or("snapshot disk path must be UTF-8")?;
        self.qmp(&serde_json::json!({"execute":"blockdev-snapshot-sync","arguments":{"node-name":node,"snapshot-file":child,"snapshot-node-name":child_node,"format":"qcow2","mode":"existing"}}))?;
        let blocks = self.qmp(&serde_json::json!({"execute":"query-block"}))?;
        let actual = blocks
            .as_array()
            .ok_or("QMP block list is missing")?
            .iter()
            .find(|block| block["device"].as_str() == Some("osdisk"))
            .and_then(|block| block["inserted"]["node-name"].as_str());
        if actual != Some(child_node.as_str()) {
            return Err("QMP disk pivot result is uncertain; operation journal retained".into());
        }
        Ok(())
    }
    /// Full resume requires the same QEMU version and execution configuration.
    pub fn compatibility_for(
        options: &BackendOptions,
        vm: &VmConfig,
        bundle: &Bundle,
    ) -> Result<String, String> {
        use sha2::{Digest, Sha256};
        let machine = Machine::of(bundle.arch)?;
        let output = Command::new(machine.qemu(&options.qemu))
            .arg("--version")
            .output()
            .map_err(|e| format!("QEMU compatibility version: {e}"))?;
        if !output.status.success() || output.stdout.len() > 8192 {
            return Err("QEMU compatibility version is unavailable".into());
        }
        // The same decision the launch makes, so the identity matches the boot.
        let acceleration = launch_accel(options, &vm.launch, machine)?
            .accelerator
            .qemu_name();
        let host_identity = if acceleration == "kvm" {
            let machine = std::fs::read_to_string("/etc/machine-id")
                .map_err(|e| format!("full snapshot host identity is unavailable: {e}"))?;
            if machine.trim().is_empty() || machine.len() > 128 {
                return Err("full snapshot host identity is invalid".into());
            }
            let cpuinfo = std::fs::read_to_string("/proc/cpuinfo")
                .map_err(|e| format!("full snapshot CPU identity is unavailable: {e}"))?;
            let fields: Vec<_> = cpuinfo
                .split("\n\n")
                .next()
                .unwrap_or_default()
                .lines()
                .filter_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    matches!(
                        name.trim(),
                        "vendor_id" | "cpu family" | "model" | "stepping" | "flags"
                    )
                    .then(|| (name.trim(), value.trim()))
                })
                .collect();
            if fields.len() < 5 {
                return Err("full snapshot static CPU identity is incomplete".into());
            }
            let digest = Sha256::digest(
                serde_json::to_vec(&(machine.trim(), fields)).map_err(|e| e.to_string())?,
            );
            Some(
                digest
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            )
        } else {
            None
        };
        let mut value = serde_json::json!({"launch_policy":2,"host_identity":host_identity,"qemu":String::from_utf8_lossy(&output.stdout),"machine":machine.identity(vm.stealth.machine.qemu()),"cpus":vm.cpus,"ram_mib":vm.ram_mib,"nat":vm.nat,"launch":vm.launch.identity(),"transport":vm.transport,"acceleration":acceleration,"force_tcg":options.force_tcg,"headless":options.headless,"bootstrap_gpa":options.bootstrap_gpa,"bundle_identity":bundle.base_identity,"kernel_append":bundle.kernel_append,"kernel_version":bundle.kernel_version});
        // Keep pre-isolation checkpoints compatible for unchanged network setups.
        if let Some(key) = network_identity_key(vm) {
            value[key] = serde_json::Value::Bool(true);
        }
        let digest = Sha256::digest(serde_json::to_vec(&value).map_err(|e| e.to_string())?);
        Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }
    pub fn force_stop(&mut self) -> Result<(), String> {
        if self.child.try_wait().map_err(|e| e.to_string())?.is_some() {
            return Ok(());
        }
        if let Ok(mut socket) = UnixStream::connect(&self.qmp_path) {
            let _ = socket.set_read_timeout(Some(Duration::from_millis(200)));
            let _ = socket.set_write_timeout(Some(Duration::from_millis(200)));
            let mut greeting = [0; 2048];
            let _ = socket.read(&mut greeting);
            let _ = socket.write_all(b"{\"execute\":\"qmp_capabilities\"}\n");
            let _ = socket.read(&mut greeting);
            let _ = socket.write_all(b"{\"execute\":\"quit\"}\n");
        }
        if self.child.try_wait().map_err(|e| e.to_string())?.is_none() {
            self.child.kill().map_err(|e| e.to_string())?;
        }
        self.child.wait().map_err(|e| e.to_string())?;
        Ok(())
    }
}
impl Drop for VmProcess {
    fn drop(&mut self) {
        let _ = self.force_stop();
        if self._ram_memory.is_none() {
            let _ = std::fs::remove_file(&self.ram_path);
        }
        let _ = std::fs::remove_file(&self.qmp_path);
        if let Some(socket) = &self.screen_socket {
            let _ = std::fs::remove_file(socket);
        }
        if self.qmp_path.parent() != Some(self.runtime_dir.as_path())
            && let Some(parent) = self.qmp_path.parent()
        {
            let _ = std::fs::remove_dir(parent);
        }
        // The gateway stops and removes its socket before its folder goes.
        drop(self.gateway.take());
        if let Some(dir) = self.net_dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::VmAcceleration;

    fn kvm_choice() -> crate::accel::Choice {
        crate::accel::Choice {
            accelerator: crate::accel::Accelerator::Kvm,
            fallback: None,
        }
    }
    #[test]
    fn a_vm_boots_the_root_uuid_its_disk_was_given() {
        let base = "BOOT_IMAGE=/boot/vmlinuz-6.12.94+deb13-amd64 \
                    root=UUID=0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d ro quiet";
        assert_eq!(
            vm_kernel_append(base, Some("11111111-2222-4333-8444-555555555555")),
            "BOOT_IMAGE=/boot/vmlinuz-6.12.94+deb13-amd64 \
             root=UUID=11111111-2222-4333-8444-555555555555 ro quiet"
        );
        // A disk provisioned before (no UUID of its own) and a base that
        // names no root by UUID keep their command line.
        assert_eq!(vm_kernel_append(base, None), base);
        let busybox = "console=tty0 console=ttyS0 panic=-1";
        assert_eq!(
            vm_kernel_append(busybox, Some("11111111-2222-4333-8444-555555555555")),
            busybox
        );
    }
    #[test]
    fn qmp_connect_waits_for_a_greeting_sent_after_the_socket_listens() {
        use std::io::{BufRead, BufReader};
        use std::os::unix::net::UnixListener;
        use std::thread;
        let root = std::env::temp_dir().join(format!("ant-qmp-greeting-{}", unique_id()));
        private_dir(&root).unwrap();
        let path = root.join("qmp.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_secs(6));
            let mut socket = socket;
            socket.write_all(b"{\"QMP\":{}}\n").unwrap();
            let mut line = String::new();
            BufReader::new(socket.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            socket.write_all(b"{\"return\":{}}\n").unwrap();
        });
        let started = std::time::Instant::now();
        Qmp::connect(&path, Duration::from_secs(15)).expect("delayed greeting");
        assert!(started.elapsed() >= Duration::from_secs(6));
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(root);
    }
    #[test]
    fn qmp_connect_reports_timeout_instead_of_a_temporary_read_error() {
        use std::os::unix::net::UnixListener;
        use std::thread;
        let root = std::env::temp_dir().join(format!("ant-qmp-timeout-{}", unique_id()));
        private_dir(&root).unwrap();
        let path = root.join("qmp.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_secs(2));
            drop(socket);
        });
        let error = match Qmp::connect(&path, Duration::from_millis(400)) {
            Ok(_) => panic!("greeting arrived from a silent peer"),
            Err(error) => error,
        };
        assert!(error.contains("timed out waiting for a reply"), "{error}");
        assert!(!error.contains("os error 11"), "{error}");
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(root);
    }
    #[test]
    fn external_state_capture_restores_shared_ram_paused_and_allows_repeated_pivots() {
        use std::io::{Seek, SeekFrom};
        struct Fixture(PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                std::fs::remove_dir_all(&self.0).unwrap();
            }
        }
        let root = std::env::temp_dir().join(format!("ant-vm-snapshot-{}", unique_id()));
        private_dir(&root).unwrap();
        let _fixture = Fixture(root.clone());
        let disk = root.join("disk.qcow2");
        let output = Command::new("qemu-img")
            .args(["create", "-f", "qcow2"])
            .arg(&disk)
            .arg("16M")
            .output()
            .unwrap();
        assert!(output.status.success());
        let spawn = |name: &str, disk: &Path, incoming: bool| {
            let runtime_dir = root.join(name);
            private_dir(&runtime_dir).unwrap();
            let ram_path = runtime_dir.join("ram");
            File::create(&ram_path).unwrap();
            let qmp_path = runtime_dir.join("qmp.sock");
            let mut command = Command::new("qemu-system-x86_64");
            command
                .args([
                    "-machine",
                    "q35,memory-backend=shared,max-ram-below-4g=4G",
                    "-accel",
                    "tcg",
                    "-m",
                    "64",
                    "-smp",
                    "1",
                    "-S",
                    "-display",
                    "none",
                    "-monitor",
                    "none",
                    "-serial",
                    "none",
                ])
                .arg("-object")
                .arg(format!(
                    "memory-backend-file,id=shared,size=64M,mem-path={},share=on",
                    ram_path.display()
                ))
                .arg("-drive")
                .arg(format!(
                    "file={},format=qcow2,if=virtio,id=osdisk,node-name=antinomie-disk",
                    disk.display()
                ))
                .arg("-qmp")
                .arg(format!("unix:{},server=on,wait=off", qmp_path.display()))
                .stderr(File::create(runtime_dir.join("qemu.log")).unwrap());
            if incoming {
                command.args(["-incoming", "defer"]);
            }
            let child = command.spawn().unwrap();
            let process = VmProcess {
                child,
                ram_path,
                _ram_memory: None,
                runtime_dir,
                bootstrap: 0,
                ram_layout: RamLayout::q35(64 * 1024 * 1024),
                machine: Machine::Pc,
                qmp_path,
                screen_socket: None,
                gateway: None,
                net_dir: None,
                stealth_fallbacks: Vec::new(),
                accel: kvm_choice(),
                waits: crate::accel::Waits::kvm_default(),
            };
            // QEMU starts as slowly as the host lets it, and one exchange
            // waits for its greeting for two seconds: ask until it answers.
            let ready = std::time::Instant::now() + Duration::from_secs(120);
            while let Err(error) = process.qmp(&serde_json::json!({"execute":"query-status"})) {
                assert!(std::time::Instant::now() < ready, "{error}");
                std::thread::sleep(Duration::from_millis(100));
            }
            process
        };
        let overlay = |name: &str, parent: &Path| {
            let path = root.join(name);
            let output = Command::new("qemu-img")
                .args(["create", "-f", "qcow2", "-F", "qcow2", "-b"])
                .arg(parent)
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            path
        };
        let mut source = spawn("source", &disk, false);
        let marker = |ram: &Path, bytes: &[u8]| {
            let mut file = OpenOptions::new().write(true).open(ram).unwrap();
            file.seek(SeekFrom::Start(3 * 1024 * 1024)).unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
        };
        marker(&source.ram_path, b"RESTORED");
        let first = overlay("first.qcow2", &disk);
        source.pivot_disk(&first).unwrap();
        let second = overlay("second.qcow2", &first);
        source.pivot_disk(&second).unwrap();
        let state = root.join("state.bin");
        source.save_state(&state).unwrap();
        source.resume().unwrap();
        let rejected = root.join("running-state.bin");
        assert!(source.save_state(&rejected).is_err());
        assert!(!rejected.exists());
        assert!(source.pause().unwrap());
        marker(&source.ram_path, b"FUTURE!!");
        source.force_stop().unwrap();
        let restore = overlay("restore.qcow2", &first);
        let mut destination = spawn("destination", &restore, true);
        destination.load_state(&state).unwrap();
        assert!(!destination.pause().unwrap());
        let mut file = File::open(&destination.ram_path).unwrap();
        file.seek(SeekFrom::Start(3 * 1024 * 1024)).unwrap();
        let mut bytes = [0; 8];
        file.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"RESTORED");
        destination.resume().unwrap();
        destination.force_stop().unwrap();
        let corrupt = root.join("corrupt-state.bin");
        std::fs::write(&corrupt, b"invalid migration stream").unwrap();
        let disk = overlay("bad-restore.qcow2", &first);
        let mut failed = spawn("failed", &disk, true);
        assert!(failed.load_state(&corrupt).is_err());
        failed.force_stop().unwrap();
    }
    /// A QEMU started for a restore (`-incoming defer`) may create its
    /// monitor socket seconds later on a busy host: loading the state waits
    /// for it instead of failing on the missing socket (ENOENT).
    #[test]
    fn loading_a_state_waits_for_a_monitor_socket_made_late() {
        use std::io::{BufRead, BufReader};
        use std::os::unix::net::UnixListener;
        let root = std::env::temp_dir().join(format!("antinomie-late-qmp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        private_dir(&root).unwrap();
        let state = root.join("state.bin");
        std::fs::write(&state, b"state").unwrap();
        let qmp_path = root.join("qmp.sock");
        let waits = crate::accel::Waits::kvm_default();
        let late = waits.qmp_connect() + Duration::from_millis(1500);
        let socket = qmp_path.clone();
        let server = std::thread::spawn(move || {
            std::thread::sleep(late);
            let listener = UnixListener::bind(&socket).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            stream.write_all(b"{\"QMP\":{}}\n").unwrap();
            let mut asked = Vec::new();
            for answer in [
                &b"{\"return\":{}}\n"[..],
                b"{\"error\":{\"class\":\"GenericError\",\"desc\":\"late test server\"}}\n",
            ] {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                asked.push(line);
                stream.write_all(answer).unwrap();
            }
            asked
        });
        let process = VmProcess {
            child: Command::new("sleep").arg("60").spawn().unwrap(),
            ram_path: "/nonexistent/ram".into(),
            _ram_memory: None,
            runtime_dir: root.clone(),
            bootstrap: 0,
            ram_layout: RamLayout::q35(0),
            machine: Machine::Pc,
            qmp_path,
            screen_socket: None,
            gateway: None,
            net_dir: None,
            stealth_fallbacks: Vec::new(),
            accel: kvm_choice(),
            waits,
        };
        let error = process.load_state(&state).unwrap_err();
        let asked = server.join().unwrap();
        assert!(error.contains("late test server"), "{error}");
        assert!(asked[0].contains("qmp_capabilities") && asked[1].contains("getfd"));
        drop(process);
        std::fs::remove_dir_all(&root).unwrap();
    }
    use crate::api::{DisplayResolution, GuestProfile};

    #[test]
    fn a_routed_vm_has_no_user_network_and_changes_the_snapshot_identity() {
        let mut vm = VmConfig::default();
        assert_eq!(network_identity_key(&vm), None);
        vm.routed = true;
        assert_eq!(vm.network(), VmNetwork::Routed);
        assert!(vm.has_network());
        // Its card is wired to the gateway, not to QEMU's user network.
        assert_eq!(user_network_backend(&vm), None);
        assert_eq!(network_identity_key(&vm), Some("routed"));
        // Isolated wins over Routed, and Routed over NAT.
        vm.nat = true;
        assert_eq!(vm.network(), VmNetwork::Routed);
        assert_eq!(user_network_backend(&vm), None);
        vm.isolated_network = true;
        assert_eq!(vm.network(), VmNetwork::Isolated);
        assert_eq!(user_network_backend(&vm), Some("user,id=net0,restrict=on"));
        // A saved VM from before Routed existed reads as not routed.
        let old: VmConfig = serde_json::from_str(
            &serde_json::to_string(&VmConfig::default())
                .unwrap()
                .replace("\"routed\":false,", ""),
        )
        .unwrap();
        assert!(!old.routed);
    }

    #[test]
    fn isolated_network_overrides_nat_without_forwarding() {
        let mut vm = VmConfig::default();
        assert_eq!(user_network_backend(&vm), None);
        vm.nat = true;
        assert_eq!(user_network_backend(&vm), Some("user,id=net0"));
        vm.isolated_network = true;
        assert_eq!(user_network_backend(&vm), Some("user,id=net0,restrict=on"));
        vm.nat = false;
        assert_eq!(user_network_backend(&vm), Some("user,id=net0,restrict=on"));
    }

    #[test]
    fn stale_guest_ram_is_removed_but_open_ram_is_kept() {
        let root = std::env::temp_dir().join(format!("ant-stale-ram-{}", unique_id()));
        let options = BackendOptions {
            data_dir: root.clone(),
            ..BackendOptions::default()
        };
        let vm = VmConfig {
            id: "stale_ram_vm".into(),
            ..VmConfig::default()
        };
        let dir = root.join(&vm.id);
        private_dir(&dir).unwrap();
        crate::storage::atomic_json(&dir.join("config.json"), &vm).unwrap();
        let (stale, live) = (dir.join("runtime/a"), dir.join("runtime/b"));
        for run in [&stale, &live] {
            private_dir(run).unwrap();
            std::fs::write(run.join("shared-ram"), vec![1; 8192]).unwrap();
        }
        // A running QEMU holds its RAM file open; this test process stands in.
        let held = File::open(live.join("shared-ram")).unwrap();
        assert!(remove_stale_guest_ram(&options, &[&vm.id]) >= 8192);
        assert!(!stale.join("shared-ram").exists());
        assert!(live.join("shared-ram").exists());
        drop(held);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn bundle(graphical: bool) -> Bundle {
        Bundle {
            arch: Default::default(),
            kernel: "kernel".into(),
            base_disk: "base.qcow2".into(),
            initrd: None,
            kernel_append: "root=/dev/vda console=ttyS0".into(),
            kernel_version: "6.12.94".into(),
            schema_id: 1,
            base_identity: None,
            guest: graphical.then(|| GuestProfile {
                id: "debian-xfce".into(),
                label: "Debian 13 (Xfce)".into(),
                min_ram_mib: 2048,
                min_disk_gib: 8,
                requires_credentials: true,
                graphical: true,
            }),
            fixed_display: true,
            build_provenance: None,
            antinomie_revision: None,
            antinomie_source: None,
            built_with: None,
            min_app_version: None,
            name: None,
            symbols: None,
            stealth_support: Vec::new(),
            uefi: Default::default(),
        }
    }

    fn launch_args(
        options: &BackendOptions,
        launch: &VmLaunchOptions,
        graphical: bool,
    ) -> Result<Vec<String>, String> {
        let mut command = Command::new("qemu");
        apply_launch_settings(
            &mut command,
            options,
            launch,
            &crate::accel::choose_with(options, launch, || None)?,
            &crate::stealth::StealthProfile::transparent(),
            4,
            &bundle(graphical),
            0x40000000,
        )?;
        Ok(command
            .get_args()
            .map(|arg| arg.to_str().unwrap().to_owned())
            .collect())
    }

    #[test]
    fn an_aged_profile_passes_its_boot_age_to_the_guest_kernel() {
        let mut stealth = crate::stealth::StealthProfile::transparent();
        stealth.boot_age_s = 734_512;
        let mut command = Command::new("qemu");
        let (options, launch) = (BackendOptions::default(), VmLaunchOptions::default());
        apply_launch_settings(
            &mut command,
            &options,
            &launch,
            &crate::accel::choose_with(&options, &launch, || None).unwrap(),
            &stealth,
            4,
            &bundle(false),
            0x40000000,
        )
        .unwrap();
        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            value(&args, "-append"),
            Some(
                "root=/dev/vda console=ttyS0 antinomie_boot_gpa=0x40000000 antinomie_boot_age=734512:suspend"
            )
        );
    }

    #[test]
    fn the_clock_model_reaches_the_guest_as_resolved_for_the_base() {
        use crate::stealth::{ClockModel, StealthPreset, StealthProfile};
        let append = |stealth: &StealthProfile, debian: bool| {
            let mut command = Command::new("qemu");
            let (options, launch) = (BackendOptions::default(), VmLaunchOptions::default());
            apply_launch_settings(
                &mut command,
                &options,
                &launch,
                &crate::accel::choose_with(&options, &launch, || None).unwrap(),
                stealth,
                4,
                &bundle(debian),
                0x40000000,
            )
            .unwrap();
            let args: Vec<String> = command
                .get_args()
                .map(|arg| arg.to_str().unwrap().to_owned())
                .collect();
            let append = value(&args, "-append").unwrap().to_owned();
            append.rsplit(':').next().unwrap().to_owned()
        };
        let mut server = StealthProfile::realistic(StealthPreset::RealisticServer, "GenuineIntel");
        // Auto: a server is always running, except on a Debian base.
        assert_eq!(append(&server, false), "continuous");
        assert_eq!(append(&server, true), "suspend");
        // A choice wins on either base.
        server.clock_model = ClockModel::Continuous;
        assert_eq!(append(&server, true), "continuous");
        server.clock_model = ClockModel::Suspend;
        assert_eq!(append(&server, false), "suspend");
    }

    #[test]
    fn a_vm_name_cannot_inject_qemu_sub_options() {
        assert_eq!(name_option("Lab"), "guest=Lab");
        assert_eq!(name_option("Lab,process=x"), "guest=Lab,,process=x");
        assert_eq!(name_option("Test=1"), "guest=Test=1");
    }

    fn value<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
        args.windows(2)
            .find(|pair| pair[0] == key)
            .map(|pair| pair[1].as_str())
    }

    fn device_values(args: &[String]) -> Vec<&str> {
        args.windows(2)
            .filter(|pair| pair[0] == "-device")
            .map(|pair| pair[1].as_str())
            .collect()
    }

    #[test]
    fn legacy_launch_preserves_default_accelerator_display_and_graphics() {
        for graphical in [false, true] {
            for force_tcg in [false, true] {
                for headless in [false, true] {
                    let options = BackendOptions {
                        force_tcg,
                        headless,
                        ..BackendOptions::default()
                    };
                    let window = VmLaunchOptions {
                        screen: crate::api::VmScreen::QemuWindow,
                        ..VmLaunchOptions::default()
                    };
                    let args = launch_args(&options, &window, graphical).unwrap();
                    // The in-app screen differs only in the display backend.
                    let in_app =
                        launch_args(&options, &VmLaunchOptions::default(), graphical).unwrap();
                    assert_eq!(value(&in_app, "-display"), Some("none"));
                    assert_eq!(device_values(&in_app), device_values(&args));
                    assert_eq!(
                        value(&args, "-accel"),
                        Some(if force_tcg { "tcg" } else { "kvm" })
                    );
                    assert_eq!(
                        value(&args, "-display"),
                        Some(if headless {
                            "none"
                        } else {
                            "gtk,zoom-to-fit=off"
                        })
                    );
                    assert_eq!(value(&args, "-cpu"), None);
                    assert_eq!(value(&args, "-vga"), graphical.then_some("virtio"));
                    assert_eq!(
                        device_values(&args),
                        if headless {
                            vec![]
                        } else {
                            vec!["virtio-tablet-pci"]
                        }
                    );
                    assert_eq!(
                        value(&args, "-append"),
                        Some("root=/dev/vda console=ttyS0 antinomie_boot_gpa=0x40000000")
                    );
                }
            }
        }
    }

    #[test]
    fn fixed_resolution_sets_one_adapter_edid_and_kernel_video_mode() {
        let expected = [
            (DisplayResolution::R800x600, 800, 600),
            (DisplayResolution::R1024x768, 1024, 768),
            (DisplayResolution::R1280x720, 1280, 720),
            (DisplayResolution::R1280x800, 1280, 800),
            (DisplayResolution::R1600x900, 1600, 900),
            (DisplayResolution::R1920x1080, 1920, 1080),
            (DisplayResolution::R2560x1440, 2560, 1440),
        ];
        assert_eq!(DisplayResolution::Auto.dimensions(), None);
        for (resolution, width, height) in expected {
            assert_eq!(resolution.dimensions(), Some((width, height)));
            for graphical in [false, true] {
                for headless in [false, true] {
                    let options = BackendOptions {
                        headless,
                        ..BackendOptions::default()
                    };
                    let launch = VmLaunchOptions {
                        resolution,
                        screen: crate::api::VmScreen::QemuWindow,
                        ..VmLaunchOptions::default()
                    };
                    let args = launch_args(&options, &launch, graphical).unwrap();
                    assert_eq!(value(&args, "-vga"), Some("none"));
                    assert_eq!(
                        value(&args, "-display"),
                        Some(if headless {
                            "none"
                        } else {
                            "gtk,zoom-to-fit=off"
                        })
                    );
                    let devices = device_values(&args);
                    let gpu = format!("virtio-gpu-pci,edid=on,xres={width},yres={height}");
                    assert_eq!(devices.first().copied(), Some(gpu.as_str()));
                    assert_eq!(devices.len(), if headless { 1 } else { 2 });
                    assert_eq!(devices.contains(&"virtio-tablet-pci"), !headless);
                    assert_eq!(
                        value(&args, "-append"),
                        Some(
                            format!("root=/dev/vda console=ttyS0 antinomie_boot_gpa=0x40000000 video=Virtual-1:{width}x{height}").as_str()
                        )
                    );
                }
            }
        }
    }

    #[test]
    fn no_screen_runs_without_a_display_or_vnc_and_the_other_choices_keep_theirs() {
        use crate::api::VmScreen;
        for headless in [false, true] {
            for graphical in [false, true] {
                let options = BackendOptions {
                    headless,
                    ..BackendOptions::default()
                };
                let launch = |screen| VmLaunchOptions {
                    screen,
                    ..VmLaunchOptions::default()
                };
                let none = launch_args(&options, &launch(VmScreen::NoScreen), graphical).unwrap();
                let in_app = launch_args(&options, &launch(VmScreen::InApp), graphical).unwrap();
                let window =
                    launch_args(&options, &launch(VmScreen::QemuWindow), graphical).unwrap();
                assert_eq!(value(&none, "-display"), Some("none"));
                assert_eq!(value(&in_app, "-display"), Some("none"));
                assert_eq!(
                    value(&window, "-display"),
                    Some(if headless {
                        "none"
                    } else {
                        "gtk,zoom-to-fit=off"
                    })
                );
                // The guest sees the same devices without the window.
                assert_eq!(none, in_app);
                assert_eq!(in_app_screen(&options, &launch(VmScreen::InApp)), !headless);
                assert!(!in_app_screen(&options, &launch(VmScreen::NoScreen)));
                assert!(!in_app_screen(&options, &launch(VmScreen::QemuWindow)));
            }
        }
        let saved: VmLaunchOptions = serde_json::from_str("{}").unwrap();
        assert_eq!(saved.screen, VmScreen::InApp);
        let saved: VmLaunchOptions = serde_json::from_str(r#"{"screen":"no_screen"}"#).unwrap();
        assert_eq!(saved.screen, VmScreen::NoScreen);
    }

    #[test]
    fn gtk_flags_and_headless_override_are_independent() {
        for (fullscreen, fit_to_window, display) in [
            (false, false, "gtk,zoom-to-fit=off"),
            (true, false, "gtk,full-screen=on,zoom-to-fit=off"),
            (false, true, "gtk,zoom-to-fit=on"),
            (true, true, "gtk,full-screen=on,zoom-to-fit=on"),
        ] {
            let launch = VmLaunchOptions {
                fullscreen,
                fit_to_window,
                screen: crate::api::VmScreen::QemuWindow,
                ..VmLaunchOptions::default()
            };
            for headless in [false, true] {
                let options = BackendOptions {
                    headless,
                    ..BackendOptions::default()
                };
                let args = launch_args(&options, &launch, false).unwrap();
                assert_eq!(
                    value(&args, "-display"),
                    Some(if headless { "none" } else { display })
                );
            }
        }
    }

    #[test]
    fn accelerator_override_and_allowlisted_cpu_arguments() {
        for &acceleration in VmAcceleration::ALL {
            for (cpu_model, cpu) in [
                (VmCpuModel::Default, None),
                (VmCpuModel::Qemu64, Some("qemu64")),
                (VmCpuModel::Host, Some("host")),
                (VmCpuModel::Max, Some("max")),
            ] {
                for force_tcg in [false, true] {
                    let options = BackendOptions {
                        force_tcg,
                        ..BackendOptions::default()
                    };
                    let launch = VmLaunchOptions {
                        acceleration,
                        cpu_model,
                        ..VmLaunchOptions::default()
                    };
                    let result = launch_args(&options, &launch, false);
                    let tcg = force_tcg || acceleration == VmAcceleration::Tcg;
                    if cpu_model == VmCpuModel::Host && tcg {
                        assert!(result.unwrap_err().contains("requires KVM"));
                    } else {
                        let args = result.unwrap();
                        assert_eq!(
                            value(&args, "-accel"),
                            Some(if tcg { "tcg" } else { "kvm" })
                        );
                        assert_eq!(value(&args, "-cpu"), cpu);
                    }
                }
            }
        }
    }

    #[test]
    fn an_i440fx_profile_keeps_q35_where_the_ram_layouts_differ() {
        use crate::stealth::{CLOUDS, MachineType, StealthProfile};
        const MIB: u64 = 1024 * 1024;
        let mut profile = StealthProfile::cloud_vps(&CLOUDS[0]);
        assert_eq!(profile.machine, MachineType::Pc);
        assert!(effective_machine(&mut profile, 2816 * MIB - 1).is_none());
        assert_eq!(profile.machine, MachineType::Pc);
        let note = effective_machine(&mut profile, 2816 * MIB).unwrap();
        assert!(note.contains("q35 will be used"));
        assert_eq!(profile.machine, MachineType::Q35);
        // A q35 profile is never touched.
        assert!(effective_machine(&mut profile, 8192 * MIB).is_none());
    }

    #[test]
    fn ram_layout_follows_q35_split() {
        const MIB: u64 = 1024 * 1024;
        assert_eq!(
            RamLayout::q35(2048 * MIB),
            RamLayout {
                base: 0,
                low: 2048 * MIB,
                high: 0
            }
        );
        assert_eq!(
            RamLayout::q35(2815 * MIB),
            RamLayout {
                base: 0,
                low: 2815 * MIB,
                high: 0
            }
        );
        assert_eq!(
            RamLayout::q35(2816 * MIB),
            RamLayout {
                base: 0,
                low: 2048 * MIB,
                high: 768 * MIB
            }
        );
        assert_eq!(
            RamLayout::q35(3072 * MIB),
            RamLayout {
                base: 0,
                low: 2048 * MIB,
                high: 1024 * MIB
            }
        );
        assert_eq!(
            RamLayout::q35(8192 * MIB),
            RamLayout {
                base: 0,
                low: 2048 * MIB,
                high: 6144 * MIB
            }
        );
    }
    #[test]
    fn ram_layout_matches_qemu_memory_map() {
        // Lines from QEMU 11.0.3 `info mtree` with -m 4096 (each appears twice).
        let mtree = "\
  0000000000000000-000000007fffffff (prio 0, ram): alias ram-below-4g @shared 0000000000000000-000000007fffffff
  0000000100000000-000000017fffffff (prio 0, ram): alias ram-above-4g @shared 0000000080000000-00000000ffffffff
    0000000000000000-000000007fffffff (prio 0, ram): alias ram-below-4g @shared 0000000000000000-000000007fffffff
    0000000100000000-000000017fffffff (prio 0, ram): alias ram-above-4g @shared 0000000080000000-00000000ffffffff
  00000000fec00000-00000000fec00fff (prio 0, i/o): ioapic";
        let found = RamLayout::from_mtree(mtree).unwrap();
        assert_eq!(found, RamLayout::q35(4096 << 20).expected());
        assert_ne!(found, RamLayout::q35(3072 << 20).expected());
        let low_only = "  0000000000000000-000000007fffffff (prio 0, ram): alias ram-below-4g @shared 0000000000000000-000000007fffffff";
        assert_eq!(
            RamLayout::from_mtree(low_only).unwrap(),
            RamLayout::q35(2048 << 20).expected()
        );
    }
    #[test]
    fn arm64_runs_on_virt_with_ram_at_one_gib_and_the_bootstrap_in_its_middle() {
        use crate::api::GuestArch;
        const MIB: u64 = 1024 * 1024;
        assert_eq!(Machine::of(GuestArch::X86_64), Ok(Machine::Pc));
        assert_eq!(Machine::of(GuestArch::AARCH64), Ok(Machine::Virt));
        assert!(Machine::of(GuestArch::MIPS).unwrap_err().contains("MIPS"));
        // x86-64 keeps its default bootstrap page and its checks.
        let q35 = RamLayout::q35(2048 * MIB);
        assert_eq!(q35.default_bootstrap(), 0x4000_0000);
        assert!(q35.bootstrap_fits(0x100000) && !q35.bootstrap_fits(0xff000));
        assert!(!q35.bootstrap_fits(0x4000_0800) && !q35.bootstrap_fits(2048 * MIB));
        // MA-09: RAM base + RAM/2 (0x60000000 for 1 GiB, 0x50000000 for 512 MiB).
        let virt = Machine::Virt.ram_layout(1024 * MIB);
        assert_eq!(virt.expected(), vec![(0x4000_0000, 1024 * MIB, 0)]);
        assert_eq!(virt.default_bootstrap(), 0x6000_0000);
        assert_eq!(
            Machine::Virt.ram_layout(512 * MIB).default_bootstrap(),
            0x5000_0000
        );
        assert!(virt.bootstrap_fits(0x6000_0000) && !virt.bootstrap_fits(0x2000_0000));
        assert!(!virt.bootstrap_fits(0x8000_0000) && !virt.bootstrap_fits(0x4000_0000));
        assert!(
            Machine::Virt
                .check_ram(511)
                .unwrap_err()
                .contains("at least 512 MiB")
        );
        assert!(Machine::Virt.check_ram(512).is_ok() && Machine::Pc.check_ram(256).is_ok());
        assert_eq!(
            (Machine::Pc.console(), Machine::Virt.console()),
            ("ttyS0", "ttyAMA0")
        );
        assert_eq!(
            (Machine::Pc.time_scale(), Machine::Virt.time_scale()),
            (1, ARM64_TIME_SCALE)
        );
        assert_eq!(Machine::Pc.identity("q35"), "q35,max-ram-below-4g=4G");
        assert_ne!(Machine::Virt.identity("q35"), Machine::Pc.identity("q35"));
        let qemu = Path::new("/opt/qemu/bin/qemu-system-x86_64");
        assert_eq!(Machine::Pc.qemu(qemu), qemu);
        assert_eq!(
            Machine::Virt.qemu(qemu),
            Path::new("/opt/qemu/bin/qemu-system-aarch64")
        );
        assert_eq!(
            Machine::Virt.qemu(Path::new("qemu-system-x86_64")),
            Path::new("qemu-system-aarch64")
        );
        // `info mtree -f` lines of QEMU 11.0.3 virt with a 1 GiB shared backend
        // (MA-09), once per address space.
        let flat = "\
FlatView #0
 AS \"memory\", root: system
  0000000000000000-0000000003ffffff (prio 0, romd): virt.flash0
  0000000004000000-0000000007ffffff (prio 0, romd): virt.flash1
  0000000040000000-000000007fffffff (prio 0, ram): shared
FlatView #1
  0000000040000000-000000007fffffff (prio 0, ram): shared";
        assert_eq!(RamLayout::from_flat_mtree(flat).unwrap(), virt.expected());
        assert_ne!(
            RamLayout::from_flat_mtree(flat).unwrap(),
            Machine::Virt.ram_layout(512 * MIB).expected()
        );
    }
    #[test]
    fn owned_process_is_reaped_on_drop() {
        let child = Command::new("sleep").arg("60").spawn().unwrap();
        let pid = child.id();
        let process = VmProcess {
            child,
            ram_path: "/nonexistent/ram".into(),
            _ram_memory: None,
            runtime_dir: "/nonexistent".into(),
            bootstrap: 0,
            ram_layout: RamLayout::q35(0),
            machine: Machine::Pc,
            qmp_path: "/nonexistent/qmp".into(),
            screen_socket: None,
            gateway: None,
            net_dir: None,
            stealth_fallbacks: Vec::new(),
            accel: kvm_choice(),
            waits: crate::accel::Waits::kvm_default(),
        };
        drop(process);
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    }
    #[test]
    fn failed_initial_sizing_reaps_only_owned_child() {
        let mut unrelated = Command::new("sleep").arg("60").spawn().unwrap();
        let child = Command::new("sleep").arg("60").spawn().unwrap();
        let pid = child.id();
        let mut process = VmProcess {
            child,
            ram_path: "/nonexistent/ram".into(),
            _ram_memory: None,
            runtime_dir: "/nonexistent".into(),
            bootstrap: 0,
            ram_layout: RamLayout::q35(0),
            machine: Machine::Pc,
            qmp_path: "/nonexistent/qmp".into(),
            screen_socket: None,
            gateway: None,
            net_dir: None,
            stealth_fallbacks: Vec::new(),
            accel: kvm_choice(),
            waits: crate::accel::Waits::kvm_default(),
        };
        let (sizing, _server) =
            crate::display::InitialWindowSize::stalled_for_test(Duration::from_millis(50));
        let start = std::time::Instant::now();
        assert!(
            process
                .set_initial_window_size(sizing, 1280, 720)
                .unwrap_err()
                .contains("timed out")
        );
        assert!(start.elapsed() < Duration::from_secs(30));
        assert!(process.child.try_wait().unwrap().is_some());
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        assert!(unrelated.try_wait().unwrap().is_none());
        unrelated.kill().unwrap();
        unrelated.wait().unwrap();
    }
    #[test]
    fn only_fixed_fitted_windowed_display_hides_chrome_and_forces_x11() {
        for resolution in [DisplayResolution::Auto, DisplayResolution::R1280x720] {
            for headless in [false, true] {
                for fullscreen in [false, true] {
                    for fit_to_window in [false, true] {
                        let options = BackendOptions {
                            headless,
                            ..BackendOptions::default()
                        };
                        let launch = VmLaunchOptions {
                            resolution,
                            fullscreen,
                            fit_to_window,
                            screen: crate::api::VmScreen::QemuWindow,
                            ..VmLaunchOptions::default()
                        };
                        let mut command = Command::new("qemu-system-x86_64");
                        apply_launch_settings(
                            &mut command,
                            &options,
                            &launch,
                            &crate::accel::choose_with(&options, &launch, || None).unwrap(),
                            &crate::stealth::StealthProfile::transparent(),
                            4,
                            &bundle(true),
                            0x40000000,
                        )
                        .unwrap();
                        let expected = resolution != DisplayResolution::Auto
                            && !headless
                            && !fullscreen
                            && fit_to_window;
                        let args: Vec<_> = command
                            .get_args()
                            .map(|arg| arg.to_string_lossy().into_owned())
                            .collect();
                        assert_eq!(
                            value(&args, "-display")
                                .unwrap()
                                .contains("show-menubar=off,show-tabs=off"),
                            expected
                        );
                        assert_eq!(
                            command.get_envs().any(|(key, value)| key == "GDK_BACKEND"
                                && value == Some(std::ffi::OsStr::new("x11"))),
                            expected
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn commas_in_paths_cannot_inject_qemu_options() {
        assert_eq!(
            qemu_path(Path::new("/tmp/a,share=off")).unwrap(),
            "/tmp/a,,share=off"
        );
    }
    #[test]
    fn the_bootstrap_page_counts_as_published_once_its_first_word_is_written() {
        let root = std::env::temp_dir().join(format!("ant-bootstrap-{}", unique_id()));
        private_dir(&root).unwrap();
        let ram = root.join("ram");
        let layout = RamLayout::q35(1 << 28);
        let bootstrap = 0x0100_0000;
        let file = File::create(&ram).unwrap();
        file.set_len(1 << 28).unwrap();
        assert!(!bootstrap_magic_written(&ram, &layout, bootstrap));
        {
            use std::os::unix::fs::FileExt;
            file.write_all_at(b"ANTT", bootstrap).unwrap();
        }
        assert!(bootstrap_magic_written(&ram, &layout, bootstrap));
        // An address outside every RAM region, and a missing file, are not published.
        assert!(!bootstrap_magic_written(&ram, &layout, 1 << 40));
        assert!(!bootstrap_magic_written(
            &root.join("none"),
            &layout,
            bootstrap
        ));
        let _ = std::fs::remove_dir_all(root);
    }
    #[test]
    fn a_stalled_qmp_reply_waits_as_long_as_it_is_given() {
        use std::io::{BufRead, BufReader};
        use std::os::unix::net::UnixListener;
        use std::thread;
        let root = std::env::temp_dir().join(format!("ant-qmp-reply-{}", unique_id()));
        private_dir(&root).unwrap();
        let path = root.join("qmp.sock");
        let listener = UnixListener::bind(&path).unwrap();
        // QEMU's main loop answers the capabilities request 1.5 s late.
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().unwrap();
                socket.write_all(b"{\"QMP\":{}}\n").unwrap();
                let mut line = String::new();
                BufReader::new(socket.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                thread::sleep(Duration::from_millis(1500));
                let _ = socket.write_all(b"{\"return\":{}}\n");
            }
        });
        let error =
            match Qmp::connect_with(&path, Duration::from_secs(5), Duration::from_millis(300)) {
                Ok(_) => panic!("answered in time"),
                Err(error) => error,
            };
        assert!(is_timeout(&error), "{error}");
        Qmp::connect_with(&path, Duration::from_secs(5), Duration::from_secs(5))
            .expect("a longer reply wait covers the stall");
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(root);
    }
    /// The first connection of a QEMU under load greets late; a second one is
    /// answered at once. The first command no longer fails on the first miss.
    #[test]
    fn a_late_greeting_is_retried_and_a_dead_qemu_is_named() {
        use std::io::{BufRead, BufReader};
        use std::os::unix::net::UnixListener;
        use std::thread;
        let root = std::env::temp_dir().join(format!("ant-qmp-retry-{}", unique_id()));
        private_dir(&root).unwrap();
        let path = root.join("qmp.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            // The first connection never greets within the wait.
            let (silent, _) = listener.accept().unwrap();
            let (mut socket, _) = listener.accept().unwrap();
            socket.write_all(b"{\"QMP\":{}}\n").unwrap();
            let mut line = String::new();
            BufReader::new(socket.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            socket.write_all(b"{\"return\":{}}\n").unwrap();
            thread::sleep(Duration::from_millis(300));
            drop(silent);
        });
        Qmp::connect_retrying(&path, Duration::from_millis(300), Duration::from_secs(5), 3)
            .expect("the second connection is answered");
        server.join().unwrap();
        // Nothing answers any attempt: the error says how often it was tried.
        let listener = UnixListener::bind(root.join("dead.sock")).unwrap();
        let hold = thread::spawn(move || {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept() {
                held.push(socket);
                if held.len() == 2 {
                    break;
                }
            }
            held
        });
        let error = match Qmp::connect_retrying(
            &root.join("dead.sock"),
            Duration::from_millis(200),
            Duration::from_secs(5),
            2,
        ) {
            Ok(_) => panic!("nothing greeted"),
            Err(error) => error,
        };
        assert!(
            is_timeout(&error) && error.contains("tried 2 times"),
            "{error}"
        );
        drop(hold.join().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }
    #[test]
    fn only_commands_that_are_safe_to_repeat_are_sent_again() {
        for name in ["query-status", "query-block", "stop", "cont"] {
            assert!(repeatable(&serde_json::json!({"execute": name})), "{name}");
        }
        for name in ["system_reset", "blockdev-snapshot-sync", "migrate", "quit"] {
            assert!(!repeatable(&serde_json::json!({"execute": name})), "{name}");
        }
    }
    #[test]
    fn a_slow_tcg_timeout_says_why_and_what_to_do() {
        let tcg = crate::accel::Choice {
            accelerator: crate::accel::Accelerator::Tcg,
            fallback: None,
        };
        let waits =
            crate::accel::Waits::with_load(&tcg, &crate::api::StartSettings::default(), 2.0);
        let hint = slow_hint(&tcg, &waits);
        assert!(hint.contains("software emulation"));
        assert!(hint.contains("20 times"));
        assert!(hint.contains("TCG multiplier"));
        assert!(hint.contains("reduce the load"));
        assert!(hint.contains("use KVM"));
        let kvm = crate::accel::Choice {
            accelerator: crate::accel::Accelerator::Kvm,
            fallback: None,
        };
        assert!(slow_hint(&kvm, &crate::accel::Waits::kvm_default()).is_empty());
        assert!(is_timeout("QMP read: timed out waiting for a reply"));
        assert!(!is_timeout("QMP closed"));
    }
}
