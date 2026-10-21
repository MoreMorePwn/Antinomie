use crate::{
    api::{BackendOptions, VmAcceleration, VmConfig, VmCpuModel, VmLaunchOptions},
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

fn user_network_backend(vm: &VmConfig) -> Option<&'static str> {
    if vm.isolated_network {
        Some("user,id=net0,restrict=on")
    } else if vm.nat {
        Some("user,id=net0")
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
/// Guest RAM as q35 lays it out: QEMU keeps 0xb0000000 bytes below 4 GiB, or
/// only 2 GiB once RAM reaches that size, and places the rest at 4 GiB. Both
/// parts come from one backing file, the high part directly after the low.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RamLayout {
    pub low: u64,
    pub high: u64,
}
pub(crate) const HIGH_RAM_GPA: u64 = 1 << 32;
impl RamLayout {
    pub fn q35(ram_size: u64) -> Self {
        let lowmem = if ram_size >= 0xb000_0000 {
            0x8000_0000
        } else {
            0xb000_0000
        };
        let low = ram_size.min(lowmem);
        Self {
            low,
            high: ram_size - low,
        }
    }
    /// Reads QEMU's `ram-below-4g`/`ram-above-4g` aliases from `info mtree`
    /// output as (GPA, size, backing offset) triples.
    fn from_mtree(mtree: &str) -> Result<Vec<(u64, u64, u64)>, String> {
        let parse = |range: &str| -> Option<(u64, u64)> {
            let (start, end) = range.trim().split_once('-')?;
            let start = u64::from_str_radix(start, 16).ok()?;
            let end = u64::from_str_radix(end.split_whitespace().next()?, 16).ok()?;
            Some((start, end.checked_sub(start)?.checked_add(1)?))
        };
        let mut found = Vec::new();
        for line in mtree.lines() {
            let Some((range, alias)) = line.split_once(" (prio ") else {
                continue;
            };
            let Some((_, target)) = alias
                .split_once("alias ram-below-4g @")
                .or_else(|| alias.split_once("alias ram-above-4g @"))
            else {
                continue;
            };
            let (gpa, size) = parse(range).ok_or("unreadable QEMU memory map")?;
            let (offset, alias_size) = target
                .split_once(' ')
                .and_then(|(_, range)| parse(range))
                .ok_or("unreadable QEMU memory map")?;
            if alias_size != size {
                return Err("unreadable QEMU memory map".into());
            }
            if !found.contains(&(gpa, size, offset)) {
                found.push((gpa, size, offset));
            }
        }
        found.sort_unstable();
        Ok(found)
    }
    fn expected(&self) -> Vec<(u64, u64, u64)> {
        let mut regions = vec![(0, self.low, 0)];
        if self.high != 0 {
            regions.push((HIGH_RAM_GPA, self.high, self.low));
        }
        regions
    }
}
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
fn initial_size(options: &BackendOptions, launch: &VmLaunchOptions) -> Option<(u16, u16)> {
    (!options.headless && !launch.fullscreen && launch.fit_to_window)
        .then(|| launch.resolution.dimensions())
        .flatten()
}

fn apply_launch_settings(
    command: &mut Command,
    options: &BackendOptions,
    launch: &VmLaunchOptions,
    stealth: &crate::stealth::StealthProfile,
    bundle: &Bundle,
    bootstrap: u64,
) -> Result<(), String> {
    launch.validate_for(options)?;
    let acceleration = if options.force_tcg || launch.acceleration == VmAcceleration::Tcg {
        "tcg"
    } else {
        "kvm"
    };
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
    if let Some(cpu) = crate::stealth::cpu_option(stealth, base, acceleration == "kvm") {
        command.arg("-cpu").arg(cpu);
    }
    let mut append = format!(
        "{} antinomie_boot_gpa=0x{bootstrap:x}",
        bundle.kernel_append
    );
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
    let mut display = if options.headless { "none" } else { "gtk" }.to_owned();
    if !options.headless {
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
        // An absolute pointer keeps the GTK display from grabbing and
        // recentering the host cursor. The guest kernel already binds
        // CONFIG_VIRTIO_INPUT, so no additional controller is required.
        command.args(["-device", "virtio-tablet-pci"]);
    }
    command.arg("-display").arg(display);
    Ok(())
}

pub(crate) struct VmProcess {
    pub child: Child,
    pub ram_path: PathBuf,
    /// Keeps in-memory guest RAM alive; `ram_path` then names it through /proc.
    _ram_memory: Option<OwnedFd>,
    pub runtime_dir: PathBuf,
    pub bootstrap: u64,
    pub ram_size: u64,
    pub qmp_path: PathBuf,
}
/// The QEMU command. Through util-linux `setpriv`, when installed, QEMU gets
/// SIGKILL if the app dies, instead of running on with the VM's disk locked
/// (the next Start would then fail on that lock).
/// The `-name` value: an explicit `guest=` so a name holding `=` is not read
/// as a sub-option, and commas doubled like every QEMU option value.
fn name_option(name: &str) -> String {
    format!("guest={}", crate::stealth::escape(name))
}

fn qemu_command(qemu: &Path) -> Command {
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

/// A QMP connection, past the greeting and capability negotiation.
pub(crate) mod keyboard;

struct Qmp {
    writer: UnixStream,
    reader: std::io::BufReader<UnixStream>,
}
impl Qmp {
    fn send_fd(&mut self, stream: &UnixStream) -> Result<(), String> {
        use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
        let command = b"{\"execute\":\"getfd\",\"arguments\":{\"fdname\":\"antinomie-state\"}}\n";
        let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        let descriptors = [stream.as_fd()];
        if !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)) {
            return Err("QMP descriptor control buffer is too small".into());
        }
        let sent = sendmsg(
            &self.writer,
            &[std::io::IoSlice::new(command)],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .map_err(|e| format!("QMP descriptor transfer: {e}"))?;
        if sent < command.len() {
            self.writer
                .write_all(&command[sent..])
                .map_err(|e| e.to_string())?;
        }
        self.reply("")?;
        Ok(())
    }
    /// Connects, retrying for `wait` while QEMU is still creating the socket
    /// or has not reached the main loop that sends the greeting.
    ///
    /// `server=on,wait=off` listens before QEMU can write that greeting.
    /// A read against the accepted connection then returns EAGAIN when its
    /// receive timeout expires, which is the same code as a nonblocking read.
    fn connect(path: &Path, wait: Duration) -> Result<Self, String> {
        let deadline = std::time::Instant::now() + wait;
        let socket = loop {
            match UnixStream::connect(path) {
                Ok(socket) => break socket,
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Err(error) => return Err(error.to_string()),
            }
        };
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err("QMP read: timed out waiting for a reply".into());
        }
        socket
            .set_read_timeout(Some(remaining))
            .and_then(|_| socket.set_write_timeout(Some(Duration::from_secs(5))))
            .map_err(|e| e.to_string())?;
        let mut qmp = Qmp {
            writer: socket.try_clone().map_err(|e| e.to_string())?,
            reader: std::io::BufReader::new(socket),
        };
        qmp.reply("")?;
        qmp.reader
            .get_mut()
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        qmp.reply("{\"execute\":\"qmp_capabilities\"}\n")?;
        Ok(qmp)
    }
    /// Sends `command` (unless empty) and returns the next greeting or
    /// return value, skipping events.
    fn reply(&mut self, command: &str) -> Result<serde_json::Value, String> {
        if !command.is_empty() {
            self.writer
                .write_all(command.as_bytes())
                .map_err(|e| format!("QMP write: {e}"))?;
        }
        loop {
            let mut line = String::new();
            if std::io::BufRead::read_line(&mut self.reader, &mut line).map_err(|error| {
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut
                {
                    "QMP read: timed out waiting for a reply".to_string()
                } else {
                    format!("QMP read: {error}")
                }
            })? == 0
            {
                return Err("QMP closed".into());
            }
            let value: serde_json::Value =
                serde_json::from_str(&line).map_err(|e| format!("QMP reply: {e}"))?;
            if value.get("QMP").is_some() || value.get("return").is_some() {
                return Ok(value);
            }
            if let Some(error) = value.get("error") {
                return Err(format!("QMP error: {error}"));
            }
        }
    }
}
impl VmProcess {
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
        vm.launch.validate_for(options)?;
        crate::dependencies::require_vm(options, &vm.launch)?;
        crate::storage::validate_boot_display(vm, bundle)?;
        let initial_size = initial_size(options, &vm.launch)
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
        let layout = RamLayout::q35(ram_size);
        let bootstrap = options.bootstrap_gpa.unwrap_or((layout.low / 2) & !4095);
        if bootstrap < 0x100000
            || !bootstrap.is_multiple_of(4096)
            || bootstrap
                .checked_add(4096)
                .is_none_or(|end| end > layout.low)
        {
            return Err("bootstrap GPA must be page aligned and inside VM RAM below 4 GiB".into());
        }
        let (ram_path, ram_memory) = guest_ram(ram_path, ram_size)?;
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
        let serial = File::create(runtime_dir.join("serial.log")).map_err(|e| e.to_string())?;
        let stderr = File::create(runtime_dir.join("qemu.log")).map_err(|e| e.to_string())?;
        let mut cmd = qemu_command(&options.qemu);
        cmd.arg("-name")
            .arg(name_option(&vm.name))
            .arg("-machine")
            .arg(format!(
                "q35,memory-backend=shared,max-ram-below-4g=4G{}",
                crate::stealth::machine_options(&vm.stealth)
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
            .arg(crate::stealth::smp_option(&vm.stealth, vm.cpus))
            .arg("-kernel")
            .arg(&bundle.kernel)
            .arg("-drive")
            .arg(format!(
                "file={},format=qcow2,if=virtio,id=osdisk,node-name=antinomie-disk",
                qemu_path(disk)?
            ))
            .arg("-qmp")
            .arg(format!("unix:{},server=on,wait=off", qemu_path(&qmp_path)?))
            .args(["-monitor", "none", "-serial", "stdio"])
            .stdin(Stdio::null())
            .stdout(Stdio::from(serial))
            .stderr(Stdio::from(stderr));
        if incoming {
            cmd.args(["-S", "-incoming", "defer"]);
        }
        // Guests from revision 13 (Antinomie 0.3.0) size their telemetry rings
        // from the kernel command line; older guests keep 256 KiB rings.
        let mut boot = bundle.clone();
        if bundle
            .antinomie_revision
            .is_some_and(|revision| revision >= 13)
        {
            boot.kernel_append
                .push_str(&format!(" antinomie_ring_kib={}", vm.transport.ring_kib));
        }
        apply_launch_settings(&mut cmd, options, &vm.launch, &vm.stealth, &boot, bootstrap)?;
        crate::stealth::apply(&mut cmd, &vm.stealth, &runtime_dir)?;
        if let Some(initrd) = &bundle.initrd {
            cmd.arg("-initrd").arg(initrd);
        }
        if let Some(netdev) = user_network_backend(vm) {
            // Network captures attach a filter-dump to net0 over QMP.
            cmd.args(["-netdev", netdev, "-device"])
                .arg(crate::stealth::nic_option(&vm.stealth));
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
            ram_size,
            qmp_path,
        };
        if let Some((sizing, (width, height))) = initial_size {
            process.set_initial_window_size(sizing, width, height)?;
        }
        cleanup.started = true;
        if let Some(cleanup) = socket_cleanup.as_mut() {
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
        let mut qmp = Qmp::connect(&self.qmp_path, Duration::from_secs(60)).map_err(|error| {
            format!(
                "QMP connect for RAM layout: {error}{}",
                qemu_log_hint(&self.runtime_dir)
            )
        })?;
        let mtree = qmp.reply(
            "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"info mtree\"}}\n",
        )?;
        let mtree = mtree["return"]
            .as_str()
            .ok_or("QMP memory map is not text")?;
        let layout = RamLayout::q35(self.ram_size);
        let found = RamLayout::from_mtree(mtree)?;
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
        let mut qmp = Qmp::connect(&self.qmp_path, Duration::from_secs(2))
            .map_err(|error| format!("QMP connect: {error}"))?;
        let reply = qmp.reply(&format!("{command}\n"))?;
        Ok(reply.get("return").cloned().unwrap_or_default())
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
        let output = Command::new(&options.qemu)
            .arg("--version")
            .output()
            .map_err(|e| format!("QEMU compatibility version: {e}"))?;
        if !output.status.success() || output.stdout.len() > 8192 {
            return Err("QEMU compatibility version is unavailable".into());
        }
        let acceleration = if options.force_tcg || vm.launch.acceleration == VmAcceleration::Tcg {
            "tcg"
        } else if Path::new("/dev/kvm").exists() {
            "kvm"
        } else {
            "tcg"
        };
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
        let mut value = serde_json::json!({"launch_policy":2,"host_identity":host_identity,"qemu":String::from_utf8_lossy(&output.stdout),"machine":"q35,max-ram-below-4g=4G","cpus":vm.cpus,"ram_mib":vm.ram_mib,"nat":vm.nat,"launch":vm.launch,"transport":vm.transport,"acceleration":acceleration,"force_tcg":options.force_tcg,"headless":options.headless,"bootstrap_gpa":options.bootstrap_gpa,"bundle_identity":bundle.base_identity,"kernel_append":bundle.kernel_append,"kernel_version":bundle.kernel_version});
        // Keep pre-isolation checkpoints compatible for unchanged network setups.
        if vm.isolated_network {
            value["isolated_network"] = serde_json::Value::Bool(true);
        }
        let digest = Sha256::digest(serde_json::to_vec(&value).map_err(|e| e.to_string())?);
        Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }
    pub fn save_state(&self, path: &Path) -> Result<(), String> {
        if self.qmp(&serde_json::json!({"execute":"query-status"}))?["running"].as_bool()
            != Some(false)
        {
            return Err("memory capture requires paused guest execution".into());
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("snapshot memory file: {e}"))?;
        self.transfer_state(file, false)
    }
    pub fn load_state(&self, path: &Path) -> Result<(), String> {
        let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !metadata.file_type().is_file() || metadata.len() == 0 {
            return Err("snapshot memory file must be a nonempty regular file".into());
        }
        self.transfer_state(File::open(path).map_err(|e| e.to_string())?, true)?;
        if self.qmp(&serde_json::json!({"execute":"query-status"}))?["running"].as_bool()
            != Some(false)
        {
            return Err("incoming migration unexpectedly started execution".into());
        }
        Ok(())
    }
    fn transfer_state(&self, mut file: File, incoming: bool) -> Result<(), String> {
        let mut qmp = Qmp::connect(&self.qmp_path, Duration::from_secs(2))?;
        if !incoming {
            qmp.reply("{\"execute\":\"migrate-set-capabilities\",\"arguments\":{\"capabilities\":[{\"capability\":\"x-ignore-shared\",\"state\":false}]}}\n")?;
            let capabilities = qmp.reply("{\"execute\":\"query-migrate-capabilities\"}\n")?;
            if capabilities["return"]
                .as_array()
                .and_then(|values| {
                    values
                        .iter()
                        .find(|value| value["capability"].as_str() == Some("x-ignore-shared"))
                })
                .and_then(|value| value["state"].as_bool())
                != Some(false)
            {
                return Err("QEMU cannot guarantee capture of shared guest RAM".into());
            }
        }
        let (mut host, guest) = UnixStream::pair().map_err(|e| e.to_string())?;
        host.set_read_timeout(Some(Duration::from_secs(30)))
            .and_then(|_| host.set_write_timeout(Some(Duration::from_secs(30))))
            .map_err(|e| e.to_string())?;
        let cancel = host.try_clone().map_err(|e| e.to_string())?;
        qmp.send_fd(&guest)?;
        drop(guest);
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("antinomie-vm-state".into())
            .spawn(move || {
                let result = (|| -> Result<(), String> {
                    let mut buffer = vec![0u8; 256 * 1024];
                    loop {
                        let used = if incoming {
                            file.read(&mut buffer)
                        } else {
                            host.read(&mut buffer)
                        }
                        .map_err(|e| format!("snapshot state stream read: {e}"))?;
                        if used == 0 {
                            break;
                        }
                        if incoming {
                            host.write_all(&buffer[..used])
                        } else {
                            file.write_all(&buffer[..used])
                        }
                        .map_err(|e| format!("snapshot state stream write: {e}"))?;
                    }
                    if incoming {
                        host.shutdown(std::net::Shutdown::Write)
                            .map_err(|e| e.to_string())?;
                    } else {
                        file.sync_all()
                            .map_err(|e| format!("snapshot state durability: {e}"))?;
                    }
                    Ok(())
                })();
                let _ = sender.send(result);
            })
            .map_err(|e| format!("snapshot state worker: {e}"))?;
        let result = (|| -> Result<(), String> {
            let operation = if incoming {
                "migrate-incoming"
            } else {
                "migrate"
            };
            qmp.reply(&format!(
                "{}\n",
                serde_json::json!({"execute":operation,"arguments":{"uri":"fd:antinomie-state"}})
            ))?;
            let deadline = std::time::Instant::now() + Duration::from_secs(300);
            let mut stream_complete = false;
            loop {
                if !stream_complete {
                    match receiver.try_recv() {
                        Ok(result) => {
                            result?;
                            stream_complete = true;
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => {}
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            return Err("snapshot state worker disconnected".into());
                        }
                    }
                }
                let migration = qmp.reply("{\"execute\":\"query-migrate\"}\n")?;
                match migration["return"]["status"].as_str() {
                    Some("completed") if stream_complete => return Ok(()),
                    Some("failed" | "cancelled") => {
                        return Err(format!(
                            "QEMU snapshot migration failed: {}",
                            migration["return"]
                        ));
                    }
                    _ => {}
                }
                if std::time::Instant::now() >= deadline {
                    return Err("QEMU snapshot migration exceeded 300 seconds".into());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        })();
        if result.is_err() {
            let _ = qmp.reply("{\"execute\":\"migrate_cancel\"}\n");
            let _ = cancel.shutdown(std::net::Shutdown::Both);
        }
        worker
            .join()
            .map_err(|_| "snapshot state worker panicked")?;
        result
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
        if self.qmp_path.parent() != Some(self.runtime_dir.as_path())
            && let Some(parent) = self.qmp_path.parent()
        {
            let _ = std::fs::remove_dir(parent);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
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
                ram_size: 64 * 1024 * 1024,
                qmp_path,
            };
            process
                .qmp(&serde_json::json!({"execute":"query-status"}))
                .unwrap();
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
    use crate::api::{DisplayResolution, GuestProfile};

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
            &crate::stealth::StealthProfile::transparent(),
            &bundle(graphical),
            0x40000000,
        )?;
        Ok(command
            .get_args()
            .map(|arg| arg.to_str().unwrap().to_owned())
            .collect())
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
                    let args =
                        launch_args(&options, &VmLaunchOptions::default(), graphical).unwrap();
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
    fn ram_layout_follows_q35_split() {
        const MIB: u64 = 1024 * 1024;
        assert_eq!(
            RamLayout::q35(2048 * MIB),
            RamLayout {
                low: 2048 * MIB,
                high: 0
            }
        );
        assert_eq!(
            RamLayout::q35(2815 * MIB),
            RamLayout {
                low: 2815 * MIB,
                high: 0
            }
        );
        assert_eq!(
            RamLayout::q35(2816 * MIB),
            RamLayout {
                low: 2048 * MIB,
                high: 768 * MIB
            }
        );
        assert_eq!(
            RamLayout::q35(3072 * MIB),
            RamLayout {
                low: 2048 * MIB,
                high: 1024 * MIB
            }
        );
        assert_eq!(
            RamLayout::q35(8192 * MIB),
            RamLayout {
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
    fn owned_process_is_reaped_on_drop() {
        let child = Command::new("sleep").arg("60").spawn().unwrap();
        let pid = child.id();
        let process = VmProcess {
            child,
            ram_path: "/nonexistent/ram".into(),
            _ram_memory: None,
            runtime_dir: "/nonexistent".into(),
            bootstrap: 0,
            ram_size: 0,
            qmp_path: "/nonexistent/qmp".into(),
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
            ram_size: 0,
            qmp_path: "/nonexistent/qmp".into(),
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
        assert!(start.elapsed() < Duration::from_secs(1));
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
                            ..VmLaunchOptions::default()
                        };
                        let mut command = Command::new("qemu-system-x86_64");
                        apply_launch_settings(
                            &mut command,
                            &options,
                            &launch,
                            &crate::stealth::StealthProfile::transparent(),
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
}
