use crate::{
    api::{BackendOptions, VmAcceleration, VmConfig, VmCpuModel, VmLaunchOptions},
    storage::{Bundle, private_dir, unique_id, vm_dir},
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::{fs::OpenOptionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

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
    if let Some(cpu) = cpu {
        command.args(["-cpu", cpu]);
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
    pub runtime_dir: PathBuf,
    pub bootstrap: u64,
    pub ram_size: u64,
    pub qmp_path: PathBuf,
}
impl VmProcess {
    pub fn launch(
        options: &BackendOptions,
        vm: &VmConfig,
        bundle: &Bundle,
    ) -> Result<Self, String> {
        vm.launch.validate_for(options)?;
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
        let ram = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&ram_path)
            .map_err(|e| e.to_string())?;
        ram.set_len(ram_size).map_err(|e| e.to_string())?;
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
        let mut cmd = Command::new(&options.qemu);
        cmd.arg("-name")
            .arg(&vm.name)
            .args(["-machine", "q35,memory-backend=shared,max-ram-below-4g=4G"])
            .arg("-object")
            .arg(format!(
                "memory-backend-file,id=shared,size={}M,mem-path={},share=on",
                vm.ram_mib,
                qemu_path(&ram_path)?
            ))
            .arg("-m")
            .arg(vm.ram_mib.to_string())
            .arg("-smp")
            .arg(vm.cpus.to_string())
            .arg("-kernel")
            .arg(&bundle.kernel)
            .arg("-drive")
            .arg(format!(
                "file={},format=qcow2,if=virtio",
                qemu_path(&vm_dir(options, &vm.id)?.join("disk.qcow2"))?
            ))
            .arg("-qmp")
            .arg(format!("unix:{},server=on,wait=off", qemu_path(&qmp_path)?))
            .args(["-monitor", "none", "-serial", "stdio"])
            .stdin(Stdio::null())
            .stdout(Stdio::from(serial))
            .stderr(Stdio::from(stderr));
        apply_launch_settings(&mut cmd, options, &vm.launch, bundle, bootstrap)?;
        if let Some(initrd) = &bundle.initrd {
            cmd.arg("-initrd").arg(initrd);
        }
        if vm.nat {
            cmd.args(["-nic", "user,model=virtio-net-pci"]);
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
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let socket = loop {
            match UnixStream::connect(&self.qmp_path) {
                Ok(socket) => break socket,
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Err(error) => return Err(format!("QMP connect for RAM layout: {error}")),
            }
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .and_then(|_| socket.set_write_timeout(Some(Duration::from_secs(5))))
            .map_err(|e| e.to_string())?;
        let mut writer = socket.try_clone().map_err(|e| e.to_string())?;
        let mut reader = std::io::BufReader::new(socket);
        let mut reply = |command: &str| -> Result<serde_json::Value, String> {
            if !command.is_empty() {
                writer
                    .write_all(command.as_bytes())
                    .map_err(|e| format!("QMP write: {e}"))?;
            }
            loop {
                let mut line = String::new();
                if std::io::BufRead::read_line(&mut reader, &mut line)
                    .map_err(|e| format!("QMP read: {e}"))?
                    == 0
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
        };
        reply("")?;
        reply("{\"execute\":\"qmp_capabilities\"}\n")?;
        let mtree = reply(
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
        let _ = std::fs::remove_file(&self.ram_path);
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
    use crate::api::{DisplayResolution, GuestProfile};

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
            &bundle(graphical),
            0x40000000,
        )?;
        Ok(command
            .get_args()
            .map(|arg| arg.to_str().unwrap().to_owned())
            .collect())
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
