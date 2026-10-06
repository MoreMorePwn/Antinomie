use crate::{
    api::{BackendOptions, VmConfig},
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
fn qemu_path(path: &Path) -> Result<String, String> {
    Ok(path
        .to_str()
        .ok_or("QEMU composite paths must be UTF-8")?
        .replace(',', ",,"))
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
        let runtime_dir = vm_dir(options, &vm.id)?.join("runtime").join(unique_id());
        private_dir(&runtime_dir).map_err(|e| e.to_string())?;
        let mut cleanup = UnstartedRuntime {
            path: runtime_dir.clone(),
            started: false,
        };
        let ram_path = runtime_dir.join("shared-ram");
        let ram_size = u64::from(vm.ram_mib) * 1024 * 1024;
        let bootstrap = options.bootstrap_gpa.unwrap_or((ram_size / 2) & !4095);
        if bootstrap < 0x100000
            || !bootstrap.is_multiple_of(4096)
            || bootstrap.checked_add(4096).is_none_or(|end| end > ram_size)
        {
            return Err("bootstrap GPA must be page aligned and inside VM RAM".into());
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
            .arg("-accel")
            .arg(if options.force_tcg { "tcg" } else { "kvm" })
            .arg("-kernel")
            .arg(&bundle.kernel)
            .arg("-append")
            .arg(format!(
                "{} antinomie_boot_gpa=0x{bootstrap:x}",
                bundle.kernel_append
            ))
            .arg("-drive")
            .arg(format!(
                "file={},format=qcow2,if=virtio",
                qemu_path(&vm_dir(options, &vm.id)?.join("disk.qcow2"))?
            ))
            .arg("-qmp")
            .arg(format!("unix:{},server=on,wait=off", qemu_path(&qmp_path)?))
            .args(["-monitor", "none", "-serial", "stdio", "-display"])
            .arg(if options.headless { "none" } else { "gtk" })
            .stdin(Stdio::null())
            .stdout(Stdio::from(serial))
            .stderr(Stdio::from(stderr));
        if let Some(initrd) = &bundle.initrd {
            cmd.arg("-initrd").arg(initrd);
        }
        if bundle.guest.as_ref().is_some_and(|guest| guest.graphical) {
            cmd.args(["-vga", "virtio"]);
        }
        if vm.nat {
            cmd.args(["-nic", "user,model=virtio-net-pci"]);
        } else {
            cmd.args(["-nic", "none"]);
        }
        let child = cmd.spawn().map_err(|e| format!("QEMU launch: {e}"))?;
        cleanup.started = true;
        if let Some(cleanup) = socket_cleanup.as_mut() {
            cleanup.started = true;
        }
        Ok(Self {
            child,
            ram_path,
            runtime_dir,
            bootstrap,
            ram_size,
            qmp_path,
        })
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
    fn commas_in_paths_cannot_inject_qemu_options() {
        assert_eq!(
            qemu_path(Path::new("/tmp/a,share=off")).unwrap(),
            "/tmp/a,,share=off"
        );
    }
}
