//! QEMU base builder (ANT-T0028): builds a base inside a Debian VM so the host
//! needs only QEMU and curl.
//!
//! The builder boots Debian's official genericcloud image (its SHA-512 is taken
//! from Debian's `SHA512SUMS` over HTTPS). On first use a cached tools overlay
//! is prepared: cloud-init installs the build packages and the VM powers off.
//! Each build then boots a throw-away overlay of it. A loopback HTTP server
//! with a random path token serves the cloud-init seed, the kit, the kernel
//! tarball and the job, and receives the bundle files; the guest runs the kit's
//! orchestrator as root and powers off. Build output comes over a second serial
//! port (ttyS1) as lines prefixed with `ANTINOMIE-BUILD: `.

use crate::build::run_streaming;
use sha2::{Digest, Sha256, Sha512};
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const CLOUD_BASE: &str = "https://cloud.debian.org/images/cloud/trixie/latest";
const CLOUD_IMAGE: &str = "debian-13-genericcloud-amd64.qcow2";
const LINE_PREFIX: &str = "ANTINOMIE-BUILD: ";
/// Packages the builder needs for the kit (kernel, BusyBox and Debian images).
const TOOL_PACKAGES: &[&str] = &[
    "build-essential",
    "bc",
    "bison",
    "flex",
    "libelf-dev",
    "libssl-dev",
    "openssl",
    "dwarves",
    "python3",
    "dpkg-dev",
    "patch",
    "kmod",
    "cpio",
    "xz-utils",
    "gzip",
    "tar",
    "curl",
    "ca-certificates",
    "e2fsprogs",
    "libarchive13t64",
    "qemu-utils",
    "busybox-static",
    "mmdebstrap",
    "debian-archive-keyring",
];
/// Bundle files the guest may upload; `provenance.tar` is unpacked on the host.
const OUTPUT_FILES: &[&str] = &[
    "bundle.json",
    "kernel",
    "kernel.config",
    "initrd.gz",
    "base.qcow2",
    "provenance.tar",
    "kernel.tar",
];
const TOOLS_TIMEOUT: Duration = Duration::from_secs(90 * 60);
const BUILD_TIMEOUT: Duration = Duration::from_secs(10 * 60 * 60);

/// Everything one QEMU build needs.
pub(crate) struct QemuBuild<'a> {
    pub curl: &'a Path,
    pub qemu: &'a Path,
    pub qemu_img: &'a Path,
    /// `<data>/build`: builder images, overlays and job directories live here.
    pub root: &'a Path,
    pub kit: &'a Path,
    pub orig: &'a Path,
    pub job: &'a serde_json::Value,
    pub mirror: &'a str,
    pub proxy: &'a str,
    /// Cached kernel to reuse if present; a kernel built in the VM is stored here.
    pub kernel_cache: &'a Path,
    /// Empty directory that receives the bundle.
    pub output: &'a Path,
    pub cancel: &'a AtomicBool,
}

impl QemuBuild<'_> {
    pub(crate) fn run(&self, mut on_line: impl FnMut(&str)) -> Result<(), String> {
        let builder = self.root.join("builder");
        fs::create_dir_all(&builder).map_err(|e| format!("{}: {e}", builder.display()))?;
        let image = self.cloud_image(&builder, &mut on_line)?;
        let tools = self.tools_overlay(&builder, &image, &mut on_line)?;
        let job = self
            .root
            .join(format!("qemu-job-{}", crate::storage::unique_id()));
        fs::create_dir_all(&job).map_err(|e| format!("{}: {e}", job.display()))?;
        let result = self.build(&job, &tools, &mut on_line);
        let _ = fs::remove_dir_all(&job);
        result
    }

    /// The cached cloud image, downloaded and verified once.
    fn cloud_image(
        &self,
        builder: &Path,
        on_line: &mut impl FnMut(&str),
    ) -> Result<PathBuf, String> {
        if let Some(cached) = fs::read_dir(builder)
            .map_err(|e| e.to_string())?
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension().is_some_and(|ext| ext == "qcow2")
                    && path
                        .file_name()
                        .is_some_and(|name| name.to_string_lossy().starts_with("cloud-"))
                    && path.with_extension("verified").is_file()
            })
            .max()
        {
            return Ok(cached);
        }
        on_line("downloading the Debian 13 cloud image for the builder VM");
        let base = self.cloud_mirror()?;
        on_line(&format!("cloud image mirror {base}"));
        let sums_path = builder.join("SHA512SUMS");
        let mut child = crate::distribution::spawn_download(
            self.curl,
            &format!("{base}/SHA512SUMS"),
            &sums_path,
        )?;
        self.wait_child(&mut child, "SHA512SUMS download", |_| {})?;
        let sums = fs::read_to_string(&sums_path).map_err(|e| e.to_string())?;
        let _ = fs::remove_file(&sums_path);
        let expected = sums
            .lines()
            .find_map(|line| {
                let (hash, name) = line.split_once("  ")?;
                (name.trim() == CLOUD_IMAGE
                    && hash.len() == 128
                    && hash.bytes().all(|b| b.is_ascii_hexdigit()))
                .then(|| hash.to_ascii_lowercase())
            })
            .ok_or("Debian's SHA512SUMS does not list the genericcloud amd64 image")?;
        let target = builder.join(format!("cloud-{}.qcow2", &expected[..16]));
        let partial = builder.join("cloud.part");
        let mut child = crate::distribution::spawn_download(
            self.curl,
            &format!("{base}/{CLOUD_IMAGE}"),
            &partial,
        )?;
        let mut reported = 0;
        self.wait_child(&mut child, "cloud image download", |received| {
            if received >= reported + (64 << 20) {
                reported = received - received % (64 << 20);
                on_line(&format!("cloud image download {} MiB", reported >> 20));
            }
        })?;
        let mut file = File::open(&partial).map_err(|e| e.to_string())?;
        let mut digest = Sha512::new();
        let mut chunk = vec![0; 1 << 20];
        loop {
            let len = file.read(&mut chunk).map_err(|e| e.to_string())?;
            if len == 0 {
                break;
            }
            digest.update(&chunk[..len]);
        }
        if format!("{:x}", digest.finalize()) != expected {
            let _ = fs::remove_file(&partial);
            return Err("the downloaded cloud image does not match Debian's SHA-512".into());
        }
        fs::rename(&partial, &target).map_err(|e| e.to_string())?;
        fs::write(target.with_extension("verified"), &expected).map_err(|e| e.to_string())?;
        on_line(&format!(
            "cloud image verified (SHA-512 {}…)",
            &expected[..16]
        ));
        Ok(target)
    }

    /// cloud.debian.org redirects image downloads to a mirror and often resets
    /// connections itself; resolve the image's redirect once (with retries) and
    /// use that mirror for both the checksums and the image. Integrity rests on the SHA-512 check.
    fn cloud_mirror(&self) -> Result<String, String> {
        let output = Command::new(self.curl)
            .args([
                "-sSIL",
                "--retry",
                "10",
                "--retry-delay",
                "1",
                "--retry-all-errors",
            ])
            .args([
                "--connect-timeout",
                "30",
                "-o",
                "/dev/null",
                "-w",
                "%{url_effective}",
            ])
            .arg(format!("{CLOUD_BASE}/{CLOUD_IMAGE}"))
            .output()
            .map_err(|e| format!("curl: {e}"))?;
        let effective = String::from_utf8_lossy(&output.stdout).trim().to_string();
        match effective.strip_suffix(&format!("/{CLOUD_IMAGE}")) {
            Some(base) if output.status.success() && base.starts_with("https://") => {
                Ok(base.to_string())
            }
            _ => Err(format!(
                "cannot reach cloud.debian.org: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )),
        }
    }

    /// The cached overlay with the build packages installed, prepared on first use.
    fn tools_overlay(
        &self,
        builder: &Path,
        image: &Path,
        on_line: &mut impl FnMut(&str),
    ) -> Result<PathBuf, String> {
        let mut digest = Sha256::new();
        digest.update(image.file_name().unwrap_or_default().as_encoded_bytes());
        digest.update(TOOL_PACKAGES.join(" "));
        let key = format!("{:x}", digest.finalize());
        let overlay = builder.join(format!("tools-{}.qcow2", &key[..16]));
        if overlay.with_extension("ready").is_file() {
            // The overlay names its backing image by absolute path; keep that
            // valid if the data directory moved (header-only, unsafe rebase).
            let rebased = Command::new(self.qemu_img)
                .args(["rebase", "-u", "-F", "qcow2", "-b"])
                .arg(image)
                .arg(&overlay)
                .output()
                .map_err(|e| format!("qemu-img: {e}"))?;
            if rebased.status.success() {
                return Ok(overlay);
            }
            on_line("the cached builder tools disk is damaged; preparing it again");
        }
        for entry in fs::read_dir(builder).map_err(|e| e.to_string())?.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("tools-") {
                let _ = fs::remove_file(entry.path());
            }
        }
        on_line("preparing the builder VM: installing build packages (first build only)");
        self.qemu_img_create(&overlay, image, "12G")?;
        let mut server = Server::start(self.cancel)?;
        let script = format!(
            "{}\n{}\nexport DEBIAN_FRONTEND=noninteractive\napt-get update\napt-get install -y --no-install-recommends {}\napt-get clean\nfstrim -av || true\n",
            apt_proxy(self.proxy),
            apt_mirror(self.mirror),
            TOOL_PACKAGES.join(" ")
        );
        server.add_text("user-data", user_data(&server.base(), &script));
        server.add_text(
            "meta-data",
            format!(
                "instance-id: antinomie-tools-{}\nlocal-hostname: antinomie-builder\n",
                &key[..16]
            ),
        );
        let result = self.boot(&overlay, &server, TOOLS_TIMEOUT, on_line);
        let ok = server.status().as_deref() == Some("ok");
        server.stop();
        match result {
            Ok(()) if ok => {
                fs::write(overlay.with_extension("ready"), TOOL_PACKAGES.join("\n"))
                    .map_err(|e| e.to_string())?;
                Ok(overlay)
            }
            Ok(()) => {
                let _ = fs::remove_file(&overlay);
                Err("the builder VM did not finish installing its build packages".into())
            }
            Err(error) => {
                let _ = fs::remove_file(&overlay);
                Err(error)
            }
        }
    }

    fn build(
        &self,
        job: &Path,
        tools: &Path,
        on_line: &mut impl FnMut(&str),
    ) -> Result<(), String> {
        let disk = job.join("disk.qcow2");
        self.qemu_img_create(&disk, tools, "80G")?;
        let kit_tar = job.join("kit.tar");
        crate::kit::write_tar(self.kit, &kit_tar)?;
        let orig_name = self
            .orig
            .file_name()
            .ok_or("kernel tarball has no name")?
            .to_string_lossy()
            .into_owned();
        let mut server = Server::start(self.cancel)?;
        server.add_file("kit.tar", kit_tar);
        server.add_file(&format!("inputs/{orig_name}"), self.orig.to_path_buf());
        server.add_text(
            "job.json",
            serde_json::to_string(self.job).map_err(|e| e.to_string())?,
        );
        if self.kernel_cache.is_file() {
            server.add_file("kernel.tar", self.kernel_cache.to_path_buf());
        }
        server.accept_uploads(self.output);
        let script = format!(
            r#"{proxy}
mkdir -p /build/kit /build/inputs
curl -fsS "$base/kit.tar" | tar -x -C /build/kit
curl -fsS -o "/build/inputs/{orig}" "$base/inputs/{orig}"
curl -fsS -o /build/job.json "$base/job.json"
cached=0
if curl -fsS -o /build/kernel.tar "$base/kernel.tar" 2>/dev/null; then cached=1; else rm -f /build/kernel.tar; fi
python3 /build/kit/scripts/build-base.py --job /build/job.json --inputs /build/inputs \
    --work /build/work --output /build/out --jobs "$(nproc)" --kernel-cache /build/kernel.tar
cd /build/out
if [ -d provenance ]; then tar -cf provenance.tar provenance; fi
if [ "$cached" = 0 ] && [ -f /build/kernel.tar ]; then mv /build/kernel.tar kernel.tar; fi
for name in {outputs}; do
    if [ -f "$name" ]; then
        curl -fsS -H 'Expect:' -T "$name" "$base/out/$name"
    fi
done
"#,
            proxy = apt_proxy(self.proxy),
            orig = orig_name,
            outputs = OUTPUT_FILES.join(" ")
        );
        server.add_text("user-data", user_data(&server.base(), &script));
        server.add_text(
            "meta-data",
            format!(
                "instance-id: antinomie-build-{}\nlocal-hostname: antinomie-builder\n",
                crate::storage::unique_id()
            ),
        );
        let result = self.boot(&disk, &server, BUILD_TIMEOUT, on_line);
        let status = server.status();
        server.stop();
        result?;
        match status.as_deref() {
            Some("ok") => {}
            Some(other) => return Err(format!("build in the builder VM failed: {other}")),
            None => return Err("the builder VM stopped without reporting a result".into()),
        }
        let built_kernel = self.output.join("kernel.tar");
        if built_kernel.is_file() {
            let parent = self
                .kernel_cache
                .parent()
                .ok_or("kernel cache has no parent")?;
            fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
            fs::rename(&built_kernel, self.kernel_cache).map_err(|e| e.to_string())?;
            on_line("kernel stored in the cache for later builds");
        }
        let provenance = self.output.join("provenance.tar");
        if provenance.is_file() {
            let status = Command::new("tar")
                .arg("-xf")
                .arg(&provenance)
                .arg("-C")
                .arg(self.output)
                .status()
                .map_err(|e| format!("tar: {e}"))?;
            if !status.success() {
                return Err("unpacking the build provenance failed".into());
            }
            fs::remove_file(&provenance).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn qemu_img_create(&self, overlay: &Path, backing: &Path, size: &str) -> Result<(), String> {
        let output = Command::new(self.qemu_img)
            .args(["create", "-q", "-f", "qcow2", "-F", "qcow2", "-b"])
            .arg(backing)
            .arg(overlay)
            .arg(size)
            .output()
            .map_err(|e| format!("qemu-img: {e}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "qemu-img create failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }

    /// Boot the builder on `disk` until it powers off, forwarding prefixed lines.
    fn boot(
        &self,
        disk: &Path,
        server: &Server,
        timeout: Duration,
        on_line: &mut impl FnMut(&str),
    ) -> Result<(), String> {
        let (accel, cpu) = if kvm_usable() {
            ("kvm", "host")
        } else {
            on_line(
                "no KVM access: the builder VM runs without hardware acceleration and can take many hours",
            );
            ("tcg", "max")
        };
        let cpus = thread::available_parallelism().map_or(2, |n| n.get());
        // ttyS0 is the guest console (kernel, systemd, login prompt) and goes to a
        // file kept after the job; the build log uses ttyS1, where no getty runs.
        let serial_log = self.root.join("builder-console.log");
        let mut command = Command::new(self.qemu);
        command
            .args(["-machine", &format!("q35,accel={accel}")])
            .args(["-cpu", cpu, "-smp", &cpus.to_string()])
            .args(["-m", &builder_ram_mib().to_string()])
            .arg("-drive")
            .arg(format!(
                "file={},if=virtio,format=qcow2,discard=unmap,detect-zeroes=unmap",
                disk.display()
            ))
            .args([
                "-netdev",
                "user,id=net0",
                "-device",
                "virtio-net-pci,netdev=net0",
            ])
            .arg("-smbios")
            .arg(format!("type=1,serial=ds=nocloud;s={}/", server.base()))
            .args(["-display", "none", "-monitor", "none", "-no-reboot"])
            .arg("-serial")
            .arg(format!("file:{}", serial_log.display()))
            .args(["-serial", "stdio"]);
        let deadline = Instant::now() + timeout;
        let (stop, expired, finished) = (
            AtomicBool::new(false),
            AtomicBool::new(false),
            AtomicBool::new(false),
        );
        let result = thread::scope(|scope| {
            // run_streaming polls one flag: raise it on cancel or at the deadline.
            scope.spawn(|| {
                while !finished.load(Ordering::Relaxed) {
                    if self.cancel.load(Ordering::Relaxed) {
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                    if Instant::now() >= deadline {
                        expired.store(true, Ordering::Relaxed);
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                    thread::sleep(Duration::from_millis(200));
                }
            });
            let result = run_streaming(&mut command, "builder VM", &stop, |line| {
                let line = line.trim_end_matches('\r');
                if let Some((_, text)) = line.split_once(LINE_PREFIX) {
                    on_line(text);
                }
            });
            finished.store(true, Ordering::Relaxed);
            result
        });
        if expired.load(Ordering::Relaxed) {
            return Err(format!(
                "the builder VM did not finish within {} minutes; console log {}",
                timeout.as_secs() / 60,
                serial_log.display()
            ));
        }
        result.map_err(|error| format!("{error}; console log {}", serial_log.display()))
    }

    /// Wait for a download; `progress` gets the partial file's size.
    fn wait_child(
        &self,
        child: &mut std::process::Child,
        what: &str,
        mut progress: impl FnMut(u64),
    ) -> Result<(), String> {
        let partial = self.root.join("builder/cloud.part");
        loop {
            progress(fs::metadata(&partial).map_or(0, |meta| meta.len()));
            if self.cancel.load(Ordering::Relaxed) {
                let _ = child.kill();
                let _ = child.wait();
                return Err("build cancelled".into());
            }
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                return if status.success() {
                    Ok(())
                } else {
                    Err(format!("{what} failed: {status}"))
                };
            }
            thread::sleep(Duration::from_millis(200));
        }
    }
}

fn kvm_usable() -> bool {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

/// Half of this host's memory, between 2 and 8 GiB.
fn builder_ram_mib() -> u64 {
    let total_kib = fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("MemTotal:"))
                .and_then(|rest| rest.split_whitespace().next()?.parse::<u64>().ok())
        })
        .unwrap_or(4 << 20);
    (total_kib / 2 / 1024).clamp(2048, 8192)
}

fn apt_proxy(proxy: &str) -> String {
    if proxy.is_empty() {
        String::new()
    } else {
        format!(
            "printf 'Acquire::http::Proxy \"%s\";\\nAcquire::https::Proxy \"%s\";\\n' '{proxy}' '{proxy}' > /etc/apt/apt.conf.d/90antinomie-proxy"
        )
    }
}

/// Point the cloud image's apt sources at the chosen mirror (security stays).
/// Debian's cloud images name their mirror in `/etc/apt/mirrors/debian.list`
/// (`mirror+file:` sources); older layouts list it in `debian.sources`.
fn apt_mirror(mirror: &str) -> String {
    let mirror = mirror.trim_end_matches('/');
    if mirror == crate::build::DEFAULT_MIRROR {
        String::new()
    } else {
        format!(
            "if [ -f /etc/apt/mirrors/debian.list ]; then printf '%s\\n' '{mirror}' > /etc/apt/mirrors/debian.list; \
             else sed -i 's|http://deb.debian.org/debian$|{mirror}|' /etc/apt/sources.list.d/debian.sources; fi"
        )
    }
}

/// cloud-config that runs `script` with bash, reports its status and powers off.
fn user_data(base: &str, script: &str) -> String {
    let body = format!("#!/bin/bash\nset -euo pipefail\nbase={base}\n{script}");
    let indented: String = body.lines().map(|line| format!("      {line}\n")).collect();
    format!(
        r#"#cloud-config
write_files:
  - path: /usr/local/sbin/antinomie-step
    permissions: '0755'
    content: |
{indented}runcmd:
  - - bash
    - -c
    - |
      set -o pipefail
      if /usr/local/sbin/antinomie-step 2>&1 | sed -u 's/^/{LINE_PREFIX}/' > /dev/ttyS1; then
          curl -fsS -H 'Expect:' --data-binary ok -X PUT {base}/status || true
      else
          echo '{LINE_PREFIX}build step failed' > /dev/ttyS1
          curl -fsS -H 'Expect:' --data-binary failed -X PUT {base}/status || true
      fi
      systemctl poweroff
"#
    )
}

/// Minimal loopback HTTP server for the builder VM (reached at 10.0.2.2).
struct Server {
    port: u16,
    token: String,
    state: Arc<Mutex<ServerState>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
#[derive(Default)]
struct ServerState {
    texts: std::collections::BTreeMap<String, String>,
    files: std::collections::BTreeMap<String, PathBuf>,
    uploads: Option<PathBuf>,
    status: Option<String>,
}
impl Server {
    fn start(_cancel: &AtomicBool) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let token = format!(
            "{:x}",
            Sha256::digest(format!(
                "{}-{:?}-{}",
                crate::storage::unique_id(),
                Instant::now(),
                std::process::id()
            ))
        );
        let state = Arc::new(Mutex::new(ServerState::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let (thread_state, thread_stop, thread_token) =
            (state.clone(), stop.clone(), token.clone());
        let thread = thread::Builder::new()
            .name("antinomie-builder-http".into())
            .spawn(move || {
                while !thread_stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let state = thread_state.clone();
                            let token = thread_token.clone();
                            thread::spawn(move || {
                                let _ = serve(stream, &token, &state);
                            });
                        }
                        Err(_) => thread::sleep(Duration::from_millis(50)),
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            port,
            token,
            state,
            stop,
            thread: Some(thread),
        })
    }
    /// The URL the guest uses (QEMU user networking maps 10.0.2.2 to loopback).
    fn base(&self) -> String {
        format!("http://10.0.2.2:{}/{}", self.port, self.token)
    }
    fn add_text(&mut self, path: &str, text: String) {
        self.state.lock().unwrap().texts.insert(path.into(), text);
    }
    fn add_file(&mut self, path: &str, file: PathBuf) {
        self.state.lock().unwrap().files.insert(path.into(), file);
    }
    fn accept_uploads(&mut self, directory: &Path) {
        self.state.lock().unwrap().uploads = Some(directory.to_path_buf());
    }
    fn status(&self) -> Option<String> {
        self.state.lock().unwrap().status.clone()
    }
    fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn respond(stream: &mut TcpStream, code: &str, body: &[u8]) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {code}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)
}

fn serve(stream: TcpStream, token: &str, state: &Mutex<ServerState>) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut stream = stream;
    let mut request = String::new();
    reader.read_line(&mut request)?;
    let mut length: Option<u64> = None;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 || header == "\r\n" || header == "\n" {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().ok();
        }
    }
    let mut parts = request.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let Some(path) = target
        .strip_prefix('/')
        .and_then(|rest| rest.strip_prefix(token))
        .and_then(|rest| rest.strip_prefix('/'))
    else {
        return respond(&mut stream, "404 Not Found", b"");
    };
    let path = path.split('?').next().unwrap_or_default().to_string();
    match method {
        "GET" | "HEAD" => {
            let (text, file) = {
                let state = state.lock().unwrap();
                (
                    state.texts.get(&path).cloned(),
                    state.files.get(&path).cloned(),
                )
            };
            if let Some(text) = text {
                return respond(&mut stream, "200 OK", text.as_bytes());
            }
            let Some(file) = file else {
                return respond(&mut stream, "404 Not Found", b"");
            };
            let mut source = File::open(&file)?;
            let size = source.metadata()?.len();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n"
            )?;
            if method == "GET" {
                std::io::copy(&mut source, &mut stream)?;
            }
            Ok(())
        }
        "PUT" => {
            let length = length.unwrap_or(0);
            if path == "status" {
                let mut body = String::new();
                reader.take(length.min(4096)).read_to_string(&mut body)?;
                state.lock().unwrap().status = Some(body.trim().to_string());
                return respond(&mut stream, "200 OK", b"");
            }
            let name = path.strip_prefix("out/").unwrap_or_default();
            let directory = state.lock().unwrap().uploads.clone();
            let (Some(directory), true) = (directory, OUTPUT_FILES.contains(&name)) else {
                return respond(&mut stream, "403 Forbidden", b"");
            };
            let target = directory.join(name);
            let mut file = File::create(&target)?;
            let copied = std::io::copy(&mut (&mut reader).take(length), &mut file)?;
            file.sync_all()?;
            if copied != length {
                let _ = fs::remove_file(&target);
                return respond(&mut stream, "400 Bad Request", b"");
            }
            respond(&mut stream, "200 OK", b"")
        }
        _ => respond(&mut stream, "405 Method Not Allowed", b""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(port: u16, head: &str, body: &[u8]) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).unwrap();
        reply
    }

    #[test]
    fn server_needs_the_token_and_takes_only_listed_uploads() {
        let dir =
            std::env::temp_dir().join(format!("ant-builder-http-{}", crate::storage::unique_id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("source"), b"payload").unwrap();
        let cancel = AtomicBool::new(false);
        let mut server = Server::start(&cancel).unwrap();
        server.add_text("meta-data", "instance-id: x\n".into());
        server.add_file("kit.tar", dir.join("source"));
        let out = dir.join("out");
        fs::create_dir_all(&out).unwrap();
        server.accept_uploads(&out);
        let (port, token) = (server.port, server.token.clone());
        assert!(
            request(
                port,
                &format!("GET /{token}/meta-data HTTP/1.1\r\n\r\n"),
                b""
            )
            .ends_with("instance-id: x\n")
        );
        assert!(
            request(port, &format!("GET /{token}/kit.tar HTTP/1.1\r\n\r\n"), b"")
                .ends_with("payload")
        );
        assert!(
            request(port, "GET /wrong/meta-data HTTP/1.1\r\n\r\n", b"").starts_with("HTTP/1.1 404")
        );
        assert!(
            request(
                port,
                &format!("PUT /{token}/out/kernel HTTP/1.1\r\nContent-Length: 3\r\n\r\n"),
                b"abc"
            )
            .starts_with("HTTP/1.1 200")
        );
        assert_eq!(fs::read(out.join("kernel")).unwrap(), b"abc");
        assert!(
            request(
                port,
                &format!("PUT /{token}/out/../evil HTTP/1.1\r\nContent-Length: 1\r\n\r\n"),
                b"x"
            )
            .starts_with("HTTP/1.1 403")
        );
        assert!(!dir.join("evil").exists());
        request(
            port,
            &format!("PUT /{token}/status HTTP/1.1\r\nContent-Length: 2\r\n\r\n"),
            b"ok",
        );
        assert_eq!(server.status().as_deref(), Some("ok"));
        server.stop();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn user_data_runs_the_step_reports_and_powers_off() {
        let text = user_data("http://10.0.2.2:1/t", "echo hi\n");
        assert!(text.starts_with("#cloud-config\n"));
        assert!(text.contains("      echo hi\n"));
        assert!(text.contains("set -euo pipefail"));
        assert!(text.contains("http://10.0.2.2:1/t/status"));
        assert!(text.contains("systemctl poweroff"));
        assert!(apt_mirror(crate::build::DEFAULT_MIRROR).is_empty());
        let mirror = apt_mirror("http://mirror.example/debian/");
        assert!(mirror.contains(
            "printf '%s\\n' 'http://mirror.example/debian' > /etc/apt/mirrors/debian.list"
        ));
        assert!(apt_proxy("").is_empty());
        assert!(apt_proxy("http://p:3128").contains("Acquire::https::Proxy"));
    }
}
