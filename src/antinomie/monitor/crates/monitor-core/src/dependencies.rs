//! Runtime prerequisites, checked at startup and again before using a feature.
//! Build tools and optional analysis adapters have their own existing checks.
use crate::{BackendOptions, VmAcceleration, VmLaunchOptions};
pub use install::{
    InstallPlan, KVM_GROUP_COMMAND, KvmAdvice, PACKAGES, PackageManager, kvm_member, package,
};
use rustix::fs::{Access, AtFlags, CWD, OFlags, accessat, fcntl_getfl, fcntl_setfl};
use std::{
    fs::OpenOptions,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

mod install;

const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const PROBE_OUTPUT_SIZE: usize = 16 * 1024;

/// A runtime requirement; availability is independent of the selected feature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dependency {
    Qemu,
    QemuImg,
    Gtk,
    Kvm,
    Curl,
    DebianAccount,
    Bubblewrap,
    Tshark,
    Prlimit,
    Suricata,
    PythonVenv,
    Wireshark,
    /// Zenity, the file chooser of the Explorer and Upload.
    FileChooser,
}

/// One checked requirement, its affected action and a concrete repair hint.
#[derive(Clone, Debug)]
pub struct Check {
    pub dependency: Dependency,
    pub name: &'static str,
    pub purpose: &'static str,
    pub problem: Option<String>,
    pub hint: &'static str,
    /// Only one optional feature needs it; missing it is not a startup problem.
    pub optional: bool,
    /// The tool is installed but older than the app needs; `problem` says which
    /// version is the oldest it can drive.
    pub wrong_version: bool,
}

/// Snapshot of runtime availability. Recheck after changing host packages.
#[derive(Clone, Debug, Default)]
pub struct Report {
    pub checks: Vec<Check>,
    /// The host's package manager, from `/etc/os-release`; `None` if unknown.
    pub package_manager: Option<PackageManager>,
    /// What `/dev/kvm` needs, so the install command can add the group step.
    pub kvm: KvmAdvice,
}

impl Report {
    /// A required check failed; missing optional tools do not count.
    pub fn has_missing(&self) -> bool {
        self.checks
            .iter()
            .any(|check| check.problem.is_some() && !check.optional)
    }

    /// Reject only the listed requirements, preserving unrelated workflows.
    /// Unchecked requirements also reject the action until a check completes.
    pub fn require(&self, required: &[Dependency]) -> Result<(), String> {
        for dependency in required {
            let check = self
                .checks
                .iter()
                .find(|check| check.dependency == *dependency)
                .ok_or("app dependency check has not completed; open Tools > App dependencies")?;
            if let Some(problem) = &check.problem {
                return Err(format!("{}: {problem}. {}", check.name, check.hint));
            }
        }
        Ok(())
    }
}

pub(crate) fn executable(path: &Path) -> Option<PathBuf> {
    let runnable = |candidate: &Path| {
        candidate.is_file() && accessat(CWD, candidate, Access::EXEC_OK, AtFlags::EACCESS).is_ok()
    };
    if path.is_absolute() || path.components().count() > 1 {
        return runnable(path).then(|| path.to_owned());
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join(path))
        .find(|candidate| runnable(candidate))
}

/// Resolve a runnable configured tool, with the Debian/Ubuntu package repair.
pub(crate) fn require_tool(path: &Path, package: &str) -> Result<PathBuf, String> {
    executable(path).ok_or_else(|| {
        format!(
            "{} is missing or not executable; on Debian/Ubuntu: sudo apt install {package}",
            path.display()
        )
    })
}

fn tool(
    dependency: Dependency,
    name: &'static str,
    purpose: &'static str,
    path: &Path,
    hint: &'static str,
) -> Check {
    Check {
        dependency,
        name,
        purpose,
        problem: executable(path)
            .is_none()
            .then(|| format!("{} is missing or not executable", path.display())),
        hint,
        optional: false,
        wrong_version: false,
    }
}

/// The oldest QEMU the app drives. The network capture adds its `filter-dump`
/// object with `object-add` arguments given flat (`qom-type`, `id`, `netdev`,
/// ...), which QEMU accepts from 6.0; earlier releases want them under `props`.
/// Other tools have no minimum here: no code path needs a feature that only a
/// newer TShark or Suricata has.
pub const QEMU_MINIMUM: (u64, u64) = (6, 0);

/// `major.minor` after the word "version" in a `--version` line.
fn version_of(output: &str) -> Option<(u64, u64)> {
    let rest = output.split_once("version")?.1.trim_start();
    let mut numbers = rest
        .split(|ch: char| !ch.is_ascii_digit() && ch != '.')
        .next()?
        .split('.');
    Some((numbers.next()?.parse().ok()?, numbers.next()?.parse().ok()?))
}

/// Why an installed QEMU is too old; an unreadable version is not a problem.
fn qemu_version_problem(qemu: &Path) -> Option<String> {
    let output = probe_output(qemu, &["--version"], PROBE_TIMEOUT).ok()?;
    let found = version_of(output.lines().next()?)?;
    (found < QEMU_MINIMUM).then(|| {
        format!(
            "QEMU {}.{} is older than {}.{}, the oldest this app can drive",
            found.0, found.1, QEMU_MINIMUM.0, QEMU_MINIMUM.1
        )
    })
}

/// Where IDS scans look for Suricata.
pub const SURICATA: &[&str] = &[
    "/usr/bin/suricata",
    "/usr/sbin/suricata",
    "/usr/local/bin/suricata",
];

/// The system Python can create the virtual environment of the Sigma tool;
/// Debian and Ubuntu ship `ensurepip` separately, in python3-venv.
fn venv_problem() -> Option<String> {
    let mut child = match Command::new("/usr/bin/python3")
        .args(["-I", "-c", "import ensurepip, venv"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => return Some(format!("/usr/bin/python3 did not run: {error}")),
    };
    let deadline = Instant::now() + PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return None,
            Ok(Some(_)) => {
                return Some("/usr/bin/python3 cannot create virtual environments".into());
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Some("the Python check did not finish".into());
            }
            Err(error) => return Some(error.to_string()),
        }
    }
}

/// Check the configured runtime tools. The QEMU capability probe is bounded to
/// two seconds and 16 KiB; run this on a worker, never on the UI frame thread.
/// No packages, application data or guest disks are modified.
pub fn check(options: &BackendOptions) -> Report {
    use Dependency::*;
    let mut qemu = tool(
        Qemu,
        "QEMU",
        "Start VMs",
        &options.qemu,
        "On Debian/Ubuntu: sudo apt install qemu-system-x86",
    );
    if qemu.problem.is_none()
        && let Some(problem) = qemu_version_problem(&options.qemu)
    {
        qemu.problem = Some(problem);
        qemu.wrong_version = true;
    }
    let mut checks = vec![
        qemu,
        tool(
            QemuImg,
            "QEMU image tools",
            "Create, reset, inspect and dump VM disks",
            &options.qemu_img,
            "On Debian/Ubuntu: sudo apt install qemu-utils",
        ),
        tool(
            Curl,
            "curl",
            "Download bases and analysis tools",
            &options.curl,
            "On Debian/Ubuntu: sudo apt install curl",
        ),
        tool(
            DebianAccount,
            "virt-customize",
            "Create Debian guest accounts",
            Path::new("virt-customize"),
            "On Debian/Ubuntu: sudo apt install libguestfs-tools",
        ),
        tool(
            Bubblewrap,
            "bubblewrap",
            "Run static analysis and read guest filesystems in the Disks tab",
            Path::new("/usr/bin/bwrap"),
            "On Debian/Ubuntu: sudo apt install bubblewrap",
        ),
        tool(
            Tshark,
            "TShark",
            "Apply Wireshark packet display filters",
            Path::new("tshark"),
            "On Debian/Ubuntu: sudo apt install tshark",
        ),
        tool(
            Prlimit,
            "prlimit",
            "Bound packet-filter, network-triage and Disks reader resources",
            Path::new("prlimit"),
            "On Debian/Ubuntu: sudo apt install util-linux",
        ),
        Check {
            dependency: Wireshark,
            name: "Wireshark",
            purpose: "Inspect saved captures in Wireshark, outside Antinomie",
            problem: executable(Path::new("wireshark"))
                .is_none()
                .then(|| "wireshark is missing or not executable".to_owned()),
            hint: "On Debian/Ubuntu: sudo apt install wireshark",
            optional: true,
            wrong_version: false,
        },
        Check {
            dependency: FileChooser,
            name: "File chooser (Zenity)",
            purpose: "Choose folders and files in Explorer and Upload",
            problem: executable(Path::new("zenity"))
                .is_none()
                .then(|| "zenity is missing or not executable".to_owned()),
            hint: "On Debian/Ubuntu: sudo apt install zenity",
            optional: true,
            wrong_version: false,
        },
        Check {
            dependency: Suricata,
            name: "Suricata",
            purpose: "IDS scans of captured traffic",
            problem: SURICATA
                .iter()
                .all(|path| executable(Path::new(path)).is_none())
                .then(|| "Suricata is not installed".to_owned()),
            hint: "On Debian/Ubuntu: sudo apt install suricata",
            optional: true,
            wrong_version: false,
        },
        Check {
            dependency: PythonVenv,
            name: "Python venv",
            purpose: "Install the Sigma tool from Tools > Analysis tools",
            problem: venv_problem(),
            hint: "On Debian/Ubuntu: sudo apt install python3-venv",
            optional: true,
            wrong_version: false,
        },
    ];
    if !options.headless {
        checks.push(Check {
            dependency: Gtk,
            name: "QEMU GTK display",
            purpose: "Open VM display windows",
            problem: gtk_problem(&options.qemu),
            hint: "On Debian/Ubuntu: sudo apt install qemu-system-gui",
            optional: false,
            wrong_version: false,
        });
    }
    // Always report KVM, even when TCG is selected; it remains a recommendation
    // for that mode and must not prevent software-emulated VMs from starting.
    checks.push(Check {
        dependency: Kvm,
        name: "KVM access",
        purpose: "Start VMs with hardware acceleration (TCG does not need it)",
        problem: kvm_problem(),
        hint: "Enable hardware virtualization and access to /dev/kvm (kvm group; sign in again), or select TCG in VM settings",
        optional: false,
        wrong_version: false,
    });
    Report {
        checks,
        package_manager: PackageManager::detect(),
        kvm: KvmAdvice::probe(),
    }
}

fn kvm_problem() -> Option<String> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .err()
        .map(|error| format!("cannot open /dev/kvm: {error}"))
}

fn gtk_problem(qemu: &Path) -> Option<String> {
    let qemu = match require_tool(qemu, "qemu-system-x86 qemu-system-gui") {
        Ok(qemu) => qemu,
        Err(error) => return Some(error),
    };
    match display_help(&qemu, PROBE_TIMEOUT) {
        Ok(output) if output.lines().any(|line| line.trim() == "gtk") => None,
        Ok(_) => Some("the configured QEMU has no GTK display backend".into()),
        Err(error) => Some(format!("could not check QEMU GTK support: {error}")),
    }
}

/// Required checks for a launch, respecting headless and explicit TCG mode.
pub fn vm_requirements(options: &BackendOptions, launch: &VmLaunchOptions) -> Vec<Dependency> {
    let mut required = vec![Dependency::Qemu, Dependency::QemuImg];
    if !options.headless {
        required.push(Dependency::Gtk);
    }
    if !options.force_tcg && launch.acceleration != VmAcceleration::Tcg {
        required.push(Dependency::Kvm);
    }
    required
}

/// Revalidate launch requirements before allocating RAM or spawning a guest.
pub(crate) fn require_vm(options: &BackendOptions, launch: &VmLaunchOptions) -> Result<(), String> {
    require_tool(&options.qemu, "qemu-system-x86")?;
    if let Some(problem) = qemu_version_problem(&options.qemu) {
        return Err(format!("{problem}; install a newer QEMU"));
    }
    require_tool(&options.qemu_img, "qemu-utils")?;
    if !options.headless
        && let Some(problem) = gtk_problem(&options.qemu)
    {
        return Err(format!(
            "{problem}; on Debian/Ubuntu: sudo apt install qemu-system-gui"
        ));
    }
    if !options.force_tcg
        && launch.acceleration != VmAcceleration::Tcg
        && let Some(problem) = kvm_problem()
    {
        return Err(format!(
            "{problem}; enable KVM access or select TCG in VM settings"
        ));
    }
    Ok(())
}

fn display_help(qemu: &Path, timeout: Duration) -> Result<String, String> {
    probe_output(qemu, &["-display", "help"], timeout)
}

/// Standard output of `program args`, bounded in time and size.
fn probe_output(program: &Path, args: &[&str], timeout: Duration) -> Result<String, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())?;
    let result = (|| {
        let mut stdout = child.stdout.take().ok_or("QEMU probe has no stdout")?;
        let flags = fcntl_getfl(&stdout).map_err(|error| error.to_string())?;
        fcntl_setfl(&stdout, flags | OFlags::NONBLOCK).map_err(|error| error.to_string())?;
        let deadline = Instant::now() + timeout;
        let mut output = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            loop {
                match stdout.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(len) => {
                        if output.len() + len > PROBE_OUTPUT_SIZE {
                            return Err("QEMU probe exceeded 16 KiB output limit".into());
                        }
                        output.extend_from_slice(&buffer[..len]);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.to_string()),
                }
            }
            if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                if !status.success() {
                    return Err(format!("QEMU probe exited with {status}"));
                }
                // Drain the last bytes written between the read and wait.
                loop {
                    match stdout.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(len) if output.len() + len <= PROBE_OUTPUT_SIZE => {
                            output.extend_from_slice(&buffer[..len])
                        }
                        Ok(_) => {
                            return Err("QEMU probe exceeded 16 KiB output limit".into());
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error.to_string()),
                    }
                }
                return String::from_utf8(output)
                    .map_err(|_| "QEMU probe output is not UTF-8".into());
            }
            if Instant::now() >= deadline {
                return Err("QEMU probe timed out after its deadline".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    // Always reap, including failures setting up or reading the probe pipe.
    if child
        .try_wait()
        .map_err(|error| error.to_string())?
        .is_none()
    {
        child
            .kill()
            .map_err(|error| format!("QEMU probe cleanup: {error}"))?;
    }
    child
        .wait()
        .map_err(|error| format!("QEMU probe reap: {error}"))?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn a_missing_optional_tool_is_not_a_startup_problem() {
        let entry = |optional, problem: Option<&str>| Check {
            dependency: Dependency::Suricata,
            name: "Suricata",
            purpose: "IDS scans",
            problem: problem.map(str::to_owned),
            hint: "On Debian/Ubuntu: sudo apt install suricata",
            optional,
            wrong_version: false,
        };
        let optional = Report {
            checks: vec![
                entry(true, Some("Suricata is not installed")),
                entry(false, None),
            ],
            ..Report::default()
        };
        assert!(!optional.has_missing());
        let required = Report {
            checks: vec![entry(false, Some("missing"))],
            ..Report::default()
        };
        assert!(required.has_missing());
        let checked = check(&BackendOptions::default());
        for dependency in [
            Dependency::Suricata,
            Dependency::PythonVenv,
            Dependency::Wireshark,
            Dependency::FileChooser,
        ] {
            assert!(
                checked
                    .checks
                    .iter()
                    .any(|check| check.dependency == dependency && check.optional)
            );
        }
    }

    struct Fixture(PathBuf);
    impl Fixture {
        fn new(script: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("ant-dependencies-{}", crate::storage::unique_id()));
            fs::create_dir(&dir).unwrap();
            let executable = dir.join("qemu");
            fs::write(&executable, format!("#!/bin/sh\n{script}\n")).unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
            Self(dir)
        }
        fn executable(&self) -> PathBuf {
            self.0.join("qemu")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn qemu_without_gtk_is_rejected_before_allocating_a_vm() {
        let fixture = Fixture::new("printf 'Available display backend types:\\nnone\\ncurses\\n'");
        let options = BackendOptions {
            qemu: fixture.executable(),
            qemu_img: fixture.executable(),
            force_tcg: true,
            ..Default::default()
        };
        let error = require_vm(&options, &VmLaunchOptions::default()).unwrap_err();
        assert!(error.contains("no GTK") && error.contains("qemu-system-gui"));
        let headless = BackendOptions {
            headless: true,
            ..options
        };
        require_vm(&headless, &VmLaunchOptions::default()).unwrap();
    }

    #[test]
    fn recheck_detects_a_newly_available_gtk_backend() {
        let fixture = Fixture::new("printf 'none\\ngtk-ish\\n'");
        assert!(gtk_problem(&fixture.executable()).is_some());
        fs::write(fixture.executable(), "#!/bin/sh\nprintf 'none\\ngtk\\n'\n").unwrap();
        assert!(gtk_problem(&fixture.executable()).is_none());
    }

    #[test]
    fn a_qemu_older_than_the_minimum_is_a_wrong_version_not_a_missing_tool() {
        assert_eq!(
            version_of("QEMU emulator version 11.0.3 (Debian 1:11.0.3+ds-2)"),
            Some((11, 0))
        );
        assert_eq!(version_of("QEMU emulator version 5.2.0"), Some((5, 2)));
        assert_eq!(version_of("none\ngtk"), None);
        let old = Fixture::new("echo 'QEMU emulator version 5.2.0 (Debian 1:5.2+dfsg-11)'");
        let problem = qemu_version_problem(&old.executable()).unwrap();
        assert!(
            problem.contains("5.2") && problem.contains("6.0"),
            "{problem}"
        );
        let options = BackendOptions {
            qemu: old.executable(),
            qemu_img: old.executable(),
            headless: true,
            force_tcg: true,
            ..Default::default()
        };
        let checked = check(&options);
        let qemu = checked
            .checks
            .iter()
            .find(|check| check.dependency == Dependency::Qemu)
            .unwrap();
        assert!(qemu.wrong_version && qemu.problem.is_some());
        assert!(
            require_vm(&options, &VmLaunchOptions::default())
                .unwrap_err()
                .contains("older than 6.0")
        );
        for output in [
            "QEMU emulator version 6.0.0",
            "QEMU emulator version 11.0.3",
            "unreadable",
        ] {
            let fine = Fixture::new(&format!("echo '{output}'"));
            assert_eq!(qemu_version_problem(&fine.executable()), None, "{output}");
        }
        let checked = check(&BackendOptions::default());
        assert!(
            checked
                .checks
                .iter()
                .all(|check| { check.dependency == Dependency::Qemu || !check.wrong_version })
        );
    }

    #[test]
    fn non_executable_and_missing_tools_are_not_available() {
        let fixture = Fixture::new("exit 0");
        fs::set_permissions(fixture.executable(), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            require_tool(&fixture.executable(), "qemu-system-x86")
                .unwrap_err()
                .contains("sudo apt install")
        );
        assert!(require_tool(&fixture.0.join("missing"), "curl").is_err());
    }

    #[test]
    fn probes_have_deadlines_and_output_limits() {
        let hanging = Fixture::new("while :; do :; done");
        let started = Instant::now();
        assert!(
            display_help(&hanging.executable(), Duration::from_millis(50))
                .unwrap_err()
                .contains("timed out")
        );
        assert!(started.elapsed() < Duration::from_secs(30));
        let noisy = Fixture::new("while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\\n'; done");
        assert!(
            display_help(&noisy.executable(), PROBE_TIMEOUT)
                .unwrap_err()
                .contains("output limit")
        );
        let failed = Fixture::new("printf gtk; exit 1");
        assert!(display_help(&failed.executable(), PROBE_TIMEOUT).is_err());
    }

    #[test]
    fn tcg_and_headless_do_not_require_hardware_or_display() {
        let options = BackendOptions {
            headless: true,
            force_tcg: true,
            ..Default::default()
        };
        assert_eq!(
            vm_requirements(&options, &VmLaunchOptions::default()),
            vec![Dependency::Qemu, Dependency::QemuImg]
        );
        let options = BackendOptions::default();
        let launch = VmLaunchOptions {
            acceleration: VmAcceleration::Tcg,
            ..Default::default()
        };
        assert_eq!(
            vm_requirements(&options, &launch),
            vec![Dependency::Qemu, Dependency::QemuImg, Dependency::Gtk]
        );
        assert!(vm_requirements(&options, &VmLaunchOptions::default()).contains(&Dependency::Kvm));
    }

    #[test]
    fn missing_download_tool_does_not_block_unrelated_actions() {
        let report = Report {
            checks: vec![Check {
                dependency: Dependency::Curl,
                name: "curl",
                purpose: "Downloads",
                problem: Some("missing".into()),
                hint: "sudo apt install curl",
                optional: false,
                wrong_version: false,
            }],
            ..Report::default()
        };
        assert!(report.has_missing());
        report.require(&[]).unwrap();
        assert!(
            report
                .require(&[Dependency::Curl])
                .unwrap_err()
                .contains("sudo apt install curl")
        );
        assert!(report.require(&[Dependency::Qemu]).is_err());
    }
}
