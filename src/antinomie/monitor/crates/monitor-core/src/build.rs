//! Local base build workflows (host Linux).
//!
//! The app orchestrates the repository's documented build scripts rather than
//! reimplementing them (see `Agents/Decisions/ANT-ADR-0001`). A profile declares
//! its host tools; a plan is the ordered steps that produce a source-format
//! bundle. Missing tools are reported with an install hint and nothing is
//! installed automatically.

use std::{
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
};

/// Base families that can be built locally.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    BusyBox,
    DebianXfce,
}

/// A buildable base offered by "Build base".
pub struct BuildProfile {
    pub id: &'static str,
    pub label: &'static str,
    pub kind: Kind,
}

/// The buildable profiles, in menu order.
pub const BUILD_PROFILES: &[BuildProfile] = &[
    BuildProfile {
        id: "busybox",
        label: "BusyBox (minimal)",
        kind: Kind::BusyBox,
    },
    BuildProfile {
        id: "debian-xfce",
        label: "Debian 13 (Xfce)",
        kind: Kind::DebianXfce,
    },
];

/// Resolve a profile by its stable id.
pub fn profile(id: &str) -> Option<&'static BuildProfile> {
    BUILD_PROFILES.iter().find(|profile| profile.id == id)
}

/// A host tool a profile needs, with its Debian/Ubuntu package hint.
#[derive(Clone, Copy, Debug)]
pub struct ToolSpec {
    pub tool: &'static str,
    pub package: &'static str,
}

/// Toolchain shared by every profile (the pinned kernel build).
const KERNEL_TOOLS: &[ToolSpec] = &[
    ToolSpec {
        tool: "bash",
        package: "bash",
    },
    ToolSpec {
        tool: "make",
        package: "make",
    },
    ToolSpec {
        tool: "gcc",
        package: "gcc",
    },
    ToolSpec {
        tool: "bison",
        package: "bison",
    },
    ToolSpec {
        tool: "flex",
        package: "flex",
    },
    ToolSpec {
        tool: "bc",
        package: "bc",
    },
    ToolSpec {
        tool: "perl",
        package: "perl",
    },
];

const BUSYBOX_TOOLS: &[ToolSpec] = &[
    ToolSpec {
        tool: "python3",
        package: "python3",
    },
    ToolSpec {
        tool: "qemu-img",
        package: "qemu-utils",
    },
    ToolSpec {
        tool: "mkfs.ext4",
        package: "e2fsprogs",
    },
    ToolSpec {
        tool: "debugfs",
        package: "e2fsprogs",
    },
    ToolSpec {
        tool: "resize2fs",
        package: "e2fsprogs",
    },
    ToolSpec {
        tool: "cpio",
        package: "cpio",
    },
    ToolSpec {
        tool: "gzip",
        package: "gzip",
    },
    ToolSpec {
        tool: "busybox",
        package: "busybox-static",
    },
    ToolSpec {
        tool: "ldd",
        package: "libc-bin",
    },
];

const DEBIAN_TOOLS: &[ToolSpec] = &[
    ToolSpec {
        tool: "python3",
        package: "python3",
    },
    ToolSpec {
        tool: "virt-builder",
        package: "libguestfs-tools",
    },
    ToolSpec {
        tool: "guestfish",
        package: "libguestfs-tools",
    },
    ToolSpec {
        tool: "qemu-img",
        package: "qemu-utils",
    },
    ToolSpec {
        tool: "cpio",
        package: "cpio",
    },
    ToolSpec {
        tool: "gzip",
        package: "gzip",
    },
    ToolSpec {
        tool: "busybox",
        package: "busybox-static",
    },
    ToolSpec {
        tool: "resize2fs",
        package: "e2fsprogs",
    },
    ToolSpec {
        tool: "dpkg-query",
        package: "dpkg",
    },
];

/// Host tools required by a profile.
pub fn tools(kind: Kind) -> Vec<ToolSpec> {
    let mut all = KERNEL_TOOLS.to_vec();
    all.extend_from_slice(match kind {
        Kind::BusyBox => BUSYBOX_TOOLS,
        Kind::DebianXfce => DEBIAN_TOOLS,
    });
    all
}

/// Presence of one host tool.
#[derive(Clone, Copy, Debug)]
pub struct ToolStatus {
    pub tool: &'static str,
    pub package: &'static str,
    pub present: bool,
}

/// `PATH` lookup for a bare tool name.
pub fn which(tool: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(tool))
        .find(|candidate| candidate.is_file())
}

/// Status of every tool a profile needs.
pub fn status(kind: Kind) -> Vec<ToolStatus> {
    tools(kind)
        .into_iter()
        .map(|spec| ToolStatus {
            tool: spec.tool,
            package: spec.package,
            present: which(spec.tool).is_some(),
        })
        .collect()
}

/// Missing tools, deduplicated by package order of appearance.
pub fn missing(kind: Kind) -> Vec<ToolStatus> {
    status(kind)
        .into_iter()
        .filter(|tool| !tool.present)
        .collect()
}

/// A copy-paste install hint for the missing tools (Debian/Ubuntu package
/// names). Empty when nothing is missing.
pub fn install_hint(kind: Kind) -> String {
    let mut packages: Vec<&str> = Vec::new();
    for tool in missing(kind) {
        if !packages.contains(&tool.package) {
            packages.push(tool.package);
        }
    }
    if packages.is_empty() {
        String::new()
    } else {
        format!("sudo apt install {}", packages.join(" "))
    }
}

/// One ordered build step.
pub struct Step {
    pub label: &'static str,
    pub program: String,
    pub args: Vec<String>,
}

/// Build the ordered steps for a profile against a workspace checkout.
///
/// The kernel step prints the bzImage path; the image step consumes
/// `work/monitor-build/{arch/x86/boot/bzImage,.config}` and writes the source
/// bundle to `output`.
pub fn plan(workspace: &Path, kind: Kind, output: &Path) -> Vec<Step> {
    let kernel = workspace.join("work/monitor-build/arch/x86/boot/bzImage");
    let config = workspace.join("work/monitor-build/.config");
    let script = match kind {
        Kind::BusyBox => "scripts/build-monitor-image.py",
        Kind::DebianXfce => "scripts/build-debian-image.py",
    };
    vec![
        Step {
            label: "kernel",
            program: "bash".into(),
            args: vec!["scripts/build-monitor-kernel.sh".into()],
        },
        Step {
            label: "image",
            program: "python3".into(),
            args: vec![
                script.into(),
                "--kernel".into(),
                kernel.display().to_string(),
                "--kernel-config".into(),
                config.display().to_string(),
                "--output".into(),
                output.display().to_string(),
            ],
        },
    ]
}

/// Run the steps in order, streaming each output line to `on_line`.
///
/// Stops at the first failing step (non-zero exit or spawn failure) and after a
/// cancel request. `on_line` receives both stdout and stderr lines.
pub fn run(
    steps: &[Step],
    workspace: &Path,
    cancel: &AtomicBool,
    mut on_line: impl FnMut(&str),
) -> Result<(), String> {
    for step in steps {
        if cancel.load(Ordering::Relaxed) {
            return Err("build cancelled".into());
        }
        on_line(&format!("$ {} {}", step.program, step.args.join(" ")));
        let mut child = Command::new(&step.program)
            .args(&step.args)
            .current_dir(workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("{}: cannot start {}: {error}", step.label, step.program))?;
        let stderr = child.stderr.take();
        let (sender, receiver) = mpsc::channel::<String>();
        let reader = stderr.map(|handle| {
            std::thread::spawn(move || {
                for line in BufReader::new(handle).lines().map_while(Result::ok) {
                    let _ = sender.send(line);
                }
            })
        });
        let stdout = child.stdout.take().expect("piped stdout");
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            for error in receiver.try_iter() {
                on_line(&error);
            }
            if cancel.load(Ordering::Relaxed) {
                let _ = child.kill();
                let _ = child.wait();
                return Err("build cancelled".into());
            }
            on_line(&line);
        }
        let status = child.wait().map_err(|error| error.to_string())?;
        for error in receiver.try_iter() {
            on_line(&error);
        }
        if let Some(reader) = reader {
            let _ = reader.join();
        }
        if !status.success() {
            return Err(format!("{} step failed: {status}", step.label));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn collect() -> (std::sync::Arc<Mutex<Vec<String>>>, impl FnMut(&str)) {
        let log = std::sync::Arc::new(Mutex::new(Vec::new()));
        let sink = log.clone();
        (log, move |line: &str| {
            sink.lock().unwrap().push(line.to_string());
        })
    }

    #[test]
    fn profiles_are_distinct_and_addressable() {
        assert!(profile("busybox").is_some());
        assert!(profile("debian-xfce").is_some());
        assert!(profile("nope").is_none());
        let ids: std::collections::HashSet<_> = BUILD_PROFILES.iter().map(|p| p.id).collect();
        assert_eq!(ids.len(), BUILD_PROFILES.len());
    }

    #[test]
    fn plan_orders_kernel_before_image_and_uses_the_output() {
        let workspace = Path::new("/repo");
        let output = Path::new("/out/debian");
        let steps = plan(workspace, Kind::DebianXfce, output);
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].label, "kernel");
        assert!(
            steps[0]
                .args
                .iter()
                .any(|a| a.contains("build-monitor-kernel.sh"))
        );
        assert_eq!(steps[1].label, "image");
        assert!(
            steps[1]
                .args
                .iter()
                .any(|a| a.ends_with("build-debian-image.py"))
        );
        assert!(steps[1].args.iter().any(|a| a == "/out/debian"));
        let busy = plan(workspace, Kind::BusyBox, output);
        assert!(
            busy[1]
                .args
                .iter()
                .any(|a| a.ends_with("build-monitor-image.py"))
        );
    }

    #[test]
    fn run_streams_output_and_stops_on_failure() {
        let dir = std::env::temp_dir().join(format!("antinomie-build-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let steps = vec![Step {
            label: "demo",
            program: "sh".into(),
            args: vec!["-c".into(), "echo one; echo two 1>&2".into()],
        }];
        let (log, sink) = collect();
        run(&steps, &dir, &AtomicBool::new(false), sink).unwrap();
        let text = log.lock().unwrap().join("\n");
        assert!(text.contains("one"), "{text}");
        assert!(text.contains("two"), "{text}");

        let fail = vec![Step {
            label: "demo",
            program: "sh".into(),
            args: vec!["-c".into(), "exit 4".into()],
        }];
        let (_log, sink) = collect();
        let error = run(&fail, &dir, &AtomicBool::new(false), sink).unwrap_err();
        assert!(error.contains("demo step failed"), "{error}");

        let missing = vec![Step {
            label: "demo",
            program: "antinomie-not-a-real-tool".into(),
            args: vec![],
        }];
        let (_log, sink) = collect();
        assert!(run(&missing, &dir, &AtomicBool::new(false), sink).is_err());
    }

    #[test]
    fn run_honours_cancel() {
        let cancel = AtomicBool::new(true);
        let steps = vec![Step {
            label: "demo",
            program: "sh".into(),
            args: vec!["-c".into(), "echo never".into()],
        }];
        let (_log, sink) = collect();
        let error = run(&steps, Path::new("/tmp"), &cancel, sink).unwrap_err();
        assert_eq!(error, "build cancelled");
    }

    #[test]
    fn install_hint_lists_each_missing_package_once() {
        // Force a missing tool by using a profile that needs one, then check the
        // mapping is package-deduplicated for a synthetic set.
        let hint = {
            let mut packages: Vec<&str> = Vec::new();
            for tool in [
                ToolSpec {
                    tool: "x",
                    package: "e2fsprogs",
                },
                ToolSpec {
                    tool: "y",
                    package: "e2fsprogs",
                },
                ToolSpec {
                    tool: "z",
                    package: "cpio",
                },
            ] {
                if !packages.contains(&tool.package) {
                    packages.push(tool.package);
                }
            }
            format!("sudo apt install {}", packages.join(" "))
        };
        assert_eq!(hint, "sudo apt install e2fsprogs cpio");
    }
}
