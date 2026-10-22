// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Launch into the guest's graphical session. The guest has no helper
//! program, and only the guest knows the session's display, so a constant
//! `/bin/sh` script (`guest_desktop.sh`) is the launched program: it imports
//! the display variables from a process of the user's session and then
//! executes the requested program, or opens a terminal window running it.
//! The program path and arguments are positional parameters of that script,
//! never shell text, so no quoting of user values happens on the host.
use crate::api::{ExecRequest, RunIn};

const SCRIPT: &str = include_str!("guest_desktop.sh");
/// `$0` of the wrapper, shown as the shell's name in its messages.
const NAME: &str = "antinomie";

/// The wrapper script as sent to the guest: comment-only lines removed.
fn script() -> String {
    SCRIPT
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .fold(String::with_capacity(SCRIPT.len()), |mut text, line| {
            text.push_str(line);
            text.push('\n');
            text
        })
}

/// The request the guest kernel executes for `request`: unchanged for the app
/// terminal, otherwise `/bin/sh -c SCRIPT antinomie MODE UID PATH ARGS...`
/// with the caller's cwd, environment and credentials. Static analysis is
/// left to the caller: the kernel would otherwise acquire `/bin/sh`.
pub(crate) fn wire_request(request: &ExecRequest) -> Result<ExecRequest, String> {
    let mode = match request.run_in {
        RunIn::AppTerminal => return Ok(request.clone()),
        RunIn::GuestDesktop => "desktop",
        RunIn::GuestDesktopTerminal => "terminal",
    };
    crate::control::string(&request.path, true)?;
    let mut args = vec![
        "-c".to_owned(),
        script(),
        NAME.to_owned(),
        mode.to_owned(),
        request.uid.to_string(),
        request.path.clone(),
    ];
    args.extend(request.args.iter().cloned());
    Ok(ExecRequest {
        path: "/bin/sh".into(),
        args,
        analysis: crate::analysis::AnalysisSelection::default(),
        ..request.clone()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output, Stdio};

    /// A fake `/proc` and `PATH` the wrapper runs against on the host.
    struct Guest {
        root: PathBuf,
    }
    impl Guest {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .join(format!("ant-guest-desktop-{}", crate::storage::unique_id()));
            fs::create_dir_all(root.join("proc")).unwrap();
            fs::create_dir_all(root.join("bin")).unwrap();
            for tool in ["grep", "tr", "head", "wc"] {
                let found = ["/usr/bin", "/bin"]
                    .iter()
                    .map(|dir| Path::new(dir).join(tool))
                    .find(|path| path.exists())
                    .unwrap();
                std::os::unix::fs::symlink(found, root.join("bin").join(tool)).unwrap();
            }
            Self { root }
        }
        fn process(&self, pid: u32, owner: u32, environ: &[&str]) {
            let dir = self.root.join("proc").join(pid.to_string());
            fs::create_dir_all(&dir).unwrap();
            let mut data = Vec::new();
            for entry in environ {
                data.extend_from_slice(entry.as_bytes());
                data.push(0);
            }
            fs::write(dir.join("environ"), data).unwrap();
            fs::write(
                dir.join("status"),
                format!("Name:\tshell\nUid:\t{owner}\t{owner}\t{owner}\t{owner}\n"),
            )
            .unwrap();
        }
        fn tool(&self, name: &str, body: &str) {
            let path = self.root.join("bin").join(name);
            fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        /// Run the wire request's wrapper with `/proc/` pointing at the fake.
        fn run(&self, request: &ExecRequest, env: &[(&str, &str)], stdin: &str) -> Output {
            let wire = wire_request(request).unwrap();
            assert_eq!(wire.path, "/bin/sh");
            let proc = format!("{}/", self.root.join("proc").display());
            let mut args = wire.args.clone();
            args[1] = args[1].replace("/proc/", &proc);
            let mut command = Command::new(&wire.path);
            command
                .args(&args)
                .env_clear()
                .env("PATH", self.root.join("bin"))
                .envs(env.iter().copied())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = command.spawn().unwrap();
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(stdin.as_bytes())
                .unwrap();
            child.wait_with_output().unwrap()
        }
    }
    impl Drop for Guest {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// Arguments no shell may reinterpret on their way to the program.
    const HOSTILE: [&str; 8] = [
        "two words",
        "it's",
        "$(touch /tmp/ant-pwned)",
        "`id`",
        "",
        "*",
        "a\nnew line",
        "'\\''; exit 9 #",
    ];

    fn request(run_in: RunIn) -> ExecRequest {
        ExecRequest {
            path: "/bin/sh".into(),
            args: [
                "-c",
                r#"for a; do printf '<%s>\n' "$a"; done; printf 'D=%s W=%s X=%s H=%s B=%s L=%s\n' "${DISPLAY-}" "${WAYLAND_DISPLAY-}" "${XAUTHORITY-}" "${HOME-}" "${DBUS_SESSION_BUS_ADDRESS-}" "${LANG-}""#,
                "program",
            ]
            .into_iter()
            .chain(HOSTILE)
            .map(str::to_owned)
            .collect(),
            run_in,
            ..ExecRequest::default()
        }
    }

    fn expected_arguments() -> String {
        HOSTILE.iter().map(|arg| format!("<{arg}>\n")).collect()
    }

    #[test]
    fn app_terminal_requests_are_unchanged_and_desktop_requests_wrap_the_program() {
        let mut plain = request(RunIn::AppTerminal);
        plain.analysis.enabled = true;
        let wire = wire_request(&plain).unwrap();
        assert_eq!(
            crate::control::execute(&wire),
            crate::control::execute(&plain)
        );
        assert!(wire.analysis.enabled);
        for (run_in, mode) in [
            (RunIn::GuestDesktop, "desktop"),
            (RunIn::GuestDesktopTerminal, "terminal"),
        ] {
            let mut original = request(run_in);
            original.analysis.enabled = true;
            original.uid = 1234;
            original.cwd = "/home/user".into();
            let wire = wire_request(&original).unwrap();
            assert_eq!(wire.path, "/bin/sh");
            assert_eq!(&wire.args[..1], ["-c"]);
            assert!(
                !wire.args[1]
                    .lines()
                    .any(|l| l.trim_start().starts_with('#'))
            );
            assert_eq!(&wire.args[2..6], [NAME, mode, "1234", "/bin/sh"]);
            assert_eq!(&wire.args[6..], &original.args[..]);
            assert_eq!(
                (&wire.cwd, &wire.env, wire.uid, wire.gid, wire.run_in),
                (&original.cwd, &original.env, 1234, 1000, run_in)
            );
            assert!(!wire.analysis.enabled, "the kernel would acquire /bin/sh");
            assert!(crate::control::execute(&wire).is_ok());
            original.path = "relative".into();
            assert!(wire_request(&original).is_err());
        }
    }

    #[test]
    fn desktop_imports_the_best_session_of_the_run_user_and_keeps_the_arguments() {
        let guest = Guest::new();
        // Started before the display existed: no display variables.
        guest.process(10, 1000, &["HOME=/home/user", "LANG=C.UTF-8"]);
        guest.process(
            11,
            1000,
            &[
                "WAYLAND_DISPLAY=wayland-0",
                "XDG_RUNTIME_DIR=/run/user/1000",
            ],
        );
        guest.process(
            12,
            1000,
            &[
                "WAYLAND_DISPLAY=wayland-0",
                "DISPLAY=:0",
                "XAUTHORITY=/run/user/1000/.Xauth it's",
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
                "HOME=/home/user",
                "LANG=en_US.UTF-8",
                "SECRET=not imported",
            ],
        );
        // Another user's session scores higher but is not the run's.
        guest.process(
            13,
            1001,
            &[
                "WAYLAND_DISPLAY=wayland-1",
                "DISPLAY=:1",
                "XAUTHORITY=/x",
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/b",
                "XDG_RUNTIME_DIR=/run/user/1001",
            ],
        );
        let output = guest.run(&request(RunIn::GuestDesktop), &[("LANG", "kept")], "");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        assert_eq!(
            stdout,
            format!(
                "{}D=:0 W=wayland-0 X=/run/user/1000/.Xauth it's H=/home/user B=unix:path=/run/user/1000/bus L=kept\n",
                expected_arguments()
            )
        );
        assert!(stderr.contains("joined the graphical session of UID 1000"));
        assert!(!Path::new("/tmp/ant-pwned").exists());
    }

    #[test]
    fn root_joins_a_user_session_but_not_the_greeter_or_that_users_home() {
        let guest = Guest::new();
        guest.process(20, 120, &["WAYLAND_DISPLAY=wayland-0", "DISPLAY=:1024"]);
        guest.process(
            21,
            1000,
            &[
                "DISPLAY=:0",
                "HOME=/home/user",
                "XDG_RUNTIME_DIR=/nonexistent",
            ],
        );
        let mut root = request(RunIn::GuestDesktop);
        root.uid = 0;
        let output = guest.run(&root, &[], "");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(output.status.success());
        assert!(stdout.ends_with("D=:0 W= X= H= B= L=\n"), "{stdout}");
    }

    #[test]
    fn missing_session_explains_itself_and_never_starts_the_program() {
        let guest = Guest::new();
        guest.process(30, 1000, &["HOME=/home/user"]);
        guest.process(31, 120, &["WAYLAND_DISPLAY=wayland-0"]);
        for run_in in [RunIn::GuestDesktop, RunIn::GuestDesktopTerminal] {
            let output = guest.run(&request(run_in), &[], "");
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert_eq!(
                stderr,
                "antinomie: UID 1000 has no graphical session on the guest; log in as that user on the VM display, then run the program again\n"
            );
        }
        let mut root = request(RunIn::GuestDesktop);
        root.uid = 0;
        let stderr = String::from_utf8(guest.run(&root, &[], "").stderr).unwrap();
        assert!(stderr.contains("no graphical session is logged in"));
    }

    #[test]
    fn oversized_ineligible_environments_are_not_read() {
        let guest = Guest::new();
        let oversized = format!("DISPLAY={}", "x".repeat(70_000));
        for pid in 100..132 {
            guest.process(pid, 1001, &[&oversized]);
        }
        guest.process(200, 1000, &["DISPLAY=:0"]);
        let output = guest.run(&request(RunIn::GuestDesktop), &[], "");
        assert!(output.status.success(), "{:?}", output.stderr);
        assert!(String::from_utf8(output.stdout).unwrap().contains("D=:0"));
    }

    #[test]
    fn session_discovery_rejects_candidate_exhaustion_before_launch() {
        let guest = Guest::new();
        for pid in 1..=4096 {
            fs::create_dir(guest.root.join("proc").join(pid.to_string())).unwrap();
        }
        let output = guest.run(&request(RunIn::GuestDesktop), &[], "");
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("has no graphical session")
        );
        guest.process(4097, 1000, &["DISPLAY=:0"]);
        let output = guest.run(&request(RunIn::GuestDesktop), &[], "");
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("4096-process candidate limit")
        );
    }

    #[test]
    fn selected_environment_limit_keeps_complete_entries_and_rejects_truncation() {
        let guest = Guest::new();
        // DISPLAY=, value and its NUL terminator total exactly 64 KiB.
        let exact = format!("DISPLAY={}", "x".repeat(65_527));
        guest.process(1, 1000, &[&exact]);
        let mut target = request(RunIn::GuestDesktop);
        target.args = vec!["-c".into(), "printf 'length=%s' \"${#DISPLAY}\"".into()];
        let output = guest.run(&target, &[], "");
        assert!(output.status.success(), "{:?}", output.stderr);
        assert_eq!(output.stdout, b"length=65527");

        // A valid display before an oversized entry must not cause a launch
        // with an imported prefix of that entry.
        let oversized = format!("XAUTHORITY={}", "x".repeat(70_000));
        guest.process(1, 1000, &["DISPLAY=:0", &oversized]);
        let output = guest.run(&target, &[], "");
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("65536-byte environment limit")
        );
    }

    #[test]
    fn terminals_receive_the_program_as_arguments_and_hold_its_window() {
        let guest = Guest::new();
        guest.process(40, 1000, &["DISPLAY=:0"]);
        // Each fake terminal checks its own options, then runs the command
        // the way the real one does.
        guest.tool(
            "xfce4-terminal",
            r#"[ "$1 $2" = "--disable-server -x" ] || exit 90; shift 2; exec "$@""#,
        );
        let output = guest.run(&request(RunIn::GuestDesktopTerminal), &[], "\n");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(0), "{stdout}");
        assert!(stdout.starts_with(&expected_arguments()), "{stdout}");
        assert!(stdout.ends_with("\n[/bin/sh exited with status 0; press Enter to close]"));

        // lxterminal joins its command into one string and parses it again.
        fs::remove_file(guest.root.join("bin/xfce4-terminal")).unwrap();
        guest.tool(
            "lxterminal",
            r#"[ "$1 $2" = "--no-remote -e" ] && [ $# = 3 ] || exit 91; eval "set -- $3"; exec "$@""#,
        );
        let output = guest.run(&request(RunIn::GuestDesktopTerminal), &[], "\n");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(0), "{stdout}");
        assert!(stdout.starts_with(&expected_arguments()), "{stdout}");
        assert!(!Path::new("/tmp/ant-pwned").exists());

        // This fake terminal propagates the child's status.
        let mut failing = request(RunIn::GuestDesktopTerminal);
        failing.args = vec!["-c".into(), "exit 7".into()];
        let output = guest.run(&failing, &[], "\n");
        assert_eq!(output.status.code(), Some(7));

        // Real emulators such as Xfce can exit successfully after their child
        // fails: the wrapper reports the emulator's code, while the hold
        // shell still displays the target program's own result.
        guest.tool(
            "xfce4-terminal",
            r#"[ "$1 $2" = "--disable-server -x" ] || exit 90; shift 2; "$@"; exit 0"#,
        );
        let output = guest.run(&failing, &[], "\n");
        assert_eq!(output.status.code(), Some(0));
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .ends_with("\n[/bin/sh exited with status 7; press Enter to close]")
        );
    }

    #[test]
    fn terminal_fallbacks_warn_or_explain_what_is_missing() {
        let guest = Guest::new();
        guest.process(50, 1000, &["WAYLAND_DISPLAY=wayland-0"]);
        let output = guest.run(&request(RunIn::GuestDesktopTerminal), &[], "");
        assert_eq!(output.status.code(), Some(127));
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("the guest has no terminal emulator")
        );
        // xterm needs an X display, which this session does not name.
        guest.tool("xterm", "exit 92");
        guest.tool(
            "x-terminal-emulator",
            r#"[ "$1" = -e ] || exit 93; shift; exec "$@""#,
        );
        let output = guest.run(&request(RunIn::GuestDesktopTerminal), &[], "\n");
        assert_eq!(output.status.code(), Some(0));
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("x-terminal-emulator may run the program in a separate terminal server")
        );
    }
}
