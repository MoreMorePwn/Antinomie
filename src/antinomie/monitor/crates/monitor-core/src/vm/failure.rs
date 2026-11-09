// SPDX-License-Identifier: GPL-3.0-only
//! What a failed start says: QEMU's own words when it exited (a device it
//! refused, a locked disk), and the TCG speed note only when a wait ran out.
use super::*;

/// The last line of `qemu.log`, where QEMU says why it stopped (for example
/// that another process holds the disk's write lock, or a device it refused).
pub(super) fn qemu_log_line(runtime_dir: &Path) -> Option<String> {
    const TAIL: u64 = 2048;
    let mut file = File::open(runtime_dir.join("qemu.log")).ok()?;
    let len = file.metadata().map_or(0, |metadata| metadata.len());
    let _ = file.seek(SeekFrom::Start(len.saturating_sub(TAIL)));
    let mut tail = String::new();
    let _ = file.take(TAIL).read_to_string(&mut tail);
    tail.lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_owned())
}

/// [`qemu_log_line`] as the end of a message.
pub(super) fn qemu_log_hint(runtime_dir: &Path) -> String {
    qemu_log_line(runtime_dir).map_or_else(String::new, |line| format!("; QEMU said: {line}"))
}

/// A start step's `error` with what QEMU says about it. QEMU exited
/// (`exit`): its status and last line (`said`) first, and nothing about
/// speed, since no wait was too short. QEMU running: its last line, and
/// `slow` (the TCG note) only when a wait ran out.
pub(super) fn start_error(
    error: &str,
    exit: Option<std::process::ExitStatus>,
    said: Option<&str>,
    slow: &str,
) -> String {
    match (exit, said) {
        (Some(status), Some(line)) => {
            format!("QEMU exited ({status}) before the VM started: {line} ({error})")
        }
        (Some(status), None) => format!("QEMU exited ({status}) before the VM started ({error})"),
        (None, said) => format!(
            "{error}{}{}",
            said.map_or_else(String::new, |line| format!("; QEMU said: {line}")),
            if waited_out(error) { slow } else { "" }
        ),
    }
}

impl VmProcess {
    /// QEMU's exit status if it has exited. `grace`: wait up to two seconds
    /// for an exit under way (QEMU's sockets close just before it ends).
    fn exited(&mut self, grace: bool) -> Option<std::process::ExitStatus> {
        let deadline = std::time::Instant::now()
            + if grace {
                Duration::from_secs(2)
            } else {
                Duration::ZERO
            };
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                _ => return None,
            }
        }
    }

    /// [`start_error`] for this QEMU process.
    pub(super) fn start_failure(&mut self, error: &str) -> String {
        let exit = self.exited(!waited_out(error));
        let said = qemu_log_line(&self.runtime_dir);
        start_error(error, exit, said.as_deref(), &self.slow_hint())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REFUSED: &str = "qemu-system-aarch64: -device igb,netdev=net0,mac=00:30:64:ab:85:51,addr=0x19: VF addr overflows";
    const RESET: &str =
        "QMP connect for RAM layout: QMP read: Connection reset by peer (os error 104)";

    fn tcg_process(script: &str, dir: &Path) -> VmProcess {
        let tcg = crate::accel::Choice {
            accelerator: crate::accel::Accelerator::Tcg,
            fallback: None,
        };
        VmProcess {
            child: Command::new("sh").args(["-c", script]).spawn().unwrap(),
            ram_path: "/nonexistent/ram".into(),
            _ram_memory: None,
            runtime_dir: dir.to_path_buf(),
            bootstrap: 0,
            ram_layout: RamLayout::q35(0),
            machine: Machine::Virt,
            qmp_path: "/nonexistent/qmp".into(),
            screen_socket: None,
            gateway: None,
            net_dir: None,
            stealth_fallbacks: Vec::new(),
            waits: crate::accel::Waits::with_load(&tcg, &crate::api::StartSettings::default(), 1.0),
            accel: tcg,
        }
    }

    #[test]
    fn a_device_qemu_refused_is_quoted_without_the_tcg_note() {
        let dir = std::env::temp_dir().join(format!("ant-start-error-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("qemu.log"), format!("{REFUSED}\n\n")).unwrap();
        let mut process = tcg_process("exit 1", &dir);
        let message = process.start_failure(RESET);
        assert!(
            message.starts_with("QEMU exited (exit status: 1) before the VM started: "),
            "{message}"
        );
        assert!(message.contains(&format!(": {REFUSED} (")), "{message}");
        assert!(message.ends_with(&format!("({RESET})")), "{message}");
        assert!(!message.contains("TCG"), "{message}");
        // A QEMU that still runs when a wait ran out: its last line and the
        // TCG note; one that runs but closed the socket: no note.
        let mut running = tcg_process("sleep 60", &dir);
        let timeout = "QMP read: timed out waiting for a reply";
        let message = running.start_failure(timeout);
        assert!(message.starts_with(timeout), "{message}");
        assert!(
            message.contains(&format!("; QEMU said: {REFUSED}")),
            "{message}"
        );
        assert!(message.contains("TCG multiplier"), "{message}");
        let message = running.start_failure("QMP socket not ready after 600 s: refused");
        assert!(message.contains("TCG multiplier"), "{message}");
        let message = running.start_failure("QMP closed");
        assert!(!message.contains("TCG"), "{message}");
        running.child.kill().unwrap();
        running.child.wait().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_start_error_without_qemu_words_still_names_the_exit() {
        let status = Command::new("sh").args(["-c", "exit 1"]).status().unwrap();
        let slow = ". TCG is software emulation";
        assert_eq!(
            start_error(RESET, Some(status), None, slow),
            format!("QEMU exited (exit status: 1) before the VM started ({RESET})")
        );
        assert_eq!(start_error("QMP closed", None, None, slow), "QMP closed");
        assert_eq!(
            start_error("QMP read: timed out waiting for a reply", None, None, slow),
            format!("QMP read: timed out waiting for a reply{slow}")
        );
    }
}
