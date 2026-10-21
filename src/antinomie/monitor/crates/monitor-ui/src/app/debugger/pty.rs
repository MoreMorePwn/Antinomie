// SPDX-License-Identifier: MIT
//! A host program on a pseudo-terminal, for the gdb console: the program is a
//! session leader on the PTY (so Ctrl-C reaches it), a thread reads what it
//! prints, and closing the console asks it to quit before it is killed.
use rustix::{
    fs::{Mode, OFlags},
    process::{ioctl_tiocsctty, setsid},
    pty::{grantpt, openpt, ptsname, unlockpt, OpenptFlags},
    termios::{tcsetwinsize, Winsize},
};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::{fd::BorrowedFd, unix::process::CommandExt},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

/// What to run and how.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Launch {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(&'static str, &'static str)>,
    pub env_remove: Vec<&'static str>,
}

/// How long a closing console gets to quit by itself.
const QUIT_GRACE: Duration = Duration::from_secs(3);

pub(super) struct PtyChild {
    child: Option<Child>,
    master: Option<File>,
    output: mpsc::Receiver<Vec<u8>>,
    /// The reader saw the end of the output.
    ended: bool,
}

impl PtyChild {
    /// Start `launch` on a new PTY of `rows` x `cols`. `wake` is called when
    /// the program has printed something, to redraw the console.
    pub fn spawn(
        launch: &Launch,
        rows: u16,
        cols: u16,
        wake: impl Fn() + Send + 'static,
    ) -> io::Result<Self> {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)?;
        grantpt(&master)?;
        unlockpt(&master)?;
        let name = ptsname(&master, Vec::new())?;
        let slave = rustix::fs::open(
            name.as_c_str(),
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        // The size is set before the program starts, so it reads it right away.
        Self::size(&slave, rows, cols)?;
        let master = File::from(master);
        let child = {
            let mut command = Command::new(&launch.program);
            command.args(&launch.args);
            for name in &launch.env_remove {
                command.env_remove(name);
            }
            for (name, value) in &launch.env {
                command.env(name, value);
            }
            command
                .stdin(Stdio::from(slave.try_clone()?))
                .stdout(Stdio::from(slave.try_clone()?))
                .stderr(Stdio::from(slave.try_clone()?));
            // SAFETY: only async-signal-safe calls (setsid, ioctl) run between
            // fork and exec.
            unsafe {
                command.pre_exec(|| {
                    setsid()?;
                    // SAFETY: fd 0 is the PTY the Command just installed.
                    ioctl_tiocsctty(BorrowedFd::borrow_raw(0))?;
                    Ok(())
                });
            }
            let child = command.spawn()?;
            // The program holds the slave now; keeping ours would stop the
            // reader from ever seeing the end of the output.
            drop(command);
            child
        };
        drop(slave);
        let (sender, output) = mpsc::channel();
        let mut reader = master.try_clone()?;
        std::thread::spawn(move || {
            let mut buffer = [0u8; 8192];
            // EIO is how Linux reports that the last slave end closed.
            while let Ok(read @ 1..) = reader.read(&mut buffer) {
                if sender.send(buffer[..read].to_vec()).is_err() {
                    return;
                }
                wake();
            }
            let _ = sender.send(Vec::new());
            wake();
        });
        Ok(Self {
            child: Some(child),
            master: Some(master),
            output,
            ended: false,
        })
    }

    fn size(fd: impl std::os::fd::AsFd, rows: u16, cols: u16) -> io::Result<()> {
        tcsetwinsize(
            fd,
            Winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )?;
        Ok(())
    }

    pub fn resize(&self, rows: u16, cols: u16) {
        if let Some(master) = &self.master {
            let _ = Self::size(master, rows, cols);
        }
    }

    pub fn write(&mut self, bytes: &[u8]) {
        if let Some(master) = &mut self.master {
            let _ = master.write_all(bytes);
        }
    }

    /// What the program printed since the last call, and how it ended once it
    /// has (and all its output has been read).
    pub fn poll(&mut self) -> (Vec<u8>, Option<String>) {
        let mut printed = Vec::new();
        while let Ok(chunk) = self.output.try_recv() {
            if chunk.is_empty() {
                self.ended = true;
            } else {
                printed.extend(chunk);
            }
        }
        if !self.ended {
            return (printed, None);
        }
        let status = self
            .child
            .as_mut()
            .and_then(|child| child.wait().ok())
            .map(|status| status.to_string());
        (printed, Some(status.unwrap_or_else(|| "ended".into())))
    }
}

impl Drop for PtyChild {
    /// Ask the program to quit (Ctrl-C to stop a running gdb, then `quit`,
    /// which detaches it from the debug session) and kill it if it does not.
    /// This happens on a thread, so a closing tab never waits.
    fn drop(&mut self) {
        let (Some(mut child), Some(mut master)) = (self.child.take(), self.master.take()) else {
            return;
        };
        std::thread::spawn(move || {
            if child.try_wait().ok().flatten().is_none() {
                let _ = master.write_all(b"\x03");
                std::thread::sleep(Duration::from_millis(200));
                let _ = master.write_all(b"\nquit\n");
                let deadline = Instant::now() + QUIT_GRACE;
                while child.try_wait().ok().flatten().is_none() {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            let _ = child.wait();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell(script: &str) -> Launch {
        Launch {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            env: vec![("TERM", "xterm-256color")],
            env_remove: Vec::new(),
        }
    }

    fn read_until(child: &mut PtyChild, wanted: &str) -> (String, Option<String>) {
        let mut text = String::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            let (bytes, ended) = child.poll();
            text.push_str(&String::from_utf8_lossy(&bytes));
            if text.contains(wanted) || ended.is_some() {
                return (text, ended);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        (text, None)
    }

    #[test]
    fn a_program_runs_on_a_terminal_that_takes_input_and_reports_its_end() {
        let mut child = PtyChild::spawn(
            &shell("test -t 0 && echo tty-yes; stty size; read line; echo got:$line; exit 3"),
            30,
            100,
            || {},
        )
        .unwrap();
        let (text, _) = read_until(&mut child, "30 100");
        assert!(
            text.contains("tty-yes") && text.contains("30 100"),
            "{text:?}"
        );
        child.write(b"hello\n");
        let (text, ended) = read_until(&mut child, "never");
        assert!(text.contains("got:hello"), "{text:?}");
        assert_eq!(ended.as_deref(), Some("exit status: 3"));
    }

    #[test]
    fn the_terminal_can_be_resized_while_the_program_runs() {
        let mut child =
            PtyChild::spawn(&shell("read a; stty size; sleep 5"), 24, 80, || {}).unwrap();
        child.resize(40, 120);
        child.write(b"go\n");
        let (text, _) = read_until(&mut child, "40 120");
        assert!(text.contains("40 120"), "{text:?}");
    }

    #[test]
    fn closing_asks_the_program_to_quit_first() {
        let root = std::env::temp_dir().join(format!("ant-pty-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let record = root.join("record");
        let script = format!(
            "trap 'echo interrupted >> {0}' INT; n=0; while [ $n -lt 200 ]; do n=$((n+1)); read -r line || sleep 0.05; echo $line >> {0}; \
             [ \"$line\" = quit ] && exit 0; done",
            record.display()
        );
        let child = PtyChild::spawn(&shell(&script), 24, 80, || {}).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        drop(child);
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut seen = String::new();
        while Instant::now() < deadline && !seen.contains("quit") {
            seen = std::fs::read_to_string(&record).unwrap_or_default();
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            seen.contains("interrupted") && seen.contains("quit"),
            "{seen:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
