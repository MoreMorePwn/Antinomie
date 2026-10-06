// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
use antinomie_monitor_core::{
    recording::open_recording, Backend, BackendOptions, Command, ExecRequest, GuestCredentials,
    Notification, RunSummary, Snapshot, VmConfig,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

struct Harness {
    backend: Backend,
    snapshot: Snapshot,
    runs: BTreeMap<String, RunSummary>,
    output: BTreeMap<String, Vec<u8>>,
    replies: BTreeMap<u64, Result<String, String>>,
}

impl Harness {
    fn receive(&mut self) -> Result<(), String> {
        while let Some(message) = self.backend.try_recv() {
            match message {
                Notification::Snapshot(snapshot) => self.snapshot = snapshot,
                Notification::RunStarted(run) => {
                    self.runs.insert(run.id.clone(), run);
                }
                Notification::Terminal { run_id, data, .. } => {
                    let output = self.output.entry(run_id).or_default();
                    if output.len().saturating_add(data.len()) > 1024 * 1024 {
                        return Err("test terminal output exceeds 1 MiB".into());
                    }
                    output.extend(data);
                }
                Notification::CommandResult {
                    id,
                    success,
                    message,
                } => {
                    self.replies
                        .insert(id, if success { Ok(message) } else { Err(message) });
                }
                Notification::TerminalScreen { .. } => {}
            }
        }
        Ok(())
    }

    fn command(&mut self, command: Command) -> Result<String, String> {
        let id = self.backend.send(command)?;
        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            self.receive()?;
            if let Some(result) = self.replies.remove(&id) {
                return result;
            }
            if Instant::now() >= deadline {
                return Err(format!("test command {id} exceeded deadline"));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn launch(&mut self, script: &str, uid: u32) -> Result<RunSummary, String> {
        let before = self.runs.len();
        self.command(Command::Execute(ExecRequest {
            path: "/bin/bash".into(),
            args: vec!["-c".into(), script.into()],
            uid,
            gid: uid,
            ..ExecRequest::default()
        }))?;
        self.receive()?;
        if self.runs.len() != before + 1 {
            return Err("launch did not publish exactly one run".into());
        }
        self.runs
            .values()
            .find(|run| run.request.args.get(1).is_some_and(|s| s == script))
            .cloned()
            .ok_or_else(|| "launched run missing".into())
    }

    fn wait_pid1(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            self.receive()?;
            if self
                .snapshot
                .serial_log
                .as_ref()
                .and_then(|path| fs::read(path).ok())
                .is_some_and(|data| data.windows(8).any(|part| part == b"systemd["))
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("Debian PID1 startup deadline".into());
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn marker(&mut self, run: &RunSummary, marker: &[u8]) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            self.receive()?;
            if self
                .output
                .get(&run.id)
                .is_some_and(|data| data.windows(marker.len()).any(|v| v == marker))
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "marker {} missing; output {}",
                    String::from_utf8_lossy(marker),
                    String::from_utf8_lossy(
                        self.output
                            .get(&run.id)
                            .map(Vec::as_slice)
                            .unwrap_or_default()
                    )
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

fn owned_qmp(serial: &Path) -> Result<PathBuf, String> {
    for entry in fs::read_dir("/proc").map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if fs::read_link(entry.path().join("fd/1")).ok().as_deref() != Some(serial) {
            continue;
        }
        let Ok(command) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let arguments: Vec<_> = command.split(|&byte| byte == 0).collect();
        if !arguments
            .windows(2)
            .any(|pair| pair == [b"-nic".as_slice(), b"none".as_slice()])
        {
            return Err("test VM unexpectedly has a network adapter".into());
        }
        if let Some(pair) = arguments.windows(2).find(|pair| pair[0] == b"-qmp") {
            let option = std::str::from_utf8(pair[1]).map_err(|e| e.to_string())?;
            let socket = option
                .strip_prefix("unix:")
                .and_then(|s| s.strip_suffix(",server=on,wait=off"))
                .ok_or("unexpected owned QMP option")?;
            return Ok(PathBuf::from(socket.replace(",,", ",")));
        }
    }
    Err("test-owned QEMU QMP socket not found".into())
}

struct Qmp {
    socket: UnixStream,
    reader: BufReader<UnixStream>,
    sequence: u64,
}

impl Qmp {
    fn connect(path: &Path) -> Result<Self, String> {
        let socket = UnixStream::connect(path).map_err(|e| e.to_string())?;
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| e.to_string())?;
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| e.to_string())?;
        let reader = BufReader::new(socket.try_clone().map_err(|e| e.to_string())?);
        let mut qmp = Self {
            socket,
            reader,
            sequence: 0,
        };
        qmp.read()?;
        qmp.execute("qmp_capabilities", json!({}))?;
        Ok(qmp)
    }

    fn read(&mut self) -> Result<Value, String> {
        let mut data = Vec::new();
        self.reader
            .by_ref()
            .take(1024 * 1024)
            .read_until(b'\n', &mut data)
            .map_err(|e| e.to_string())?;
        if data.last() != Some(&b'\n') {
            return Err("truncated or oversized QMP reply".into());
        }
        serde_json::from_slice(&data).map_err(|e| e.to_string())
    }

    fn execute(&mut self, command: &str, args: Value) -> Result<Value, String> {
        self.sequence += 1;
        serde_json::to_writer(
            &mut self.socket,
            &json!({"execute": command, "arguments": args, "id": self.sequence}),
        )
        .map_err(|e| e.to_string())?;
        self.socket.write_all(b"\n").map_err(|e| e.to_string())?;
        for _ in 0..256 {
            let response = self.read()?;
            if response.get("id").and_then(Value::as_u64) == Some(self.sequence) {
                if response.get("error").is_some() {
                    return Err(format!("QMP {command} rejected"));
                }
                return response
                    .get("return")
                    .cloned()
                    .ok_or_else(|| "QMP result missing".into());
            }
        }
        Err("QMP response budget exceeded".into())
    }

    fn key(&mut self, key: &str) -> Result<(), String> {
        self.keys(&[key])
    }

    fn keys(&mut self, keys: &[&str]) -> Result<(), String> {
        self.execute(
            "send-key",
            json!({"keys": keys.iter().map(|key| json!({"type": "qcode", "data": key})).collect::<Vec<_>>(), "hold-time": 40}),
        )?;
        thread::sleep(Duration::from_millis(80));
        Ok(())
    }

    fn text(&mut self, text: &str) -> Result<(), String> {
        for character in text.chars() {
            match character {
                'a'..='z' | '0'..='9' => self.key(&character.to_string())?,
                ' ' => self.key("spc")?,
                '-' => self.key("minus")?,
                '/' => self.key("slash")?,
                '\n' => self.key("ret")?,
                _ => return Err("unsupported test keyboard character".into()),
            }
        }
        Ok(())
    }

    fn password(&mut self, password: &str) -> Result<(), String> {
        for character in password.chars() {
            if !character.is_ascii_hexdigit() || character.is_ascii_uppercase() {
                return Err("test password is not a lowercase hex value".into());
            }
            self.key(&character.to_string())?;
        }
        self.key("ret")
    }

    fn screenshot(&mut self, path: &Path) -> Result<(), String> {
        self.execute("screendump", json!({"filename": path, "format": "png"}))?;
        Ok(())
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 2 {
        return Err("usage: debian-smoke BUNDLE NEW_DATA_DIR".into());
    }
    let root = PathBuf::from(&arguments[1]);
    if root.exists() {
        return Err("test data directory must not already exist".into());
    }
    let mut random = [0; 16];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut random))
        .map_err(|e| e.to_string())?;
    let password: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let credentials = GuestCredentials::new("qauser".into(), password.clone())?;
    if format!("{credentials:?}").contains(&password) {
        return Err("credentials Debug exposes password".into());
    }
    let mut test = Harness {
        backend: Backend::new(BackendOptions {
            data_dir: root.clone(),
            bundle_dir: PathBuf::from(&arguments[0]),
            headless: std::env::var_os("ANTINOMIE_QA_SHOW_GUI").is_none(),
            shutdown_timeout: Duration::from_secs(60),
            ..BackendOptions::default()
        })?,
        snapshot: Snapshot::default(),
        runs: BTreeMap::new(),
        output: BTreeMap::new(),
        replies: BTreeMap::new(),
    };
    test.command(Command::CreateWithCredentials {
        vm: VmConfig {
            name: "Debian QA".into(),
            cpus: 4,
            ram_mib: 2048,
            disk_gib: 8,
            ..VmConfig::default()
        },
        credentials,
    })?;
    test.receive()?;
    let vm_id = test
        .snapshot
        .vms
        .first()
        .ok_or("created VM missing")?
        .id
        .clone();
    test.command(Command::Start {
        vm_id: vm_id.clone(),
    })?;
    test.wait_pid1()?;
    let readiness = test.launch("set -e; for n in {1..90}; do if systemctl is-active --quiet lightdm && systemctl is-active --quiet systemd-user-sessions && pgrep -u lightdm -f '^/usr/sbin/lightdm-gtk-greeter' >/dev/null; then break; fi; sleep 1; done; systemctl is-active lightdm systemd-user-sessions; pgrep -u lightdm -f '^/usr/sbin/lightdm-gtk-greeter' >/dev/null; test $(id -u) = 1000; test $(id -un) = qauser; getent group sudo | grep -w qauser; if sudo -n true 2>/dev/null; then exit 9; fi; test $(awk -F= '$1 == \"ID\" {print $2}' /etc/os-release) = debian; echo DEBIAN-READY", 1000)?;
    test.marker(&readiness, b"DEBIAN-READY")?;
    let serial = test
        .snapshot
        .serial_log
        .clone()
        .ok_or("serial log missing")?;
    let mut qmp = Qmp::connect(&owned_qmp(&serial)?)?;
    thread::sleep(Duration::from_secs(3));
    qmp.screenshot(&root.join("greeter.png"))?;
    println!("GREETER_READY {}", root.join("greeter.png").display());
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let mut enter_username = true;
    if std::env::var_os("ANTINOMIE_QA_LOGIN_BARRIER").is_some() {
        let mut response = String::new();
        std::io::stdin()
            .read_line(&mut response)
            .map_err(|e| e.to_string())?;
        enter_username = response.trim() != "password";
    }
    if enter_username {
        qmp.text("qauser")?;
        qmp.key("tab")?;
    }
    qmp.password(&password)?;
    let desktop = test.launch("set -e; for n in {1..60}; do if pgrep -u 1000 -x xfce4-session >/dev/null; then echo DESKTOP-PASS; exit; fi; sleep 1; done; exit 8", 1000)?;
    test.marker(&desktop, b"DESKTOP-PASS")?;
    thread::sleep(Duration::from_secs(3));
    qmp.screenshot(&root.join("desktop.png"))?;
    println!("DESKTOP_READY {}", root.join("desktop.png").display());
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    if std::env::var_os("ANTINOMIE_QA_LOGIN_BARRIER").is_some() {
        let mut response = String::new();
        std::io::stdin()
            .read_line(&mut response)
            .map_err(|e| e.to_string())?;
        if response.trim() == "enter" {
            qmp.key("ret")?;
            thread::sleep(Duration::from_secs(2));
        }
    }
    qmp.keys(&["ctrl", "alt", "t"])?;
    thread::sleep(Duration::from_secs(4));
    qmp.text("sudo -k touch /tmp/antinomie-sudo-pass\n")?;
    thread::sleep(Duration::from_secs(1));
    qmp.password(&password)?;
    let sudo = test.launch("set -e; for n in {1..30}; do if test -e /tmp/antinomie-sudo-pass; then test $(stat -c %u /tmp/antinomie-sudo-pass) = 0; echo SUDO-AUTH-PASS; exit; fi; sleep 1; done; exit 7", 1000)?;
    test.marker(&sudo, b"SUDO-AUTH-PASS")?;
    qmp.screenshot(&root.join("sudo.png"))?;
    let content = test.launch("set -e; printf 'DEBIAN-PERSISTENT\n' > /home/qauser/monitor-test; cat /home/qauser/monitor-test; printf 'TERMINAL-READY\n'; read -r line; test \"$line\" = ping; /usr/bin/printf 'TERMINAL-PASS\n'", 1000)?;
    test.marker(&content, b"TERMINAL-READY")?;
    test.command(Command::TerminalInput {
        run_id: content.id.clone(),
        data: b"ping\n".to_vec(),
    })?;
    test.marker(&content, b"TERMINAL-PASS")?;
    let upload = root.join("upload-test.sh");
    fs::write(
        &upload,
        b"#!/bin/bash\nset -e\ntest $(id -u) = 1000\necho UPLOAD-PASS\n",
    )
    .map_err(|e| e.to_string())?;
    test.command(Command::Upload {
        source: upload,
        destination: "/home/qauser/upload-test.sh".into(),
        executable: true,
        overwrite: false,
    })?;
    let uploaded = test.launch("set -e; /home/qauser/upload-test.sh", 1000)?;
    test.marker(&uploaded, b"UPLOAD-PASS")?;
    test.command(Command::Stop)?;
    test.command(Command::Start {
        vm_id: vm_id.clone(),
    })?;
    test.wait_pid1()?;
    let persisted = test.launch(
        "set -e; grep -Fx DEBIAN-PERSISTENT /home/qauser/monitor-test; echo PERSISTENCE-PASS",
        1000,
    )?;
    test.marker(&persisted, b"PERSISTENCE-PASS")?;
    test.command(Command::Stop)?;
    test.command(Command::Duplicate {
        vm_id: vm_id.clone(),
        name: "Debian QA copy".into(),
    })?;
    test.receive()?;
    let copy_id = test
        .snapshot
        .vms
        .iter()
        .find(|vm| vm.id != vm_id)
        .ok_or("duplicate missing")?
        .id
        .clone();
    test.command(Command::Start { vm_id: copy_id })?;
    test.wait_pid1()?;
    let copied = test.launch("set -e; test $(id -un) = qauser; grep -Fx DEBIAN-PERSISTENT /home/qauser/monitor-test; echo DUPLICATE-PASS", 1000)?;
    test.marker(&copied, b"DUPLICATE-PASS")?;
    test.command(Command::Stop)?;
    test.command(Command::Reset {
        vm_id: vm_id.clone(),
        confirmed: true,
    })?;
    test.command(Command::Start {
        vm_id: vm_id.clone(),
    })?;
    test.wait_pid1()?;
    let reset = test.launch("set -e; test $(id -un) = qauser; getent group sudo | grep -w qauser; test ! -e /home/qauser/monitor-test; test ! -e /home/qauser/upload-test.sh; echo RESET-PASS", 1000)?;
    test.marker(&reset, b"RESET-PASS")?;
    test.command(Command::Stop)?;
    test.receive()?;
    let mut network_vm = test
        .snapshot
        .vms
        .iter()
        .find(|vm| vm.id == vm_id)
        .ok_or("original VM missing")?
        .clone();
    network_vm.nat = true;
    test.command(Command::Save(network_vm))?;
    test.command(Command::Start { vm_id })?;
    test.wait_pid1()?;
    let network = test.launch("set -e; for n in {1..30}; do if ip -4 route get 1.1.1.1 >/dev/null 2>&1; then echo NAT-DHCP-PASS; exit; fi; sleep 1; done; exit 6", 1000)?;
    test.marker(&network, b"NAT-DHCP-PASS")?;
    test.command(Command::Stop)?;
    test.backend.shutdown()?;
    let recording = open_recording(&content.directory).map_err(|e| e.to_string())?;
    let payload = b"DEBIAN-PERSISTENT\n";
    if !recording.events.iter().any(|event| {
        event.syscall_nr == 1
            && event.phase == 1
            && event.fields.iter().any(|field| {
                field
                    .preview
                    .windows(payload.len())
                    .any(|part| part == payload)
            })
    }) {
        return Err("expected guest write payload not captured".into());
    }
    for run in test.runs.values() {
        for name in [
            "run.json",
            "terminal-transcript.raw",
            "terminal.journal",
            "terminal-screen.ansi",
            "manifest.json",
        ] {
            let path = run.directory.join(name);
            if path.is_file()
                && contains_secret(
                    File::open(&path).map_err(|e| e.to_string())?,
                    password.as_bytes(),
                )?
            {
                return Err("test password was retained in recording metadata/output".into());
            }
        }
    }
    println!(
        "PASS: Debian13/Xfce, password GUI login, password-authenticated sudo, four CPUs, terminal I/O, upload, dynamic programs, traced payload, reboot persistence, duplicate and reset account, explicit NAT DHCP route; {} retained events",
        recording.events.len()
    );
    Ok(())
}

fn contains_secret(mut reader: impl Read, secret: &[u8]) -> Result<bool, String> {
    if secret.is_empty() {
        return Err("empty test secret".into());
    }
    let mut chunk = [0u8; 8192];
    let mut window = Vec::with_capacity(chunk.len() + secret.len());
    loop {
        let count = reader.read(&mut chunk).map_err(|e| e.to_string())?;
        if count == 0 {
            return Ok(false);
        }
        window.extend_from_slice(&chunk[..count]);
        if window.windows(secret.len()).any(|part| part == secret) {
            return Ok(true);
        }
        let discard = window.len().saturating_sub(secret.len() - 1);
        window.drain(..discard);
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::contains_secret;
    use std::io::Cursor;

    #[test]
    fn secret_scan_detects_a_chunk_boundary_match() {
        let secret = b"test-secret";
        let mut data = vec![b'x'; 8190];
        data.extend_from_slice(secret);
        data.extend_from_slice(b"remaining output");
        assert!(contains_secret(Cursor::new(data), secret).unwrap());
    }

    #[test]
    fn secret_scan_rejects_empty_secret_and_accepts_clean_output() {
        assert!(contains_secret(Cursor::new(b"output"), b"").is_err());
        assert!(!contains_secret(Cursor::new(b"output"), b"test-secret").unwrap());
    }
}
