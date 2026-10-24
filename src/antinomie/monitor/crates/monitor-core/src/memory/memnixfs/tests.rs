// SPDX-License-Identifier: GPL-3.0-only
//! MemNixFS backend tests: dump classification, result conversion, the
//! messages, and whole runs against a fake `memnixfs` in the real sandbox.
use super::*;
use crate::memory::{Os, import};
use sha2::Digest;
use std::os::unix::fs::PermissionsExt;

fn temp(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "ant-memnixfs-{name}-{}",
        crate::storage::unique_id()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn vm() -> crate::api::VmConfig {
    crate::api::VmConfig {
        id: "vm".into(),
        name: "Sample".into(),
        ram_mib: 64,
        ..crate::api::VmConfig::default()
    }
}

fn note(name: &str, data_len: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    let name_len = name.len() as u32 + 1;
    bytes.extend(name_len.to_le_bytes());
    bytes.extend((data_len as u32).to_le_bytes());
    bytes.extend(0u32.to_le_bytes());
    bytes.extend(name.as_bytes());
    bytes.push(0);
    bytes.resize(bytes.len().div_ceil(4) * 4, 0);
    bytes.resize(bytes.len() + data_len.div_ceil(4) * 4, 0);
    bytes
}

/// An ELF64 core: one PT_NOTE with `notes`, and a PT_LOAD per
/// `(paddr, vaddr, size)` with that many bytes of data.
fn elf_core(loads: &[(u64, u64, u64)], notes: &[&str]) -> Vec<u8> {
    let note_bytes: Vec<u8> = notes.iter().flat_map(|name| note(name, 8)).collect();
    let header_len = 64 + 56 * (loads.len() as u64 + 1);
    let mut file = vec![0u8; 64];
    file[..4].copy_from_slice(b"\x7fELF");
    file[4] = 2;
    file[5] = 1;
    file[6] = 1;
    file[16..18].copy_from_slice(&4u16.to_le_bytes());
    file[18..20].copy_from_slice(&62u16.to_le_bytes());
    file[20..24].copy_from_slice(&1u32.to_le_bytes());
    file[32..40].copy_from_slice(&64u64.to_le_bytes());
    file[52..54].copy_from_slice(&64u16.to_le_bytes());
    file[54..56].copy_from_slice(&56u16.to_le_bytes());
    file[56..58].copy_from_slice(&(loads.len() as u16 + 1).to_le_bytes());
    let phdr = |kind: u32, offset: u64, vaddr: u64, paddr: u64, size: u64| {
        let mut entry = Vec::new();
        entry.extend(kind.to_le_bytes());
        entry.extend(0u32.to_le_bytes());
        for value in [offset, vaddr, paddr, size, size, 0] {
            entry.extend(value.to_le_bytes());
        }
        entry
    };
    file.extend(phdr(4, header_len, 0, 0, note_bytes.len() as u64));
    let mut offset = header_len + note_bytes.len() as u64;
    for &(paddr, vaddr, size) in loads {
        file.extend(phdr(1, offset, vaddr, paddr, size));
        offset += size;
    }
    file.extend(&note_bytes);
    for &(.., size) in loads {
        file.extend(vec![0xAB; size as usize]);
    }
    file
}

fn write(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn guest_memory_dumps_are_told_from_other_files() {
    let root = temp("format");
    // QEMU dump-guest-memory: physical addresses, QEMU notes.
    let qemu = elf_core(&[(0, 0, 4096), (0xc0000, 0xc0000, 4096)], &["CORE", "QEMU"]);
    assert_eq!(
        format::classify(&write(&root, "qemu.elf", &qemu)),
        Ok(DumpFormat::ElfCore {
            ranges: 2,
            qemu: true,
            vmcoreinfo: false
        })
    );
    // kdump: VMCOREINFO decides, even with a first segment at address 0.
    let vmcore = elf_core(&[(0, 0, 4096)], &["CORE", "VMCOREINFO"]);
    assert!(matches!(
        format::classify(&write(&root, "vmcore", &vmcore)),
        Ok(DumpFormat::ElfCore {
            vmcoreinfo: true,
            qemu: false,
            ..
        })
    ));
    // Physical addresses without notes still count.
    let plain = elf_core(&[(0x1000, 0, 4096)], &[]);
    assert!(format::classify(&write(&root, "plain.elf", &plain)).is_ok());

    // A process core has only virtual addresses.
    let process = elf_core(
        &[(0, 0x400000, 4096), (0, 0x7fff0000, 8192)],
        &["CORE", "CORE", "LINUX"],
    );
    let error = format::classify(&write(&root, "core.1234", &process)).unwrap_err();
    assert!(error.contains("process core"), "{error}");

    assert_eq!(
        format::classify(&write(&root, "a.avml", b"AVML\x02\0\0\0 and more")),
        Ok(DumpFormat::Avml)
    );
    assert_eq!(
        format::classify(&write(&root, "a.lime", b"EMiL\x01\0\0\0 and more")),
        Ok(DumpFormat::Lime)
    );
    assert_eq!(
        format::classify(&write(&root, "a.raw", &[0u8; 4096])),
        Ok(DumpFormat::Raw)
    );
    for (name, bytes) in [
        ("crash.dmp", &b"PAGEDU64 and more"[..]),
        ("hiberfil.sys", &b"hibr and more"[..]),
    ] {
        let error = format::classify(&write(&root, name, bytes)).unwrap_err();
        assert!(error.contains("Windows"), "{error}");
    }
    assert!(
        format::classify(&write(&root, "empty", b""))
            .unwrap_err()
            .contains("empty")
    );
    // A program, a big-endian core, a truncated header, an ELF without data.
    let mut program = qemu.clone();
    program[16] = 2;
    assert!(
        format::classify(&write(&root, "prog", &program))
            .unwrap_err()
            .contains("not a core")
    );
    let mut big = qemu.clone();
    big[5] = 2;
    assert!(format::classify(&write(&root, "big", &big)).is_err());
    assert!(
        format::classify(&write(&root, "short", &qemu[..40]))
            .unwrap_err()
            .contains("truncated")
    );
    let mut arm = qemu.clone();
    arm[18] = 183;
    assert!(
        format::classify(&write(&root, "arm", &arm))
            .unwrap_err()
            .contains("x86-64")
    );
    let empty = elf_core(&[], &["QEMU"]);
    assert!(format::classify(&write(&root, "none", &empty)).is_err());
    // Segment tables that lie about their size do not read past the file.
    let mut lie = qemu.clone();
    lie[56..58].copy_from_slice(&4000u16.to_le_bytes());
    assert!(format::classify(&write(&root, "lie", &lie)).is_err());
    fs::remove_dir_all(root).unwrap();
}

fn lines(path: &Path) -> Vec<serde_json::Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn json_exports_become_typed_tables() {
    let root = temp("json");
    let input = write(
        &root,
        "pslist.json",
        br#"[{"pid":1,"comm":"init","uid":0,"cmdline":"init","tags":["a"],"mixed":1},
            {"pid":116,"comm":"sh","uid":0,"extra":true,"mixed":"x"}]"#,
    );
    let mut out = Vec::new();
    let done = convert::json_table(&input, &mut out, &["pid", "comm", "missing"]).unwrap();
    assert_eq!(done.rows, 2);
    fs::write(root.join("out.jsonl"), &out).unwrap();
    let rows = lines(&root.join("out.jsonl"));
    let names: Vec<_> = rows[0]["columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    // Preferred columns first, then alphabetical; unknown preferred ones dropped.
    assert_eq!(
        names,
        ["pid", "comm", "cmdline", "extra", "mixed", "tags", "uid"]
    );
    let kind = |name: &str| {
        rows[0]["columns"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap()["type"]
            .clone()
    };
    assert_eq!(kind("pid"), "int");
    assert_eq!(kind("extra"), "bool");
    assert_eq!(kind("mixed"), "str", "numbers and text together");
    assert_eq!(kind("tags"), "str");
    assert_eq!(rows[1]["d"], 0);
    assert_eq!(rows[1]["v"][0], 1);
    assert_eq!(rows[1]["v"][5], "[\"a\"]", "lists are shown as text");
    assert!(rows[2]["v"][2].is_null(), "a missing value is empty");

    // Nothing found keeps the columns the report would have.
    let empty = write(&root, "empty.json", b"[]");
    let mut out = Vec::new();
    let done = convert::json_table(&empty, &mut out, &["pid", "comm"]).unwrap();
    assert_eq!(done.rows, 0);
    assert!(String::from_utf8(out).unwrap().contains("\"comm\""));

    for bad in [&b"{}"[..], b"[1,2]", b"[{", b""] {
        let input = write(&root, "bad.json", bad);
        assert!(convert::json_table(&input, &mut Vec::new(), &[]).is_err());
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn text_reports_become_lines() {
    let root = temp("text");
    let long = "x".repeat(20_000);
    let input = write(
        &root,
        "triage.txt",
        format!("# header\r\nfirst\n\n{long}\nlast").as_bytes(),
    );
    let mut out = Vec::new();
    let done = convert::text_table(&input, &mut out).unwrap();
    assert_eq!(done.rows, 5);
    assert!(done.notes.is_empty());
    fs::write(root.join("out.jsonl"), &out).unwrap();
    let rows = lines(&root.join("out.jsonl"));
    assert_eq!(rows[0]["columns"][0]["name"], "line");
    assert_eq!(rows[1]["v"][0], "# header", "carriage returns are dropped");
    assert_eq!(rows[3]["v"][0], "");
    assert!(rows[4]["v"][0].as_str().unwrap().len() < 9000);
    assert!(rows[4]["v"][0].as_str().unwrap().ends_with(" ..."));
    assert_eq!(rows[5]["v"][0], "last");
    // Bytes that are not UTF-8 do not fail the report.
    let binary = write(&root, "bin.txt", b"ok\n\xff\xfe\n");
    assert_eq!(
        convert::text_table(&binary, &mut Vec::new()).unwrap().rows,
        2
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn recovered_files_are_listed_without_following_links() {
    let root = temp("files");
    let tree = root.join("fs");
    fs::create_dir_all(tree.join("etc")).unwrap();
    fs::create_dir_all(tree.join("tmp")).unwrap();
    fs::write(tree.join("etc/passwd"), b"root:x:0:0\n").unwrap();
    fs::write(tree.join("tmp/dropper"), b"MZ").unwrap();
    // A link out of the tree is listed as a link and never read.
    std::os::unix::fs::symlink("/etc/shadow", tree.join("etc/shadow")).unwrap();
    std::os::unix::fs::symlink("../etc", tree.join("tmp/etc")).unwrap();
    let mut out = Vec::new();
    let done = convert::files_table(&tree, &mut out).unwrap();
    assert_eq!(done.rows, 4);
    fs::write(root.join("out.jsonl"), &out).unwrap();
    let rows = lines(&root.join("out.jsonl"));
    let paths: Vec<_> = rows[1..]
        .iter()
        .map(|row| row["v"][0].as_str().unwrap())
        .collect();
    assert_eq!(
        paths,
        ["/etc/passwd", "/etc/shadow", "/tmp/dropper", "/tmp/etc"]
    );
    assert_eq!(rows[1]["v"][1], "file");
    assert_eq!(rows[1]["v"][2], 11);
    let expected: String = sha2::Sha256::digest(b"root:x:0:0\n")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(rows[1]["v"][3], expected.as_str());
    assert_eq!(rows[2]["v"][1], "symlink");
    assert_eq!(rows[2]["v"][3], "-> /etc/shadow");
    assert!(rows[2]["v"][2].is_null());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn messages_explain_partial_failed_and_unstartable_runs() {
    let colored = "\u{1b}[38;2;128;128;128m[DBG] \u{1b}[0mhello\n";
    assert_eq!(messages::strip_colors(colored), "[DBG] hello\n");

    let log = "[INF] ok\n\
        [ERR] ISF/dump MISMATCH! ISF is for kernel 'vmlinux' but\n\
        [WRN] DTB unvalidated! Using best guess dtb=0x75e2e000\n\
        [WRN] DTB unvalidated! Using best guess dtb=0x75e2e000\n\
        [DBG] modules: read state @ 0xffffffff8e744bf8 FAILED — stopping walk\n\
        [WRN] something new happened\n\
        [WRN] mountinfo: cannot read nsproxy.mnt_ns\n";
    let notes = messages::partial_notes(log, false);
    assert_eq!(notes.len(), 5, "{notes:#?}");
    assert!(notes[0].contains("symbol table"));
    assert!(notes[1].contains("page-table root"));
    assert!(notes[2].contains("modules"));
    assert_eq!(notes[3], "MemNixFS warning: something new happened");
    assert!(notes[4].contains("Mount namespaces"));
    assert!(messages::partial_notes("[INF] fine\n[DBG] fine too\n", false).is_empty());

    assert!(
        messages::failure(
            "sandboxed memnixfs exited with exit status: 1.",
            "Error: No ISF found for kernel release '6.12.94'\n"
        )
        .contains("no symbol table")
    );
    assert_eq!(
        messages::failure("x", "[INF] a\nError: the kernel did not resolve\n"),
        "MemNixFS: the kernel did not resolve"
    );
    assert_eq!(
        messages::failure("Isolated analysis timed out.\nDiagnostics: /x", ""),
        "Isolated analysis timed out."
    );

    let missing = "memnixfs: error while loading shared libraries: libyara.so.10: cannot open \
                   shared object file: No such file or directory";
    assert!(messages::startup_problem(missing).contains("sudo apt install libyara10"));
    assert!(
        messages::startup_problem("error while loading shared libraries: libodd.so.1: no")
            .ends_with("libodd.so.1")
    );
    assert!(
        messages::startup_problem("./memnixfs: version `GLIBC_2.38' not found").contains("2.38")
    );
    assert!(messages::startup_problem("boom").contains("boom"));
}

#[test]
fn reports_are_consistent() {
    let mut names = std::collections::BTreeSet::new();
    for report in REPORTS {
        assert!(names.insert(report.name), "{} twice", report.name);
        assert!(report.path.starts_with('/'));
        assert!(!report.help.is_empty() && !report.area.is_empty());
        assert_eq!(
            report.kind == Kind::Table,
            report.path.ends_with(".json"),
            "{}",
            report.name
        );
        assert!(report.columns.is_empty() || report.kind == Kind::Table);
        assert_eq!(super::report(&report.plugin()).unwrap().name, report.name);
    }
    assert!(super::report("processes").is_some());
    assert!(super::report("memnixfs.nope").is_none());
    assert!(super::report("../../etc/passwd").is_none());
}

#[test]
fn old_runs_are_volatility_and_new_ones_keep_their_tool() {
    let old: PluginRun =
        serde_json::from_str(r#"{"id":"r","plugin":"linux.pslist.PsList","state":"finished"}"#)
            .unwrap();
    assert_eq!(old.analyzer, Analyzer::Volatility);
    assert!(old.partial.is_empty() && old.tool_version.is_none());
    let saved = serde_json::to_value(&old).unwrap();
    assert!(
        saved.get("analyzer").is_none(),
        "Volatility runs stay as before"
    );

    let run = PluginRun {
        plugin: "memnixfs.processes".into(),
        analyzer: Analyzer::MemNixFs,
        tool_version: Some("1.2".into()),
        partial: vec!["note".into()],
        ..PluginRun::default()
    };
    let saved = serde_json::to_value(&run).unwrap();
    assert_eq!(saved["analyzer"], "memnixfs");
    let back: PluginRun = serde_json::from_value(saved).unwrap();
    assert_eq!(back, run);
    assert_eq!(back.short_name(), "processes");
}

/// An installed fake: a shell script that answers like MemNixFS does, as
/// the `mode` file next to it says.
struct Fixture {
    root: PathBuf,
    data: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = temp(name);
        let data = root.join("data");
        let tool = data.join("tools/memnixfs");
        fs::create_dir_all(tool.join("lib")).unwrap();
        fs::write(
            tool.join("tool.json"),
            r#"{"id":"memnixfs","version":"1.2"}"#,
        )
        .unwrap();
        let script = tool.join("memnixfs");
        fs::write(
            &script,
            r#"#!/bin/sh
root=$(dirname "$0")
mode=$(cat "$root/mode" 2>/dev/null)
for arg in "$@"; do
  case "$arg" in --help) echo "MemNixFS 1.2 (fake)"; exit 0;; esac
done
vfs=; dir=; symbols=no
while [ $# -gt 0 ]; do
  case "$1" in
    --symbols) symbols=yes;;
    export) vfs="$2"; dir="$3"; break;;
  esac
  shift
done
echo "symbols=$symbols" > "$dir.args" 2>/dev/null
echo "HOME=$HOME LD=$LD_LIBRARY_PATH" >&2
if [ -e /etc/hostname ] && [ "$(cat /proc/net/dev 2>/dev/null | wc -l)" -gt 3 ]; then echo "[ERR] network visible" >&2; exit 3; fi
case "$mode" in
  fail) echo "[ERR] could not find the kernel" >&2; echo "Error: kernel did not resolve" >&2; exit 1;;
  sleep) sleep 120; exit 0;;
  mismatch) echo "[ERR] ISF/dump MISMATCH! ISF is for kernel 'vmlinux' but" >&2;;
esac
echo "[INF] Format: kdump (ELF64 core)" >&2
echo "[WRN] DTB unvalidated! Using best guess dtb=0x1" >&2
case "$vfs" in
  /json/pslist.json)
    mkdir -p "$dir"
    printf '[{"pid":1,"comm":"init","ppid":0,"uid":0,"cmdline":"init"},{"pid":116,"comm":"sh","ppid":1,"uid":0,"cmdline":"/bin/sh"}]' > "$dir/pslist.json";;
  /sys/findevil/triage.txt)
    mkdir -p "$dir"
    printf '# triage\nINFO PROC_SHELL_ACTIVITY pid=116\n' > "$dir/triage.txt";;
  /fs)
    mkdir -p "$dir/etc" "$dir/tmp"
    printf 'root:x:0:0\n' > "$dir/etc/passwd"
    printf 'MZ' > "$dir/tmp/dropper"
    ln -s /etc/shadow "$dir/etc/shadow";;
esac
exit 0
"#,
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let fixture = Fixture { root, data };
        fixture.mode("ok");
        fixture
    }

    fn mode(&self, mode: &str) {
        fs::write(self.data.join("tools/memnixfs/mode"), mode).unwrap();
    }

    fn dump(&self, name: &str, bytes: &[u8], symbols: bool) -> MemoryDump {
        self.dump_with_table(name, bytes, symbols, b"isf")
    }

    fn dump_with_table(&self, name: &str, bytes: &[u8], symbols: bool, table: &[u8]) -> MemoryDump {
        let file = write(&self.root, name, bytes);
        let table = write(&self.root, "isf.json.xz", table);
        import(
            &self.root,
            &vm(),
            &file,
            Os::Linux,
            symbols.then_some((table.as_path(), "Linux 6.12.94".to_owned())),
        )
        .unwrap()
    }

    fn wait(&self, handle: &RunHandle) -> PluginRun {
        let scale = std::env::var("ANTINOMIE_TEST_SCALE")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(1)
            .max(1);
        let deadline = std::time::Instant::now() + Duration::from_secs(120 * scale);
        loop {
            if let Some(run) = handle.progress().finished {
                return run;
            }
            assert!(std::time::Instant::now() < deadline, "the run did not end");
            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn guest_dump() -> Vec<u8> {
    elf_core(&[(0, 0, 4096), (0xc0000, 0xc0000, 4096)], &["CORE", "QEMU"])
}

#[test]
fn a_table_report_is_saved_like_a_volatility_result() {
    let fixture = Fixture::new("table");
    let tool = MemNixFs::locate(&fixture.data).unwrap();
    assert_eq!(tool.version, "1.2");
    let dump = fixture.dump("guest.elf", &guest_dump(), true);
    let handle = tool.start(&dump, "memnixfs.processes").unwrap();
    assert_eq!(handle.run.dump_id, dump.id, "the run belongs to the dump");
    let run = fixture.wait(&handle);
    assert_eq!(run.state, RunState::Finished, "{:?}", run.error);
    assert_eq!(run.rows, 2);
    assert_eq!(run.analyzer, Analyzer::MemNixFs);
    assert_eq!(run.plugin, "memnixfs.processes");
    assert_eq!(run.tool_version.as_deref(), Some("1.2"));
    assert!(run.dump_format.as_deref().unwrap().contains("QEMU"));
    // Partial: the tool said its page-table root was not validated.
    assert_eq!(run.partial.len(), 1, "{:?}", run.partial);
    assert!(run.partial[0].contains("page-table root"));

    // Read back through the Memory tab's own reader.
    let saved = dump.runs();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].analyzer, Analyzer::MemNixFs);
    assert_eq!(saved[0].partial, run.partial);
    let table = crate::memory::read_result(&saved[0].output(), 100).unwrap();
    assert_eq!(table.columns[0].name, "pid");
    assert_eq!(table.rows.len(), 2);
    assert_eq!(table.rows[1].values[3], "sh");
    // The raw export is kept for the Files button; the work folder is gone.
    assert!(saved[0].files().join("pslist.json").is_file());
    assert!(!saved[0].dir.join("work").exists());
    let log = fs::read_to_string(saved[0].log()).unwrap();
    assert!(log.contains("Dump format: ELF64 core of guest physical memory"));
    assert!(log.contains("Partial: The kernel's page-table root"));
    assert!(log.contains("[WRN] DTB unvalidated"), "{log}");
    assert!(!log.contains('\u{1b}'));
    // Offline, with a private home and the package's own libraries.
    assert!(
        log.contains("HOME=/tmp LD=/opt/antinomie-tools/memnixfs/lib"),
        "{log}"
    );
    assert!(!log.contains("network visible"));
    // The dump and its identity are untouched.
    assert_eq!(
        crate::memory::list(std::slice::from_ref(&fixture.root))[0].id,
        dump.id
    );
}

#[test]
fn text_and_recovered_file_reports_are_browsable() {
    let fixture = Fixture::new("files");
    let tool = MemNixFs::locate(&fixture.data).unwrap();
    // No saved symbol table: the result says what that costs.
    let dump = fixture.dump("guest.elf", &guest_dump(), false);
    let text = fixture.wait(&tool.start(&dump, "triage").unwrap());
    assert_eq!(text.state, RunState::Finished, "{:?}", text.error);
    assert_eq!(text.rows, 2);
    assert!(
        text.partial
            .iter()
            .any(|note| note.contains("no saved symbol table"))
    );
    assert!(text.files().join("triage.txt").is_file());

    let files = fixture.wait(&tool.start(&dump, "memnixfs.recovered_files").unwrap());
    assert_eq!(files.state, RunState::Finished, "{:?}", files.error);
    assert_eq!(files.rows, 3);
    assert_eq!(
        fs::read(files.files().join("etc/passwd")).unwrap(),
        b"root:x:0:0\n"
    );
    assert!(files.files().join("tmp/dropper").is_file());
    let table = crate::memory::read_result(&files.output(), 10).unwrap();
    assert_eq!(table.columns[0].name, "PATH");
    assert_eq!(dump.runs().len(), 2, "both results are kept with the dump");
}

#[test]
fn failures_and_missing_reports_are_stated() {
    let fixture = Fixture::new("fail");
    let tool = MemNixFs::locate(&fixture.data).unwrap();
    let dump = fixture.dump("guest.elf", &guest_dump(), true);

    fixture.mode("fail");
    let failed = fixture.wait(&tool.start(&dump, "processes").unwrap());
    assert_eq!(failed.state, RunState::Failed);
    assert_eq!(
        failed.error.as_deref(),
        Some("MemNixFS: kernel did not resolve")
    );
    assert!(failed.partial.is_empty());
    let log = fs::read_to_string(failed.log()).unwrap();
    assert!(log.contains("could not find the kernel"));

    // The tool succeeded but wrote nothing for this report: unavailable.
    fixture.mode("ok");
    let missing = fixture.wait(&tool.start(&dump, "modules").unwrap());
    assert_eq!(missing.state, RunState::Failed);
    assert!(
        missing
            .error
            .as_deref()
            .unwrap()
            .contains("has no modules for this dump"),
        "{:?}",
        missing.error
    );
}

#[test]
fn a_run_can_be_cancelled() {
    let fixture = Fixture::new("cancel");
    let tool = MemNixFs::locate(&fixture.data).unwrap();
    let dump = fixture.dump("guest.elf", &guest_dump(), true);
    fixture.mode("sleep");
    let handle = tool.start(&dump, "processes").unwrap();
    thread::sleep(Duration::from_millis(500));
    handle.cancel();
    let run = fixture.wait(&handle);
    assert_eq!(run.state, RunState::Cancelled);
    assert!(run.error.is_none());
    assert!(!run.dir.join("work").exists());
}

#[test]
fn only_guest_physical_memory_is_given_to_the_tool() {
    let fixture = Fixture::new("refuse");
    let tool = MemNixFs::locate(&fixture.data).unwrap();

    // A process core is an ELF core too, but not the guest's memory.
    let core = elf_core(
        &[(0, 0x400000, 4096), (0, 0x7fff0000, 4096)],
        &["CORE", "LINUX"],
    );
    let dump = fixture.dump("core.1234", &core, true);
    let error = tool.start(&dump, "processes").unwrap_err();
    assert!(error.contains("process core"), "{error}");
    assert!(dump.runs().is_empty(), "no run folder is left behind");

    // A dump of another system, an unfinished or vanished one, an unknown report.
    let mut windows = fixture.dump("win.raw", &[0u8; 4096], false);
    windows.os = Os::Windows;
    assert!(
        tool.start(&windows, "processes")
            .unwrap_err()
            .contains("Linux")
    );
    let mut unfinished = fixture.dump("a.raw", &[0u8; 4096], false);
    unfinished.finished_ms = None;
    assert!(
        tool.start(&unfinished, "processes")
            .unwrap_err()
            .contains("not complete")
    );
    let gone = fixture.dump("gone.raw", &[0u8; 4096], false);
    fs::remove_file(gone.path()).unwrap();
    assert!(tool.start(&gone, "processes").unwrap_err().contains("gone"));
    let good = fixture.dump("good.elf", &guest_dump(), false);
    assert!(
        tool.start(&good, "nonsense")
            .unwrap_err()
            .contains("unknown report")
    );
}

#[test]
fn the_tool_is_found_only_when_installed_and_able_to_start() {
    let root = temp("locate");
    let error = MemNixFs::locate(&root).unwrap_err();
    assert!(error.contains("not installed"), "{error}");
    fs::remove_dir_all(root).unwrap();

    // Installed, but a library is missing: the message names the package.
    let fixture = Fixture::new("libs");
    let script = fixture.data.join("tools/memnixfs/memnixfs");
    fs::write(
        &script,
        "#!/bin/sh\necho 'memnixfs: error while loading shared libraries: libsnappy.so.1: \
         cannot open shared object file' >&2\nexit 127\n",
    )
    .unwrap();
    let error = MemNixFs::locate(&fixture.data).unwrap_err();
    assert!(error.contains("sudo apt install libsnappy1v5"), "{error}");
}

const BANNER: &str =
    "Linux version 6.12.94 (debian-kernel@lists.debian.org) #1 SMP Debian 6.12.94-1";

/// A symbol table (xz JSON) whose `linux_banner` holds `banner`.
fn isf_with_banner(banner: &str) -> Vec<u8> {
    use base64_shim::encode;
    let json = format!(
        r#"{{"metadata":{{"linux":{{"name":"vmlinux"}}}},"types":{{}},"symbols":{{"init_task":{{"address":1}},"linux_banner":{{"address":2,"constant_data":"{}"}}}}}}"#,
        encode(format!("{banner}\n\0").as_bytes())
    );
    let mut writer =
        lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1)).unwrap();
    std::io::Write::write_all(&mut writer, json.as_bytes()).unwrap();
    writer.finish().unwrap()
}

mod base64_shim {
    pub fn encode(data: &[u8]) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }
}

#[test]
fn a_matching_banner_drops_the_false_mismatch_and_a_different_one_keeps_it() {
    let log = "[ERR] ISF/dump MISMATCH! ISF is for kernel 'vmlinux' but\n\
               [WRN] DTB unvalidated! Using best guess dtb=0x1\n";
    let verified = messages::partial_notes(log, true);
    assert_eq!(verified.len(), 1, "{verified:?}");
    assert!(verified[0].contains("page-table root"));
    assert_eq!(messages::partial_notes(log, false).len(), 2);

    let fixture = Fixture::new("banner");
    let tool = MemNixFs::locate(&fixture.data).unwrap();
    fixture.mode("mismatch");
    let mut memory = guest_dump();
    memory.extend_from_slice(b"\0junk\0");
    memory.extend_from_slice(BANNER.as_bytes());
    memory.extend_from_slice(b"\n\0");

    let same = fixture.dump_with_table("same.elf", &memory, true, &isf_with_banner(BANNER));
    let run = fixture.wait(&tool.start(&same, "memnixfs.processes").unwrap());
    assert_eq!(run.state, RunState::Finished, "{:?}", run.error);
    assert_eq!(run.partial.len(), 1, "{:?}", run.partial);
    assert!(run.partial[0].contains("page-table root"));

    let other = isf_with_banner(&BANNER.replace("6.12.94", "6.1.0"));
    let different = fixture.dump_with_table("different.elf", &memory, true, &other);
    let run = fixture.wait(&tool.start(&different, "memnixfs.processes").unwrap());
    assert_eq!(run.partial.len(), 2, "{:?}", run.partial);
    assert!(run.partial[0].contains("symbol table"));

    // A table that cannot be read never drops the warning.
    let broken = fixture.dump_with_table("broken.elf", &memory, true, b"isf");
    let run = fixture.wait(&tool.start(&broken, "memnixfs.processes").unwrap());
    assert_eq!(run.partial.len(), 2, "{:?}", run.partial);
}

#[test]
fn the_banner_verdict_is_reached_once_per_dump_and_a_stop_gives_none() {
    let root = temp("verdict");
    fs::create_dir_all(&root).unwrap();
    let dump = root.join("dump.bin");
    let mut memory = vec![7u8; 1000];
    memory.extend_from_slice(BANNER.as_bytes());
    fs::write(&dump, &memory).unwrap();
    let table = root.join("symbols.json.xz");
    fs::write(&table, isf_with_banner(BANNER)).unwrap();
    let go = AtomicBool::new(false);
    let stopped = AtomicBool::new(true);

    // Stopped: not verified, and not remembered.
    assert!(!banner::matches(&table, &dump, &stopped));
    assert!(banner::matches(&table, &dump, &go));
    // The table is gone from under it: only a remembered verdict says yes.
    fs::write(&table, b"not a table").unwrap();
    assert!(banner::matches(&table, &dump, &go));
    // Another dump is checked on its own.
    let other = root.join("other.bin");
    fs::write(&other, &memory).unwrap();
    assert!(!banner::matches(&table, &other, &go));
    fs::remove_dir_all(&root).unwrap();
}
