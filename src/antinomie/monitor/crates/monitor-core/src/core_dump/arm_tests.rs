// SPDX-License-Identifier: GPL-3.0-only
//! 32-bit ARM process cores: a real one (`tests/fixtures/arm-core`, written by
//! qemu-user for a Thumb-state crash of an EABI5 program) and synthesized ones
//! in the layout `fs/compat_binfmt_elf.c` gives AArch32 tasks of an arm64 guest.
use super::*;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/arm-core/thumb-crash.core")
}

#[test]
fn a_real_thumb_crash_core_gives_registers_notes_and_memory() {
    let core = CoreDump::open(&fixture_path()).unwrap();
    assert_eq!(core.machine, EM_ARM);
    assert_eq!(core.threads.len(), 1);
    let thread = &core.threads[0];
    assert_eq!(thread.signal, 11);
    assert_eq!(thread.registers.len(), 18);
    assert_eq!(thread.register("pc"), Some(0x1037e));
    assert_eq!(thread.register("sp"), Some(0x407f_e710));
    assert_eq!(thread.register("lr"), Some(0x103a1));
    assert_eq!(thread.register("r0"), Some(4));
    assert_eq!(thread.register("cpsr"), Some(0x200b_0030));
    assert_eq!(thread.register("rip"), None);
    assert!(
        core.notes
            .iter()
            .any(|n| n == "process: crash; arguments: ./crash ")
    );
    assert_eq!(core.auxv.len(), 19 - 1);
    assert_eq!(core.mappings.len(), 2);
    assert_eq!(core.mappings[0].permissions(), "r-x");
    assert_eq!(core.mappings[1].permissions(), "rw-");
    assert!(core.warnings.is_empty(), "{:?}", core.warnings);
    // The faulting Thumb instruction and its neighbours, as captured.
    let bytes = core.read_virtual(0x1037c, 4).unwrap();
    assert_eq!(bytes, [Some(0x1b), Some(0x68), Some(0x18), Some(0x60)]);
    // Stack memory at sp reads; the page after it was not captured.
    assert!(
        core.read_virtual(0x407f_e710, 16)
            .unwrap()
            .iter()
            .all(Option::is_some)
    );
    assert_eq!(core.read_virtual(0x407f_f000, 1).unwrap(), [None]);
}

#[test]
fn the_pc_is_decoded_as_thumb_from_cpsr_and_other_addresses_by_their_low_bit() {
    let core = CoreDump::open(&fixture_path()).unwrap();
    // The thread's own pc: CPSR.T is set.
    assert_eq!(core.arm_mode_at(0x1037e), (ArmMode::Thumb, 0x1037e));
    // A symbol's low bit marks Thumb; without it, and not a pc, the code is ARM.
    assert_eq!(core.arm_mode_at(0x1_0379), (ArmMode::Thumb, 0x1_0378));
    assert_eq!(core.arm_mode_at(0x1036c), (ArmMode::Arm, 0x1036c));
    let thumb = core.disassemble(0x1037e, 6).unwrap();
    assert!(thumb.contains("(Thumb mode)"), "{thumb}");
    let lines: Vec<&str> = thumb.lines().skip(1).collect();
    assert_eq!(
        lines,
        [
            "000000000001037e  str r0, [r3]",
            "0000000000010380  adds r0, #5",
            "0000000000010382  bx lr",
        ]
    );
    let marked = core.disassemble(0x1_0379, 8).unwrap();
    assert!(marked.contains("at 0x10378 (Thumb mode)"), "{marked}");
    assert!(
        marked.contains("0000000000010378  ldr r3, [pc, #8]"),
        "{marked}"
    );
    let arm = core.disassemble(0x1036c, 12).unwrap();
    assert!(arm.contains("(ARM mode)"), "{arm}");
    let lines: Vec<&str> = arm.lines().skip(1).collect();
    assert_eq!(
        lines,
        [
            "000000000001036c  add r0, r0, r0, lsl #1",
            "0000000000010370  add r0, r0, #1",
            "0000000000010374  bx lr",
        ]
    );
    // Memory the core does not hold stops the listing.
    let edge = core.disassemble(0x10ffc, 16).unwrap();
    assert!(edge.contains("[stopped at missing memory]"), "{edge}");
    assert!(core.disassemble(0x30000, 4).is_err());
}

fn put32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn note(owner: &[u8], kind: u32, desc: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend((owner.len() as u32 + 1).to_le_bytes());
    out.extend((desc.len() as u32).to_le_bytes());
    out.extend(kind.to_le_bytes());
    out.extend(owner);
    out.push(0);
    out.resize(out.len().next_multiple_of(4), 0);
    out.extend(desc);
    out.resize(out.len().next_multiple_of(4), 0);
    out
}

fn prstatus(tid: u32, ppid: u32, signal: u16, regs: [u32; 18]) -> Vec<u8> {
    let mut desc = vec![0u8; 148];
    desc[12..14].copy_from_slice(&signal.to_le_bytes());
    put32(&mut desc, 24, tid);
    put32(&mut desc, 28, ppid);
    for (index, value) in regs.iter().enumerate() {
        put32(&mut desc, 72 + index * 4, *value);
    }
    note(b"CORE", 1, &desc)
}

/// What the guest's `elf_core_dump` writes for an AArch32 task: two threads with
/// VFP sets, siginfo, prpsinfo, auxv and NT_FILE.
fn guest_core(vfp_size: usize) -> Vec<u8> {
    let mut regs = [0u32; 18];
    regs[15] = 0x10074; // pc
    regs[13] = 0x7efff000; // sp
    regs[16] = 0x10; // cpsr: user mode, ARM state
    let mut notes = prstatus(100, 99, 11, regs);
    let mut vfp = vec![0u8; vfp_size];
    vfp[..8].copy_from_slice(&0x4009_21fb_5444_2d18u64.to_le_bytes());
    if vfp_size >= 260 {
        put32(&mut vfp, 256, 0x0300_0000);
    }
    notes.extend(note(b"LINUX", 0x400, &vfp));
    regs[15] = 0x1007c; // the Thumb halfwords after the two ARM words
    regs[16] = 0x30; // Thumb
    notes.extend(prstatus(101, 99, 0, regs));
    notes.extend(note(b"LINUX", 0x400, &vec![0u8; 260]));
    let mut prpsinfo = vec![0u8; 124];
    prpsinfo[28..32].copy_from_slice(b"samp");
    prpsinfo[44..52].copy_from_slice(b"samp -v ");
    notes.extend(note(b"CORE", 3, &prpsinfo));
    let mut siginfo = vec![0u8; 128];
    put32(&mut siginfo, 0, 11);
    put32(&mut siginfo, 8, 1); // SEGV_MAPERR
    put32(&mut siginfo, 12, 0xdead_0004); // si_addr at the 32-bit union offset
    notes.extend(note(b"CORE", 0x5349_4749, &siginfo));
    let mut auxv = Vec::new();
    for (key, value) in [(6u32, 4096u32), (7, 0x4000_0000), (25, 0x7efff8f0), (0, 0)] {
        auxv.extend(key.to_le_bytes());
        auxv.extend(value.to_le_bytes());
    }
    notes.extend(note(b"CORE", 6, &auxv));
    let mut files = Vec::new();
    for word in [1u32, 4096, 0x10000, 0x11000, 0] {
        files.extend(word.to_le_bytes());
    }
    files.extend(b"/tmp/samp\0");
    notes.extend(note(b"CORE", 0x4649_4c45, &files));

    let notes_at = 52 + 2 * 32;
    let code_at = (notes_at + notes.len()).next_multiple_of(16);
    let mut data = vec![0u8; code_at + 16];
    data[..8].copy_from_slice(b"\x7fELF\x01\x01\x01\x00");
    data[16..18].copy_from_slice(&4u16.to_le_bytes());
    data[18..20].copy_from_slice(&40u16.to_le_bytes());
    put32(&mut data, 28, 52);
    data[42..44].copy_from_slice(&32u16.to_le_bytes());
    data[44..46].copy_from_slice(&2u16.to_le_bytes());
    for (index, fields) in [
        [4, notes_at as u32, 0, 0, notes.len() as u32, 0, 0, 0],
        [1, code_at as u32, 0x10074, 0, 16, 0x1000, 5, 0x1000],
    ]
    .iter()
    .enumerate()
    {
        for (field, value) in fields.iter().enumerate() {
            put32(&mut data, 52 + index * 32 + field * 4, *value);
        }
    }
    data[notes_at..notes_at + notes.len()].copy_from_slice(&notes);
    // add r0, r0, #1 ; bx lr ; then the Thumb instructions movs r0, #7 ; bx lr.
    for (index, word) in [0xe280_0001u32, 0xe12f_ff1e, 0x4770_2007, 0]
        .iter()
        .enumerate()
    {
        put32(&mut data, code_at + index * 4, *word);
    }
    data
}

/// A core written to a temporary file that goes away with it (reads need the file).
#[derive(Debug)]
struct Held(CoreDump, PathBuf);
impl std::ops::Deref for Held {
    type Target = CoreDump;
    fn deref(&self) -> &CoreDump {
        &self.0
    }
}
impl Drop for Held {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.1);
    }
}

fn open_bytes(name: &str, data: &[u8]) -> Result<Held> {
    let path =
        std::env::temp_dir().join(format!("antinomie-core-arm-{name}-{}", std::process::id()));
    fs::write(&path, data).unwrap();
    let core = CoreDump::open(&path);
    match core {
        Ok(core) => Ok(Held(core, path)),
        Err(error) => {
            fs::remove_file(path).unwrap();
            Err(error)
        }
    }
}

#[test]
fn a_guest_written_elf32_core_has_vfp_siginfo_files_and_auxv() {
    let core = open_bytes("guest", &guest_core(260)).unwrap();
    assert_eq!(core.machine, EM_ARM);
    assert_eq!(core.threads.len(), 2);
    assert_eq!((core.threads[0].tid, core.threads[0].parent_pid), (100, 99));
    assert_eq!(core.threads[0].signal, 11);
    let first = &core.threads[0];
    // VFP follows the thread whose PRSTATUS it came after.
    assert_eq!(first.register("d0"), Some(0x4009_21fb_5444_2d18));
    assert_eq!(first.register("fpscr"), Some(0x0300_0000));
    assert_eq!(first.registers.len(), 18 + 33);
    assert_eq!(core.threads[1].register("d0"), Some(0));
    assert_eq!(core.threads[1].register("cpsr"), Some(0x30));
    assert!(
        core.notes
            .contains(&"signal info: signo=11 errno=0 code=1".into())
    );
    assert!(core.notes.contains(&"fault address: 0xdead0004".into()));
    assert!(
        core.notes
            .contains(&"process: samp; arguments: samp -v ".into())
    );
    assert_eq!(core.auxv, [(6, 4096), (7, 0x4000_0000), (25, 0x7efff8f0)]);
    assert_eq!(core.files.len(), 1);
    assert_eq!(
        (
            core.files[0].start,
            core.files[0].end,
            core.files[0].file_offset
        ),
        (0x10000, 0x11000, 0)
    );
    assert_eq!(core.files[0].path, "/tmp/samp");
    assert!(core.warnings.is_empty(), "{:?}", core.warnings);
    // ARM at thread 1's pc; thread 2's pc (even address, T set) is Thumb.
    assert!(
        core.disassemble(0x10074, 8)
            .unwrap()
            .contains("add r0, r0, #1")
    );
    let thumb = core.disassemble(0x1007c, 4).unwrap();
    assert!(
        thumb.contains("(Thumb mode)") && thumb.contains("movs r0, #7"),
        "{thumb}"
    );
}

#[test]
fn a_short_vfp_note_warns_and_a_foreign_elf32_is_refused() {
    let core = open_bytes("short", &guest_core(128)).unwrap();
    assert!(core.warnings.iter().any(|w| w == "truncated NT_ARM_VFP"));
    assert_eq!(core.threads[0].register("d0"), None);
    // ELF32 of another machine (x86), a big-endian one, and an ELF64 ARM core.
    for (what, patch) in [("x86", (18usize, 3u16)), ("mips", (18, 8))] {
        let mut data = guest_core(260);
        data[patch.0..patch.0 + 2].copy_from_slice(&patch.1.to_le_bytes());
        let error = open_bytes(what, &data).unwrap_err().to_string();
        assert!(error.contains("32-bit ARM"), "{what}: {error}");
    }
    let mut data = guest_core(260);
    data[5] = 2;
    assert!(open_bytes("big", &data).is_err());
    let mut data = guest_core(260);
    data[4] = 2;
    assert!(open_bytes("class64", &data).is_err());
    // The program-header table must fit: a 32-byte entry size minimum.
    let mut data = guest_core(260);
    data[42..44].copy_from_slice(&20u16.to_le_bytes());
    assert!(open_bytes("phsize", &data).is_err());
}

#[test]
fn elf32_segment_extents_are_bounded() {
    let mut data = guest_core(260);
    // PT_LOAD memsz smaller than filesz, and a virtual extent past 4 GiB.
    put32(&mut data, 52 + 32 + 20, 8);
    assert!(
        open_bytes("memsz", &data)
            .unwrap_err()
            .to_string()
            .contains("exceeds")
    );
    let mut data = guest_core(260);
    put32(&mut data, 52 + 32 + 8, 0xffff_f000);
    put32(&mut data, 52 + 32 + 20, 0x2000);
    put32(&mut data, 52 + 32 + 16, 16);
    assert!(
        open_bytes("wrap", &data).is_ok(),
        "a 32-bit extent is kept in u64"
    );
}

#[test]
fn elf32_records_round_trip_through_the_saved_metadata() {
    let path = std::env::temp_dir().join(format!("antinomie-core-arm-rec-{}", std::process::id()));
    fs::write(&path, guest_core(260)).unwrap();
    let root = path.with_extension("recording");
    let record = CoreRecord::import(&path, &root).unwrap();
    let listed = list_records(std::slice::from_ref(&root)).unwrap();
    assert_eq!(listed[0].core.machine, EM_ARM);
    assert_eq!(listed[0].core.threads[0].register("pc"), Some(0x10074));
    assert_eq!(listed[0].core.arm_mode_at(0x1007c).0, ArmMode::Thumb);
    drop(record);
    fs::remove_dir_all(root).unwrap();
    fs::remove_file(path).unwrap();
}
