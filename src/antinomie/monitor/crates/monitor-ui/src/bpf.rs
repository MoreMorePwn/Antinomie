// SPDX-License-Identifier: MIT
//! Readable translation of captured eBPF instructions. Bytes are the guest's
//! recorded program image; this is a disassembly, not proof the kernel loaded it.
use std::path::{Path, PathBuf};

use antinomie_monitor_core::EventSummary;

/// Classic and eBPF instructions are 8 octets: opcode, registers, offset, immediate.
pub(crate) fn translate(bytes: &[u8]) -> String {
    let (insns, tail) = bytes.as_chunks::<8>();
    if insns.is_empty() {
        return format!(
            "captured {} octets, 0 instructions\npartial tail {} octets, not padded",
            bytes.len(),
            tail.len()
        );
    }
    let mut lines = Vec::new();
    let mut index = 0;
    while index < insns.len() {
        let insn = insns[index];
        let op = insn[0];
        let regs = insn[1];
        let dst = regs & 0x0f;
        let src = regs >> 4;
        let off = i16::from_le_bytes([insn[2], insn[3]]);
        let imm = i32::from_le_bytes([insn[4], insn[5], insn[6], insn[7]]);
        let slot = index;
        // BPF_LD | BPF_DW | BPF_IMM is one 16-byte instruction. The next slot
        // holds the high 32 bits and is not a second load.
        let text = if op == 0x18 {
            match insns.get(index + 1) {
                Some(high) => {
                    let lo = u32::from_le_bytes([insn[4], insn[5], insn[6], insn[7]]);
                    let hi = u32::from_le_bytes([high[4], high[5], high[6], high[7]]);
                    let wide = (u64::from(hi) << 32) | u64::from(lo);
                    index += 2;
                    format!("lddw r{dst}, 0x{wide:x}")
                }
                None => {
                    index += 1;
                    format!("lddw r{dst}, wide immediate is truncated")
                }
            }
        } else {
            index += 1;
            mnemonic(op, dst, src, off, imm, slot, insns.len())
        };
        lines.push(format!("{slot:04}  {text}"));
    }
    // An LDDW pair is one line, so the line count is the instruction count.
    let mut rendered = Vec::with_capacity(lines.len() + 2);
    rendered.push(captured_header(bytes.len(), lines.len()));
    if !tail.is_empty() {
        rendered.push(format!("partial tail {} octets, not padded", tail.len()));
    }
    rendered.extend(lines);
    rendered.join("\n")
}

/// Identity recorded on the invocation. Absent values stay absent.
#[derive(Clone, Debug, Default)]
pub(crate) struct BpfIdentity {
    pub vm_id: Option<String>,
    pub boot_id: Option<String>,
    pub run_id: Option<String>,
    pub cookie: Option<u64>,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub timestamp_ns: Option<u64>,
    /// `load`, `attach`, or another recorded action name.
    pub action: String,
}

/// JSON metadata and a hex dump of the exact captured bytes.
/// A short tail is reported and is not extended with zero bytes.
pub(crate) fn export_capture(bytes: &[u8], identity: &BpfIdentity) -> String {
    let hash = antinomie_monitor_core::storage::sha256_hex(bytes);
    let meta = serde_json::json!({
        "sha256": hash,
        "captured_octets": bytes.len(),
        "complete_instructions": bytes.len() / 8,
        "partial_tail_octets": bytes.len() % 8,
        "partial": !bytes.len().is_multiple_of(8),
        "padded": false,
        "vm_id": identity.vm_id,
        "boot_id": identity.boot_id,
        "run_id": identity.run_id,
        "cookie": identity.cookie,
        "pid": identity.pid,
        "tid": identity.tid,
        "timestamp_ns": identity.timestamp_ns,
        "action": identity.action,
    });
    format!("{meta}\n{}", dump(bytes))
}

/// Write the captured bytes and a JSON sidecar. The binary is the recorded
/// octets only; a short tail is not padded.
pub(crate) fn write_export(
    directory: &Path,
    bytes: &[u8],
    identity: &BpfIdentity,
) -> Result<(PathBuf, PathBuf), String> {
    std::fs::create_dir_all(directory).map_err(|error| error.to_string())?;
    let hash = antinomie_monitor_core::storage::sha256_hex(bytes);
    let binary_name = format!("{hash}.bin");
    let binary = directory.join(&binary_name);
    let metadata = directory.join(format!("{hash}.json"));
    std::fs::write(&binary, bytes).map_err(|error| error.to_string())?;
    let meta = serde_json::json!({
        "sha256": hash,
        "binary": binary_name,
        "captured_octets": bytes.len(),
        "complete_instructions": bytes.len() / 8,
        "partial_tail_octets": bytes.len() % 8,
        "partial": !bytes.len().is_multiple_of(8),
        "padded": false,
        "vm_id": identity.vm_id,
        "boot_id": identity.boot_id,
        "run_id": identity.run_id,
        "cookie": identity.cookie,
        "pid": identity.pid,
        "tid": identity.tid,
        "timestamp_ns": identity.timestamp_ns,
        "action": identity.action,
    });
    std::fs::write(
        &metadata,
        serde_json::to_vec_pretty(&meta).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    Ok((binary, metadata))
}

/// Classic `sock_filter`: little-endian `u16 code`, `u8 jt`, `u8 jf`, `u32 k`.
/// A length that is not a multiple of 8 is reported as captured and is not
/// completed with zero bytes.
pub(crate) fn translate_classic(bytes: &[u8]) -> String {
    let instructions = bytes.len() / 8;
    let mut lines = vec![captured_header(bytes.len(), instructions)];
    let tail = bytes.len() % 8;
    if tail != 0 {
        lines.push(format!("partial tail {tail} octets, not padded"));
    }
    let (words, _) = bytes.as_chunks::<8>();
    for (slot, insn) in words.iter().enumerate() {
        let code = u16::from_le_bytes([insn[0], insn[1]]);
        let jt = insn[2];
        let jf = insn[3];
        let k = u32::from_le_bytes([insn[4], insn[5], insn[6], insn[7]]);
        lines.push(format!(
            "{slot:04}  {}",
            classic_mnemonic(code, jt, jf, k, slot, instructions)
        ));
    }
    lines.join("\n")
}

/// Exact captured bytes. Complete 8-octet words are the instruction count;
/// a short tail is not filled with `00`.
pub(crate) fn dump(bytes: &[u8]) -> String {
    let header = captured_header(bytes.len(), bytes.len() / 8);
    if bytes.is_empty() {
        return header;
    }
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!("{header}\n{hex}")
}

fn captured_header(octets: usize, instructions: usize) -> String {
    format!("captured {octets} octets, {instructions} instructions")
}

fn classic_mnemonic(code: u16, jt: u8, jf: u8, k: u32, index: usize, len: usize) -> String {
    let class_id = code & 7;
    let class = match class_id {
        0 => "ld",
        1 => "ldx",
        2 => "st",
        3 => "stx",
        4 => "alu",
        5 => "jmp",
        6 => "ret",
        _ => "misc",
    };
    let body = format!("{class} code={code:#06x} jt={jt} jf={jf} k={k:#010x}");
    if class_id != 5 {
        return body;
    }
    // BPF_JA is op 0. Other jump ops compare and take jt or jf. Counts are
    // from the next instruction, and a landing past the captured image is not
    // invented by padding.
    let destination = if code & 0xf0 == 0 {
        classic_landing(index, k, len).map(|target| format!("-> insn {target}"))
    } else {
        match (
            classic_landing(index, u32::from(jt), len),
            classic_landing(index, u32::from(jf), len),
        ) {
            (Some(when_true), Some(when_false)) => {
                Some(format!("-> insn {when_true} / insn {when_false}"))
            }
            _ => None,
        }
    };
    match destination {
        Some(destination) => format!("{body} {destination}"),
        None => format!("{body} -> outside"),
    }
}

/// `offset` is an instruction count from the next classic instruction.
fn classic_landing(index: usize, offset: u32, len: usize) -> Option<u64> {
    let target = (index as u64)
        .checked_add(1)?
        .checked_add(u64::from(offset))?;
    if target < len as u64 {
        Some(target)
    } else {
        None
    }
}

fn mnemonic(op: u8, dst: u8, src: u8, off: i16, imm: i32, index: usize, len: usize) -> String {
    let class = op & 0x07;
    let source = if op & 0x08 == 0 {
        format!("r{dst}")
    } else {
        format!("r{src}")
    };
    match class {
        0x04 | 0x07 => {
            let width = if class == 0x07 { "64" } else { "32" };
            let operation = match (op >> 4) & 0x0f {
                0x0 => "add",
                0x1 => "sub",
                0x2 => "mul",
                0x3 => "div",
                0x4 => "or",
                0x5 => "and",
                0x6 => "lsh",
                0x7 => "rsh",
                0x8 => "neg",
                0x9 => "mod",
                0xa => "xor",
                0xb => "mov",
                0xc => "arsh",
                0xd => "end",
                _ => "alu",
            };
            if operation == "neg" {
                format!("{operation}{width} r{dst}")
            } else if op & 0x08 == 0 {
                format!("{operation}{width} r{dst}, {imm}")
            } else {
                format!("{operation}{width} r{dst}, {source}")
            }
        }
        0x05 | 0x06 => {
            let operation = match (op >> 4) & 0x0f {
                0x0 => "ja",
                0x1 => "jeq",
                0x2 => "jgt",
                0x3 => "jge",
                0x4 => "jset",
                0x5 => "jne",
                0x6 => "jsgt",
                0x7 => "jsge",
                0x8 => "call",
                0x9 => "exit",
                0xa => "jlt",
                0xb => "jle",
                0xc => "jslt",
                0xd => "jsle",
                _ => "jmp",
            };
            if operation == "exit" {
                "exit".into()
            } else if operation == "call" {
                format!("call {}", helper(imm))
            } else if operation == "ja" {
                format!("ja {off:+} {}", ebpf_landing(index, off, len))
            } else if op & 0x08 == 0 {
                format!(
                    "{operation} r{dst}, {imm}, {off:+} {}",
                    ebpf_landing(index, off, len)
                )
            } else {
                format!(
                    "{operation} r{dst}, r{src}, {off:+} {}",
                    ebpf_landing(index, off, len)
                )
            }
        }
        0x00..=0x03 => {
            let size = match op & 0x18 {
                0x00 => "w",
                0x08 => "h",
                0x10 => "b",
                _ => "dw",
            };
            let mode = if class <= 1 { "ldx" } else { "stx" };
            if class == 0 || class == 2 {
                format!("{mode}{size} r{dst}, [{imm:+}]")
            } else {
                format!("{mode}{size} r{dst}, [r{src}{off:+}]")
            }
        }
        _ => format!("op {op:#04x} r{dst}, r{src}, {off}, {imm}"),
    }
}

/// The eBPF offset is relative to the next instruction: `index + offset + 1`.
fn ebpf_landing(index: usize, off: i16, len: usize) -> String {
    let target = index as i64 + i64::from(off) + 1;
    if target >= 0 && target < len as i64 {
        format!("-> insn {target}")
    } else {
        "-> outside".into()
    }
}

fn helper(id: i32) -> String {
    let name = match id {
        1 => "map_lookup_elem",
        2 => "map_update_elem",
        3 => "map_delete_elem",
        4 => "probe_read",
        5 => "ktime_get_ns",
        6 => "trace_printk",
        7 => "get_prandom_u32",
        14 => "get_current_pid_tgid",
        15 => "get_current_uid_gid",
        16 => "get_current_comm",
        25 => "perf_event_output",
        31 => "skb_change_proto",
        _ => return format!("helper {id}"),
    };
    format!("{name} ({id})")
}

/// BPF_PROG_LOAD and neighbouring bpf(2) commands, for the triage list.
pub(crate) fn command_name(event: &EventSummary) -> Option<&'static str> {
    if event.syscall_name != "bpf" && event.syscall_nr != 321 {
        return None;
    }
    Some(match event.args.map(|args| args[0]) {
        Some(0) => "BPF_MAP_CREATE",
        Some(1) => "BPF_MAP_LOOKUP_ELEM",
        Some(2) => "BPF_MAP_UPDATE_ELEM",
        Some(3) => "BPF_MAP_DELETE_ELEM",
        Some(5) => "BPF_PROG_LOAD",
        Some(6) => "BPF_OBJ_PIN",
        Some(7) => "BPF_OBJ_GET",
        Some(8) => "BPF_PROG_ATTACH",
        Some(9) => "BPF_PROG_DETACH",
        _ => "bpf",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_export_keeps_a_partial_tail() {
        let bytes = [0x15u8, 0, 0, 1, 1, 0, 0, 0, 0xaa];
        let dir = std::env::temp_dir().join(format!("antinomie-bpf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let identity = BpfIdentity {
            action: "attach".into(),
            ..BpfIdentity::default()
        };
        let (binary, metadata) = write_export(&dir, &bytes, &identity).unwrap();
        assert_eq!(std::fs::read(&binary).unwrap(), bytes);
        let text = std::fs::read_to_string(&metadata).unwrap();
        assert!(text.contains("\"partial\": true"), "{text}");
        assert!(text.contains("\"padded\": false"), "{text}");
        assert!(text.contains("\"partial_tail_octets\": 1"), "{text}");
        assert!(!std::fs::read(&binary).unwrap().ends_with(&[0, 0, 0]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn translates_a_240_byte_classic_socket_filter() {
        let bytes = [0x06u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00].repeat(30);
        assert_eq!(bytes.len(), 240);
        let text = translate_classic(&bytes);
        assert!(text.starts_with("captured 240 octets, 30 instructions"), "{text}");
        assert!(text.contains("0029"), "{text}");
        assert!(!text.contains("partial tail"), "{text}");
    }

    #[test]
    fn translates_mov_and_exit() {
        // mov64 r0, 0; exit
        let mut bytes = vec![0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        bytes.extend_from_slice(&[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let text = translate(&bytes);
        assert!(text.contains("mov64 r0, 0"), "{text}");
        assert!(text.contains("exit"), "{text}");
    }

    #[test]
    fn translates_lddw_two_slots_as_one_wide_immediate() {
        // lddw r0, 0x123456789abcdef0 — low half has its top bit set.
        let bytes = [
            0x18, 0x00, 0x00, 0x00, 0xf0, 0xde, 0xbc, 0x9a, 0x00, 0x00, 0x00, 0x00, 0x78, 0x56,
            0x34, 0x12,
        ];
        let text = translate(&bytes);
        assert_eq!(
            text,
            "captured 16 octets, 1 instructions\n0000  lddw r0, 0x123456789abcdef0"
        );
        let load_rows = text
            .lines()
            .filter(|line| {
                line.split_whitespace()
                    .nth(1)
                    .is_some_and(|mnemonic| mnemonic.starts_with("ld"))
            })
            .count();
        assert_eq!(load_rows, 1, "{text}");
    }

    #[test]
    fn translates_lddw_missing_high_slot_as_truncated() {
        let bytes = [0x18, 0x00, 0x00, 0x00, 0xf0, 0xde, 0xbc, 0x9a];
        let text = translate(&bytes);
        assert_eq!(
            text,
            "captured 8 octets, 1 instructions\n0000  lddw r0, wide immediate is truncated"
        );
        assert!(!text.contains("0x"), "{text}");
    }

    #[test]
    fn translates_helper_16_as_get_current_comm() {
        // call 16
        let bytes = [0x85, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00];
        let text = translate(&bytes);
        assert_eq!(
            text,
            "captured 8 octets, 1 instructions\n0000  call get_current_comm (16)"
        );
        assert!(text.contains("get_current_comm"), "{text}");
    }

    #[test]
    fn translates_helper_31_is_not_get_current_comm() {
        // call 31
        let bytes = [0x85, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00];
        let text = translate(&bytes);
        assert_eq!(
            text,
            "captured 8 octets, 1 instructions\n0000  call skb_change_proto (31)"
        );
        assert!(!text.contains("get_current_comm"), "{text}");
    }

    #[test]
    fn translates_jump_to_destination_index() {
        // ja +1; mov64 r0, 0; exit. Offset is from the next insn, so +1 lands on exit.
        let mut bytes = vec![0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        bytes.extend_from_slice(&[0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let text = translate(&bytes);
        assert_eq!(
            text,
            "captured 24 octets, 3 instructions\n0000  ja +1 -> insn 2\n0001  mov64 r0, 0\n0002  exit"
        );
        // A single ja +0 would land on an instruction this image does not contain.
        let outside = translate(&[0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            outside,
            "captured 8 octets, 1 instructions\n0000  ja +0 -> outside"
        );
    }

    #[test]
    fn classic_jump_prints_true_and_false_targets() {
        // ja k=1, then two fillers, so the landing is instruction 2.
        let mut ja = vec![0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        ja.extend_from_slice(&[0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        ja.extend_from_slice(&[0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let ja_text = translate_classic(&ja);
        assert!(
            ja_text.contains("0000  jmp code=0x0005 jt=0 jf=0 k=0x00000001 -> insn 2"),
            "{ja_text}"
        );
        // jeq with jt=1, jf=2 needs four instructions: true -> 2, false -> 3.
        let mut branch = vec![0x15, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00];
        branch.extend_from_slice(&[0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        branch.extend_from_slice(&[0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        branch.extend_from_slice(&[0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let branch_text = translate_classic(&branch);
        assert_eq!(
            branch_text.lines().nth(1),
            Some("0000  jmp code=0x0015 jt=1 jf=2 k=0x00000000 -> insn 2 / insn 3")
        );
        let short = translate_classic(&[0x15, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00]);
        assert!(
            short.ends_with("jmp code=0x0015 jt=1 jf=2 k=0x00000000 -> outside"),
            "{short}"
        );
    }

    #[test]
    fn classic_ret_contains_ret() {
        let bytes = [0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let text = translate_classic(&bytes);
        assert!(text.contains("ret"), "{text}");
        assert!(
            text.starts_with("captured 8 octets, 1 instructions\n"),
            "{text}"
        );
        let partial = translate_classic(&[0x06, 0x00, 0xff]);
        assert_eq!(
            partial,
            "captured 3 octets, 0 instructions\npartial tail 3 octets, not padded"
        );
        assert_eq!(
            dump(&[0x06, 0x00, 0xff]),
            "captured 3 octets, 0 instructions\n06 00 ff"
        );
    }

    #[test]
    fn classic_and_ebpf_sequences_disassemble_without_running() {
        // ld [0], jeq #1 jump 0/1, ret #0. Three classic instructions.
        let mut classic = vec![0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        classic.extend_from_slice(&[0x15, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00]);
        classic.extend_from_slice(&[0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        classic.push(0xaa);
        let text = translate_classic(&classic);
        assert!(text.contains("ld "), "{text}");
        assert!(text.contains("jmp "), "{text}");
        assert!(text.contains("ret "), "{text}");
        assert!(text.contains("partial tail 1 octets, not padded"), "{text}");
        assert!(!text.contains("00 aa"), "{text}");

        // mov64 r0, 1; jeq r0, 1, +1; exit; mov64 r0, 0; exit.
        let mut ebpf = vec![0xb7, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        ebpf.extend_from_slice(&[0x15, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00]);
        ebpf.extend_from_slice(&[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        ebpf.extend_from_slice(&[0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        ebpf.extend_from_slice(&[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let text = translate(&ebpf);
        assert!(text.contains("mov64 r0, 1"), "{text}");
        assert!(text.contains("jeq r0, 1"), "{text}");
        assert!(text.contains("-> insn 3"), "{text}");
        assert_eq!(text.matches("exit").count(), 2, "{text}");

        let exported = export_capture(
            &classic,
            &BpfIdentity {
                vm_id: None,
                boot_id: Some("boot".into()),
                run_id: None,
                cookie: Some(4),
                pid: Some(9),
                tid: None,
                timestamp_ns: Some(10),
                action: "load".into(),
            },
        );
        assert!(exported.contains("\"vm_id\":null"), "{exported}");
        assert!(exported.contains("\"run_id\":null"), "{exported}");
        assert!(exported.contains("\"tid\":null"), "{exported}");
        assert!(exported.contains("\"boot_id\":\"boot\""), "{exported}");
        assert!(exported.contains("\"action\":\"load\""), "{exported}");
        assert!(exported.contains("\"partial\":true"), "{exported}");
        assert!(exported.contains("\"padded\":false"), "{exported}");
        let dump_line = exported.lines().last().unwrap_or("");
        assert!(dump_line.ends_with(" aa"), "{exported}");
    }
}
