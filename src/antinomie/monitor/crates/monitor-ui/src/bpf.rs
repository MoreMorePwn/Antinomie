// SPDX-License-Identifier: MIT
//! Readable translation of captured eBPF instructions. Bytes are the guest's
//! recorded program image; this is a disassembly, not proof the kernel loaded it.
use std::{
    io::Write,
    path::{Path, PathBuf},
};

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
                Some(high) if high[..4] == [0; 4] => {
                    let lo = u32::from_le_bytes([insn[4], insn[5], insn[6], insn[7]]);
                    let hi = u32::from_le_bytes([high[4], high[5], high[6], high[7]]);
                    let wide = (u64::from(hi) << 32) | u64::from(lo);
                    index += 2;
                    format!("lddw r{dst}, 0x{wide:x}")
                }
                Some(_) => {
                    index += 2;
                    format!("lddw r{dst}, malformed continuation; high slot retained")
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
    pub stream_id: u64,
    pub vm_id: Option<String>,
    pub boot_id: Option<String>,
    pub run_id: Option<String>,
    pub cookie: Option<u64>,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub timestamp_ns: Option<u64>,
    /// `load`, `attach`, or another recorded action name.
    pub action: String,
    pub source_syscall: String,
    pub event_id: Option<u64>,
    pub result: Option<i64>,
    pub attachment_kind: String,
    pub declared_instruction_count: Option<u64>,
    pub fd: Option<i64>,
    pub program_id: Option<u64>,
    pub capture_issues: Vec<String>,
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
        "partial": capture_partial(bytes, identity),
        "padded": false,
        "vm_id": identity.vm_id,
        "boot_id": identity.boot_id,
        "run_id": identity.run_id,
        "cookie": identity.cookie,
        "stream_id": identity.stream_id,
        "pid": identity.pid,
        "tid": identity.tid,
        "timestamp_ns": identity.timestamp_ns,
        "action": identity.action,
        "source_syscall": identity.source_syscall,
        "event_id": identity.event_id,
        "result": identity.result,
        "attachment_kind": identity.attachment_kind,
        "declared_instruction_count": identity.declared_instruction_count,
        "fd": identity.fd,
        "program_id": identity.program_id,
        "capture_issues": identity.capture_issues,
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
    let provenance =
        antinomie_monitor_core::storage::sha256_hex(export_capture(bytes, identity).as_bytes());
    let stem = format!("{hash}-{}", &provenance[..16]);
    let binary_name = format!("{stem}.bin");
    let binary = directory.join(&binary_name);
    let metadata = directory.join(format!("{stem}.json"));
    let meta = serde_json::json!({
        "sha256": hash,
        "binary": binary_name,
        "captured_octets": bytes.len(),
        "complete_instructions": bytes.len() / 8,
        "partial_tail_octets": bytes.len() % 8,
        "partial": capture_partial(bytes, identity),
        "padded": false,
        "vm_id": identity.vm_id,
        "boot_id": identity.boot_id,
        "run_id": identity.run_id,
        "cookie": identity.cookie,
        "stream_id": identity.stream_id,
        "pid": identity.pid,
        "tid": identity.tid,
        "timestamp_ns": identity.timestamp_ns,
        "action": identity.action,
        "source_syscall": identity.source_syscall,
        "event_id": identity.event_id,
        "result": identity.result,
        "attachment_kind": identity.attachment_kind,
        "declared_instruction_count": identity.declared_instruction_count,
        "fd": identity.fd,
        "program_id": identity.program_id,
        "capture_issues": identity.capture_issues,
    });
    let encoded = serde_json::to_vec_pretty(&meta).map_err(|error| error.to_string())?;
    write_new_export(&binary, bytes)?;
    if let Err(error) = write_new_export(&metadata, &encoded) {
        return match std::fs::remove_file(&binary) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(format!("{error}; incomplete export cleanup: {cleanup}")),
        };
    }
    Ok((binary, metadata))
}

fn capture_partial(bytes: &[u8], identity: &BpfIdentity) -> bool {
    !bytes.len().is_multiple_of(8)
        || identity
            .declared_instruction_count
            .is_some_and(|count| count > (bytes.len() / 8) as u64)
        || !identity.capture_issues.is_empty()
}

fn write_new_export(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        return match std::fs::remove_file(path) {
            Ok(()) => Err(error.to_string()),
            Err(cleanup) => Err(format!("{error}; incomplete export cleanup: {cleanup}")),
        };
    }
    Ok(())
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

/// The same classic instruction offsets refer to different input structures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClassicContext {
    Socket,
    Seccomp,
    Unknown,
}

/// Decode without executing. Each retained word has its exact bytes and an
/// explanatory operation; context-dependent meanings are never guessed.
pub(crate) fn translate_classic_explained(bytes: &[u8], context: ClassicContext) -> String {
    let mut output = translate_classic(bytes);
    if bytes.len() < 8 {
        return output;
    }
    output.push_str("\n\nPseudocode (A/X are unsigned 32-bit; M has 16 scratch words)\n");
    output.push_str(match context {
        ClassicContext::Socket => "Input: socket packet; packet loads use network byte order. Return 0 drops, otherwise retain up to the returned length.\n",
        ClassicContext::Seccomp => "Input: native x86-64 seccomp_data; loads use native little endian. Returns select a seccomp action and 16-bit data.\n",
        ClassicContext::Unknown => "Input context unavailable; packet and seccomp field meanings are unresolved.\n",
    });
    let (words, _) = bytes.as_chunks::<8>();
    for (index, word) in words.iter().enumerate() {
        let code = u16::from_le_bytes([word[0], word[1]]);
        let k = u32::from_le_bytes(word[4..8].try_into().expect("instruction immediate"));
        let raw = word
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let operation = classic_operation(code, word[2], word[3], k, index, words.len(), context);
        output.push_str(&format!("{index:04} [{raw}] {operation}\n"));
    }
    output
}

fn classic_operation(
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
    index: usize,
    len: usize,
    context: ClassicContext,
) -> String {
    let unknown = || format!("unresolved opcode {code:#06x}, jt={jt}, jf={jf}, k={k:#x}");
    if code > 0xff {
        return unknown();
    }
    let register = if code & 7 == 1 { "X" } else { "A" };
    let operand = if code & 8 != 0 {
        "X".into()
    } else {
        format!("{k:#x}")
    };
    let landing = |offset| {
        classic_landing(index, offset, len).map_or_else(
            || "unavailable target outside captured image".into(),
            |target| format!("insn {target}"),
        )
    };
    match code & 7 {
        0 | 1 => {
            let size = match code & 0x18 {
                0 => 32,
                8 => 16,
                16 => 8,
                _ => return unknown(),
            };
            let mode = code & 0xe0;
            if matches!(mode, 0 | 0x60 | 0x80) && size != 32 {
                return unknown();
            }
            match mode {
                0 => format!("{register} = {k:#x}"),
                0x60 if k < 16 => format!("{register} = M[{k}]"),
                0x60 => format!("invalid scratch index M[{k}] (16 words available)"),
                0x80 if context == ClassicContext::Socket => format!("{register} = packet.length"),
                0x80 => format!("{register} = input.length (unsupported for seccomp)"),
                0x20 if register == "A" => format!("A = {}", classic_input(k, size, context)),
                0x40 if register == "A" && context == ClassicContext::Socket => {
                    format!("A = load_be_u{size}(packet, X + {k}); out-of-range load returns 0")
                }
                0xa0 if code == 0xb1 && context == ClassicContext::Socket => {
                    format!("X = (load_u8(packet, {k}) & 0xf) << 2; out-of-range load returns 0")
                }
                _ => unknown(),
            }
        }
        2 | 3 if code == 2 || code == 3 => {
            let source = if code == 2 { "A" } else { "X" };
            if k < 16 {
                format!("M[{k}] = {source}")
            } else {
                format!("invalid scratch index M[{k}] (16 words available)")
            }
        }
        4 if code & 0x80 == 0 || code == 0x84 || matches!(code & 0xf0, 0x90 | 0xa0) => {
            let op = match code & 0xf0 {
                0 => "+",
                0x10 => "-",
                0x20 => "*",
                0x30 => "/",
                0x40 => "|",
                0x50 => "&",
                0x60 => "<<",
                0x70 => ">>",
                0x80 => return "A = wrapping_u32(-A)".into(),
                0x90 => "%",
                0xa0 => "^",
                _ => return unknown(),
            };
            format!(
                "A = wrapping_u32(A {op} {operand}){}",
                if matches!(op, "/" | "%") {
                    "; zero divisor returns 0"
                } else {
                    ""
                }
            )
        }
        5 => {
            if code == 5 {
                return format!("goto {}", landing(k));
            }
            let op = match code & 0xf0 {
                0x10 => "==",
                0x20 => ">",
                0x30 => ">=",
                0x40 => "&",
                _ => return unknown(),
            };
            let condition = if op == "&" {
                format!("(A & {operand}) != 0")
            } else {
                format!("A {op} {operand}")
            };
            format!(
                "if {condition}: goto {}; else: goto {}",
                landing(jt.into()),
                landing(jf.into())
            )
        }
        6 if code == 0x06 || code == 0x16 => {
            if code == 0x16 {
                return "return A".into();
            }
            match context {
                ClassicContext::Seccomp => {
                    let action = match k & 0xffff0000 {
                        0x80000000 => "KILL_PROCESS",
                        0 => "KILL_THREAD",
                        0x00030000 => "TRAP",
                        0x00050000 => "ERRNO",
                        0x7fc00000 => "USER_NOTIF",
                        0x7ff00000 => "TRACE",
                        0x7ffc0000 => "LOG",
                        0x7fff0000 => "ALLOW",
                        _ => "UNKNOWN_ACTION",
                    };
                    format!(
                        "return SECCOMP_RET_{action} | {} (raw {k:#010x})",
                        k & 0xffff
                    )
                }
                ClassicContext::Socket if k == 0 => "return 0; drop packet".into(),
                ClassicContext::Socket => {
                    format!("return {k}; retain min(packet.length, {k}) octets")
                }
                ClassicContext::Unknown => format!("return {k:#x}; context-dependent result"),
            }
        }
        7 if code == 0x07 => "X = A".into(),
        7 if code == 0x87 => "A = X".into(),
        _ => unknown(),
    }
}

fn classic_input(offset: u32, size: u32, context: ClassicContext) -> String {
    match context {
        ClassicContext::Unknown => {
            format!("load_u{size}(input, {offset:#x}); field meaning unresolved")
        }
        ClassicContext::Socket => {
            let ancillary = match offset.wrapping_sub((-0x1000_i32) as u32) {
                0 => Some("protocol"),
                4 => Some("packet_type"),
                8 => Some("interface_index"),
                20 => Some("mark"),
                24 => Some("queue"),
                28 => Some("hardware_type"),
                32 => Some("rx_hash"),
                36 => Some("cpu"),
                44 => Some("vlan_tag"),
                48 => Some("vlan_present"),
                52 => Some("payload_offset"),
                56 => Some("random"),
                60 => Some("vlan_tpid"),
                _ => None,
            };
            ancillary.map_or_else(
                || format!("load_be_u{size}(packet, {offset:#x}); out-of-range load returns 0"),
                |field| format!("socket.{field}"),
            )
        }
        ClassicContext::Seccomp => {
            if size != 32 || !offset.is_multiple_of(4) || offset >= 64 {
                return format!("invalid seccomp_data load u{size} at {offset:#x}");
            }
            match offset {
                0 => "seccomp.nr".into(),
                4 => "seccomp.arch".into(),
                8 => "seccomp.instruction_pointer.low32".into(),
                12 => "seccomp.instruction_pointer.high32".into(),
                _ => format!(
                    "seccomp.args[{}].{}32",
                    (offset - 16) / 8,
                    if offset.is_multiple_of(8) {
                        "low"
                    } else {
                        "high"
                    }
                ),
            }
        }
    }
}

/// Register operations annotate the disassembly; unknown instructions remain raw.
pub(crate) fn translate_explained(bytes: &[u8]) -> String {
    let mut output = translate(bytes);
    output.push_str(
        "\n\nPseudocode (r1 is entry context; r10 is frame pointer; r0 is return value)\n",
    );
    let (words, _) = bytes.as_chunks::<8>();
    let mut index = 0;
    while index < words.len() {
        let word = words[index];
        let op = word[0];
        let dst = word[1] & 15;
        let src = word[1] >> 4;
        let offset = i16::from_le_bytes([word[2], word[3]]);
        let immediate = i32::from_le_bytes(word[4..].try_into().expect("instruction immediate"));
        let raw = word
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let operation = if dst > 10 || src > 10 {
            "invalid register encoding; retained raw instruction".into()
        } else if op == 0x18 {
            match words.get(index + 1) {
                Some(high) if high[..4] == [0; 4] => {
                    let value = u64::from(u32::from_le_bytes(
                        word[4..].try_into().expect("low immediate"),
                    )) | (u64::from(u32::from_le_bytes(
                        high[4..].try_into().expect("high immediate"),
                    )) << 32);
                    format!("r{dst} = {value:#018x}; two-slot immediate, pseudo source {src} (map/BTF identity requires recorded context)")
                }
                Some(_) => "malformed lddw continuation; retained raw pair".into(),
                None => "truncated lddw; high slot unavailable".into(),
            }
        } else if op == 0x95 {
            "return r0".into()
        } else if op == 0x85 && src == 0 {
            format!(
                "r0 = {}(r1, r2, r3, r4, r5); r1..r5 clobbered",
                helper(immediate)
            )
        } else if op == 0x85 && src == 1 {
            format!(
                "call local function at {}",
                ebpf_landing_wide(index, immediate, words.len())
            )
        } else {
            ebpf_operation(op, dst, src, offset, immediate, index, words)
        };
        output.push_str(&format!("{index:04} [{raw}] {operation}\n"));
        index += if op == 0x18 && index + 1 < words.len() {
            2
        } else {
            1
        };
    }
    output
}

fn ebpf_operation(
    op: u8,
    dst: u8,
    src: u8,
    offset: i16,
    immediate: i32,
    index: usize,
    words: &[[u8; 8]],
) -> String {
    let class = op & 7;
    let width = if class == 4 { 32 } else { 64 };
    let right = if op & 8 == 0 {
        format!("{immediate}")
    } else {
        format!("r{src}")
    };
    if matches!(class, 4 | 7) {
        let arithmetic = match op & 0xf0 {
            0 => "+",
            0x10 => "-",
            0x20 => "*",
            0x30 => "/",
            0x40 => "|",
            0x50 => "&",
            0x60 => "<<",
            0x70 => ">>",
            0x90 => "%",
            0xa0 => "^",
            0x80 => return format!("r{dst} = wrapping_u{width}(-r{dst})"),
            0xb0 => return format!("r{dst} = wrapping_u{width}({right})"),
            0xc0 => {
                return format!("r{dst} = wrapping_u{width}(signed_i{width}(r{dst}) >> {right})")
            }
            0xd0 if matches!(immediate, 16 | 32 | 64) => {
                return format!(
                    "r{dst} = {}_u{immediate}(r{dst})",
                    if op & 8 == 0 { "to_le" } else { "to_be" }
                )
            }
            _ => return format!("unresolved ALU opcode {op:#x}, immediate {immediate}"),
        };
        return format!("r{dst} = wrapping_u{width}(r{dst} {arithmetic} {right})");
    }
    let landing = |delta: i32| {
        let target = index as i64 + i64::from(delta) + 1;
        if target < 0 || target >= words.len() as i64 {
            "unavailable target outside captured image".into()
        } else if target > 0 && words[target as usize - 1][0] == 0x18 {
            format!("invalid target insn {target} (lddw continuation)")
        } else {
            format!("insn {target}")
        }
    };
    if matches!(class, 5 | 6) {
        if op & 0xf0 == 0 {
            return format!(
                "goto {}",
                landing(if class == 6 { immediate } else { offset.into() })
            );
        }
        let (operator, signed) = match op & 0xf0 {
            0x10 => ("==", false),
            0x20 => (">", false),
            0x30 => (">=", false),
            0x40 => ("&", false),
            0x50 => ("!=", false),
            0x60 => (">", true),
            0x70 => (">=", true),
            0xa0 => ("<", false),
            0xb0 => ("<=", false),
            0xc0 => ("<", true),
            0xd0 => ("<=", true),
            _ => return mnemonic(op, dst, src, offset, immediate, index, words.len()),
        };
        let width = if class == 6 { 32 } else { 64 };
        let cast = if signed { "i" } else { "u" };
        let condition = if operator == "&" {
            format!("(u{width}(r{dst}) & u{width}({right})) != 0")
        } else {
            format!("{cast}{width}(r{dst}) {operator} {cast}{width}({right})")
        };
        return format!(
            "if {condition}: goto {}; else: goto {}",
            landing(offset.into()),
            landing(0)
        );
    }
    let size = match op & 0x18 {
        0 => 32,
        8 => 16,
        16 => 8,
        _ => 64,
    };
    match (class, op & 0xe0) {
        (1, 0x60) => format!("r{dst} = load_u{size}(r{src} {offset:+})"),
        (2, 0x60) => format!("store_u{size}(r{dst} {offset:+}, {immediate})"),
        (3, 0x60) => format!("store_u{size}(r{dst} {offset:+}, r{src})"),
        (3, 0xc0) if matches!(size, 32 | 64) => match immediate {
            0xe1 => format!("r{src} = atomic_exchange_u{size}(r{dst} {offset:+}, r{src})"),
            0xf1 => format!("r0 = atomic_compare_exchange_u{size}(r{dst} {offset:+}, r0, r{src})"),
            _ => {
                let operator = match immediate & !1 {
                    0 => "+",
                    0x40 => "|",
                    0x50 => "&",
                    0xa0 => "^",
                    _ => return format!("unresolved atomic opcode {immediate:#x}"),
                };
                format!(
                    "old = atomic_update_u{size}(r{dst} {offset:+}, old {operator} r{src}){}",
                    if immediate & 1 != 0 {
                        format!("; r{src} = old")
                    } else {
                        String::new()
                    }
                )
            }
        },
        _ => mnemonic(op, dst, src, offset, immediate, index, words.len()),
    }
}

fn ebpf_landing_wide(index: usize, offset: i32, len: usize) -> String {
    let target = index as i64 + i64::from(offset) + 1;
    if target >= 0 && target < len as i64 {
        format!("insn {target}")
    } else {
        "unavailable target outside captured image".into()
    }
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
                _ => return format!("unresolved alu opcode {op:#04x}, r{dst}, r{src}, {imm}"),
            };
            if operation == "end" {
                format!(
                    "endian r{dst}, {}{imm}",
                    if op & 8 == 0 { "le" } else { "be" }
                )
            } else if operation == "neg" {
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
                match src {
                    0 => format!("call {}", helper(imm)),
                    1 => format!("call local {}", ebpf_landing_wide(index, imm, len)),
                    2 => format!("call unresolved BTF kernel function ID {imm}"),
                    _ => format!("call unresolved pseudo source {src}, immediate {imm}"),
                }
            } else if operation == "ja" {
                if class == 6 {
                    format!("ja32 {imm:+} -> {}", ebpf_landing_wide(index, imm, len))
                } else {
                    format!("ja {off:+} {}", ebpf_landing(index, off, len))
                }
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
            match (class, op & 0xe0) {
                (0, 0x20) => format!("ldabs{size} r0, packet[{imm:+}]"),
                (0, 0x40) => format!("ldind{size} r0, packet[r{src}{imm:+}]"),
                (1, 0x60) => format!("ldx{size} r{dst}, [r{src}{off:+}]"),
                (2, 0x60) => format!("st{size} [r{dst}{off:+}], {imm}"),
                (3, 0x60) => format!("stx{size} [r{dst}{off:+}], r{src}"),
                (3, 0xc0) => format!("atomic{size} [r{dst}{off:+}], r{src}, operation={imm:#x}; fetch/cmpxchg semantics from opcode"),
                _ => format!("unresolved memory opcode {op:#04x}, r{dst}, r{src}, {off}, {imm}"),
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

// Helper names/IDs follow the pinned Linux 6.12.94 UAPI bpf_func_id registry.
fn helper(id: i32) -> String {
    let name = match id {
        0 => "unspec",
        1 => "map_lookup_elem",
        2 => "map_update_elem",
        3 => "map_delete_elem",
        4 => "probe_read",
        5 => "ktime_get_ns",
        6 => "trace_printk",
        7 => "get_prandom_u32",
        8 => "get_smp_processor_id",
        9 => "skb_store_bytes",
        10 => "l3_csum_replace",
        11 => "l4_csum_replace",
        12 => "tail_call",
        13 => "clone_redirect",
        14 => "get_current_pid_tgid",
        15 => "get_current_uid_gid",
        16 => "get_current_comm",
        17 => "get_cgroup_classid",
        18 => "skb_vlan_push",
        19 => "skb_vlan_pop",
        20 => "skb_get_tunnel_key",
        21 => "skb_set_tunnel_key",
        22 => "perf_event_read",
        23 => "redirect",
        24 => "get_route_realm",
        25 => "perf_event_output",
        26 => "skb_load_bytes",
        27 => "get_stackid",
        28 => "csum_diff",
        29 => "skb_get_tunnel_opt",
        30 => "skb_set_tunnel_opt",
        31 => "skb_change_proto",
        32 => "skb_change_type",
        33 => "skb_under_cgroup",
        34 => "get_hash_recalc",
        35 => "get_current_task",
        36 => "probe_write_user",
        37 => "current_task_under_cgroup",
        38 => "skb_change_tail",
        39 => "skb_pull_data",
        40 => "csum_update",
        41 => "set_hash_invalid",
        42 => "get_numa_node_id",
        43 => "skb_change_head",
        44 => "xdp_adjust_head",
        45 => "probe_read_str",
        46 => "get_socket_cookie",
        47 => "get_socket_uid",
        48 => "set_hash",
        49 => "setsockopt",
        50 => "skb_adjust_room",
        51 => "redirect_map",
        52 => "sk_redirect_map",
        53 => "sock_map_update",
        54 => "xdp_adjust_meta",
        55 => "perf_event_read_value",
        56 => "perf_prog_read_value",
        57 => "getsockopt",
        58 => "override_return",
        59 => "sock_ops_cb_flags_set",
        60 => "msg_redirect_map",
        61 => "msg_apply_bytes",
        62 => "msg_cork_bytes",
        63 => "msg_pull_data",
        64 => "bind",
        65 => "xdp_adjust_tail",
        66 => "skb_get_xfrm_state",
        67 => "get_stack",
        68 => "skb_load_bytes_relative",
        69 => "fib_lookup",
        70 => "sock_hash_update",
        71 => "msg_redirect_hash",
        72 => "sk_redirect_hash",
        73 => "lwt_push_encap",
        74 => "lwt_seg6_store_bytes",
        75 => "lwt_seg6_adjust_srh",
        76 => "lwt_seg6_action",
        77 => "rc_repeat",
        78 => "rc_keydown",
        79 => "skb_cgroup_id",
        80 => "get_current_cgroup_id",
        81 => "get_local_storage",
        82 => "sk_select_reuseport",
        83 => "skb_ancestor_cgroup_id",
        84 => "sk_lookup_tcp",
        85 => "sk_lookup_udp",
        86 => "sk_release",
        87 => "map_push_elem",
        88 => "map_pop_elem",
        89 => "map_peek_elem",
        90 => "msg_push_data",
        91 => "msg_pop_data",
        92 => "rc_pointer_rel",
        93 => "spin_lock",
        94 => "spin_unlock",
        95 => "sk_fullsock",
        96 => "tcp_sock",
        97 => "skb_ecn_set_ce",
        98 => "get_listener_sock",
        99 => "skc_lookup_tcp",
        100 => "tcp_check_syncookie",
        101 => "sysctl_get_name",
        102 => "sysctl_get_current_value",
        103 => "sysctl_get_new_value",
        104 => "sysctl_set_new_value",
        105 => "strtol",
        106 => "strtoul",
        107 => "sk_storage_get",
        108 => "sk_storage_delete",
        109 => "send_signal",
        110 => "tcp_gen_syncookie",
        111 => "skb_output",
        112 => "probe_read_user",
        113 => "probe_read_kernel",
        114 => "probe_read_user_str",
        115 => "probe_read_kernel_str",
        116 => "tcp_send_ack",
        117 => "send_signal_thread",
        118 => "jiffies64",
        119 => "read_branch_records",
        120 => "get_ns_current_pid_tgid",
        121 => "xdp_output",
        122 => "get_netns_cookie",
        123 => "get_current_ancestor_cgroup_id",
        124 => "sk_assign",
        125 => "ktime_get_boot_ns",
        126 => "seq_printf",
        127 => "seq_write",
        128 => "sk_cgroup_id",
        129 => "sk_ancestor_cgroup_id",
        130 => "ringbuf_output",
        131 => "ringbuf_reserve",
        132 => "ringbuf_submit",
        133 => "ringbuf_discard",
        134 => "ringbuf_query",
        135 => "csum_level",
        136 => "skc_to_tcp6_sock",
        137 => "skc_to_tcp_sock",
        138 => "skc_to_tcp_timewait_sock",
        139 => "skc_to_tcp_request_sock",
        140 => "skc_to_udp6_sock",
        141 => "get_task_stack",
        142 => "load_hdr_opt",
        143 => "store_hdr_opt",
        144 => "reserve_hdr_opt",
        145 => "inode_storage_get",
        146 => "inode_storage_delete",
        147 => "d_path",
        148 => "copy_from_user",
        149 => "snprintf_btf",
        150 => "seq_printf_btf",
        151 => "skb_cgroup_classid",
        152 => "redirect_neigh",
        153 => "per_cpu_ptr",
        154 => "this_cpu_ptr",
        155 => "redirect_peer",
        156 => "task_storage_get",
        157 => "task_storage_delete",
        158 => "get_current_task_btf",
        159 => "bprm_opts_set",
        160 => "ktime_get_coarse_ns",
        161 => "ima_inode_hash",
        162 => "sock_from_file",
        163 => "check_mtu",
        164 => "for_each_map_elem",
        165 => "snprintf",
        166 => "sys_bpf",
        167 => "btf_find_by_name_kind",
        168 => "sys_close",
        169 => "timer_init",
        170 => "timer_set_callback",
        171 => "timer_start",
        172 => "timer_cancel",
        173 => "get_func_ip",
        174 => "get_attach_cookie",
        175 => "task_pt_regs",
        176 => "get_branch_snapshot",
        177 => "trace_vprintk",
        178 => "skc_to_unix_sock",
        179 => "kallsyms_lookup_name",
        180 => "find_vma",
        181 => "loop",
        182 => "strncmp",
        183 => "get_func_arg",
        184 => "get_func_ret",
        185 => "get_func_arg_cnt",
        186 => "get_retval",
        187 => "set_retval",
        188 => "xdp_get_buff_len",
        189 => "xdp_load_bytes",
        190 => "xdp_store_bytes",
        191 => "copy_from_user_task",
        192 => "skb_set_tstamp",
        193 => "ima_file_hash",
        194 => "kptr_xchg",
        195 => "map_lookup_percpu_elem",
        196 => "skc_to_mptcp_sock",
        197 => "dynptr_from_mem",
        198 => "ringbuf_reserve_dynptr",
        199 => "ringbuf_submit_dynptr",
        200 => "ringbuf_discard_dynptr",
        201 => "dynptr_read",
        202 => "dynptr_write",
        203 => "dynptr_data",
        204 => "tcp_raw_gen_syncookie_ipv4",
        205 => "tcp_raw_gen_syncookie_ipv6",
        206 => "tcp_raw_check_syncookie_ipv4",
        207 => "tcp_raw_check_syncookie_ipv6",
        208 => "ktime_get_tai_ns",
        209 => "user_ringbuf_drain",
        210 => "cgrp_storage_get",
        211 => "cgrp_storage_delete",
        _ => return format!("unresolved helper {id}"),
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
    fn classic_context_changes_field_and_return_meaning_without_changing_captured_words() {
        let bytes = [0x20, 0, 0, 0, 16, 0, 0, 0, 0x06, 0, 0, 0, 0, 0, 0xff, 0x7f];
        let seccomp = translate_classic_explained(&bytes, ClassicContext::Seccomp);
        assert!(seccomp.contains("seccomp.args[0].low32"));
        assert!(seccomp.contains("SECCOMP_RET_ALLOW"));
        let socket = translate_classic_explained(&bytes, ClassicContext::Socket);
        assert!(socket.contains("load_be_u32(packet, 0x10)"));
        assert!(socket.contains("retain min(packet.length"));
        assert!(!socket.contains("seccomp.args"));
        let unresolved = translate_classic_explained(&bytes, ClassicContext::Unknown);
        assert!(unresolved.contains("field meaning unresolved"));
        let malformed =
            translate_classic_explained(&[0x60, 0, 0, 0, 16, 0, 0, 0], ClassicContext::Socket);
        assert!(malformed.contains("invalid scratch index M[16]"));
    }

    #[test]
    fn ebpf_explanation_keeps_memory_direction_wide_pairs_and_branch_validity() {
        let bytes = [
            0x63, 0x21, 0xfc, 0xff, 0, 0, 0, 0, 0x05, 0, 1, 0, 0, 0, 0, 0, 0x18, 0, 0, 0, 1, 0, 0,
            0, 0, 0, 0, 0, 2, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0,
        ];
        let text = translate_explained(&bytes);
        assert!(text.contains("store_u32(r1 -4, r2)"));
        assert!(text.contains("invalid target insn 3 (lddw continuation)"));
        assert!(text.contains("0x0000000200000001"));
        assert!(text.contains("return r0"));
        let malformed =
            translate_explained(&[0x18, 0, 0, 0, 1, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0]);
        assert!(malformed.contains("malformed lddw continuation"));
        assert!(helper(211).contains("cgrp_storage_delete"));
        assert!(helper(10000).contains("unresolved helper"));
    }

    #[test]
    fn aligned_incomplete_capture_is_partial_and_exports_never_overwrite() {
        let bytes = [0x06, 0, 0, 0, 0, 0, 0, 0];
        let identity = BpfIdentity {
            declared_instruction_count: Some(30),
            event_id: Some(2),
            ..BpfIdentity::default()
        };
        let exported = export_capture(&bytes, &identity);
        assert!(exported.contains("\"partial\":true"));
        let root = std::env::temp_dir().join(format!(
            "ant-bpf-export-{}",
            antinomie_monitor_core::storage::sha256_hex(exported.as_bytes())
        ));
        if root.exists() {
            std::fs::remove_dir_all(&root).unwrap();
        }
        let (binary, metadata) = write_export(&root, &bytes, &identity).unwrap();
        let saved_metadata = std::fs::read(&metadata).unwrap();
        assert!(write_export(&root, &bytes, &identity).is_err());
        assert_eq!(std::fs::read(&binary).unwrap(), bytes);
        assert_eq!(std::fs::read(&metadata).unwrap(), saved_metadata);
        let other = BpfIdentity {
            event_id: Some(3),
            ..identity
        };
        let (other_binary, _) = write_export(&root, &bytes, &other).unwrap();
        assert_ne!(binary, other_binary);
        std::fs::remove_dir_all(root).unwrap();
    }

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
        assert!(
            text.starts_with("captured 240 octets, 30 instructions"),
            "{text}"
        );
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
                ..BpfIdentity::default()
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
