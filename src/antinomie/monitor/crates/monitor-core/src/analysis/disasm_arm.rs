// SPDX-License-Identifier: GPL-3.0-only
//! 32-bit ARM disassembly (AArch32 programs of arm64 guests): the A32 and the
//! Thumb instruction sets, decoded with Capstone like aarch64
//! (`disasm_aarch64.rs`). Which set applies is the caller's knowledge: the
//! CPSR T bit for the program counter, the low bit of a symbol or branch
//! target elsewhere.
use super::DecodedInstruction;
use capstone::prelude::*;

/// The instruction set a code range is decoded in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArmMode {
    Arm,
    Thumb,
}
impl ArmMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Arm => "ARM",
            Self::Thumb => "Thumb",
        }
    }
}

/// Bytes of the Thumb instruction whose first halfword is `first`: the
/// 32-bit encodings start with 0b11101, 0b11110 or 0b11111.
pub fn thumb_len(first: u16) -> usize {
    if first >> 11 >= 0b11101 { 4 } else { 2 }
}

fn engine(mode: ArmMode) -> Option<Capstone> {
    Capstone::new()
        .arm()
        .mode(match mode {
            ArmMode::Arm => arch::arm::ArchMode::Arm,
            ArmMode::Thumb => arch::arm::ArchMode::Thumb,
        })
        .build()
        .ok()
}

/// A word or halfword Capstone cannot decode, in the assembler's spelling.
fn data_row(address: u64, bytes: &[u8]) -> DecodedInstruction {
    let text = if bytes.len() == 2 {
        format!(".short {:#06x}", u16::from_le_bytes([bytes[0], bytes[1]]))
    } else {
        format!(
            ".word {:#010x}",
            u32::from_le_bytes(bytes.try_into().expect("four bytes"))
        )
    };
    DecodedInstruction {
        address,
        bytes: bytes.to_vec(),
        text,
    }
}

/// Decode `bytes` (starting at `address`) from their first byte: at most
/// `count` instructions. One call per run, so Capstone follows IT blocks. A
/// position it cannot decode becomes a `.short`/`.word` row and decoding goes
/// on after it.
fn decode_run(
    engine: &Capstone,
    mode: ArmMode,
    address: u64,
    bytes: &[u8],
    count: usize,
) -> Vec<DecodedInstruction> {
    let mut rows: Vec<DecodedInstruction> = Vec::new();
    let mut offset = 0usize;
    let step = if mode == ArmMode::Arm { 4 } else { 2 };
    while rows.len() < count && offset + step <= bytes.len() {
        let want = count - rows.len();
        let at = address + offset as u64;
        let decoded = engine.disasm_count(&bytes[offset..], at, want).ok();
        let before = rows.len();
        if let Some(decoded) = &decoded {
            for instruction in decoded.iter() {
                let from = (instruction.address() - address) as usize;
                let to = (from + instruction.bytes().len()).min(bytes.len());
                let mnemonic = instruction.mnemonic().unwrap_or("");
                rows.push(DecodedInstruction {
                    address: instruction.address(),
                    bytes: bytes[from..to].to_vec(),
                    text: match instruction.op_str().filter(|ops| !ops.is_empty()) {
                        Some(ops) => format!("{mnemonic} {ops}"),
                        None => mnemonic.to_string(),
                    },
                });
                offset = to;
            }
        }
        if rows.len() == before {
            // Nothing decodable here (or the engine failed): one data row.
            rows.push(data_row(
                address + offset as u64,
                &bytes[offset..offset + step],
            ));
            offset += step;
        }
    }
    rows
}

/// Decode ARM or Thumb code around `focus` from `bytes` that start at
/// `address`: up to `before` instructions ahead of `focus` and `after` from it
/// on (counting it). A32 is one aligned word per instruction, so the rows
/// before the focus are exact. Thumb instructions are 2 or 4 bytes: the rows
/// before the focus are the longest run, starting in the window, that lands
/// exactly on the focus (a guess, as for x86), else the window starts at the
/// focus.
pub fn decode_window_arm(
    address: u64,
    bytes: &[u8],
    focus: u64,
    before: usize,
    after: usize,
    mode: ArmMode,
) -> Vec<DecodedInstruction> {
    let unit = if mode == ArmMode::Arm { 4 } else { 2 };
    let Some(focus_offset) = focus
        .checked_sub(address)
        .and_then(|offset| usize::try_from(offset).ok())
        .filter(|offset| *offset < bytes.len() && focus.is_multiple_of(unit as u64))
    else {
        return Vec::new();
    };
    let Some(engine) = engine(mode) else {
        return Vec::new();
    };
    // The first byte to decode from; the window's own alignment (`address`)
    // may differ from the instruction set's.
    let aligned_start = (address % unit as u64) as usize;
    let first = match mode {
        ArmMode::Arm => {
            let back = ((focus_offset.saturating_sub(aligned_start)) / 4).min(before) * 4;
            focus_offset - back
        }
        ArmMode::Thumb => {
            // The farthest start (up to `before` four-byte instructions back)
            // whose decoding steps onto the focus.
            let farthest = focus_offset
                .saturating_sub(before * 4)
                .max(aligned_start)
                .next_multiple_of(2);
            (farthest..focus_offset)
                .step_by(2)
                .find(|start| {
                    let mut at = *start;
                    while at < focus_offset {
                        let Some(half) = bytes.get(at..at + 2) else {
                            return false;
                        };
                        at += thumb_len(u16::from_le_bytes([half[0], half[1]]));
                    }
                    at == focus_offset
                })
                .unwrap_or(focus_offset)
        }
    };
    let rows = decode_run(
        &engine,
        mode,
        address + first as u64,
        &bytes[first..],
        bytes.len(),
    );
    // Keep at most `before` rows ahead of the focus and `after` from it on.
    let Some(index) = rows.iter().position(|row| row.address >= focus) else {
        return Vec::new();
    };
    let start = index.saturating_sub(before);
    rows.into_iter()
        .skip(start)
        .take(index - start + after)
        .collect()
}

/// Linear decode of a bounded span from its first byte, in one set.
pub fn decode_span_arm(address: u64, bytes: &[u8], mode: ArmMode) -> Vec<DecodedInstruction> {
    let Some(engine) = engine(mode) else {
        return Vec::new();
    };
    decode_run(&engine, mode, address, bytes, bytes.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(values: &[u32]) -> Vec<u8> {
        values.iter().flat_map(|word| word.to_le_bytes()).collect()
    }
    fn halves(values: &[u16]) -> Vec<u8> {
        values.iter().flat_map(|half| half.to_le_bytes()).collect()
    }
    fn texts(rows: &[DecodedInstruction]) -> Vec<(u64, &str)> {
        rows.iter()
            .map(|row| (row.address, row.text.as_str()))
            .collect()
    }

    #[test]
    fn a32_words_around_the_focus() {
        // mov r1, r0; add r0, r1, r1, lsl #1; svc #0; bx lr; one word of udf.
        let code = words(&[
            0xe1a0_1000,
            0xe081_0081,
            0xef00_0000,
            0xe12f_ff1e,
            0xe7f0_00f0,
        ]);
        let rows = decode_window_arm(0x10000, &code, 0x10008, 1, 3, ArmMode::Arm);
        assert_eq!(
            texts(&rows),
            [
                (0x10004, "add r0, r1, r1, lsl #1"),
                (0x10008, "svc #0"),
                (0x1000c, "bx lr"),
                (0x10010, "udf #0"),
            ]
        );
        assert_eq!(rows[1].bytes, [0x00, 0x00, 0x00, 0xef]);
        assert!(decode_window_arm(0x10000, &code, 0x10002, 1, 1, ArmMode::Arm).is_empty());
        assert!(decode_window_arm(0x10000, &code, 0x20000, 1, 1, ArmMode::Arm).is_empty());
    }

    #[test]
    fn thumb_mixes_sixteen_and_thirty_two_bit_instructions() {
        // push {r7, lr}; bl +0 (32-bit); movs r0, #1; pop {r7, pc}.
        let code = halves(&[0xb580, 0xf000, 0xf800, 0x2001, 0xbd80]);
        let rows = decode_window_arm(0x8000, &code, 0x8008, 3, 2, ArmMode::Thumb);
        assert_eq!(
            texts(&rows),
            [
                (0x8000, "push {r7, lr}"),
                (0x8002, "bl #0x8006"),
                (0x8006, "movs r0, #1"),
                (0x8008, "pop {r7, pc}"),
            ]
        );
        assert_eq!(rows[1].bytes, [0x00, 0xf0, 0x00, 0xf8]);
        // A focus inside the 32-bit instruction cannot be backed up to: the
        // window starts at the focus.
        let rows = decode_window_arm(0x8000, &code, 0x8004, 3, 2, ArmMode::Thumb);
        assert_eq!(rows[0].address, 0x8004);
        // An odd focus is no Thumb instruction address.
        assert!(decode_window_arm(0x8000, &code, 0x8001, 1, 1, ArmMode::Thumb).is_empty());
    }

    #[test]
    fn thumb_it_blocks_keep_their_condition() {
        // cmp r0, #0; ite eq; moveq r1, #1; movne r1, #2.
        let code = halves(&[0x2800, 0xbf0c, 0x2101, 0x2102]);
        let rows = decode_span_arm(0x100, &code, ArmMode::Thumb);
        let text: Vec<&str> = rows.iter().map(|row| row.text.as_str()).collect();
        assert_eq!(
            text,
            ["cmp r0, #0", "ite eq", "moveq r1, #1", "movne r1, #2"]
        );
    }

    #[test]
    fn undecodable_data_keeps_a_row() {
        let rows = decode_span_arm(0x1000, &0xf7f0_a000u32.to_le_bytes(), ArmMode::Arm);
        assert_eq!(rows.len(), 1);
        let rows = decode_span_arm(0x1000, &[0xff, 0xff, 0xff, 0xff], ArmMode::Arm);
        assert_eq!(rows.len(), 1);
        assert_eq!(thumb_len(0xf000), 4);
        assert_eq!(thumb_len(0xe7fe), 2);
        assert_eq!(thumb_len(0xbd80), 2);
    }
}
