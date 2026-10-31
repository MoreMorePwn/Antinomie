// SPDX-License-Identifier: GPL-3.0-only
//! aarch64 disassembly for the debugger's code pane, decoded with Capstone
//! (built for arm64 alone). x86 keeps iced-x86 (`disasm.rs`).
use super::DecodedInstruction;
use capstone::prelude::*;

/// Decode aarch64 code around `focus` from `bytes` that start at `address`: up
/// to `before` instructions ahead of `focus` and `after` from it on (counting
/// it). Every A64 instruction is one aligned word, so the instructions before
/// the focus are exact, not a guess. A word Capstone cannot decode is shown as
/// `.inst 0x…` (the assembler's spelling), so the rows stay one per word.
pub fn decode_window_aarch64(
    address: u64,
    bytes: &[u8],
    focus: u64,
    before: usize,
    after: usize,
) -> Vec<DecodedInstruction> {
    let Some(focus_offset) = focus
        .checked_sub(address)
        .and_then(|offset| usize::try_from(offset).ok())
        .filter(|offset| *offset < bytes.len() && focus.is_multiple_of(4))
    else {
        return Vec::new();
    };
    let Ok(engine) = Capstone::new()
        .arm64()
        .mode(arch::arm64::ArchMode::Arm)
        .build()
    else {
        return Vec::new();
    };
    // Whole words in the window, aligned on the focus.
    let first = focus_offset - (focus_offset / 4).min(before) * 4;
    let words = (bytes.len() - first) / 4;
    let count = ((focus_offset - first) / 4 + after).min(words);
    (0..count)
        .map(|index| {
            let offset = first + index * 4;
            let word = &bytes[offset..offset + 4];
            let at = address + offset as u64;
            let text = engine
                .disasm_count(word, at, 1)
                .ok()
                .and_then(|decoded| {
                    let instruction = decoded.iter().next()?;
                    let mnemonic = instruction.mnemonic()?;
                    Some(match instruction.op_str().filter(|ops| !ops.is_empty()) {
                        Some(ops) => format!("{mnemonic} {ops}"),
                        None => mnemonic.to_string(),
                    })
                })
                .unwrap_or_else(|| {
                    format!(
                        ".inst {:#010x}",
                        u32::from_le_bytes(word.try_into().expect("four bytes"))
                    )
                });
            DecodedInstruction {
                address: at,
                bytes: word.to_vec(),
                text,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_words_around_the_focus() {
        // mov x1, x0; add x0, x1, x1, lsl #1; svc #0; ret; and one undefined word.
        let code: Vec<u8> = [
            0xaa00_03e1u32,
            0x8b01_0420,
            0xd400_0001,
            0xd65f_03c0,
            0x0000_0000,
        ]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
        let lines = decode_window_aarch64(0x400740, &code, 0x400748, 1, 3);
        let text: Vec<(u64, &str)> = lines
            .iter()
            .map(|line| (line.address, line.text.as_str()))
            .collect();
        assert_eq!(
            text,
            [
                (0x400744, "add x0, x1, x1, lsl #1"),
                (0x400748, "svc #0"),
                (0x40074c, "ret"),
                (0x400750, "udf #0"),
            ]
        );
        assert_eq!(lines[1].bytes, [0x01, 0x00, 0x00, 0xd4]);
        // The window's start and an unaligned or outside focus.
        assert_eq!(
            decode_window_aarch64(0x400740, &code, 0x400740, 4, 1).len(),
            1
        );
        assert!(decode_window_aarch64(0x400740, &code, 0x400742, 1, 1).is_empty());
        assert!(decode_window_aarch64(0x400740, &code, 0x400800, 1, 1).is_empty());
        // A word that is no instruction keeps its row.
        let bad = 0xffff_ffffu32.to_le_bytes();
        let lines = decode_window_aarch64(0x1000, &bad, 0x1000, 0, 1);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].text, ".inst 0xffffffff");
    }
}
