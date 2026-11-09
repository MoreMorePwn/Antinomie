// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Host syscall ids: a call's number on its ABI with the ABI in the high bits.
use super::Abi;

/// Where a host syscall id keeps its ABI: the bits above every architecture's
/// numbers (MIPS o32's start at 4000).
const ABI_SHIFT: u32 = 48;
const NUMBER_MASK: u64 = (1 << ABI_SHIFT) - 1;
/// The tag of a call no table describes (another ABI's call on an arm64 guest).
const UNTABLED: u64 = 0xffff;

impl Abi {
    /// The id tag of the ABI's calls: x86-64 has none, so its ids are its
    /// numbers (every recording and rule before arm64 reads the same); others
    /// their ELF machine.
    pub(super) fn tag(self) -> u64 {
        match self {
            Self::X86_64 => 0,
            Self::Aarch64 => u64::from(crate::api::GuestArch::ELF_AARCH64),
            Self::Arm => u64::from(crate::api::GuestArch::ELF_ARM),
            Self::I386 => u64::from(crate::api::GuestArch::ELF_386),
        }
    }
}

/// A host syscall id: a call's number on its ABI with the ABI in the high
/// bits, which is what an event's `syscall_nr` holds. Every lookup by id
/// below reads the table of the call's own ABI, so decoders, rules and views
/// that pass an event's id along decode every architecture.
pub fn id(abi: Abi, number: u64) -> u64 {
    (abi.tag() << ABI_SHIFT) | (number & NUMBER_MASK)
}

/// The id of a call no table describes, kept by its number.
pub fn untabled_id(number: u64) -> u64 {
    (UNTABLED << ABI_SHIFT) | (number & NUMBER_MASK)
}

/// The number the guest's records and programs use for an id.
pub fn wire_number(id: u64) -> u64 {
    id & NUMBER_MASK
}

/// The ABI tag of an id (0: x86-64).
pub(super) fn tag_of(id: u64) -> u64 {
    id >> ABI_SHIFT
}

/// The ids of these calls on every ABI this host ships a table for, the way
/// an event's `syscall_nr` carries them: x86-64's numbers, and the aarch64,
/// arm and i386 calls of the same name or of that family (arm's `send` for
/// `sendto`, `mmap2` for `mmap`). A list of calls names x86-64's; a filter
/// built from [`super::number`] alone keeps no call of an arm64 or a compat run.
pub fn ids_on_every_abi(names: &[String]) -> std::collections::HashSet<u64> {
    let wanted: std::collections::HashSet<&str> = names.iter().map(String::as_str).collect();
    [Abi::X86_64, Abi::Aarch64, Abi::Arm, Abi::I386]
        .into_iter()
        .flat_map(|abi| {
            let wanted = &wanted;
            super::table(abi)
                .all()
                .iter()
                .filter(move |entry| {
                    wanted.contains(entry.name.as_str())
                        || entry
                            .family
                            .as_deref()
                            .is_some_and(|family| wanted.contains(family))
                })
                .map(move |entry| id(abi, entry.number))
        })
        .collect()
}
