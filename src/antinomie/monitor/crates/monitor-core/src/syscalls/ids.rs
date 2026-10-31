// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Host syscall ids: a call's number on its ABI with the ABI in the high bits.
use super::Abi;

/// Where a host syscall id keeps its ABI: the bits above every architecture's
/// numbers (MIPS o32's start at 4000).
const ABI_SHIFT: u32 = 48;
const NUMBER_MASK: u64 = (1 << ABI_SHIFT) - 1;
/// The tag of a call no table describes (an AArch32 call on an arm64 guest).
const UNTABLED: u64 = 0xffff;

impl Abi {
    /// The id tag of the ABI's calls: x86-64 has none, so its ids are its
    /// numbers (every recording and rule before arm64 reads the same); others
    /// their ELF machine.
    pub(super) fn tag(self) -> u64 {
        match self {
            Self::X86_64 => 0,
            Self::Aarch64 => u64::from(crate::api::GuestArch::ELF_AARCH64),
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
