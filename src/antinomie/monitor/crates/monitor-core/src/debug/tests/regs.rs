// SPDX-License-Identifier: MIT
use crate::debug::{
    ArchTag, RegKind, RegisterFile, RegsetBlob,
    amd64::{self, FXSAVE_SIZE, NT_PRFPREG, NT_PRSTATUS, USER_REGS_SIZE, full_tag_word},
};

fn file() -> RegisterFile {
    let mut general = vec![0u8; USER_REGS_SIZE];
    // r15..: every u64 slot holds its own index so the mapping is checkable.
    for slot in 0..27 {
        general[slot * 8..slot * 8 + 8].copy_from_slice(&(0x1000 + slot as u64).to_le_bytes());
    }
    let mut fp = vec![0u8; FXSAVE_SIZE];
    fp[0..2].copy_from_slice(&0x037fu16.to_le_bytes());
    fp[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
    for (index, byte) in fp[160..416].iter_mut().enumerate() {
        *byte = index as u8;
    }
    let mut file = RegisterFile::new();
    file.insert(RegsetBlob {
        nt_type: NT_PRSTATUS,
        data: general,
    });
    file.insert(RegsetBlob {
        nt_type: NT_PRFPREG,
        data: fp,
    });
    file
}

#[test]
fn description_is_consistent() {
    let description = ArchTag::X86_64.description();
    assert_eq!(description.image_len(), 560);
    assert_eq!(description.regs.len(), 24 + 8 + 8 + 16 + 1 + 1 + 2);
    // The XML lists registers feature by feature, so the register order must
    // already be grouped the same way or `g` and the XML would disagree.
    let mut order = Vec::new();
    for feature in &description.features {
        order.extend(
            description
                .regs
                .iter()
                .filter(|reg| reg.feature == feature.name)
                .map(|reg| reg.name),
        );
    }
    let flat: Vec<&str> = description.regs.iter().map(|reg| reg.name).collect();
    assert_eq!(order, flat);
    let xml = description.xml();
    for name in [
        "rax", "rip", "eflags", "st7", "fop", "xmm15", "mxcsr", "orig_rax", "fs_base", "gs_base",
    ] {
        assert!(xml.contains(&format!("<reg name=\"{name}\" ")), "{name}");
    }
    assert!(xml.contains("<architecture>i386:x86-64</architecture>"));
    assert!(xml.contains("<osabi>GNU/Linux</osabi>"));
    let positions: Vec<usize> = flat
        .iter()
        .map(|name| xml.find(&format!("<reg name=\"{name}\" ")).unwrap())
        .collect();
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "XML order is the image order"
    );
    let (offset, rip) = description.find("rip").unwrap();
    assert_eq!((offset, rip.kind), (8 * 16, RegKind::CodePointer));
    assert_eq!(description.find("orig_rax").unwrap().0, 536);
    assert_eq!(description.find("gs_base").unwrap().0, 552);
}

#[test]
fn image_holds_each_register_where_gdb_expects_it() {
    let description = ArchTag::X86_64.description();
    let image = description.serialize(&file());
    assert_eq!(image.len(), 560);
    let u64_at = |name: &str| {
        let (offset, _) = description.find(name).unwrap();
        u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap())
    };
    // user_regs_struct order: r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi ...
    assert_eq!(u64_at("r15"), 0x1000);
    assert_eq!(u64_at("rbx"), 0x1005);
    assert_eq!(u64_at("rax"), 0x100a);
    assert_eq!(u64_at("rdi"), 0x100e);
    assert_eq!(u64_at("orig_rax"), 0x100f);
    assert_eq!(u64_at("rip"), 0x1010);
    assert_eq!(u64_at("rsp"), 0x1013);
    assert_eq!(u64_at("fs_base"), 0x1015);
    assert_eq!(u64_at("gs_base"), 0x1016);
    // 32-bit registers come from the low half of their 64-bit slot.
    let (offset, _) = description.find("eflags").unwrap();
    assert_eq!(
        u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap()),
        0x1012
    );
    let (offset, _) = description.find("cs").unwrap();
    assert_eq!(
        u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap()),
        0x1011
    );
    // x87 and SSE come from the FXSAVE image.
    let (offset, _) = description.find("fctrl").unwrap();
    assert_eq!(
        u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap()),
        0x037f
    );
    let (offset, _) = description.find("mxcsr").unwrap();
    assert_eq!(
        u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap()),
        0x1f80
    );
    let (offset, _) = description.find("xmm2").unwrap();
    assert_eq!(image[offset], 32);
    assert_eq!(image[offset + 15], 47);
    let (offset, reg) = description.find("st0").unwrap();
    assert_eq!(reg.bytes(), 10);
    assert_eq!(&image[offset..offset + 10], &[0; 10]);
    // A missing register set reads as zero (an empty x87 stack) rather than failing.
    let mut empty = vec![0u8; 560];
    let (offset, _) = description.find("ftag").unwrap();
    empty[offset..offset + 2].copy_from_slice(&[0xff, 0xff]);
    assert_eq!(description.serialize(&RegisterFile::new()), empty);
}

#[test]
fn x87_tag_word_is_rebuilt_from_the_abridged_tag() {
    let mut fx = vec![0u8; FXSAVE_SIZE];
    assert_eq!(full_tag_word(&fx), 0xffff, "all empty");
    // TOP = 6, physical registers 6 and 7 valid: ST(0) = 1.0, ST(1) = 0.0.
    fx[2..4].copy_from_slice(&((6u16) << 11).to_le_bytes());
    fx[4] = 0b1100_0000;
    fx[32..42].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f]);
    // ST(1) stays all zero: a zero.
    let word = full_tag_word(&fx);
    assert_eq!((word >> 12) & 3, 0, "physical 6 holds ST(0) = 1.0, valid");
    assert_eq!((word >> 14) & 3, 1, "physical 7 holds ST(1) = 0, zero");
    assert_eq!(word & 0x0fff, 0x0fff, "the rest are empty");
    // A special value (infinity) in ST(0).
    fx[40..42].copy_from_slice(&0x7fffu16.to_le_bytes());
    assert_eq!((full_tag_word(&fx) >> 12) & 3, 2);
    assert_eq!(full_tag_word(&fx[..100]), 0xffff, "short image");
}

#[test]
fn image_round_trips_and_writes_back_only_what_changed() {
    let description = ArchTag::X86_64.description();
    let original = file();
    let image = description.serialize(&original);
    let mut copy = original.clone();
    assert!(
        description
            .deserialize(&image, &mut copy)
            .unwrap()
            .is_empty()
    );
    assert_eq!(copy, original);

    let (offset, _) = description.find("rax").unwrap();
    let mut changed = image.clone();
    changed[offset..offset + 8].copy_from_slice(&0xdead_beef_u64.to_le_bytes());
    let mut copy = original.clone();
    assert_eq!(
        description.deserialize(&changed, &mut copy).unwrap(),
        vec![NT_PRSTATUS]
    );
    assert_eq!(
        &copy.get(NT_PRSTATUS).unwrap()[80..88],
        &0xdead_beef_u64.to_le_bytes()
    );

    let (offset, _) = description.find("xmm0").unwrap();
    let mut changed = image.clone();
    changed[offset] = 0xaa;
    let mut copy = original.clone();
    assert_eq!(
        description.deserialize(&changed, &mut copy).unwrap(),
        vec![NT_PRFPREG]
    );
    assert_eq!(copy.get(NT_PRFPREG).unwrap()[160], 0xaa);

    // A segment register write keeps the slot's upper half.
    let mut seeded = original.clone();
    seeded.get_mut(NT_PRSTATUS).unwrap()[140..144].copy_from_slice(&[0xee; 4]);
    let image = description.serialize(&seeded);
    let (offset, _) = description.find("cs").unwrap();
    let mut changed = image.clone();
    changed[offset..offset + 4].copy_from_slice(&0x33u32.to_le_bytes());
    description.deserialize(&changed, &mut seeded).unwrap();
    assert_eq!(
        &seeded.get(NT_PRSTATUS).unwrap()[136..140],
        &0x33u32.to_le_bytes()
    );
    assert_eq!(&seeded.get(NT_PRSTATUS).unwrap()[140..144], &[0xee; 4]);

    // A tag word that disagrees with the abridged tag is written back.
    let (offset, _) = description.find("ftag").unwrap();
    let mut changed = description.serialize(&original);
    changed[offset..offset + 2].copy_from_slice(&0xfff0u16.to_le_bytes());
    let mut copy = original.clone();
    assert_eq!(
        description.deserialize(&changed, &mut copy).unwrap(),
        vec![NT_PRFPREG]
    );
    // 0xfff0: x87 registers 0 and 1 carry values, the others are empty.
    assert_eq!(copy.get(NT_PRFPREG).unwrap()[4], 0b11);

    assert!(description.deserialize(&image[..559], &mut copy).is_err());
}

#[test]
fn register_view_carries_names_and_groups() {
    let description = ArchTag::X86_64.description();
    let view = description.view(&file());
    assert_eq!(view.len(), description.regs.len());
    let rip = view.iter().find(|value| value.name == "rip").unwrap();
    assert_eq!(rip.bytes.len(), 8);
    assert_eq!(
        u64::from_le_bytes(rip.bytes[..8].try_into().unwrap()),
        0x1010
    );
    assert_eq!(rip.feature, "org.gnu.gdb.i386.core");
    let xmm = view.iter().find(|value| value.name == "xmm0").unwrap();
    assert_eq!((xmm.bits, xmm.group), (128, Some("vector")));
    let gdb = amd64::Amd64Registers::default();
    assert_eq!(gdb.image.len(), 560);
}
