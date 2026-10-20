// SPDX-License-Identifier: MIT
use super::*;
use crate::disks::fixture::{
    EXT4_START, Fixture, OTHER_LENGTH, OTHER_START, Scheme, require_tools,
};
use std::fs;

fn head_of(disk: &std::path::Path) -> (Vec<u8>, u64) {
    let bytes = fs::read(disk).unwrap();
    let size = bytes.len() as u64;
    (bytes[..HEAD_SECTORS * 512].to_vec(), size)
}

#[test]
fn gpt_and_mbr_tables_are_carved_to_the_right_byte_ranges() {
    require_tools!();
    let fixture = Fixture::new();
    let ext4 = fixture.standard_image();
    for scheme in [Scheme::Gpt, Scheme::Mbr] {
        let disk = fixture.partitioned("disk.raw", scheme, &ext4);
        let (head, size) = head_of(&disk);
        let table = parse(&head, size).unwrap().expect("a table");
        assert_eq!(
            table.kind,
            if scheme == Scheme::Gpt {
                TableKind::Gpt
            } else {
                TableKind::Mbr
            }
        );
        assert_eq!(table.partitions.len(), 2, "{table:?}");
        let (first, second) = (&table.partitions[0], &table.partitions[1]);
        assert_eq!((first.start, first.length), (OTHER_START, OTHER_LENGTH));
        assert_eq!(second.start, EXT4_START);
        assert_eq!(second.length, fs::metadata(&ext4).unwrap().len());
        assert!(second.linux && !first.linux);
        assert_eq!(second.root, scheme == Scheme::Gpt);
        if scheme == Scheme::Gpt {
            assert_eq!(
                (first.name.as_str(), second.name.as_str()),
                ("swap", "root")
            );
            assert_eq!(second.kind, "Linux root (x86-64)");
        }
        assert_eq!(table.skipped, 0);
    }
}

#[test]
fn a_whole_disk_filesystem_and_a_blank_disk_have_no_table() {
    require_tools!();
    let fixture = Fixture::new();
    let ext4 = fixture.standard_image();
    let (head, size) = head_of(&ext4);
    assert_eq!(parse(&head, size).unwrap(), None);
    assert_eq!(parse(&vec![0; 64 * 1024], 1 << 20).unwrap(), None);
    assert_eq!(parse(&[], 0).unwrap(), None);
}

#[test]
fn the_default_partition_prefers_a_root_then_the_largest_ext4() {
    let part = |index, length, fs, root| Partition {
        index,
        start: u64::from(index) * 1_000_000,
        length,
        fs,
        root,
        ..Partition::default()
    };
    let table = PartitionTable {
        partitions: vec![
            part(1, 900, PartitionFs::Other, false),
            part(2, 500, PartitionFs::Ext4, false),
            part(3, 100, PartitionFs::Ext4, true),
            part(4, 800, PartitionFs::Ext4, false),
        ],
        ..PartitionTable::default()
    };
    assert_eq!(table.default_partition(), Some(3));
    let mut without_root = table.clone();
    without_root.partitions[2].root = false;
    assert_eq!(without_root.default_partition(), Some(4));
    without_root
        .partitions
        .retain(|p| p.fs != PartitionFs::Ext4);
    assert_eq!(without_root.default_partition(), None);
}

#[test]
fn entries_outside_the_disk_are_skipped_not_trusted() {
    require_tools!();
    let fixture = Fixture::new();
    let ext4 = fixture.standard_image();
    let disk = fixture.partitioned("disk.raw", Scheme::Mbr, &ext4);
    let (head, size) = head_of(&disk);
    // The same table on a disk that is too small for partition 2.
    let table = parse(&head, EXT4_START).unwrap().unwrap();
    assert_eq!(table.partitions.len(), 1);
    assert_eq!(table.skipped, 1);
    let _ = size;
}

#[test]
fn hostile_tables_never_panic_and_stay_bounded() {
    require_tools!();
    let fixture = Fixture::new();
    let ext4 = fixture.standard_image();
    let disk = fixture.partitioned("disk.raw", Scheme::Gpt, &ext4);
    let (good, size) = head_of(&disk);
    // A damaged GPT header behind a protective MBR is an error, not a panic.
    let mut no_header = good.clone();
    no_header[512..520].copy_from_slice(b"NOTAGPT!");
    assert!(parse(&no_header, size).is_err());
    // Entry arrays that are absurd, misplaced or overflowing.
    for (offset, value) in [
        (80usize, u32::MAX),
        (80, 0),
        (84, 0),
        (84, u32::MAX),
        (84, 12),
    ] {
        let mut head = good.clone();
        head[512 + offset..512 + offset + 4].copy_from_slice(&value.to_le_bytes());
        assert!(parse(&head, size).is_err(), "{offset} {value}");
    }
    for lba in [0u64, 1, u64::MAX, u64::MAX / 512, 1 << 40] {
        let mut head = good.clone();
        head[512 + 72..512 + 80].copy_from_slice(&lba.to_le_bytes());
        assert!(parse(&head, size).is_err(), "{lba}");
    }
    // Entries with reversed, huge or wrapping ranges are skipped.
    let mut head = good.clone();
    let entry = 1024;
    head[entry + 32..entry + 40].copy_from_slice(&u64::MAX.to_le_bytes());
    head[entry + 40..entry + 48].copy_from_slice(&0u64.to_le_bytes());
    let table = parse(&head, size).unwrap().unwrap();
    assert_eq!(table.skipped, 1);
    // Pseudo-random bytes: every prefix length parses or errors, never panics.
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    for round in 0..300 {
        let mut head = if round % 2 == 0 {
            good.clone()
        } else {
            vec![0; HEAD_SECTORS * 512]
        };
        for _ in 0..40 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let at = (state >> 33) as usize % head.len();
            head[at] = (state >> 20) as u8;
            if round % 2 == 1 {
                head[510] = 0x55;
                head[511] = 0xAA;
                head[446 + 4] = (state >> 8) as u8;
            }
        }
        let cut = (state >> 40) as usize % (head.len() + 1);
        let _ = parse(&head[..cut], size);
    }
}

#[test]
fn the_real_sgdisk_agrees_when_it_is_installed() {
    require_tools!();
    if crate::dependencies::executable(std::path::Path::new("sgdisk")).is_none()
        && !std::path::Path::new("/usr/sbin/sgdisk").is_file()
    {
        eprintln!("skipped: sgdisk is not installed");
        return;
    }
    let fixture = Fixture::new();
    let disk = fixture.path("real.raw");
    fs::File::create(&disk)
        .unwrap()
        .set_len(40 * 1024 * 1024)
        .unwrap();
    let sgdisk = if std::path::Path::new("/usr/sbin/sgdisk").is_file() {
        "/usr/sbin/sgdisk".to_string()
    } else {
        "sgdisk".to_string()
    };
    let status = std::process::Command::new(sgdisk)
        .args([
            "-n1:2048:+8M",
            "-t1:8300",
            "-c1:data",
            "-n2:0:+16M",
            "-t2:8304",
        ])
        .arg(&disk)
        .output()
        .unwrap();
    assert!(status.status.success());
    let (head, size) = head_of(&disk);
    let table = parse(&head, size).unwrap().unwrap();
    assert_eq!(table.partitions.len(), 2);
    assert_eq!(table.partitions[0].start, 2048 * 512);
    assert_eq!(table.partitions[0].length, 8 * 1024 * 1024);
    assert_eq!(table.partitions[0].name, "data");
    assert_eq!(table.partitions[1].kind, "Linux root (x86-64)");
    assert!(table.partitions[1].root);
}

#[test]
fn image_options_escape_commas_in_the_file_name() {
    let part = Partition {
        start: 1048576,
        length: 8388608,
        ..Partition::default()
    };
    assert_eq!(
        part.image_opts(std::path::Path::new("/vm,1/disk.qcow2")),
        "driver=raw,offset=1048576,size=8388608,file.driver=qcow2,file.file.filename=/vm,,1/disk.qcow2"
    );
}
