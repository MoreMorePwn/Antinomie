// SPDX-License-Identifier: GPL-3.0-only
//! A raw look at one ext4 inode, by number.
//!
//! `ext4-view` finds files by path and does not say which inode a path
//! reached. A run's trace names a file by device, inode number and
//! generation, so to tell that the file at a path on the starting disk is the
//! one the run saw (and not another file that took the name, or a file that
//! took over a freed inode number) the reader reads the inode record itself:
//! superblock, group descriptor, inode table. Only the fields that identify
//! an inode are read; nothing here follows the file's data.
use ext4_view::Ext4Read;

const SUPERBLOCK_OFFSET: u64 = 1024;
const MAGIC: u16 = 0xef53;
const INCOMPAT_64BIT: u32 = 0x80;
/// Inode sizes ext4 allows; a larger or odd one is a damaged superblock.
const INODE_SIZE_RANGE: std::ops::RangeInclusive<u32> = 128..=4096;

/// The identifying fields of an inode record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawInode {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    /// Seconds of the modification time, low 32 bits.
    pub mtime: u32,
    pub links: u16,
    pub generation: u32,
}

fn le16(data: &[u8], at: usize) -> u32 {
    u32::from(u16::from_le_bytes([data[at], data[at + 1]]))
}
fn le32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

/// The inode `ino` of the filesystem on `disk`.
pub fn read_inode(disk: &mut dyn Ext4Read, ino: u64) -> Result<RawInode, String> {
    let io = |error: Box<dyn std::error::Error + Send + Sync>| error.to_string();
    let mut sb = [0u8; 256];
    disk.read(SUPERBLOCK_OFFSET, &mut sb).map_err(io)?;
    if le16(&sb, 0x38) != u32::from(MAGIC) {
        return Err("not an ext4 superblock".into());
    }
    let inodes_count = u64::from(le32(&sb, 0x00));
    let block_size = 1024u64
        .checked_shl(le32(&sb, 0x18))
        .filter(|size| *size <= 65_536)
        .ok_or("ext4 block size out of range")?;
    let first_data_block = u64::from(le32(&sb, 0x14));
    let per_group = u64::from(le32(&sb, 0x28));
    let inode_size = if le32(&sb, 0x4c) == 0 {
        128
    } else {
        le16(&sb, 0x58)
    };
    let incompat = le32(&sb, 0x60);
    let descriptor_size = if incompat & INCOMPAT_64BIT != 0 {
        u64::from(le16(&sb, 0xfe)).max(64)
    } else {
        32
    };
    if per_group == 0 || !INODE_SIZE_RANGE.contains(&inode_size) {
        return Err("ext4 superblock out of range".into());
    }
    if ino == 0 || ino > inodes_count {
        return Err("inode number outside the filesystem".into());
    }
    let group = (ino - 1) / per_group;
    let index = (ino - 1) % per_group;
    let descriptor_at = (first_data_block + 1) * block_size + group * descriptor_size;
    let mut descriptor = [0u8; 64];
    let length = usize::try_from(descriptor_size.min(64)).unwrap_or(32);
    disk.read(descriptor_at, &mut descriptor[..length])
        .map_err(io)?;
    let mut table = u64::from(le32(&descriptor, 0x08));
    if descriptor_size >= 64 {
        table |= u64::from(le32(&descriptor, 0x28)) << 32;
    }
    if table == 0 {
        return Err("ext4 group has no inode table".into());
    }
    let at = table * block_size + index * u64::from(inode_size);
    let mut raw = vec![0u8; usize::try_from(inode_size).unwrap_or(128).max(128)];
    disk.read(at, &mut raw).map_err(io)?;
    Ok(RawInode {
        mode: le16(&raw, 0x00) as u16,
        uid: le16(&raw, 0x02) | (le16(&raw, 0x78) << 16),
        gid: le16(&raw, 0x18) | (le16(&raw, 0x7a) << 16),
        size: u64::from(le32(&raw, 0x04)) | (u64::from(le32(&raw, 0x6c)) << 32),
        mtime: le32(&raw, 0x10),
        links: le16(&raw, 0x1a) as u16,
        generation: le32(&raw, 0x64),
    })
}
