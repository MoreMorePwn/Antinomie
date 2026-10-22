// SPDX-License-Identifier: GPL-3.0-only
//! A read-only view of a standalone qcow2 image as the raw disk it holds, for
//! `ext4-view`.
//!
//! An installed base is a qcow2 file of a whole-disk ext4 filesystem. Reading
//! a few files from it (the guest's `/etc/passwd` and `/etc/group`) must not
//! cost a full `qemu-img convert` of a multi-gigabyte image, so the reader
//! follows the image's own tables instead. Only what a base uses is read:
//! qcow2 version 2 or 3, no encryption, no backing file, no external data
//! file, no extended L2 entries, and zlib (deflate) compressed clusters.
//! Anything else is refused, never guessed at. Every offset and length comes
//! from the file and is checked before use; the tables a read needs are kept
//! (bounded), one decompressed cluster at a time.
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::FileExt,
};

/// `QFI\xfb`.
const MAGIC: u32 = 0x5146_49fb;
/// Clusters of 512 bytes to 2 MiB, as qemu allows.
const CLUSTER_BITS: std::ops::RangeInclusive<u32> = 9..=21;
/// Largest virtual disk read: well above any base.
const MAX_VIRTUAL_SIZE: u64 = 1 << 42;
/// L2 tables kept at once (each one cluster).
const L2_CACHE_COUNT: usize = 32;
const OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const COMPRESSED: u64 = 1 << 62;
const ZERO: u64 = 1;
/// Incompatible features this reader accepts: the dirty bit only (refcounts
/// are never read).
const KNOWN_INCOMPATIBLE: u64 = 1;

type BoxedError = Box<dyn std::error::Error + Send + Sync>;

pub struct Qcow2 {
    file: File,
    file_size: u64,
    cluster_bits: u32,
    virtual_size: u64,
    l1: Vec<u64>,
    l2: BTreeMap<u64, Vec<u64>>,
    /// The last decompressed cluster: its host entry and bytes.
    compressed: Option<(u64, Vec<u8>)>,
}

/// Whether `header` starts like a qcow2 image.
pub fn is_qcow2(header: &[u8]) -> bool {
    header.len() >= 4 && u32::from_be_bytes([header[0], header[1], header[2], header[3]]) == MAGIC
}

fn be32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(data[at..at + 4].try_into().unwrap_or_default())
}
fn be64(data: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(data[at..at + 8].try_into().unwrap_or_default())
}

impl Qcow2 {
    pub fn open(mut file: File) -> Result<Self, String> {
        let file_size = file.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
        let mut header = [0u8; 112];
        let length = header.len().min(usize::try_from(file_size).unwrap_or(0));
        file.read_exact_at(&mut header[..length], 0)
            .map_err(|e| e.to_string())?;
        if length < 72 || !is_qcow2(&header) {
            return Err("not a qcow2 image".into());
        }
        let version = be32(&header, 4);
        let backing_offset = be64(&header, 8);
        let cluster_bits = be32(&header, 20);
        let virtual_size = be64(&header, 24);
        let crypt = be32(&header, 32);
        let l1_count = be32(&header, 36);
        let l1_offset = be64(&header, 40);
        if !(2..=3).contains(&version) {
            return Err(format!("qcow2 version {version} is not supported"));
        }
        if backing_offset != 0 {
            return Err("a qcow2 image with a backing file is not read on its own".into());
        }
        if crypt != 0 {
            return Err("encrypted qcow2 images are not supported".into());
        }
        if !CLUSTER_BITS.contains(&cluster_bits) || virtual_size > MAX_VIRTUAL_SIZE {
            return Err("qcow2 cluster size or disk size out of range".into());
        }
        if version == 3 {
            if length < 104 {
                return Err("truncated qcow2 header".into());
            }
            let incompatible = be64(&header, 72);
            let header_size = be32(&header, 100);
            // Bit 3 says the compression type byte follows; only zlib (0).
            let compression = if incompatible & 8 != 0 && header_size > 104 && length > 104 {
                header[104]
            } else {
                0
            };
            if incompatible & !(KNOWN_INCOMPATIBLE | 8) != 0 || compression != 0 {
                return Err("the qcow2 image uses features this reader does not read".into());
            }
        }
        let cluster_size = 1u64 << cluster_bits;
        let l2_count = cluster_size / 8;
        let needed = virtual_size.div_ceil(cluster_size).div_ceil(l2_count);
        if u64::from(l1_count) < needed || u64::from(l1_count) > needed.max(1) * 2 + 16 {
            return Err("qcow2 L1 table size does not match the disk size".into());
        }
        let l1_size = u64::from(l1_count) * 8;
        if !l1_offset.is_multiple_of(cluster_size)
            || l1_offset
                .checked_add(l1_size)
                .is_none_or(|end| end > file_size)
        {
            return Err("qcow2 L1 table lies outside the file".into());
        }
        let mut raw = vec![0u8; usize::try_from(l1_size).map_err(|e| e.to_string())?];
        file.read_exact_at(&mut raw, l1_offset)
            .map_err(|e| e.to_string())?;
        let l1 = raw
            .as_chunks::<8>()
            .0
            .iter()
            .map(|entry| u64::from_be_bytes(*entry))
            .collect();
        Ok(Self {
            file,
            file_size,
            cluster_bits,
            virtual_size,
            l1,
            l2: BTreeMap::new(),
            compressed: None,
        })
    }

    pub fn virtual_size(&self) -> u64 {
        self.virtual_size
    }

    fn cluster_size(&self) -> u64 {
        1 << self.cluster_bits
    }

    /// The L2 entry of the cluster holding guest offset `at`.
    fn l2_entry(&mut self, at: u64) -> Result<u64, String> {
        let cluster_size = self.cluster_size();
        let per_table = cluster_size / 8;
        let cluster = at >> self.cluster_bits;
        let l1_index = usize::try_from(cluster / per_table).map_err(|e| e.to_string())?;
        let l1_entry = *self
            .l1
            .get(l1_index)
            .ok_or("guest offset beyond the qcow2 L1 table")?;
        let table = l1_entry & OFFSET_MASK;
        if table == 0 {
            return Ok(0);
        }
        if !self.l2.contains_key(&table) {
            if !table.is_multiple_of(cluster_size)
                || table
                    .checked_add(cluster_size)
                    .is_none_or(|end| end > self.file_size)
            {
                return Err("qcow2 L2 table lies outside the file".into());
            }
            let mut raw = vec![0u8; cluster_size as usize];
            self.file
                .read_exact_at(&mut raw, table)
                .map_err(|e| e.to_string())?;
            if self.l2.len() >= L2_CACHE_COUNT {
                self.l2.pop_first();
            }
            self.l2.insert(
                table,
                raw.as_chunks::<8>()
                    .0
                    .iter()
                    .map(|entry| u64::from_be_bytes(*entry))
                    .collect(),
            );
        }
        Ok(self.l2[&table][(cluster % per_table) as usize])
    }

    /// The decompressed cluster of compressed L2 `entry`.
    fn inflate(&mut self, entry: u64) -> Result<&[u8], String> {
        if self
            .compressed
            .as_ref()
            .is_none_or(|(held, _)| *held != entry)
        {
            let cluster_size = self.cluster_size();
            let shift = 62 - (self.cluster_bits - 8);
            let host = entry & ((1u64 << shift) - 1);
            let sectors = ((entry >> shift) & ((1u64 << (self.cluster_bits - 8)) - 1)) + 1;
            let length = (sectors * 512).saturating_sub(host & 511);
            let length = length.min(self.file_size.saturating_sub(host));
            if host >= self.file_size || length == 0 || length > 2 * cluster_size + 512 {
                return Err("qcow2 compressed cluster lies outside the file".into());
            }
            let mut raw = vec![0u8; length as usize];
            self.file
                .read_exact_at(&mut raw, host)
                .map_err(|e| e.to_string())?;
            let mut cluster = Vec::with_capacity(cluster_size as usize);
            // A deflate stream may stop early (trailing sector padding); it
            // must not inflate past one cluster.
            flate2::read::DeflateDecoder::new(&raw[..])
                .take(cluster_size)
                .read_to_end(&mut cluster)
                .map_err(|e| format!("qcow2 compressed cluster: {e}"))?;
            cluster.resize(cluster_size as usize, 0);
            self.compressed = Some((entry, cluster));
        }
        Ok(&self.compressed.as_ref().expect("filled above").1)
    }

    /// Fill `dst` with the guest bytes from `start`.
    pub fn read_at(&mut self, start: u64, dst: &mut [u8]) -> Result<(), String> {
        let end = start
            .checked_add(dst.len() as u64)
            .filter(|end| *end <= self.virtual_size)
            .ok_or("read beyond the end of the qcow2 disk")?;
        let cluster_size = self.cluster_size();
        let mut at = start;
        while at < end {
            let within = at % cluster_size;
            let count = (cluster_size - within).min(end - at) as usize;
            let out = &mut dst[(at - start) as usize..][..count];
            let entry = self.l2_entry(at)?;
            if entry & COMPRESSED != 0 {
                let cluster = self.inflate(entry & !COMPRESSED & !(1 << 63))?;
                out.copy_from_slice(&cluster[within as usize..][..count]);
            } else {
                let host = entry & OFFSET_MASK;
                if host == 0 || entry & ZERO != 0 {
                    out.fill(0);
                } else if !host.is_multiple_of(cluster_size)
                    || host
                        .checked_add(cluster_size)
                        .is_none_or(|end| end > self.file_size.next_multiple_of(cluster_size))
                {
                    return Err("qcow2 data cluster lies outside the file".into());
                } else {
                    // A last cluster may end before its size; the rest reads
                    // as the zeros qemu would return.
                    let from = host + within;
                    let present = self.file_size.saturating_sub(from).min(count as u64) as usize;
                    self.file
                        .read_exact_at(&mut out[..present], from)
                        .map_err(|e| e.to_string())?;
                    out[present..].fill(0);
                }
            }
            at += count as u64;
        }
        Ok(())
    }
}

impl ext4_view::Ext4Read for Qcow2 {
    fn read(&mut self, start_byte: u64, dst: &mut [u8]) -> Result<(), BoxedError> {
        self.read_at(start_byte, dst).map_err(BoxedError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disks::fixture::{Fixture, require_tools};
    use std::{io::Write, path::Path, process::Command};

    fn convert(raw: &Path, out: &Path, compress: bool) {
        let mut command = Command::new("qemu-img");
        command.args(["convert", "-f", "raw", "-O", "qcow2"]);
        if compress {
            command.arg("-c");
        }
        let status = command.arg(raw).arg(out).status().unwrap();
        assert!(status.success());
    }

    /// The same bytes come back from the qcow2 file as from the raw disk,
    /// plain and compressed, across cluster boundaries and holes.
    #[test]
    fn a_qcow2_image_reads_back_as_its_raw_disk() {
        require_tools!();
        let fixture = Fixture::new();
        let raw = fixture.path("disk.raw");
        let mut disk = vec![0u8; 3 << 20];
        for (index, byte) in disk.iter_mut().enumerate().skip(4096).take(300_000) {
            *byte = (index * 31 + 7) as u8;
        }
        disk[(2 << 20) + 5..(2 << 20) + 20].copy_from_slice(b"end of the disk");
        File::create(&raw).unwrap().write_all(&disk).unwrap();
        for compress in [false, true] {
            let image = fixture.path(&format!("disk-{compress}.qcow2"));
            convert(&raw, &image, compress);
            let mut qcow = Qcow2::open(File::open(&image).unwrap()).unwrap();
            assert_eq!(qcow.virtual_size(), disk.len() as u64);
            for (start, length) in [(0, 512), (4000, 200_000), (65_530, 20), (2 << 20, 4096)] {
                let mut out = vec![0xaa; length];
                qcow.read_at(start, &mut out).unwrap();
                assert_eq!(out, disk[start as usize..][..length], "{compress} {start}");
            }
            let mut beyond = [0u8; 2];
            assert!(qcow.read_at(disk.len() as u64 - 1, &mut beyond).is_err());
        }
    }

    /// A base as installed: the reader opens the qcow2 file itself and reads
    /// a file out of the ext4 filesystem it holds.
    #[test]
    fn the_reader_reads_files_out_of_a_qcow2_base() {
        require_tools!();
        let fixture = Fixture::new();
        let tree = fixture.standard_tree("tree");
        let raw = fixture.ext4("base.raw", &tree, &[]);
        let base = fixture.path("base.qcow2");
        convert(&raw, &base, true);
        let out = fixture.path("out");
        crate::storage::private_dir(&out).unwrap();
        let image = super::super::image::Image::open(&base, &out);
        let answer = image
            .handle(
                7,
                super::super::protocol::DiskRequest::Extract {
                    path: "/etc/passwd".into(),
                    max_len: 1 << 20,
                },
            )
            .unwrap();
        assert!(matches!(
            answer,
            super::super::protocol::DiskAnswer::Extracted(_)
        ));
        assert_eq!(
            std::fs::read(out.join("7")).unwrap(),
            b"root:x:0:0:root:/root:/bin/sh\n"
        );
    }

    #[test]
    fn a_damaged_or_unsupported_header_is_refused() {
        let fixture = Fixture::new();
        let path = fixture.path("bad.qcow2");
        let mut header = vec![0u8; 512];
        header[..4].copy_from_slice(&MAGIC.to_be_bytes());
        header[4..8].copy_from_slice(&3u32.to_be_bytes());
        header[20..24].copy_from_slice(&16u32.to_be_bytes());
        header[24..32].copy_from_slice(&(1u64 << 20).to_be_bytes());
        header[36..40].copy_from_slice(&1u32.to_be_bytes());
        header[40..48].copy_from_slice(&(1u64 << 16).to_be_bytes());
        header[100..104].copy_from_slice(&104u32.to_be_bytes());
        // The L1 table points past the end of the file.
        fs_write(&path, &header);
        assert!(
            Qcow2::open(File::open(&path).unwrap())
                .err()
                .unwrap()
                .contains("outside")
        );
        let mut backing = header.clone();
        backing[8..16].copy_from_slice(&200u64.to_be_bytes());
        fs_write(&path, &backing);
        assert!(Qcow2::open(File::open(&path).unwrap()).is_err());
        let mut encrypted = header.clone();
        encrypted[32..36].copy_from_slice(&1u32.to_be_bytes());
        fs_write(&path, &encrypted);
        assert!(Qcow2::open(File::open(&path).unwrap()).is_err());
        let mut external = header;
        external[72..80].copy_from_slice(&4u64.to_be_bytes());
        fs_write(&path, &external);
        assert!(Qcow2::open(File::open(&path).unwrap()).is_err());
        fs_write(
            &path,
            b"not a disk image at all, just text that is long enough",
        );
        assert!(Qcow2::open(File::open(&path).unwrap()).is_err());
    }

    fn fs_write(path: &Path, data: &[u8]) {
        std::fs::write(path, data).unwrap();
    }
}
