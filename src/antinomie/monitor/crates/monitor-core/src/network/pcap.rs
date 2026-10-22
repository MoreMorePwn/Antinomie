// SPDX-License-Identifier: GPL-3.0-only
//! Reading pcap and pcapng files in bounded pages.
use super::*;

/// Packets and bytes of a pcap file, from its record headers. A record still
/// being written is not counted.
pub fn count_packets(path: &Path) -> Result<(u64, u64), String> {
    let mut file = BufReader::new(open_capture(path)?);
    let size = file.get_ref().metadata().map_err(|e| e.to_string())?.len();
    let mut header = [0u8; 24];
    if file.read_exact(&mut header).is_err() {
        return Ok((0, size));
    }
    let little = header_endian(&header)?;
    let (mut packets, mut position) = (0u64, 24u64);
    let mut record = [0u8; 16];
    while file.read_exact(&mut record).is_ok() {
        let bytes: [u8; 4] = record[8..12].try_into().expect("4 bytes");
        let captured = if little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        };
        if captured > MAX_FRAME || position + 16 + u64::from(captured) > size {
            break;
        }
        file.seek_relative(i64::from(captured))
            .map_err(|e| e.to_string())?;
        position += 16 + u64::from(captured);
        packets += 1;
    }
    Ok((packets, size))
}

fn open_capture(path: &Path) -> Result<File, String> {
    let path = std::fs::canonicalize(path).map_err(|error| error.to_string())?;
    crate::archive_io::open_regular(path.parent().unwrap_or(Path::new(".")), &path)
        .map_err(|error| format!("network capture file: {error}"))
}

/// The pcap global header: 24 bytes, microsecond timestamps, little or big
/// endian, Ethernet link type.
fn header_endian(header: &[u8; 24]) -> Result<bool, String> {
    let little = match header[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] => false,
        _ => return Err("not a pcap file (or nanosecond pcap)".into()),
    };
    let read = |at: usize| {
        let bytes: [u8; 4] = header[at..at + 4].try_into().expect("4 bytes");
        if little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    };
    if read(20) != 1 {
        return Err(format!("pcap link type {} is not Ethernet", read(20)));
    }
    Ok(little)
}

/// Read up to `limit` packets starting at `offset` (0 or a previous
/// `next_offset`). A record still being written ends the page.
pub fn read_page(
    path: &Path,
    offset: u64,
    number: u64,
    limit: usize,
) -> Result<NetworkPage, String> {
    let mut file = BufReader::new(open_capture(path)?);
    let size = file.get_ref().metadata().map_err(|e| e.to_string())?.len();
    let mut header = [0u8; 24];
    if let Err(error) = file.read_exact(&mut header) {
        // QEMU writes the header when it opens the file; until then it is empty.
        return if error.kind() == std::io::ErrorKind::UnexpectedEof {
            Ok(NetworkPage::default())
        } else {
            Err(error.to_string())
        };
    }
    let little = header_endian(&header)?;
    let read_u32 = |bytes: &[u8]| {
        let bytes: [u8; 4] = bytes.try_into().expect("4 bytes");
        if little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    };
    let mut position = offset.max(24);
    file.seek(SeekFrom::Start(position))
        .map_err(|e| e.to_string())?;
    let mut page = NetworkPage {
        packets: Vec::new(),
        next_offset: position,
        next_number: number,
    };
    let mut record = [0u8; 16];
    while page.packets.len() < limit {
        if file.read_exact(&mut record).is_err() {
            break;
        }
        let captured = read_u32(&record[8..12]);
        let length = read_u32(&record[12..16]);
        if captured > MAX_FRAME {
            return Err(format!("pcap record at {position} is {captured} bytes"));
        }
        // The frame bytes are not needed for the raw list: skip them, and
        // stop at a record still being written.
        if position + 16 + u64::from(captured) > size {
            break;
        }
        if file.seek_relative(i64::from(captured)).is_err() {
            break;
        }
        page.next_number += 1;
        page.packets.push(NetworkPacket {
            number: page.next_number,
            offset: position,
            time_us: u64::from(read_u32(&record[..4])) * 1_000_000
                + u64::from(read_u32(&record[4..8])),
            length,
            captured,
            info: format!("Raw frame, {captured} bytes"),
            ..NetworkPacket::default()
        });
        position += 16 + u64::from(captured);
        page.next_offset = position;
    }
    Ok(page)
}

/// The captured bytes of the frame whose record starts at `offset`.
pub fn frame(path: &Path, offset: u64) -> Result<Vec<u8>, String> {
    let mut file = open_capture(path)?;
    let mut header = [0u8; 24];
    file.read_exact(&mut header).map_err(|e| e.to_string())?;
    let little = header_endian(&header)?;
    if offset < 24 {
        return Err("offset is inside the pcap header".into());
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| e.to_string())?;
    let mut record = [0u8; 16];
    file.read_exact(&mut record).map_err(|e| e.to_string())?;
    let bytes: [u8; 4] = record[8..12].try_into().expect("4 bytes");
    let captured = if little {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    };
    if captured > MAX_FRAME {
        return Err("pcap record too large".into());
    }
    let mut frame = vec![0; captured as usize];
    file.read_exact(&mut frame).map_err(|e| e.to_string())?;
    Ok(frame)
}
