// SPDX-License-Identifier: GPL-3.0-only
//! Country and organization for the destinations TShark's resolver missed.
//!
//! TShark asks a helper process (`mmdbresolve`) for each address and does not
//! wait for the answer, so the first packets of a capture (all of them, in a
//! capture of a few packets) are read before the helper has replied. The
//! destinations still without an answer are looked up in a throw-away capture
//! that repeats each of them many times, long enough for the helper to answer
//! while TShark reads it. It runs in the same sandbox with the same databases
//! and only fills what is empty.
use super::{network::Inventory, pcap_scan::organization_with_asn};
use std::{
    collections::HashMap,
    io::Write,
    net::IpAddr,
    sync::{atomic::AtomicBool, Arc},
};

/// Captures at most this large get the extra look-up; a larger capture gives
/// the helper time on its own.
pub const SMALL_CAPTURE: u64 = 4 << 20;
/// Destinations looked up at most, and packets in the throw-away capture.
pub const MAX_ADDRESSES: usize = 64;
pub const PACKETS: usize = 20_000;
/// Ethernet frames (LINKTYPE_ETHERNET): the packet filter reads nothing else.
pub const LINKTYPE_ETHERNET: u32 = 1;
pub const ETHERNET: [u8; 12] = [0; 12];

pub fn packet(ip: IpAddr) -> Vec<u8> {
    let udp = [0u8, 53, 0, 53, 0, 8, 0, 0];
    match ip {
        IpAddr::V4(address) => {
            let mut frame = ETHERNET.to_vec();
            frame.extend([8, 0, 0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1]);
            frame.extend(address.octets());
            frame.extend(udp);
            frame
        }
        IpAddr::V6(address) => {
            let mut frame = ETHERNET.to_vec();
            frame.extend([0x86, 0xdd, 0x60, 0, 0, 0, 0, 8, 17, 64]);
            frame.extend([0u8; 15]);
            frame.push(1);
            frame.extend(address.octets());
            frame.extend(udp);
            frame
        }
    }
}

pub fn write_capture(path: &std::path::Path, addresses: &[IpAddr]) -> std::io::Result<()> {
    let mut out = std::io::BufWriter::new(std::fs::File::create(path)?);
    out.write_all(&0xa1b2_c3d4u32.to_le_bytes())?;
    out.write_all(&[2, 0, 4, 0])?;
    out.write_all(&[0; 8])?;
    out.write_all(&65535u32.to_le_bytes())?;
    out.write_all(&LINKTYPE_ETHERNET.to_le_bytes())?;
    let frames: Vec<Vec<u8>> = addresses.iter().map(|ip| packet(*ip)).collect();
    for number in 0..PACKETS {
        let frame = &frames[number % frames.len()];
        out.write_all(&1_700_000_000u32.to_le_bytes())?;
        out.write_all(&(number as u32).to_le_bytes())?;
        out.write_all(&(frame.len() as u32).to_le_bytes())?;
        out.write_all(&(frame.len() as u32).to_le_bytes())?;
        out.write_all(frame)?;
    }
    out.flush()
}

/// Fill the country and organization of the public destinations of
/// `inventory` that still have none.
pub fn fill(inventory: &mut Inventory, cancel: &Arc<AtomicBool>) -> Result<(), String> {
    if !antinomie_monitor_core::geoip::configured() {
        return Ok(());
    }
    let addresses: Vec<IpAddr> = inventory
        .incomplete()
        .iter()
        .filter_map(|ip| ip.parse().ok())
        .take(MAX_ADDRESSES)
        .collect();
    if addresses.is_empty() {
        return Ok(());
    }
    let directory = std::env::temp_dir().join(format!(
        "antinomie-geoip-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    ));
    std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let result = look_up(&directory, &addresses, cancel);
    let _ = std::fs::remove_dir_all(&directory);
    for (ip, (country, organization)) in result? {
        inventory.fill_missing(&ip, &country, &organization);
    }
    Ok(())
}

pub fn look_up(
    directory: &std::path::Path,
    addresses: &[IpAddr],
    cancel: &Arc<AtomicBool>,
) -> Result<HashMap<String, (String, String)>, String> {
    let path = directory.join("lookup.pcap");
    write_capture(&path, addresses).map_err(|error| error.to_string())?;
    let identity = antinomie_monitor_core::packet_filter::CaptureIdentity::read(&path)?;
    let found = Arc::new(std::sync::Mutex::new(
        HashMap::<String, (String, String)>::new(),
    ));
    let sink = Arc::clone(&found);
    antinomie_monitor_core::packet_filter::stream_fields(
        &identity,
        "",
        &[
            "ip.dst",
            "ipv6.dst",
            "ip.geoip.dst_country",
            "ipv6.geoip.dst_country",
            "ip.geoip.dst_org",
            "ipv6.geoip.dst_org",
            "ip.geoip.dst_asnum",
            "ipv6.geoip.dst_asnum",
        ],
        false,
        Arc::clone(cancel),
        move |line| {
            let fields = super::pcap_scan::tsv_fields(line)?;
            let [ip4, ip6, country4, country6, org4, org6, asn4, asn6] = fields.as_slice() else {
                return Ok(());
            };
            let pick = |a: &String, b: &String| if a.is_empty() { b.clone() } else { a.clone() };
            let ip = pick(ip4, ip6);
            let country = pick(country4, country6);
            if ip.is_empty() || country.is_empty() {
                return Ok(());
            }
            let organization = organization_with_asn(&pick(org4, org6), &pick(asn4, asn6));
            if let Ok(mut found) = sink.lock() {
                found.insert(ip, (country, organization));
            }
            Ok(())
        },
    )?;
    let found = found.lock().map_err(|_| "look-up lock poisoned")?;
    Ok(found.clone())
}
