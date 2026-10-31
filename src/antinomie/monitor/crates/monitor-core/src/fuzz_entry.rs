// SPDX-License-Identifier: GPL-3.0-only
//! Entry points for the cargo-fuzz targets in `monitor/fuzz` (feature
//! `fuzzing`; not part of a normal build). Each function takes the bytes a
//! target was handed and drives one parser the way the application does, so a
//! panic, hang or runaway allocation in it is a finding. Results are dropped:
//! a parser answering "invalid" is the expected outcome for most inputs.
//!
//! | Function | Parser reached | Who controls the bytes |
//! |---|---|---|
//! | [`antt`] | `parser::parse_packet`, `Assembler::ingest` | guest kernel records |
//! | [`debug_wire`] | `debug::wire::parse_*` | guest debug replies |
//! | [`control_wire`] | `control`, `core_limits`, `kernel_resources`, `guest_resources` replies | guest replies |
//! | [`typed_fields`] | `typed_fields::decode` | guest memory captured by a call |
//! | [`route_frames`] | gateway frame, DNS and DHCP parsers | guest network traffic |
//! | [`pdml`] | `packet_filter` PDML tree | TShark output over guest packets |
//! | [`pcap`] | `network::pcap` readers | QEMU capture of guest traffic |
//! | [`partition`] | `disks::partition::parse` | guest disk head |
//! | [`disk_image`] | `Qcow2`, ext4 reader requests | guest disk |
//! | [`core_dump`] | `core_dump::CoreDump` | guest process core |
//! | [`analysis_section`] | the in-process static checks | the sample |
//! | [`tool_text`] | FLOSS/binwalk/capa/catalog/feed replies | tool output, servers |
use std::path::PathBuf;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::var_os("ANTINOMIE_FUZZ_SCRATCH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/dev/shm/antinomie-fuzz"))
        .join(format!("{}-{}", name, std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// A byte reader for inputs that carry a few choices before the payload.
struct Take<'a>(&'a [u8]);
impl<'a> Take<'a> {
    fn byte(&mut self) -> u8 {
        let Some((first, rest)) = self.0.split_first() else {
            return 0;
        };
        self.0 = rest;
        *first
    }
    fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.byte(), self.byte()])
    }
    fn u64(&mut self) -> u64 {
        let mut word = [0u8; 8];
        for slot in &mut word {
            *slot = self.byte();
        }
        u64::from_le_bytes(word)
    }
    fn bytes(&mut self, len: usize) -> &'a [u8] {
        let len = len.min(self.0.len());
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        head
    }
    fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.0)
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Make `packet` a well-formed ANTT packet of a chosen shape, so the fuzzer
/// reaches the assembler instead of stopping at the length checks.
fn antt_shape(packet: &mut Vec<u8>, selector: u8) {
    let minor = usize::from(selector >> 1) % 3;
    let header = [128usize, 136, 144][minor];
    if packet.len() < header {
        packet.resize(header, 0);
    }
    if selector & 0x40 != 0 {
        // A record of type 1 with a fragment whose body has its true layout.
        packet[10..12].copy_from_slice(&1u16.to_le_bytes());
        packet[98] = 1 + packet[98] % 3;
        let fragment = 1 + packet[99] % 5;
        packet[99] = fragment;
        if fragment == 1 || fragment == 5 {
            packet[100..104].copy_from_slice(&0u32.to_le_bytes());
        } else if packet[100..104] == [0; 4] {
            packet[100] = 1;
        }
        if fragment != 3 {
            packet[104..112].copy_from_slice(&0u64.to_le_bytes());
        }
        let mut body = packet.split_off(header);
        match fragment {
            1 => {
                body.resize(120, 0);
                body[52..56].fill(0);
                body[116..120].fill(0);
                body[48] %= 7;
                body[49] %= 5;
            }
            2 => {
                body.resize(40, 0);
                let key = usize::from(body[32] % 12);
                let layout = usize::from(body[34] % 12);
                body[32..34].copy_from_slice(&(key as u16).to_le_bytes());
                body[34..36].copy_from_slice(&(layout as u16).to_le_bytes());
                body[6..8].fill(0);
                body[0] %= 6;
                body[1] = 1 + body[1] % 3;
                let (first, second) = (1 + u16::from(body[2]) % 5, 1 + u16::from(body[4]) % 5);
                body[2..4].copy_from_slice(&first.to_le_bytes());
                body[4..6].copy_from_slice(&second.to_le_bytes());
                body.extend((0..key + layout).map(|at| b'a' + (at % 26) as u8));
            }
            3 => {
                if selector & 0x20 != 0 {
                    packet[112..120].copy_from_slice(&u64::MAX.to_le_bytes());
                }
            }
            _ => body.resize(32, 0),
        }
        packet.extend(body);
    }
    let len = packet.len();
    packet[..4].copy_from_slice(b"ANTT");
    packet[4..6].copy_from_slice(&1u16.to_le_bytes());
    packet[6..8].copy_from_slice(&(minor as u16).to_le_bytes());
    packet[8..10].copy_from_slice(&(header as u16).to_le_bytes());
    packet[12..16].copy_from_slice(&(len as u32).to_le_bytes());
    packet[120..124].copy_from_slice(&((len - header) as u32).to_le_bytes());
    packet[124..128].fill(0);
}

/// A stream of guest packets: each is `[selector][len u16][bytes]`; a selector
/// with bit 7 set sends the bytes as they are.
pub fn antt(data: &[u8]) {
    let mut input = Take(data);
    let mut packets: Vec<Vec<u8>> = Vec::new();
    while !input.is_empty() && packets.len() < 64 {
        let selector = input.byte();
        let len = usize::from(input.u16()) % 1200;
        let mut packet = input.bytes(len).to_vec();
        if selector & 0x80 == 0 {
            antt_shape(&mut packet, selector);
        }
        packets.push(packet);
    }
    for packet in &packets {
        let _ = crate::parser::parse_packet(packet);
    }
    let directory = scratch("antt");
    let objects = directory.join("objects");
    if let Ok(mut assembler) = crate::parser::Assembler::new(objects, 256 * 1024) {
        assembler.set_event_table(16);
        for packet in &packets {
            let _ = assembler.ingest(packet);
        }
        assembler.flush();
        for event in assembler.history() {
            for field in &event.fields {
                let _ = crate::recording::read_captured_range(&directory, field, 0, 64);
                let _ = crate::typed_fields::decode(None, field);
            }
        }
        let _ = assembler.recent(8);
        assembler.release_tables();
    }
    let _ = std::fs::remove_dir_all(&directory);
}

/// Every guest debug reply decoder over the same bytes.
pub fn debug_wire(data: &[u8]) {
    use crate::debug::wire;
    let mut input = Take(data);
    let choice = input.byte();
    let reply = input.rest();
    let _ = wire::parse_caps(reply, choice & 1 != 0);
    let _ = wire::parse_attach(reply);
    let _ = wire::parse_status(reply);
    let _ = wire::parse_cont(reply);
    let _ = wire::parse_threads(reply);
    let _ = wire::parse_regs_many(reply, &[1, 2, 0x202][..usize::from(choice >> 1) % 4]);
    let _ = wire::parse_regs(reply, u32::from(choice >> 3));
    let _ = wire::parse_mem_read(reply, usize::from(choice) * 64);
    let _ = wire::parse_mem_write(reply, usize::from(choice) * 64);
    let _ = wire::parse_auxv(reply);
    let _ = wire::parse_config(reply);
    let _ = wire::parse_events(reply);
    let _ = wire::parse_thread_ctl(reply);
    let _ = wire::parse_sessions(reply);
    let _ = wire::parse_bp_list(reply);
}

/// The fixed-layout replies the control channel decodes.
pub fn control_wire(data: &[u8]) {
    let _ = crate::control::capture_started(data);
    let _ = crate::control::capture_status(data, 1);
    let _ = crate::control::tracer_caps(data);
    let _ = crate::control::acquisition(data);
    let _ = crate::control::acquisition_bounded(data, 1 << 20);
    let _ = crate::control::info(data);
    let _ = crate::control::arch_caps(data);
    let _ = crate::core_limits::CoreLimits::parse(data);
    let _ = crate::guest_resources::terminal_data(data);
    crate::kernel_resources::fuzz_parse(data);
}

/// Captured guest memory handed to the typed-field decoders, under every
/// layout name they know.
pub fn typed_fields(data: &[u8]) {
    const LAYOUTS: [&str; 20] = [
        "sigset_t",
        "sigset_argpack",
        "siginfo_t",
        "siginfo_t[]",
        "sigevent",
        "stack_t",
        "bpf_attr",
        "cap_data[]",
        "uid_t",
        "gid_t[]",
        "u32",
        "pid_t",
        "linux_dirent[]",
        "linux_dirent64[]",
        "file_handle",
        "io_uring_params",
        "msgbuf",
        "ipt_replace",
        "xt_counters_info",
        "user_desc",
    ];
    let mut input = Take(data);
    let choice = usize::from(input.byte());
    let args = [input.u64(), 0, 0, 0, 0, 0];
    let preview = input.rest().to_vec();
    let layouts = [
        LAYOUTS[choice % LAYOUTS.len()],
        "desc_struct[]",
        "xt_counters_info",
    ];
    for layout in layouts {
        let field = crate::api::FieldSummary {
            arg: Some(0),
            object_id: 1,
            key: "attr".into(),
            layout: layout.into(),
            logical_len: Some(preview.len() as u64 + (choice as u64 & 3)),
            captured_len: preview.len() as u64,
            status: None,
            capture_error: 0,
            complete: choice & 4 == 0,
            preview: preview.clone(),
            raw_path: None,
            ranges: vec![(0, preview.len() as u64)],
            recapture: None,
            encoding: None,
        };
        for name in ["bpf", "capget", "capset", "rt_sigaction"] {
            let call = crate::typed_fields::Call {
                name,
                args: Some(args),
            };
            let _ = crate::typed_fields::decode(Some(&call), &field);
        }
        let _ = crate::typed_fields::decode(None, &field);
    }
}

/// The gateway's view of what a guest sends on its virtual link.
pub fn route_frames(data: &[u8]) {
    use crate::route::fuzz as route;
    let _ = route::dns_query(data);
    let lease = route::Lease {
        guest: [10, 0, 2, 15].into(),
        gateway: [10, 0, 2, 2].into(),
        dns: [10, 0, 2, 3].into(),
        mask: [255, 255, 255, 0].into(),
        broadcast: [10, 0, 2, 255].into(),
    };
    let _ = route::dhcp_reply(data, &lease);
    if let Some(eth) = route::parse_eth(data) {
        let _ = route::parse_arp(eth.payload);
        if let Some(ip) = route::parse_ipv4(eth.payload) {
            let _ = route::parse_tcp(ip.payload);
            let _ = route::parse_udp(ip.payload);
        }
    }
    let _ = route::parse_arp(data);
    if let Some(ip) = route::parse_ipv4(data) {
        let _ = route::parse_tcp(ip.payload);
        if let Some(udp) = route::parse_udp(ip.payload) {
            let _ = route::dns_query(udp.payload);
            let _ = route::dhcp_reply(udp.payload, &lease);
        }
    }
    let _ = route::parse_tcp(data);
    let _ = route::parse_udp(data);
}

/// TShark's PDML for one frame.
pub fn pdml(data: &[u8]) {
    let mut input = Take(data);
    let frame_len = usize::from(input.u16());
    let _ = crate::packet_filter::fuzz_pdml(input.rest(), frame_len);
}

/// A pcap file as QEMU writes it, read through the page and frame readers.
pub fn pcap(data: &[u8]) {
    let directory = scratch("pcap");
    let path = directory.join("capture.pcap");
    if std::fs::write(&path, data).is_ok() {
        let _ = crate::network::count_packets(&path);
        let mut offset = 0;
        let mut number = 0;
        for _ in 0..4 {
            let Ok(page) = crate::network::read_page(&path, offset, number, 64) else {
                break;
            };
            for packet in page.packets.iter().take(4) {
                let _ = crate::network::frame(&path, packet.offset);
            }
            if page.next_offset == offset {
                break;
            }
            (offset, number) = (page.next_offset, page.next_number);
        }
        let _ = crate::network::frame(&path, 24);
    }
    let _ = std::fs::remove_dir_all(&directory);
}

/// The first sectors of a guest disk (MBR or GPT), after a disk size.
pub fn partition(data: &[u8]) {
    let mut input = Take(data);
    let size = input.u64();
    let _ = crate::disks::partition::parse(input.rest(), size);
    let _ = crate::disks::partition::parse(data, 1 << 30);
}

/// A guest disk: the base images are made by `fuzz/seeds.sh` (a small ext4
/// filesystem, raw and as qcow2); the input is `[base][patches...]` where a
/// patch is `[offset u32][len u8][bytes]`. The disk is then read through the
/// reader's requests, the way the sandboxed reader serves the disk tabs.
pub fn disk_image(data: &[u8]) {
    use crate::disks::reader::{DiskAnswer, DiskRequest, FindMode, FindQuery, image::Image};
    const BASES: [&str; 3] = ["ext4.raw", "ext4.qcow2", "ext4.compressed.qcow2"];
    thread_local! {
        static BASE: std::cell::RefCell<Vec<Option<Vec<u8>>>> = const { std::cell::RefCell::new(Vec::new()) };
    }
    let mut input = Take(data);
    let which = usize::from(input.byte()) % BASES.len();
    let mut disk = BASE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.is_empty() {
            let root = std::env::var_os("ANTINOMIE_FUZZ_DISKS").map(PathBuf::from);
            let root = root.unwrap_or_else(|| PathBuf::from("/dev/shm/antinomie-fuzz-bases"));
            *cache = BASES
                .iter()
                .map(|name| std::fs::read(root.join(name)).ok())
                .collect();
        }
        cache[which].clone()
    });
    let Some(disk) = disk.as_mut() else {
        panic!("fuzz base images are missing; run fuzz/seeds.sh");
    };
    while !input.is_empty() {
        let offset = (u32::from(input.u16()) | u32::from(input.u16()) << 16) as usize;
        let len = usize::from(input.byte());
        let patch = input.bytes(len);
        let start = offset % disk.len();
        if let Some(window) = disk.get_mut(start..) {
            let take = patch.len().min(window.len());
            window[..take].copy_from_slice(&patch[..take]);
        }
    }
    let directory = scratch("disk");
    let image_path = directory.join("disk.img");
    let out = directory.join("out");
    let _ = std::fs::create_dir_all(&out);
    if std::fs::write(&image_path, &*disk).is_ok() {
        let image = Image::open(&image_path, &out);
        let mut paths: Vec<String> = vec![
            "/".into(),
            "/etc".into(),
            "/etc/passwd".into(),
            "/bin/busybox".into(),
        ];
        if let Ok(DiskAnswer::Listed(root)) = image.handle(
            1,
            DiskRequest::List {
                path: "/".into(),
                offset: 0,
            },
        ) {
            for entry in root.entries.iter().take(16) {
                let path = format!("/{}", entry.name);
                if let Ok(DiskAnswer::Listed(inner)) = image.handle(
                    2,
                    DiskRequest::List {
                        path: path.clone(),
                        offset: 0,
                    },
                ) {
                    paths.extend(
                        inner
                            .entries
                            .iter()
                            .take(8)
                            .map(|e| format!("{path}/{}", e.name)),
                    );
                }
                paths.push(path);
            }
        }
        let _ = image.handle(3, DiskRequest::Probe);
        for (id, path) in paths.iter().enumerate().take(48) {
            let id = 10 + id as u64 * 4;
            let _ = image.handle(
                id,
                DiskRequest::List {
                    path: path.clone(),
                    offset: 0,
                },
            );
            let _ = image.handle(
                id + 1,
                DiskRequest::Info {
                    path: path.clone(),
                    hash_cap: 1 << 20,
                },
            );
            let _ = image.handle(
                id + 2,
                DiskRequest::ReadRange {
                    path: path.clone(),
                    offset: 1,
                    len: 8192,
                },
            );
            let _ = image.handle(
                id + 3,
                DiskRequest::Extract {
                    path: path.clone(),
                    max_len: 1 << 20,
                },
            );
            let _ = image.handle(
                id + 3,
                DiskRequest::Locate {
                    path: path.clone(),
                    ino: Some(12),
                    generation: None,
                },
            );
        }
        for (pattern, mode) in [
            ("passwd", FindMode::Name),
            ("*.txt", FindMode::Glob),
            ("milk", FindMode::Content),
        ] {
            let query = FindQuery {
                pattern: pattern.into(),
                mode,
            };
            let _ = image.handle(900, DiskRequest::Find { query });
        }
        let _ = image.handle(901, DiskRequest::Diff);
        let other = Image::open_with(&image_path, Some(&image_path), &out);
        let _ = other.handle(902, DiskRequest::Diff);
    }
    let _ = std::fs::remove_dir_all(&directory);
}

/// An ELF process core as the host receives it.
pub fn core_dump(data: &[u8]) {
    let directory = scratch("core");
    let path = directory.join("core");
    if std::fs::write(&path, data).is_ok()
        && let Ok(core) = crate::core_dump::CoreDump::open(&path)
    {
        for mapping in core.mappings.iter().take(8) {
            let _ = core.read_virtual(mapping.start, 4096);
            let _ = core.disassemble(mapping.start, 256);
        }
        for file in core.files.iter().take(4) {
            let _ = crate::core_dump::binary_functions(&path, file);
        }
        let _ = core.read_virtual(u64::MAX - 8, 64);
    }
    let _ = crate::analysis::sparse_core_plan(data);
    let _ = std::fs::remove_dir_all(&directory);
}

fn kind_of(choice: u8) -> crate::analysis::AnalysisKind {
    use crate::analysis::AnalysisKind as K;
    const KINDS: [K; 8] = [
        K::Metadata,
        K::Structures,
        K::Strings,
        K::Entropy,
        K::Hardening,
        K::Identification,
        K::Disassembly,
        K::Unpacking,
    ];
    KINDS[usize::from(choice) % KINDS.len()]
}

/// One of the worker's in-process checks over a sample.
pub fn analysis_section(data: &[u8]) {
    let mut input = Take(data);
    let choice = input.byte();
    let specimen = input.rest();
    let directory = scratch("analysis");
    let kind = kind_of(choice);
    crate::analysis::fuzz::section(kind, specimen, &directory.join("listings"));
    if choice & 0x80 != 0 {
        let mut section =
            crate::analysis::AnalysisSection::new(crate::analysis::AnalysisKind::Unpacking);
        crate::analysis::fuzz::unpack(&mut section, specimen, &directory);
    }
    let _ = crate::analysis::decode_window(
        0x1000,
        specimen,
        0x1000 + u64::from(choice) * 3,
        usize::from(choice >> 4),
        usize::from(choice & 15),
    );
    let _ = crate::samples::detect_type(specimen);
    let _ = std::fs::remove_dir_all(&directory);
}

/// Text or JSON that tools and servers return.
pub fn tool_text(data: &[u8]) {
    let mut input = Take(data);
    let choice = input.byte();
    let body = input.rest();
    let text = String::from_utf8_lossy(body);
    crate::analysis::fuzz::floss(&text, u64::from(choice) << 12);
    crate::analysis::fuzz::binwalk(&text, u64::from(choice) << 12);
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
        crate::analysis::fuzz::capa(&value);
    }
    let _ = crate::ioc::online::parse_threatfox(&text);
    let _ = crate::ioc::online::parse_urlhaus(&text);
    let _ = crate::samples::parse_reply(body);
    let _ = crate::update_check::parse_release(&text);
    let _ = crate::distribution::parse_catalog(body);
    let _ = crate::toolchain::parse_pins(&text);
    let _ = crate::disks::job::parse_progress(&text);
}
