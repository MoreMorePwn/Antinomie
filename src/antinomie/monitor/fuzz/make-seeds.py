#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Write small, benign seed inputs for the fuzz targets into OUT/<target>/.

Everything is built from the repository's own fixtures or generated here;
no malware or behaviour sample is read. Usage: make-seeds.py OUT [REPO_ROOT]
"""
import json
import pathlib
import struct
import sys

out = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else pathlib.Path(__file__).resolve().parents[4]
core = root / "src/antinomie/monitor/crates/monitor-core"


def put(target, name, data):
    d = out / target
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(data if isinstance(data, bytes) else data.encode())


# ANTT guest packets: a complete event with one string field, then health.
def antt_packet(kind, seq, body, obj=0, offset=0, total=2**64 - 1):
    p = bytearray(128)
    p[0:4] = b"ANTT"
    struct.pack_into("<HHHHI", p, 4, 1, 0, 128, 1, 128 + len(body))
    struct.pack_into("<I", p, 20, 1)
    struct.pack_into("<Q", p, 24, 7)
    struct.pack_into("<Q", p, 32, 5)
    struct.pack_into("<Q", p, 40, 9)
    struct.pack_into("<Q", p, 56, seq)
    struct.pack_into("<H", p, 96, 1)
    p[98] = 1
    p[99] = kind
    struct.pack_into("<IQQ", p, 100, obj, offset, total)
    struct.pack_into("<I", p, 120, len(body))
    return bytes(p) + body


def stream(packets):
    s = b""
    for packet in packets:
        s += bytes([0x80]) + struct.pack("<H", len(packet)) + packet
    return s


begin = bytearray(40) + b"patha" + b"char*"
begin[0:3] = bytes([1, 1, 1])
begin[4] = 2
struct.pack_into("<HH", begin, 32, 5, 5)
fend = bytearray(32)
struct.pack_into("<QQQ", fend, 0, 12, 12, 1)
eend = bytearray(32)
struct.pack_into("<QQ", eend, 0, 1, 4)
event = antt_packet(1, 1, bytes(120))
data = [
    event,
    antt_packet(2, 2, bytes(begin), obj=1),
    antt_packet(3, 3, b"/etc/passwd\0", obj=1),
    antt_packet(4, 4, bytes(fend), obj=1),
    antt_packet(5, 5, bytes(eend)),
]
put("antt_assembler", "event", stream(data))
put("antt_assembler", "event-first", stream(data[:1]))
put("antt_assembler", "shaped", bytes([0x40 | 0x20, 0x20, 0x00]) + bytes(32) + bytes([0x41, 0x40, 0x00]) + bytes(40))

# Debug and control replies of the lengths the decoders expect.
for n in (16, 32, 48, 64, 96, 128, 160, 256):
    put("debug_wire", f"zeros{n}", bytes([0]) + bytes(n))
put("debug_wire", "abi", bytes([0]) + struct.pack("<II", 1, 62) + bytes(120))
for n in (8, 16, 32, 48, 96, 160, 256, 512):
    put("control_wire", f"zeros{n}", bytes(n))
put("control_wire", "ids", struct.pack("<QQ", 1, 2))

# Typed fields: one record of each shape the decoders know.
for i in range(20):
    put("typed_fields", f"layout{i:02d}", bytes([i]) + struct.pack("<Q", i) + bytes(range(64)) + bytes(64))

# Network frames: DHCP discover and DNS query over UDP over IPv4 over Ethernet.
def csum(b):
    s = sum(struct.unpack(f">{len(b)//2}H", b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ipv4(proto, payload, src=b"\x0a\x00\x02\x0f", dst=b"\x0a\x00\x02\x02"):
    h = bytearray(struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, src, dst))
    h[10:12] = struct.pack(">H", csum(bytes(h)))
    return bytes(h) + payload


def udp(sport, dport, payload):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def eth(payload, ethertype=0x0800):
    return b"\xff" * 6 + b"\x52\x54\x00\x12\x34\x56" + struct.pack(">H", ethertype) + payload


dns = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
dhcp = bytearray(240) + bytes([53, 1, 1, 255])
dhcp[0:3] = bytes([1, 1, 6])
dhcp[236:240] = b"\x63\x82\x53\x63"
tcp = struct.pack(">HHIIBBHHH", 40000, 80, 1, 0, 0x50, 2, 1024, 0, 0)
arp = struct.pack(">HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, b"\x52\x54\x00\x12\x34\x56", b"\x0a\x00\x02\x0f", bytes(6), b"\x0a\x00\x02\x02")
put("route_frames", "dns", dns)
put("route_frames", "dhcp", bytes(dhcp))
put("route_frames", "eth-udp-dns", eth(ipv4(17, udp(5353, 53, dns))))
put("route_frames", "eth-udp-dhcp", eth(ipv4(17, udp(68, 67, bytes(dhcp)))))
put("route_frames", "eth-tcp", eth(ipv4(6, tcp)))
put("route_frames", "eth-arp", eth(arp, 0x0806))

# PDML: the document the parser's own test reads, and a tiny one.
src = (core / "src/packet_filter/pdml.rs").read_text()
sample = src.split('const SAMPLE: &str = r#"', 1)[1].split('"#;', 1)[0]
put("pdml", "sample", struct.pack("<H", 22) + sample.encode())
put("pdml", "tiny", struct.pack("<H", 4) + b'<pdml><packet><proto name="a" showname="a" pos="0" size="2"/></packet></pdml>')

# Capture: the repository's own pcap fixture, and a truncated header.
pcap = (core / "src/packet_filter/testdata/protocols.pcap").read_bytes()
put("pcap", "protocols", pcap)
put("pcap", "header-only", pcap[:24])

# Partition tables: a protective MBR with one entry, and a GPT with one entry.
mbr = bytearray(512)
mbr[446 + 4] = 0x83
struct.pack_into("<II", mbr, 446 + 8, 2048, 4096)
mbr[510:512] = b"\x55\xaa"
put("partition", "mbr", struct.pack("<Q", 1 << 30) + bytes(mbr))
gpt = bytearray(512 * 40)
gpt[510:512] = b"\x55\xaa"
gpt[450] = 0xEE
gpt[512:520] = b"EFI PART"
struct.pack_into("<IIIIQQQQ", gpt, 520, 0x10000, 92, 0, 0, 1, 2097151, 34, 2097118)
struct.pack_into("<QIII", gpt, 568, 2, 128, 128, 128)
gpt[1024 : 1024 + 16] = bytes(range(1, 17))
struct.pack_into("<QQ", gpt, 1024 + 32, 2048, 4095)
put("partition", "gpt", struct.pack("<Q", 1 << 30) + bytes(gpt))

# Disk: the three base images, no patches; a patch into the superblock area.
for base in range(3):
    put("disk_image", f"base{base}", bytes([base]))
    put("disk_image", f"super{base}", bytes([base]) + struct.pack("<HHB", 1024 + 0x38, 0, 2) + b"\x53\xef")

# Static analysis: the repository's benign ELF fixtures, one per check.
fixtures = sorted((core / "tests/fixtures/ghidra-listing").glob("*.elf"))
for i, path in enumerate(fixtures):
    data = path.read_bytes()
    for choice in (0, 1, 2, 5, 6, 7):
        put("analysis_section", f"{path.stem}-{choice}", bytes([choice]) + data)
upx = bytearray(256)
upx[:4] = b"\x7fELF"
upx[4:6] = bytes([2, 1])
upx[100:104] = b"UPX!"
put("analysis_section", "upx-like", bytes([7 | 0x80]) + bytes(upx))

# Process core: an ELF core header with one PT_NOTE and one PT_LOAD.
hdr = bytearray(64)
hdr[:4] = b"\x7fELF"
hdr[4:7] = bytes([2, 1, 1])
struct.pack_into("<HHIQQQIHHHHHH", hdr, 16, 4, 62, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
ph_note = struct.pack("<IIQQQQQQ", 4, 0, 64 + 112, 0, 0, 0, 0, 4)
ph_load = struct.pack("<IIQQQQQQ", 1, 5, 64 + 112, 0x400000, 0, 16, 16, 0x1000)
put("core_dump", "minimal", bytes(hdr) + ph_note + ph_load + bytes(range(16)))

# Tool and server text.
floss = {"strings": {"decoded_strings": [{"string": "hello", "decoded_at": 4198400, "decoding_routine": 4198144}],
                     "stack_strings": [{"string": "stack", "function": 4198144, "program_counter": 4198200}],
                     "tight_strings": [], "language_strings": []}}
put("tool_text", "floss", bytes([1]) + json.dumps(floss).encode())
put("tool_text", "binwalk", bytes([1]) + b"DECIMAL       HEXADECIMAL     DESCRIPTION\n0             0x0             ELF, 64-bit LSB executable\n4096          0x1000          gzip compressed data\n")
put("tool_text", "capa", bytes([1]) + b'{"parts":["credential-access","brute force"],"id":"T1110"}')
put("tool_text", "threatfox", bytes([1]) + b'{"query_status":"ok","data":[{"id":"1","malware":"win.x","malware_printable":"X","ioc":"1.2.3.4:80","ioc_type":"ip:port","confidence_level":75}]}')
put("tool_text", "release", bytes([1]) + b'{"tag_name":"v0.8.0","html_url":"https://github.com/MoreMorePwn/Antinomie/releases/tag/v0.8.0"}')
put("tool_text", "progress", bytes([1]) + b"    (12.34/100%)")

# The daemon's socket framing: request lines as a client writes them.
put("socket_frames", "requests", b'{"frame":"engine.hello"}\n{"id":1,"op":"health"}\n{"id":2,"op":"job.get","params":{"job_id":"j_01ARZ3NDEKTSV4RRFFQ69G5FAV"}}\n{"id":2,"op":"cancel"}\n')
put("socket_frames", "upload", b'{"id":3,"op":"upload.put","params":{"upload_id":"u_01ARZ3NDEKTSV4RRFFQ69G5FAV","offset":0,"data":"IyEvYmluL3NoCmVjaG8gaGkK"}}\n')
put("socket_frames", "subscribe", b'{"id":4,"op":"events.subscribe","params":{"since_gseq":17,"types":["job.state"]}}\n')

# JobSpec JSON: a minimal spec, a full one, and one with an unknown member.
put("job_spec", "minimal", b'{"sample":{"sha256":"' + b"ab" * 32 + b'"}}')
put("job_spec", "full", json.dumps({"sample": {"upload_id": "u_01ARZ3NDEKTSV4RRFFQ69G5FAV"}, "name": "a.sh", "policy": "default", "priority": 7,
    "labels": {"case": "42", "src.x": "y"}, "idempotency_key": "k-1",
    "overrides": {"timeout_s": 60, "args": ["-v"], "env": ["A=1"], "route": "inet_sim", "memory_dump": True}}).encode())
put("job_spec", "unknown", b'{"sample":{"path":"/tmp/x"},"evil":1}')

# Policy and service TOML: the shipped default policy text and a small service.toml.
cfg = (root / "src/antinomie/monitor/crates/service/src/config/mod.rs").read_text()
if 'DEFAULT_POLICY' in cfg and 'r#"' in cfg:
    put("config_toml", "default-policy", cfg.split('r#"', 1)[1].split('"#', 1)[0])
put("config_toml", "policy", '[vm]\nlane_vm = "auto-1"\n[sample]\naccept_types = ["sh", "elf"]\n[network]\nroute = "drop"\nallowed_routes = ["drop", "inet_sim"]\n[[verdict.rule]]\nwhen = "highest_tier == 'high' and counts.processes > 2"\nlabel = "suspicious"\n')
put("config_toml", "service", '[[watch]]\npath = "/srv/drop"\npolicy = "default"\nrecursive = false\n')

# Watch-folder names, NUL separated.
put("watch_names", "plain", b"sample.exe\0report (1).sh\0.hidden\0upload.part\0")
put("watch_names", "hostile", b"a\nb.sh\0\x1b]0;x\x07\0$(id)\0..\0-rf\0bad-\xff.sh\0" + b"n" * 200)

# Label expressions.
put("label_expr", "simple", b"highest_tier == 'high' and counts.findings >= 1")
put("label_expr", "nested", b'(families in ["x", "y"] or techniques == "T1059") and counts.files_changed > 10')
put("label_expr", "bad", b"((counts.processes and) or ")
