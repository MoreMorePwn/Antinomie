// SPDX-License-Identifier: GPL-3.0-only
//! The five built-in presets (the presets specification, "Built-in presets").
//! They ship with the service, are always offered and are read-only: a file
//! in `presets/` may not take one of their names; copy one under another name
//! to change it. 0.9.0's `default` policy is Standard.
//!
//! Deep scans every 2 minutes from 0.9.1; `detection.scan_every_min` is a key
//! 0.9.0 reserves at 0, so Deep ships with 0 here.

/// Standard: every key at its default, written out with the app's labels.
/// `packaging/presets/standard.toml.example` is this text.
pub const STANDARD: &str = r#"title = "Standard"
description = "Five minutes, nothing leaves the lab, HTML and JSON report"
offered_to = ["analyst", "lead", "admin"]      # who sees it on Submit (a list, not a lock)
required_stages = ["analyse"]                  # stages whose failure fails the run (Auto only)

[accepts]
types = ["elf", "sh"]
arch = ["x86_64"]
max_sample_mib = 64                            # at most the node ceiling (256)

[duplicates]
on_duplicate = "run"                           # run | reuse | reject
reuse_across_presets = false

[program]                                      # Run program: Program, Arguments, Session
source = "upload"                              # Source: upload (guest_path arrives with 0.9.1)
executable = ""                                # Executable, with source = "guest_path"
guest_path = "/tmp/{name}"                     # Upload > Guest path ({name}: the sample's file name)
arguments = []                                 # Arguments, one per entry
working_directory = "/tmp"                     # Working directory
environment = ["PATH=/bin:/sbin:/usr/bin:/usr/sbin", "TERM=xterm"]
user = "normal"                                # User: normal | root | nobody | custom (root needs run.as_root)
uid = 1000                                     # UID, GID with user = "custom" (below 1000 needs run.as_root)
gid = 1000
run_in = "app_terminal"                        # Run in: app_terminal (the desktop values arrive with 0.9.1)
run_time_s = 300                               # Run time, 5 to 1800 seconds
preload = []                                   # [{ sample = "<sha256>", how = "ld_preload" }] (0.9.1)
extra_files = []                               # [{ sample = "<sha256>", guest_path = "/tmp/lib.so" }] (0.9.1)

[record]
scope = "program"                              # program | whole_vm (Capture all, 0.9.1)
screenshot_every_s = 0                         # Screenshot every N s (1 to 999), 0 = off

[network]
capture = true                                 # Capture network
route = "drop"                                 # Route: drop | inet_sim (live routes need route.* and node setup)
private_addresses = false                      # Allow private network addresses (route.lan, 0.9.1)
abuse_filter = true                            # false needs route.unfiltered (0.9.1)

[dumps]
memory_dump_on_exit = false                    # needs evidence.memory_dump
core_dump_on_exit = false                      # needs evidence.core_dump
core_budget_mib = 256                          # Budget, 64 to 1024
core_deadline_ms = 5000                        # Deadline
dump_when_suspicious = false                   # Dump when suspicious activity is seen
minimum_tier = "high"                          # low | medium | high
trigger_memory_dump = false                    # Memory dump (needs evidence.memory_dump)
trigger_core = true                            # Core of the process that triggered it (needs evidence.core_dump)
read_non_resident_pages = false
max_dumps = 1                                  # At most N dump(s) per run, 1..8
dumps_apart_s = 30                             # at least N s apart, 0..3600
disk_dump = false                              # Dump disk (needs evidence.disk_dump, 0.9.1)

[vm]
lane_group = "x86_64"                          # a lane group from node setup ([lanes] group)
keep_on_failure = false                        # Keep the VM after a failure (needs run.keep_vm, 0.9.1)
allow_control = true                           # Allow taking control (people with interactive.control)

[static_analysis]
enabled = true                                 # Static analysis
triage_checks = ["metadata", "structures", "strings", "regex", "entropy", "hardening",
                 "rules", "identification", "capabilities", "embedded", "unpacking"]
deep_checks = []                               # disassembly | decompilation | floss
time_limit_per_tool_min = 0                    # Time limit per tool: 0 = each tool's own, up to 480
ghidra_disassembly = false                     # Ghidra for Disassembly
required_checks = []
rebuilt_file_mib = 16                          # Rebuilt file bytes (Triage), per file (0.9.1)
rebuilt_run_mib = 256                          #   and per run

[static_analysis.limits]                       # Size limits (each within the engine's range)
rows_per_check = 2048
listing_mib = 64
ghidra_disassembly_mib = 128
text_per_value_bytes = 4096
local_tool_output_mib = 1
capa_floss_output_mib = 32
floss_strings = 50000
floss_largest_file_mib = 16

[triage]
enabled = true
written_per_file_mib = 64                      # File activity: written content kept (0.9.1)
written_per_run_mib = 1024
earlier_per_file_mib = 64                      # File activity: earlier bytes kept (0.9.1)
earlier_per_run_mib = 1024

[detection]
yara = true
sigma = true
ids = true
scan_every_min = 0                             # Scan every N min while the program runs (0.9.1)
check_online = false                           # Check online at abuse.ch (needs lookup.online and the node's abuse.ch key)

[report]
formats = ["html", "json"]                     # html | pdf | json | misp | stix | md
sections = "all"                               # (a list of sections arrives with 0.9.1)
bundle = false                                 # Evidence bundle
defang = true                                  # Defang indicators in HTML, PDF and Markdown

[verdict]
mapping = "default"
tag_library = false

[retry]
max_attempts = 2
backoff_s = [30, 120]
retry_on = ["vm_start_failed", "guest_unreachable", "upload_failed", "guest_lost"]
"#;

pub const QUICK_LOOK: &str = r#"title = "Quick look"
description = "Two minutes, nothing leaves the lab, five static checks and YARA"

[program]
run_time_s = 120

[static_analysis]
triage_checks = ["metadata", "strings", "hardening", "rules", "identification"]

[detection]
yara = true
sigma = false
ids = false

[vm]
allow_control = false
"#;

pub const DEEP: &str = r#"title = "Deep"
description = "Fifteen minutes on InetSim, dumps when suspicious, deep static analysis, PDF and evidence bundle"

[program]
run_time_s = 900

[network]
route = "inet_sim"

[dumps]
core_dump_on_exit = true
dump_when_suspicious = true
minimum_tier = "medium"
trigger_memory_dump = true
trigger_core = true

[static_analysis]
deep_checks = ["disassembly", "decompilation", "floss"]

[report]
formats = ["html", "json", "pdf"]
bundle = true
"#;

pub const INTERACTIVE: &str = r#"title = "Interactive"
description = "Ten minutes, nothing leaves the lab, taking control allowed"

[program]
run_time_s = 600

[detection]
yara = true
sigma = true
ids = false

[vm]
allow_control = true
"#;

pub const LIVE_NETWORK: &str = r#"title = "Live network"
description = "Ten minutes through Tor"

[program]
run_time_s = 600

[network]
route = "tor"

[detection]
yara = true
sigma = false
ids = true
"#;

/// The built-in presets by name, Standard first.
pub const BUILT_IN: [(&str, &str); 5] = [
    ("standard", STANDARD),
    ("quick-look", QUICK_LOOK),
    ("deep", DEEP),
    ("interactive", INTERACTIVE),
    ("live-network", LIVE_NETWORK),
];

/// The preset a run uses when the request names none.
pub const DEFAULT_PRESET: &str = "standard";

/// Whether `name` is a built-in preset's.
pub fn is_built_in(name: &str) -> bool {
    BUILT_IN.iter().any(|(built, _)| *built == name)
}
