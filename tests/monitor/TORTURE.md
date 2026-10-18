# Stress samples

`build-torture.sh` builds benign programs that each push one Antinomie feature
as far as it goes, plus `ant-torture`, which holds all of them. They contain no
malware. Detection matches come from the public rule packs the Rule manager
installs (YARA-Forge Core, Emerging Threats Open, Suricata built-in, SigmaHQ
Linux), triggered by inert text, DNS lookups and harmless commands; no custom
rules are needed.

The [feature sample](FEATURE-SAMPLE.md) touches every view once; these
samples find the limits.

## Build

```sh
tests/monitor/build-torture.sh /path/to/output            # Debian guests
tests/monitor/build-torture.sh /path/to/output --static   # BusyBox guests
```

The default build links glibc dynamically and stops if a binary would need a
newer glibc than the Debian trixie guest has (2.41). A static build cannot
resolve host names through glibc, so `--public` HTTP reports UNAVAILABLE in it.

## Run

Upload a sample and run it like any program. Every sample takes:

| Option | Meaning |
|---|---|
| `--level light\|heavy\|extreme` | How hard to push: counts grow x1, x4, x16 |
| `--duration SECONDS` | Overrides the module's time for its level |
| `--public` | Network modules also contact example.com |
| `--keep` | Keep the work directory under `/tmp` |
| `--workdir DIR` | Work under DIR instead of a new `/tmp/antinomie-torture-*` |

`ant-torture` also takes `--all`, `--only a,b,...`, `--parallel` (modules at
the same time) and `--list`.

Each step prints `PASS`, `LIMIT` (a cap stopped it), `UNAVAILABLE` or `FAIL`,
and the run ends with a scorecard of what it generated, to compare with the
counts Antinomie recorded. Parts that need root print a `WARNING` and are
skipped when run unprivileged.

Whatever the level, a module stays under 20,000 processes, 512 MiB of memory,
2 GiB of disk and 30 s of maximum syscall load, and removes its files.

## The samples

| Sample | Pushes | What to check in Antinomie |
|---|---|---|
| `ant-syscall-flood` | Syscalls on every CPU (1, all, or 2x the CPUs) for 5 / 15 / 30 s | Call count against the scorecard; TRL and Capture All shedding; the UI stays responsive |
| `ant-long-run` | Mixed file and terminal activity for 60 s / 10 min / 30 min | STL stays 0 past 20 minutes; the run finalizes; memory stays flat |
| `ant-object-capture` | Buffers of 1 byte to 64 KiB / 1 MiB / 4 MiB, repeats and scatter writes | `objects/` holds a few pack files; repeated buffers are stored once |
| `ant-terminal-flood` | 2,000 to 32,000 colored lines, a 16 KiB to 256 KiB line, a progress bar, UTF-8 and raw bytes | The run is not throttled; scrollback and the saved transcript render |
| `ant-process-tree` | 300 to 4,800 children, a chain of 50 to 800, threads, an exec chain, orphans | Process tree completeness and speed; PID reuse; orphans reparented |
| `ant-unkillable` | A root, a `setsid` child and a daemon that ignore SIGTERM, for 30 s / 2 min / 10 min | Stop or Kill the run, then read which processes survived |
| `ant-file-churn` | 250, 4,000 or 64,000 files: renames, links, xattrs, truncates, copies, plus `O_TMPFILE`, `msync`, `fallocate`, `RENAME_EXCHANGE`, `sendfile` | Files tab counts and changed-file entries |
| `ant-network-storm` | DNS questions, TCP connects and UDP to the NAT gateway; IPv4 and IPv6 loopback transfers | Network capture size, the Network view, DNS rows |
| `ant-async-io` | io_uring linked writes and reads 32 / 128 / 256 deep, and a cancelled read | Async requests attributed to the run |
| `ant-decoder-zoo` | Socket options by level, ptrace, keyctl, prctl, seccomp, clone3, execveat, semctl arrays, queued signals, failing arguments; BPF and mount as root | Decoded arguments in the trace |
| `ant-crash-core` | Children crash with SIGSEGV and abort; the root holds 32 / 128 / 500 MiB of patterned pages, then crashes | Take a live core while it holds; Core dump on exit should be about that size. Every MiB starts with the Kobalos text, so YARA on the core reports `ESET_Kobalos_Ssh_Credential_Stealer` |
| `ant-memory-tricks` | RWX code, `mprotect` flips, memfd `fexecve`, a 16 to 256 MiB region holding the memory-only Kobalos text | Suspicious activity; memory dump and YARA memory scan |
| `ant-detect-yara` | Indicator text in the executable, in a dropped file and only in memory | See [Detection](#detection) |
| `ant-detect-sigma` | The feature sample's SigmaHQ-checked commands started directly, rule-named files, execution from `/tmp` and `/dev/shm`, connects to callback ports; a bash `/dev/tcp` connection with `--public` | See [Detection](#detection) |
| `ant-detect-ids` | DNS lookups ET Open reports by name, odd DNS questions; with `--public`, HTTP IP lookups | See [Detection](#detection) |
| `ant-argv-env` | 300 to 4,800 arguments, one of 4 KiB to 128 KiB, binary and multi-line arguments, 200 to 3,200 variables; a 256 KiB argument refused with E2BIG | CommandLine capture and its limits |
| `ant-timing` | 50 to 800 children that exit at once or after a 10,000-call burst | Short runs and their first calls are recorded |
| `ant-torture` | All of the above, in turn or with `--parallel` | Everything at once |

### Static analysis

| Sample | Built with |
|---|---|
| `ant-static-symbols` | `-O0 -g`, every symbol |
| `ant-static-stripped` | `-s` |
| `ant-static-nopie` | `-no-pie` |
| `ant-static-norelro` | no RELRO, lazy binding |
| `ant-static-unprotected` | no canary, no FORTIFY, no PIE, executable stack, no RELRO |
| `ant-static-hardened` | canary, `_FORTIFY_SOURCE=3`, stack clash protection, CET, PIE, full RELRO |
| `ant-static-static` | statically linked |
| `ant-static-packed` | a 256 KiB high-entropy block and embedded gzip, ZIP and PNG |
| `ant-static-huge` | 3,000 functions, 2,000 strings and 200 named sections |

The Hardening tab should tell them apart, binwalk should find the packed
payloads, and the huge one exercises disassembly, decompilation and listing
limits.

## Detection

Install the public packs in Tools → Rule manager: YARA-Forge Core, Emerging
Threats Open, Suricata built-in and SigmaHQ Linux. Turn on network capture,
and memory and recovered-file scanning for YARA.

| Engine | Target | Rule | Checked |
|---|---|---|---|
| YARA | `ant-detect-yara`, `ant-torture` | `CADOSECURITY_Linux_Wiper_SOLOSHRED`, `CADOSECURITY_Linux_Worm_ORCSHRED` | YARA-X 1.21 on the installed pack; the other 25 samples match nothing |
| YARA | `/tmp/antinomie-torture-yara-dropped.txt` (kept for recovery) | `ESET_Mozi_Killswitch` | YARA-X 1.21 |
| YARA | Memory only (also cores of `ant-crash-core`) | `ESET_Kobalos_Ssh_Credential_Stealer` | YARA-X 1.21 on a live memory dump; the text is XOR-encoded in the executable |
| IDS | DNS questions `api.ipify.org`, `tunnel.ngrok.io`, `dashboard.ngrok.com`, `antinomie.duckdns.org`, `checkip.dyndns.org`, `transfer.sh`, `gateway.discord.com`, `api.telegram.org`, `termbin.com`, `ip-api.io` | ET Open 2047702, 2022642, 2022641, 2042936, 2043238, 2034316, 2035465, 2033966, 2050513, 2039045 (and 2066094, 2022918, 2071627) | Suricata 8 on the sample's own packets with the installed ET Open pack |
| IDS | A question with the Z flag, one with opcode 15, one with a 300-byte name | Suricata built-in 2240006, 2240007; ET Open 2013075 | Same |
| IDS | `--public`: HTTP to api.ipify.org and icanhazip.com | ET Open 2029622, 2017398 | Not replayed |
| Sigma | Discovery, decoding, `mkfifo`, `nohup`, `chmod u+s`, execution from `/tmp` and `/dev/shm`, rule-named files | SigmaHQ Linux process_creation and file_event | The commands the feature sample checked against SigmaHQ |
| Sigma | Connects to 192.0.2.1 (TEST-NET-1) on 4444, 2222, 888, 6789 | `net_connection_lnx_susp_malware_callback_port` | Rule logic; needs the app's network_connection mapping |
| Sigma | `--public`: bash `/dev/tcp` to example.com | `net_connection_lnx_back_connect_shell_dev` | Rule logic |

The DNS questions are lookups only: nothing connects to those services. The
IDS checks can be repeated without a VM: `ant-torture --child dns-pcap
FILE.pcap` writes the exact DNS packets as a capture for Suricata.
