# Stress samples

`build-torture.sh` builds benign programs that each push one Antinomie feature
as far as it goes, plus `ant-torture`, which holds all of them. They contain no
malware and no malware signatures. Detection matches come from the bundled
`torture/torture.yar` and `torture/torture.rules`, or from SigmaHQ rules that
describe the shape of a harmless command.

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
| `ant-crash-core` | Children crash with SIGSEGV and abort; the root holds 32 / 128 / 500 MiB of patterned pages, then crashes | Take a live core while it holds; Core dump on exit should be about that size (the `Antinomie_Torture_Core_Pattern` rule counts pages) |
| `ant-memory-tricks` | RWX code, `mprotect` flips, memfd `fexecve`, a 16 to 256 MiB region with a memory-only marker | Suspicious activity; memory dump and YARA memory scan |
| `ant-detect-yara` | A marker in the executable, one in a dropped file, one only in memory | Each `torture.yar` rule matches only its own target |
| `ant-detect-sigma` | Discovery commands, base64 to a shell, hidden files, FIFOs, `nohup`, execution from `/tmp` and `/dev/shm`, a long command line, bash `/dev/tcp` connects; `chmod u+s` as root | SigmaHQ Linux process_creation, file_event and network_connection matches |
| `ant-detect-ids` | DNS and UDP markers; with `--public`, an HTTP user agent | `torture.rules` sids 9900701, 9900702, 9900703 and 9900704 |
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

## Detection setup

1. In Tools → Rule manager, add `torture/torture.yar` as a custom YARA group
   and `torture/torture.rules` as a custom IDS group. For Sigma, install
   SigmaHQ Linux and set the Sigma Python.
2. Turn on network capture, and memory and recovered-file scanning for YARA.
3. `ant-detect-yara` keeps `/tmp/antinomie-torture-yara-dropped.bin` for
   recovery; the other samples remove what they create.
