# Feature sample

`feature-sample.c` is a benign program for exploring Antinomie end to end:
triage, community-rule detection and every static analysis tab. It contains
no malware and no malware signatures. Rule matches come from behavior the
rules describe by program name, file name or network destination, so each
match is an observation, not a verdict.

The [triage sample](TRIAGE-SAMPLE.md) remains the reproducible, isolated
recording with its own local servers. This sample is meant to be uploaded and
run by hand in an ordinary VM, including public network requests.

## Build

```sh
tests/monitor/build-feature-sample.sh /path/to/output
```

The default build links glibc dynamically and keeps its symbols, so capa and
the Symbols tab see its imports. The script stops if the binary would need a
newer glibc than the Debian trixie guest has (2.41); `--static` builds a
static binary instead, at the cost of most capa results. The embedded gzip,
PNG, ZIP and noise payloads are generated reproducibly into the output
directory.

## Run

1. Optional, for detection: in Tools → Rule manager install YARA-Forge Core,
   Emerging Threats Open and SigmaHQ Linux, and add `feature-sample.yar` and
   `feature-sample.rules` as custom groups. IDS needs Suricata on the host.
   Sigma needs a Python with pySigma 2.x and its SQLite backend, set as the
   Sigma Python in Settings.
2. Use a VM with NAT networking for the public requests; Isolated still
   records the DNS questions. Turn on network capture and static analysis.
3. Upload `antinomie-feature-sample` and run it. It re-runs itself from
   `/tmp/antinomie-feature-sample`, works in a new
   `/tmp/antinomie-feature-XXXXXX` directory and prints one PASS or
   UNAVAILABLE line per step. `--offline` skips the public requests.

Run it as root to also load the BPF program; other steps work unprivileged.

## What it exercises

| View | Evidence |
|---|---|
| Process tree | Self re-exec from `/tmp`, discovery tools, a shell with a background grandchild, a dropped script, a program run from `/dev/shm`, a memfd `fexecve` named `[kworker/0:1H]`, a worker thread, a double-forked daemon, a `prctl` rename to `kworker/u8:3` |
| Suspicious | RWX mapping, exec and shell interpreter, memfd creation and memfd exec, ptrace, `process_vm_readv` of its own memory, no-op `setresuid`/`setresgid`, a write attempt under `/etc`, BPF program and socket filter, allow-all seccomp filter |
| Files › Opened / Read | `/etc/passwd`, `/etc/os-release`, `/proc/self/maps`, `/proc/cpuinfo`, a denied or allowed `/etc/shadow` open, an expected ENOENT |
| Files › Changed | write, pwrite, writev, fallocate, truncate, chmod, chown, xattrs, utimensat, rename, link, symlink, unlink, mkdir/rmdir, `copy_file_range`, `sendfile`, shared-mapping `msync`, `O_TMPFILE` + `linkat` |
| Network | DNS questions for `*.ngrok.io`, `api.ipify.org` and `example.com`; HTTP to example.com, testmynids.org, api.ipify.org and icanhazip.com; TLS ClientHellos with SNI |
| Detection › IDS | ET 2047702 (ipify DNS), 2022642 (ngrok DNS), 2029622 (ipify HTTP), 2017398 (icanhazip HTTP), 2047703 (ipify SNI), 2019512 (ipify certificate), GPL 2100498 (testmynids `uid=0(root)` reply), and the custom 9900631 |
| Detection › Sigma | Execution from `/tmp` and from `/dev/shm`; system information (`uname`, `hostname`, `uptime`), account (`id`), group (`groups`), file (`find`) and network (`ip`, `who`) discovery; `rm`, `mkfifo`, `nohup`; file names with an embedded base64 command and the Triple Cross lock and persistence names |
| Detection › YARA | The custom `Antinomie_Feature_Sample` rule |
| Static analysis | Sections and all 14 program headers; 700+ strings; binwalk finds the ZIP, PNG, zlib and gzip payloads and the Base64 table; capa reports about 40 capabilities, including XOR, Base64 and RC4 (T1027) and discovery (T1082, T1083, T1033); a high-entropy region; symbols, imports, disassembly and decompilation |

## Limits

- YARA-Forge Core holds family signatures; a benign file can only match
  them by copying malware strings, which this sample does not do.
- Antinomie does not record a process `CommandLine` (argv may be cut short),
  so Sigma rules that need one do not apply; matches here use `Image` and
  `TargetFilename` only.
- binwalk also reports two "ESP Image" signatures inside the random noise
  block; they are false positives of its signature scan.
- The certificate rule needs a TLS 1.2 reply; the ClientHello offers only
  TLS 1.2 for that reason.
- `/tmp/rootlog`, `/dev/shm/antinomie-shm-true` and, as root,
  `/etc/antinomie-feature-sample.conf` are removed after use;
  the work directory and `/tmp/antinomie-feature-sample` are kept for
  inspection.
