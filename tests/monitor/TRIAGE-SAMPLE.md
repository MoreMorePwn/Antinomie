# Recorded triage sample

This creates a real guest recording for exploring the triage tabs. The original
C sample is benign: its files stay in a fresh guest `/tmp` directory, its BPF
program is a socket filter on an owned socket, and its seccomp filter allows all
syscalls. The setuid bit is briefly set on a non-executable data file and then
removed. No malware is needed and no rules are disabled to obtain matches.

Build the existing host harnesses with the Cargo cache:

```sh
cargo build --manifest-path src/antinomie/monitor/Cargo.toml \
  --release --locked -p antinomie-monitor-core \
  --example guest-run --example triage-results
python3 tests/monitor/run-triage-sample.py /path/to/busybox-bundle /path/to/new-sample
./run.sh --data-dir /path/to/new-sample/data
```

The output directory must be new. Required host tools are gcc with static libc,
Linux kernel UAPI headers, iproute2, unshare, QEMU and working KVM. If available,
musl-gcc produces a smaller static specimen. No guest image rebuild is needed.
The runner enters its own user/network namespace with loopback only. Local
HTTP/DNS servers answer the guest at the user-network gateway; no request is
forwarded externally. After recording, the stopped sample VM is saved with
isolated networking for future boots. Existing application data is never used.

Select **Triage sample 0.6.2**, then select its run in Runs/Triage. The sample
provides the following evidence:

| View | Observable operation |
|---|---|
| Summary | Whole-run calls, task identities, file/network and detection counts |
| Properties | Retained exact static ELF, MD5/SHA-1/SHA-256, size, type and magic |
| Process | Root self-exec, shell child, grandchild and worker thread; recorded exits |
| Suspicious | RWX mmap, shell exec, BPF program load and allow-all seccomp installation |
| Files / Opened | Successful opens plus an expected ENOENT failure |
| Files / Read | Original and changed bytes, pread/readv evidence |
| Files / Changed | Original-to-final known bytes, write/truncate/chmod/rename/link/delete timeline; gaps stay labeled |
| Network | DNS A question/answer for triage.test, HTTP GET/200, destination and hostname inventories |
| BPF | Two-instruction eBPF load/attach and a one-instruction classic seccomp filter |
| Memory / Core | Memory Dump on Exit and Core Dump on Exit enabled, with a retained readable marker |
| Static analysis | Executable acquisition and selected normal static checks; optional absent tools remain unavailable |

Detection is explicitly on demand. Choose `triage-sample.yar` in the YARA rule
field and `triage-sample.rules` in IDS to get benign, reproducible marker hits.
Sigma's built-in rules can match shell execution, setuid-mode change and BPF
program loading. IDS needs local Suricata; Sigma needs a local pySigma 2.x Python
environment with the SQLite backend. Those optional tools are not installed by
this sample. Matches are observations, not proof of malicious behavior.

The live acceptance run also exposed two existing heuristic limitations: x86-64
`rt_sigsuspend` (syscall 130) is incorrectly included in the privilege-change
list, and generic exec observations carry a shell-related ATT&CK reference even
for the sample's non-shell self-exec. These are retained as review findings;
the fixture does not hide the observations or claim they are valid detections.

For automated inspection of the actual recording, the opt-in UI test
`triage::tests::recorded_triage_sample_populates_every_evidence_table` takes the
run directory in `ANTINOMIE_TRIAGE_SAMPLE`. It invokes the normal triage index,
saves `sample-triage.json` and creates the run-scoped normalized journal needed
by Sigma. `triage-results --properties ANALYSIS_DIR` runs the real offline
Properties worker. `triage-results --detect REQUEST.json` uses the public
`analysis::detection::Request` format and retains the normal engine report.

This sample covers each evidence table, not every community rule or every
possible suspicious behavior. vhash cannot be computed locally; optional
classifiers/hashes, absent tools and GeoIP/ASN data remain unavailable. Network
capture times retain their recorded clock. Do not infer a country or organization
for the local fixture address.
