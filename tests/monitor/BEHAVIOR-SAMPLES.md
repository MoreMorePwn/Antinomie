# Behavior samples

`demo-*` are small static x86-64 ELFs that reproduce the *shape* of attacker
behaviour for testing Antinomie end to end, above all the 0.7.1 Suspicious
activity rules, the network triage and the activity graph. They are not stress
tests: each scenario does a handful of things an analyst would triage, then
exits. `demo-all` runs every scenario in the order of the graph's phases
(recon, download, persistence, escalation, hide/inject, C2, spread, impact),
so one run is a short intrusion storyline.

Everything harmful is replaced by a harmless destination or a harmless form:

- the default endpoint is the QEMU user-network host `10.0.2.2`, so a NAT guest
  reaches a listener on the host and nowhere else; pass `--host 198.51.100.23`
  (RFC 5737 TEST-NET) or `--host 127.0.0.1 --port 9` for an offline baseline;
- `--host` and `--resolver` take numeric IPv4 only; no name is ever resolved, so
  names such as `remote.example-host.invalid`, `api.telegram.org` or `x.onion` appear only
  inside payloads and DNS questions sent to the numeric listener address
  (10.0.2.2 is a private address, but it is the host of QEMU and VirtualBox NAT
  only: on a machine whose own network uses 10.0.2.0/24, pass `--host`
  explicitly);
- downloaded content runs only if it matches a pinned hash of the bundled
  hello-world payload: `download` and `download-elf` save what they fetch inside the
  work directory, compare its SHA-256 with the constant compiled into the
  sample, and only on an exact match `chmod +x` and start it. Any other server
  gets `NOTE ... hash mismatch, not executed` and nothing runs. `memfd-exec`
  runs only a copy of its own binary;
- writes stay below a per-run work directory and are removed unless `--keep`
  (an existing `--workdir/<scenario>` is refused, never adopted); the only
  exceptions are the opt-in `--cred-home`, which creates missing decoys with
  `O_EXCL` and removes what it created, and the opt-in `--real-paths`, whose
  opens cannot create, change or read anything (see below);
- no real persistence, privilege escalation, exploitation or destruction: files
  that look like persistence are lookalikes in the work directory; commands
  that would change the system (`iptables`, `crontab`, `useradd`, `shutdown`,
  `xmrig`, ...) are *exec stand-ins*, this binary started with that argument
  vector, which only exits; system calls that would change the system
  (`syslog` clear, bind mount over `/proc/PID`, `chattr`, file capabilities,
  `setns`, `finit_module`) are made with arguments the kernel refuses;
  ptrace and `/proc/PID/mem` only ever target a child the sample forked;
- no real credential is read: decoys only; the standard locations are `stat`ed;
- every loop is bounded by a constant or by `--rounds` (1-50), every wait is
  bounded, and every helper process is killed by pid if it overruns.

Options accept both `--host 10.0.2.2` and `--host=10.0.2.2`. A bare
`./demo-all` runs every scenario; `--only a,b` selects a subset, `--list`
prints the registry and `--help` the options.

## Build

```sh
tests/monitor/build-behavior-samples.sh /tmp/demo-all
tests/monitor/build-behavior-samples.sh /tmp/demo-all --dynamic
```

Static is the default (glibc, no `PT_INTERP`), which runs on every guest base.
The script builds `demo-all` and one `demo-<scenario>` per entry of
`./demo-all --list`, with `-Wall -Wextra` and no warnings.

## Quick start

On the host (from the repository root), then in the guest:

```sh
python3 tests/monitor/sinkhole.py --nat       # QEMU NAT guest -> host listener
./demo-all --host 10.0.2.2 --rounds 1              # in the guest

python3 tests/monitor/sinkhole.py                     # same machine
./demo-all --host 127.0.0.1 --rounds 1 --delay 0
```

The sinkhole prints the exact `--host` (and `--dns-port` when port 53 is not
available) to pass. `--rounds 1 --delay 0 --gap 0` is a quick pass of a few
seconds; the default (3 rounds, 500 ms, a 1 s gap between scenarios) spreads the
activity over a minute so the graph can separate the phases.

## Options

```text
--rounds N        repetitions of http-beacon and udp-beacon (1-50, default 3); the
                  other scenarios have fixed, bounded counts
--delay MS        pause between rounds (0-10000, default 500)
--host ADDRESS    numeric IPv4 of the listener (default 10.0.2.2)
--port N          override the scenario's own port
--resolver ADDR   DNS server for the DNS scenarios (default: --host, else 10.0.2.2)
--dns-port N      DNS port (default 53, or $SAMPLE_DNS_PORT); the sinkhole falls back to 5353
--workdir DIR     base directory; each run uses DIR/<scenario>
--keep            keep the work directory for evidence inspection
--cred-home       cred-read: plant decoys under $HOME (never overwrites)
--wide            allow net-wide: a few packets to 203.0.113.0/24
--real-paths      allow real-path-probes: opens that cannot create or read
--gap MS          pause between scenarios in a full run (0-5000, default 1000)
--evade           check for an analysis environment first; do nothing else if one is found
--why             print every environment check and its answer (with the Stealth entry)
--ignore LIST     skip check categories: debugger,vm,container,sandbox
--evade-sleep MS  the evading sleep (0-5000; default 3000-4500)
--test-root DIR   tests only: the checks read their files below DIR (see Evasive variant)
--list            registry: name, phase, requires, expected rule ids, summary (tab separated)
--all / --only a,b   select scenarios in demo-all
```

Several rules look at the work directory's path: a hidden component (`.cache`,
`.bin`, `.ssh`) or a `/tmp` workdir makes it a staging directory. The default
workdir is `/tmp/demo-sample-XXXXXX`; with `--workdir` the scenarios still
use hidden subdirectories for everything that must look like a drop.

## Scorecard

Every line is `TAG scenario message`; the tags are stable:

```text
== download: GET a hello-world script, ... (phase download, rounds 1, work /tmp/...)
EXPECT      download          execution.dropped_exec,execution.chmod_exec_temp,...
DEPENDS     download          runs only when the SHA-256 matches; ...
NOTE        download          sha256 4267d61ee8379b7c... matches the pinned payload (82 bytes)
PASS        download          verified 82 bytes, ran .../install.sh (exit 0) and through a pipe into sh ...
UNAVAILABLE shell-sim         raw socket Operation not permitted, ...: c2.bpf_backdoor needs root
SKIP        net-wide          not run: pass --wide to enable it (...)
...
SCENARIO    download          status=PASS pass=1 note=2 unavailable=0 fail=0 skip=0 phase="download" expect=...
== scorecard: 26 pass, 53 note, 1 unavailable, 0 fail, 2 skip
SUMMARY     scenarios=28 pass=26 note=53 unavailable=1 fail=0 skip=2 expected_rules=113
RULES       all               c2.bpf_backdoor,c2.bind_shell,...   (sorted union of the scenarios that ran)
```

- Extra tags of the evasive variant: `CHECK` (one environment check and its answer,
  with `--why`), `EVADE category: reasons` (also on stderr), `GATE` (the verdict) and
  `PATH` (the rule ids of the path taken).
- `EXPECT` is what Antinomie should list for the scenario; `DEPENDS` says what
  that depends on (root, a guest, a capture, a work directory under /tmp).
- `PASS` is the scenario's own summary of what it did; `NOTE` is detail
  (including why a download did not run); `UNAVAILABLE` means a step could not
  be done here (no listener, not root, a call refused) and says which rule it
  affects; `SKIP` means a step or scenario was deliberately not run, with the
  reason; `FAIL` is a bug or an unwritable work directory and makes the exit
  status 1.
- Compare Antinomie with the run: filter Suspicious activity by the ids in
  `RULES` (or one `SCENARIO` line's `expect=`). Missing ids that the scorecard
  marks `UNAVAILABLE` or `SKIP` are expected to be missing. Rows from a call
  that the kernel refused are one tier lower and flagged `failed`.

## Scenarios and the rules they should fire

The ids are those of the 0.7.1 rule table
(`src/antinomie/monitor/crates/monitor-ui/src/triage/rules/table.rs`);
`tests/monitor/test-sinkhole.py` checks that every id in the registry
exists there. A tier is the rule's own; failed or allow-listed matches are lower.

| Scenario | Graph phase | Rule ids it should fire | What to look at in Antinomie |
|---|---|---|---|
| `demo-recon` | recon | `discovery.system_info`, `network.ip_literal` | Triage > Suspicious activity (discovery.system_info INFO); Network tab: POST /gate.php with Host as an IP literal; Files tab: `stage/recon.txt` with `--keep`. |
| `demo-discovery` | recon | `discovery.user_enum`, `discovery.system_info`, `discovery.network_config`, `discovery.process_enum`, `discovery.file_search`, `discovery.security_software`, `discovery.network_scan` | Suspicious activity, Discovery group: user/system/network reads, 16 `/proc/PID` probes, 232 directory listings in 60 s, stat probes of security-software paths; Process tab: eight stand-in programs named `ps`, `id`, `ip`, `find`, `nmap`. |
| `demo-sandbox-probe` | recon | `evasion.sandbox_probe`, `evasion.probe_then_exit`, `evasion.container_check`, `evasion.debugger_check`, `evasion.traceme`, `discovery.system_info`, `discovery.network_config` | Evasion rows `evasion.sandbox_probe` (open the row: each check with the answer the guest gave and whether it would show a VM), `evasion.container_check`, `evasion.debugger_check`; a `probe_then_exit` row for the child that checked and exited; compare a default guest with a Stealth-profile guest. |
| `demo-ptrace-antidebug` | recon | `evasion.debugger_check`, `evasion.traceme` | Evasion: `evasion.debugger_check` (TracerPid, maps) and `evasion.traceme` (the child's `PTRACE_TRACEME`, EPERM when something already traces it). |
| `demo-sleep-evasion` | recon | `evasion.long_sleep` | Evasion: six `evasion.long_sleep` rows, one per sleeper (nanosleep, clock_nanosleep, select, poll, alarm, timerfd_settime), MEDIUM with the text "before any network or file write". |
| `demo-cred-read` | - | `credential.history_read`, `credential.wallet`, `credential.kerberos_ccache`, `credential.cloud_tokens`, `credential.ssh_keys`, `credential.browser_store`, `network.ip_literal` | Credential group: the decoy paths in the Files tab (Credentials location), `credential.*` rows; the exfil POST in Network. With `--cred-home` the real-home rules fire as well. |
| `demo-download` | download | `execution.dropped_exec`, `execution.chmod_exec_temp`, `execution.temp_exec`, `execution.download_cradle`, `process.interpreter`, `process.exec`, `network.ip_literal` | Execution rows `execution.download_cradle`, `execution.dropped_exec`, `execution.chmod_exec_temp`, `execution.temp_exec`; the process tree shows `demo-download -> install.sh` and `sh -c ... | sh`; Files: `.cache/install.sh`, `download-marker.txt` with `--keep`; Network: `GET /install.sh`. Graph phase: download. |
| `demo-download-elf` | download | `c2.elf_download`, `execution.dropped_exec`, `execution.chmod_exec_temp`, `execution.temp_exec`, `execution.compile_then_run`, `network.ip_literal` | `c2.elf_download` (HIGH): the socket read that starts with `\x7fELF` and the write that follows; `execution.dropped_exec` for `payload.elf` and for `.bin/cc`; `execution.compile_then_run` for `.bin/a.out`. Graph phase: download. |
| `demo-persistence` | persistence | `persistence.systemd`, `persistence.xdg_autostart`, `persistence.shell_profile`, `persistence.ssh_authorized_keys`, `persistence.pam`, `persistence.config_write`, `persistence.cron`, `persistence.at_job`, `persistence.account`, `persistence.rc_init`, `persistence.module`, `execution.chmod_exec_temp` | Persistence group in the Files tab (Persistence location) and Suspicious activity; process tree: `crontab`, `at`, `useradd`, `update-rc.d`, `systemctl` stand-ins. Graph phase: persistence. |
| `demo-privesc-sim` | escalation | `privilege.setid_bit`, `privilege.userns`, `privilege.container_escape`, `privilege.pwnkit`, `privilege.dirty_pipe`, `privilege.drop`, `execution.temp_exec` | Privilege group; `privilege.setid_bit` names the chmod 04755/02755 and the refused file capability; the process tree has a `pkexec` with an empty argument vector. Graph phase: escalation. |
| `demo-memfd-exec` | hide/inject | `process.memfd`, `execution.memfd_elf`, `process.memfd_exec`, `memory.rwx`, `memory.wx_transition`, `memory.rwx_attempt`, `execution.fileless_exec`, `execution.dropped_library` | Execution: `process.memfd`, `execution.memfd_elf`, `process.memfd_exec`, `memory.rwx` (and the refused zero-length `memory.rwx_attempt`), `memory.wx_transition`, `execution.fileless_exec` for `/proc/self/fd/N`, `execution.dropped_library` for `.cache/libdemo.so`. |
| `demo-inject-sim` | hide/inject | `injection.ptrace_attach`, `injection.ptrace_poke`, `process.ptrace`, `injection.vm_write`, `injection.proc_mem_write`, `credential.proc_mem_read`, `injection.ld_preload_env`, `evasion.traceme` | Injection group: attach, poke, `process_vm_writev`, `/proc/PID/mem` read and write, all against the sample's own child; `injection.ld_preload_env` on the stand-in started with `LD_PRELOAD=`. Graph phase: hide/inject. |
| `demo-evasion-misc` | hide/inject | `evasion.masquerade_kthread`, `evasion.masquerade_daemon`, `evasion.dumpable_off`, `bpf.seccomp_filter`, `evasion.hidden_artifact`, `evasion.history_clear`, `evasion.timestomp`, `evasion.immutable_attr`, `evasion.self_delete`, `evasion.log_clear`, `evasion.kill_list`, `evasion.proc_hide_mount`, `evasion.sysctl_security`, `evasion.firewall_modify`, `evasion.audit_disable`, `evasion.security_disable`, `bpf.program`, `evasion.io_uring_usage`, `execution.dropped_exec`, `execution.temp_exec`, `execution.chmod_exec_temp` | Evasion group: masquerade rows (a child named `kworker/0:1H` and `sshd`), dumpable, seccomp, bpf, history/log clearing, timestomp, `...` and ` ` entries, `evasion.self_delete` for `.cache/.svc`, immutable attribute on the decoy `authorized_keys`, stand-in firewall/audit/SELinux commands. |
| `demo-http-beacon` | C2 | `network.ip_literal` | Network tab: HTTP POSTs with a browser User-Agent; `network.ip_literal`; IOC window: URI `/gate.php`, User-Agent. |
| `demo-beacon-loop` | C2 | `network.beacon`, `network.ip_literal` | `network.beacon` after the eighth request: ten GETs 200 ms apart; the row shows the period. |
| `demo-dns-tunnel` | C2 | `network.dns_tunnel` | `network.dns_tunnel` twice (long labels, then the TXT burst); Network: the hex labels under `exfil.example-dns.invalid`; IOC window: DNS names. |
| `demo-dga` | C2 | `network.dga_nxdomain` | `network.dga_nxdomain` once fourteen random-looking names fail after one name was answered; Network: the NXDOMAIN replies. |
| `demo-tls-sni` | C2 | (none by design) | No finding on purpose. Network tab: TLS ClientHello, SNI `update.example-cdn.invalid`; IOC window: the SNI. |
| `demo-udp-beacon` | C2 | (none by design) | No finding on purpose. Network tab: UDP datagrams to port 4444 with a JSON body; IOC window: the destination and port. |
| `demo-c2-misc` | C2 | `network.nonstandard_port`, `network.irc_c2`, `network.tor`, `network.web_service`, `credential.cloud_metadata`, `impact.miner`, `network.proxy_tunnel`, `network.ip_literal` | Network group: `network.nonstandard_port` (HTTP 9080, TLS 9443, SSH 2222), `network.irc_c2`, `network.tor`, `network.web_service`, `credential.cloud_metadata`, `impact.miner` (Stratum text), `network.proxy_tunnel` (stand-ins). |
| `demo-shell-sim` | C2 | `c2.reverse_shell`, `c2.bind_shell`, `network.listen_any`, `network.raw_socket`, `bpf.socket_filter`, `c2.bpf_backdoor`, `process.interpreter` | Command group: `c2.reverse_shell` and `c2.bind_shell` (the exec of `sh` with a socket as stdin/stdout), `network.listen_any`; as root also `network.raw_socket` and `c2.bpf_backdoor`. |
| `demo-exfil-sim` | C2 | `exfil.file_to_socket`, `collection.archive_staging`, `lateral.tool_transfer`, `network.ip_literal` | `exfil.file_to_socket` (sendfile of `.ssh/id_exfil`), `collection.archive_staging`, `lateral.tool_transfer` for the scp/curl -T/rsync stand-ins; Network: `PUT /upload/id_exfil`. |
| `demo-collection-sim` | - | `collection.clipboard`, `collection.screen_capture`, `collection.av_capture`, `collection.tty_inject`, `collection.local_sweep` | Collection group: clipboard, screen and audio stand-ins, `collection.tty_inject` (ioctl TIOCSTI on a file), and `collection.local_sweep` only with a work directory under /home or /root. |
| `demo-lateral-sim` | spread | `discovery.network_scan`, `lateral.bruteforce`, `lateral.ssh_spread` | `discovery.network_scan` (24 ports of the host), `lateral.bruteforce` (12 connects to ports 22 and 23), `lateral.ssh_spread` after the known_hosts read. Graph phase: spread. Loopback hosts are not counted: use the NAT host. |
| `demo-impact-sim` | impact | `impact.fork_bomb`, `impact.ransom_rewrite`, `impact.ransom_note`, `impact.inhibit_recovery`, `impact.service_stop`, `impact.reboot`, `impact.miner`, `impact.miner_tuning`, `impact.ddos_flood`, `impact.block_device_write` | Impact group: `impact.fork_bomb` (230 vforks), `impact.ransom_rewrite` and `impact.ransom_note`, miner/shutdown/lvremove stand-ins, `impact.ddos_flood` (1120 datagrams). Graph phase: impact. |
| `demo-rule-markers` | - | `discovery.system_info`, `discovery.user_enum` | Files tab / static analysis: YARA and Sigma tag strings in `rule-markers.txt`; Process tab: real `uname`, `id`, `crontab -l`, `cat` for Sigma process_creation rules. |
| `demo-evasive` (named with `--only evasive`, or its own binary) | - | see "Evasive variant": the check rows on both paths, the chain's rows only when it proceeds | Checks first; on a VM it prints `EVADE vm: ...` and exits 0 after 3-4.5 s; on a clean machine the whole chain runs. See below. |
| `demo-real-path-probes` (needs `--real-paths`) | - | `persistence.cron`, `persistence.at_job`, `persistence.systemd`, `persistence.rc_init`, `persistence.event_script`, `persistence.shell_profile`, `persistence.ssh_authorized_keys`, `persistence.xdg_autostart`, `persistence.udev`, `persistence.pam`, `persistence.module_autoload`, `persistence.apt_hook`, `persistence.web_shell`, `persistence.config_write`, `injection.ld_so_preload`, `injection.ld_so_conf`, `privilege.sudoers`, `evasion.audit_disable`, `evasion.log_clear`, `impact.block_device_write`, `impact.miner_tuning`, `credential.shadow_read`, `collection.keylog`, `collection.screen_capture`, `collection.av_capture` | Persistence/Injection/Privilege/Impact rows with the `failed` flag and one tier down; Files: the same system paths as failed opens. `credential.shadow_read` and the device rows appear only where the node exists and is readable (root). |
| `demo-net-wide` (needs `--wide`) | spread | `lateral.service_exploit`, `discovery.network_scan`, `exfil.large_upload` | `lateral.service_exploit` (6379 on three hosts), `discovery.network_scan` (port 8080 on twelve hosts), `exfil.large_upload` (1.12 MB of zeros over connected UDP); all toward 203.0.113.0/24. |

Rows that come from the capture (`network.*` except the connect-based ones,
`credential.cloud_metadata` from a Host header, `network.ip_literal`) need the
sinkhole and a recording of the guest's network; the capture has no process, so
Antinomie ties a row to the sample only when the sample's own `connect` to the
same address was seen, and otherwise marks it VM-wide (one tier lower).

### What a rule depends on

| Condition | Rules |
|---|---|
| needs a capture and a listener that answers | `network.ip_literal`, `network.beacon`, `network.dns_tunnel`, `network.dga_nxdomain`, `network.nonstandard_port`, `network.web_service`, `network.tor` (the DNS and Host forms), `credential.cloud_metadata` |
| a resolver that answers one name and refuses the rest | `network.dga_nxdomain` (the sinkhole does; otherwise the rule is reported as not evaluated) |
| root in the guest | `privilege.drop`, `privilege.container_escape` (the `setns` form; the `nsenter` stand-in works for any user), `network.raw_socket` and `c2.bpf_backdoor` (a failed attempt still gives `network.raw_socket`), `credential.shadow_read` and the device opens of `real-path-probes`, a `PTRACE_SEIZE` of the parent and `/proc/1/ns` |
| an answer that shows a VM, a container or a debugger | `evasion.probe_then_exit` (and the tier of `evasion.sandbox_probe`: MEDIUM when two or more kinds of check were made, otherwise INFO) |
| a private `--host` that is not loopback | `discovery.network_scan`, `lateral.bruteforce`, `lateral.ssh_spread` (the connect forms; loopback is skipped by the rules) and `impact.ddos_flood` (the sample refuses to send a burst or a sweep to a non-private address) |
| a work directory under `/tmp` | the dotfile form of `evasion.hidden_artifact` (the `...` and ` ` names fire anywhere) |
| a work directory under `/home` or `/root` | `collection.local_sweep` |
| `--cred-home` | `credential.browser_store` and the `~/.aws`, `~/.kube`, `~/.ssh`, `~/.bitcoin` forms of `credential.cloud_tokens`, `credential.wallet` and `credential.ssh_keys` |
| `--wide` | `lateral.service_exploit`, `exfil.large_upload` (and the multi-host form of `discovery.network_scan`) |
| `--real-paths` | `persistence.event_script`, `persistence.udev`, `persistence.module_autoload`, `persistence.apt_hook`, `persistence.web_shell`, `injection.ld_so_preload`, `injection.ld_so_conf`, `privilege.sudoers`, `credential.shadow_read`, and the real-path forms of the other persistence rules, `evasion.audit_disable`, `evasion.log_clear`, `impact.block_device_write`, `impact.miner_tuning`, `collection.keylog`/`screen_capture`/`av_capture` |
| a stand-in only (the real file or syscall form is not exercised) | `persistence.cron`, `persistence.at_job`, `persistence.account`, `persistence.rc_init`, `impact.reboot`, `impact.service_stop`, `impact.inhibit_recovery`, `impact.miner`, `evasion.firewall_modify`, `evasion.kill_list`, `evasion.security_disable`, `collection.clipboard`, `collection.screen_capture`, `collection.av_capture`, `network.proxy_tunnel`, `lateral.tool_transfer`, `lateral.bruteforce` (also a connect form), `evasion.masquerade_*` (also `prctl`) |

### Rules that are not covered, and why

| Rule | Why |
|---|---|
| `impact.mass_delete` | counts 100 deletions of files the run did not create; the samples delete only what they made |
| `persistence.binary_replace` | needs a created or written file under `/bin`, `/usr/bin`, `/lib`, ...: no lookalike has that path class, and a failed open is not a write |
| `privilege.gain`, `privilege.setuid_exec`, `privilege.kernel_exploit` | read the kernel's credential-change records; only a real gain of rights (a setuid exec, `commit_creds`) produces them, and the samples never escalate |
| `privilege.kernel_helper_hijack` | exact existing kernel files (`core_pattern`, `modprobe`, `uevent_helper`, `binfmt_misc/register`); opening them for writing is not harmless |
| `rootkit.dev_mem` | exact device nodes `/dev/mem`, `/dev/kmem`, `/dev/port`, `/proc/kcore`; the samples do not open raw-memory devices, even read-only |
| `process.exec` | INFO, counted for every program the samples start; it has no scenario of its own |

## Evasive variant

`demo-evasive` behaves the way real evasive malware does: it asks the guest
whether it is being analysed *before* doing anything, and leaves quietly if the
answer is yes. The same gate is available on any binary as `--evade`
(`demo-all --evade`); a bare `demo-all` run does not use it and does not
include the `evasive` scenario, so the coverage suite is unchanged.

**If any category trips** it prints one line per category, on stdout and on
stderr, for example `EVADE vm: dmi sys_vendor=QEMU; mac VM prefix (52:54:00:12:34:56)`,
then the scorecard, a decoy (reads `/etc/hostname`, prints `hello from ...`), one
more look at the DMI vendor, `/proc/cpuinfo` and `/proc/uptime`, a bounded sleep
of 3.0 to 4.5 s (`--evade-sleep MS`, at most 5 s), and exits 0. No download, no
persistence, no beacon. Nothing is written after the last look, so Antinomie's
`evasion.probe_then_exit` can see "exited within 5 s, no network, no file write,
no new process" after a check that showed a VM.

**If every check is clean** (`GATE ... verdict=proceed`) it runs the chain, using
the code of the existing scenarios: `recon`, the hash-pinned `download` and
run, `persistence`, `beacon-loop` (10 requests) and one exfil POST. The usual
safety rules hold: numeric endpoints, bounded loops, only pinned payloads run.

### The checks

All are system calls Antinomie records. The last column is the entry of the
Stealth profile window (VM settings > Stealth profile) that changes the answer;
"none" means the profile does not shape it.

| Category | Check | Trips when | Stealth entry |
|---|---|---|---|
| debugger | `TracerPid` in `/proc/self/status` | not 0 | none: the analyser debugger uses no ptrace |
| debugger | `ptrace(PTRACE_TRACEME)` in a child | refused (EPERM) | none |
| debugger | `LD_PRELOAD`, `LD_AUDIT` | set | none |
| debugger | `/proc/self/maps` | names frida, gdbserver, valgrind, libfaketime, ... | none |
| vm | DMI `sys_vendor`, `product_name` | QEMU, KVM, VirtualBox, VMware, Bochs, Xen, Parallels, Hyper-V, SeaBIOS, "Standard PC", ... | Hardware identity > Machine (System maker, Product) |
| vm | DMI `board_vendor` | the same words | Hardware identity > Board maker |
| vm | DMI `bios_vendor` | the same words | Hardware identity > BIOS vendor |
| vm | DMI `chassis_type` | 1 or 2 (Other, Unknown) | Hardware identity > Chassis |
| vm | `/proc/cpuinfo` `hypervisor` flag | set | CPU > Hide the hypervisor CPU flag |
| vm | `/proc/cpuinfo` `model name` | QEMU, KVM, Virtual, TCG, ... | CPU > Model, Brand string, Pass the host CPU through |
| vm | `/sys/class/net/*/address` | OUI 52:54:00, 08:00:27, 0a:00:27, 00:0c:29, 00:50:56, 00:05:69, 00:1c:14, 00:16:3e, 00:15:5d, 00:1c:42 | Network > MAC address |
| vm | `/sys/class/net/*/device/vendor` | 0x1af4 (virtio), 0x15ad (VMware), 0x80ee (VirtualBox) | Network > Card (e1000e) |
| vm | `/sys/block/*`, `device/model` | a `vd*` virtio disk, or a model naming QEMU, VBOX, VMware, Virtual | Storage and devices > Disk bus (SATA or NVMe) and Disk model |
| vm | `current_clocksource` | kvm-clock, hyperv, xen | CPU > Hide the KVM signature |
| vm (shown only) | `/sys/firmware/qemu_fw_cfg`, `/sys/bus/virtio/devices`, `/sys/hypervisor/type` | never decisive | none: listed under Still visible |
| container | `/.dockerenv`, `/run/.containerenv`, `/proc/1/cgroup`, `/proc/self/cgroup`, `$container` | present, or names docker, kubepods, containerd, lxc, podman, crio | none: the guest is not a container |
| sandbox | CPU count (`sched_getaffinity`), RAM (`sysinfo`), root filesystem size (`statfs`), process count (`/proc`), uptime (`/proc/uptime`) | at least 3 of: under 2 CPUs, under 1 GiB, under 4 GiB, under 10 processes, under 60 s | none: the VM's own size and a fresh boot |

The sandbox hints are weak on purpose and need three of five: a default Antinomie
guest (2 vCPUs, 2 GiB, 8 GiB) trips at most the uptime and the process count in
its first minute. `--why` prints every answer with its Stealth entry, even when
the sample proceeds, and `--ignore vm,debugger,container,sandbox` skips
categories (for example `--ignore sandbox` to ignore the size hints).

### Rules by path

- **Evade:** `evasion.sandbox_probe` (MEDIUM, because several kinds of VM
  evidence are read), `evasion.debugger_check`, `evasion.container_check`,
  `evasion.traceme` (the child's `PTRACE_TRACEME`), `evasion.probe_then_exit`
  (when an answer showed a VM and the process then exits within 5 s doing
  nothing), `discovery.system_info` (the decoy) and `discovery.network_config`
  (the MAC reads). `evasion.long_sleep` does not apply: the sleep is under 60 s.
- **Proceed:** the same check rows (without `probe_then_exit`), then the full set
  of the chain: `network.ip_literal`, `execution.download_cradle`,
  `execution.dropped_exec`, `execution.chmod_exec_temp`, `execution.temp_exec`,
  `process.interpreter`, the persistence group of `persistence`, `network.beacon`,
  and the phases recon, download, persistence and C2 in the activity graph.

### Two-run demo

1. Start the sinkhole on the host (`--nat`), VM on NAT, Stealth preset
   **Transparent** (the default). Wait a minute after boot, then run
   `./demo-evasive --host 10.0.2.2 --why`.
   It prints `EVADE vm: dmi sys_vendor=QEMU; cpuinfo hypervisor flag set; mac VM
   prefix (52:54:00:...)`, `hello`, and exits 0 after a few seconds. In Antinomie:
   Suspicious activity shows the Evasion rows above and a `probe_then_exit` row;
   the sinkhole saw nothing.
2. Stop the VM, open VM settings > Stealth profile > Preset **Realistic desktop**
   (SATA disk, e1000e card with an Intel MAC, real-looking DMI, no hypervisor
   flag, host CPU passed through), start it, wait a minute and run the same
   command. `GATE ... verdict=proceed`: the chain runs, the sinkhole logs recon,
   `/install.sh`, ten beacons and the exfil POST, and the graph shows the phases.
   If it still evades, `--why` shows which check and which Stealth entry to
   change (a virtio disk or card, or a preset without the CPU entries).

Tests: `python3 tests/monitor/test-evasive-sample.py` builds the binary and runs
both paths against fixture directories (`--test-root DIR` reads every `/sys` and
`/proc` file below `DIR`; `DIR/overrides` fakes CPU count, RAM, disk, process
count, `container` and the TRACEME result). The flag is for tests only and is
not part of the default behaviour.

## Simulating the connection and the exfiltration

Pick by what you want to prove.

### 1. Refused connect: the baseline, no setup

Leave the guest network isolated or point at a closed port. The sample records
`socket`, `connect`, `sendto` and the failure reason:

```sh
./demo-http-beacon --host 127.0.0.1 --port 9 --rounds 1
```

Expect `Connection refused` and `0/1 check-ins`. Use this to verify the syscall
view, error classification and the "attempted, not delivered" wording. The
download scenarios print `UNAVAILABLE ... nothing was fetched` and run nothing.

### 2. The sinkhole: a complete exchange (recommended)

`sinkhole.py` answers every protocol the samples speak, so the sample's
`recv` path also runs and the capture contains request *and* response. It is
in the repository, needs only Python 3, and nothing leaves the machine.

```text
Demo sinkhole           log: /tmp/demo-sinkhole-1000/sinkhole.log

  listener  address                serves
  http      127.0.0.1:8080         GET /install.sh /payload.elf, POST /gate.php, PUT /upload
  http-alt  127.0.0.1:9080         off-standard HTTP port (c2-misc)
  tls       127.0.0.1:8443         ClientHello read, answered with an alert (tls-sni)
  tls-alt   127.0.0.1:9443         off-standard TLS port (c2-misc)
  udp       127.0.0.1:4444         JSON check-ins and the datagram burst
  dns       127.0.0.1:5353         A/TXT, NXDOMAIN for DGA names, mode auto
  ssh       127.0.0.1:2222         SSH banner (c2-misc)
  irc       127.0.0.1:6667         IRC and Stratum text (c2-misc)
  shell     127.0.0.1:4445         reverse-shell echo sink, read-only (shell-sim)

  Give the samples:  --host 127.0.0.1 --dns-port 5353
```

- `--host ADDR` is the listen address and the `--host` to give the samples;
  `--nat` listens on 0.0.0.0 and shows `10.0.2.2` (NAT, not Isolated, in the VM
  settings); `--guest-host ADDR` overrides what is shown. Every port has a flag
  (`--http-port`, `--tls-port`, `--udp-port`, `--dns-port`, `--alt-http-port`,
  `--alt-tls-port`, `--ssh-port`, `--irc-port`, `--shell-port`).
- Port 53 needs root. Without it the sinkhole listens on 5353 and says to pass
  `--dns-port 5353` (an explicit `--dns-port` is never changed).
- DNS (`--dns-mode auto`): names are answered with `--dns-answer` (default the
  address shown for the samples) and TXT with a fixed string; names that look
  generated (10 to 18 letters under .com/.net/.org/.info/.biz) and `.onion`
  names get NXDOMAIN, so the DGA scenario has failures to count and one answer
  to trust the resolver by. `nxdomain` and `answer` force one outcome.
- TLS: the ClientHello is read, the SNI logged, and a fatal handshake_failure
  alert returned. No certificate is needed.
- HTTP: `/install.sh` and `/payload.elf` return the fixed bytes whose SHA-256
  is compiled into the samples (`samples.h`); `/gate.php` returns a small JSON
  task; other paths return `{"ok":true}`. Nothing is ever sent as a command;
  the shell sink only reads what the stand-in shell echoes.
- Log lines are aligned: `time  proto peer scenario request`, filed under the
  scenario that sent them (from the path, a `scenario=` field, the SNI or the DNS
  name). Repeats are rate limited (the first five, then every 100th).
- Ctrl-C (or SIGTERM) stops every listener, then prints a per-scenario summary:
  events, bytes and protocols for each network scenario, and which scenarios
  sent nothing (`--summary-json PATH` writes the same as JSON).
- The log is not written to the repository: the default is
  `<temp dir>/demo-sinkhole-<uid>/sinkhole.log` (mode 0600); `--log PATH`
  chooses another. `--pwned` prints a banner and a `PWNED` line per payload.

Unit tests: `python3 tests/monitor/test-sinkhole.py` (the pinned hashes
match `samples.h`, the payloads, the DNS policy, shutdown, the log path and the
rule ids).

### 3. NAT guest and host listener

Antinomie launches QEMU with `-netdev user,id=net0` when NAT is on; Isolated
adds `restrict=on`, which blocks guest to host, so this needs NAT. Under QEMU
user networking the guest reaches the host at **10.0.2.2** (DNS is 10.0.2.3,
the guest itself 10.0.2.15). Start the sinkhole with `--nat`, run the samples in
the guest with no `--host` (they default to `10.0.2.2`), and confirm
reachability with `nc -vz 10.0.2.2 8080` if nothing arrives. slirp proxies the
connection, so the sinkhole sees the source as 127.0.0.1; the payload's `host=`,
`uid=` and `arch=` fields identify the guest.

This proves the payload left the guest and reached a host service. It is not a
reverse shell: the listener only prints and answers, so no attacker code runs on
the host.

### 4. Capture only

If the point is the capture and not the reply, pass `--host 198.51.100.23`
(TEST-NET) or leave the guest disconnected, and record on the guest interface.
TEST-NET traffic is routed to the default gateway, so the packets appear in the
capture even though no reply comes back. Behind a transparent proxy TEST-NET
connects can be *accepted* while returning no data; the samples then say
"request sent, no response" rather than claiming delivery.

## Using them in Antinomie

1. Build, then upload `demo-all` (or one `demo-*`) to a VM.
2. Set the VM to **NAT**, start the sinkhole with `--nat`, run
   `./demo-all --rounds 1` and read the scorecard.
3. Open Triage > Suspicious activity and the activity graph; the phases in the
   table above should appear in order. Use `RULES` or a `SCENARIO` line's
   `expect=` to check each id.
4. `--keep` leaves the work directory (`stage/recon.txt`, the lookalike
   persistence files, the decoys, `.cache/install.sh`) for the Files tab and
   YARA scans.
5. Run `demo-sandbox-probe` once with the default profile and once with a
   Stealth profile to see which answers change.

`memfd-exec`, `inject-sim` and `ptrace-antidebug` are the scenarios to run when
the guest uses a ptrace-based monitor; under one, `PTRACE_TRACEME` is refused
with EPERM and an attach to a child may fail, which turns those rows into failed
attempts. The memfd child announces itself as `memfd-child` and exits
immediately, so it cannot start another generation.

`recon` reads `/etc/os-release` when present and falls back to `uname -sr`.
`cred-read` only reads decoy files it writes itself; with `--cred-home` it puts
the home-relative decoys at the real paths (for the rules keyed on `~/.aws/...`),
creating only missing files with `O_EXCL` and deleting everything it created
even with `--keep`.

### `--real-paths` and `--wide`

Both are off by default and the scenarios say `SKIP` until asked.

- `--real-paths` (`real-path-probes`): opens real system paths in ways that
  cannot change or read anything. The write probes name files that do not exist
  (for example `/etc/cron.d/demo-sample`), use no `O_CREAT`, and are skipped if
  `lstat` finds the path; the read probes (`/etc/shadow`, input, framebuffer,
  video and audio nodes) call `open` and `close` and never `read`. Most fail with
  ENOENT or EACCES, and the rows are marked `failed`.
- `--wide` (`net-wide`): 15 non-blocking connects toward 203.0.113.0/24 and
  1.12 MB of zeros over a connected UDP socket to 203.0.113.9:9. That block is
  reserved for documentation; the packets leave the guest and are dropped.

The server names, URIs, User-Agent and SNI are intentionally stable strings so
static analysis and network triage have something deterministic to report.
