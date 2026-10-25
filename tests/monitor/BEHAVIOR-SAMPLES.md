# Behavior samples

`ant-sample-*` are small static x86-64 ELFs that reproduce the *shape* of attacker
behaviour for testing Antinomie end to end. They are not stress tests: each
scenario does one thing an analyst would triage, then exits.

Everything harmful is replaced by a harmless destination:

- the default endpoint is the QEMU user-network host `10.0.2.2`, so a NAT guest
  reaches a listener on the host and nowhere else; pass `--host 198.51.100.23`
  (RFC 5737 TEST-NET) or `--host 127.0.0.1 --port 9` for an offline baseline;
- `--host` and `--resolver` take numeric IPv4 only; no name is ever resolved, so
  the `.invalid` names appear only inside payloads (10.0.2.2 is a private
  address, but it is the host of QEMU and VirtualBox NAT only: on a machine
  whose own network uses 10.0.2.0/24, pass `--host` explicitly);
- downloaded bytes are counted, never executed (`memfd-exec` runs only a copy
  of its own binary);
- writes stay below a per-run work directory and are removed unless `--keep`
  (an existing `--workdir/<scenario>` is refused, never adopted); the only
  exception is the opt-in `--cred-home`, which creates missing decoys with
  `O_EXCL` and removes what it created;
- every loop is bounded by `--rounds` (1-50).

Options accept both `--host 10.0.2.2` and `--host=10.0.2.2`. A bare
`./ant-sample-all` runs every scenario; `--only a,b` selects a subset and `--list`
prints the registry.

## Build

```sh
tests/monitor/build-behavior-samples.sh /tmp/ant-sample-all
tests/monitor/build-behavior-samples.sh /tmp/ant-sample-all --dynamic
```

Static is the default (glibc, no `PT_INTERP`), which runs on every guest base.

## Scenarios

| Binary | Shape |
|---|---|
| `ant-sample-recon` | `uname`/hostname/uid fingerprint, staging file, exfil POST |
| `ant-sample-http-beacon` | periodic `POST /gate.php` check-ins, browser User-Agent |
| `ant-sample-dns-tunnel` | fingerprint hex-encoded into A and TXT questions |
| `ant-sample-tls-sni` | TLS 1.2 ClientHello with SNI `update.antinomie.invalid` |
| `ant-sample-udp-beacon` | JSON check-in datagrams to port 4444 |
| `ant-sample-download` | `GET /download.bin`, counted but never executed |
| `ant-sample-dga` | deterministic 2026-style DGA candidates, printed only |
| `ant-sample-persistence` | autostart, systemd user unit, crontab shape, self-copy |
| `ant-sample-memfd-exec` | anonymous memfd, RWX mapping, self re-exec via `fexecve` |
| `ant-sample-ptrace-antidebug` | `TracerPid`, instrumented mappings, `PTRACE_TRACEME` check |
| `ant-sample-cred-read` | decoy credential files read, standard paths only `stat`ed |
| `ant-sample-rule-markers` | MITRE/Sigma tag strings plus four benign discovery commands |
| `ant-sample-all` | every scenario in order |

Defaults: `--rounds 3 --delay 500`, host `10.0.2.2` (the QEMU NAT host), HTTP
8080, TLS 8443, UDP 4444, resolver `10.0.2.2`.

## Options

```text
--rounds N        repetitions per scenario (1-50, default 3)
--delay MS        pause between rounds (default 500)
--host ADDRESS    remote address (default 10.0.2.2, the QEMU NAT host)
--port N          override the scenario's port
--resolver ADDR   DNS server for dns-tunnel (default 10.0.2.2)
--workdir DIR     base for per-scenario work directories
--keep            keep the work directory for evidence inspection
--cred-home       cred-read: plant decoys under $HOME (never overwrites)
--list            list scenarios
--all / --only a,b   select scenarios in ant-sample-all
```

`SAMPLE_DNS_PORT` (environment) moves `dns-tunnel` off port 53, so a sinkhole can
run unprivileged.

## Simulating the connection and the exfiltration

The samples default to unroutable addresses so that nothing real is contacted.
That leaves three useful ways to get a *complete* exchange instead of a failed
connect. Pick by what you want to prove.

### 1. Refused connect — the baseline, no setup

Leave the guest network isolated or point at a closed port. The sample records
`socket` → `connect` → `sendto` and the failure reason:

```sh
./ant-sample-http-beacon --host 127.0.0.1 --port 9 --rounds 1
```

Expect `Connection refused` and `0/1 check-ins`. Use this to verify the syscall
view, error classification and the "attempted, not delivered" wording.

### 2. Local sinkhole — full application-layer exchange (recommended)

`sinkhole.py` listens on loopback and answers HTTP, TLS, UDP and DNS, so
the sample's `recv` path also runs and the capture contains request *and*
response. Nothing leaves the machine.

```sh
python3 tests/monitor/sinkhole.py \
    --http-port 8080 --tls-port 8443 --udp-port 4444 --dns-port 5353

./ant-sample-http-beacon --host 127.0.0.1 --port 8080 --rounds 1
./ant-sample-recon       --host 127.0.0.1 --port 8080 --rounds 1
./ant-sample-download      --host 127.0.0.1 --port 8080 --rounds 1
./ant-sample-tls-sni     --host 127.0.0.1 --port 8443 --rounds 1
./ant-sample-udp-beacon  --host 127.0.0.1 --port 4444 --rounds 1
SAMPLE_DNS_PORT=5353 ./ant-sample-dns-tunnel --resolver 127.0.0.1 --rounds 1
```

The sinkhole logs each exchange to stdout and `sinkhole.log`, decoding the HTTP
request line, User-Agent and body, the TLS SNI, the UDP payload and the DNS
question name. It also confirms the request is well formed, which is what makes
the Suricata/YARA rules in `feature-sample.rules` and `triage-sample.rules`
fire on a capture. Use `--dns-mode answer --dns-answer 127.0.0.1` to make the
tunnel resolver path succeed instead of returning NXDOMAIN.

`--dns-port 53` needs root; 5353 plus `SAMPLE_DNS_PORT` avoids that. The sample
still sends to 53 unless the variable is set, so set both or neither.

### 2b. NAT guest → host listener (prints PWNED)

Antinomie launches QEMU with `-netdev user,id=net0` when NAT is on; Isolated
adds `restrict=on`, which blocks guest→host, so this needs NAT. Under QEMU user
networking the guest reaches the host at **10.0.2.2** (DNS is 10.0.2.3, the
guest itself is 10.0.2.15). Nothing needs to be forwarded into the guest.

On the host:

```sh
python3 tests/monitor/sinkhole.py --nat --pwned \
    --http-port 8080 --tls-port 8443 --udp-port 4444 --dns-port 5353
```

`--nat` binds 0.0.0.0 and prints the guest-side recipe. In the guest:

```sh
./ant-sample-recon      --host 10.0.2.2 --port 8080 --rounds 1
./ant-sample-http-beacon --host 10.0.2.2 --port 8080 --rounds 1
./ant-sample-udp-beacon --host 10.0.2.2 --port 4444 --rounds 1
SAMPLE_DNS_PORT=5353 ./ant-sample-dns-tunnel --resolver 10.0.2.2 --rounds 1
```

The listener prints a banner on the first payload and a `PWNED <proto> <bytes>
from <guest>` line per hit, plus the decoded request. Confirm reachability from
the guest first with `nc -vz 10.0.2.2 8080` or `curl -s http://10.0.2.2:8080/`.
If that hangs, check host firewall rules and `ss -ltnp | grep 8080`.

This proves the payload left the guest and reached a host service. It is not a
reverse shell: the listener only prints and answers, so no attacker code runs on
the host. For an inbound host→guest test you would need QEMU `hostfwd`, which
these samples do not use.

slirp proxies the connection, so the listener sees the source as 127.0.0.1
rather than 10.0.2.15; the payload's `host=`, `uid=` and `arch=` fields identify
the guest. Binding the host listener to 127.0.0.1 is enough — `--nat` only
selects 0.0.0.0 and prints the recipe.

### 3. Host-side packet capture only — what the Network tab sees

If the point is the capture and not the reply, pass `--host 198.51.100.23`
(TEST-NET) or leave the guest disconnected, and record on the guest interface.
TEST-NET traffic is routed to the default gateway, so the packets appear in the
capture even though no reply comes back. Antinomie's Network tab (TShark decode,
Wireshark display filters)
then shows the request with `tcp.flags.syn == 1 and tcp.flags.ack == 0`, the
HTTP request in `http.request`, or the DNS query in `dns.qry.name`. This is the
closest to real attack traffic without contacting a third party.

Two environment caveats: behind a transparent proxy TEST-NET connects can be
*accepted* while returning no data — the samples then print "request sent, no
response" rather than claiming delivery. And an intercepting resolver may answer
`.invalid` names; use `--resolver` to aim at the guest nameserver deliberately.

## Using them in Antinomie

1. Build, then upload one binary to a VM.
2. Best path: set the VM to **NAT** (not Isolated), start the host listener with
   `--nat --pwned`, and run the sample with no `--host` (it defaults to
   `10.0.2.2`). The payload reaches the host and the listener prints `PWNED`.
3. Offline path: leave the guest disconnected or Isolated. Connects fail with
   `ENETUNREACH` (or `restrict=on`), which still produces the
   `socket`/`connect`/`sendto`/`sendmsg` records the syscall view shows.
4. `--keep` leaves `stage/recon.txt`, the persistence shapes and the decoy
   credential files for the Files tab and YARA scans.

Options accept `--opt value` and `--opt=value`; a bare `./ant-sample-all` runs all
scenarios, so `./ant-sample-all --rounds 1 --delay 0` is a quick full pass.

`memfd-exec` and `ptrace-antidebug` are the two scenarios to run when the guest
uses a ptrace-based monitor. The memfd child announces itself as `memfd-child`
and exits immediately, so it cannot start another generation; the antidebug
scenario reports a non-zero `TracerPid` and `PTRACE_TRACEME` refusing with EPERM,
both of which are the expected result under Antinomie's own monitor.

`recon` reads `/etc/os-release` when present and falls back to `uname -sr`, so
minimal guests report e.g. `Linux 6.12.94` instead of `unknown`.

`cred-read` only reads decoy files it writes itself. The real `~/.aws`,
`~/.ssh`, browser profile and `/etc/shadow` are `stat`ed for presence and never
read, so no guest secret leaves the VM. Pass `--cred-home` in a disposable VM
if you want the decoys at the real paths (for rules keyed on
`~/.aws/credentials`): it creates only missing files with `O_EXCL`, never
overwrites an existing one, and deletes everything it created even with
`--keep`.

The server names, URIs, User-Agent and SNI are intentionally stable strings so
static analysis and network triage have something deterministic to report.
