# Implementation record: Network and routes

Network routes, the IOC window and Network tabs, and the abuse.ch Suricata packs. Part of the [implementation record](../implementation.md).

### abuse.ch Suricata rule packs with update checks (0.7.1)

Host only. `monitor-core/src/ruleset/abusech.rs` and `monitor-ui/src/rules_window/abusech.rs`
(the **abuse.ch** tab of the IDS engine).

* **Packs.** `LIVE_PACKS`: `abuse-ch-threatfox` (`threatfox_suricata.tar.gz`) and
  `abuse-ch-urlhaus` (`urlhaus_ids.tar.gz`), both under
  `…-api.abuse.ch/v2/files/exports/<key>/` (Auth-Key),
  `abuse-ch-feodo`, `abuse-ch-sslbl-ja3` and
  `abuse-ch-sslbl` (the certificate pack that was already in the catalog, same
  id). Each is a `SourcePack` for the `ids` engine built from the file that was
  just downloaded, so it goes through `install_source` like any pack (filter,
  index, provenance, the previous version kept on failure). The aggressive files
  are never listed.
* **Pin.** The publisher rewrites the file in place, so the pin is the snapshot:
  `revision` is abuse.ch's `Last updated` stamp (`YYYYMMDDTHHMMSSZ`, or `snapshot`
  when the file states none) plus the first 8 hex of the SHA-256, and the source
  is a pinned `file` download with that digest, so the install verifies exactly
  what was checked.
* **Archives.** `rules_text` recognizes a download by its first bytes: gzip is
  read as a tar, `PK` as a zip, anything else as the rules text itself. Only
  regular files whose name ends in `.rules` are taken (symlinks, hard links,
  directories and every other member are skipped; a name with `..`, a leading
  `/`, a backslash or a drive letter is skipped). Limits: 2,000 entries read,
  64 rules files, 32 MiB of rules text in all and per member, and the gzip
  stream is cut at four times that; an archive with no `.rules` member is an
  error. The members are joined in name order into one rules text, and that
  text is what is cached, pinned and installed (so the pin and the `file`
  format below are unchanged). Nothing is ever written under a member's name.
* **Retired pack.** `retired_if_empty` marks the SSLBL JA3 pack: if abuse.ch
  serves `ja3_fingerprints.rules` empty, an empty or comment-only file is a
  valid answer with 0 rules (HTML or other text is still an error);
  `live_states` reports `LiveStatus::Retired`, the tab shows "Retired
  upstream" with the install buttons off, and `install_live` returns a message
  rather than installing. The SSLBL IP list (`sslipblacklist.csv`/`.rules`,
  header only since 2026-06-30) has no dataset and no pack; a stored copy under
  `ioc/feeds/sslbl-ip/` is ignored and `update_all` removes it
  (`feeds::remove_withdrawn`). IP matching comes from `feodo`, `threatfox`
  `ip:port` and `urlhaus` (URLs and IP hosts).
* **Check and update.** `check_live` downloads the file into staging, unpacks
  it, refuses anything without a rule line, keeps it as `rules/live/<id>.rules` and records
  `{at, sha256, size, stamp, rules}` in `rules/live/checks.json`. A pack is not
  requested again until [`MIN_CHECK_SECONDS`] (300) have passed; inside that
  window the recorded answer is returned and no request is made, however often the
  button is pressed. `install_live` runs a check (reusing a fresh one) and installs
  from the kept file through a `Fetcher` that copies it, so check plus install is
  one request. `live_states` compares the installed pack's download digest with
  the last snapshot: Not installed, Not checked, Up to date or Update available.
* **Key.** The Auth-Key is a path segment of the two keyed URLs, so it is
  handled as a secret everywhere a URL goes. `Curl` (`ruleset/source_fetch.rs`)
  passes the URL to curl as a configuration on standard input (`-K -`,
  `url = "…"`), never as an argument, so it is not in `ps` or
  `/proc/<pid>/cmdline`; a URL with a quote, backslash or control character is
  refused. The `Curl` type no longer holds a key or sends an `Auth-Key` header
  (the online IOC check and the sample search still send theirs on stdin, as
  before). `redact_url` turns `/exports/<key>/` into `/exports/****/` in every
  message `Curl` produces (timeouts, size limits, redirects, HTTP status, curl's
  stderr) and in `https_host` errors; `update_feed` and `check_live` also
  remove the key text itself with `api_keys::redact`, so an error that echoes
  the key without a URL is covered. Stored URLs (`meta.json`, the source pack
  and registry) use `url_display()`. The key must be letters, digits and
  `- _ . ~` (checked when it is saved and again when a URL is built). Status
  codes: 401 or 403 from an abuse.ch host is "abuse.ch rejected the Auth-Key
  (HTTP 401); check it in Tools > API keys, or get a free one at auth.abuse.ch",
  404 is "abuse.ch has no file at this address (HTTP 404); the export may have moved
  or been renamed, so update Antinomie", 410 is "abuse.ch has retired this
  endpoint (HTTP 410); update Antinomie", 429 and 5xx say to try again later. A feed
  that needs the key and has none is refused before any request ("needs the abuse.ch
  Auth-Key (free at auth.abuse.ch); set it in Tools > API keys"). The free-space check
  of a dataset download is three times its expected size (at least 64 MiB), not the
  sum of the largest download and text the limits allow.
* **Tests.** Fixtures in the packs' real format and mock fetchers; no request
  leaves the machine.

### IOC window and the Network tabs (0.7.1)

Host only. Core: `monitor-core/src/ioc/` (`indicator`, `verdict`, `online`,
`export`, `strings`, `disk`). Triage model (0.9.0, `crates/triage/src/`): `ioc_scan.rs`,
`ioc_view.rs` (row fields and values, verdict line, jumps) with its fixtures, `net_tabs.rs`
(columns, `capture_zone_shift`), `rules/ioc.rs`, `files/ioc.rs`. UI: `monitor-ui/src/triage/`
`ioc_view.rs` and `ioc_view/` (tabs, chips, tables), `net_tabs.rs` (the Network tabs).

* **Collector.** `indicator::Collector` merges plain observations into
  `Indicator`s of five types (endpoint, domain, URL, TLS group, file), each with
  its sources, first and last time (host microseconds), per-source details,
  evidence jumps and the normal-form values it can be matched by (`lookups`).
  A private address, a local name or a file with no content has no lookup and
  reads `Not checked`. A process is named only when exactly one process made a
  matching call: an endpoint by its own `connect`/`sendto` calls, a URL or TLS
  row by its `ip:port`, a domain by the addresses it resolved or reached, a file
  by the task that made the call; several processes give `candidates` and no name.
  Each list stops at 20,000 and counts what it dropped.
* **Where the observations come from.** The packet scan: `Inventory`
  (`triage/network.rs`) now also keeps the remote `ip:port` of every frame (the
  non-local side, else the lower port), HTTP requests, DNS answer codes and TLS
  sessions (client hello joined to the server hello and certificate by
  `tcp.stream`; the certificate SHA-1 is computed from TShark's DER; TLS 1.3 hides
  the certificate). New TShark fields: `tls.handshake.ja3s`,
  `tls.handshake.certificate`, `frame.len`,
  `tls.handshake.extensions.supported_version`. The rules pass
  (`rules/ioc.rs`) logs each `connect`/datagram `sendto` and each successful exec
  (with the guest's SHA-256 of the image when it is the program itself). The files
  come from the existing `Change` records (`files/ioc.rs`): created, written at
  close (with the guest's hash), changed, deleted. The sample's hashes and strings
  come from the static report (`strings::scan` finds `ip:port`, URLs and domains;
  file extensions are not domains). Not collected: the eBPF/audit `connect`
  records (`kernel` source).
* **Disk hashes.** `ioc/disk.rs`: with a saved, readable disk dump in the run's
  recording folder, the created, changed and written files (up to 2,000, 256 MiB
  each) are hashed by the sandboxed disk reader (`DiskRequest::Info`) for SHA-256
  and MD5; the answer is kept while the dump and the list stay the same.
* **Matching.** `verdict::scan_datasets` reads each usable feed once, as a stream,
  for the set of wanted values; `Scan` indexes the hits by value (at most 6
  records per value). `evaluate` decides the verdict from the loaded feeds that
  can answer for the type (`coverage`), the hits, the known false positives
  (`known_fp::find`, an entry for a dataset excuses only that dataset) and any
  online answers; the date is that of the oldest feed that answered (the feed that
  matched, for a match). A TLS row needs an SSLBL feed (JA3 or certificate). The answer is cached in
  `ScanRequest::ioc_cache` under a key of the wanted values and the datasets'
  `(id, fetch time, switch)` list, so the 5-second refresh of a live run does not
  read the feeds again; a dataset update, a false-positive entry or an online
  answer changes the scan's stamp and rescans.
* **Findings.** `ioc_scan::list_findings` hands each Matched indicator to
  `Engine::ioc_match`, which records a `c2.ioc_match` row (category C2, T1071,
  tier by confidence) with packet or call evidence, folded by task and object, so
  it reaches the findings journal, the graph, the Summary and the live toast like
  any other row. Known FP and online-excused values make none.
* **View.** `View` keeps tab, filter text (the table filter language,
  `FIELDS`), verdict chips, selection, the verdicts (rebuilt when the scan, the
  false-positive list or the online answers change), a session-only online
  switch and the online job. Export writes `<run>/ioc/ioc-<type>-<time>.csv|json`
  (files 0600, never replacing one; CSV cells that start with `=+-@` get a
  leading apostrophe). The online check (`ioc/online.rs`) asks ThreatFox
  `search_ioc`/`search_hash` and URLhaus `host`/`url`/`payload`, key on curl's
  stdin, only to abuse.ch hosts, 50 values at most per press, and stops at the
  first refusal.
* **Network section.** It shows Endpoints, Domains, URLs and TLS (`net_tabs.rs`).
  The 0.7.0 layout (IPs, Hosts, HTTP, DNS, Sessions) and the switch to it were removed
  after 0.7.1's preview: the scan no longer pages those rows (the DNS and session rows
  still go to the observer for the detection rules, the Domains and TLS tabs and the
  journal). The tables use their own query slots (17 to 19; URLs reuse slot 3 and its
  HTTP fields), and
  `ENDPOINT_FIELDS`, `DOMAIN_FIELDS` and `TLS_FIELDS` keep the old names
  (`network.country`, `dns.name`, `session.alpn`) beside new ones. The IOC column
  is added after paging, from the verdicts of the same scan.
* **Tests.** Core: record parsing of each feed format from small fixtures, the
  collector's process rule, verdicts under missing, partial, old datasets, false
  positives and online answers, the online request shapes and key handling with a
  mock transport, the CSV/JSON export. UI: a fixture pcap scanned with and without
  datasets (served by a mock fetcher), the finding and its removal by a false
  positive, the tabs and the layout switch, export, the session-only online
  switch, and the rules-pass recorder.

### Network routes (0.7.1)

Per-run routing of the guest's traffic, modelled on CAPE's rooter options (none,
Internet, InetSim, Tor, VPN) but without a root daemon: no iptables, no network
namespace, no TUN or tap device, no `sudo`. Host side only; nothing is installed
or patched in the guest. Code: `monitor-core/src/route.rs` and `route/`, the
backend wiring in `backend/run_route.rs`, the interface in
`monitor-ui/src/route_ui.rs` and `app/route_settings.rs`.

**How guest networking worked.** A VM's network was QEMU user networking
(`-netdev user,id=net0`, with `restrict=on` for Isolated) or no card at all
(`-nic none`); `nat` and `isolated_network` in `VmConfig`. A network capture is
a `filter-dump` object attached to `netdev=net0` over QMP, so it records the
frames the guest NIC sees. The user-mode netdev is fixed for the VM's life,
and slirp cannot send a connection through a SOCKS proxy, so a route cannot be
chosen per run on it.

**The Routed network.** A third mode, `VmConfig::routed` (VM dialog: Network >
Routed), wires the NIC (`nic_option`, unchanged, so the stealth profile still
applies) to `-netdev stream,id=net0,server=off,addr.type=unix,addr.path=<runtime
folder>/net.sock` (QEMU 7.2 or newer; checked before launch). The socket is
owned by a `Gateway` thread inside Antinomie, created before QEMU starts and
stopped with the VM process (`VmProcess::gateway`). The gateway is the guest's
whole network: ARP (MACs `52:55:` plus the address, as slirp does), a DHCP
server giving the lease QEMU's user network gives (10.0.2.15/24, router
10.0.2.2, DNS 10.0.2.3, or the profile's NAT network, so the guest configures
itself unchanged), a DNS server, ICMP echo for its own addresses, and a small
TCP endpoint per guest connection (`tcp.rs`: in-order segments, constant window,
go-back-N retransmission; the link is a local socket and loses nothing). Each
accepted connection is dialed upstream on a thread (`upstream.rs`) and the bytes
are relayed through bounded queues, so a slow upstream is a segment the guest
retransmits. IPv6, fragments and everything else are counted and dropped.
Because the capture is on the NIC, **the pcap is the guest-side view on every
route**; nothing about capture changed.

**Routes.** `RouteKind`: `Drop`, `Internet`, `InetSim`, `Tor`, `Vpn`, `Socks5`.
The gateway starts on `Drop` (nothing leaves) and a run changes it only through
`Gateway::claim`.

| Route | DNS | TCP | Other UDP |
|---|---|---|---|
| Drop | unanswered (counted) | SYN dropped, like a firewall (counted) | dropped, counted |
| Internet | the host resolver, on a thread | the host connects, public addresses only: not the gateway, the guest network, loopback, link-local or (unless allowed in Settings) RFC 1918 | dropped, counted |
| InetSim | every A query answers the sinkhole (198.51.100.1), AAAA is empty | any address and port reaches the built-in services (HTTP, SMTP; other ports accept and discard, no TLS) or an external INetSim at `port + offset` | dropped, counted |
| Tor, VPN, SOCKS5 | every A query answers a placeholder in 198.18.0.0/16 and the gateway remembers the name; the connection to that address is sent to the proxy as the **name** (SOCKS5 `ATYP 3`), so the proxy resolves it and no lookup leaves the host | SOCKS5 CONNECT through one upstream path (`socks.rs`, RFC 1928 with RFC 1929 login) | dropped, counted |

* **One upstream SOCKS5 path.** Tor is either Antinomie's own tor (`TorMode::Own`,
  the default; see below) or a SOCKS address the analyst gives (`TorMode::Socks`,
  default 127.0.0.1:9050, nothing started). VPN is
  WireGuard through **wireproxy** (ISC licence): a userspace WireGuard client that
  exposes a SOCKS5 port, run as a separate process with the analyst's own
  configuration file. Antinomie starts it for the run (`managed.rs`: stdout and
  stderr to an owner-only `wireproxy.log`, refuses to start when something else
  already listens on its port, waits for the port, kills it by its recorded
  handle when the route is released or the VM ends). SOCKS5 is any proxy the
  analyst gives, with optional user name and password.
* **OpenVPN is unsupported.** It needs a TUN device (root or `CAP_NET_ADMIN`)
  and there is no userspace OpenVPN client that exposes a socket. An analyst who
  has OpenVPN can run it in a container or namespace of their own with a SOCKS5
  front end and use the SOCKS5 route. Antinomie never uses `sudo`.
* **DNS and UDP.** Over SOCKS5 and Tor, DNS is SOCKS5 hostname resolution (Tor's
  DNSPort is not needed). UDP is not carried (SOCKS5 UDP ASSOCIATE is not used,
  Tor does not support it): UDP other than DNS and DHCP is dropped and counted.
  A name that does not exist therefore shows as a refused connection rather than
  NXDOMAIN. The 198.18.0.0/16 placeholders are cleared when the route changes.
* **Own tor** (`route/tor.rs`). `start_tor` runs in `Gateway::claim` through
  `managed::start_for`, so a failure drops the process and leaves the gateway on
  Drop. It makes `<data>/network/tor/<slot>` (the slot is the gateway's runtime
  folder name; one tor per gateway, so two VMs never contend for a DataDirectory
  lock) and its `data` folder with mode 0700, writes `torrc` (0600) with
  `DataDirectory`, `SocksPort 127.0.0.1:<free port>`, `ControlPort 0`,
  `CookieAuthentication 0`, `ClientOnly 1`, `SafeLogging 1`, `Log notice file
  <slot>/tor.log` and, for the bundle, `GeoIPFile`/`GeoIPv6File`; no other
  listener is configured. The port comes from binding 127.0.0.1:0 and releasing
  it; if something takes it first tor cannot bind, exits, and the route reports
  tor's own output (`tor.out`). tor runs with `--defaults-torrc` pointing at an
  empty file and `-f torrc`, so the system's torrc files are not read. No control
  connection is used: bootstrap progress is the last `Bootstrapped N%` line of
  `tor.log`, truncated at each start, and 100% is the ready signal. The wait is
  `managed::TOR_WAIT` (120 s); on expiry the error gives the last percentage and
  its text and the log path. The bundle's tor needs its own libevent and OpenSSL,
  so for the managed copy `LD_LIBRARY_PATH` is set to its `tor/` folder; a tor
  from the system or a path the analyst set runs with the environment as it is.
  The route's SOCKS port is filled in after tor starts (`RouteSpec::set_socks_port`)
  and the usual SOCKS check (greeting plus the check target) runs before the
  claim succeeds. The settings Test uses the slot `settings-test`.
* **Tools.** INetSim (GPL-2.0) is user provided and not bundled. tor
  (BSD-3-Clause) and wireproxy (ISC) are run as separate processes and are found
  in this order by `config::find_program`: the path set in Settings (an error if
  it is not a file), `PATH`, the usual system places
  (`analysis_tools::system_candidates`), then Antinomie's own copy. The own copy
  is a managed tool in `analysis_tools.rs`, installed on request and not part of
  first run or the Library tools list (`is_route_tool`); Settings > Network routes
  draws its row with `tools_page::tool_row`, the row Library uses. wireproxy 1.1.3
  is the `wireproxy_linux_amd64.tar.gz` asset of windtf/wireproxy (SHA-256
  `e88c1d09...`, the digest GitHub lists). Tor is the Tor Expert Bundle 15.0.26
  (Linux x86-64; tor 0.4.9.14) from archive.torproject.org, which keeps old
  versions where dist.torproject.org does not (SHA-256 `19cf1872...`). The
  installer checks the SHA-256 only. The bundle's OpenPGP signature (Tor Browser
  Developers key, EF6E 286D DA85 EA2A 4BA7 DE68 4E2C 6E87 9329 8290) was verified
  once with `gpg` when the pin was made. Checking it at install time would need
  the key shipped and an OpenPGP implementation (a new dependency, or `gpg`
  on the user's machine) and would check nothing the pinned hash does not, since
  the hash names those exact signed bytes.

**Fail closed.** `route::claim_for_run` runs before the run's directory or
artifacts exist. It picks the route (the request, else the saved default), builds
the checked `RouteSpec` (a missing setting, file or program is an error) and calls
`Gateway::claim`, which starts wireproxy, then **proves the route is up**: a SOCKS
route must answer the SOCKS5 greeting and login and, when it has a check target
(defaults: `check.torproject.org:443` for Tor, `1.1.1.1:443` for SOCKS5), connect
to it through the proxy; an external INetSim must accept a connection. Any
failure is the run's error, the gateway stays on Drop, wireproxy is stopped, and
nothing falls back to another route or to the host's network. A VM that is not
Routed has one fixed network: a request for another route is an error. A route
that goes away mid-run (the proxy dies) makes new connections fail (refused), it
does not redirect them. When the last run holding a route ends, the gateway goes
back to Drop, every connection made under the route is reset and wireproxy is
stopped (each connection and each placeholder address carries the route
generation it was made under, so a connection opened right after a claim is not
mistaken for an old one). ICMP echo is answered for the gateway's own addresses
only and counted otherwise. Runs that overlap on one VM must use the same route
("another run in this VM is using the route ..."). The check runs on the worker
thread before the sample starts, at most about 30 s for wireproxy (start 15 s,
check 15 s) and up to about 135 s for the own tor (bootstrap 120 s).

**Metadata.** `RunSummary::route` (`run.json`) and `RunArtifacts::route`
(`artifacts.json`) hold a `RouteRecord`: `kind`, a plain-text `label` (`Tor via
127.0.0.1:9050`; host and port only), `via` (`gateway`, `vm_nat`, `vm_isolated`,
`vm_disconnected`), `checked_ms` and, once the run's process tree ends, `stats`
(TCP connections, failures, blocks, DNS queries and unanswered, UDP/ICMP/other
dropped, bytes). Counts are for the whole VM during the run, like the capture.
Both fields are absent in older runs, which the UI shows as "Not recorded". A run
restored from a snapshot keeps its record, gets an issue saying the route is not
carried over, and the restored VM's gateway starts on Drop. `ExecRequest::route`
is the per-run choice (`None` is the saved default).

**Settings and secrets.** `<data>/network/routes.json` (`RouteConfig`) is
written through `storage::atomic_json` in a 0700 folder and chmod 0600, the same
as the sample sources' `api-keys.json`; it holds the default route, the Tor
address, the wireproxy program and configuration paths, the SOCKS5 host, port,
user name and password, the InetSim mode, host, port offset and sinkhole, and
the check targets. The backend reads it when a run starts, so the password is
never sent through the command channel. `Debug` for the SOCKS5 settings and the
resolved credentials is redacted; the password is not in a label, a record, a
log or an export (the wireproxy configuration is the analyst's own file and is
passed by path).

**Interface.** VM dialog: Network > *Routed (route per run)*. Run form, Network
section: the **Route** selector (a Routed VM; any other VM names its fixed
network) with what the route does and a warning for the Internet route or a
missing setting. Settings > Network routes: default route, per-route
configuration and a **Test** button (brings the route up the way a run would,
including wireproxy and the own tor). The Tor and VPN sections show the
program's status, version and Install/Remove button. The route is shown in Run History's run details, above the
Triage run header, in Triage > Summary > Network evidence and in Triage > Network.

**Tests.** `route/tests/` drives the real gateway over a Unix socket with a
scripted guest (DHCP, ARP, DNS, a small TCP client with retransmission) and a
fake SOCKS5 server that is also the far end: Drop, InetSim (built-in and
external), Tor, SOCKS5 with login, refusals, fail-closed claims, overlapping
runs, reset on release, 400 KB up and 500 KB down, wireproxy start and stop with
stand-in programs, and the own tor with a stand-in `tor` script (private modes,
torrc contents, library path, bootstrap parsing, a tor that exits, stalls or
does not speak SOCKS, stop on release). The managed tools are tested with the
pins and unpacking only; no test downloads anything. No real Tor, VPN or Internet traffic is used.

**Captures and failed starts on a Routed VM (0.8.0, ANT-T0182).** A Routed VM's NIC is
`net0` like any other, so the run's network capture and the toolbar capture attach to
it. Before, `prepare_network_capture` refused every VM with neither `nat` nor
`isolated_network` set ("this VM has no network: select NAT or isolated network"),
which a Routed VM is: every run with *Capture network* on a Routed VM failed, on every
route, after its record existed, and Run History listed it as Unknown. The check now
reads `VmConfig::has_network()`, and a capture on a VM without a network card is
refused before the run exists (`NO_NETWORK_CARD`), as are a route the VM's network
cannot carry and a route that is not set up or does not answer: nothing is listed for
them. The Run form says so first: the capture box is off on a VM without a network
card with a **VM settings…** button, and a route whose settings are missing has an
**Open Network routes settings** button. `examples/route-check.rs` (full tier `route`) runs
`tests/monitor/route-probe.c` on every route of a Routed VM with a cloud profile, on a
NAT VM and on a VM without a card; Tor, VPN (a stand-in wireproxy) and SOCKS5 go to
local fake proxies that answer the probe's one HTTP request themselves and record the
name they were asked to connect to; the Internet route sends one plain `GET /` to
example.com.

**Routes across a restore, a reconnect and a stopped helper (0.8.0, ANT-T0182).**
The host checkpoint (`HostCheckpoint::route_claims`) lists the runs that hold their
route on the gateway, with the counters at their claim. A transport reconnect keeps
the VM process and its gateway, which still holds the route under the same run id:
the new timeline's owner takes the claim over, so the route is released when the
run's tree ends (before, the claim was lost and the route stayed up after the run).
A restored full snapshot has a new gateway on Drop: `run_route::restored_route`
claims the run's route again for the restored run, starting wireproxy or tor and
checking it, before the guest's CPUs run. If it cannot (settings changed, proxy
down), the gateway stays on Drop and the run's issues say "could not be brought back
after the snapshot restore". A checkpoint written before 0.8.0 does not say: a live
run with a gateway route is taken as holding it. The gateway also watches the route's
program (`Gateway::helper_stopped`, checked each second with the resource sample):
when wireproxy or tor exits while runs hold the route, the gateway installs a route
that drops everything (whatever listens on the port later is not the route), refuses
new runs on it ("went down during another run in this VM"), and every run holding it
gets the issue "the route … went down during the run: wireproxy stopped (exit status:
7) …", shown as a notice too. The last run out puts the gateway back on Drop and
clears it. `route-check` checks both on the Routed VM (a fake wireproxy told to exit
mid-run; a full snapshot of a run waiting on InetSim, restored and let go).
