# Antinomie implementation record

This is the implementation contract: a chronological record of the behaviour,
wire contracts, limits and measurements implemented in each Antinomie release.
Every section names the release it belongs to, and sections headed "Accepted"
record the requirements as implemented for that release. Where a newer section
conflicts with an older one, the newer section supersedes it; older sections are
kept for the releases they describe. User-facing documentation lives in
[`README.md`](../README.md) and [`docs/usage.md`](usage.md).

How paths are written. A path such as `scripts/check-kernel-btf.py`,
`tests/monitor/route-probe.c` or `docs/usage.md` is relative to the repository
root. A Rust path such as `debug/rsp_client.rs` or `triage/files.rs` is relative to
`src/antinomie/monitor/crates/monitor-core/src/` or `.../monitor-ui/src/`, whichever
holds it. From 0.9.0 the Triage model (scan, activity rules, query language, bpf decoder) is in
the `antinomie-triage` crate: a `triage/<file>.rs` of it is `.../crates/triage/src/<file>.rs`. A path under `kernel/antinomie/`, `arch/`, `fs/` or `include/`, and the
kernel's own `scripts/` files (`scripts/antinomie_btf.py`, `scripts/link-vmlinux.sh`,
`scripts/Makefile.modfinal`), belong to the patched Linux 6.12 tree that the
series in `src/antinomie/core/6.12/` builds, not to a folder of this repository;
the patch that adds or changes a file is named where it matters ("Patch 0019").

## Current licensing boundary (0.7.0)

Original host application, host transport, scripts, tests and product
documentation use GPL-3.0-only from 0.7.0. The shared kernel headers remain MIT;
kernel implementation and historical patch exports keep their kernel terms.
Imports and separately installed tools/rules retain their own licenses. Earlier
releases and the separate documentation/website repositories retain their
original license scopes. `scripts/check-licenses.py` validates the boundary and
locked dependency license expressions, and records notice-document gaps without
claiming full legal clearance. Release packaging includes that inventory.

Work on the initial release started on 2026-10-01.
The accepted 0.5.0 snapshot/reconnect extension below supersedes the historical
V7-only restriction; older requirements remain recorded for their releases.

## Sections by area

The record is split by area; inside each file the sections keep their original
order, and each is headed with its release.

| File | Holds |
|---|---|
| [Guest, kernel and transport](implementation/guest-and-kernel.md) | Accepted requirements for the guest tracer and the telemetry transport, VM regression tiers, guest patch series and architectures, the Debian-neutral kernel BTF, native syscalls, the telemetry protocol and host/control contract. |
| [Host UI](implementation/host-ui.md) | The debugger tabs, performance and background tasks, status cards, upload and picker follow-ups, tab docking, display settings and terminal windows. |
| [Triage and analysis](implementation/triage-and-analysis.md) | Run triage, Suspicious activity, the activity graph, file activity, static analysis, regex matches, IOC datasets, detection inputs and run state questions. |
| [Network and routes](implementation/network-and-routes.md) | Network routes, the IOC window and Network tabs, abuse.ch Suricata rule packs. |
| [Disks, memory and recording](implementation/disks-memory.md) | The Disks tab, process cores, MemNixFS, the recording quota and recording disk work. |
| [Bases and stealth](implementation/bases-and-stealth.md) | Debian module ABI and base builds, Debian bases, VM stealth profiles, Guest stealth and Cloud VPS profiles. |
