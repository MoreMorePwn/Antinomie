# License inventory for release builds

From 0.7.0, original host code uses GPL-3.0-only. Shared headers remain MIT;
kernel and imported material retain their own terms. Earlier releases retain
their original license. LICENSING.md defines this boundary.

| Command | Result |
|---|---|
| `python3 scripts/check-licenses.py` | Validate the boundary and the license expressions of locked Cargo packages. Unsupported mandatory licenses, unknown exceptions and malformed expressions fail. |
| `python3 scripts/check-licenses.py --output DIR` | Also retain dependency notices and `manifest.json` in a new packaging directory. |
| `python3 tests/monitor/test-licenses.py` | Exercise alternatives, mandatory conditions, exceptions and malformed expressions. |

Cargo metadata uses the locked Linux x86-64 dependency graph, including build
and development dependencies. All returned package expressions are checked;
the manifest distinguishes reachable host packages from other target packages.
Cargo may fetch missing locked source packages on a cold build. Set
`CARGO_NET_OFFLINE=true` to require the existing cache.

| Manifest field | Meaning |
|---|---|
| `host_license` | License selected for the original application. |
| `packages[].license` | Upstream expression, preserved rather than relabeled. |
| `packages[].linux_x86_64_reachable` | Whether the package is in the filtered workspace dependency graph. This includes test/build tooling, not just linked runtime code. |
| `packages[].documents` | Retained relative notice paths and SHA-256 hashes. |
| `packages[].notice_status` | Whether documents were retained or only metadata is available. |
| `packages[].bundled_license` | Terms of an embedded C library the crate builds, where its metadata does not name them (see below). |

Some published crates omit their workspace's license files. The prepared
`LICENSES/third-party/cargo-upstream/manifest.json` records exact upstream
commits, source package checksums where available, source URLs and notice
hashes. Before use, the checker confines prepared paths to that directory and
verifies each hash. Standard license texts and original crate declarations are
retained for crates that supply no separate file; no copyright owner or year
is invented. Font data keeps its independent font licenses.

A crate whose sources embed a C library under terms its Cargo metadata does
not name is listed in the checker's `BUNDLED` table: `capstone-sys` (MIT
bindings) compiles the Capstone C library, BSD-3-Clause with LLVM-derived
tables under NCSA. The checker evaluates those terms like any expression,
records them as `packages[].bundled_license`, and fails when the bundled
notice files are not among the retained documents.

The inventory is a reproducible metadata/notice check, not a blanket assertion
of legal clearance. New dependencies or missing host notice documents need
review. Do not change imported licenses to the host license. The release
archive includes the inventory and notices; corresponding source access for
binary recipients remains a separate release obligation.

## DB-IP Lite (IP geolocation data)

Reviewed 2026-11-03 against the licence statements on
`https://db-ip.com/db/download/ip-to-country-lite` and `ip-to-asn-lite`: the
free Lite databases are licensed under Creative Commons Attribution 4.0
International; the user must give attribution to DB-IP.com for the data, and a
web application must link back to `https://db-ip.com` where results are shown
("IP Geolocation by DB-IP"). The download page asks the user to agree to these
terms; Settings > Network lookup states them next to the install button.
Antinomie downloads the files on request and does not redistribute them (the
optional full pack carries them unmodified with the licence note).

Attribution is shown in: Settings > Network lookup, Tools > App dependencies
(through the same status block), the Endpoints tab of Triage > Network, and the
notes of exported triage reports; it is listed in `THIRD-PARTY-NOTICES.md`.
The text lives in `monitor-core/src/geoip.rs` (`ATTRIBUTION`, `ATTRIBUTION_NOTE`).
