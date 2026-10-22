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

Some published crates omit their workspace's license files. The prepared
`LICENSES/third-party/cargo-upstream/manifest.json` records exact upstream
commits, source package checksums where available, source URLs and notice
hashes. Before use, the checker confines prepared paths to that directory and
verifies each hash. Standard license texts and original crate declarations are
retained for crates that supply no separate file; no copyright owner or year
is invented. Font data keeps its independent font licenses.

The inventory is a reproducible metadata/notice check, not a blanket assertion
of legal clearance. New dependencies or missing host notice documents need
review. Do not change imported licenses to the host license. The release
archive includes the inventory and notices; corresponding source access for
binary recipients remains a separate release obligation.
