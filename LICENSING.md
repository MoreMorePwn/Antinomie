# Licensing and copyright

Original, independently licensable Antinomie code and documentation in this
repository, from 0.7.0 onward, are GPL-3.0-only under [LICENSE](LICENSE), unless a file-specific
notice or an exception below states otherwise.

Copyright (c) 2026 MikiMiku (MoreMorePwn).

This notice identifies the project owner's original contributions. It does not
claim ownership of dependencies, upstream code, other contributors' work or
third-party assets. Preserve their applicable notices and terms.

## Scope

| Material | License / treatment |
|---|---|
| Original Rust monitor, scripts, tests, packaging glue and documentation | GPL-3.0-only from 0.7.0, except explicitly marked or imported material |
| `scripts/build-base.py` | MIT, as marked; the base build orchestrator that the executable embeds in its base build kit next to the kernel material |
| `src/antinomie/transport/host.c`, `host_api.h` | GPL-3.0-only; independently built host transport |
| Original shared `abi.h`, `queue.h`, `bootstrap_layout.h`, monitor `protocol/control.h` | MIT; kernel copies retain this file-specific license |
| Kernel-only `transport/guest.c`, `bootstrap.c`, `guest_api.h` | GPL-2.0-only, as marked ([GPL-2.0-only.txt](LICENSES/GPL-2.0-only.txt)); excluded from root GPLv3 scope |
| Kernel changes and upstream context in `src/antinomie/core/` and `src/antinomie/patches/` | Kernel GPL/file-specific terms, unchanged. The separate licensing patch (0002) changes only original shared headers to MIT |
| Imported `src/debian/`, source archives, packaging references and patches | Existing upstream/file-specific terms; excluded from root GPLv3 scope |
| Community YARA rules (`crates/monitor-core/assets/rules/yara-forge-core.yar`) and capa-rules (`capa-rules-v9.4.0.tar.gz`) | Per-rule licenses (CC BY-SA 4.0, DRL 1.1, BSD-2-Clause, Apache-2.0, CC BY 4.0, MIT) and Apache-2.0; excluded from root GPLv3 scope. The YARA file is the prepared-pack source. Production scans do not load it; the rule manager (catalog schema 2) downloads each collection from its publisher instead of redistributing an archive. The published archive includes `LICENSES/third-party/rules/`. This is not complete legal clearance. See [third-party notices](THIRD-PARTY-NOTICES.md) |
| `LICENSES/third-party/`, dependencies and embedded fonts/icons | Their own licenses/notices; excluded from root GPLv3 scope; see [third-party notices](THIRD-PARTY-NOTICES.md) |
| Built kernel, BusyBox rootfs, VM images and bundled host dependencies | Composite distributions; comply with each component's terms |
| The `antinomie-monitor` executable | GPLv3 host application with linked dependencies under their own notices, and a separate embedded base build kit carrying the kernel patch series (`src/antinomie/core/`, GPL/file-specific terms) and Debian `linux` source inputs (`src/debian/`, upstream terms) unchanged, with the GPL-2.0 text. Community rule packs are installed separately. Release archives include `LICENSE`, this file, `THIRD-PARTY-NOTICES.md` and `LICENSES/` |

The 0.7.0 host relicense does not change the Linux kernel's license.
The patch that introduces the shared headers keeps their original kernel
notice; the separate licensing patch after it establishes the current
shared-header licensing.
Historical source walkthroughs published elsewhere remain snapshots, not
updated copies or authority for current source licensing.

Earlier releases remain under their original MIT terms; this change does not
withdraw rights already granted. `LICENSES/Antinomie-MIT.txt` retains the MIT
notice for shared headers and earlier original code, and
`LICENSES/GPL-2.0-only.txt` the license of the kernel-derived code. The separate
website keeps its own license scope.

## Contributions and distribution

Contributors must own or have permission to license their contributions under
the applicable destination license. New original host/tooling contributions
default to GPL-3.0-only; shared headers stay MIT and kernel-derived contributions
follow their kernel/file terms. Contributions use the destination file's license.
Do not relabel imported code, remove attribution, or infer permission from a
public repository. New third-party code/assets require provenance and license
review before import.

Redistribution of GPLv3 application binaries requires the applicable notices and
equivalent access to corresponding source, including the build/install scripts.
Keep a release's source access instructions next to its binary downloads; for an
official release, the matching `vX.Y.Z` tag of this public repository is the
corresponding source. MIT portions retain
their copyright and permission notices. Dependencies and guest components have separate obligations;
release packaging must include applicable notices and source/source-offer
arrangements where required. This source licensing change is not a complete
binary/image distribution compliance audit. `scripts/check-licenses.py` checks
the host/kernel boundary and locked Cargo license expressions and can collect
upstream license documents. Its manifest marks crates lacking separate notice
files for source review; a metadata pass is not full legal clearance.

The Hugging Face `MoreMorePwn/antinomie-bases` bucket holds the image catalog,
its README, the VM bundle files and, under `sources/`, the corresponding source
of every listed base: the Debian `linux` source package each guest kernel is
built on, the Antinomie patch series and exact kernel configuration of that
base, the source packages of the BusyBox, glibc and e2fsprogs binaries copied
into its images, and a package inventory with snapshot.debian.org links for each
Debian base
(<https://huggingface.co/buckets/MoreMorePwn/antinomie-bases/tree/main/sources>;
`bases/<identity>/SOURCES.json` there names every file of one base). Nothing in
the bucket depends on access to a private repository. A base is published
together with its `sources/` section (`scripts/publish-base-sources.py`); a base
whose sources cannot be published is not listed in `index.json`. The patch series
is also in the `vX.Y.Z` tag of this repository under `src/antinomie/core/`.
Keeping the image catalog separate does not remove component-specific source
distribution obligations.

Unnecessary reference mockups, copied branding and research artifacts stay out
of the product repository; required
notices and accurate technical dependency/provenance records stay in it.
