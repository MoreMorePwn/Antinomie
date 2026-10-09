# Licensing and copyright

Original, independently licensable Antinomie code and documentation in this
repository are MIT licensed under [LICENSE](LICENSE), unless a file-specific
notice or an exception below states otherwise.

Copyright (c) 2026 MikiMiku (MoreMorePwn).

This notice identifies the project owner's original contributions. It does not
claim ownership of dependencies, upstream code, other contributors' work or
third-party assets. Preserve their applicable notices and terms.

## Scope

| Material | License / treatment |
|---|---|
| Original Rust monitor, scripts, tests, packaging glue and documentation | MIT, except explicitly marked or imported material |
| `src/antinomie/transport/host.c`, `host_api.h` | MIT; independently built host transport |
| Original shared `abi.h`, `queue.h`, `bootstrap_layout.h`, monitor `protocol/control.h` | MIT; kernel copies retain this file-specific license |
| Kernel-only `transport/guest.c`, `bootstrap.c`, `guest_api.h` | GPL-2.0-only, as marked; excluded from root MIT grant |
| Kernel changes and upstream context in `src/antinomie/core/` and `src/antinomie/patches/` | Kernel GPL/file-specific terms; not blanket MIT. The follow-up licensing patch changes only original shared headers to MIT |
| Imported `src/debian/`, source archives, packaging references and patches | Existing upstream/file-specific terms; excluded from root MIT grant |
| Community YARA rules (`crates/monitor-core/assets/rules/yara-forge-core.yar`) and capa-rules (`capa-rules-v9.4.0.tar.gz`) | Per-rule licenses (CC BY-SA 4.0, DRL 1.1, BSD-2-Clause, Apache-2.0, CC BY 4.0, MIT) and Apache-2.0; excluded from root MIT grant; see [third-party notices](THIRD-PARTY-NOTICES.md) |
| `LICENSES/third-party/`, dependencies and embedded fonts/icons | Their own licenses/notices; excluded from root MIT grant; see [third-party notices](THIRD-PARTY-NOTICES.md) |
| Built kernel, BusyBox rootfs, VM images and bundled host dependencies | Composite distributions, not wholly MIT; comply with each component's terms |
| The `antinomie-monitor` executable | Composite: MIT application code, linked dependencies under their own licenses, the embedded analysis rule sets (per-rule licenses above), and the embedded base build kit, which carries the kernel patch series (`src/antinomie/core/`, GPL/file-specific terms) and the Debian `linux` source package files (`src/debian/`, upstream terms) unchanged. Release archives include `LICENSE`, this file, `THIRD-PARTY-NOTICES.md` and `LICENSES/` |

The shared-header licensing change does not change the Linux kernel's license.
Historical patches retain their original notices; the ordered follow-up patch
establishes the current shared-header licensing without rewriting history.
Historical source walkthroughs in the separate documentation repository remain
snapshots, not updated copies or authority for current source licensing.

## Contributions and distribution

Contributors must own or have permission to license their contributions under
the applicable destination license. New original host/tooling contributions
default to MIT; kernel-derived contributions follow their kernel/file terms.
Do not relabel imported code, remove attribution, or infer permission from a
public repository. New third-party code/assets require provenance and license
review before import.

Redistribution of MIT portions must retain copyright and permission notices.
This requires notices, not an in-app credit or endorsement. MIT does not grant
trademark rights. Dependencies and guest components have separate obligations;
release packaging must include applicable notices and source/source-offer
arrangements where required. This source licensing change is not a complete
binary/image distribution compliance audit.

The documentation guide's `Agents/Licensing and Provenance.md` governs clean
product commits and required exceptions. Unnecessary reference mockups, copied
branding and research artifacts stay out of the product repository; required
notices and accurate technical dependency/provenance records stay in it.
