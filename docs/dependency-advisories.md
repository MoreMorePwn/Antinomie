# Dependency advisory applicability for 0.7.0

Reviewed against the locked Linux x86-64 build on 2026-10-23. The audit remains
blocking for unreviewed advisories. Entries in `.cargo/audit.toml` are scoped
applicability assessments, not claims that an upstream vulnerability was fixed.
Dependency upgrades remain tracked in the existing dependency-advisory backlog.

| Advisory | Source and applicability assessment |
|---|---|
| RUSTSEC-2026-0359 | [Upstream description](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-wjc8-633q-pwxr): dropping attacker-defined chains of recursive Wasm types. Antinomie accepts YARA source and invokes YARA-X's compiler, rather than accepting guest Wasm or serialized compiled rule modules. YARA-X's generated module uses its own fixed type schema; Wasmtime's `gc` feature is disabled. This assessment must be revisited if raw/compiled Wasm imports, custom Wasm types or GC are enabled. |
| RUSTSEC-2026-0379 | [RustSec](https://rustsec.org/advisories/RUSTSEC-2026-0379.html): aarch64 Cranelift branch-table lowering. The distributed host is Linux x86-64. A future aarch64 host distribution invalidates this exception. |
| RUSTSEC-2026-0362 | [RustSec](https://rustsec.org/advisories/RUSTSEC-2026-0362.html): component-model async entrypoints. The resolved Wasmtime features are `cranelift`, `once_cell`, `runtime`, `std`, `wasmtime-jit-icache-coherence`; no `component-model` or `async`. |
| RUSTSEC-2026-0363 | [RustSec](https://rustsec.org/advisories/RUSTSEC-2026-0363.html): component-model handle tables. The component model is not enabled or used. |
| RUSTSEC-2026-0367 | [RustSec](https://rustsec.org/advisories/RUSTSEC-2026-0367.html): privileged mode bits in ZIP extraction helpers. `analysis_tools::unpack_zip` and `ruleset::source_archive::extract_zip` iterate entries instead of calling those helpers; the tool extractor masks modes and rule imports do not retain archive permissions. |
| RUSTSEC-2026-0368 | [RustSec](https://rustsec.org/advisories/RUSTSEC-2026-0368.html): escaping links created by `ZipArchive::extract`. That API is not called. Rule imports reject links; the separate tool extractor validates its own link targets. This is an assessment of the named upstream helper, not proof that every possible archive attack is prevented. |
| RUSTSEC-2026-0369 | [RustSec](https://rustsec.org/advisories/RUSTSEC-2026-0369.html): applying permissions through links in ZIP extraction helpers. Those helpers are not called. |

Evidence: locked Cargo metadata with `--filter-platform
x86_64-unknown-linux-gnu`; YARA-X 1.21.0's Wasmtime declaration uses
`default-features = false` with `cranelift` and `runtime`; the selected YARA
sources are compiled in `analysis/detection/yara.rs`; archive entry handling is
in `analysis_tools.rs` and `ruleset/source_archive.rs`. Revisit these conclusions
when the corresponding feature, input format, architecture or API call changes.

The older reviewed RSA and Wasmtime exceptions retain their existing reasons.
Maintenance warnings remain visible. Nothing here changes upstream versions,
removes loss reporting or defers a newly demonstrated reachable vulnerability.
