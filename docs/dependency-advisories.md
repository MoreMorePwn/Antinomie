# Dependency advisory applicability

Reviewed against the locked Linux x86-64 build on 2026-10-23 (0.7.0) and updated
on 2026-10-30 (0.7.1). The audit remains blocking for unreviewed advisories.
Every entry in [`.cargo/audit.toml`](../src/antinomie/monitor/.cargo/audit.toml)
is listed below. Each one is a scoped applicability assessment, not a claim that
an upstream vulnerability was fixed; the dependencies are upgraded once a
compatible fixed release exists.

RUSTSEC-2026-0385, published on 2026-10-23, is resolved by updating the locked
transitive `ctutils` from 0.4.3 to 0.4.4. The
[upstream patch](https://github.com/RustCrypto/utils/pull/1569) corrects mask
constant-time code generation and 32-bit `u128` comparisons. No audit exception
was added for this advisory; the patch does not change the other assessments
below or complete the broader YARA-X/Wasmtime update backlog.

| Advisory | Source and applicability assessment |
|---|---|
| RUSTSEC-2023-0071 | [RustSec](https://rustsec.org/advisories/RUSTSEC-2023-0071.html): Marvin timing side channel in `rsa` private-key decryption and signing. YARA-X uses `rsa` only to verify Authenticode signatures with public keys taken from the scanned file; no private key exists in Antinomie. Revisit if any code signs or decrypts with RSA. |
| RUSTSEC-2026-0387 | [RustSec](https://rustsec.org/advisories/RUSTSEC-2026-0387.html): timing variability in `crypto-bigint` operations meant to be constant-time, fixed only in 0.7.6. The locked 0.5.5 comes from `elliptic-curve` 0.13 through `p256`/`p384`, which YARA-X uses only as ECDSA `VerifyingKey`s to check signatures of scanned files (`modules/utils/crypto.rs`). Verification handles public data, so there is no secret to leak. Revisit when YARA-X moves to `elliptic-curve` 0.14 or any code uses these curves with private keys. |
| RUSTSEC-2026-0316 | [RustSec](https://rustsec.org/advisories/RUSTSEC-2026-0316.html): dynamic record lifting can allocate beyond the hostcall fuel limit, a component-model path. `component-model` is not enabled (features listed under RUSTSEC-2026-0362); scanning also runs inside the bubblewrap sandbox. |
| RUSTSEC-2026-0222 | [RustSec](https://rustsec.org/advisories/RUSTSEC-2026-0222.html): stores can mix up type indices between engines. YARA-X uses a single engine for the rules it compiles; no stores or modules are shared across engines. |
| RUSTSEC-2026-0327 | [RustSec](https://rustsec.org/advisories/RUSTSEC-2026-0327.html): unvalidated result count of component async-lifted callbacks. Neither `component-model` nor `async` is enabled; YARA-X runs core modules it compiles from the selected rules. |
| RUSTSEC-2026-0269 | [RustSec](https://rustsec.org/advisories/RUSTSEC-2026-0269.html): Wasmtime WASI filesystem path handling. WASI is not enabled; YARA-X modules get no filesystem access. |
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

Maintenance warnings remain visible. Nothing here changes upstream versions,
removes loss reporting or defers a newly demonstrated reachable vulnerability.
