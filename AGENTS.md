# Antinomie engineering conventions

Contributor guide for people and coding tools. Read docs/implementation.md and
CONTRIBUTING.md before changing code. The implementation document records the
accepted scope and contracts; do not redesign a neighboring module on your own,
and do not implement a new version, a redesign or an unrelated fix without the
maintainer's approval. Never record machine-specific paths, user names or tool
directories in this repository. Explicit maintainer instructions take priority
over this guide.

## Conventions

- Every new application release starts on a fresh `release-X.Y.Z` branch before
  versioned work begins; use `scripts/new-release.sh X.Y.Z` from the current
  release branch. Keep each release's changes on that branch, including host,
  guest and UI work. Do not reuse an older release branch for a newer version.
- Use project-focused commit messages.
  Never include agent or model names in branch names, commit messages or trailers.
- Rust: snake_case functions/fields/modules, PascalCase types, SCREAMING_SNAKE
  constants. Kernel: existing Linux conventions and checkpatch where applicable.
- Suffix sizes with `_size` (capacity/extent), `_len` (used length/count of data),
  `_count` (items), `_offset` (position). Unit is documented; avoid `_bytes`.
- Keep modules by responsibility: transport FFI, protocol parsing, control
  encoding, VM lifecycle, recording/storage, frontend. No monolithic UI backend.
- Backend APIs accept owned domain values, not widgets or raw transport queues.
  The frontend never reads shared RAM, manages CPU rings, or dereferences data.
- Reuse stable libraries for serialization, terminal parsing, CLI/UI surfaces;
  parse guest binary wire messages with explicit checked offsets.
- No global current VM/client state. Independent session objects are required
  even though only one VM may run in the first release.
- No shell interpolation for QEMU arguments, executable arguments or paths.
- Propagate typed errors; reserve panic/unwrap for proved invariants and tests.
- Keep unsafe Rust in the FFI module; each unsafe block states pointer/lifetime
  and threading requirements. Safe wrappers enforce C client owner restrictions.
- Bound queues, parser states and in-memory payload previews. Large capture
  extents must not turn into host allocation requests. Preserve exact gap status.
- Task/VM/capture identity must survive CPU migration, PID reuse, and parent
  exit. Declare what unsupported guest ABIs/layouts produce.
- Partial failures must release owned files/tasks/PTYs/threads and produce
  observable status. No silently ignored spawn/read/write/fsync errors.

## Verification and handoff

- Run formatting, focused build/checks and meaningful behavioral tests.
- Negative cases: malformed/truncated records, invalid copy pointers, command
  rejection, full rings, full recordings, and shutdown races where applicable.
- Report the changed files, the exact checks and their results, and remaining
  limitations. Keep summaries short. Never label unrun tests as passing.
- Change only the files your task needs and preserve unrelated changes.
- Full kernel source trees and VM images stay outside tracked source files.
- User-created persistent VM data never lives in disposable work/ build trees.
- Follow docs/project-layout.md: `work/` and Cargo `target/` are disposable;
  retain important source inputs, release provenance and reusable scripts in
  explicitly named external cache/archive/release locations before cleaning.

## Licensing and provenance

Read LICENSING.md and THIRD-PARTY-NOTICES.md before importing code/assets or preparing a release.
Original eligible host/tooling code defaults to GPL-3.0-only from 0.7.0 with the project identity
`MikiMiku (MoreMorePwn)`; preserve kernel and upstream/file-specific terms.
Do not commit unnecessary third-party branding, reference mockups or research
artifacts to this product repository. Required notices and honest technical
provenance are mandatory exceptions; never remove or disguise them.

## Documentation

Public arguments, return values and declaration purposes use tables. Walkthrough
excerpts include source filename and actual line numbers with explanation below.
Mermaid blocks stay unnumbered. Document measured benchmark environment and
limitations.
