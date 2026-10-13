# Antinomie engineering conventions

The enduring project guide is the documentation checkout's `Agents/README.md`.
Use `$ANTINOMIE_GUIDE_DIR/README.md` if configured, or locate the existing
documentation checkout; do not duplicate policy or auto-clone it. Never record
machine-specific paths, user names or agent tool directories in this repository.
Read the index and applicable workflow/delegation/engineering/skills chapters
before writing. Report missing guidance before risky changes. Higher-priority
instructions and explicit user scope prevail over the project guide.

Selected work is tracked in the docs `Kanban.md` and `Agents/Tasks/` with scope,
owned paths, baseline/contracts, acceptance checks, budget and checkpoints.
Use bounded subagents when useful and permitted; dependent coding needs an
accepted shared contract, disjoint ownership and coordinator review/integration.
Do not implement a new version/redesign or unrelated fix without user approval;
record proposed changes in Backlog. Reread guidance explicitly after updates.

Read docs/implementation.md and CONTRIBUTING.md before changing code.
The implementation brief records accepted scope; ask the coordinator about
contract changes instead of independently redesigning a neighboring module.

## Ownership and maintainability

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

## Skills

Skills are named here; agents find them in their own installed skills.

- Host Rust and UI workers: the `rust-skills` skill; read relevant rules only
  (API, ownership, errors, unsafe, concurrency, tests).
- UI worker also: the `frontend-design` skill. Apply native operational-tool
  design; web hero guidance is irrelevant to this application.
- Explicit threat-model requests: the `security-threat-model` skill.
  Do not invoke for generic code review/design; keep models grounded in actual
  implemented boundaries. Ordinary boundary review still follows project rules.
- Kernel worker: the `antinomie-kernel` skill plus pinned
  kernel headers/source and CONTRIBUTING.md; Rust rules do not replace Linux
  locking/lifecycle APIs.

## Verification and handoff

- Run formatting, focused build/checks and meaningful behavioral tests.
- Negative cases: malformed/truncated records, invalid copy pointers, command
  rejection, full rings, full recordings, and shutdown races where applicable.
- Return changed files, exact checks/results, remaining limitations. Summaries
  are short; logs/results live in work/. Never label unrun tests as passing.
- Workers edit only assigned files; coordinator commits outer repository and
  documentation. No nested subagents. Preserve unrelated user changes.
- Full kernel source trees and VM images stay outside tracked source files.
- User-created persistent VM data never lives in disposable work/ build trees.
- Follow docs/project-layout.md: `work/` and Cargo `target/` are disposable;
  retain important source inputs, release provenance and reusable scripts in
  explicitly named external cache/archive/release locations before cleaning.

## Licensing and provenance

Read LICENSING.md, THIRD-PARTY-NOTICES.md and the guide's
`Licensing and Provenance.md` before importing code/assets or preparing a release.
Original eligible host/tooling code defaults to MIT with the project identity
`MikiMiku (MoreMorePwn)`; preserve kernel and upstream/file-specific terms.
Do not commit unnecessary third-party branding, reference mockups or research
artifacts to this product repository. Required notices and honest technical
provenance are mandatory exceptions; never remove or disguise them.

## Documentation

Public arguments, return values and declaration purposes use tables. Walkthrough
excerpts include source filename and actual line numbers with explanation below.
Mermaid blocks stay unnumbered. Document measured benchmark environment and
limitations. Coordinator commits/pushes docs repo after validation.
