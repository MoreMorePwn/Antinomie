# Contributing to the Antinomie kernel packaging

This document is the operational guide for adding and maintaining Antinomie
patches. It assumes you have read the design documents in the project vault
(`Documentation/Antinomie/`), in particular *Debian Kernel and Image
Development Guide*.

---

## 1. What this repository is (and is not)

It **is** the durable home of:

- the pinned Debian source inputs (`src/debian/`),
- the distro-agnostic Antinomie delta (`src/antinomie/core/`),
- the generated Quilt views (`src/antinomie/patches/<adapter>/antinomie/`),
- the per-target adapters (`src/antinomie/packaging/<adapter>/`).

It **is not** a place to store kernel trees. Extracted trees, build outputs,
rootfs and images are disposable and live under the gitignored `work/`.

Two rules follow from that:

1. **Never commit a kernel tree.** `work/` is rebuilt from the tracked text.
2. **Never hand-edit a generated artifact.** `src/antinomie/patches/` is
   produced from `src/antinomie/core/` by `scripts/commit.sh`.

---

## 2. Mental model

There are three trees and two representations.

| Tree / location | Role | Disposable? |
|---|---|---|
| `src/` | durable text: inputs, core delta, Quilt views, adapters | no |
| `work/<adapter>/<SOURCE_DIRNAME>/` | Quilt **build** tree (upstream + Debian series) | yes |
| `work/<adapter>/core/` | Git **author** tree (history, rebase, bisect) | yes |

| Representation | Location | Purpose |
|---|---|---|
| Git commit series | `work/<adapter>/core` (exported to `src/antinomie/core/`) | review, rebase, conflict resolution |
| Quilt patch series | `src/antinomie/patches/<adapter>/antinomie/` | what `dpkg-source` / `debian/rules` apply |

The change flows one way:

```
author in work/<adapter>/core (Git)
        │  scripts/commit.sh
        ▼
src/antinomie/core/<line>/*.patch          (portable delta)
src/antinomie/patches/<adapter>/antinomie/  (generated Quilt view + series)
        │  copy into the build tree
        ▼
work/<adapter>/<SOURCE_DIRNAME>/debian/patches/antinomie/  → quilt push -a → build
```

**Context vs content:** the *content* of a patch is portable kernel code; its
*context* must match the tree it applies to — i.e. upstream **plus** the full
Debian main series. The Antinomie block is applied **last** in
`debian/patches/series`.

---

## 3. Prerequisites

- An ext4 workspace (never a case-insensitive / 9p mount).
- `git`, `dpkg-source`, `quilt`, `sha256sum`.
- Debian kernel build deps: `debhelper-compat`, `python3-dacite`, `python3-jinja2`,
  `bc`, `libssl-dev`, `libelf-dev`, `pahole`, `bison`, `flex`, `cpio`, `xz-utils`,
  `zstd`, `gcc-14`, `kmod`, `kernel-wedge`.

---

## 4. First-time setup

```bash
git clone <url> ~/src/antinomie
cd ~/src/antinomie
scripts/bootstrap.sh                 # default adapter: debian-6.12.94-1-trixie
```

`bootstrap.sh` fetches the large upstream source tarball on demand (see
`scripts/fetch-inputs.sh`; live Debian pool first, `snapshot.debian.org`
fallback), verifies all pinned inputs, extracts the baseline tree, and creates
the Git author repo on top of the Debian-patched baseline. It is safe to re-run.

To target a different adapter explicitly:

```bash
scripts/bootstrap.sh <adapter-name>
```

---

## 5. Adding a patch

All edits happen in the **author repo**, never in a `.patch` file.

```bash
cd work/debian-6.12.94-1-trixie/core
git checkout 6.12
git checkout -b antinomie/<short-topic>
```

Edit the source. Put bulk code in **new files** under `kernel/antinomie/`;
keep hooks into existing files small and in regions no distro patch touches.

```bash
git add -p
git commit -m "antinomie: <what changed>"
```

Turn the commit into the durable artifacts and stage them:

```bash
cd ~/src/antinomie
scripts/commit.sh                    # prompts for DEP-3 headers
```

Then verify it applies and builds in the disposable tree:

```bash
cd work/debian-6.12.94-1-trixie/linux-6.12.94
export QUILT_PATCHES=debian/patches
mkdir -p debian/patches/antinomie
cp ../../src/antinomie/patches/debian-6.12.94-1-trixie/antinomie/*.patch debian/patches/antinomie/

# ensure the fenced Antinomie block is present at the END of debian/patches/series
# (it lists the entries from src/antinomie/patches/debian-6.12.94-1-trixie/antinomie/series)

quilt pop -a && quilt push -a        # must apply with zero fuzz
debian/bin/check-patches.sh
debian/bin/test-patches -f amd64 -s none -j "$(nproc)" \
  ../../src/antinomie/patches/debian-6.12.94-1-trixie/antinomie/<new>.patch
```

Finally, commit the tracked text:

```bash
cd ~/src/antinomie
git add src/antinomie/
git commit -m "antinomie: <what changed>"
git push
```

The only differences for the *first* patch are that `git am` in
`bootstrap.sh` replays nothing, and the series/fence are created rather than
appended.

---

## 6. Patch conventions

- **Naming:** `NNNN-antinomie-<slug>.patch`, numbered in application order.
  `scripts/commit.sh` assigns the number.
- **Ordering:** entries appear in `src/antinomie/patches/<adapter>/antinomie/series`
  in the same order, and the fenced block in `debian/patches/series` is last.
- **DEP-3 headers:** every patch carries `Description`, `Author`, `Origin`,
  `Forwarded`, `Last-Update`, and `Bug`/CVE where applicable. `commit.sh`
  prompts for these.
- **Minimality:** bulk code in new files under `kernel/antinomie/`; hooks into
  existing files (`arch/x86/entry/…`, `kernel/Makefile`, `kernel/Kconfig`,
  `mm/`) as small as possible.
- **Provenance:** anything upstreamable should land upstream first and be
  carried as a backport with its upstream commit id in `Origin`.
- **ABI:** a patch that changes exported module ABI symbols needs a deliberate
  ABI bump; self-contained code that no module links against does not. Record
  the decision per patch.

---

## 7. Verifying and building

Run in increasing cost order:

1. **Inputs:** `scripts/verify-inputs.sh`.
2. **Patch integrity:** `quilt pop -a && quilt push -a`,
   `debian/bin/check-patches.sh`; zero fuzz.
3. **Control/config generation:** regenerate and review `control`/`rules.gen`.
4. **Build deps:** `dpkg-checkbuilddeps` with the intended profiles.
5. **Focused build:** image + headers for the `amd64`/`none`/`amd64` tuple.
6. **Out-of-tree module:** `debian/tests/headers-kbuild`.
7. **Boot test:** boot the exact `.deb` in a disposable QEMU image.
8. **Image test:** golden qcow2 cold boot, settle, snapshot, disposable overlay.

Do **not** use `pkg.linux.quick` or disable BTF when validating anything
BPF/BTF-derived.

---

## 8. Maintenance

### 8.1 Debian stable / security update (same release)

1. Obtain the next source package; verify its hashes.
2. Add the new inputs to `src/debian/` and add a new adapter (or update the
   existing one) with the new `SOURCE_VERSION`/hashes.
3. Re-extract the new baseline and rebase the core series onto it:
   `git rebase baseline/<new-adapter>` inside the author repo.
4. Resolve conflicts as real source edits. Never use `--fuzz`.
5. Regenerate the Quilt view (`scripts/commit.sh`, or `git format-patch`).
6. Refresh config fragments and review the ABI.
7. Run the ladder in section 7.

### 8.2 New Debian release (`trixie` → `forky`)

New adapter folder. The ABI suffix changes (`+deb13` → `+deb14`), config
fragments are refreshed, package names/relations reviewed. The core series is
unchanged.

### 8.3 New distro

New adapter folder. Ubuntu kernels are downstream of upstream with their own
sauce and a different packaging layout; the core patch text is reused
verbatim, and the adapter handles the different insertion point and flavour
mapping.

### 8.4 New upstream kernel line (6.12 → 6.13, or a second LTS)

New `src/antinomie/core/<line>/` folder. This is the only case where kernel
logic itself is duplicated, and only because the code genuinely differs.
Forward-port each hunk and review it; never blind-copy.

---

## 9. Adding a new adapter

1. Create `src/antinomie/packaging/<distro>-<version>-<release>/`.
2. Add `adapter.conf` declaring `DISTRO`, `RELEASE`, `UPSTREAM_LINE`,
   `SOURCE_VERSION`, `SOURCE_DIRNAME`, `ABI_SUFFIX`, the input paths and
   hashes, the patch insertion point, and the build/test commands.
3. Add `config/` fragments and a `series.fence` for the insertion block.
4. Add the pinned inputs under `src/debian/` (or a distro-specific input dir).
5. `scripts/bootstrap.sh <adapter>` and confirm the core series applies.
6. Create `src/antinomie/patches/<adapter>/antinomie/` and let `commit.sh`
   populate its `series`.

Adding an adapter must not modify `src/antinomie/core/`.

---

## 10. Rules

- Edit in Git (`core/`), ship from Quilt (`patches/`). Never the reverse.
- Never hand-edit a `.patch` as the durable fix.
- Never commit `work/`, build outputs, `.pc/`, generated keys, rootfs trees or
  qcow2 images.
- Never maintain two copies of the same patch.
- Never fix a rebase with `--fuzz`.
- Keep upstream, Debian, and Antinomie commits distinguishable.
- Every commit maps to a backlog item.

---

## 11. Release record

For every candidate baseline retain: Antinomie Git commit(s); upstream tag and
commit; Debian source version and input SHA-256s; main + Antinomie series
digests and ordered patch list; final config digest; compiler and build-profile
values; output `.deb` names/versions/SHA-256s; image spec, rootfs package lock,
qcow2 digest, QEMU version and command-policy revision; test results, known
limitations, snapshot id.

---

## 12. Versioning

Antinomie uses semantic versioning. The one version number is
`[workspace.package] version` in `src/antinomie/monitor/Cargo.toml`; the app
shows it in its title bar, **Help > About Antinomie** and
`antinomie-monitor --version`.

| Change | Bump | Example |
|---|---|---|
| Bug fix, no new behaviour | patch | 0.1.0 → 0.1.1 |
| New feature (anything a user can see or use) | minor | 0.1.1 → 0.2.0 |
| First release; later, incompatible changes | major | 0.x → 1.0.0 |

The guest kernel has its own **contract revision** (`ANTC_REVISION` in the
shared control header, documented in `native-schema-slices.md`). It changes
only when guest-visible kernel behaviour changes, and only together with a
minor or major release:

1. Raise `ANTC_REVISION` in the kernel's `control_wire.h` (mirrored to
   `src/antinomie/monitor/protocol/control.h`).
2. Add `{"revision": N, "first_app_version": "X.Y.0"}` to
   `src/antinomie/monitor/protocol/revisions.json`.
3. Raise the workspace version to `X.Y.0`.

`cargo test` fails if the table does not end with the current revision, if an
entry is not an `x.y.0` version, or if it names a version newer than the app.
Builders refuse a kernel whose revision is not in the table. Every base
records `built_with` (the app version that built it) and `min_app_version`
(the first version of its kernel's revision); the app refuses bases that need
a newer version and labels older ones as outdated. A patch release therefore
never makes existing bases outdated.

For a release: update `CHANGELOG.md`, raise the version, commit, and tag the
commit `vX.Y.Z`. Pushing the tag runs `.github/workflows/release.yml`: it
checks that the tag matches the version, runs the tests, builds the archive
with `scripts/build-release.sh` and publishes the GitHub release with the
version's changelog section as notes. Bases are built and uploaded
separately (see the base distribution notes).

Every push runs `.github/workflows/ci.yml` (`scripts/check-privacy.sh`,
`cargo fmt --check`, strict Clippy, the release-mode tests, the build-script
tests and shellcheck); `.github/workflows/nightly.yml` boots the current
BusyBox base under KVM every night (`tests/ci/nightly-vm.py`).
