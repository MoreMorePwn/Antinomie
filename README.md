# Antinomie kernel packaging

This repository maintains the **Antinomie delta** against a pinned Debian
kernel source package. It is a *packaging* repository: it holds patch text and
packaging metadata, never an extracted kernel tree.

- **Baseline:** Debian `linux` **6.12.94-1**, `trixie-security`, source format
  `3.0 (quilt)`.
- **Delta:** an extra Quilt series applied on top of Debian's 79-patch main
  series, namespaced under `debian/patches/antinomie/`.
- **Design:** one distro-agnostic *core* plus one thin *adapter* per
  (distro, source-package version). Adding a target costs an adapter folder,
  not a fork of the kernel.

## Quickstart

```bash
git clone <url> ~/src/antinomie
cd ~/src/antinomie

scripts/bootstrap.sh                       # build the disposable work trees
#   edit in work/debian-6.12.94-1-trixie/core, then commit there
scripts/commit.sh                          # turn that commit into a Quilt patch
git commit -m "antinomie: <change>" && git push
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow, patch
conventions, and the maintenance playbook.

The initial native monitoring application, kernel-only controls and BusyBox
guest workflow are documented in [Native Monitor](src/antinomie/monitor/README.md).
Shared agent conventions are in [AGENTS.md](AGENTS.md).

## Layout

```
.
├── CONTRIBUTING.md                  workflow, conventions, maintenance
├── scripts/
│   ├── bootstrap.sh                 build work/ trees for an adapter
│   ├── commit.sh                    commit -> DEP-3 Quilt patch
│   └── verify-inputs.sh             verify pinned input hashes
├── src/                             durable, tracked
│   ├── debian/                      pinned Debian inputs + packaging reference
│   └── antinomie/
│       ├── core/6.12/               the portable delta (patch series)
│       ├── patches/debian-6.12.94-1-trixie/antinomie/   generated Quilt view
│       └── packaging/
│           └── debian-6.12.94-1-trixie/   adapter: adapter.conf, config, fence
└── work/                            disposable, gitignored, rebuilt on demand
    └── debian-6.12.94-1-trixie/
        ├── linux-6.12.94/           extracted tree (upstream + Debian series)
        ├── core/                    Git author repo
        └── images/                  rootfs / qcow2 pipeline
```

## Requirements

- An **ext4** workspace. Never extract or build on a case-insensitive or 9p
  mount (the kernel tree has case-colliding paths that silently lose files).
- `git`, `dpkg-source`, `quilt`, `sha256sum`, and the Debian kernel build
  dependencies.
