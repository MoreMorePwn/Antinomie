# Antinomie - Source Archives

Updated: 2026-09-22
Location: `<project-root>/src` (Windows `<project-root>\src`, NTFS via WSL2)

Total size on disk after cleanup: about **156 MB**.

---

## Warning - Windows drives are case-insensitive

Under WSL2, a Windows drive (mounted as `/mnt/<letter>`) is an NTFS volume and
is case-insensitive by default: creating `CaseTest.tmp` makes `casetest.tmp`
resolve to the same file.

The Linux kernel source tree contains 13 pairs of files whose names differ only
by case. On a case-insensitive filesystem, one member of each pair can silently
overwrite the other. `tar` may still exit successfully, leaving a broken or
subtly incomplete kernel tree.

The remaining Debian 6.12.94 source archive was checked directly:

| # | Pair |
|---|---|
| 1 | `include/uapi/linux/netfilter/xt_CONNMARK.h` <-> `xt_connmark.h` |
| 2 | `include/uapi/linux/netfilter/xt_DSCP.h` <-> `xt_dscp.h` |
| 3 | `include/uapi/linux/netfilter/xt_MARK.h` <-> `xt_mark.h` |
| 4 | `include/uapi/linux/netfilter/xt_RATEEST.h` <-> `xt_rateest.h` |
| 5 | `include/uapi/linux/netfilter/xt_TCPMSS.h` <-> `xt_tcpmss.h` |
| 6 | `include/uapi/linux/netfilter_ipv4/ipt_ECN.h` <-> `ipt_ecn.h` |
| 7 | `include/uapi/linux/netfilter_ipv4/ipt_TTL.h` <-> `ipt_ttl.h` |
| 8 | `include/uapi/linux/netfilter_ipv6/ip6t_HL.h` <-> `ip6t_hl.h` |
| 9 | `net/netfilter/xt_DSCP.c` <-> `xt_dscp.c` |
| 10 | `net/netfilter/xt_HL.c` <-> `xt_hl.c` |
| 11 | `net/netfilter/xt_RATEEST.c` <-> `xt_rateest.c` |
| 12 | `net/netfilter/xt_TCPMSS.c` <-> `xt_tcpmss.c` |
| 13 | `tools/memory-model/litmus-tests/Z6.0+pooncelock+poonceLock+pombonce.litmus` <-> `...+pooncelock+pooncelock+pombonce.litmus` |

Therefore, on a Windows drive:

- Do not extract `linux_6.12.94.orig.tar.xz` here.
- Do not put a Linux kernel Git checkout or worktree here.
- Do all source, package, rootfs, and image build work under a case-sensitive
  ext4 path such as `~/src/antinomie/`.

`debian/debian/` is extracted here deliberately. It comes from the Debian
packaging delta, not the full kernel tree, and was checked for case collisions.

---

## Contents kept

| Path | Size | Source URL |
|---|---:|---|
| `debian/linux_6.12.94-1.dsc` | 288,306 B | `http://deb.debian.org/debian/pool/main/l/linux/linux_6.12.94-1.dsc` |
| `debian/linux_6.12.94.orig.tar.xz` | 151,297,764 B | `http://deb.debian.org/debian/pool/main/l/linux/linux_6.12.94.orig.tar.xz` |
| `debian/linux_6.12.94-1.debian.tar.xz` | 1,838,436 B | `http://deb.debian.org/debian/pool/main/l/linux/linux_6.12.94-1.debian.tar.xz` |
| `debian/debian/` | about 9.6 MB | extracted from `linux_6.12.94-1.debian.tar.xz` |

Old upstream-only kernel artifacts and the local full Git mirror were removed
from this workspace. The Antinomie baseline is now only the Debian `linux`
source package version `6.12.94-1`.

---

## Extracted Debian folder map

`src/debian/debian/` is the extracted Debian packaging delta. It is safe to keep
here because it is packaging metadata, not the full kernel source tree.

| Path | What it contains | What it controls |
|---|---|---|
| `debian/changelog` | Current Debian package history. | Version, target suite, urgency, ABI context, and release notes. |
| `debian/control` | Generated source and binary package metadata. | Build dependencies, binary package names, package relationships, and descriptions. |
| `debian/rules`, `rules.gen`, `rules.real`, `rules.defs` | Make entry points and generated dispatch rules. | Source preparation, config generation, compile targets, package staging, binary builds, and cleaning. |
| `debian/bin/` | Debian Kernel Team helper scripts. | Control generation, Kconfig processing, stable-update handling, patch checks, test patch builds, and RT patch import helpers. |
| `debian/lib/python/` | Python modules used by helper scripts. | Shared logic for parsing templates, config definitions, package metadata, and generated build files. |
| `debian/config/` | Common, architecture, feature-set, and flavour Kconfig fragments plus `defines.toml` files. | Kernel feature selection, supported architectures/flavours, cloud variants, RT variants, and config merge order. |
| `debian/config/amd64/` | amd64-specific config and flavour definitions. | The standard x86-64 `amd64` and `cloud-amd64` build setup most relevant to Antinomie. |
| `debian/config/featureset-rt/` | RT-specific config fragment. | Enables the PREEMPT_RT feature set when building `rt` kernels. |
| `debian/patches/` | Main Quilt patch stack and `series`. | Debian defaults, bug fixes, security policy, feature additions, packaging integration, and DFSG adjustments applied to every build. |
| `debian/patches-rt/` | PREEMPT_RT Quilt patch stack and `series`. | Extra scheduler, locking, timer, tracing, and architecture changes used only by RT builds. |
| `debian/templates/` | Templates for generated package metadata and maintainer files. | Source, image, header, tool, installer, and signed-package metadata generation. |
| `debian/rules.d/` | Make fragments for tools, scripts, and certificates. | Packaging of kernel-tree userspace tools such as `perf`, `cpupower`, `bpftool`, `usbip`, and related helper outputs. |
| `debian/installer/` | Debian Installer package and module lists. | Kernel udebs used by the Debian installer. Usually not needed for Antinomie runtime images. |
| `debian/tests/` | Autopkgtest files and helpers. | Package validation, especially testing that installed headers can build an external kernel module. |
| `debian/generated.signed-amd64/` and `generated.signed-arm64/` | Generated signed-image package metadata. | Debian's separate signed-kernel workflow. Local builds still produce unsigned kernel image packages unless a signing pipeline is added. |
| `debian/signing_templates/` | Templates for signed-image source packages. | Inputs for generated signing metadata. |
| `debian/source/` | Source-package metadata. | Declares source format `3.0 (quilt)` for `dpkg-source`. |
| `debian/certs/` | Debian packaging certificates and test signing material. | Regulatory/signing-related packaging paths; not Antinomie runtime secrets. |
| `debian/upstream/` | Upstream metadata. | Informational metadata for Debian tooling. |

Top-level files with suffixes such as `.install`, `.links`, `.manpages`,
`.symbols`, `.maintscript`, `.postinst`, `.preinst`, `.postrm`, `.prerm`,
`.lintian-overrides`, `.NEWS`, and `.bug-presubj` are package-specific
debhelper instructions and maintainer metadata. They decide what each binary
package installs and how it behaves during install, upgrade, removal, linting,
and bug reporting.

For the full map of the reconstructed `linux-6.12.94/` tree after
`dpkg-source -x`, including upstream folders such as `arch/`, `fs/`,
`kernel/`, `mm/`, `net/`, `security/`, `tools/`, and the generated Debian build
folders, see
[`Documentation/Antinomie/Debian Kernel and Image Development Guide.md`](../Documentation/Antinomie/Debian%20Kernel%20and%20Image%20Development%20Guide.md).

---

## Version

Debian source package:

- Source: `linux`
- Version: `6.12.94-1`
- Debian target: `trixie-security`
- Upstream base: Linux `6.12.94`
- Source format: `3.0 (quilt)`
- Main Debian patch series: 79 patches
- PREEMPT_RT patch series: 43 patches, kept separately under `debian/patches-rt/`

---

## Verification

Expected `.dsc` checksums:

```text
3eea3dd18f67a103f6f8312e314075f695a27eaddd839e7b6c4641e6616dabba 151297764 linux_6.12.94.orig.tar.xz
8c5130fd9dee8d6efcc594dc3357809ad8e0d0234357139f85f5ed39b37922b4   1838436 linux_6.12.94-1.debian.tar.xz
```

Local verification already performed:

| Check | Result |
|---|---|
| `linux_6.12.94.orig.tar.xz` size vs `.dsc` `Checksums-Sha256` | match |
| `linux_6.12.94-1.debian.tar.xz` size vs `.dsc` `Checksums-Sha256` | match |
| `linux_6.12.94.orig.tar.xz` SHA256 vs `.dsc` | OK |
| `linux_6.12.94-1.debian.tar.xz` SHA256 vs `.dsc` | OK |

The `.dsc` is PGP-clearsigned. If the Debian archive keyring is available,
verify it with:

```bash
gpg --verify linux_6.12.94-1.dsc
```

---

## How to get a working tree

Always work on a Linux file system (ext4), not on a mounted Windows drive:

```bash
mkdir -p ~/src/antinomie/debian-source
cd ~/src/antinomie/debian-source
cp "$REPO/src/debian/"linux_6.12.94* .   # $REPO: this checkout
dpkg-source -x linux_6.12.94-1.dsc
cd linux-6.12.94
```

`dpkg-source -x` reconstructs the Debian source tree from the three source
package files and applies the main Quilt patch series. That reconstructed tree
is the correct place to build, patch, test, and generate `.deb` artifacts.

If you need upstream Git history for research or cherry-picking, clone it
outside this workspace and off any Windows drive, for example:

```bash
git clone https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git \
    ~/src/antinomie/linux-stable
```

Do not reintroduce a full upstream mirror into `src/` unless the project
explicitly needs it again.
