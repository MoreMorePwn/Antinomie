# Source layout

| Path | What it holds |
|---|---|
| `antinomie/` | Antinomie's own sources: the guest kernel patch series (`core/`, `patches/`), the image packaging inputs (`packaging/`), the transport (`transport/`) and the host application (`monitor/`). |
| `debian/` | The pinned Debian `linux` 6.12.94-1 source package (`.dsc`, `.debian.tar.xz`, upstream tarball) and the extracted packaging delta in `debian/debian/`. |

The Debian packaging delta is metadata only, not the kernel tree. The upstream
tarball `linux_6.12.94.orig.tar.xz` is not extracted here.

## Build on a case-sensitive filesystem

The Linux kernel source contains pairs of files whose names differ only by
case (for example `include/uapi/linux/netfilter/xt_DSCP.h` and `xt_dscp.h`).
On a case-insensitive filesystem, such as a Windows drive mounted in WSL2
under `/mnt/<letter>`, one member of each pair silently overwrites the other,
and `tar` can still exit successfully with an incomplete tree.

So do not extract the upstream tarball or check out a kernel tree on such a
drive. Reconstruct and build the kernel source on a case-sensitive Linux
filesystem:

```bash
mkdir -p ~/src/antinomie/debian-source
cd ~/src/antinomie/debian-source
cp "$REPO/src/debian/"linux_6.12.94* .   # $REPO: this checkout
dpkg-source -x linux_6.12.94-1.dsc
cd linux-6.12.94
```

`dpkg-source -x` rebuilds the Debian source tree from the three source package
files and applies the main Quilt series. That tree is where the kernel is
patched, built and packaged. The `.dsc` is PGP-clearsigned; verify it with
`gpg --verify linux_6.12.94-1.dsc` when the Debian archive keyring is installed.
