# The full pack

[← Back to the overview](../README.md)

The application archive does not contain the optional analysis tools: the app
downloads each on request (**Tools > Analysis tools**, Settings > Network
routes, the Memory tab). The **full pack** is a second release asset that carries
all of them, already downloaded and checked, for computers that should not
download anything on first use, or that are offline.

It holds the tools Antinomie manages: capa, FLOSS, UPX, Detect It Easy, Ghidra
with its Temurin JDK, Volatility 3, MemNixFS, Sigma (pySigma), Magika, GEF,
pwndbg, wireproxy and Tor. The list, URLs and SHA-256 values are read from the
app's own registry (`monitor-core/src/analysis_tools.rs`), so the pack cannot
drift from what the app would install. It does **not** hold bases, detection-rule
packs, IOC datasets or the system packages (QEMU, TShark, bubblewrap): those are
downloaded or installed separately. A tool already installed on the system still
takes precedence over the pack's copy.

## Install

Install the application first (see the [overview](../README.md#quick-start)), then:

```sh
sha256sum --check SHA256SUMS-full-pack
tar -xf antinomie-X.Y.Z-full-pack-linux-x86_64.tar.xz
cd antinomie-X.Y.Z-full-pack
./install-full-pack.sh               # into ~/antinomie/tools
./install-full-pack.sh --list        # what it holds; changes nothing
./install-full-pack.sh --data-dir DIR --only ghidra,capa --force
```

The installer checks every file against the pack's `SHA256SUMS`, then installs
each tool beside the others with the same rename-when-complete step the app
uses, so **Tools > Analysis tools** shows it as installed. A tool already
installed at the same version is left alone (`--force` reinstalls). Sigma needs
`/usr/bin/python3` 3.11 or newer with `python3-venv`, as when the app installs it;
the pack carries the hash-locked wheels (for Python 3.11, 3.12 and 3.13) and the
installer builds the environment from them offline. It never downloads, and
never touches bases, VMs or recordings. Remove a tool from the app as usual.

## Contents

```text
antinomie-X.Y.Z-full-pack/
  tools/<id>/…               each tool as the app unpacks it, with tool.json
  wheels/sigma/              hash-locked wheels and requirements.txt
  licenses/<id>/             licence text the upstream download lacks, Debian copyright files
  THIRD-PARTY-NOTICES-FULL-PACK.md
  MANIFEST.json  SHA256SUMS  README.txt
  install-full-pack.sh  install-full-pack.py
```

## Build it

```sh
python3 scripts/build-full-pack.py --output dist           # needs curl, tar, xz, pip
scripts/build-release.sh --full-pack dist                  # the application archive too
python3 scripts/test-full-pack.py                          # offline self-test
```

The builder fetches each pinned URL (HTTPS only) into `dist/.full-pack-cache`,
checks size and SHA-256, unpacks with the app's rules (stripped path components,
no `..`, safe symlinks, file modes), and fails if a tool lacks its entry file or
any licence file. `--no-network` uses the cache only. It writes
`antinomie-X.Y.Z-full-pack-linux-x86_64.tar.xz`, `antinomie-X.Y.Z-full-pack.manifest.json`
(every tool, version, URL, hash, tree hash and licence file, plus the archive's
size and hash) and `SHA256SUMS-full-pack`. Nothing is uploaded; the release
workflow attaches the files after the application release exists, so an
unavailable tool host never blocks the application itself.

A new managed tool needs an entry in `scripts/full-pack/policy.json` (its
redistribution decision); the builder refuses to run without it.

## Size

The pinned downloads add up to 1,079,424,617 octets (about 1.0 GiB). Unpacked, the
tools take roughly 2.5 to 3 GiB (Ghidra and its JDK are the bulk; the pwndbg
build alone is about 665 MiB). The compressed archive is expected to be about
1.0 to 1.3 GiB; these are estimates, and the builder prints the real numbers.
It enforces a budget: the archive must stay under 2,000,000,000 octets
(`--max-archive-bytes`; GitHub refuses release assets of 2 GiB), and the unpacked
tools under 6 GiB (`--max-unpacked-bytes`). Building needs about three times the
download size in free disk space.

## Licences

The pack redistributes unmodified upstream releases. Each tool's licence files
stay in its folder; `THIRD-PARTY-NOTICES-FULL-PACK.md` lists versions, hashes and
the source locations, with a written offer for the corresponding source of
copyleft components. This table is a summary, not legal advice.

| Tool | Licence | In the pack | What it requires |
|---|---|---|---|
| capa, FLOSS | Apache-2.0 | yes | Licence and NOTICE kept. PyInstaller executables embed libraries whose notices the releases do not list. |
| UPX | GPL-2.0-or-later with stub exception | yes | COPYING/LICENSE kept; source available (offer). |
| Detect It Easy | MIT; Qt LGPL-3.0; ICU Unicode | yes | LGPL libraries stay replaceable shared libraries; ICU copyright file kept. |
| Ghidra | Apache-2.0 | yes | Licence, NOTICE and licenses folder kept. |
| Temurin 21 JDK (with Ghidra) | GPL-2.0 with Classpath Exception | yes | Legal notices kept; source available (offer). |
| Volatility 3 and its wheels | Volatility Software License 1.0; MIT; BSD | yes, flagged | The licence text must travel with it (supplied). Its copyleft covers "Additions", including wrappers that run it and parse its results: maintainer review recommended before publishing. |
| MemNixFS (with libfmt, libfuse3) | Apache-2.0; MIT; LGPL-2.1+ | yes | libfuse3 stays a shared library; Debian copyright files kept. |
| Sigma (pySigma and wheels) | LGPL-3.0; LGPL-2.1; others | yes | Unmodified wheels with their dist-info licences. |
| Magika | Apache-2.0 | yes | The release asset has only the executable: the licence text is supplied. |
| GEF (bata24) | MIT | yes | Licence text supplied. |
| pwndbg portable | MIT; bundles GDB 17.2 (GPL-3.0+), Python (PSF) and libraries | yes, flagged | The pack becomes a distribution of GDB: GPL-3.0 source availability applies (offer); the maintainer must be ready to honour it. |
| wireproxy | ISC; wireguard-go MIT and other Go modules | yes | Licence text supplied; embedded Go module notices are not listed upstream. |
| Tor Expert Bundle | BSD-3-Clause (also marked GPL-3.0+); libevent BSD; OpenSSL Apache-2.0; transports | yes | The bundle's docs/ licence folder is kept; redistribute unmodified. |

No managed tool's licence forbids redistribution, so none is left out. To leave
one out, set `"redistribute": false` in `scripts/full-pack/policy.json`; the
notices then list it as left out and the app downloads it on request as usual.
[THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md) says the application does not
redistribute these tools; that describes the application archive, and the same
file names the full pack as the exception.
