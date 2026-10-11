# Third-party notices

These materials are not relicensed by the root MIT license. This inventory
records known embedded UI assets and distribution boundaries; it is not a
complete transitive-dependency or binary-release compliance audit.

## Embedded analysis rules and engines

The static-analysis worker embeds two rule sets and links two analysis
engines. The rule files keep every rule's author, license and source meta.

| Component | Terms / retained notice |
|---|---|
| Antinomie rules, `crates/monitor-core/assets/rules/antinomie.yar` | MIT (this project) |
| Community rules from YARA-Forge release 20261004 (core package), `crates/monitor-core/assets/rules/yara-forge-core.yar`, reduced by `scripts/refresh-yara-rules.py` to the 2096 rules whose license meta allows redistribution | Per rule, as its `license` or `malpedia_license` meta states: CC BY-SA 4.0 ([CC-BY-SA-4.0.txt](LICENSES/third-party/rules/CC-BY-SA-4.0.txt); Malpedia rules), Detection Rule License 1.1 ([DRL-1.1.md](LICENSES/third-party/rules/DRL-1.1.md)), BSD 2-Clause ([BSD-2-Clause.txt](LICENSES/third-party/rules/BSD-2-Clause.txt)), Apache License 2.0 ([Apache-2.0.txt](LICENSES/third-party/rules/Apache-2.0.txt)), CC BY 4.0 ([CC-BY-4.0.txt](LICENSES/third-party/rules/CC-BY-4.0.txt)), MIT ([MIT.txt](LICENSES/third-party/rules/MIT.txt)). Rules without a redistributable license are not included |
| capa-rules v9.4.0 (Mandiant), `crates/monitor-core/assets/rules/capa-rules-v9.4.0.tar.gz` | Apache License 2.0 in [capa-rules-Apache-2.0.txt](LICENSES/third-party/rules/capa-rules-Apache-2.0.txt) |
| `yara-x 1.21` (VirusTotal) and its dependencies | BSD-3-Clause (yara-x); dependencies under their own licenses |
| `iced-x86 1.21` | MIT |

Ghidra, radare2, capa, Detect It Easy, objdump, readelf and file are not
bundled: the worker runs them when they are installed on the host. On the
user's request (**Tools > Analysis tools**) the app downloads capa 9.4.0
(Apache-2.0), Detect It Easy 3.21 (MIT, with Qt under LGPL-3.0) plus Ubuntu's
ICU 66 libraries (Unicode license), and Ghidra 12.1.4 (Apache-2.0) with the
Eclipse Temurin 21 JDK (GPL-2.0 with Classpath exception) directly from their
upstream releases into the user's data folder; Antinomie does not
redistribute them. Their license files arrive with each download.

For memory analysis, the same dialog (or **Install Volatility 3** in the
Memory tab) downloads Volatility 3 2.28.2 (Volatility Software License 1.0)
with pefile 2024.8.26 (MIT), Capstone 5.0.9 (BSD-3-Clause) and PyCryptodome
3.23.0 (BSD-2-Clause and public domain) as pinned wheels from PyPI; they run
on the host's Python 3 and are not redistributed either. Base builds download
Volatility's dwarf2json 0.9.0 (Volatility Software License 1.0) to write each
kernel's symbol table; the tool is not part of any base. The symbol table
(`symbols.json.xz`) describes the base's Linux kernel and ships with it under
the kernel's GPL-2.0.

The Memory tab's community plugin catalog lists third-party Volatility 3
plugins by their upstream repository, a pinned commit and the SHA-256 of each
file; installing one downloads it from that repository into the user's data
folder, with its license file (Apache-2.0, GPL-3.0 or MIT, as listed), and
applies the small compatibility edits the catalog shows. Antinomie does not
redistribute them. Symbol tables of dumps without their own are looked up,
when the user allows it, in Abyss-W4tcher/volatility3-symbols on GitHub by
Volatility itself; they are downloaded to Volatility's cache and not
redistributed.

## Embedded UI assets

The UI uses the DejaVu fonts (text and data), egui default fonts as fallbacks and the regular egui-phosphor icon font.
Notices below are retained for these bundled assets, not promotional credits.

| Locked component / material | Terms / retained notice |
|---|---|
| `epaint_default_fonts 0.31.1` / Hack | MIT and Bitstream Vera terms in [Hack-Regular.txt](LICENSES/third-party/fonts/Hack-Regular.txt) |
| `epaint_default_fonts 0.31.1` / Noto Emoji | SIL OFL 1.1 in [OFL.txt](LICENSES/third-party/fonts/OFL.txt) |
| `epaint_default_fonts 0.31.1` / Ubuntu Light | Ubuntu Font License 1.0 in [UFL.txt](LICENSES/third-party/fonts/UFL.txt) |
| `epaint_default_fonts 0.31.1` / emoji icon font | MIT in [emoji-icon-font-mit-license.txt](LICENSES/third-party/fonts/emoji-icon-font-mit-license.txt) |
| DejaVu Sans and DejaVu Sans Mono 2.37 (Debian `fonts-dejavu-core` 2.37-8), bundled in `crates/monitor-ui/assets/fonts` | Bitstream Vera and Arev font terms, DejaVu changes in the public domain; [DejaVu-copyright.txt](LICENSES/third-party/fonts/DejaVu-copyright.txt) |
| `egui-phosphor 0.9.0` binding | MIT option selected; [egui-phosphor-MIT.txt](LICENSES/third-party/fonts/egui-phosphor-MIT.txt) |
| Phosphor Icons 2.1.0 font bundled by that crate | MIT; [Phosphor-Icons-MIT.txt](LICENSES/third-party/fonts/Phosphor-Icons-MIT.txt) |

Font notices were copied from the locked crate source distributions. The icon
notice is from the upstream web license linked by egui-phosphor's README,
retrieved at commit `3d40a3eaa73b25d20d263f0e1e55c9fed3e66809`:
https://github.com/phosphor-icons/web/blob/3d40a3eaa73b25d20d263f0e1e55c9fed3e66809/LICENSE.
The locked font metadata also supplies these copyright statements, retained
here alongside the generic font license texts:

Noto Emoji: Copyright 2013 Google Inc. All Rights Reserved.

Ubuntu Light: Copyright 2011 Canonical Ltd. Licensed under the Ubuntu Font Licence 1.0

Retain these notices with any redistributed executable embedding the assets.
Font licenses can impose additional requirements on modified fonts; copying
their notices does not authorize removal of those requirements.

## Other components and release gate

Static-analysis executable parsing uses `object 0.40.0` with read/std features
only (no write, build or automatic compression). The MIT option is selected;
its unmodified locked crate notice is retained in
[object-MIT.txt](LICENSES/third-party/object-MIT.txt). Generic byte analysis is
original code. Optional external analysis tools and isolation utilities retain
their own terms and are not relicensed or bundled by this dependency addition.

The native workspace uses `egui_dock 0.16.0` under MIT. Its unmodified crate
notice is retained in [egui-dock-MIT.txt](LICENSES/third-party/egui-dock-MIT.txt).
The adapter for separate operating-system viewports is original project code;
the library's ordinary floating windows alone are not native windows.

The recording browser uses `rusqlite 0.40.2` and `libsqlite3-sys 0.38.2`;
their identical MIT copyright/permission text is retained in
[rusqlite-MIT.txt](LICENSES/third-party/rusqlite-MIT.txt), copied from both
locked crate distributions. SQLite is linked from the system, not bundled by
this build. Its upstream code is public domain; see
[SQLite copyright](https://www.sqlite.org/copyright.html). Packaging must still
inventory the actual library shipped and the crates' transitive dependencies.
The core and UI use `vt100 0.16.2` for terminal persistence and scrollback,
including corrected history offsets and cursor restoration after resizing;
the version update does not change its upstream MIT terms. The copyright and
permission notices for `vt100` and its updated parser dependency `vte 0.15.0`
(MIT option selected) are copied from the locked crate distributions in
[vt100-MIT.txt](LICENSES/third-party/vt100-MIT.txt) and
[vte-MIT.txt](LICENSES/third-party/vte-MIT.txt).

Malware samples are read from MalwareBazaar's AES archives with the `zip`
crate's `aes-crypto` feature, which brings the RustCrypto crates `aes`,
`cipher`, `pbkdf2`, `hmac`, `sha1`, `digest` and their helpers (`block-buffer`,
`crypto-common`, `inout`, `hybrid-array`, `cpufeatures`, `cpubits`, `cmov`,
`ctutils`, `const-oid`, `zeroize`, `typenum`), each under MIT or Apache-2.0,
and `constant_time_eq` (CC0-1.0, MIT-0 or Apache-2.0). Samples themselves are
downloaded by the user from MalwareBazaar under abuse.ch's terms with their own
API key; Antinomie hosts and redistributes none.

The launch module directly uses already-locked `x11rb 0.13.2` and `rustix 1.1.5`
for bounded X11/XWayland window sizing and deadline-aware polling. MIT options
are selected; original notices are retained in
[x11rb-MIT.txt](LICENSES/third-party/x11rb-MIT.txt),
[rustix-MIT.txt](LICENSES/third-party/rustix-MIT.txt) and
[rustix-COPYRIGHT.txt](LICENSES/third-party/rustix-COPYRIGHT.txt), copied from
the locked crate distributions. This does not complete the transitive audit.

Rust crates, linked system libraries and external tools retain their own terms.
Use the locked Cargo metadata and actual packaged artifacts, not just the
application manifest, to inventory a release. The source workspace's MIT
metadata describes its own crates, not all dependencies.

The image builder uses Linux, BusyBox, e2fsprogs utilities and guest libraries.
Kernel/BusyBox/e2fsprogs GPL and library-specific terms still apply. Before
publishing executables or guest images, review every distributed component,
collect its applicable notices, and provide matching source or another valid
license-compliant source arrangement when required. Do not label an entire
guest image MIT or claim that this notice inventory completes that review.

The optional Debian desktop pipeline uses external libguestfs tools and an
authenticated Debian template/package repository. These tools are not copied
into the monitor ELF. The generated guest retains `/usr/share/doc/*/copyright`,
package/version inventory and template/build provenance; Debian packages,
Xfce, Xorg, fonts and libraries retain their individual upstream terms. A local
development image is not a license-cleared redistribution bundle. Distributing
it requires the same component-specific notice/source review above, including
the exact patched kernel build.
