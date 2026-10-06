# Third-party notices

These materials are not relicensed by the root MIT license. This inventory
records known embedded UI assets and distribution boundaries; it is not a
complete transitive-dependency or binary-release compliance audit.

## Embedded UI assets

The UI uses egui default fonts and the regular egui-phosphor icon font.
Notices below are retained for these bundled assets, not promotional credits.

| Locked component / material | Terms / retained notice |
|---|---|
| `epaint_default_fonts 0.31.1` / Hack | MIT and Bitstream Vera terms in [Hack-Regular.txt](LICENSES/third-party/fonts/Hack-Regular.txt) |
| `epaint_default_fonts 0.31.1` / Noto Emoji | SIL OFL 1.1 in [OFL.txt](LICENSES/third-party/fonts/OFL.txt) |
| `epaint_default_fonts 0.31.1` / Ubuntu Light | Ubuntu Font License 1.0 in [UFL.txt](LICENSES/third-party/fonts/UFL.txt) |
| `epaint_default_fonts 0.31.1` / emoji icon font | MIT in [emoji-icon-font-mit-license.txt](LICENSES/third-party/fonts/emoji-icon-font-mit-license.txt) |
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
The core also uses the already locked `vt100 0.15.2` for terminal persistence;
moving a dependency to core does not change its upstream terms.

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
