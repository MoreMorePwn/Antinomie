# The Antinomie guest kernel patch series

The guest kernel is Debian's `linux` 6.12.94-1 (trixie) with Antinomie's own
patch series on top. The series is fourteen topic patches; each one adds one
part of the design and says, in its description, what it adds, why, which
existing kernel files it hooks and why there, and which contract revision it
belongs to.

## Two copies, one canonical

| Copy | Format | Used by |
|---|---|---|
| `src/antinomie/core/6.12/*.patch` | `git format-patch` mail format, file names truncated by git | **Canonical.** `scripts/build-base.py` applies it, `scripts/build-monitor-kernel.sh` hashes it into the kernel's series identity, `scripts/bootstrap.sh` replays it into the author tree, and the app embeds it in its base build kit |
| `src/antinomie/patches/debian-6.12.94-1-trixie/antinomie/` | Quilt: DEP-3 header and the same diff, listed in `series` with section comments | The Debian packaging workflow in [CONTRIBUTING.md](../../../CONTRIBUTING.md#5-adding-a-patch) |

The Quilt view is derived and never edited by hand. Regenerate it from the
canonical copy, and check that it is in step:

```bash
python3 scripts/sync-quilt-view.py           # rewrite the view from core/6.12
python3 scripts/sync-quilt-view.py --check   # change nothing; exit 1 if out of step
```

The rewrite takes each view patch's DEP-3 header from the series patch's commit
message (the subject is `Description`, the body its long description, `Last-Update`
the patch date; `Origin: project` and `Forwarded: no` unless a last paragraph of
`Origin:`, `Forwarded:` or `Bug:` lines says otherwise) and its diff from the
series patch, removes view patches the series no longer has, and keeps the
comment lines of `series` above the patch they preceded.

## Topics

New files are the topic's own; hooked files are existing kernel files it
changes. Line counts are added/removed lines of the patch.

| # | Patch | Lines | Own new files | Hooked kernel files |
|---|---|---|---|---|
| 1 | add the host control channel and its shared-memory transport | +1462 | `kernel/antinomie/{abi.h,queue.h,bootstrap_layout.h,bootstrap.c,guest.c,control.c,control_wire.h,Kconfig,Makefile}`, `include/linux/antinomie.h`, `include/linux/antinomie_boot.h` | `arch/x86/kernel/setup.c`, `arch/x86/boot/compressed/kaslr.c`, `drivers/firmware/efi/libstub/x86-stub.c`, `init/Kconfig`, `kernel/Makefile` |
| 2 | license the shared transport headers under MIT | +8 -4 | none (`abi.h`, `bootstrap_layout.h`, `queue.h`, `control_wire.h` change licence) | none |
| 3 | add the generated table of x86-64 system calls | +4381 | `kernel/antinomie/native_syscalls.h` (generated) | none |
| 4 | record the system calls of launched and attached processes | +1528 -3 | `kernel/antinomie/{recorder.c,observer.c,observer.h}`, `include/linux/antinomie_monitor.h` | `arch/x86/entry/common.c`, `kernel/fork.c`, `kernel/exit.c`, `fs/exec.c`, `include/linux/sched.h` |
| 5 | decode system call arguments by syscall family | +3816 -13 | `kernel/antinomie/{native_capture.c,native_capture.h,capture_api.h}` | `ipc/sem.c` |
| 6 | track each launched run and stop its whole process tree | +403 -8 | `kernel/antinomie/{run.c,run.h}` | `include/linux/sched.h`, `kernel/fork.c`, `kernel/exit.c` |
| 7 | observe io_uring and AIO requests | +2359 -27 | `kernel/antinomie/{async.c,async.h,async_capture.c,async_capture.h}` | `io_uring/{io_uring.c,io_uring.h,epoll.c,fs.c,futex.c,kbuf.c,net.c,net.h,openclose.c,rsrc.c,rw.c,statx.c,timeout.c,uring_cmd.c,waitid.c,xattr.c}`, `include/linux/io_uring_types.h`, `fs/aio.c`, `include/linux/sched.h`, `kernel/fork.c` |
| 8 | capture the launched program's executable image | +575 -5 | `kernel/antinomie/{specimen.c,specimen.h}` | `fs/exec.c` |
| 9 | publish credentials, file identities and file hashes | +1468 -7 | `kernel/antinomie/{fileid.c,fileid.h,hash.c,hash.h,notes.h}` | `kernel/cred.c`, `kernel/audit.c`, `fs/open.c`, `fs/namei.c`, `fs/exec.c`, `fs/file_table.c`, `fs/aio.c`, `io_uring/{io_uring.c,io_uring.h,fs.c,openclose.c,splice.c}`, `include/linux/sched.h`, `kernel/fork.c` |
| 10 | capture process cores at exit and on request | +2320 -57 | `kernel/antinomie/{process_core.c,process_core.h,manual_core.c}` | `fs/coredump.c`, `fs/binfmt_elf.c`, `include/linux/coredump.h`, `kernel/exit.c`, `kernel/signal.c` |
| 11 | add a ptrace-free debug engine | +4487 -13 | `kernel/antinomie/{debug.c,debug.h,debug_x86.c}` | `kernel/signal.c`, `kernel/entry/common.c`, `kernel/fork.c`, `fs/exec.c`, `mm/memory.c` |
| 12 | sample guest memory and root filesystem usage | +234 | `kernel/antinomie/{resources.c,resources.h}` | none |
| 13 | launch programs as a terminal shell would have run them | +74 -4 | none (`control.c`, `control_wire.h`) | none |
| 14 | hide the recorder from programs in the guest | +227 -23 | `kernel/antinomie/{stealth.c,sections.h,section_begin.c,section_end.c}`, `include/linux/antinomie_stealth.h` | `arch/x86/kernel/setup.c`, `kernel/kallsyms.c`, `fs/proc/base.c`, `drivers/acpi/scan.c` |

Every topic also adds its part of the files shared by all of them:
`control.c` (dispatch), `control_wire.h` (the wire contract), `antinomie_monitor.h`
(the hooks' declarations), `recorder.c`, `Makefile`, `run.c` and `guest.c`. The
licence patch is kept apart because it has a licence meaning of its own: patch 1
introduces the four shared headers under the kernel's GPL-2.0-only, patch 2 makes
them MIT, and what later patches add to them is MIT.

Patch 1 builds alone; each later patch builds on the ones before it
(checked with an out-of-tree `bzImage` build of every prefix of the series).

## Series identity

The kernel reports `CONFIG_ANTINOMIE_SOURCE_ID` = `"<revision>:<series sha256>"`
(the INFO command, and IKCONFIG). The series hash is the SHA-256 of
`sha256sum -- *.patch` run in `src/antinomie/core/6.12`, so it changes with any
byte of any patch file, commit messages and file names included, even when the
patched source does not. `build-base.py`, `build-monitor-kernel.sh` and
`monitor-core/src/kit.rs` compute the same value; the app's kernel cache key
includes it, so a new series rebuilds the kernel once. The host checks only that
the source id is well formed and names the reported revision; it does not pin a
hash.

## Changing the series

Edit in the author tree (`work/debian-6.12.94-1-trixie/core`, made by
`scripts/bootstrap.sh`), whose history is the baseline tag
`baseline/debian-6.12.94-1-trixie` and one commit per patch.

- A change to an existing topic is a fixup of that topic's commit
  (`git commit --fixup <topic>`, then `git rebase -i --autosquash
  baseline/debian-6.12.94-1-trixie`), followed by a full export:

  ```bash
  cd work/debian-6.12.94-1-trixie/core
  rm ../../../src/antinomie/core/6.12/*.patch
  git format-patch -N -o ../../../src/antinomie/core/6.12 baseline/debian-6.12.94-1-trixie
  cd ../../.. && python3 scripts/sync-quilt-view.py
  ```

- A new topic is a new commit at the end; `scripts/commit.sh` exports it and
  rewrites the view.

Keep hooks in existing kernel files small and put the code in `kernel/antinomie/`.
A patch's description says what it adds, why, which kernel files it hooks and
why there, and the contract revision; plain English, no ticket ids.

## Verifying a rewrite

A rewrite that only regroups or re-describes patches must leave the patched
kernel source byte-identical. Apply the old and the new series to two copies of
the pristine Debian source, the way `build-base.py` prepares it, and compare:

```bash
mkdir -p /var/tmp/series-check/pkg && cd /var/tmp/series-check/pkg
ln -s "$REPO"/src/debian/linux_6.12.94-1.dsc "$REPO"/src/debian/linux_6.12.94-1.debian.tar.xz \
      /path/to/linux_6.12.94.orig.tar.xz .
dpkg-source --no-copy -x linux_6.12.94-1.dsc ../old   # Debian's own patches applied
cp -a ../old ../new
for p in /path/to/old/core/6.12/*.patch; do patch -p1 --fuzz=0 --forward --batch -s -d ../old -i "$p"; done
for p in "$REPO"/src/antinomie/core/6.12/*.patch; do patch -p1 --fuzz=0 --forward --batch -s -d ../new -i "$p"; done
diff -r ../old ../new && echo identical
```

The series identity is not part of the tree (the build writes it into the
kernel configuration), so the trees compare equal; only the kernel's source id
changes. If a rewrite also changes code, build each prefix of the series and run
the guest conformance tier as for any kernel change.

## History

The series was reorganised by topic for 0.7.1. Before that it was 60 patches in
development order, which `docs/implementation.md` and `CHANGELOG.md` cite by
number. The old patches went into these topics:

| Topic | Old patches |
|---|---|
| 1 | 0001 (transport and control), 0013, 0018, 0019, 0027, 0032, 0052, and the transport functions of 0012 and 0056 |
| 2 | 0002 |
| 3 | the system call table of 0004 |
| 4 | 0001 (recorder), 0003 (lineage tag), 0004 (recorder), 0012 (non-resident pages), 0016, 0017, 0051 (terminal ioctls), 0053 |
| 5 | 0004 (native decoders), 0005, 0006, 0007, 0008, 0009, 0011 (semctl operand) |
| 6 | 0003 (tree stop), 0004 (run tracking), 0033, 0043 |
| 7 | 0004 (async), 0010, 0011, 0012, 0016 (async admission), 0051, 0055, 0056 |
| 8 | 0014, 0015 |
| 9 | 0029, 0044, 0045, 0054, 0057 |
| 10 | 0021, 0022, 0023, 0024, 0025, 0026, 0034, 0039, 0040 |
| 11 | 0030, 0031, 0035, 0036, 0037, 0038, 0041, 0042, 0058, 0059, 0060 |
| 12 | 0028 |
| 13 | 0020, 0050 |
| 14 | 0046, 0047, 0048, 0049 |
