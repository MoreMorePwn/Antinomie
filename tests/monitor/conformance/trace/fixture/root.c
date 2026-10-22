// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// root.c — privileged success variants, run as UID 0 in a disposable VM.
// Every effect is private (a child's own namespaces or process state, files
// in work_dir) or undone before the area returns.
//
// Slots (success paths): mount umount2 pivot_root chroot sethostname
// setdomainname swapon swapoff acct reboot kexec_load kexec_file_load
// init_module finit_module delete_module iopl ioperm settimeofday
// clock_settime setuid setgid setgroups capset sched_setscheduler
// setpriority mknod fanotify_init fanotify_mark name_to_handle_at
// open_by_handle_at setns open_tree fsopen fsconfig fsmount move_mount fspick
// mount_setattr statmount listmount bpf perf_event_open syslog quotactl
// vhangup mlockall process_mrelease userfaultfd memfd_secret migrate_pages
// move_pages.
#include "areas.h"

#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/kexec.h>
#include <linux/perf_event.h>
#include <linux/reboot.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/quota.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>

#ifndef SYSLOG_ACTION_READ_ALL
#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_SIZE_BUFFER 10
#endif
#ifndef KEXEC_FILE_UNLOAD
#define KEXEC_FILE_UNLOAD 0x1
#endif
#ifndef KEXEC_SEGMENT_MAX
#define KEXEC_SEGMENT_MAX 16
#endif
#ifndef MCL_ONFAULT
#define MCL_ONFAULT 4
#endif
#ifndef AT_HANDLE_MNT_ID_UNIQUE
#define AT_HANDLE_MNT_ID_UNIQUE 0x001
#endif
#ifndef STATX_MNT_ID_UNIQUE
#define STATX_MNT_ID_UNIQUE 0x4000U
#endif
#ifndef MNT_ID_REQ_SIZE_VER0
#define MNT_ID_REQ_SIZE_VER0 24
#endif
#ifndef STATMOUNT_SB_BASIC
#define STATMOUNT_SB_BASIC 0x1U
#define STATMOUNT_MNT_BASIC 0x2U
#endif
#ifndef LSMT_ROOT
#define LSMT_ROOT 0xffffffffffffffffULL
#endif
#define PERF_ATTR_SIZE_612 136
#define SWAP_PAGES 64
#define HANDLE_CAPACITY 128

static char mount_options[4096] __attribute__((aligned(4096))) = "size=1m,mode=0700";
static char move_page[4096] __attribute__((aligned(4096)));
static const struct bpf_insn return_zero[2] = {
    {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0},
    {.code = BPF_JMP | BPF_EXIT},
};
static const struct bpf_insn lone_exit[1] = {{.code = BPF_JMP | BPF_EXIT}};

// See system.c: map every page of the image before pointing a call into it;
// forked children start without page-table entries for file pages.
static void make_resident(void)
{
    char line[512], path[300];
    unsigned long start, end;
    FILE *maps = fopen("/proc/self/maps", "re");
    if (!maps) {
        ora_fail("root: read the process maps");
        return;
    }
    while (fgets(line, sizeof line, maps)) {
        char perms[8];
        path[0] = 0;
        if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %299s", &start, &end, perms, path) < 3)
            continue;
        if (perms[0] != 'r' || strcmp(path, self_path) != 0)
            continue;
        for (unsigned long page = start; page < end; page += 4096)
            (void)*(volatile const char *)page;
    }
    fclose(maps);
}

static void private_mounts(void)
{
    if (unshare(CLONE_NEWNS) != 0 || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
        ora_fail("root: private mount namespace");
}

// --- mount, umount2, pivot_root, chroot (children with private namespaces)

static void mount_child(void *unused)
{
    (void)unused;
    make_resident();
    if (unshare(CLONE_NEWNS) != 0)
        ora_fail("root: unshare mount namespace");
    CALL("mount.make_private", mount, WANT_OK, NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
    in_str(1, "/");
    why("first call in a fresh mount namespace: nothing propagates back to the parent");
    DONE();
    CALL("mount.tmpfs", mount, WANT_OK, "ant-tmpfs", "root-mnt", "tmpfs", MS_NOSUID | MS_NODEV,
         mount_options);
    in_str(0, "ant-tmpfs");
    in_str(1, "root-mnt");
    in_str(2, "tmpfs");
    in_key("arg4.data", mount_options, sizeof mount_options);
    why("a 1 MiB tmpfs in this child's private mount namespace");
    DONE();
    CALL("mount.remount_ro", mount, WANT_OK, NULL, "root-mnt", NULL, MS_REMOUNT | MS_RDONLY,
         NULL);
    in_str(1, "root-mnt");
    DONE();
    CALL("mount.bind", mount, WANT_OK, "root-mnt", "root-bind", NULL, MS_BIND, NULL);
    in_str(0, "root-mnt");
    in_str(1, "root-bind");
    DONE();
    CALL("mount.bind_missing", mount, ENOENT, "root-missing", "root-bind", NULL, MS_BIND, NULL);
    in_str(0, "root-missing");
    in_str(1, "root-bind");
    DONE();
    CALL("umount2.bind", umount2, WANT_OK, "root-bind", 0);
    in_str(0, "root-bind");
    DONE();
    CALL("umount2.detach", umount2, WANT_OK, "root-mnt", MNT_DETACH);
    in_str(0, "root-mnt");
    DONE();
    CALL("umount2.not_mounted", umount2, EINVAL, "root-mnt", 0);
    in_str(0, "root-mnt");
    DONE();
}

static void pivot_child(void *unused)
{
    (void)unused;
    make_resident();
    private_mounts();
    if (mount("ant-pivot", "root-pr", "tmpfs", 0, "size=64k") != 0 || mkdir("root-pr/old", 0700))
        ora_fail("root: pivot root mount");
    CALL("pivot_root.missing_put_old", pivot_root, ENOENT, "root-pr", "root-pr/missing");
    in_str(0, "root-pr");
    in_str(1, "root-pr/missing");
    DONE();
    long done = CALL("pivot_root.private_ns", pivot_root, WANT_ANY, "root-pr", "root-pr/old");
    in_str(0, "root-pr");
    in_str(1, "root-pr/old");
    why("only this child's private mount namespace changes root; EINVAL when the guest root "
        "is the initramfs rootfs, which cannot be pivoted");
    DONE();
    if (done == 0 && (chdir("/") != 0 || umount2("/old", MNT_DETACH) != 0))
        ora_fail("root: leave the old root");
}

static void chroot_child(void *unused)
{
    (void)unused;
    make_resident();
    CALL("chroot.missing_root", chroot, ENOENT, "root-missing");
    in_str(0, "root-missing");
    DONE();
    CALL("chroot.not_directory", chroot, ENOTDIR, "root-file");
    in_str(0, "root-file");
    DONE();
    CALL("chroot.work_dir", chroot, WANT_OK, ".");
    in_str(0, ".");
    why("only this child's root changes; it exits right after");
    DONE();
}

static void uts_child(void *unused)
{
    (void)unused;
    make_resident();
    if (unshare(CLONE_NEWUTS) != 0)
        ora_fail("root: unshare UTS namespace");
    CALL("sethostname.private_uts", sethostname, WANT_OK, "ant-host", 8);
    in_buf(0, "ant-host", 8);
    why("the host name changes in this child's own UTS namespace only");
    DONE();
    char long_name[80];
    memset(long_name, 'h', sizeof long_name);
    CALL("sethostname.too_long", sethostname, EINVAL, long_name, 65);
    want_status(0, "in", "INVALID_EXTENT");
    DONE();
    CALL("setdomainname.private_uts", setdomainname, WANT_OK, "ant-domain", 10);
    in_buf(0, "ant-domain", 10);
    why("the domain name changes in this child's own UTS namespace only");
    DONE();
    CALL("setdomainname.negative_len", setdomainname, EINVAL, "ant-domain", -1);
    want_status(0, "in", "INVALID_EXTENT");
    DONE();
}

// --- the new mount API in a private mount namespace

static void mount_api_child(void *unused)
{
    (void)unused;
    make_resident();
    private_mounts();
    unsigned char blob[3] = {1, 2, 3};
    long fs = CALL("fsopen.tmpfs", fsopen, WANT_OK, "tmpfs", FSOPEN_CLOEXEC);
    in_str(0, "tmpfs");
    why("a tmpfs context in this child's private mount namespace");
    DONE();
    CALL("fsopen.bad_flags", fsopen, EINVAL, "tmpfs", 0x80);
    in_str(0, "tmpfs");
    DONE();
    CALL("fsconfig.set_string_size", fsconfig, WANT_OK, fs, FSCONFIG_SET_STRING, "size", "1m", 0);
    in_str(2, "size");
    in_str(3, "1m");
    DONE();
    CALL("fsconfig.set_flag_unknown", fsconfig, EINVAL, fs, FSCONFIG_SET_FLAG, "ant_unknown",
         NULL, 0);
    in_str(2, "ant_unknown");
    why("tmpfs rejects an unknown parameter without failing the context");
    DONE();
    CALL("fsconfig.set_binary_rejected", fsconfig, EINVAL, fs, FSCONFIG_SET_BINARY, "size", blob,
         sizeof blob);
    in_str(2, "size");
    in_buf(3, blob, sizeof blob);
    why("tmpfs size takes a string, not a binary blob");
    DONE();
    CASE("fsconfig.create", fsconfig, WANT_OK, fs, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
    CASE("fsconfig.create_again", fsconfig, EBUSY, fs, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
    long mnt = CASE("fsmount.tmpfs", fsmount, WANT_OK, fs, FSMOUNT_CLOEXEC,
                    MOUNT_ATTR_NODEV | MOUNT_ATTR_NOSUID);
    CASE("fsmount.bad_flags", fsmount, EINVAL, fs, 0x80, 0);
    CALL("move_mount.attach", move_mount, WANT_OK, mnt, "", AT_FDCWD, "root-fsmnt",
         MOVE_MOUNT_F_EMPTY_PATH);
    in_str(1, "");
    in_str(3, "root-fsmnt");
    DONE();
    CALL("move_mount.bad_flags", move_mount, EINVAL, AT_FDCWD, "root-fsmnt", AT_FDCWD,
         "root-fsmnt2", 0x80000000UL);
    in_str(1, "root-fsmnt");
    in_str(3, "root-fsmnt2");
    DONE();
    struct mount_attr ro = {.attr_set = MOUNT_ATTR_RDONLY};
    CALL("mount_setattr.read_only", mount_setattr, WANT_OK, AT_FDCWD, "root-fsmnt", 0, &ro,
         sizeof ro);
    in_str(1, "root-fsmnt");
    in_buf(3, &ro, sizeof ro);
    DONE();
    struct mount_attr nop;
    memset(&nop, 0, sizeof nop);
    CALL("mount_setattr.nop", mount_setattr, WANT_OK, AT_FDCWD, "root-fsmnt", 0, &nop,
         sizeof nop);
    in_str(1, "root-fsmnt");
    in_buf(3, &nop, sizeof nop);
    why("an empty change returns before the path is looked up");
    DONE();
    long pick = CALL("fspick.mount_root", fspick, WANT_OK, AT_FDCWD, "root-fsmnt",
                     FSPICK_CLOEXEC);
    in_str(1, "root-fsmnt");
    DONE();
    CASE("fsconfig.reconfigure", fsconfig, WANT_OK, pick, FSCONFIG_CMD_RECONFIGURE, NULL, NULL,
         0);
    CALL("fspick.not_mount_root", fspick, EINVAL, AT_FDCWD, ".", 0);
    in_str(1, ".");
    DONE();
    long tree = CALL("open_tree.clone", open_tree, WANT_OK, AT_FDCWD, "root-fsmnt",
                     OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
    in_str(1, "root-fsmnt");
    DONE();
    CALL("move_mount.attach_clone", move_mount, WANT_OK, tree, "", AT_FDCWD, "root-fsmnt2",
         MOVE_MOUNT_F_EMPTY_PATH);
    in_str(1, "");
    in_str(3, "root-fsmnt2");
    DONE();
    CALL("open_tree.missing", open_tree, ENOENT, AT_FDCWD, "root-missing", OPEN_TREE_CLONE);
    in_str(1, "root-missing");
    DONE();
    if (umount2("root-fsmnt2", MNT_DETACH) != 0 || umount2("root-fsmnt", MNT_DETACH) != 0)
        ora_fail("root: mount API cleanup");
    const long fds[] = {tree, pick, mnt, fs};
    for (size_t i = 0; i < sizeof fds / sizeof fds[0]; i++)
        if (fds[i] >= 0)
            close((int)fds[i]);
}

// --- swap, accounting, reboot, kexec, modules

static int write_swap_file(const char *name)
{
    static unsigned char page[4096];
    uint32_t version = 1, last = SWAP_PAGES - 1;
    int fd = open(name, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    int ok = 1;
    for (int i = 0; i < SWAP_PAGES && ok; i++) {
        memset(page, 0, sizeof page);
        if (i == 0) {
            memcpy(page + 1024, &version, 4);
            memcpy(page + 1028, &last, 4);
            memcpy(page + 4086, "SWAPSPACE2", 10);
        }
        ok = write(fd, page, sizeof page) == (ssize_t)sizeof page;
    }
    ok = ok && fsync(fd) == 0;
    close(fd);
    return ok ? 0 : -1;
}

static void swap_acct_cases(void)
{
    if (write_swap_file("root-swap") != 0)
        ora_fail("root: swap file");
    long on = CALL("swapon.file", swapon, WANT_ANY, "root-swap", 0);
    in_str(0, "root-swap");
    why("a 256 KiB swap file of this area, removed again by swapoff below; filesystems "
        "without swap-file support (tmpfs) refuse it with EINVAL");
    DONE();
    CALL("swapoff.file", swapoff, on >= 0 ? WANT_OK : EINVAL, "root-swap");
    in_str(0, "root-swap");
    why("undoes swapon.file; EINVAL when the file never became a swap area");
    DONE();
    CALL("swapon.missing", swapon, ENOENT, "root-missing", 0);
    in_str(0, "root-missing");
    DONE();
    CALL("swapoff.missing", swapoff, ENOENT, "root-missing");
    in_str(0, "root-missing");
    DONE();
    unlink("root-swap");

    int fd = open("root-acct", O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        ora_fail("root: accounting file");
    else
        close(fd);
    CALL("acct.file", acct, WANT_OK, "root-acct");
    in_str(0, "root-acct");
    why("accounting into a work_dir file, switched off again by acct.off");
    DONE();
    CALL("acct.off", acct, WANT_OK, NULL);
    want_status(0, "any", "NULL_POINTER");
    DONE();
    CALL("acct.missing", acct, ENOENT, "root-missing");
    in_str(0, "root-missing");
    DONE();
    unlink("root-acct");
}

static int read_cad(void)
{
    char text[16] = {0};
    int fd = open("/proc/sys/kernel/ctrl-alt-del", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    ssize_t got = read(fd, text, sizeof text - 1);
    close(fd);
    return got > 0 && atoi(text) != 0;
}

static void reboot_kexec_cases(void)
{
    int cad_was_on = read_cad();
    CALL("reboot.cad_off", reboot, WANT_OK, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
         LINUX_REBOOT_CMD_CAD_OFF, NULL);
    why("only changes what Ctrl-Alt-Del does; restored by reboot.cad_restore");
    DONE();
    CALL("reboot.cad_restore", reboot, WANT_OK, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
         cad_was_on ? LINUX_REBOOT_CMD_CAD_ON : LINUX_REBOOT_CMD_CAD_OFF, NULL);
    why("puts back the Ctrl-Alt-Del setting read from /proc/sys/kernel/ctrl-alt-del");
    DONE();
    CALL("reboot.bad_magic", reboot, EINVAL, LINUX_REBOOT_MAGIC1, 0x5678,
         LINUX_REBOOT_CMD_CAD_OFF, NULL);
    why("a wrong second magic is rejected before the command is looked at");
    DONE();
    CALL("reboot.unknown_cmd", reboot, EINVAL, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, 0x7fff,
         NULL);
    want_key_status("reboot.unknown_selector", "NO_DECODER");
    why("an unknown command falls to the default case of the switch: nothing happens");
    DONE();

    struct kexec_segment segments[KEXEC_SEGMENT_MAX + 1];
    memset(segments, 0, sizeof segments);
    CALL("kexec_load.unload", kexec_load, WANT_OK, 0, 0, NULL, KEXEC_ARCH_DEFAULT);
    in_buf(2, "", 0);
    why("zero segments unloads the staged kexec image; none is loaded in the guest");
    DONE();
    CALL("kexec_load.too_many_segments_root", kexec_load, EINVAL, 0, KEXEC_SEGMENT_MAX + 1,
         segments, KEXEC_ARCH_DEFAULT);
    want_status(2, "in", "INVALID_EXTENT");
    DONE();
    CALL("kexec_load.bad_flags", kexec_load, EINVAL, 0, 0, NULL, 0x100);
    in_buf(2, "", 0);
    DONE();
    CALL("kexec_file_load.unload", kexec_file_load, WANT_ANY, -1, -1, 0, NULL,
         KEXEC_FILE_UNLOAD);
    want_status(3, "any", "NULL_POINTER");
    why("unloads nothing; the pinned guest kernel has no CONFIG_KEXEC_FILE (ENOSYS)");
    DONE();
}

static void module_cases(void)
{
    unsigned char image[128];
    pattern(image, sizeof image, 9);
    CALL("init_module.garbage_image", init_module, ENOEXEC, image, sizeof image, "");
    in_buf(0, image, sizeof image);
    in_str(2, "");
    why("the image has no ELF magic: rejected before anything is loaded");
    DONE();
    int fd = open("root-module", O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 || write(fd, image, sizeof image) != (ssize_t)sizeof image)
        ora_fail("root: module file");
    if (fd >= 0)
        close(fd);
    fd = open("root-module", O_RDONLY | O_CLOEXEC);
    CALL("finit_module.not_a_module", finit_module, ENOEXEC, fd, "", 0);
    in_str(1, "");
    why("a work_dir file without ELF magic: read, then rejected");
    DONE();
    CALL("finit_module.bad_flags", finit_module, EINVAL, fd, "", 0x40);
    in_str(1, "");
    DONE();
    CALL("finit_module.badf", finit_module, EBADF, 999, "", 0);
    in_str(1, "");
    DONE();
    if (fd >= 0)
        close(fd);
    unlink("root-module");
    CALL("delete_module.missing", delete_module, ENOENT, "ant_missing", O_NONBLOCK);
    in_str(0, "ant_missing");
    why("no module of that name is loaded: nothing is unloaded");
    DONE();
}

static void io_port_child(void *unused)
{
    (void)unused;
    make_resident();
    CALL("ioperm.on_root", ioperm, WANT_OK, 0x80, 1, 1);
    why("grants this child port 0x80 only; it never touches the port and exits");
    DONE();
    CASE("ioperm.off_root", ioperm, WANT_OK, 0x80, 1, 0);
    CALL("iopl.raise_root", iopl, WANT_OK, 3);
    why("this child's emulated I/O privilege level; no port is accessed");
    DONE();
    CASE("iopl.lower_root", iopl, WANT_OK, 0);
}

// --- time, identity, scheduling, devices

static void time_cases(void)
{
    struct timeval tv;
    struct timespec ts;
    gettimeofday(&tv, NULL);
    CALL("settimeofday.same_time", settimeofday, WANT_OK, &tv, NULL);
    in_buf(0, &tv, sizeof tv);
    want_status(1, "any", "NULL_POINTER");
    volatile_case();
    why("sets the wall clock to the value just read (a few microseconds back); no time zone, "
        "so the clock is never warped. CLOCK_MONOTONIC, used by the trace, is unaffected");
    DONE();
    struct timeval bad = {.tv_sec = tv.tv_sec, .tv_usec = 2000000};
    CALL("settimeofday.bad_usec", settimeofday, EINVAL, &bad, NULL);
    in_buf(0, &bad, sizeof bad);
    want_status(1, "any", "NULL_POINTER");
    volatile_case();
    DONE();
    clock_gettime(CLOCK_REALTIME, &ts);
    CALL("clock_settime.same_time", clock_settime, WANT_OK, CLOCK_REALTIME, &ts);
    in_buf(1, &ts, sizeof ts);
    volatile_case();
    why("sets CLOCK_REALTIME to the value just read");
    DONE();
    CALL("clock_settime.monotonic", clock_settime, EINVAL, CLOCK_MONOTONIC, &ts);
    in_buf(1, &ts, sizeof ts);
    volatile_case();
    DONE();
}

static void identity_child(void *unused)
{
    (void)unused;
    make_resident();
    gid_t groups[1] = {1000};
    CALL("setgroups.one_group", setgroups, WANT_OK, 1, groups);
    in_buf(1, groups, sizeof groups);
    why("this child's supplementary groups only");
    DONE();
    CALL("setgroups.too_many", setgroups, EINVAL, 65537, groups);
    want_status(1, "in", "INVALID_EXTENT");
    DONE();
    CALL("setgroups.empty", setgroups, WANT_OK, 0, NULL);
    want_status(1, "any", "NULL_POINTER");
    DONE();

    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2];
    memset(data, 0, sizeof data);
    if (syscall(SYS_capget, &header, data) != 0)
        ora_fail("root: capget");
    data[0].effective &= ~(1U << CAP_SYS_BOOT);
    data[0].permitted &= ~(1U << CAP_SYS_BOOT);
    data[0].inheritable &= ~(1U << CAP_SYS_BOOT);
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;
    CALL("capset.drop_sys_boot", capset, WANT_OK, &header, data);
    in_key("arg0.version", &header.version, sizeof header.version);
    in_key("arg0.pid", &header.pid, sizeof header.pid);
    in_key("arg1.capabilities", data, sizeof data);
    why("this child drops CAP_SYS_BOOT from its own sets");
    DONE();
    struct __user_cap_header_struct bad = {0x12345678, 0};
    uint32_t bad_version = bad.version;
    CALL("capset.bad_version", capset, EINVAL, &bad, data);
    in_key("arg0.version", &bad_version, sizeof bad_version);
    out_key("arg0.required_version", &bad.version, sizeof bad.version);
    why("the kernel writes the version it prefers back into the header");
    DONE();

    CALL("setgid.user", setgid, WANT_OK, 1000);
    why("this child becomes group 1000 and then user 1000, then exits");
    DONE();
    CASE("setuid.user", setuid, WANT_OK, 1000);
    CALL("setuid.regain_root", setuid, EPERM, 0);
    why("setuid to a non-root user cleared every capability");
    DONE();
    CASE("setgid.regain_root", setgid, EPERM, 0);
}

static void sched_child(void *unused)
{
    (void)unused;
    make_resident();
    struct sched_param fifo = {.sched_priority = 1};
    CALL("sched_setscheduler.fifo", sched_setscheduler, WANT_OK, 0, SCHED_FIFO, &fifo);
    in_buf(2, &fifo, sizeof fifo);
    why("this idle child at the lowest real-time priority, switched back below");
    DONE();
    struct sched_param high = {.sched_priority = 100};
    CALL("sched_setscheduler.bad_priority", sched_setscheduler, EINVAL, 0, SCHED_FIFO, &high);
    in_buf(2, &high, sizeof high);
    DONE();
    struct sched_param other = {.sched_priority = 0};
    CALL("sched_setscheduler.back_to_other", sched_setscheduler, WANT_OK, 0, SCHED_OTHER, &other);
    in_buf(2, &other, sizeof other);
    DONE();
    CALL("setpriority.negative_nice", setpriority, WANT_OK, PRIO_PROCESS, 0, -5);
    why("raising this child's priority needs CAP_SYS_NICE; the child exits right after");
    DONE();
    CASE("setpriority.bad_which", setpriority, EINVAL, 99, 0, 0);
}

static void device_cases(void)
{
    CALL("mknod.char_device", mknod, WANT_OK, "root-null", S_IFCHR | 0600, makedev(1, 3));
    in_str(0, "root-null");
    why("a /dev/null node (1:3) in work_dir, removed right after");
    DONE();
    CALL("mknod.exists", mknod, EEXIST, "root-null", S_IFCHR | 0600, makedev(1, 3));
    in_str(0, "root-null");
    DONE();
    CALL("mknod.directory_type", mknod, EPERM, "root-dir-node", S_IFDIR | 0700, 0);
    in_str(0, "root-dir-node");
    why("mknod never creates directories");
    DONE();
    unlink("root-null");

    long fan = CALL("fanotify_init.notify", fanotify_init, WANT_ANY,
                    FAN_CLASS_NOTIF | FAN_CLOEXEC, O_RDONLY);
    why("the pinned guest kernel has no CONFIG_FANOTIFY (ENOSYS)");
    DONE();
    CALL("fanotify_mark.work_dir", fanotify_mark, WANT_ANY, fan, FAN_MARK_ADD, FAN_OPEN,
         AT_FDCWD, work_dir);
    in_str(4, work_dir);
    why("watches work_dir only; ENOSYS without CONFIG_FANOTIFY");
    DONE();
    if (fan >= 0)
        close((int)fan);
}

static void handle_cases(void)
{
    union {
        struct file_handle fh;
        unsigned char raw[sizeof(struct file_handle) + HANDLE_CAPACITY];
    } handle, small, empty;
    int fd = open("root-handle", O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        ora_fail("root: handle file");
    else
        close(fd);
    int dir = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);

    memset(&handle, 0, sizeof handle);
    handle.fh.handle_bytes = HANDLE_CAPACITY;
    struct file_handle header = handle.fh;
    int mount_id = -1;
    CALL("name_to_handle_at.file", name_to_handle_at, WANT_OK, AT_FDCWD, "root-handle", &handle,
         &mount_id, 0);
    in_str(1, "root-handle");
    in_key("handle.header", &header, sizeof header);
    out_key("handle.header", &handle.fh, sizeof header);
    out_key("handle.bytes", handle.fh.f_handle, handle.fh.handle_bytes);
    out_key("arg3.mount_id", &mount_id, sizeof mount_id);
    volatile_case();
    DONE();
    union {
        struct file_handle fh;
        unsigned char raw[sizeof(struct file_handle) + HANDLE_CAPACITY];
    } unique;
    memset(&unique, 0, sizeof unique);
    unique.fh.handle_bytes = HANDLE_CAPACITY;
    uint64_t unique_id = 0;
    CALL("name_to_handle_at.unique_mount_id", name_to_handle_at, WANT_OK, AT_FDCWD,
         "root-handle", &unique, &unique_id, AT_HANDLE_MNT_ID_UNIQUE);
    in_str(1, "root-handle");
    in_key("handle.header", &header, sizeof header);
    out_key("handle.header", &unique.fh, sizeof header);
    out_key("handle.bytes", unique.fh.f_handle, unique.fh.handle_bytes);
    out_key("arg3.mount_id", &unique_id, sizeof unique_id);
    volatile_case();
    DONE();
    memset(&small, 0, sizeof small);
    struct file_handle zero = small.fh;
    int small_id = -1;
    CALL("name_to_handle_at.too_small", name_to_handle_at, EOVERFLOW, AT_FDCWD, "root-handle",
         &small, &small_id, 0);
    in_str(1, "root-handle");
    in_key("handle.header", &zero, sizeof zero);
    out_key("handle.header", &small.fh, sizeof zero);
    out_key("arg3.mount_id", &small_id, sizeof small_id);
    volatile_case();
    why("a zero-byte handle: the kernel reports the size it needs and the mount id");
    DONE();
    CALL("name_to_handle_at.bad_flags", name_to_handle_at, EINVAL, AT_FDCWD, "root-handle",
         &small, &small_id, 0x40000000);
    in_str(1, "root-handle");
    in_key("handle.header", &small.fh, sizeof zero);
    DONE();
    CALL("name_to_handle_at.missing", name_to_handle_at, ENOENT, AT_FDCWD, "root-missing", &small,
         &small_id, 0);
    in_str(1, "root-missing");
    in_key("handle.header", &small.fh, sizeof zero);
    DONE();

    long opened = CALL("open_by_handle_at.file", open_by_handle_at, WANT_OK, dir, &handle,
                       O_RDONLY | O_CLOEXEC);
    in_key("handle.header", &handle.fh, sizeof header);
    in_key("handle.bytes", handle.fh.f_handle, handle.fh.handle_bytes);
    volatile_case();
    why("needs CAP_DAC_READ_SEARCH; opens this area's own file read-only");
    DONE();
    if (opened >= 0)
        close((int)opened);
    memset(&empty, 0, sizeof empty);
    empty.fh.handle_type = handle.fh.handle_type;
    CALL("open_by_handle_at.zero_bytes", open_by_handle_at, EINVAL, dir, &empty, O_RDONLY);
    in_key("handle.header", &empty.fh, sizeof header);
    want_key_status("handle.bytes", "INVALID_EXTENT");
    volatile_case();
    DONE();
    CALL("open_by_handle_at.badf", open_by_handle_at, EBADF, 999, &handle, O_RDONLY);
    in_key("handle.header", &handle.fh, sizeof header);
    in_key("handle.bytes", handle.fh.f_handle, handle.fh.handle_bytes);
    volatile_case();
    DONE();
    if (dir >= 0)
        close(dir);
    unlink("root-handle");
}

// --- setns: a grandchild holds a private UTS namespace the child joins.

static void setns_child(void *unused)
{
    (void)unused;
    make_resident();
    int ready[2], release[2];
    if (pipe2(ready, O_CLOEXEC) != 0 || pipe2(release, O_CLOEXEC) != 0) {
        ora_fail("root: setns pipes");
        return;
    }
    ora_flush();
    pid_t holder = fork();
    if (holder < 0) {
        ora_fail("root: setns holder");
        return;
    }
    if (holder == 0) {
        char byte;
        ora_child(722);
        close(ready[0]);
        close(release[1]);
        alarm(10);
        if (unshare(CLONE_NEWUTS) != 0)
            _exit(4);
        if (write(ready[1], "r", 1) != 1)
            _exit(5);
        ssize_t ignored = read(release[0], &byte, 1);
        (void)ignored;
        _exit(0);
    }
    close(ready[1]);
    close(release[0]);
    char byte = 0, path[64];
    if (read(ready[0], &byte, 1) != 1)
        ora_fail("root: setns holder not ready");
    snprintf(path, sizeof path, "/proc/%d/ns/uts", (int)holder);
    int ns = open(path, O_RDONLY | O_CLOEXEC);
    long pidfd = syscall(SYS_pidfd_open, holder, 0);
    CALL("setns.uts_fd", setns, WANT_OK, ns, CLONE_NEWUTS);
    why("this child joins its own grandchild's private UTS namespace");
    DONE();
    CASE("setns.wrong_type", setns, EINVAL, ns, CLONE_NEWNET);
    CASE("setns.any_type", setns, WANT_OK, ns, 0);
    CASE("setns.pidfd_uts", setns, WANT_OK, pidfd, CLONE_NEWUTS);
    CASE("setns.pidfd_no_flags", setns, EINVAL, pidfd, 0);
    CASE("setns.badf", setns, EBADF, 999, CLONE_NEWUTS);
    if (ns >= 0)
        close(ns);
    if (pidfd >= 0)
        close((int)pidfd);
    close(release[1]);
    close(ready[0]);
    ora_wait(holder, "setns holder");
}

static void vhangup_child(void *unused)
{
    (void)unused;
    make_resident();
    if (setsid() < 0)
        ora_fail("root: setsid");
    CALL0("vhangup.no_tty", vhangup, WANT_OK);
    why("a new session has no controlling terminal: there is nothing to hang up");
    DONE();
}

static void mlock_child(void *unused)
{
    (void)unused;
    make_resident();
    CALL("mlockall.current", mlockall, WANT_OK, MCL_CURRENT);
    why("locks this short-lived child's few resident pages");
    DONE();
    CASE("mlockall.future_onfault", mlockall, WANT_OK, MCL_FUTURE | MCL_ONFAULT);
    CASE("mlockall.no_flags", mlockall, EINVAL, 0);
    CASE("mlockall.onfault_only", mlockall, EINVAL, MCL_ONFAULT);
    munlockall();
}

// --- process_mrelease on this area's own child

static void mrelease_cases(void)
{
    int release[2];
    if (pipe2(release, O_CLOEXEC) != 0) {
        ora_fail("root: mrelease pipe");
        return;
    }
    ora_flush();
    pid_t target = fork();
    if (target < 0) {
        ora_fail("root: mrelease target");
        return;
    }
    if (target == 0) {
        char byte;
        ora_child(721);
        close(release[1]);
        alarm(10);
        ssize_t ignored = read(release[0], &byte, 1);
        (void)ignored;
        _exit(0);
    }
    close(release[0]);
    long pidfd = syscall(SYS_pidfd_open, target, 0);
    CALL("process_mrelease.live_target", process_mrelease, EINVAL, pidfd, 0);
    why("a live process is not exiting, so there is nothing to reap");
    DONE();
    CASE("process_mrelease.bad_flags", process_mrelease, EINVAL, pidfd, 1);
    CASE("process_mrelease.badf", process_mrelease, EBADF, 999, 0);
    kill(target, SIGKILL);
    CALL("process_mrelease.killed_target", process_mrelease, WANT_ANY, pidfd, 0);
    why("this area's own child, just sent SIGKILL: 0 when its memory is reaped here, ESRCH "
        "when it already exited");
    DONE();
    int status;
    while (waitpid(target, &status, 0) < 0 && errno == EINTR)
        ;
    CASE("process_mrelease.reaped_target", process_mrelease, ESRCH, pidfd, 0);
    if (pidfd >= 0)
        close((int)pidfd);
    close(release[1]);
}

// --- queries and kernel interfaces that need root to succeed

static void root_device(char *out, size_t size)
{
    char line[512], device[256], target[256];
    snprintf(out, size, "/dev/vda");
    FILE *mounts = fopen("/proc/self/mounts", "re");
    if (!mounts)
        return;
    while (fgets(line, sizeof line, mounts))
        if (sscanf(line, "%255s %255s", device, target) == 2 && !strcmp(target, "/") &&
            !strncmp(device, "/dev/", 5))
            snprintf(out, size, "%s", device);
    fclose(mounts);
}

static void query_cases(void)
{
    char device[256];
    unsigned int format = 0;
    root_device(device, sizeof device);
    long got = CALL("quotactl.getfmt_root_device", quotactl, WANT_ANY, QCMD(Q_GETFMT, USRQUOTA),
                    device, 0, &format);
    in_str(1, device);
    if (got == 0)
        out_buf(3, &format, sizeof format);
    why("a read-only query; ESRCH without quota, ENODEV or ENOTBLK when the root is not a "
        "block device, ENOENT when the device node is missing");
    DONE();

    struct statx stx;
    struct mnt_id_req req;
    static uint64_t ids[16];
    static uint64_t info[512];
    memset(&stx, 0, sizeof stx);
    memset(ids, 0, sizeof ids);
    memset(info, 0, sizeof info);
    if (statx(AT_FDCWD, ".", 0, STATX_MNT_ID_UNIQUE, &stx) != 0)
        ora_fail("root: unique mount id");
    memset(&req, 0, sizeof req);
    req.size = MNT_ID_REQ_SIZE_VER0;
    req.mnt_id = LSMT_ROOT;
    got = CALL("listmount.root_namespace", listmount, WANT_OK, &req, ids, 16, 0);
    in_buf(0, &req, MNT_ID_REQ_SIZE_VER0);
    out_any(1);
    volatile_case();
    DONE();
    memset(&req, 0, sizeof req);
    req.size = MNT_ID_REQ_SIZE_VER0;
    req.mnt_id = stx.stx_mnt_id;
    req.param = STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC;
    CALL("statmount.root_work_dir", statmount, WANT_OK, &req, info, sizeof info, 0);
    in_buf(0, &req, MNT_ID_REQ_SIZE_VER0);
    out_any(1);
    volatile_case();
    DONE();
    (void)got;

    static char log[8192];
    memset(log, 0, sizeof log);
    CASE("syslog.size_buffer_root", syslog, WANT_OK, SYSLOG_ACTION_SIZE_BUFFER, NULL, 0);
    CALL("syslog.read_all_root", syslog, WANT_OK, SYSLOG_ACTION_READ_ALL, log, sizeof log);
    out_any(1);
    volatile_case();
    why("reads the kernel log without clearing it");
    DONE();

    struct perf_event_attr attr;
    memset(&attr, 0, sizeof attr);
    attr.size = PERF_ATTR_SIZE_612;
    attr.type = PERF_TYPE_SOFTWARE;
    attr.config = PERF_COUNT_SW_TASK_CLOCK;
    attr.disabled = 1;
    long fd = CALL("perf_event_open.root_task_clock", perf_event_open, WANT_OK, &attr, 0, -1, -1,
                   PERF_FLAG_FD_CLOEXEC);
    in_buf(0, &attr, PERF_ATTR_SIZE_612);
    why("a disabled software counter on this process, closed right after");
    DONE();
    if (fd >= 0)
        close((int)fd);
}

static void bpf_cases(void)
{
    union bpf_attr attr, entry;
    uint32_t key = 1, next_key = 0;
    unsigned char value[8];
    char log[4096];

    memset(&attr, 0, sizeof attr);
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4;
    attr.value_size = 8;
    attr.max_entries = 4;
    strcpy(attr.map_name, "ant_array");
    entry = attr;
    long map = CALL("bpf.map_create_root", bpf, WANT_OK, BPF_MAP_CREATE, &attr, 72);
    in_key("arg1.attr", &entry, 72);
    why("a 4-entry array map owned by this process, closed at the end");
    DONE();

    memcpy(value, "ANTIMAP1", 8);
    memset(&attr, 0, sizeof attr);
    attr.map_fd = (uint32_t)map;
    attr.key = (uintptr_t)&key;
    attr.value = (uintptr_t)value;
    attr.flags = BPF_ANY;
    entry = attr;
    CALL("bpf.map_update", bpf, WANT_OK, BPF_MAP_UPDATE_ELEM, &attr, 32);
    in_key("arg1.attr", &entry, 32);
    in_key("arg1.attr.key", &key, sizeof key);
    in_key("arg1.attr.value", "ANTIMAP1", 8);
    DONE();
    memset(value, 0, sizeof value);
    CALL("bpf.map_lookup", bpf, WANT_OK, BPF_MAP_LOOKUP_ELEM, &attr, 32);
    in_key("arg1.attr", &entry, 32);
    in_key("arg1.attr.key", &key, sizeof key);
    out_key("arg1.attr.value", value, sizeof value);
    DONE();
    attr.next_key = (uintptr_t)&next_key;
    entry = attr;
    CALL("bpf.map_get_next_key", bpf, WANT_OK, BPF_MAP_GET_NEXT_KEY, &attr, 32);
    in_key("arg1.attr", &entry, 32);
    in_key("arg1.attr.key", &key, sizeof key);
    out_key("arg1.attr.next_key", &next_key, sizeof next_key);
    DONE();
    attr.value = 0;
    attr.next_key = 0;
    entry = attr;
    CALL("bpf.map_delete_array", bpf, EINVAL, BPF_MAP_DELETE_ELEM, &attr, 32);
    in_key("arg1.attr", &entry, 32);
    in_key("arg1.attr.key", &key, sizeof key);
    why("array map elements cannot be deleted");
    DONE();

    memset(&attr, 0, sizeof attr);
    memset(log, 0, sizeof log);
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = 2;
    attr.insns = (uintptr_t)return_zero;
    attr.license = (uintptr_t) "GPL";
    attr.log_level = 1;
    attr.log_size = sizeof log;
    attr.log_buf = (uintptr_t)log;
    entry = attr;
    long prog = CALL("bpf.prog_load_root", bpf, WANT_OK, BPF_PROG_LOAD, &attr, 40);
    in_key("arg1.attr", &entry, 40);
    in_key("arg1.attr.insns", return_zero, sizeof return_zero);
    in_key("arg1.attr.license", "GPL", 4);
    out_key("arg1.attr.log_buf", log, strlen(log) + 1);
    why("a socket filter returning 0, never attached, closed at the end");
    DONE();
    memset(log, 0, sizeof log);
    attr.insn_cnt = 1;
    attr.insns = (uintptr_t)lone_exit;
    entry = attr;
    CALL("bpf.prog_load_rejected", bpf, EACCES, BPF_PROG_LOAD, &attr, 40);
    in_key("arg1.attr", &entry, 40);
    in_key("arg1.attr.insns", lone_exit, sizeof lone_exit);
    in_key("arg1.attr.license", "GPL", 4);
    out_key("arg1.attr.log_buf", log, strlen(log) + 1);
    why("the verifier rejects reading an uninitialized R0 and writes why into the log");
    DONE();
    if (prog >= 0)
        close((int)prog);
    if (map >= 0)
        close((int)map);
}

static void memory_cases(void)
{
    long fd = CALL("userfaultfd.plain", userfaultfd, WANT_ANY, O_CLOEXEC);
    why("the pinned guest kernel has no CONFIG_USERFAULTFD (ENOSYS)");
    DONE();
    if (fd >= 0)
        close((int)fd);
    fd = CALL("memfd_secret.plain", memfd_secret, WANT_ANY, 0);
    why("ENOSYS when secretmem is disabled at boot or the direct map cannot be split");
    DONE();
    if (fd >= 0)
        close((int)fd);
    CALL("memfd_secret.bad_flags", memfd_secret, WANT_ANY, 0x40);
    why("EINVAL for the unknown flag, or ENOSYS first when secretmem is unavailable");
    DONE();

    unsigned long from = 1, to = 1, offline = 1UL << 5;
    CALL("migrate_pages.self", migrate_pages, WANT_OK, 0, 65, &from, &to);
    in_buf(2, &from, sizeof from);
    in_buf(3, &to, sizeof to);
    why("node 0 to node 0 on this process: nothing moves");
    DONE();
    CALL("migrate_pages.offline_node", migrate_pages, EINVAL, 0, 65, &from, &offline);
    in_buf(2, &from, sizeof from);
    in_buf(3, &offline, sizeof offline);
    DONE();
    CALL("migrate_pages.huge_maxnode", migrate_pages, EINVAL, 0, 40000, &from, &to);
    want_status(2, "in", "INVALID_EXTENT");
    want_status(3, "in", "INVALID_EXTENT");
    DONE();
    CALL("migrate_pages.missing_pid", migrate_pages, ESRCH, 0x3ffffff0, 65, &from, &to);
    in_buf(2, &from, sizeof from);
    in_buf(3, &to, sizeof to);
    DONE();

    memset(move_page, 0x41, sizeof move_page);
    void *pages[1] = {move_page};
    int nodes[1] = {0}, status[1] = {-1};
    CALL("move_pages.query", move_pages, WANT_OK, 0, 1, pages, NULL, status, 0);
    in_buf(2, pages, sizeof pages);
    out_buf(4, status, sizeof status);
    DONE();
    status[0] = -1;
    CALL("move_pages.to_node0", move_pages, WANT_OK, 0, 1, pages, nodes, status, 0);
    in_buf(2, pages, sizeof pages);
    in_buf(3, nodes, sizeof nodes);
    out_buf(4, status, sizeof status);
    why("a page of this process to the node it is already on");
    DONE();
    int offline_nodes[1] = {5};
    CALL("move_pages.offline_node", move_pages, ENODEV, 0, 1, pages, offline_nodes, status, 0);
    in_buf(2, pages, sizeof pages);
    in_buf(3, offline_nodes, sizeof offline_nodes);
    DONE();
    CALL("move_pages.bad_flags", move_pages, EINVAL, 0, 1, pages, NULL, status, 0x10);
    in_buf(2, pages, sizeof pages);
    DONE();
}

void area_root(void)
{
    if (getuid() != 0 || geteuid() != 0) {
        ora_fail("root area must run as UID 0");
        return;
    }
    make_resident();
    static const char *const dirs[] = {"root-mnt", "root-bind", "root-pr", "root-fsmnt",
                                       "root-fsmnt2"};
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++)
        if (mkdir(dirs[i], 0700) != 0)
            ora_fail("root: mount point");
    int file = open("root-file", O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
    if (file < 0)
        ora_fail("root: plain file");
    else
        close(file);

    in_child(710, "mount child", mount_child, NULL);
    in_child(711, "pivot_root child", pivot_child, NULL);
    in_child(712, "chroot child", chroot_child, NULL);
    in_child(713, "UTS child", uts_child, NULL);
    in_child(714, "mount API child", mount_api_child, NULL);
    swap_acct_cases();
    reboot_kexec_cases();
    module_cases();
    in_child(720, "I/O port child", io_port_child, NULL);
    time_cases();
    in_child(715, "identity child", identity_child, NULL);
    in_child(716, "scheduler child", sched_child, NULL);
    device_cases();
    handle_cases();
    in_child(717, "setns child", setns_child, NULL);
    in_child(718, "vhangup child", vhangup_child, NULL);
    in_child(719, "mlockall child", mlock_child, NULL);
    mrelease_cases();
    query_cases();
    bpf_cases();
    memory_cases();

    unlink("root-file");
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++)
        if (rmdir(dirs[i]) != 0)
            ora_fail("root: mount point cleanup");
}
