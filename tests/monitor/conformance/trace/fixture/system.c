// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// system.c — administrative and dangerous calls, exercised as UID 1000 so
// that the kernel refuses every one that would change the system.
//
// Slots: reboot kexec_load kexec_file_load init_module finit_module
// delete_module swapon swapoff mount umount2 pivot_root chroot acct
// sethostname setdomainname iopl ioperm modify_ldt vhangup syslog quotactl
// quotactl_fd sysfs perf_event_open bpf open_tree move_mount fsopen fsconfig
// fsmount fspick mount_setattr statmount listmount uretprobe, and the rows
// with no entry point: uselib _sysctl create_module get_kernel_syms
// query_module nfsservctl getpmsg putpmsg afs_syscall tuxcall security
// set_thread_area get_thread_area lookup_dcookie epoll_ctl_old
// epoll_wait_old vserver.
//
// The area refuses to run with any effective capability: every dangerous
// case below relies on the kernel's privilege check failing first.
#include "areas.h"

#include <asm/ldt.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/dqblk_xfs.h>
#include <linux/kexec.h>
#include <linux/perf_event.h>
#include <linux/reboot.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/quota.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/wait.h>

#ifndef SYSLOG_ACTION_READ_ALL
#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_CLEAR 5
#define SYSLOG_ACTION_CONSOLE_LEVEL 8
#define SYSLOG_ACTION_SIZE_BUFFER 10
#endif
#ifndef KEXEC_SEGMENT_MAX
#define KEXEC_SEGMENT_MAX 16
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
#define URETPROBE_NR 335
// Linux 6.12 knows perf_event_attr up to PERF_ATTR_SIZE_VER8.
#define PERF_ATTR_SIZE_612 136

// Mount options at a page start: the recorder reads the whole page, like
// copy_mount_options(), so the description is the full page.
static char mount_options[4096] __attribute__((aligned(4096))) = "size=1m,mode=0700";
static const struct bpf_insn return_zero[2] = {
    {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0},
    {.code = BPF_JMP | BPF_EXIT},
};

// The recorder copies user memory without faulting: map every page of this
// image (strings, tables) before the calls that point into it. A forked
// child has no page-table entries for file-backed pages yet, so children
// call this first too.
static void make_resident(void)
{
    char line[512], path[300];
    unsigned long start, end;
    FILE *maps = fopen("/proc/self/maps", "re");
    if (!maps) {
        ora_fail("system: read the process maps");
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

static int unprivileged(void)
{
    char line[128];
    int ok = geteuid() != 0;
    FILE *status = fopen("/proc/self/status", "re");
    if (!status)
        return 0;
    while (fgets(line, sizeof line, status))
        if (!strncmp(line, "CapEff:", 7))
            ok = ok && strtoull(line + 7, NULL, 16) == 0;
    fclose(status);
    return ok;
}

static void reboot_kexec_cases(void)
{
    CALL("reboot.cad_off_unprivileged", reboot, EPERM, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
         LINUX_REBOOT_CMD_CAD_OFF, NULL);
    why("CAP_SYS_BOOT is checked before anything else; UID 1000 without capabilities is refused");
    DONE();
    CALL("reboot.bad_magic_unprivileged", reboot, EPERM, 0x1234, 0x5678,
         LINUX_REBOOT_CMD_CAD_OFF, NULL);
    why("kernel/reboot.c checks CAP_SYS_BOOT before the magic numbers: EPERM, not EINVAL");
    DONE();
    CALL("reboot.restart2_unprivileged", reboot, EPERM, LINUX_REBOOT_MAGIC1,
         LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_RESTART2, "ant-restart");
    in_str(3, "ant-restart");
    why("RESTART2 is refused by the capability check before the magic or command is read");
    DONE();
    CALL("reboot.unknown_cmd_unprivileged", reboot, EPERM, LINUX_REBOOT_MAGIC1,
         LINUX_REBOOT_MAGIC2, 0x7fff, NULL);
    want_key_status("reboot.unknown_selector", "NO_DECODER");
    why("an unknown command is recorded as a selector gap; the capability check refuses it");
    DONE();

    static const char image[] = "ANTINOMIE-KEXEC";
    struct kexec_segment segment = {image, 15, (void *)0x1000000, 4096};
    struct kexec_segment segments[KEXEC_SEGMENT_MAX + 1];
    memset(segments, 0, sizeof segments);
    CALL("kexec_load.unprivileged", kexec_load, EPERM, 0x1000000, 1, &segment,
         KEXEC_ARCH_DEFAULT);
    in_key("arg2.segments", &segment, sizeof segment);
    in_key("arg2.segments[0].buf", image, 15);
    why("kexec_load_permitted() needs CAP_SYS_BOOT and runs before the segments are read");
    DONE();
    CALL("kexec_load.too_many_segments", kexec_load, EPERM, 0, KEXEC_SEGMENT_MAX + 1, segments,
         KEXEC_ARCH_DEFAULT);
    want_status(2, "in", "INVALID_EXTENT");
    why("the permission check comes before the segment limit; the recorder flags the count");
    DONE();
    CALL("kexec_load.unload_unprivileged", kexec_load, EPERM, 0, 0, NULL, KEXEC_ARCH_DEFAULT);
    in_buf(2, "", 0);
    why("an unload request is refused without CAP_SYS_BOOT");
    DONE();
    CALL("kexec_file_load.unprivileged", kexec_file_load, WANT_ANY, -1, -1, 4, "ant", 0);
    in_buf(3, "ant", 4);
    why("the pinned guest kernel has no CONFIG_KEXEC_FILE (ENOSYS); with it, EPERM without "
        "CAP_SYS_BOOT. Either way nothing is loaded");
    DONE();
}

static void module_cases(void)
{
    unsigned char image[128];
    pattern(image, sizeof image, 3);
    CALL("init_module.unprivileged", init_module, EPERM, image, sizeof image, "ant=1");
    in_buf(0, image, sizeof image);
    in_str(2, "ant=1");
    why("may_init_module() needs CAP_SYS_MODULE before the image is copied");
    DONE();
    CALL("init_module.null_args", init_module, EPERM, image, sizeof image, NULL);
    in_buf(0, image, sizeof image);
    want_status(2, "any", "NULL_POINTER");
    why("the same refusal with no parameter string");
    DONE();
    long fd = open("sys-module", O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        ora_fail("system: module file");
    CALL("finit_module.unprivileged", finit_module, EPERM, fd, "", 0);
    in_str(1, "");
    why("may_init_module() refuses before the descriptor is read");
    DONE();
    if (fd >= 0)
        close((int)fd);
    unlink("sys-module");
    CALL("delete_module.unprivileged", delete_module, EPERM, "ant_missing", O_NONBLOCK);
    in_str(0, "ant_missing");
    why("CAP_SYS_MODULE is checked before the name is looked up");
    DONE();
}

static void swap_acct_cases(void)
{
    CALL("swapon.unprivileged", swapon, EPERM, "sys-swap", 0);
    in_str(0, "sys-swap");
    why("swapon needs CAP_SYS_ADMIN; it is refused before the path is opened");
    DONE();
    CALL("swapon.bad_flags", swapon, EINVAL, "sys-swap", 0x80000);
    in_str(0, "sys-swap");
    why("unknown swap flags are rejected before the capability check");
    DONE();
    CALL("swapoff.unprivileged", swapoff, EPERM, "sys-swap");
    in_str(0, "sys-swap");
    why("swapoff needs CAP_SYS_ADMIN");
    DONE();
    CALL("acct.unprivileged", acct, EPERM, "sys-acct");
    in_str(0, "sys-acct");
    why("process accounting needs CAP_SYS_PACCT, checked before the path");
    DONE();
    CALL("acct.off_unprivileged", acct, EPERM, NULL);
    want_status(0, "any", "NULL_POINTER");
    why("turning accounting off is refused the same way");
    DONE();
}

static void mount_cases(void)
{
    if (mkdir("sys-mnt", 0700) != 0)
        ora_fail("system: mount point");
    for (size_t i = 0; i < sizeof mount_options; i += 4096)
        (void)*(volatile char *)(mount_options + i);
    CALL("mount.real_device_unprivileged", mount, EPERM, "/dev/vdb", "sys-mnt", "ext4",
         MS_RDONLY, NULL);
    in_str(0, "/dev/vdb");
    in_str(1, "sys-mnt");
    in_str(2, "ext4");
    why("may_mount() needs CAP_SYS_ADMIN in the mount namespace: the device is never opened");
    DONE();
    CALL("mount.tmpfs_options_unprivileged", mount, EPERM, "ant-tmpfs", "sys-mnt", "tmpfs",
         MS_NOSUID | MS_NODEV, mount_options);
    in_str(0, "ant-tmpfs");
    in_str(1, "sys-mnt");
    in_str(2, "tmpfs");
    in_key("arg4.data", mount_options, sizeof mount_options);
    why("the option page is copied and then refused by may_mount()");
    DONE();
    CALL("mount.bind_unprivileged", mount, EPERM, ".", "sys-mnt", NULL, MS_BIND, NULL);
    in_str(0, ".");
    in_str(1, "sys-mnt");
    why("a bind mount is refused the same way; no type or data pointer is recorded");
    DONE();
    CALL("mount.null_dir", mount, EFAULT, "none", NULL, "tmpfs", 0, NULL);
    in_str(0, "none");
    in_str(2, "tmpfs");
    want_status(1, "any", "NULL_POINTER");
    why("the target path is resolved before the permission check");
    DONE();

    CALL("umount2.unprivileged", umount2, EPERM, ".", 0);
    in_str(0, ".");
    why("can_umount() calls may_mount() first");
    DONE();
    CALL("umount2.missing", umount2, ENOENT, "sys-missing", 0);
    in_str(0, "sys-missing");
    DONE();
    CALL("umount2.bad_flags", umount2, EINVAL, "sys-mnt", 0x80);
    in_str(0, "sys-mnt");
    DONE();
    CALL("pivot_root.unprivileged", pivot_root, EPERM, ".", ".");
    in_str(0, ".");
    in_str(1, ".");
    why("pivot_root needs CAP_SYS_ADMIN before any lookup");
    DONE();
    CALL("chroot.unprivileged", chroot, EPERM, ".");
    in_str(0, ".");
    why("chroot needs CAP_SYS_CHROOT after the directory lookup succeeds");
    DONE();
    CALL("chroot.missing", chroot, ENOENT, "sys-missing");
    in_str(0, "sys-missing");
    DONE();
    CALL("chroot.null_path", chroot, EFAULT, NULL);
    want_status(0, "any", "NULL_POINTER");
    DONE();
    if (rmdir("sys-mnt") != 0)
        ora_fail("system: mount point cleanup");
}

static void uts_io_cases(void)
{
    CALL("sethostname.unprivileged", sethostname, EPERM, "ant-host", 8);
    in_buf(0, "ant-host", 8);
    why("CAP_SYS_ADMIN in the UTS namespace is checked first; the host name is unchanged");
    DONE();
    char long_name[80];
    memset(long_name, 'h', sizeof long_name);
    CALL("sethostname.too_long_unprivileged", sethostname, EPERM, long_name, 65);
    want_status(0, "in", "INVALID_EXTENT");
    why("the permission check precedes the length check; the recorder flags the length");
    DONE();
    CALL("setdomainname.unprivileged", setdomainname, EPERM, "ant-domain", 10);
    in_buf(0, "ant-domain", 10);
    why("CAP_SYS_ADMIN in the UTS namespace is checked first");
    DONE();

    CALL("iopl.same_level", iopl, WANT_OK, 0);
    why("level 0 is the current level: nothing changes and no privilege is needed");
    DONE();
    CALL("iopl.raise_unprivileged", iopl, EPERM, 3);
    why("raising the I/O privilege level needs CAP_SYS_RAWIO");
    DONE();
    CASE("iopl.bad_level", iopl, EINVAL, 4);
    CALL("ioperm.off", ioperm, WANT_OK, 0x80, 1, 0);
    why("clearing permissions on a thread without an I/O bitmap returns at once");
    DONE();
    CALL("ioperm.on_unprivileged", ioperm, EPERM, 0x80, 1, 1);
    why("granting port access needs CAP_SYS_RAWIO");
    DONE();
    CASE("ioperm.bad_range", ioperm, EINVAL, 65535, 16, 0);
    CALL0("vhangup.unprivileged", vhangup, EPERM);
    why("vhangup needs CAP_SYS_TTY_CONFIG; the terminal is not hung up");
    DONE();
}

// modify_ldt returns its int result zero-extended, so an error is a large
// positive value (0xffffffea for EINVAL) and never sets errno.
static void ldt_expect(long result, int error)
{
    if ((unsigned int)result != (unsigned int)-error)
        ora_fail("modify_ldt returned an unexpected value");
}

static void ldt_child(void *unused)
{
    (void)unused;
    make_resident();
    unsigned char buffer[64];
    memset(buffer, 0x5a, sizeof buffer);
    CALL("modify_ldt.read_empty", modify_ldt, WANT_OK, 0, buffer, sizeof buffer);
    out_key("arg1.ldt", buffer, 0);
    why("a fresh process has no LDT: the read returns 0 bytes");
    DONE();
    memset(buffer, 0x5a, sizeof buffer);
    long got = CALL("modify_ldt.read_default", modify_ldt, WANT_OK, 2, buffer, 16);
    out_key("arg1.ldt", buffer, got > 0 ? (size_t)got : 0);
    DONE();
    struct user_desc empty;
    memset(&empty, 0, sizeof empty);
    empty.entry_number = 0;
    empty.read_exec_only = 1;
    empty.seg_not_present = 1;
    CALL("modify_ldt.write_empty_entry", modify_ldt, WANT_OK, 0x11, &empty, sizeof empty);
    in_buf(1, &empty, sizeof empty);
    why("an empty descriptor only clears entry 0 of this child's own LDT");
    DONE();
    struct user_desc legacy;
    memset(&legacy, 0, sizeof legacy);
    legacy.entry_number = 1;
    CALL("modify_ldt.write_legacy_clear", modify_ldt, WANT_OK, 1, &legacy, sizeof legacy);
    in_buf(1, &legacy, sizeof legacy);
    why("legacy mode with base and limit 0 clears entry 1 of this child's LDT");
    DONE();
    memset(buffer, 0x5a, sizeof buffer);
    got = CALL("modify_ldt.read_entries", modify_ldt, WANT_OK, 0, buffer, 16);
    out_key("arg1.ldt", buffer, got > 0 ? (size_t)got : 0);
    DONE();
    long raw = CALL("modify_ldt.write_bad_size", modify_ldt, WANT_ANY, 0x11, &empty, 8);
    want_status(1, "in", "INVALID_EXTENT");
    why("EINVAL comes back as the zero-extended int 0xffffffea, so it looks like success");
    DONE();
    ldt_expect(raw, EINVAL);
    raw = CALL("modify_ldt.unknown_func", modify_ldt, WANT_ANY, 5, buffer, 16);
    want_key_status("modify_ldt.unknown_selector", "NO_DECODER");
    why("ENOSYS comes back zero-extended (0xffffffda)");
    DONE();
    ldt_expect(raw, ENOSYS);
}

static void syslog_cases(void)
{
    static char log[8192];
    memset(log, 0, sizeof log);
    CALL("syslog.size_buffer", syslog, WANT_ANY, SYSLOG_ACTION_SIZE_BUFFER, NULL, 0);
    why("allowed for everyone unless kernel.dmesg_restrict is set (then EPERM)");
    DONE();
    long got = CALL("syslog.read_all", syslog, WANT_ANY, SYSLOG_ACTION_READ_ALL, log, sizeof log);
    if (got >= 0)
        out_any(1);
    volatile_case();
    why("reading the log without clearing it is allowed unless kernel.dmesg_restrict is set");
    DONE();
    CALL("syslog.read_all_negative_len", syslog, WANT_ANY, SYSLOG_ACTION_READ_ALL, log, -1);
    why("EINVAL for the negative length, or EPERM first when kernel.dmesg_restrict is set");
    DONE();
    CALL("syslog.clear_unprivileged", syslog, EPERM, SYSLOG_ACTION_CLEAR, NULL, 0);
    why("clearing the ring buffer needs CAP_SYSLOG; nothing is cleared");
    DONE();
    CALL("syslog.console_level_unprivileged", syslog, EPERM, SYSLOG_ACTION_CONSOLE_LEVEL, NULL,
         1);
    why("changing the console level needs CAP_SYSLOG; the level is unchanged");
    DONE();
    CALL("syslog.unknown_unprivileged", syslog, EPERM, 99, log, 16);
    want_key_status("syslog.unknown_selector", "NO_DECODER");
    why("an unknown action is a restricted one: refused before it is decoded");
    DONE();
}

static void quota_cases(void)
{
    unsigned int format = 0, flags = 1;
    struct fs_quota_statv statv;
    struct dqblk quota;
    memset(&statv, 0, sizeof statv);
    statv.qs_version = FS_QSTATV_VERSION1;
    memset(&quota, 0, sizeof quota);
    quota.dqb_bhardlimit = 1;

    CALL("quotactl.getfmt_missing_device", quotactl, ENOENT, QCMD(Q_GETFMT, USRQUOTA),
         "/dev/ant-missing", 0, &format);
    in_str(1, "/dev/ant-missing");
    DONE();
    CALL("quotactl.quotaon_missing_device", quotactl, ENOENT, QCMD(Q_QUOTAON, USRQUOTA),
         "/dev/ant-missing", QFMT_VFS_V1, "aquota.user");
    in_str(1, "/dev/ant-missing");
    in_str(3, "aquota.user");
    why("the quota file path is decoded at entry; the missing device ends the call");
    DONE();
    CALL("quotactl.setquota_missing_device", quotactl, ENOENT, QCMD(Q_SETQUOTA, USRQUOTA),
         "/dev/ant-missing", 1000, &quota);
    in_str(1, "/dev/ant-missing");
    in_buf(3, &quota, sizeof quota);
    DONE();
    CALL("quotactl.xquotaon_flags", quotactl, ENOENT, QCMD(Q_XQUOTAON, USRQUOTA),
         "/dev/ant-missing", 0, &flags);
    in_str(1, "/dev/ant-missing");
    in_buf(3, &flags, sizeof flags);
    DONE();
    CALL("quotactl.xgetqstatv_version", quotactl, ENOENT, QCMD(Q_XGETQSTATV, USRQUOTA),
         "/dev/ant-missing", 0, &statv);
    in_str(1, "/dev/ant-missing");
    in_buf(3, &statv, 1);
    why("the kernel reads only qs_version before writing the result");
    DONE();
    CALL("quotactl.bad_type", quotactl, EINVAL, QCMD(Q_GETFMT, 7), "/dev/ant-missing", 0,
         &format);
    in_str(1, "/dev/ant-missing");
    DONE();
    CASE("quotactl.null_special", quotactl, ENODEV, QCMD(Q_GETFMT, USRQUOTA), NULL, 0, &format);
    CALL("quotactl.sync_all", quotactl, WANT_OK, QCMD(Q_SYNC, USRQUOTA), NULL, 0, NULL);
    why("Q_SYNC without a device syncs quota on every filesystem; no privilege is needed");
    DONE();
    CALL("quotactl.unknown_cmd", quotactl, ENOENT, QCMD(0x7fff, USRQUOTA), "/dev/ant-missing", 0,
         &format);
    in_str(1, "/dev/ant-missing");
    want_key_status("quotactl.unknown_selector", "NO_DECODER");
    DONE();

    int dir = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir < 0)
        ora_fail("system: quota directory");
    CALL("quotactl_fd.getfmt_no_quota", quotactl_fd, ESRCH, dir, QCMD(Q_GETFMT, USRQUOTA), 0,
         &format);
    why("the guest /tmp filesystem supports quota but has none enabled");
    DONE();
    CALL("quotactl_fd.setquota_unprivileged", quotactl_fd, EPERM, dir,
         QCMD(Q_SETQUOTA, USRQUOTA), 1000, &quota);
    in_buf(3, &quota, sizeof quota);
    why("setting a limit needs CAP_SYS_ADMIN; the limit is never applied");
    DONE();
    CASE("quotactl_fd.bad_type", quotactl_fd, EINVAL, dir, QCMD(Q_GETFMT, 7), 0, &format);
    CASE("quotactl_fd.badf", quotactl_fd, EBADF, 999, QCMD(Q_GETFMT, USRQUOTA), 0, &format);
    if (dir >= 0)
        close(dir);
}

static void sysfs_cases(void)
{
    char name[256];
    memset(name, 0, sizeof name);
    long index = CALL("sysfs.fs_index", sysfs, WANT_OK, 1, "proc");
    in_str(1, "proc");
    DONE();
    CALL("sysfs.fs_name", sysfs, WANT_OK, 2, index, name);
    out_str(2, name);
    DONE();
    CASE("sysfs.fs_count", sysfs, WANT_OK, 3);
    CALL("sysfs.missing_name", sysfs, EINVAL, 1, "ant-nofs");
    in_str(1, "ant-nofs");
    DONE();
    CASE("sysfs.bad_index", sysfs, EINVAL, 2, 9999, name);
    CALL("sysfs.unknown_option", sysfs, EINVAL, 9);
    want_key_status("sysfs.unknown_selector", "NO_DECODER");
    DONE();
}

static void perf_cases(void)
{
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof attr);
    attr.size = PERF_ATTR_SIZE_612;
    attr.type = PERF_TYPE_SOFTWARE;
    attr.config = PERF_COUNT_SW_TASK_CLOCK;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    long fd = CALL("perf_event_open.self_task_clock", perf_event_open, WANT_ANY, &attr, 0, -1, -1,
                   PERF_FLAG_FD_CLOEXEC);
    in_buf(0, &attr, PERF_ATTR_SIZE_612);
    why("a user-space software counter on the caller is allowed when kernel.perf_event_paranoid "
        "is at most 2, refused (EACCES) above that");
    DONE();
    if (fd >= 0)
        close((int)fd);
    CALL("perf_event_open.bad_flags", perf_event_open, EINVAL, &attr, 0, -1, -1, 0x80000000UL);
    in_buf(0, &attr, PERF_ATTR_SIZE_612);
    DONE();
    struct perf_event_attr small;
    memset(&small, 0, sizeof small);
    small.size = 32;
    small.type = PERF_TYPE_SOFTWARE;
    CALL("perf_event_open.small_size", perf_event_open, E2BIG, &small, 0, -1, -1, 0);
    want_status(0, "in", "INVALID_EXTENT");
    out_key("arg0.required_size", &small.size, sizeof small.size);
    why("a size below PERF_ATTR_SIZE_VER0: the kernel writes the size it knows back");
    DONE();
    struct perf_event_attr zero;
    memset(&zero, 0, sizeof zero);
    zero.type = PERF_TYPE_SOFTWARE;
    zero.sample_type = 1ULL << 63;
    CALL("perf_event_open.size_zero_bad_sample", perf_event_open, EINVAL, &zero, 0, -1, -1, 0);
    in_buf(0, &zero, 64);
    why("size 0 means PERF_ATTR_SIZE_VER0; an unknown sample_type bit is rejected");
    DONE();
    CALL("perf_event_open.attr_fault", perf_event_open, EFAULT, 1, 0, -1, -1, 0);
    want_status(0, "in", "COPY_FAULT");
    DONE();
}

static void bpf_cases(void)
{
    union bpf_attr attr, entry;
    memset(&attr, 0, sizeof attr);
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4;
    attr.value_size = 8;
    attr.max_entries = 4;
    strcpy(attr.map_name, "ant_array");
    entry = attr;
    CALL("bpf.map_create_unprivileged", bpf, EPERM, BPF_MAP_CREATE, &attr, 72);
    in_key("arg1.attr", &entry, 72);
    why("kernel.unprivileged_bpf_disabled defaults to 2 in the guest config: no map is created");
    DONE();

    memset(&attr, 0, sizeof attr);
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = 2;
    attr.insns = (uintptr_t)return_zero;
    attr.license = (uintptr_t) "GPL";
    entry = attr;
    long fd = CALL("bpf.prog_load_unprivileged", bpf, WANT_ANY, BPF_PROG_LOAD, &attr, 40);
    in_key("arg1.attr", &entry, 40);
    in_key("arg1.attr.insns", return_zero, sizeof return_zero);
    in_key("arg1.attr.license", "GPL", 4);
    why("an unprivileged socket filter loads only when kernel.unprivileged_bpf_disabled is 0; "
        "the program returns 0 and is never attached");
    DONE();
    if (fd >= 0)
        close((int)fd);

    char missing[300];
    work_path(missing, sizeof missing, "sys-bpf-missing");
    memset(&attr, 0, sizeof attr);
    attr.pathname = (uintptr_t)missing;
    entry = attr;
    CALL("bpf.obj_get_missing", bpf, ENOENT, BPF_OBJ_GET, &attr, 16);
    in_key("arg1.attr", &entry, 16);
    in_key("arg1.attr.pathname", missing, strlen(missing) + 1);
    why("BPF_OBJ_GET needs no privilege; a missing pinned path is ENOENT");
    DONE();

    memset(&attr, 0, sizeof attr);
    attr.map_fd = 0x414e5449;
    entry = attr;
    CALL("bpf.unknown", bpf, EINVAL, 0x7fff, &attr, 16);
    in_key("arg1.attr", &entry, 16);
    want_key_status("bpf.unknown_selector", "NO_DECODER");
    DONE();
    static char big[8192];
    memset(big, 0, sizeof big);
    CALL("bpf.size_too_big", bpf, E2BIG, BPF_MAP_CREATE, big, sizeof big);
    want_status(1, "in", "INVALID_EXTENT");
    DONE();
    CALL("bpf.attr_fault", bpf, EFAULT, BPF_MAP_CREATE, 1, 16);
    want_status(1, "in", "COPY_FAULT");
    DONE();
}

static void mount_api_cases(void)
{
    struct mount_attr attr = {.attr_set = MOUNT_ATTR_RDONLY};
    unsigned char blob[3] = {1, 2, 3};

    long fd = CALL("open_tree.plain", open_tree, WANT_OK, AT_FDCWD, ".", OPEN_TREE_CLOEXEC);
    in_str(1, ".");
    why("without OPEN_TREE_CLONE open_tree only returns an O_PATH descriptor");
    DONE();
    if (fd >= 0)
        close((int)fd);
    CALL("open_tree.clone_unprivileged", open_tree, EPERM, AT_FDCWD, ".",
         OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
    in_str(1, ".");
    why("a detached clone needs CAP_SYS_ADMIN in the mount namespace");
    DONE();
    CALL("open_tree.recursive_without_clone", open_tree, EINVAL, AT_FDCWD, ".", AT_RECURSIVE);
    in_str(1, ".");
    DONE();
    CALL("open_tree.bad_flags", open_tree, EINVAL, AT_FDCWD, ".", 0x40000000);
    in_str(1, ".");
    DONE();
    CALL("move_mount.unprivileged", move_mount, EPERM, AT_FDCWD, ".", AT_FDCWD, ".", 0);
    in_str(1, ".");
    in_str(3, ".");
    why("may_mount() refuses before either path is resolved");
    DONE();
    CALL("fsopen.unprivileged", fsopen, EPERM, "tmpfs", FSOPEN_CLOEXEC);
    in_str(0, "tmpfs");
    why("creating a filesystem context needs CAP_SYS_ADMIN in the mount namespace");
    DONE();
    CALL("fsconfig.set_string_badf", fsconfig, EBADF, 999, FSCONFIG_SET_STRING, "source", "ant",
         0);
    in_str(2, "source");
    in_str(3, "ant");
    DONE();
    CALL("fsconfig.set_binary_badf", fsconfig, EBADF, 999, FSCONFIG_SET_BINARY, "size", blob,
         sizeof blob);
    in_str(2, "size");
    in_buf(3, blob, sizeof blob);
    DONE();
    CALL("fsconfig.flag_with_value", fsconfig, EINVAL, 999, FSCONFIG_SET_FLAG, "ro", "x", 0);
    in_str(2, "ro");
    why("SET_FLAG takes no value: rejected before the descriptor is looked up");
    DONE();
    CASE("fsconfig.create_badf", fsconfig, EBADF, 999, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
    CASE("fsconfig.negative_fd", fsconfig, EINVAL, -1, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
    CALL("fsconfig.unknown_cmd", fsconfig, EOPNOTSUPP, 999, 99, NULL, NULL, 0);
    want_key_status("fsconfig.unknown_selector", "NO_DECODER");
    DONE();
    CALL("fsmount.unprivileged", fsmount, EPERM, 999, FSMOUNT_CLOEXEC, 0);
    why("may_mount() refuses before the descriptor is looked up");
    DONE();
    CALL("fspick.unprivileged", fspick, EPERM, AT_FDCWD, ".", FSPICK_CLOEXEC);
    in_str(1, ".");
    why("reconfiguring a superblock needs CAP_SYS_ADMIN");
    DONE();
    CALL("mount_setattr.unprivileged", mount_setattr, EPERM, AT_FDCWD, ".", 0, &attr,
         sizeof attr);
    in_str(1, ".");
    in_buf(3, &attr, sizeof attr);
    why("may_mount() refuses after the size checks; no mount becomes read-only");
    DONE();
    CALL("mount_setattr.small_size", mount_setattr, EINVAL, AT_FDCWD, ".", 0, &attr, 8);
    in_str(1, ".");
    want_status(3, "in", "INVALID_EXTENT");
    DONE();
    CALL("mount_setattr.bad_flags", mount_setattr, EINVAL, AT_FDCWD, ".", 0x40000000, &attr,
         sizeof attr);
    in_str(1, ".");
    in_buf(3, &attr, sizeof attr);
    DONE();
}

static void mount_query_cases(void)
{
    struct statx stx;
    struct mnt_id_req req;
    static uint64_t ids[16];
    static uint64_t info[512];
    memset(&stx, 0, sizeof stx);
    memset(ids, 0, sizeof ids);
    memset(info, 0, sizeof info);
    if (statx(AT_FDCWD, ".", 0, STATX_MNT_ID_UNIQUE, &stx) != 0)
        ora_fail("system: unique mount id");

    memset(&req, 0, sizeof req);
    req.size = MNT_ID_REQ_SIZE_VER0;
    req.mnt_id = LSMT_ROOT;
    long got = CALL("listmount.root", listmount, WANT_ANY, &req, ids, 16, 0);
    in_buf(0, &req, MNT_ID_REQ_SIZE_VER0);
    if (got >= 0)
        out_any(1);
    volatile_case();
    why("listing the caller's own mount namespace is allowed when its root is reachable");
    DONE();
    CALL("listmount.bad_flags", listmount, EINVAL, &req, ids, 16, 0x80);
    in_buf(0, &req, MNT_ID_REQ_SIZE_VER0);
    DONE();

    memset(&req, 0, sizeof req);
    req.size = MNT_ID_REQ_SIZE_VER0;
    req.mnt_id = stx.stx_mnt_id;
    req.param = STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC;
    got = CALL("statmount.work_dir", statmount, WANT_ANY, &req, info, sizeof info, 0);
    in_buf(0, &req, MNT_ID_REQ_SIZE_VER0);
    if (got >= 0)
        out_any(1);
    volatile_case();
    why("a mount the caller can reach is described without privilege");
    DONE();
    CALL("statmount.bad_flags", statmount, EINVAL, &req, info, sizeof info, 1);
    in_buf(0, &req, MNT_ID_REQ_SIZE_VER0);
    volatile_case();
    DONE();
    struct mnt_id_req small = req;
    small.size = 8;
    CALL("statmount.small_request", statmount, EINVAL, &small, info, sizeof info, 0);
    want_status(0, "in", "INVALID_EXTENT");
    DONE();
    struct mnt_id_req low = {.size = MNT_ID_REQ_SIZE_VER0, .mnt_id = 5,
                             .param = STATMOUNT_SB_BASIC};
    CALL("statmount.legacy_id", statmount, EINVAL, &low, info, sizeof info, 0);
    in_buf(0, &low, MNT_ID_REQ_SIZE_VER0);
    why("ids at or below MNT_UNIQUE_ID_OFFSET are old-style ids, not unique ones");
    DONE();
    struct mnt_id_req missing = {.size = MNT_ID_REQ_SIZE_VER0, .mnt_id = 1ULL << 40,
                                 .param = STATMOUNT_SB_BASIC};
    CALL("statmount.missing_id", statmount, ENOENT, &missing, info, sizeof info, 0);
    in_buf(0, &missing, MNT_ID_REQ_SIZE_VER0);
    DONE();
}

// sys_uretprobe outside a uprobe trampoline: arch/x86/kernel/uprobes.c sends
// SIGILL and returns -1, so the child dies on the way back to user space.
struct remote_slot {
    long pid, tid;
    uint64_t t0;
};

static void uretprobe_case(void)
{
    struct remote_slot *slot = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (slot == MAP_FAILED) {
        ora_fail("system: uretprobe slot");
        return;
    }
    memset(slot, 0, 4096);
    ora_flush();
    pid_t child = fork();
    if (child < 0) {
        ora_fail("system: uretprobe child");
        munmap(slot, 4096);
        return;
    }
    if (child == 0) {
        ora_child(701);
        struct rlimit none = {0, 0};
        setrlimit(RLIMIT_CORE, &none);
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        slot->pid = getpid();
        slot->tid = syscall(SYS_gettid);
        slot->t0 = ora_now();
        syscall(URETPROBE_NR, 0, 0, 0, 0, 0, 0);
        _exit(3);
    }
    int status = 0;
    pid_t got;
    do
        got = waitpid(child, &status, 0);
    while (got < 0 && errno == EINTR);
    uint64_t t1 = ora_now();
    if (got != child || !WIFSIGNALED(status) || WTERMSIG(status) != SIGILL)
        ora_fail("system: uretprobe child did not die of SIGILL");
    long none[6] = {0};
    remote_begin("uretprobe.outside_trampoline", "uretprobe", URETPROBE_NR, slot->pid, slot->tid,
                 slot->t0, t1, 0, none, -1);
    key_any("context.uretprobe_regs");
    volatile_case();
    why("no uprobe trampoline is mapped: the call returns -1 and the kernel forces SIGILL on "
        "the calling child only (core dumps disabled first)");
    DONE();
    munmap(slot, 4096);
}

static void unavailable_cases(void)
{
    static const struct {
        long nr;
        const char *name, *label;
    } rows[] = {
        {134, "uselib", "uselib.not_implemented"},
        {156, "_sysctl", "_sysctl.not_implemented"},
        {174, "create_module", "create_module.not_implemented"},
        {177, "get_kernel_syms", "get_kernel_syms.not_implemented"},
        {178, "query_module", "query_module.not_implemented"},
        {180, "nfsservctl", "nfsservctl.not_implemented"},
        {181, "getpmsg", "getpmsg.not_implemented"},
        {182, "putpmsg", "putpmsg.not_implemented"},
        {183, "afs_syscall", "afs_syscall.not_implemented"},
        {184, "tuxcall", "tuxcall.not_implemented"},
        {185, "security", "security.not_implemented"},
        {205, "set_thread_area", "set_thread_area.not_implemented"},
        {211, "get_thread_area", "get_thread_area.not_implemented"},
        {212, "lookup_dcookie", "lookup_dcookie.not_implemented"},
        {214, "epoll_ctl_old", "epoll_ctl_old.not_implemented"},
        {215, "epoll_wait_old", "epoll_wait_old.not_implemented"},
        {236, "vserver", "vserver.not_implemented"},
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        CALLNR(rows[i].label, rows[i].name, rows[i].nr, ENOSYS, 0, 0, 0, 0, 0, 0);
        want_key_status("schema.argument_metadata", "NO_DECODER");
        why("the x86-64 table has no entry point for this row; the recorder has no argument "
            "metadata for it");
        DONE();
    }
}

void area_system(void)
{
    if (!unprivileged()) {
        ora_fail("system area must run without privileges");
        return;
    }
    make_resident();
    reboot_kexec_cases();
    module_cases();
    swap_acct_cases();
    mount_cases();
    uts_io_cases();
    in_child(700, "modify_ldt child", ldt_child, NULL);
    syslog_cases();
    quota_cases();
    sysfs_cases();
    perf_cases();
    bpf_cases();
    mount_api_cases();
    mount_query_cases();
    uretprobe_case();
    unavailable_cases();
}
