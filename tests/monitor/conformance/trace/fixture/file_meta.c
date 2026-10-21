// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// file_meta.c — file status, permissions, ownership, times, directory
// listings and file handles.
//
// Slots: stat fstat lstat newfstatat statx statfs fstatfs ustat access
// faccessat faccessat2 chmod fchmod fchmodat fchmodat2 chown fchown lchown
// fchownat umask utime utimes futimesat utimensat getdents getdents64
// cachestat name_to_handle_at open_by_handle_at.
#include "areas.h"

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/time.h>
#include <utime.h>

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef AT_EACCESS
#define AT_EACCESS 0x200
#endif
#ifndef AT_STATX_FORCE_SYNC
#define AT_STATX_FORCE_SYNC 0x2000
#endif
#ifndef AT_STATX_DONT_SYNC
#define AT_STATX_DONT_SYNC 0x4000
#endif
#ifndef STATX_MNT_ID
#define STATX_MNT_ID 0x00001000U
#endif
#ifndef STATX__RESERVED
#define STATX__RESERVED 0x80000000U
#endif
#ifndef AT_HANDLE_FID
#define AT_HANDLE_FID 0x200
#endif
#ifndef AT_HANDLE_MNT_ID_UNIQUE
#define AT_HANDLE_MNT_ID_UNIQUE 0x001
#endif
#ifndef UTIME_NOW
#define UTIME_NOW ((1l << 30) - 1l)
#endif
#ifndef UTIME_OMIT
#define UTIME_OMIT ((1l << 30) - 2l)
#endif

// The kernel's struct ustat (include/linux/types.h, not exported to UAPI).
struct ant_ustat {
    int f_tfree;
    unsigned long f_tinode;
    char f_fname[6];
    char f_fpack[6];
};

// include/uapi/linux/mman.h (6.5+), kept local to avoid mixing UAPI and libc headers.
struct ant_cachestat_range {
    uint64_t off, len;
};
struct ant_cachestat {
    uint64_t nr_cache, nr_dirty, nr_writeback, nr_evicted, nr_recently_evicted;
};

// struct file_handle with room for MAX_HANDLE_SZ (128) bytes.
struct ant_handle {
    unsigned int handle_bytes;
    int handle_type;
    unsigned char f_handle[128];
};
#define HANDLE_HEADER 8

static const char meta_text[] = "ANTINOMIE-CONFORMANCE-FILE-META";

static void make_file(const char *name, mode_t mode)
{
    int fd = open(name, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        ora_fail("file_meta setup: create file");
        return;
    }
    if (write(fd, meta_text, sizeof meta_text - 1) != (ssize_t)(sizeof meta_text - 1))
        ora_fail("file_meta setup: write file");
    close(fd);
    if (chmod(name, mode) != 0)
        ora_fail("file_meta setup: chmod");
}

static void stat_cases(void)
{
    struct stat st;
    long fd = open("meta-file", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        ora_fail("file_meta: open meta-file");

    memset(&st, 0, sizeof st);
    CALL("stat.file", stat, WANT_OK, "meta-file", &st);
    in_str(0, "meta-file");
    out_buf(1, &st, sizeof st);
    volatile_case();
    DONE();
    memset(&st, 0, sizeof st);
    CALL("stat.follows_symlink", stat, WANT_OK, "meta-link", &st);
    in_str(0, "meta-link");
    out_buf(1, &st, sizeof st);
    volatile_case();
    DONE();
    CALL("stat.missing", stat, ENOENT, "meta-missing", &st);
    in_str(0, "meta-missing");
    DONE();
    CALL("stat.bad_buffer", stat, EFAULT, "meta-file", 1);
    in_str(0, "meta-file");
    why("the struct stat pointer is unmapped: the kernel fails the copy-out and no output is recorded");
    DONE();
    CALL("stat.null_path", stat, EFAULT, NULL, &st);
    want_status(0, "in", "NULL_POINTER");
    DONE();

    memset(&st, 0, sizeof st);
    CALL("fstat.file", fstat, WANT_OK, fd, &st);
    out_buf(1, &st, sizeof st);
    volatile_case();
    DONE();
    CASE("fstat.badf", fstat, EBADF, 999, &st);
    CALL("fstat.bad_buffer", fstat, EFAULT, fd, 1);
    why("unmapped output buffer: no output field on failure");
    DONE();

    memset(&st, 0, sizeof st);
    CALL("lstat.symlink", lstat, WANT_OK, "meta-link", &st);
    in_str(0, "meta-link");
    out_buf(1, &st, sizeof st);
    volatile_case();
    DONE();
    CALL("lstat.missing", lstat, ENOENT, "meta-missing", &st);
    in_str(0, "meta-missing");
    DONE();
    CALL("lstat.bad_path", lstat, EFAULT, 1, &st);
    want_status(0, "in", "COPY_FAULT");
    why("an address in the first page is never mapped: the kernel and the recorder both fault");
    DONE();

    memset(&st, 0, sizeof st);
    CALL("newfstatat.cwd", newfstatat, WANT_OK, AT_FDCWD, "meta-file", &st, 0);
    in_str(1, "meta-file");
    out_buf(2, &st, sizeof st);
    volatile_case();
    DONE();
    memset(&st, 0, sizeof st);
    CALL("newfstatat.nofollow", newfstatat, WANT_OK, AT_FDCWD, "meta-link", &st,
         AT_SYMLINK_NOFOLLOW);
    in_str(1, "meta-link");
    out_buf(2, &st, sizeof st);
    volatile_case();
    DONE();
    memset(&st, 0, sizeof st);
    CALL("newfstatat.empty_path", newfstatat, WANT_OK, fd, "", &st, AT_EMPTY_PATH);
    in_str(1, "");
    out_buf(2, &st, sizeof st);
    volatile_case();
    DONE();
    memset(&st, 0, sizeof st);
    CALL("newfstatat.null_path", newfstatat, WANT_OK, fd, NULL, &st, AT_EMPTY_PATH);
    want_status(1, "in", "NULL_POINTER");
    out_buf(2, &st, sizeof st);
    volatile_case();
    why("Linux 6.11+ accepts a NULL path with exactly AT_EMPTY_PATH (fstat on the descriptor)");
    DONE();
    CALL("newfstatat.bad_flags", newfstatat, EINVAL, AT_FDCWD, "meta-file", &st, 0x1);
    in_str(1, "meta-file");
    DONE();
    CALL("newfstatat.bad_dirfd", newfstatat, EBADF, 999, "meta-file", &st, 0);
    in_str(1, "meta-file");
    DONE();

    // statx: masks, sync modes, symlinks, empty and NULL paths.
    struct statx sx;
    memset(&sx, 0, sizeof sx);
    CALL("statx.basic", statx, WANT_OK, AT_FDCWD, "meta-file", 0, STATX_BASIC_STATS, &sx);
    in_str(1, "meta-file");
    out_buf(4, &sx, sizeof sx);
    volatile_case();
    DONE();
    memset(&sx, 0, sizeof sx);
    CALL("statx.all_mnt_id", statx, WANT_OK, AT_FDCWD, "meta-file", 0,
         STATX_ALL | STATX_MNT_ID, &sx);
    in_str(1, "meta-file");
    out_buf(4, &sx, sizeof sx);
    volatile_case();
    DONE();
    memset(&sx, 0, sizeof sx);
    CALL("statx.zero_mask", statx, WANT_OK, AT_FDCWD, "meta-file", 0, 0, &sx);
    in_str(1, "meta-file");
    out_buf(4, &sx, sizeof sx);
    volatile_case();
    DONE();
    memset(&sx, 0, sizeof sx);
    CALL("statx.nofollow", statx, WANT_OK, AT_FDCWD, "meta-link", AT_SYMLINK_NOFOLLOW,
         STATX_TYPE | STATX_MODE | STATX_SIZE, &sx);
    in_str(1, "meta-link");
    out_buf(4, &sx, sizeof sx);
    volatile_case();
    DONE();
    memset(&sx, 0, sizeof sx);
    CALL("statx.force_sync", statx, WANT_OK, AT_FDCWD, "meta-file", AT_STATX_FORCE_SYNC,
         STATX_BASIC_STATS | STATX_BTIME, &sx);
    in_str(1, "meta-file");
    out_buf(4, &sx, sizeof sx);
    volatile_case();
    DONE();
    memset(&sx, 0, sizeof sx);
    CALL("statx.dont_sync", statx, WANT_OK, AT_FDCWD, "meta-file",
         AT_STATX_DONT_SYNC | AT_NO_AUTOMOUNT, STATX_SIZE, &sx);
    in_str(1, "meta-file");
    out_buf(4, &sx, sizeof sx);
    volatile_case();
    DONE();
    memset(&sx, 0, sizeof sx);
    CALL("statx.empty_path", statx, WANT_OK, fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &sx);
    in_str(1, "");
    out_buf(4, &sx, sizeof sx);
    volatile_case();
    DONE();
    memset(&sx, 0, sizeof sx);
    CALL("statx.null_path", statx, WANT_OK, fd, NULL, AT_EMPTY_PATH, STATX_BASIC_STATS, &sx);
    want_status(1, "in", "NULL_POINTER");
    out_buf(4, &sx, sizeof sx);
    volatile_case();
    why("Linux 6.11+ accepts a NULL path with AT_EMPTY_PATH on a real descriptor");
    DONE();
    CALL("statx.null_path_fdcwd", statx, EFAULT, AT_FDCWD, NULL, AT_EMPTY_PATH,
         STATX_BASIC_STATS, &sx);
    want_status(1, "in", "NULL_POINTER");
    why("the NULL-path shortcut needs a descriptor; with AT_FDCWD the path copy faults");
    DONE();
    CALL("statx.null_path_no_flag", statx, EFAULT, fd, NULL, 0, STATX_BASIC_STATS, &sx);
    want_status(1, "in", "NULL_POINTER");
    DONE();
    CALL("statx.both_sync_flags", statx, EINVAL, AT_FDCWD, "meta-file",
         AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC, STATX_BASIC_STATS, &sx);
    in_str(1, "meta-file");
    DONE();
    CALL("statx.reserved_mask", statx, EINVAL, AT_FDCWD, "meta-file", 0, STATX__RESERVED, &sx);
    in_str(1, "meta-file");
    DONE();
    CALL("statx.missing", statx, ENOENT, AT_FDCWD, "meta-missing", 0, STATX_BASIC_STATS, &sx);
    in_str(1, "meta-missing");
    DONE();

    // statfs, fstatfs, ustat.
    struct statfs fs;
    memset(&fs, 0, sizeof fs);
    CALL("statfs.dot", statfs, WANT_OK, ".", &fs);
    in_str(0, ".");
    out_buf(1, &fs, sizeof fs);
    volatile_case();
    DONE();
    CALL("statfs.missing", statfs, ENOENT, "meta-missing", &fs);
    in_str(0, "meta-missing");
    DONE();
    memset(&fs, 0, sizeof fs);
    CALL("fstatfs.file", fstatfs, WANT_OK, fd, &fs);
    out_buf(1, &fs, sizeof fs);
    volatile_case();
    DONE();
    CASE("fstatfs.badf", fstatfs, EBADF, 999, &fs);

    struct stat dir_st;
    if (stat(".", &dir_st) != 0)
        ora_fail("file_meta: stat work dir");
    struct ant_ustat us;
    memset(&us, 0, sizeof us);
    CALL("ustat.work_dir_device", ustat, WANT_OK, (unsigned)dir_st.st_dev, &us);
    out_buf(1, &us, sizeof us);
    volatile_case();
    why("the work directory's superblock is found by its device number (old 32-bit encoding)");
    DONE();
    CASE("ustat.no_device", ustat, EINVAL, 0, &us);

    close((int)fd);
}

static void access_cases(void)
{
    CALL("access.read", access, WANT_OK, "meta-file", R_OK);
    in_str(0, "meta-file");
    DONE();
    CALL("access.exists", access, WANT_OK, "meta-file", F_OK);
    in_str(0, "meta-file");
    DONE();
    CALL("access.denied", access, EACCES, "meta-ro", R_OK | W_OK);
    in_str(0, "meta-ro");
    why("meta-ro has mode 000 and the caller is not privileged");
    DONE();
    CALL("access.missing", access, ENOENT, "meta-missing", F_OK);
    in_str(0, "meta-missing");
    DONE();
    CALL("access.bad_mode", access, EINVAL, "meta-file", 0x80);
    in_str(0, "meta-file");
    DONE();

    CALL("faccessat.cwd", faccessat, WANT_OK, AT_FDCWD, "meta-file", R_OK | W_OK);
    in_str(1, "meta-file");
    DONE();
    CALL("faccessat.bad_dirfd", faccessat, EBADF, 999, "meta-file", R_OK);
    in_str(1, "meta-file");
    DONE();
    CALL("faccessat.denied", faccessat, EACCES, AT_FDCWD, "meta-ro", X_OK);
    in_str(1, "meta-ro");
    DONE();

    long dir = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    long fd = open("meta-file", O_RDONLY | O_CLOEXEC);
    CALL("faccessat2.eaccess", faccessat2, WANT_OK, AT_FDCWD, "meta-file", R_OK, AT_EACCESS);
    in_str(1, "meta-file");
    DONE();
    CALL("faccessat2.nofollow", faccessat2, WANT_OK, dir, "meta-link", F_OK,
         AT_SYMLINK_NOFOLLOW);
    in_str(1, "meta-link");
    DONE();
    CALL("faccessat2.empty_path", faccessat2, WANT_OK, fd, "", R_OK, AT_EMPTY_PATH);
    in_str(1, "");
    DONE();
    CALL("faccessat2.bad_flags", faccessat2, EINVAL, AT_FDCWD, "meta-file", R_OK, 0x1);
    in_str(1, "meta-file");
    DONE();
    CALL("faccessat2.null_path", faccessat2, EFAULT, AT_FDCWD, NULL, R_OK, 0);
    want_status(1, "in", "NULL_POINTER");
    DONE();
    close((int)fd);
    close((int)dir);
}

static void mode_owner_cases(void)
{
    long fd = open("meta-file", O_RDWR | O_CLOEXEC);
    long uid = getuid(), gid = getgid();

    CALL("chmod.file", chmod, WANT_OK, "meta-file", 0640);
    in_str(0, "meta-file");
    DONE();
    CALL("chmod.missing", chmod, ENOENT, "meta-missing", 0600);
    in_str(0, "meta-missing");
    DONE();
    CALL("chmod.not_owner", chmod, EPERM, "/tmp", 01777);
    in_str(0, "/tmp");
    why("/tmp (writable, owned by root) cannot be changed by UID 1000; same mode either way");
    DONE();
    CASE("fchmod.file", fchmod, WANT_OK, fd, 0600);
    CASE("fchmod.badf", fchmod, EBADF, 999, 0600);
    CALL("fchmodat.cwd", fchmodat, WANT_OK, AT_FDCWD, "meta-file", 0644);
    in_str(1, "meta-file");
    DONE();
    CALL("fchmodat.bad_dirfd", fchmodat, EBADF, 999, "meta-file", 0644);
    in_str(1, "meta-file");
    DONE();
    CALL("fchmodat2.nofollow_file", fchmodat2, WANT_OK, AT_FDCWD, "meta-file", 0600,
         AT_SYMLINK_NOFOLLOW);
    in_str(1, "meta-file");
    DONE();
    CALL("fchmodat2.empty_path", fchmodat2, WANT_OK, fd, "", 0640, AT_EMPTY_PATH);
    in_str(1, "");
    DONE();
    CALL("fchmodat2.nofollow_symlink", fchmodat2, EOPNOTSUPP, AT_FDCWD, "meta-link", 0600,
         AT_SYMLINK_NOFOLLOW);
    in_str(1, "meta-link");
    why("Linux does not change symlink modes: notify_change refuses ATTR_MODE on a link");
    DONE();
    CALL("fchmodat2.bad_flags", fchmodat2, EINVAL, AT_FDCWD, "meta-file", 0600, 0x1);
    in_str(1, "meta-file");
    DONE();

    CALL("chown.own_ids", chown, WANT_OK, "meta-file", uid, gid);
    in_str(0, "meta-file");
    DONE();
    CALL("chown.unchanged", chown, WANT_OK, "meta-file", -1, -1);
    in_str(0, "meta-file");
    DONE();
    CALL("chown.to_root", chown, EPERM, "meta-file", 0, 0);
    in_str(0, "meta-file");
    why("giving a file to root needs CAP_CHOWN: refused for UID 1000");
    DONE();
    CALL("chown.missing", chown, ENOENT, "meta-missing", uid, gid);
    in_str(0, "meta-missing");
    DONE();
    CASE("fchown.own_ids", fchown, WANT_OK, fd, uid, gid);
    CASE("fchown.to_root", fchown, EPERM, fd, 0, -1);
    CASE("fchown.badf", fchown, EBADF, 999, uid, gid);
    CALL("lchown.symlink", lchown, WANT_OK, "meta-link", uid, gid);
    in_str(0, "meta-link");
    DONE();
    CALL("lchown.to_root", lchown, EPERM, "meta-link", 0, 0);
    in_str(0, "meta-link");
    DONE();
    CALL("fchownat.nofollow", fchownat, WANT_OK, AT_FDCWD, "meta-link", uid, gid,
         AT_SYMLINK_NOFOLLOW);
    in_str(1, "meta-link");
    DONE();
    CALL("fchownat.empty_path", fchownat, WANT_OK, fd, "", -1, gid, AT_EMPTY_PATH);
    in_str(1, "");
    DONE();
    CALL("fchownat.bad_flags", fchownat, EINVAL, AT_FDCWD, "meta-file", uid, gid, 0x1);
    in_str(1, "meta-file");
    DONE();
    CALL("fchownat.to_root", fchownat, EPERM, AT_FDCWD, "meta-file", 0, -1, 0);
    in_str(1, "meta-file");
    DONE();

    long old = CASE("umask.set", umask, WANT_OK, 027);
    CALL("umask.full_bits", umask, WANT_OK, 0177777);
    why("only the permission bits are kept; the call cannot fail");
    DONE();
    CASE("umask.restore", umask, WANT_OK, old);
    close((int)fd);
}

static void time_cases(void)
{
    long fd = open("meta-file", O_RDWR | O_CLOEXEC);

    struct utimbuf ub = {.actime = 1000000000, .modtime = 1000000001};
    CALL("utime.explicit", utime, WANT_OK, "meta-file", &ub);
    in_str(0, "meta-file");
    in_buf(1, &ub, sizeof ub);
    DONE();
    CALL("utime.now", utime, WANT_OK, "meta-file", NULL);
    in_str(0, "meta-file");
    want_status(1, "in", "NULL_POINTER");
    DONE();
    CALL("utime.missing", utime, ENOENT, "meta-missing", &ub);
    in_str(0, "meta-missing");
    in_buf(1, &ub, sizeof ub);
    DONE();

    struct timeval tv[2] = {{.tv_sec = 1100000000, .tv_usec = 5}, {.tv_sec = 1100000001, .tv_usec = 6}};
    CALL("utimes.explicit", utimes, WANT_OK, "meta-file", tv);
    in_str(0, "meta-file");
    in_buf(1, tv, sizeof tv);
    DONE();
    CALL("utimes.now", utimes, WANT_OK, "meta-file", NULL);
    in_str(0, "meta-file");
    want_status(1, "in", "NULL_POINTER");
    DONE();
    struct timeval bad_tv[2] = {{.tv_sec = 1, .tv_usec = 1000000}, {.tv_sec = 1, .tv_usec = 0}};
    CALL("utimes.bad_usec", utimes, EINVAL, "meta-file", bad_tv);
    in_str(0, "meta-file");
    in_buf(1, bad_tv, sizeof bad_tv);
    DONE();
    CALL("utimes.not_owner", utimes, EPERM, "/tmp", tv);
    in_str(0, "/tmp");
    in_buf(1, tv, sizeof tv);
    why("explicit times on root-owned /tmp are refused for UID 1000 (writable mount, so not EROFS)");
    DONE();

    long dir = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CALL("futimesat.dirfd", futimesat, WANT_OK, dir, "meta-file", tv);
    in_str(1, "meta-file");
    in_buf(2, tv, sizeof tv);
    DONE();
    CALL("futimesat.null_path", futimesat, WANT_OK, fd, NULL, tv);
    want_status(1, "in", "NULL_POINTER");
    in_buf(2, tv, sizeof tv);
    why("a NULL name acts on the descriptor itself (legacy futimes)");
    DONE();
    CALL("futimesat.null_times", futimesat, WANT_OK, AT_FDCWD, "meta-file", NULL);
    in_str(1, "meta-file");
    want_status(2, "in", "NULL_POINTER");
    DONE();
    CALL("futimesat.bad_dirfd", futimesat, EBADF, 999, "meta-file", tv);
    in_str(1, "meta-file");
    in_buf(2, tv, sizeof tv);
    DONE();

    struct timespec ts[2] = {{.tv_sec = 1200000000, .tv_nsec = 7}, {.tv_sec = 1200000001, .tv_nsec = 8}};
    CALL("utimensat.explicit", utimensat, WANT_OK, AT_FDCWD, "meta-file", ts, 0);
    in_str(1, "meta-file");
    in_buf(2, ts, sizeof ts);
    DONE();
    CALL("utimensat.null_times", utimensat, WANT_OK, AT_FDCWD, "meta-file", NULL, 0);
    in_str(1, "meta-file");
    want_status(2, "in", "NULL_POINTER");
    DONE();
    struct timespec now_omit[2] = {{.tv_sec = 0, .tv_nsec = UTIME_NOW},
                                   {.tv_sec = 0, .tv_nsec = UTIME_OMIT}};
    CALL("utimensat.now_omit", utimensat, WANT_OK, AT_FDCWD, "meta-file", now_omit, 0);
    in_str(1, "meta-file");
    in_buf(2, now_omit, sizeof now_omit);
    DONE();
    CALL("utimensat.nofollow_symlink", utimensat, WANT_OK, AT_FDCWD, "meta-link", ts,
         AT_SYMLINK_NOFOLLOW);
    in_str(1, "meta-link");
    in_buf(2, ts, sizeof ts);
    DONE();
    CALL("utimensat.null_path_fd", utimensat, WANT_OK, fd, NULL, ts, 0);
    want_status(1, "in", "NULL_POINTER");
    in_buf(2, ts, sizeof ts);
    why("a NULL path with a descriptor is futimens()");
    DONE();
    CALL("utimensat.empty_path", utimensat, WANT_OK, fd, "", now_omit, AT_EMPTY_PATH);
    in_str(1, "");
    in_buf(2, now_omit, sizeof now_omit);
    DONE();
    struct timespec bad_ts[2] = {{.tv_sec = 1, .tv_nsec = 2000000000}, {.tv_sec = 1, .tv_nsec = 0}};
    CALL("utimensat.bad_nsec", utimensat, EINVAL, AT_FDCWD, "meta-file", bad_ts, 0);
    in_str(1, "meta-file");
    in_buf(2, bad_ts, sizeof bad_ts);
    DONE();
    CALL("utimensat.bad_flags", utimensat, EINVAL, AT_FDCWD, "meta-file", ts, 0x1);
    in_str(1, "meta-file");
    in_buf(2, ts, sizeof ts);
    DONE();
    CALL("utimensat.null_path_flags", utimensat, EINVAL, fd, NULL, ts, AT_SYMLINK_NOFOLLOW);
    want_status(1, "in", "NULL_POINTER");
    in_buf(2, ts, sizeof ts);
    why("flags are not allowed with the NULL-path descriptor form");
    DONE();
    CALL("utimensat.missing", utimensat, ENOENT, AT_FDCWD, "meta-missing", NULL, 0);
    in_str(1, "meta-missing");
    want_status(2, "in", "NULL_POINTER");
    DONE();
    CALL("utimensat.times_fault", utimensat, EFAULT, AT_FDCWD, "meta-file", 1, 0);
    in_str(1, "meta-file");
    want_status(2, "in", "COPY_FAULT");
    DONE();
    close((int)dir);
    close((int)fd);
}

static void dirent_cases(void)
{
    static char buffer[4096];
    long dir = open("meta-dir", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    long file = open("meta-file", O_RDONLY | O_CLOEXEC);
    long got;

    memset(buffer, 0, sizeof buffer);
    got = CALL("getdents64.list", getdents64, WANT_OK, dir, buffer, sizeof buffer);
    out_buf(1, buffer, got > 0 ? (size_t)got : 0);
    volatile_case();
    DONE();
    got = CALL("getdents64.end", getdents64, WANT_OK, dir, buffer, sizeof buffer);
    out_buf(1, buffer, 0);
    why("at the end of the directory the call returns 0 and writes nothing");
    DONE();
    lseek((int)dir, 0, SEEK_SET);
    CASE("getdents64.too_small", getdents64, EINVAL, dir, buffer, 8);
    CASE("getdents64.not_dir", getdents64, ENOTDIR, file, buffer, sizeof buffer);
    CASE("getdents64.badf", getdents64, EBADF, 999, buffer, sizeof buffer);

    lseek((int)dir, 0, SEEK_SET);
    memset(buffer, 0, sizeof buffer);
    got = CALL("getdents.list", getdents, WANT_OK, dir, buffer, sizeof buffer);
    out_buf(1, buffer, got > 0 ? (size_t)got : 0);
    volatile_case();
    DONE();
    got = CALL("getdents.end", getdents, WANT_OK, dir, buffer, sizeof buffer);
    out_buf(1, buffer, 0);
    DONE();
    lseek((int)dir, 0, SEEK_SET);
    CASE("getdents.too_small", getdents, EINVAL, dir, buffer, 8);
    CASE("getdents.not_dir", getdents, ENOTDIR, file, buffer, sizeof buffer);
    CASE("getdents.badf", getdents, EBADF, 999, buffer, sizeof buffer);
    lseek((int)dir, 0, SEEK_SET);
    CALL("getdents.fault", getdents, EFAULT, dir, 1, sizeof buffer);
    why("the first entry cannot be copied to an unmapped buffer; nothing is recorded as output");
    DONE();
    (void)got;
    close((int)file);
    close((int)dir);
}

static void cachestat_cases(void)
{
    long fd = open("meta-file", O_RDWR | O_CLOEXEC);
    struct ant_cachestat_range whole = {.off = 0, .len = 0};
    struct ant_cachestat_range page = {.off = 0, .len = 4096};
    struct ant_cachestat cs;

    memset(&cs, 0, sizeof cs);
    CALL("cachestat.whole_file", cachestat, WANT_OK, fd, &whole, &cs, 0);
    in_buf(1, &whole, sizeof whole);
    out_buf(2, &cs, sizeof cs);
    volatile_case();
    why("len 0 means up to the end of the file; dirty/writeback counts depend on timing");
    DONE();
    memset(&cs, 0, sizeof cs);
    CALL("cachestat.one_page", cachestat, WANT_OK, fd, &page, &cs, 0);
    in_buf(1, &page, sizeof page);
    out_buf(2, &cs, sizeof cs);
    volatile_case();
    DONE();
    CALL("cachestat.bad_flags", cachestat, EINVAL, fd, &page, &cs, 1);
    in_buf(1, &page, sizeof page);
    DONE();
    CALL("cachestat.badf", cachestat, EBADF, 999, &page, &cs, 0);
    in_buf(1, &page, sizeof page);
    DONE();
    CALL("cachestat.null_range", cachestat, EFAULT, fd, NULL, &cs, 0);
    want_status(1, "in", "NULL_POINTER");
    DONE();
    close((int)fd);
}

static void handle_cases(void)
{
    struct ant_handle handle, query, before;
    int mount_id = 0;
    uint64_t unique_id = 0;
    long dir = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    long fd = open("meta-file", O_RDONLY | O_CLOEXEC);

    memset(&handle, 0, sizeof handle);
    handle.handle_bytes = sizeof handle.f_handle;
    before = handle;
    CALL("name_to_handle_at.file", name_to_handle_at, WANT_OK, AT_FDCWD, "meta-file", &handle,
         &mount_id, 0);
    in_str(1, "meta-file");
    in_key("handle.header", &before, HANDLE_HEADER);
    out_key("handle.header", &handle, HANDLE_HEADER);
    out_key("handle.bytes", handle.f_handle,
            handle.handle_bytes <= sizeof handle.f_handle ? handle.handle_bytes : 0);
    out_key("arg3.mount_id", &mount_id, sizeof mount_id);
    volatile_case();
    why("the handle encodes the inode number and generation; the mount id is per boot");
    DONE();
    struct ant_handle saved = handle;

    memset(&query, 0, sizeof query);
    before = query;
    CALL("name_to_handle_at.size_query", name_to_handle_at, EOVERFLOW, AT_FDCWD, "meta-file",
         &query, &mount_id, 0);
    in_str(1, "meta-file");
    in_key("handle.header", &before, HANDLE_HEADER);
    out_key("handle.header", &query, HANDLE_HEADER);
    out_key("arg3.mount_id", &mount_id, sizeof mount_id);
    volatile_case();
    why("handle_bytes 0 asks for the needed size: the header and mount id are still written");
    DONE();

    memset(&handle, 0, sizeof handle);
    handle.handle_bytes = sizeof handle.f_handle;
    before = handle;
    CALL("name_to_handle_at.unique_mnt_id", name_to_handle_at, WANT_OK, AT_FDCWD, "meta-link",
         &handle, &unique_id, AT_SYMLINK_FOLLOW | AT_HANDLE_MNT_ID_UNIQUE);
    in_str(1, "meta-link");
    in_key("handle.header", &before, HANDLE_HEADER);
    out_key("handle.header", &handle, HANDLE_HEADER);
    out_key("handle.bytes", handle.f_handle,
            handle.handle_bytes <= sizeof handle.f_handle ? handle.handle_bytes : 0);
    out_key("arg3.mount_id", &unique_id, sizeof unique_id);
    volatile_case();
    why("AT_HANDLE_MNT_ID_UNIQUE (6.12) writes a u64 mount id");
    DONE();

    memset(&handle, 0, sizeof handle);
    handle.handle_bytes = sizeof handle.f_handle;
    before = handle;
    CALL("name_to_handle_at.empty_path_fid", name_to_handle_at, WANT_OK, fd, "", &handle,
         &mount_id, AT_EMPTY_PATH | AT_HANDLE_FID);
    in_str(1, "");
    in_key("handle.header", &before, HANDLE_HEADER);
    out_key("handle.header", &handle, HANDLE_HEADER);
    out_key("handle.bytes", handle.f_handle,
            handle.handle_bytes <= sizeof handle.f_handle ? handle.handle_bytes : 0);
    out_key("arg3.mount_id", &mount_id, sizeof mount_id);
    volatile_case();
    DONE();

    memset(&handle, 0, sizeof handle);
    handle.handle_bytes = 129;
    before = handle;
    CALL("name_to_handle_at.too_large", name_to_handle_at, EINVAL, AT_FDCWD, "meta-file",
         &handle, &mount_id, 0);
    in_str(1, "meta-file");
    in_key("handle.header", &before, HANDLE_HEADER);
    why("handle_bytes above MAX_HANDLE_SZ (128) is rejected");
    DONE();
    memset(&handle, 0, sizeof handle);
    handle.handle_bytes = sizeof handle.f_handle;
    before = handle;
    CALL("name_to_handle_at.bad_flags", name_to_handle_at, EINVAL, AT_FDCWD, "meta-file",
         &handle, &mount_id, 0x8000);
    in_str(1, "meta-file");
    in_key("handle.header", &before, HANDLE_HEADER);
    DONE();
    CALL("name_to_handle_at.missing", name_to_handle_at, ENOENT, AT_FDCWD, "meta-missing",
         &handle, &mount_id, 0);
    in_str(1, "meta-missing");
    in_key("handle.header", &before, HANDLE_HEADER);
    DONE();
    CALL("name_to_handle_at.null_mount_id", name_to_handle_at, EFAULT, AT_FDCWD, "meta-file",
         &handle, NULL, 0);
    in_str(1, "meta-file");
    in_key("handle.header", &before, HANDLE_HEADER);
    why("the mount id is stored before the handle: a NULL pointer fails the whole call");
    DONE();

    // open_by_handle_at needs CAP_DAC_READ_SEARCH (or the O_DIRECTORY
    // userns-admin path): UID 1000 is refused after the descriptor check.
    CALL("open_by_handle_at.user_eperm", open_by_handle_at, EPERM, dir, &saved, O_RDONLY);
    in_key("handle.header", &saved, HANDLE_HEADER);
    in_key("handle.bytes", saved.f_handle,
           saved.handle_bytes <= sizeof saved.f_handle ? saved.handle_bytes : 0);
    volatile_case();
    why("decoding a file handle needs CAP_DAC_READ_SEARCH; the root group opens it");
    DONE();
    struct ant_handle empty;
    memset(&empty, 0, sizeof empty);
    CALL("open_by_handle_at.zero_bytes", open_by_handle_at, EPERM, dir, &empty, O_RDONLY);
    in_key("handle.header", &empty, HANDLE_HEADER);
    want_key_status("handle.bytes", "INVALID_EXTENT");
    why("the recorder flags handle_bytes 0 as an invalid extent; the permission check fails first");
    DONE();
    CALL("open_by_handle_at.badf", open_by_handle_at, EBADF, 999, &saved, O_RDONLY);
    in_key("handle.header", &saved, HANDLE_HEADER);
    in_key("handle.bytes", saved.f_handle,
           saved.handle_bytes <= sizeof saved.f_handle ? saved.handle_bytes : 0);
    volatile_case();
    DONE();
    close((int)fd);
    close((int)dir);
}

void area_file_meta(void)
{
    make_file("meta-file", 0600);
    make_file("meta-ro", 0000);
    if (symlink("meta-file", "meta-link") != 0 || mkdir("meta-dir", 0700) != 0)
        ora_fail("file_meta setup: link and directory");
    make_file("meta-dir/entry-a", 0600);
    make_file("meta-dir/entry-b", 0600);

    stat_cases();
    access_cases();
    mode_owner_cases();
    time_cases();
    dirent_cases();
    cachestat_cases();
    handle_cases();

    chmod("meta-ro", 0600);
    unlink("meta-dir/entry-a");
    unlink("meta-dir/entry-b");
    rmdir("meta-dir");
    unlink("meta-link");
    unlink("meta-ro");
    unlink("meta-file");
}
