// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// paths.c — the working directory and the namespace of names: creating,
// renaming, linking and removing directory entries.
//
// Slots: getcwd chdir fchdir rename renameat renameat2 mkdir mkdirat rmdir
// link linkat unlink unlinkat symlink symlinkat readlink readlinkat mknod
// mknodat.
#include "areas.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif
#ifndef RENAME_WHITEOUT
#define RENAME_WHITEOUT (1 << 2)
#endif

static void make_file(const char *name)
{
    static const char text[] = "ANTINOMIE-CONFORMANCE-PATHS";
    int fd = open(name, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        ora_fail("paths setup: create file");
        return;
    }
    if (write(fd, text, sizeof text - 1) != (ssize_t)(sizeof text - 1))
        ora_fail("paths setup: write file");
    close(fd);
}

// lstat a name before an unlink case: the name is gone afterwards.
static struct stat before_unlink(const char *name)
{
    struct stat st;
    memset(&st, 0, sizeof st);
    if (lstat(name, &st) != 0)
        ora_fail("paths: lstat before unlink");
    return st;
}

static void cwd_cases(void)
{
    char buffer[512];
    long got;

    memset(buffer, 0, sizeof buffer);
    got = CALL("getcwd.work_dir", getcwd, WANT_OK, buffer, sizeof buffer);
    out_buf(0, buffer, got > 0 ? (size_t)got : 0);
    volatile_case();
    why("the result is the path length including its NUL; the directory name is random");
    DONE();
    CASE("getcwd.too_small", getcwd, ERANGE, buffer, 4);
    CALL("getcwd.zero_size", getcwd, ERANGE, NULL, 0);
    why("the raw call does not allocate like glibc; size 0 is ERANGE and the output-only "
        "buffer is not recorded on failure");
    DONE();
    CALL("getcwd.fault", getcwd, EFAULT, 1, sizeof buffer);
    why("the path does not fit an unmapped buffer; no output is recorded on failure");
    DONE();

    CALL("mkdir.new", mkdir, WANT_OK, "paths-dir", 0700);
    in_str(0, "paths-dir");
    DONE();
    CALL("mkdir.exists", mkdir, EEXIST, "paths-dir", 0700);
    in_str(0, "paths-dir");
    DONE();
    CALL("mkdir.missing_parent", mkdir, ENOENT, "paths-none/child", 0700);
    in_str(0, "paths-none/child");
    DONE();
    long work = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CALL("mkdirat.dirfd", mkdirat, WANT_OK, work, "paths-sub", 0755);
    in_str(1, "paths-sub");
    DONE();
    CALL("mkdirat.nested", mkdirat, WANT_OK, AT_FDCWD, "paths-dir/inner", 0700);
    in_str(1, "paths-dir/inner");
    DONE();
    CALL("mkdirat.bad_dirfd", mkdirat, EBADF, 999, "paths-sub", 0755);
    in_str(1, "paths-sub");
    DONE();
    CALL("mkdirat.null_path", mkdirat, EFAULT, AT_FDCWD, NULL, 0755);
    want_status(1, "in", "NULL_POINTER");
    DONE();

    // chdir / fchdir: every move is undone before the next group.
    long sub = open("paths-dir", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    long file = open("paths-file", O_RDONLY | O_CLOEXEC);
    CALL("chdir.subdir", chdir, WANT_OK, "paths-dir");
    in_str(0, "paths-dir");
    DONE();
    memset(buffer, 0, sizeof buffer);
    got = CALL("getcwd.subdir", getcwd, WANT_OK, buffer, sizeof buffer);
    out_buf(0, buffer, got > 0 ? (size_t)got : 0);
    volatile_case();
    DONE();
    CALL("chdir.parent", chdir, WANT_OK, "..");
    in_str(0, "..");
    DONE();
    CALL("chdir.missing", chdir, ENOENT, "paths-none");
    in_str(0, "paths-none");
    DONE();
    CALL("chdir.not_dir", chdir, ENOTDIR, "paths-file");
    in_str(0, "paths-file");
    DONE();
    CALL("chdir.null_path", chdir, EFAULT, NULL);
    want_status(0, "in", "NULL_POINTER");
    DONE();
    CASE("fchdir.subdir", fchdir, WANT_OK, sub);
    CASE("fchdir.back", fchdir, WANT_OK, work);
    CASE("fchdir.badf", fchdir, EBADF, 999);
    CASE("fchdir.not_dir", fchdir, ENOTDIR, file);
    CALL("chdir.absolute", chdir, WANT_OK, work_dir);
    in_str(0, work_dir);
    volatile_case();
    DONE();
    if (chdir(work_dir) != 0)
        ora_fail("paths: return to the work directory");
    close((int)file);
    close((int)sub);
    close((int)work);
}

static void symlink_cases(void)
{
    char buffer[256];
    long got;
    long work = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);

    CALL("symlink.new", symlink, WANT_OK, "paths-file", "paths-sym");
    in_str(0, "paths-file");
    in_str(1, "paths-sym");
    DONE();
    CALL("symlink.dangling", symlink, WANT_OK, "paths-nowhere", "paths-dangling");
    in_str(0, "paths-nowhere");
    in_str(1, "paths-dangling");
    DONE();
    CALL("symlink.exists", symlink, EEXIST, "paths-file", "paths-sym");
    in_str(0, "paths-file");
    in_str(1, "paths-sym");
    DONE();
    CALL("symlink.empty_target", symlink, ENOENT, "", "paths-empty");
    in_str(0, "");
    in_str(1, "paths-empty");
    DONE();
    CALL("symlinkat.dirfd", symlinkat, WANT_OK, "paths-file", work, "paths-sym2");
    in_str(0, "paths-file");
    in_str(2, "paths-sym2");
    DONE();
    CALL("symlinkat.bad_dirfd", symlinkat, EBADF, "paths-file", 999, "paths-sym3");
    in_str(0, "paths-file");
    in_str(2, "paths-sym3");
    DONE();
    CALL("symlinkat.null_target", symlinkat, EFAULT, NULL, AT_FDCWD, "paths-sym3");
    want_status(0, "in", "NULL_POINTER");
    in_str(2, "paths-sym3");
    DONE();

    memset(buffer, 0, sizeof buffer);
    got = CALL("readlink.full", readlink, WANT_OK, "paths-sym", buffer, sizeof buffer);
    in_str(0, "paths-sym");
    out_buf(1, buffer, got > 0 ? (size_t)got : 0);
    DONE();
    memset(buffer, 0, sizeof buffer);
    got = CALL("readlink.truncated", readlink, WANT_OK, "paths-sym", buffer, 4);
    in_str(0, "paths-sym");
    out_buf(1, buffer, got > 0 ? (size_t)got : 0);
    why("a short buffer truncates silently: the result is the bytes written, no NUL");
    DONE();
    CALL("readlink.not_link", readlink, EINVAL, "paths-file", buffer, sizeof buffer);
    in_str(0, "paths-file");
    DONE();
    CALL("readlink.missing", readlink, ENOENT, "paths-none", buffer, sizeof buffer);
    in_str(0, "paths-none");
    DONE();
    memset(buffer, 0, sizeof buffer);
    got = CALL("readlinkat.dirfd", readlinkat, WANT_OK, work, "paths-dangling", buffer,
               sizeof buffer);
    in_str(1, "paths-dangling");
    out_buf(2, buffer, got > 0 ? (size_t)got : 0);
    DONE();
    long link_fd = open("paths-sym", O_PATH | O_NOFOLLOW | O_CLOEXEC);
    memset(buffer, 0, sizeof buffer);
    got = CALL("readlinkat.empty_path", readlinkat, WANT_OK, link_fd, "", buffer, sizeof buffer);
    in_str(1, "");
    out_buf(2, buffer, got > 0 ? (size_t)got : 0);
    why("an O_PATH descriptor of the link itself with an empty name reads that link");
    DONE();
    CALL("readlinkat.zero_size", readlinkat, EINVAL, AT_FDCWD, "paths-sym", buffer, 0);
    in_str(1, "paths-sym");
    DONE();
    CALL("readlinkat.bad_dirfd", readlinkat, EBADF, 999, "paths-sym", buffer, sizeof buffer);
    in_str(1, "paths-sym");
    DONE();
    close((int)link_fd);
    close((int)work);
}

static void foreign_linkat(void *arg)
{
    long fd = *(long *)arg;
    CALL("linkat.empty_path_foreign_cred", linkat, ENOENT, fd, "", AT_FDCWD, "paths-flink",
         AT_EMPTY_PATH);
    in_str(1, "");
    in_str(3, "paths-flink");
    why("a forked child has new credentials: linking a descriptor opened by another cred needs "
        "CAP_DAC_READ_SEARCH (the root group can do it)");
    DONE();
}

static void link_cases(void)
{
    long work = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);

    CALL("link.new", link, WANT_OK, "paths-file", "paths-hard");
    in_str(0, "paths-file");
    in_str(1, "paths-hard");
    file_path("LINK", "paths-hard");
    DONE();
    CALL("link.exists", link, EEXIST, "paths-file", "paths-hard");
    in_str(0, "paths-file");
    in_str(1, "paths-hard");
    DONE();
    CALL("link.missing", link, ENOENT, "paths-none", "paths-hard2");
    in_str(0, "paths-none");
    in_str(1, "paths-hard2");
    DONE();
    CALL("link.directory", link, EPERM, "paths-dir", "paths-dirlink");
    in_str(0, "paths-dir");
    in_str(1, "paths-dirlink");
    why("hard links to directories are refused for everyone");
    DONE();

    CALL("linkat.dirfd", linkat, WANT_OK, work, "paths-file", work, "paths-hard2", 0);
    in_str(1, "paths-file");
    in_str(3, "paths-hard2");
    file_path("LINK", "paths-hard2");
    DONE();
    CALL("linkat.symlink_itself", linkat, WANT_OK, AT_FDCWD, "paths-sym", AT_FDCWD,
         "paths-symhard", 0);
    in_str(1, "paths-sym");
    in_str(3, "paths-symhard");
    file_path("LINK", "paths-symhard");
    why("without AT_SYMLINK_FOLLOW the new name is a second link to the symlink inode");
    DONE();
    CALL("linkat.follow", linkat, WANT_OK, AT_FDCWD, "paths-sym", AT_FDCWD, "paths-follow",
         AT_SYMLINK_FOLLOW);
    in_str(1, "paths-sym");
    in_str(3, "paths-follow");
    file_path("LINK", "paths-follow");
    DONE();
    long fd = open("paths-file", O_RDONLY | O_CLOEXEC);
    CALL("linkat.empty_path_own_cred", linkat, WANT_OK, fd, "", AT_FDCWD, "paths-flink",
         AT_EMPTY_PATH);
    in_str(1, "");
    in_str(3, "paths-flink");
    file_path("LINK", "paths-flink");
    why("Linux 6.10+ lets the opener (same cred) link its own descriptor without "
        "CAP_DAC_READ_SEARCH");
    DONE();
    if (unlink("paths-flink") != 0)
        ora_fail("paths: remove the own-cred link");
    in_child(100, "paths linkat foreign cred", foreign_linkat, &fd);
    CALL("linkat.bad_flags", linkat, EINVAL, AT_FDCWD, "paths-file", AT_FDCWD, "paths-hard3",
         0x1);
    in_str(1, "paths-file");
    in_str(3, "paths-hard3");
    DONE();
    CALL("linkat.bad_dirfd", linkat, EBADF, 999, "paths-file", AT_FDCWD, "paths-hard3", 0);
    in_str(1, "paths-file");
    in_str(3, "paths-hard3");
    DONE();
    close((int)fd);
    close((int)work);
}

static void rename_cases(void)
{
    long work = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    make_file("paths-a");
    make_file("paths-x");

    CALL("rename.file", rename, WANT_OK, "paths-a", "paths-b");
    in_str(0, "paths-a");
    in_str(1, "paths-b");
    file_path("RENAME", "paths-b");
    DONE();
    CALL("rename.missing", rename, ENOENT, "paths-a", "paths-b");
    in_str(0, "paths-a");
    in_str(1, "paths-b");
    DONE();
    CALL("rename.dir_over_file", rename, ENOTDIR, "paths-sub", "paths-b");
    in_str(0, "paths-sub");
    in_str(1, "paths-b");
    DONE();
    CALL("rename.null_path", rename, EFAULT, NULL, "paths-c");
    want_status(0, "in", "NULL_POINTER");
    in_str(1, "paths-c");
    DONE();

    CALL("renameat.dirfd", renameat, WANT_OK, work, "paths-b", AT_FDCWD, "paths-c");
    in_str(1, "paths-b");
    in_str(3, "paths-c");
    file_path("RENAME", "paths-c");
    DONE();
    CALL("renameat.replace", renameat, WANT_OK, AT_FDCWD, "paths-c", work, "paths-x");
    in_str(1, "paths-c");
    in_str(3, "paths-x");
    file_path("RENAME", "paths-x");
    why("plain rename replaces an existing target atomically");
    DONE();
    CALL("renameat.bad_dirfd", renameat, EBADF, 999, "paths-x", AT_FDCWD, "paths-c");
    in_str(1, "paths-x");
    in_str(3, "paths-c");
    DONE();

    CALL("renameat2.noreplace", renameat2, WANT_OK, AT_FDCWD, "paths-x", AT_FDCWD, "paths-d",
         RENAME_NOREPLACE);
    in_str(1, "paths-x");
    in_str(3, "paths-d");
    file_path("RENAME", "paths-d");
    DONE();
    CALL("renameat2.noreplace_exists", renameat2, EEXIST, AT_FDCWD, "paths-d", AT_FDCWD,
         "paths-file", RENAME_NOREPLACE);
    in_str(1, "paths-d");
    in_str(3, "paths-file");
    DONE();
    CALL("renameat2.exchange", renameat2, WANT_OK, AT_FDCWD, "paths-d", work, "paths-file",
         RENAME_EXCHANGE);
    in_str(1, "paths-d");
    in_str(3, "paths-file");
    file_path("RENAME", "paths-file");
    why("both names exist and swap inodes");
    DONE();
    CALL("renameat2.exchange_missing", renameat2, ENOENT, AT_FDCWD, "paths-d", AT_FDCWD,
         "paths-none", RENAME_EXCHANGE);
    in_str(1, "paths-d");
    in_str(3, "paths-none");
    DONE();
    CALL("renameat2.whiteout", renameat2, WANT_OK, AT_FDCWD, "paths-d", AT_FDCWD, "paths-e",
         RENAME_WHITEOUT);
    in_str(1, "paths-d");
    in_str(3, "paths-e");
    file_path("RENAME", "paths-e");
    why("since Linux 5.8 a whiteout (char 0:0) needs no CAP_MKNOD; ext4 and tmpfs support it. "
        "The old name is left as a whiteout node, removed with the work directory");
    DONE();
    CALL("renameat2.whiteout_exchange", renameat2, EINVAL, AT_FDCWD, "paths-e", AT_FDCWD,
         "paths-file", RENAME_WHITEOUT | RENAME_EXCHANGE);
    in_str(1, "paths-e");
    in_str(3, "paths-file");
    DONE();
    CALL("renameat2.bad_flags", renameat2, EINVAL, AT_FDCWD, "paths-d", AT_FDCWD, "paths-e",
         RENAME_NOREPLACE | RENAME_EXCHANGE);
    in_str(1, "paths-d");
    in_str(3, "paths-e");
    DONE();
    close((int)work);
}

static void mknod_cases(void)
{
    long work = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);

    CALL("mknod.fifo", mknod, WANT_OK, "paths-fifo", S_IFIFO | 0600, 0);
    in_str(0, "paths-fifo");
    DONE();
    CALL("mknod.regular", mknod, WANT_OK, "paths-reg", S_IFREG | 0600, 0);
    in_str(0, "paths-reg");
    DONE();
    CALL("mknod.default_type", mknod, WANT_OK, "paths-reg2", 0600, 0);
    in_str(0, "paths-reg2");
    why("a mode without a file type creates a regular file");
    DONE();
    CALL("mknod.char_device", mknod, EPERM, "paths-null", S_IFCHR | 0600,
         (unsigned)makedev(1, 3));
    in_str(0, "paths-null");
    why("device nodes need CAP_MKNOD: refused for UID 1000 (the root group creates one)");
    DONE();
    CALL("mknod.exists", mknod, EEXIST, "paths-fifo", S_IFIFO | 0600, 0);
    in_str(0, "paths-fifo");
    DONE();
    CALL("mknod.directory", mknod, EPERM, "paths-mkdir", S_IFDIR | 0700, 0);
    in_str(0, "paths-mkdir");
    why("mknod never creates directories");
    DONE();
    CALL("mknod.bad_type", mknod, EINVAL, "paths-bad", 0160000 | 0600, 0);
    in_str(0, "paths-bad");
    DONE();

    CALL("mknodat.socket", mknodat, WANT_OK, work, "paths-sock", S_IFSOCK | 0600, 0);
    in_str(1, "paths-sock");
    DONE();
    CALL("mknodat.fifo", mknodat, WANT_OK, AT_FDCWD, "paths-fifo2", S_IFIFO | 0640, 0);
    in_str(1, "paths-fifo2");
    DONE();
    CALL("mknodat.block_device", mknodat, EPERM, work, "paths-blk", S_IFBLK | 0600,
         (unsigned)makedev(7, 0));
    in_str(1, "paths-blk");
    why("block device nodes need CAP_MKNOD: refused for UID 1000");
    DONE();
    CALL("mknodat.bad_dirfd", mknodat, EBADF, 999, "paths-fifo3", S_IFIFO | 0600, 0);
    in_str(1, "paths-fifo3");
    DONE();
    close((int)work);
}

static void remove_cases(void)
{
    long work = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    struct stat st;

    st = before_unlink("paths-hard");
    CALL("unlink.file", unlink, WANT_OK, "paths-hard");
    in_str(0, "paths-hard");
    file_stat("UNLINK", &st);
    DONE();
    st = before_unlink("paths-fifo");
    CALL("unlink.fifo", unlink, WANT_OK, "paths-fifo");
    in_str(0, "paths-fifo");
    file_stat("UNLINK", &st);
    DONE();
    st = before_unlink("paths-dangling");
    CALL("unlink.symlink", unlink, WANT_OK, "paths-dangling");
    in_str(0, "paths-dangling");
    file_stat("UNLINK", &st);
    DONE();
    CALL("unlink.missing", unlink, ENOENT, "paths-hard");
    in_str(0, "paths-hard");
    DONE();
    CALL("unlink.directory", unlink, EISDIR, "paths-sub");
    in_str(0, "paths-sub");
    why("Linux reports EISDIR (not POSIX EPERM) for unlink on a directory");
    DONE();
    CALL("unlink.null_path", unlink, EFAULT, NULL);
    want_status(0, "in", "NULL_POINTER");
    DONE();

    st = before_unlink("paths-hard2");
    CALL("unlinkat.dirfd", unlinkat, WANT_OK, work, "paths-hard2", 0);
    in_str(1, "paths-hard2");
    file_stat("UNLINK", &st);
    DONE();
    st = before_unlink("paths-dir/inner");
    CALL("unlinkat.removedir", unlinkat, WANT_OK, AT_FDCWD, "paths-dir/inner", AT_REMOVEDIR);
    in_str(1, "paths-dir/inner");
    file_stat("UNLINK", &st);
    why("AT_REMOVEDIR removes an empty directory; its identity is published like an unlink's, "
        "with no link left");
    DONE();
    CALL("unlinkat.removedir_file", unlinkat, ENOTDIR, AT_FDCWD, "paths-reg", AT_REMOVEDIR);
    in_str(1, "paths-reg");
    DONE();
    if (mkdir("paths-dir/inner", 0700) != 0)
        ora_fail("paths: refill directory");
    CALL("unlinkat.not_empty", unlinkat, ENOTEMPTY, AT_FDCWD, "paths-dir", AT_REMOVEDIR);
    in_str(1, "paths-dir");
    DONE();
    CALL("unlinkat.bad_flags", unlinkat, EINVAL, AT_FDCWD, "paths-reg", 0x1);
    in_str(1, "paths-reg");
    DONE();
    CALL("unlinkat.bad_dirfd", unlinkat, EBADF, 999, "paths-reg", 0);
    in_str(1, "paths-reg");
    DONE();

    st = before_unlink("paths-dir/inner");
    CALL("rmdir.empty", rmdir, WANT_OK, "paths-dir/inner");
    in_str(0, "paths-dir/inner");
    file_stat("UNLINK", &st);
    DONE();
    CALL("rmdir.missing", rmdir, ENOENT, "paths-dir/inner");
    in_str(0, "paths-dir/inner");
    DONE();
    CALL("rmdir.not_dir", rmdir, ENOTDIR, "paths-reg");
    in_str(0, "paths-reg");
    DONE();
    CALL("rmdir.dot", rmdir, EINVAL, ".");
    in_str(0, ".");
    why("removing the dot entry is refused by name before the directory is looked at");
    DONE();
    if (mkdir("paths-dir/inner", 0700) != 0)
        ora_fail("paths: refill directory");
    CALL("rmdir.not_empty", rmdir, ENOTEMPTY, "paths-dir");
    in_str(0, "paths-dir");
    DONE();
    st = before_unlink("paths-sub");
    CALL("rmdir.subdir", rmdir, WANT_OK, "paths-sub");
    in_str(0, "paths-sub");
    file_stat("UNLINK", &st);
    DONE();
    close((int)work);
}

static void cleanup(void)
{
    static const char *const names[] = {
        "paths-file", "paths-d",     "paths-sym",  "paths-sym2", "paths-symhard",
        "paths-follow", "paths-reg", "paths-reg2", "paths-sock", "paths-fifo2",
        "paths-flink", "paths-hard3", "paths-e",   "paths-c",    "paths-b",
    };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        unlink(names[i]);
    rmdir("paths-dir/inner");
    rmdir("paths-dir");
    rmdir("paths-sub");
}

void area_paths(void)
{
    make_file("paths-file");
    cwd_cases();
    symlink_cases();
    link_cases();
    rename_cases();
    mknod_cases();
    remove_cases();
    if (chdir(work_dir) != 0)
        ora_fail("paths: return to the work directory");
    cleanup();
}
