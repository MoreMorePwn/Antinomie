// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// file_io.c — opening, reading, writing, seeking and descriptor control.
//
// Slots: read write open close lseek pread64 pwrite64 readv writev dup dup2
// dup3 sendfile fcntl flock fsync fdatasync truncate ftruncate creat
// readahead fadvise64 sync_file_range fallocate preadv pwritev preadv2
// pwritev2 copy_file_range memfd_create close_range openat openat2 sync
// syncfs getrandom.
#include "areas.h"

#include <fcntl.h>
#include <linux/close_range.h>
#include <linux/openat2.h>
#include <signal.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>

#ifndef F_GETOWNER_UIDS
#define F_GETOWNER_UIDS 17
#endif
#ifndef RWF_HIPRI
#define RWF_HIPRI 0x1
#endif
#ifndef RWF_DSYNC
#define RWF_DSYNC 0x2
#endif
#ifndef RWF_APPEND
#define RWF_APPEND 0x10
#endif

static const char text[] = "ANTINOMIE-CONFORMANCE-FILE-IO-0123456789";

static void open_cases(void)
{
    char path[300];
    struct open_how how = {.flags = O_RDONLY | O_CLOEXEC, .resolve = RESOLVE_NO_SYMLINKS};
    long fd;

    fd = CALL("open.create", open, WANT_OK, "io-open", O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC,
              0600);
    in_str(0, "io-open");
    file_fd("OPEN", (int)fd);
    DONE();
    CASE("close.open", close, WANT_OK, fd);
    CALL("open.missing", open, ENOENT, "io-missing", O_RDONLY, 0);
    in_str(0, "io-missing");
    DONE();
    CALL("open.null_path", open, EFAULT, NULL, O_RDONLY, 0);
    want_status(0, "in", "NULL_POINTER");
    DONE();
    CALL("open.bad_path", open, EFAULT, 1, O_RDONLY, 0);
    want_status(0, "in", "COPY_FAULT");
    why("an address in the first page is never mapped: the kernel and the recorder both fault");
    DONE();

    fd = CALL("openat.cwd", openat, WANT_OK, AT_FDCWD, "io-at", O_CREAT | O_WRONLY | O_EXCL, 0640);
    in_str(1, "io-at");
    file_fd("OPEN", (int)fd);
    DONE();
    CASE("close.openat", close, WANT_OK, fd);
    long dir = CALL("openat.directory", openat, WANT_OK, AT_FDCWD, ".",
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    in_str(1, ".");
    file_fd("OPEN", (int)dir);
    DONE();
    fd = CALL("openat.relative_dirfd", openat, WANT_OK, dir, "io-at", O_RDONLY | O_NOFOLLOW, 0);
    in_str(1, "io-at");
    file_fd("OPEN", (int)fd);
    DONE();
    CASE("close.relative", close, WANT_OK, fd);
    CALL("openat.exists_excl", openat, EEXIST, AT_FDCWD, "io-at", O_CREAT | O_EXCL | O_RDWR,
         0600);
    in_str(1, "io-at");
    DONE();
    fd = CALL("openat.absolute", openat, WANT_OK, AT_FDCWD,
              work_path(path, sizeof path, "io-at"), O_RDONLY | O_CLOEXEC, 0);
    in_str(1, path);
    file_fd("OPEN", (int)fd);
    DONE();
    CASE("close.absolute", close, WANT_OK, fd);
    CALL("openat.bad_dirfd", openat, EBADF, 999, "io-at", O_RDONLY, 0);
    in_str(1, "io-at");
    DONE();
    fd = CALL("openat.tmpfile", openat, WANT_ANY, AT_FDCWD, ".", O_TMPFILE | O_RDWR, 0600);
    in_str(1, ".");
    why("O_TMPFILE needs filesystem support: tmpfs has it, the result is recorded either way");
    if (fd >= 0)
        file_fd("OPEN", (int)fd);
    DONE();
    if (fd >= 0)
        CASE("close.tmpfile", close, WANT_OK, fd);

    fd = CALL("openat2.resolve", openat2, WANT_OK, AT_FDCWD, "io-at", &how, sizeof how);
    in_str(1, "io-at");
    in_buf(2, &how, sizeof how);
    file_fd("OPEN", (int)fd);
    DONE();
    CASE("close.openat2", close, WANT_OK, fd);
    CALL("openat2.small_how", openat2, EINVAL, AT_FDCWD, "io-at", &how, 8);
    in_str(1, "io-at");
    want_status(2, "in", "INVALID_EXTENT");
    why("a size below OPEN_HOW_SIZE_VER0 is rejected by the kernel and recorded as an invalid extent");
    DONE();
    struct open_how bad = {.flags = O_RDONLY, .resolve = 0x80000000ULL};
    CALL("openat2.unknown_resolve", openat2, EINVAL, AT_FDCWD, "io-at", &bad, sizeof bad);
    in_str(1, "io-at");
    in_buf(2, &bad, sizeof bad);
    DONE();

    fd = CALL("creat.new", creat, WANT_OK, "io-creat", 0600);
    in_str(0, "io-creat");
    file_fd("OPEN", (int)fd);
    DONE();
    CASE("close.creat", close, WANT_OK, fd);
    CALL("creat.missing_dir", creat, ENOENT, "no-such-dir/io-creat", 0600);
    in_str(0, "no-such-dir/io-creat");
    DONE();
    CASE("close.badf", close, EBADF, 999);
    CASE("close.directory", close, WANT_OK, dir);
}

static void read_write_cases(void)
{
    char buffer[256], second[64];
    long fd = CALL("openat.rw", openat, WANT_OK, AT_FDCWD, "io-rw", O_CREAT | O_RDWR | O_TRUNC,
                   0600);
    in_str(1, "io-rw");
    file_fd("OPEN", (int)fd);
    DONE();

    CALL("write.text", write, WANT_OK, fd, text, sizeof text - 1);
    in_buf(1, text, sizeof text - 1);
    DONE();
    CALL("write.zero_length", write, WANT_OK, fd, text, 0);
    in_buf(1, text, 0);
    DONE();
    CALL("write.fault", write, EFAULT, fd, 1, 16);
    want_status(1, "in", "COPY_FAULT");
    DONE();
    CALL("write.badf", write, EBADF, 999, text, 4);
    in_buf(1, text, 4);
    DONE();
    CASE("lseek.set", lseek, WANT_OK, fd, 0, SEEK_SET);
    CASE("lseek.end", lseek, WANT_OK, fd, 0, SEEK_END);
    CASE("lseek.cur_negative", lseek, EINVAL, fd, -4096, SEEK_CUR);
    CASE("lseek.bad_whence", lseek, EINVAL, fd, 0, 7);
    CASE("lseek.rewind", lseek, WANT_OK, fd, 0, SEEK_SET);
    memset(buffer, 0, sizeof buffer);
    long got = CALL("read.text", read, WANT_OK, fd, buffer, sizeof buffer);
    if (got > 0)
        out_buf(1, buffer, (size_t)got);
    DONE();
    CALL("read.end_of_file", read, WANT_OK, fd, buffer, sizeof buffer);
    DONE();
    CASE("read.badf", read, EBADF, 999, buffer, 8);
    CALL("read.fault_at_eof", read, WANT_OK, fd, 1, 8);
    why("at end of file read returns 0 without touching the bad buffer");
    DONE();
    lseek((int)fd, 0, SEEK_SET);
    CALL("read.fault_data", read, EFAULT, fd, 1, 8);
    DONE();

    CALL("pwrite64.offset", pwrite64, WANT_OK, fd, "PWRITE", 6, 100);
    in_buf(1, "PWRITE", 6);
    DONE();
    memset(buffer, 0, sizeof buffer);
    got = CALL("pread64.offset", pread64, WANT_OK, fd, buffer, 6, 100);
    if (got > 0)
        out_buf(1, buffer, (size_t)got);
    DONE();
    CASE("pread64.negative", pread64, EINVAL, fd, buffer, 6, -1);
    CALL("pwrite64.badf", pwrite64, EBADF, 999, "x", 1, 0);
    in_buf(1, "x", 1);
    DONE();

    struct iovec out[3] = {{(void *)"VEC-ONE-", 8}, {(void *)"", 0}, {(void *)"VEC-TWO", 7}};
    CASE("lseek.vector", lseek, WANT_OK, fd, 0, SEEK_SET);
    CALL("writev.three", writev, WANT_OK, fd, out, 3);
    in_buf(1, out, sizeof out);
    in_key("arg1.iov[0].data", "VEC-ONE-", 8);
    in_key("arg1.iov[1].data", "", 0);
    in_key("arg1.iov[2].data", "VEC-TWO", 7);
    DONE();
    CALL("writev.too_many", writev, EINVAL, fd, out, 1025);
    want_status(1, "in", "INVALID_EXTENT");
    DONE();
    memset(buffer, 0, sizeof buffer);
    memset(second, 0, sizeof second);
    struct iovec in[2] = {{buffer, 4}, {second, 32}};
    CASE("lseek.readv", lseek, WANT_OK, fd, 0, SEEK_SET);
    got = CALL("readv.two", readv, WANT_OK, fd, in, 2);
    in_buf(1, in, sizeof in);
    out_key("arg1.iov[0].data", buffer, 4);
    out_key("arg1.iov[1].data", second, got > 4 ? (size_t)got - 4 : 0);
    DONE();
    struct iovec pin[2] = {{buffer, 3}, {second, 3}};
    got = CALL("preadv.offset", preadv, WANT_OK, fd, pin, 2, 8, 0);
    in_buf(1, pin, sizeof pin);
    out_key("arg1.iov[0].data", buffer, 3);
    out_key("arg1.iov[1].data", second, got > 3 ? (size_t)got - 3 : 0);
    DONE();
    struct iovec pout[1] = {{(void *)"PWV", 3}};
    CALL("pwritev.offset", pwritev, WANT_OK, fd, pout, 1, 200, 0);
    in_buf(1, pout, sizeof pout);
    in_key("arg1.iov[0].data", "PWV", 3);
    DONE();
    CALL("pwritev2.dsync", pwritev2, WANT_OK, fd, pout, 1, 210, 0, RWF_DSYNC);
    in_buf(1, pout, sizeof pout);
    in_key("arg1.iov[0].data", "PWV", 3);
    DONE();
    CALL("pwritev2.append_at_offset", pwritev2, WANT_OK, fd, pout, 1, -1, -1, RWF_APPEND);
    in_buf(1, pout, sizeof pout);
    in_key("arg1.iov[0].data", "PWV", 3);
    why("offset -1 writes at the current position");
    DONE();
    got = CALL("preadv2.hipri", preadv2, WANT_ANY, fd, pin, 2, 0, 0, RWF_HIPRI);
    in_buf(1, pin, sizeof pin);
    if (got >= 3) {
        out_key("arg1.iov[0].data", buffer, 3);
        out_key("arg1.iov[1].data", second, (size_t)got - 3);
    }
    why("RWF_HIPRI on a page-cache file is accepted or rejected (EOPNOTSUPP) by filesystem");
    DONE();
    CALL("preadv2.bad_flags", preadv2, EOPNOTSUPP, fd, pin, 2, 0, 0, 0x80000000);
    in_buf(1, pin, sizeof pin);
    DONE();

    CASE("fsync.file", fsync, WANT_OK, fd);
    CASE("fdatasync.file", fdatasync, WANT_OK, fd);
    CASE("fsync.badf", fsync, EBADF, 999);
    CASE("sync_file_range.write", sync_file_range, WANT_OK, fd, 0, 4096,
         SYNC_FILE_RANGE_WRITE);
    CASE("sync_file_range.bad_flags", sync_file_range, EINVAL, fd, 0, 4096, 0x100);
    CASE0("sync.all", sync, WANT_OK);
    CASE("syncfs.file", syncfs, WANT_OK, fd);
    CASE("syncfs.badf", syncfs, EBADF, 999);
    CASE("readahead.file", readahead, WANT_OK, fd, 0, 4096);
    CASE("readahead.badf", readahead, EBADF, 999, 0, 4096);
    CASE("fadvise64.sequential", fadvise64, WANT_OK, fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    CASE("fadvise64.bad_advice", fadvise64, EINVAL, fd, 0, 0, 99);
    CASE("fallocate.extend", fallocate, WANT_ANY, fd, 0, 0, 8192);
    CASE("fallocate.bad_mode", fallocate, EOPNOTSUPP, fd, 0x80, 0, 4096);
    CASE("ftruncate.shrink", ftruncate, WANT_OK, fd, 64);
    CASE("ftruncate.negative", ftruncate, EINVAL, fd, -1);
    CALL("truncate.path", truncate, WANT_OK, "io-rw", 32);
    in_str(0, "io-rw");
    DONE();
    CALL("truncate.missing", truncate, ENOENT, "io-missing", 0);
    in_str(0, "io-missing");
    DONE();

    // flock: exclusive, shared, nonblocking against a second open file description.
    long other = CALL("openat.lock", openat, WANT_OK, AT_FDCWD, "io-rw", O_RDONLY, 0);
    in_str(1, "io-rw");
    file_fd("OPEN", (int)other);
    DONE();
    CASE("flock.exclusive", flock, WANT_OK, fd, LOCK_EX);
    CASE("flock.conflict_nonblock", flock, EWOULDBLOCK, other, LOCK_SH | LOCK_NB);
    CASE("flock.unlock", flock, WANT_OK, fd, LOCK_UN);
    CASE("flock.bad_operation", flock, EINVAL, fd, 0x40);
    CASE("close.lock", close, WANT_OK, other);

    // sendfile and copy_file_range between two private files.
    long target = CALL("openat.copy_target", openat, WANT_OK, AT_FDCWD, "io-copy",
                       O_CREAT | O_RDWR | O_TRUNC, 0600);
    in_str(1, "io-copy");
    file_fd("OPEN", (int)target);
    DONE();
    off_t offset = 2;
    CALL("sendfile.offset", sendfile, WANT_OK, target, fd, &offset, 8);
    in_buf(2, &(off_t){2}, sizeof(off_t));
    out_buf(2, &offset, sizeof offset);
    DONE();
    CALL("sendfile.null_offset", sendfile, WANT_OK, target, fd, NULL, 4);
    want_status(2, "any", "NULL_POINTER");
    DONE();
    CASE("sendfile.badf", sendfile, EBADF, 999, fd, NULL, 4);
    loff_t in_offset = 0, out_offset = 100;
    CALL("copy_file_range.offsets", copy_file_range, WANT_OK, fd, &in_offset, target, &out_offset,
         8, 0);
    in_buf(1, &(loff_t){0}, sizeof(loff_t));
    in_buf(3, &(loff_t){100}, sizeof(loff_t));
    out_buf(1, &in_offset, sizeof in_offset);
    out_buf(3, &out_offset, sizeof out_offset);
    DONE();
    CALL("copy_file_range.bad_flags", copy_file_range, EINVAL, fd, NULL, target, NULL, 8, 1);
    want_status(1, "in", "NULL_POINTER");
    want_status(3, "in", "NULL_POINTER");
    DONE();
    CASE("close.copy_target", close, WANT_OK, target);
    CASE("close.rw", close, WANT_OK, fd);
}

static void descriptor_cases(void)
{
    long fd = CALL("openat.dup_source", openat, WANT_OK, AT_FDCWD, "io-dup",
                   O_CREAT | O_RDWR | O_TRUNC, 0600);
    in_str(1, "io-dup");
    file_fd("OPEN", (int)fd);
    DONE();
    long copy = CASE("dup.plain", dup, WANT_OK, fd);
    CASE("dup.badf", dup, EBADF, 999);
    CASE("dup2.onto", dup2, WANT_OK, fd, 40);
    CASE("dup2.same", dup2, WANT_OK, fd, fd);
    CASE("dup2.badf", dup2, EBADF, 999, 41);
    CASE("dup3.cloexec", dup3, WANT_OK, fd, 41, O_CLOEXEC);
    CASE("dup3.same", dup3, EINVAL, fd, fd, 0);
    CASE("dup3.bad_flags", dup3, EINVAL, fd, 42, O_RDWR);

    // fcntl commands: plain integers, and the struct ones the recorder decodes.
    CASE("fcntl.getfd", fcntl, WANT_OK, fd, F_GETFD, 0);
    CASE("fcntl.setfd", fcntl, WANT_OK, fd, F_SETFD, FD_CLOEXEC);
    CASE("fcntl.getfl", fcntl, WANT_OK, fd, F_GETFL, 0);
    CASE("fcntl.setfl", fcntl, WANT_OK, fd, F_SETFL, O_APPEND | O_NONBLOCK);
    CASE("fcntl.dupfd", fcntl, WANT_OK, fd, F_DUPFD, 50);
    CASE("fcntl.dupfd_cloexec", fcntl, WANT_OK, fd, F_DUPFD_CLOEXEC, 60);
    CASE("fcntl.getown", fcntl, WANT_OK, fd, F_GETOWN, 0);
    CASE("fcntl.setsig", fcntl, WANT_OK, fd, F_SETSIG, SIGUSR1);
    CASE("fcntl.getsig", fcntl, WANT_OK, fd, F_GETSIG, 0);
    CASE("fcntl.getlease", fcntl, WANT_OK, fd, F_GETLEASE, 0);
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 16};
    CALL("fcntl.setlk", fcntl, WANT_OK, fd, F_SETLK, &lock);
    in_buf(2, &lock, sizeof lock);
    DONE();
    struct flock probe = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 8};
    struct flock probe_in = probe;
    CALL("fcntl.getlk", fcntl, WANT_OK, fd, F_GETLK, &probe);
    in_buf(2, &probe_in, sizeof probe_in);
    out_buf(2, &probe, sizeof probe);
    DONE();
    struct flock ofd = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_start = 32, .l_len = 8};
    CALL("fcntl.ofd_setlk", fcntl, WANT_OK, fd, F_OFD_SETLK, &ofd);
    in_buf(2, &ofd, sizeof ofd);
    DONE();
    struct f_owner_ex owner;
    memset(&owner, 0, sizeof owner);
    CALL("fcntl.getown_ex", fcntl, WANT_OK, fd, F_GETOWN_EX, &owner);
    out_buf(2, &owner, sizeof owner);
    DONE();
    struct f_owner_ex set_owner = {.type = F_OWNER_PID, .pid = getpid()};
    CALL("fcntl.setown_ex", fcntl, WANT_OK, fd, F_SETOWN_EX, &set_owner);
    in_buf(2, &set_owner, sizeof set_owner);
    volatile_case();
    DONE();
    uint64_t hint = 0;
    CALL("fcntl.get_rw_hint", fcntl, WANT_OK, fd, F_GET_RW_HINT, &hint);
    out_buf(2, &hint, sizeof hint);
    DONE();
    CALL("fcntl.setlk_fault", fcntl, EFAULT, fd, F_SETLK, 1);
    want_status(2, "in", "COPY_FAULT");
    DONE();
    CALL("fcntl.unknown", fcntl, EINVAL, fd, 0x7fff, 0);
    want_key_status("fcntl.unknown_selector", "NO_DECODER");
    why("an unknown command is recorded as an explicit selector gap");
    DONE();
    CASE("fcntl.badf", fcntl, EBADF, 999, F_GETFD, 0);

    // Pipe size and seals on descriptors that support them.
    long memfd = CALL("memfd_create.sealing", memfd_create, WANT_OK, "ant-memfd",
                      MFD_CLOEXEC | MFD_ALLOW_SEALING);
    in_str(0, "ant-memfd");
    DONE();
    CASE("fcntl.add_seals", fcntl, WANT_OK, memfd, F_ADD_SEALS, F_SEAL_SHRINK);
    CASE("fcntl.get_seals", fcntl, WANT_OK, memfd, F_GET_SEALS, 0);
    CALL("memfd_create.bad_flags", memfd_create, EINVAL, "ant-memfd", 0x80000000);
    in_str(0, "ant-memfd");
    DONE();
    char long_name[300];
    memset(long_name, 'n', sizeof long_name - 1);
    long_name[sizeof long_name - 1] = 0;
    CALL("memfd_create.long_name", memfd_create, EINVAL, long_name, 0);
    want_status(0, "in", "INVALID_EXTENT");
    why("a name longer than the kernel limit is rejected; the recorder stops at the same limit");
    DONE();

    CASE("close.memfd", close, WANT_OK, memfd);
    CASE("close.dup", close, WANT_OK, copy);
    CASE("close_range.above", close_range, WANT_OK, 40, 70, 0);
    CASE("close_range.cloexec", close_range, WANT_OK, 100, ~0U, CLOSE_RANGE_CLOEXEC);
    CASE("close_range.bad_order", close_range, EINVAL, 70, 40, 0);
    CASE("close_range.bad_flags", close_range, EINVAL, 40, 70, 0x80);
    CASE("close.dup_source", close, WANT_OK, fd);
}

static void random_cases(void)
{
    unsigned char bytes[16];

    memset(bytes, 0, sizeof bytes);
    long got = CALL("getrandom.plain", getrandom, WANT_OK, bytes, sizeof bytes, 0);
    if (got > 0)
        out_buf(0, bytes, (size_t)got);
    volatile_case();
    DONE();
    got = CALL("getrandom.nonblock", getrandom, WANT_OK, bytes, 8, GRND_NONBLOCK);
    if (got > 0)
        out_buf(0, bytes, (size_t)got);
    volatile_case();
    DONE();
    got = CALL("getrandom.insecure", getrandom, WANT_OK, bytes, 4, GRND_INSECURE);
    if (got > 0)
        out_buf(0, bytes, (size_t)got);
    volatile_case();
    DONE();
    CASE("getrandom.zero_length", getrandom, WANT_OK, bytes, 0, 0);
    CASE("getrandom.insecure_and_random", getrandom, EINVAL, bytes, 4,
         GRND_INSECURE | GRND_RANDOM);
    CASE("getrandom.bad_flags", getrandom, EINVAL, bytes, 4, 0x80);
    CASE("getrandom.fault", getrandom, EFAULT, 1, 4, 0);
}

void area_file_io(void)
{
    random_cases();
    open_cases();
    read_write_cases();
    descriptor_cases();
}
