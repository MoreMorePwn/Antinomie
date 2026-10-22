// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// xattr_splice.c — extended attributes and pipe splicing.
//
// Slots: setxattr lsetxattr fsetxattr getxattr lgetxattr fgetxattr listxattr
// llistxattr flistxattr removexattr lremovexattr fremovexattr splice tee
// vmsplice.
#include "areas.h"

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/xattr.h>

#ifndef XATTR_CREATE
#define XATTR_CREATE 0x1
#endif
#ifndef XATTR_REPLACE
#define XATTR_REPLACE 0x2
#endif
#ifndef SPLICE_F_MOVE
#define SPLICE_F_MOVE 0x01
#endif
#ifndef SPLICE_F_NONBLOCK
#define SPLICE_F_NONBLOCK 0x02
#endif
#ifndef SPLICE_F_MORE
#define SPLICE_F_MORE 0x04
#endif
#ifndef SPLICE_F_GIFT
#define SPLICE_F_GIFT 0x08
#endif

static const char value_one[] = "VALUE-ONE";
static const char value_two[] = "VALUE-TWO-LONGER";

static void make_file(const char *name, size_t len, unsigned seed)
{
    char data[256];
    int fd = open(name, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        ora_fail("xattr_splice setup: create file");
        return;
    }
    pattern(data, len, seed);
    if (write(fd, data, len) != (ssize_t)len)
        ora_fail("xattr_splice setup: write file");
    close(fd);
}

// Empty a pipe through libc (not a traced case of this area).
static void drain(int fd)
{
    char sink[256];
    while (read(fd, sink, sizeof sink) > 0)
        ;
}

static void set_cases(long fd)
{
    static char big[16];
    pattern(big, sizeof big, 3);

    CALL("setxattr.create", setxattr, WANT_OK, "xs-file", "user.ant", value_one,
         sizeof value_one - 1, XATTR_CREATE);
    in_str(0, "xs-file");
    in_str(1, "user.ant");
    in_buf(2, value_one, sizeof value_one - 1);
    DONE();
    CALL("setxattr.create_exists", setxattr, EEXIST, "xs-file", "user.ant", value_one,
         sizeof value_one - 1, XATTR_CREATE);
    in_str(0, "xs-file");
    in_str(1, "user.ant");
    in_buf(2, value_one, sizeof value_one - 1);
    DONE();
    CALL("setxattr.replace", setxattr, WANT_OK, "xs-file", "user.ant", value_two,
         sizeof value_two - 1, XATTR_REPLACE);
    in_str(0, "xs-file");
    in_str(1, "user.ant");
    in_buf(2, value_two, sizeof value_two - 1);
    DONE();
    CALL("setxattr.replace_missing", setxattr, ENODATA, "xs-file", "user.none", value_one,
         sizeof value_one - 1, XATTR_REPLACE);
    in_str(0, "xs-file");
    in_str(1, "user.none");
    in_buf(2, value_one, sizeof value_one - 1);
    DONE();
    CALL("setxattr.empty_value", setxattr, WANT_OK, "xs-file", "user.empty", NULL, 0, 0);
    in_str(0, "xs-file");
    in_str(1, "user.empty");
    want_status(2, "in", "NULL_POINTER");
    why("a NULL value with size 0 stores an empty attribute");
    DONE();
    CALL("setxattr.bad_flags", setxattr, EINVAL, "xs-file", "user.ant", value_one,
         sizeof value_one - 1, 0x4);
    in_str(0, "xs-file");
    in_str(1, "user.ant");
    in_buf(2, value_one, sizeof value_one - 1);
    DONE();
    CALL("setxattr.too_large", setxattr, E2BIG, "xs-file", "user.big", big, 65537, 0);
    in_str(0, "xs-file");
    in_str(1, "user.big");
    want_status(2, "in", "INVALID_EXTENT");
    why("a value above XATTR_SIZE_MAX is refused before it is read; nothing is copied");
    DONE();
    CALL("setxattr.unknown_namespace", setxattr, EOPNOTSUPP, "xs-file", "ant.unknown",
         value_one, sizeof value_one - 1, 0);
    in_str(0, "xs-file");
    in_str(1, "ant.unknown");
    in_buf(2, value_one, sizeof value_one - 1);
    DONE();
    CALL("setxattr.trusted", setxattr, EPERM, "xs-file", "trusted.ant", value_one,
         sizeof value_one - 1, 0);
    in_str(0, "xs-file");
    in_str(1, "trusted.ant");
    in_buf(2, value_one, sizeof value_one - 1);
    why("trusted.* needs CAP_SYS_ADMIN: refused for UID 1000 (the root group can set it)");
    DONE();
    CALL("setxattr.empty_name", setxattr, ERANGE, "xs-file", "", value_one,
         sizeof value_one - 1, 0);
    in_str(0, "xs-file");
    in_str(1, "");
    in_buf(2, value_one, sizeof value_one - 1);
    DONE();
    CALL("setxattr.missing", setxattr, ENOENT, "xs-missing", "user.ant", value_one,
         sizeof value_one - 1, 0);
    in_str(0, "xs-missing");
    in_str(1, "user.ant");
    in_buf(2, value_one, sizeof value_one - 1);
    DONE();
    CALL("setxattr.bad_name", setxattr, EFAULT, "xs-file", 1, value_one,
         sizeof value_one - 1, 0);
    in_str(0, "xs-file");
    want_status(1, "in", "COPY_FAULT");
    in_buf(2, value_one, sizeof value_one - 1);
    DONE();

    CALL("lsetxattr.file", lsetxattr, WANT_OK, "xs-file", "user.lset", value_one,
         sizeof value_one - 1, 0);
    in_str(0, "xs-file");
    in_str(1, "user.lset");
    in_buf(2, value_one, sizeof value_one - 1);
    DONE();
    CALL("lsetxattr.symlink_user", lsetxattr, EPERM, "xs-link", "user.ant", value_one,
         sizeof value_one - 1, 0);
    in_str(0, "xs-link");
    in_str(1, "user.ant");
    in_buf(2, value_one, sizeof value_one - 1);
    why("user.* attributes exist only on regular files and directories: writes on a link are EPERM");
    DONE();

    CALL("fsetxattr.fd", fsetxattr, WANT_OK, fd, "user.fset", value_two, sizeof value_two - 1,
         XATTR_CREATE);
    in_str(1, "user.fset");
    in_buf(2, value_two, sizeof value_two - 1);
    DONE();
    CALL("fsetxattr.badf", fsetxattr, EBADF, 999, "user.fset", value_two, sizeof value_two - 1,
         0);
    in_str(1, "user.fset");
    in_buf(2, value_two, sizeof value_two - 1);
    DONE();
}

static void get_cases(long fd)
{
    char buffer[128];
    char long_name[300];
    long got;

    memset(buffer, 0, sizeof buffer);
    got = CALL("getxattr.value", getxattr, WANT_OK, "xs-file", "user.ant", buffer,
               sizeof buffer);
    in_str(0, "xs-file");
    in_str(1, "user.ant");
    out_buf(2, buffer, got > 0 ? (size_t)got : 0);
    DONE();
    CALL("getxattr.size_query_null", getxattr, WANT_OK, "xs-file", "user.ant", NULL, 0);
    in_str(0, "xs-file");
    in_str(1, "user.ant");
    want_status(2, "out", "NULL_POINTER");
    why("size 0 returns the value length; the output extent is empty at a NULL address");
    DONE();
    CALL("getxattr.size_query_buffer", getxattr, WANT_OK, "xs-file", "user.ant", buffer, 0);
    in_str(0, "xs-file");
    in_str(1, "user.ant");
    out_buf(2, buffer, 0);
    DONE();
    CALL("getxattr.too_small", getxattr, ERANGE, "xs-file", "user.ant", buffer, 4);
    in_str(0, "xs-file");
    in_str(1, "user.ant");
    DONE();
    CALL("getxattr.missing", getxattr, ENODATA, "xs-file", "user.none", buffer, sizeof buffer);
    in_str(0, "xs-file");
    in_str(1, "user.none");
    DONE();
    got = CALL("getxattr.empty_value", getxattr, WANT_OK, "xs-file", "user.empty", buffer,
               sizeof buffer);
    in_str(0, "xs-file");
    in_str(1, "user.empty");
    out_buf(2, buffer, 0);
    DONE();
    memset(long_name, 'n', sizeof long_name - 1);
    memcpy(long_name, "user.", 5);
    long_name[sizeof long_name - 1] = 0;
    CALL("getxattr.long_name", getxattr, ERANGE, "xs-file", long_name, buffer, sizeof buffer);
    in_str(0, "xs-file");
    want_status(1, "in", "INVALID_EXTENT");
    why("a name longer than XATTR_NAME_MAX is refused; the recorder stops at the same limit");
    DONE();
    CALL("getxattr.bad_buffer", getxattr, EFAULT, "xs-file", "user.ant", 1, sizeof buffer);
    in_str(0, "xs-file");
    in_str(1, "user.ant");
    why("the value cannot be copied to an unmapped buffer; no output is recorded");
    DONE();

    memset(buffer, 0, sizeof buffer);
    got = CALL("lgetxattr.file", lgetxattr, WANT_OK, "xs-file", "user.lset", buffer,
               sizeof buffer);
    in_str(0, "xs-file");
    in_str(1, "user.lset");
    out_buf(2, buffer, got > 0 ? (size_t)got : 0);
    DONE();
    CALL("lgetxattr.symlink_user", lgetxattr, ENODATA, "xs-link", "user.ant", buffer,
         sizeof buffer);
    in_str(0, "xs-link");
    in_str(1, "user.ant");
    why("reading user.* on a link is ENODATA (writing it is EPERM)");
    DONE();

    memset(buffer, 0, sizeof buffer);
    got = CALL("fgetxattr.fd", fgetxattr, WANT_OK, fd, "user.fset", buffer, sizeof buffer);
    in_str(1, "user.fset");
    out_buf(2, buffer, got > 0 ? (size_t)got : 0);
    DONE();
    CALL("fgetxattr.badf", fgetxattr, EBADF, 999, "user.fset", buffer, sizeof buffer);
    in_str(1, "user.fset");
    DONE();
}

static void list_remove_cases(long fd)
{
    char buffer[512];
    long got;

    memset(buffer, 0, sizeof buffer);
    got = CALL("listxattr.full", listxattr, WANT_OK, "xs-file", buffer, sizeof buffer);
    in_str(0, "xs-file");
    out_buf(1, buffer, got > 0 ? (size_t)got : 0);
    why("NUL-separated names; an LSM may add security.* entries, described as seen");
    DONE();
    CALL("listxattr.size_query_null", listxattr, WANT_OK, "xs-file", NULL, 0);
    in_str(0, "xs-file");
    want_status(1, "out", "NULL_POINTER");
    DONE();
    CALL("listxattr.too_small", listxattr, ERANGE, "xs-file", buffer, 2);
    in_str(0, "xs-file");
    DONE();
    CALL("listxattr.missing", listxattr, ENOENT, "xs-missing", buffer, sizeof buffer);
    in_str(0, "xs-missing");
    DONE();
    memset(buffer, 0, sizeof buffer);
    got = CALL("llistxattr.symlink", llistxattr, WANT_OK, "xs-link", buffer, sizeof buffer);
    in_str(0, "xs-link");
    out_buf(1, buffer, got > 0 ? (size_t)got : 0);
    why("the link itself carries no user.* names; the list is usually empty");
    DONE();
    memset(buffer, 0, sizeof buffer);
    got = CALL("flistxattr.fd", flistxattr, WANT_OK, fd, buffer, sizeof buffer);
    out_buf(1, buffer, got > 0 ? (size_t)got : 0);
    DONE();
    CASE("flistxattr.badf", flistxattr, EBADF, 999, buffer, sizeof buffer);

    CALL("removexattr.existing", removexattr, WANT_OK, "xs-file", "user.empty");
    in_str(0, "xs-file");
    in_str(1, "user.empty");
    DONE();
    CALL("removexattr.missing", removexattr, ENODATA, "xs-file", "user.empty");
    in_str(0, "xs-file");
    in_str(1, "user.empty");
    DONE();
    CALL("removexattr.missing_path", removexattr, ENOENT, "xs-missing", "user.ant");
    in_str(0, "xs-missing");
    in_str(1, "user.ant");
    DONE();
    CALL("lremovexattr.file", lremovexattr, WANT_OK, "xs-file", "user.lset");
    in_str(0, "xs-file");
    in_str(1, "user.lset");
    DONE();
    CALL("lremovexattr.symlink_user", lremovexattr, EPERM, "xs-link", "user.ant");
    in_str(0, "xs-link");
    in_str(1, "user.ant");
    DONE();
    CALL("fremovexattr.fd", fremovexattr, WANT_OK, fd, "user.fset");
    in_str(1, "user.fset");
    DONE();
    CALL("fremovexattr.badf", fremovexattr, EBADF, 999, "user.fset");
    in_str(1, "user.fset");
    DONE();
    CALL("fremovexattr.last", fremovexattr, WANT_OK, fd, "user.ant");
    in_str(1, "user.ant");
    DONE();
}

static void splice_cases(int p1[2], int p2[2], long fd, long other)
{
    loff_t off, off_before;

    off = off_before = 4;
    CALL("splice.file_to_pipe_offset", splice, WANT_OK, fd, &off, p1[1], NULL, 16, 0);
    in_buf(1, &off_before, sizeof off_before);
    out_buf(1, &off, sizeof off);
    want_status(3, "any", "NULL_POINTER");
    DONE();
    off = off_before = 100;
    CALL("splice.pipe_to_file_offset", splice, WANT_OK, p1[0], NULL, fd, &off, 16, SPLICE_F_MORE);
    want_status(1, "any", "NULL_POINTER");
    in_buf(3, &off_before, sizeof off_before);
    out_buf(3, &off, sizeof off);
    DONE();
    lseek((int)fd, 0, SEEK_SET);
    CALL("splice.file_position", splice, WANT_OK, fd, NULL, p1[1], NULL, 8, SPLICE_F_MOVE);
    want_status(1, "any", "NULL_POINTER");
    want_status(3, "any", "NULL_POINTER");
    why("NULL offsets use and advance the file position");
    DONE();
    CALL("splice.pipe_to_pipe", splice, WANT_OK, p1[0], NULL, p2[1], NULL, 8, SPLICE_F_NONBLOCK);
    want_status(1, "any", "NULL_POINTER");
    want_status(3, "any", "NULL_POINTER");
    DONE();
    drain(p2[0]);
    CALL("splice.empty_nonblock", splice, EAGAIN, p1[0], NULL, p2[1], NULL, 8,
         SPLICE_F_NONBLOCK);
    want_status(1, "in", "NULL_POINTER");
    want_status(3, "in", "NULL_POINTER");
    why("the source pipe is empty: SPLICE_F_NONBLOCK returns instead of waiting");
    DONE();
    off = off_before = 0;
    CALL("splice.offset_on_pipe", splice, ESPIPE, p1[0], &off, fd, NULL, 8, 0);
    in_buf(1, &off_before, sizeof off_before);
    want_status(3, "in", "NULL_POINTER");
    DONE();
    CALL("splice.no_pipe", splice, EINVAL, fd, NULL, other, NULL, 8, 0);
    want_status(1, "in", "NULL_POINTER");
    want_status(3, "in", "NULL_POINTER");
    why("neither end is a pipe");
    DONE();
    CALL("splice.badf", splice, EBADF, 999, NULL, p1[1], NULL, 8, 0);
    want_status(1, "in", "NULL_POINTER");
    want_status(3, "in", "NULL_POINTER");
    DONE();
    off = off_before = -1;
    CALL("splice.negative_offset", splice, EINVAL, fd, &off, p1[1], NULL, 8, 0);
    in_buf(1, &off_before, sizeof off_before);
    want_status(3, "in", "NULL_POINTER");
    DONE();
    CALL("splice.offset_fault", splice, EFAULT, fd, 1, p1[1], NULL, 8, 0);
    want_status(1, "in", "COPY_FAULT");
    want_status(3, "in", "NULL_POINTER");
    DONE();
    CALL("splice.bad_flags", splice, EINVAL, fd, NULL, p1[1], NULL, 8, 0x80);
    want_status(1, "in", "NULL_POINTER");
    want_status(3, "in", "NULL_POINTER");
    DONE();
    drain(p1[0]);
}

static void tee_cases(int p1[2], int p2[2], long fd)
{
    static const char data[] = "TEE-DATA";
    if (write(p1[1], data, 8) != 8)
        ora_fail("xattr_splice: fill pipe for tee");
    CASE("tee.pipe_to_pipe", tee, WANT_OK, p1[0], p2[1], 8, SPLICE_F_NONBLOCK);
    CASE("tee.zero_length", tee, WANT_OK, p1[0], p2[1], 0, 0);
    CASE("tee.same_pipe", tee, EINVAL, p1[0], p1[1], 8, SPLICE_F_NONBLOCK);
    CASE("tee.not_pipe", tee, EINVAL, fd, p2[1], 8, SPLICE_F_NONBLOCK);
    CASE("tee.badf", tee, EBADF, 999, p2[1], 8, SPLICE_F_NONBLOCK);
    CASE("tee.wrong_direction", tee, EBADF, p1[1], p2[1], 8, SPLICE_F_NONBLOCK);
    CASE("tee.bad_flags", tee, EINVAL, p1[0], p2[1], 8, 0x80);
    drain(p1[0]);
    drain(p2[0]);
    CASE("tee.empty_nonblock", tee, EAGAIN, p1[0], p2[1], 8, SPLICE_F_NONBLOCK);
}

static void vmsplice_cases(int p1[2], long fd)
{
    static const char one[] = "VMSPLICE-", two[] = "PAYLOAD";
    static char gift[64] __attribute__((aligned(64)));
    char target[12], before[12];

    struct iovec out[2] = {{(void *)one, 9}, {(void *)two, 7}};
    CALL("vmsplice.to_pipe", vmsplice, WANT_OK, p1[1], out, 2, 0);
    in_buf(1, out, sizeof out);
    in_key("arg1.iov[0].data", one, 9);
    in_key("arg1.iov[1].data", two, 7);
    DONE();
    drain(p1[0]);
    pattern(gift, sizeof gift, 11);
    struct iovec g[1] = {{gift, sizeof gift}};
    CALL("vmsplice.gift", vmsplice, WANT_OK, p1[1], g, 1, SPLICE_F_GIFT | SPLICE_F_NONBLOCK);
    in_buf(1, g, sizeof g);
    in_key("arg1.iov[0].data", gift, sizeof gift);
    DONE();
    drain(p1[0]);

    if (write(p1[1], "FROM-PIPE-12", 12) != 12)
        ora_fail("xattr_splice: fill pipe for vmsplice");
    pattern(target, sizeof target, 5);
    memcpy(before, target, sizeof before);
    struct iovec in[1] = {{target, sizeof target}};
    CALL("vmsplice.from_pipe", vmsplice, WANT_OK, p1[0], in, 1, SPLICE_F_NONBLOCK);
    in_buf(1, in, sizeof in);
    in_key("arg1.iov[0].data", before, sizeof before);
    why("on a read end vmsplice copies into the vector; the recorder treats the vector as "
        "input and records the bytes before the call");
    DONE();
    CALL("vmsplice.from_empty_nonblock", vmsplice, EAGAIN, p1[0], in, 1, SPLICE_F_NONBLOCK);
    in_buf(1, in, sizeof in);
    in_key("arg1.iov[0].data", target, sizeof target);
    DONE();
    CALL("vmsplice.zero_segments", vmsplice, WANT_OK, p1[1], out, 0, 0);
    in_buf(1, out, 0);
    DONE();
    CALL("vmsplice.badf", vmsplice, EBADF, 999, out, 2, 0);
    in_buf(1, out, sizeof out);
    in_key("arg1.iov[0].data", one, 9);
    in_key("arg1.iov[1].data", two, 7);
    DONE();
    CALL("vmsplice.not_pipe", vmsplice, EBADF, fd, out, 2, 0);
    in_buf(1, out, sizeof out);
    in_key("arg1.iov[0].data", one, 9);
    in_key("arg1.iov[1].data", two, 7);
    why("a writable regular file is not a pipe");
    DONE();
    CALL("vmsplice.bad_flags", vmsplice, EINVAL, p1[1], out, 2, 0x80);
    in_buf(1, out, sizeof out);
    in_key("arg1.iov[0].data", one, 9);
    in_key("arg1.iov[1].data", two, 7);
    DONE();
    CALL("vmsplice.too_many", vmsplice, EINVAL, p1[1], out, 1025, 0);
    want_status(1, "in", "INVALID_EXTENT");
    DONE();
    CALL("vmsplice.iov_fault", vmsplice, EFAULT, p1[1], 1, 2, 0);
    want_status(1, "in", "COPY_FAULT");
    DONE();
    drain(p1[0]);
}

void area_xattr_splice(void)
{
    make_file("xs-file", 32, 1);
    make_file("xs-splice", 64, 2);
    make_file("xs-other", 16, 4);
    if (symlink("xs-file", "xs-link") != 0)
        ora_fail("xattr_splice setup: symlink");
    long fd = open("xs-file", O_RDWR | O_CLOEXEC);
    if (fd < 0)
        ora_fail("xattr_splice setup: open xs-file");

    set_cases(fd);
    get_cases(fd);
    list_remove_cases(fd);
    close((int)fd);

    int p1[2], p2[2];
    if (pipe2(p1, O_CLOEXEC | O_NONBLOCK) != 0 || pipe2(p2, O_CLOEXEC | O_NONBLOCK) != 0) {
        ora_fail("xattr_splice setup: pipes");
        return;
    }
    long data = open("xs-splice", O_RDWR | O_CLOEXEC);
    long other = open("xs-other", O_RDWR | O_CLOEXEC);
    if (data < 0 || other < 0)
        ora_fail("xattr_splice setup: open splice files");
    splice_cases(p1, p2, data, other);
    tee_cases(p1, p2, data);
    vmsplice_cases(p1, data);
    close(p1[0]);
    close(p1[1]);
    close(p2[0]);
    close(p2[1]);
    close((int)data);
    close((int)other);
    unlink("xs-link");
    unlink("xs-file");
    unlink("xs-splice");
    unlink("xs-other");
}
