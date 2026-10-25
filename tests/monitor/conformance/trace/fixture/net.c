// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// net.c — sockets: AF_UNIX (paths in work_dir, abstract names, autobind),
// and TCP/UDP over the IPv4 and IPv6 loopback only. Nothing leaves the guest.
//
// Slots: socket socketpair bind listen connect accept accept4 getsockname
// getpeername sendto recvfrom sendmsg recvmsg sendmmsg recvmmsg shutdown
// setsockopt getsockopt.
#include "areas.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>

_Static_assert(sizeof(struct msghdr) == 56, "x86-64 user_msghdr");
_Static_assert(sizeof(struct mmsghdr) == 64, "x86-64 mmsghdr");

static int np[2] = {-1, -1}; // a pipe: descriptors that are not sockets

static size_t smaller(size_t a, size_t b)
{
    return a < b ? a : b;
}

static socklen_t unix_path(struct sockaddr_un *addr, const char *path)
{
    memset(addr, 0, sizeof *addr);
    addr->sun_family = AF_UNIX;
    snprintf(addr->sun_path, sizeof addr->sun_path, "%s", path);
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(addr->sun_path) + 1);
}

static socklen_t unix_abstract(struct sockaddr_un *addr, const char *name)
{
    size_t len = strlen(name);
    memset(addr, 0, sizeof *addr);
    addr->sun_family = AF_UNIX;
    memcpy(addr->sun_path + 1, name, len);
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + len);
}

// Wait (bounded) until fd has something to read / room to write.
static int ready(int fd, short events)
{
    struct pollfd p = {fd, events, 0};
    return poll(&p, 1, 2000) == 1;
}

// getsockopt: the optlen it was given, and on success the optlen and the
// option bytes it wrote. The caller adds notes and calls DONE().
static long sockget(const char *label, long want, int fd, int level, int name, void *value,
                    int capacity)
{
    int len = capacity;
    const int given = capacity;
    if (capacity > 0)
        memset(value, 0, (size_t)capacity);
    long result = CALL(label, getsockopt, want, fd, level, name, value, &len);
    in_buf(4, &given, sizeof given);
    if (result == 0) {
        out_buf(4, &len, sizeof len);
        out_buf(3, value, len > 0 ? (size_t)len : 0);
    }
    return result;
}

static long sockset(const char *label, long want, int fd, int level, int name, const void *value,
                    int len)
{
    long result = CALL(label, setsockopt, want, fd, level, name, value, len);
    in_buf(3, value, (size_t)len);
    return result;
}

// getsockname/getpeername with a capacity: the recorder keeps the capacity at
// entry and the length and (capacity-bounded) address at exit.
static long sockname(const char *label, int peer, long want, int fd, void *addr, int capacity,
                     int *length)
{
    int len = capacity;
    const int given = capacity;
    long result = CALLNR(label, peer ? "getpeername" : "getsockname",
                         peer ? SYS_getpeername : SYS_getsockname, want, fd, addr, &len);
    in_key("arg2.socklen.capacity", &given, sizeof given);
    if (result == 0) {
        out_key("arg2.socklen.output", &len, sizeof len);
        out_key("arg1.sockaddr", addr, smaller((size_t)len, (size_t)given));
    }
    if (length)
        *length = len;
    return result;
}

// The entry fields of a message being sent: iovec array, each element's
// bytes, the name and the control block. sendmsg records a NULL name or
// control as NULL_POINTER; sendmmsg records them only when present.
static void sent_message(const char *prefix, const struct msghdr *msg, int nulls)
{
    char key[96];
    snprintf(key, sizeof key, "%s.iov", prefix);
    in_key(key, msg->msg_iov, msg->msg_iovlen * sizeof(struct iovec));
    for (size_t i = 0; i < msg->msg_iovlen; i++) {
        snprintf(key, sizeof key, "%s.iov[%zu].data", prefix, i);
        in_key(key, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
    }
    snprintf(key, sizeof key, "%s.name", prefix);
    if (msg->msg_name)
        in_key(key, msg->msg_name, msg->msg_namelen);
    else if (nulls)
        want_key_status(key, "NULL_POINTER");
    snprintf(key, sizeof key, "%s.control", prefix);
    if (msg->msg_control)
        in_key(key, msg->msg_control, msg->msg_controllen);
    else if (nulls)
        want_key_status(key, "NULL_POINTER");
}

// The exit fields of a received message: the bytes each element got (in
// order, up to `transferred`), the name and the control block bounded by
// both the capacity given and the length the kernel wrote back.
static void received_message(const char *prefix, const struct msghdr *after,
                             const struct msghdr *before, size_t transferred, int nulls)
{
    char key[96];
    for (size_t i = 0; i < before->msg_iovlen; i++) {
        size_t size = smaller(before->msg_iov[i].iov_len, transferred);
        snprintf(key, sizeof key, "%s.iov[%zu].data", prefix, i);
        out_key(key, before->msg_iov[i].iov_base, size);
        transferred -= size;
    }
    snprintf(key, sizeof key, "%s.name", prefix);
    if (before->msg_name)
        out_key(key, before->msg_name,
                smaller(sizeof(struct sockaddr_storage),
                        smaller(before->msg_namelen, after->msg_namelen)));
    else if (nulls)
        want_key_status(key, "NULL_POINTER");
    snprintf(key, sizeof key, "%s.control", prefix);
    if (before->msg_control)
        out_key(key, before->msg_control,
                smaller(before->msg_controllen, after->msg_controllen));
    else if (nulls)
        want_key_status(key, "NULL_POINTER");
}

static void socket_cases(void)
{
    int sv[2] = {-1, -1}, value = 0;
    long fd;

    fd = CASE("socket.unix_seqpacket", socket, WANT_OK, AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd >= 0)
        close((int)fd);
    fd = CALL("socket.unix_raw", socket, WANT_OK, AF_UNIX, SOCK_RAW | SOCK_CLOEXEC, 0);
    why("AF_UNIX accepts SOCK_RAW for compatibility and makes it a datagram socket");
    DONE();
    if (fd >= 0) {
        sockget("getsockopt.so_type_unix_raw", WANT_OK, (int)fd, SOL_SOCKET, SO_TYPE, &value,
                sizeof value);
        why("SOCK_DGRAM");
        DONE();
        close((int)fd);
    }
    fd = CASE("socket.inet_tcp_explicit", socket, WANT_OK, AF_INET, SOCK_STREAM | SOCK_CLOEXEC,
              IPPROTO_TCP);
    if (fd >= 0) {
        sockget("getsockopt.so_domain", WANT_OK, (int)fd, SOL_SOCKET, SO_DOMAIN, &value,
                sizeof value);
        DONE();
        close((int)fd);
    }
    CASE("socket.unix_rdm", socket, ESOCKTNOSUPPORT, AF_UNIX, SOCK_RDM, 0);
    CASE("socket.unix_bad_protocol", socket, EPROTONOSUPPORT, AF_UNIX, SOCK_STREAM, 6);
    CASE("socket.bad_family", socket, EAFNOSUPPORT, 4000, SOCK_STREAM, 0);
    CASE("socket.bad_type", socket, EINVAL, AF_INET, 15, 0);
    CASE("socket.bad_flags", socket, EINVAL, AF_INET, SOCK_STREAM | 0x40000000, 0);
    CALL("socket.raw_icmp", socket, EPERM, AF_INET, SOCK_RAW, IPPROTO_ICMP);
    why("raw IP sockets need CAP_NET_RAW: EPERM as UID 1000 (root.c can succeed)");
    DONE();

    CALL("socketpair.unix_stream", socketpair, WANT_OK, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0,
         sv);
    out_buf(3, sv, sizeof sv);
    DONE();
    close(sv[0]);
    close(sv[1]);
    CALL("socketpair.unix_seqpacket", socketpair, WANT_OK, AF_UNIX,
         SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sv);
    out_buf(3, sv, sizeof sv);
    DONE();
    close(sv[0]);
    close(sv[1]);
    CALL("socketpair.inet", socketpair, EOPNOTSUPP, AF_INET, SOCK_STREAM, 0, sv);
    why("TCP has no socketpair: no output field on failure");
    DONE();
    CASE("socketpair.bad_flags", socketpair, EINVAL, AF_UNIX, SOCK_STREAM | 0x40000000, 0, sv);
    CASE("socketpair.fault", socketpair, EFAULT, AF_UNIX, SOCK_STREAM, 0, 1);
}

static void unix_stream_cases(void)
{
    static const char stream_text[] = "STREAM-DATA-0123";
    struct sockaddr_un addr, peer, quiet_addr;
    socklen_t alen = unix_path(&addr, "net-stream");
    socklen_t qlen = unix_abstract(&quiet_addr, "antinomie-conformance-listen");
    char buffer[128];
    int value = 0;
    long got;

    long listener = CASE("socket.unix_stream", socket, WANT_OK, AF_UNIX,
                         SOCK_STREAM | SOCK_CLOEXEC, 0);
    CALL("bind.unix_path", bind, WANT_OK, listener, &addr, alen);
    in_buf(1, &addr, alen);
    why("a relative path: the socket file is created in work_dir");
    DONE();
    int extra = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CALL("bind.unix_path_in_use", bind, EADDRINUSE, extra, &addr, alen);
    in_buf(1, &addr, alen);
    DONE();
    CASE("listen.unbound", listen, EINVAL, extra, 1);
    CASE("listen.unix", listen, WANT_OK, listener, 4);
    sockget("getsockopt.so_acceptconn", WANT_OK, (int)listener, SOL_SOCKET, SO_ACCEPTCONN, &value,
            sizeof value);
    DONE();

    long client = CASE("socket.unix_stream_client", socket, WANT_OK, AF_UNIX,
                       SOCK_STREAM | SOCK_CLOEXEC, 0);
    CALL("connect.unix_path", connect, WANT_OK, client, &addr, alen);
    in_buf(1, &addr, alen);
    DONE();
    memset(&peer, 0, sizeof peer);
    socklen_t plen = sizeof peer;
    const socklen_t pcap = plen;
    long server = CALL("accept.unix_address", accept, WANT_OK, listener, &peer, &plen);
    in_key("address.capacity", &pcap, sizeof pcap);
    out_key("address.length", &plen, sizeof plen);
    out_key("address.data", &peer, smaller(plen, pcap));
    why("the client never bound a name: only its family comes back");
    DONE();

    int second = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CALL("connect.unix_backlog", connect, WANT_OK, second, &addr, alen);
    in_buf(1, &addr, alen);
    DONE();
    long second_server = CASE("accept.null_address", accept, WANT_OK, listener, NULL, NULL);
    int third = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (connect(third, (struct sockaddr *)&addr, alen) != 0)
        ora_fail("net: connect the third client");
    memset(&peer, 0, sizeof peer);
    int cap4 = sizeof peer, len4 = cap4;
    long third_server = CALL("accept4.flags_address", accept4, WANT_OK, listener, &peer, &len4,
                             SOCK_CLOEXEC | SOCK_NONBLOCK);
    in_key("arg2.socklen.capacity", &cap4, sizeof cap4);
    out_key("arg2.socklen.output", &len4, sizeof len4);
    out_key("arg1.sockaddr", &peer, smaller((size_t)len4, (size_t)cap4));
    DONE();
    int fourth = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (connect(fourth, (struct sockaddr *)&addr, alen) != 0)
        ora_fail("net: connect the fourth client");
    CALL("accept4.length_fault", accept4, EFAULT, listener, &peer, 1, 0);
    want_status(2, "in", "COPY_FAULT");
    why("the pending connection is accepted, then storing its address faults: it is dropped");
    DONE();
    CASE("accept4.bad_flags", accept4, EINVAL, listener, NULL, NULL, 1);
    CASE("accept.not_listening", accept, EINVAL, client, NULL, NULL);
    CASE("accept.notsock", accept, ENOTSOCK, np[0], NULL, NULL);
    CASE("accept.badf", accept, EBADF, 999, NULL, NULL);

    int quiet = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CALL("bind.unix_abstract", bind, WANT_OK, quiet, &quiet_addr, qlen);
    in_buf(1, &quiet_addr, qlen);
    why("an abstract name: no file is created");
    DONE();
    CASE("listen.unix_abstract", listen, WANT_OK, quiet, 1);
    CASE("accept.nonblocking_empty", accept, EAGAIN, quiet, NULL, NULL);
    CASE("listen.badf", listen, EBADF, 999, 1);
    CASE("listen.notsock", listen, ENOTSOCK, np[0], 1);

    // Names.
    memset(&peer, 0, sizeof peer);
    sockname("getsockname.unix_accepted", 0, WANT_OK, (int)server, &peer, sizeof peer, NULL);
    why("an accepted socket reports the listener's name");
    DONE();
    memset(&peer, 0, sizeof peer);
    sockname("getpeername.unix_path", 1, WANT_OK, (int)client, &peer, sizeof peer, NULL);
    DONE();
    memset(&peer, 0, sizeof peer);
    sockname("getpeername.unix_unnamed", 1, WANT_OK, (int)server, &peer, sizeof peer, NULL);
    DONE();
    memset(&peer, 0, sizeof peer);
    sockname("getsockname.short_capacity", 0, WANT_OK, (int)listener, &peer, 4, NULL);
    why("the name is cut to the capacity; the length reports the full size");
    DONE();
    int negative = -1;
    CALL("getsockname.negative_capacity", getsockname, EINVAL, listener, &peer, &negative);
    want_status(2, "in", "INVALID_EXTENT");
    DONE();
    CALL("getsockname.length_fault", getsockname, EFAULT, listener, &peer, 1);
    want_status(2, "in", "COPY_FAULT");
    DONE();
    int capacity = sizeof peer;
    CALL("getsockname.null_address", getsockname, EFAULT, listener, NULL, &capacity);
    why("a NULL address with room for a name faults; the recorder captures nothing for it");
    DONE();
    memset(&peer, 0, sizeof peer);
    sockname("getpeername.not_connected", 1, ENOTCONN, (int)listener, &peer, sizeof peer, NULL);
    DONE();
    sockname("getsockname.notsock", 0, ENOTSOCK, np[0], &peer, sizeof peer, NULL);
    DONE();
    sockname("getpeername.badf", 1, EBADF, 999, &peer, sizeof peer, NULL);
    DONE();

    // Options.
    value = 65536;
    sockset("setsockopt.so_rcvbuf", WANT_OK, (int)client, SOL_SOCKET, SO_RCVBUF, &value,
            sizeof value);
    DONE();
    sockget("getsockopt.so_rcvbuf", WANT_OK, (int)client, SOL_SOCKET, SO_RCVBUF, &value,
            sizeof value);
    why("the kernel doubles the requested size for its bookkeeping");
    DONE();
    sockget("getsockopt.so_type", WANT_OK, (int)server, SOL_SOCKET, SO_TYPE, &value, sizeof value);
    DONE();
    struct ucred cred;
    sockget("getsockopt.so_peercred", WANT_OK, (int)server, SOL_SOCKET, SO_PEERCRED, &cred,
            sizeof cred);
    volatile_case();
    why("the connecting process's pid, uid and gid");
    DONE();
    sockget("getsockopt.so_error", WANT_OK, (int)client, SOL_SOCKET, SO_ERROR, &value,
            sizeof value);
    DONE();
    sockget("getsockopt.short_optlen", WANT_OK, (int)server, SOL_SOCKET, SO_TYPE, &value, 2);
    why("an int option cut to the 2 bytes asked for");
    DONE();
    sockget("getsockopt.negative_optlen", EINVAL, (int)server, SOL_SOCKET, SO_TYPE, &value, -1);
    DONE();
    CALL("getsockopt.optlen_fault", getsockopt, EFAULT, server, SOL_SOCKET, SO_TYPE, &value, 1);
    want_status(4, "in", "COPY_FAULT");
    DONE();
    sockget("getsockopt.notsock", ENOTSOCK, np[0], SOL_SOCKET, SO_TYPE, &value, sizeof value);
    DONE();
    value = 1;
    sockset("setsockopt.badf", EBADF, 999, SOL_SOCKET, SO_RCVBUF, &value, sizeof value);
    DONE();

    // Data, with and without peeking, and an empty nonblocking receive.
    CALL("sendto.stream_connected", sendto, WANT_OK, client, stream_text, 16, 0, NULL, 0);
    in_buf(1, stream_text, 16);
    DONE();
    int queued = -1;
    CALL("ioctl.socket_inq", ioctl, WANT_OK, server, FIONREAD, &queued);
    want_status(2, "in", "NO_DECODER");
    why("socket requests are not decoded: the output is an explicit gap");
    DONE();
    memset(buffer, 0, sizeof buffer);
    got = CALL("recvfrom.peek", recvfrom, WANT_OK, server, buffer, sizeof buffer, MSG_PEEK, NULL,
               NULL);
    if (got > 0)
        out_buf(1, buffer, (size_t)got);
    why("MSG_PEEK leaves the bytes queued");
    DONE();
    memset(buffer, 0, sizeof buffer);
    got = CALL("recvfrom.null_address", recvfrom, WANT_OK, server, buffer, sizeof buffer, 0,
               NULL, NULL);
    if (got > 0)
        out_buf(1, buffer, (size_t)got);
    why("no source address asked for: only the data is captured");
    DONE();
    CASE("recvfrom.dontwait_empty", recvfrom, EAGAIN, server, buffer, sizeof buffer, MSG_DONTWAIT,
         NULL, NULL);
    CASE("recvfrom.badf", recvfrom, EBADF, 999, buffer, sizeof buffer, 0, NULL, NULL);
    CASE("recvfrom.notsock", recvfrom, ENOTSOCK, np[0], buffer, sizeof buffer, MSG_DONTWAIT, NULL,
         NULL);

    // SCM_RIGHTS: pass the pipe's write end over the stream.
    char d0[] = "RIGHTS-", d1[] = "ONE-", d2[] = "FD";
    struct iovec iov[3] = {{d0, 7}, {d1, 4}, {d2, 2}};
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } control, rcontrol;
    struct msghdr msg, before;
    memset(&control, 0, sizeof control);
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = iov;
    msg.msg_iovlen = 3;
    msg.msg_control = control.buf;
    msg.msg_controllen = sizeof control.buf;
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &np[1], sizeof(int));
    CALL("sendmsg.scm_rights", sendmsg, WANT_OK, client, &msg, 0);
    in_key("arg1.msghdr", &msg, sizeof msg);
    sent_message("arg1.msghdr", &msg, 1);
    why("three iovec elements and one descriptor; no name on a connected stream");
    DONE();
    char r0[8], r1[32];
    struct iovec riov[2] = {{r0, sizeof r0}, {r1, sizeof r1}};
    memset(r0, 0, sizeof r0);
    memset(r1, 0, sizeof r1);
    memset(&rcontrol, 0, sizeof rcontrol);
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = riov;
    msg.msg_iovlen = 2;
    msg.msg_control = rcontrol.buf;
    msg.msg_controllen = sizeof rcontrol.buf;
    memcpy(&before, &msg, sizeof msg);
    got = CALL("recvmsg.scm_rights", recvmsg, WANT_OK, server, &msg, MSG_CMSG_CLOEXEC);
    in_key("arg1.msghdr", &before, sizeof before);
    in_key("arg1.msghdr.iov", riov, sizeof riov);
    out_key("arg1.msghdr.output", &msg, sizeof msg);
    received_message("arg1.msghdr", &msg, &before, got > 0 ? (size_t)got : 0, 1);
    why("the control block carries the number of the new descriptor");
    DONE();
    cm = CMSG_FIRSTHDR(&msg);
    if (got > 0 && cm && cm->cmsg_type == SCM_RIGHTS) {
        int passed;
        memcpy(&passed, CMSG_DATA(cm), sizeof passed);
        close(passed);
    } else {
        ora_fail("net: no descriptor received");
    }
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = riov;
    msg.msg_iovlen = 2;
    memcpy(&before, &msg, sizeof msg);
    CALL("recvmsg.dontwait_empty", recvmsg, EAGAIN, server, &msg, MSG_DONTWAIT);
    in_key("arg1.msghdr", &before, sizeof before);
    in_key("arg1.msghdr.iov", riov, sizeof riov);
    DONE();
    CALL("recvmsg.fault", recvmsg, EFAULT, server, 1, 0);
    want_status(1, "in", "COPY_FAULT");
    DONE();

    struct iovec single = {d0, 7};
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = &single;
    msg.msg_iovlen = 1;
    CALL("sendmsg.not_connected", sendmsg, ENOTCONN, extra, &msg, MSG_NOSIGNAL);
    in_key("arg1.msghdr", &msg, sizeof msg);
    sent_message("arg1.msghdr", &msg, 1);
    DONE();
    msg.msg_iovlen = 2000;
    CALL("sendmsg.too_many_iov", sendmsg, EMSGSIZE, client, &msg, 0);
    in_key("arg1.msghdr", &msg, sizeof msg);
    want_key_status("arg1.msghdr.iov", "INVALID_EXTENT");
    want_key_status("arg1.msghdr.name", "NULL_POINTER");
    want_key_status("arg1.msghdr.control", "NULL_POINTER");
    why("more than UIO_MAXIOV elements: refused, the element bytes are not read");
    DONE();
    int bad_fd = 999;
    memset(&control, 0, sizeof control);
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = &single;
    msg.msg_iovlen = 1;
    msg.msg_control = control.buf;
    msg.msg_controllen = sizeof control.buf;
    cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &bad_fd, sizeof bad_fd);
    CALL("sendmsg.bad_rights", sendmsg, EBADF, client, &msg, 0);
    in_key("arg1.msghdr", &msg, sizeof msg);
    sent_message("arg1.msghdr", &msg, 1);
    why("the descriptor to pass is not open");
    DONE();
    CALL("sendmsg.fault", sendmsg, EFAULT, client, 1, 0);
    want_status(1, "in", "COPY_FAULT");
    DONE();

    // Shutdown: end of stream, then writing after it.
    CASE("shutdown.unix_write", shutdown, WANT_OK, client, SHUT_WR);
    CALL("recvfrom.eof", recvfrom, WANT_OK, server, buffer, sizeof buffer, 0, NULL, NULL);
    why("the peer shut down its write side: 0 bytes, no data field");
    DONE();
    CALL("sendto.epipe", sendto, EPIPE, client, stream_text, 4, MSG_NOSIGNAL, NULL, 0);
    in_buf(1, stream_text, 4);
    why("writing after SHUT_WR; MSG_NOSIGNAL keeps SIGPIPE away");
    DONE();
    CASE("shutdown.unix_both", shutdown, WANT_OK, server, SHUT_RDWR);
    CASE("shutdown.bad_how", shutdown, EINVAL, server, 7);
    CASE("shutdown.notsock", shutdown, ENOTSOCK, np[0], SHUT_RD);
    CASE("shutdown.badf", shutdown, EBADF, 999, SHUT_RD);

    close(extra);
    close(second);
    close(third);
    close(fourth);
    close(quiet);
    close((int)second_server);
    if (third_server >= 0)
        close((int)third_server);
    close((int)server);
    close((int)client);
    close((int)listener);
    unlink("net-stream");
}

static void unix_dgram_cases(void)
{
    static const char one[] = "DGRAM-ONE";
    char rpath[300], buffer[128];
    struct sockaddr_un raddr, saddr, from, missing, autoaddr;
    socklen_t rlen = unix_path(&raddr, work_path(rpath, sizeof rpath, "net-dgram"));
    socklen_t slen = unix_abstract(&saddr, "antinomie-conformance-dgram");
    socklen_t mlen = unix_path(&missing, "net-missing");
    int value = 0;
    long got;

    long receiver = CASE("socket.unix_dgram", socket, WANT_OK, AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC,
                         0);
    CALL("bind.unix_dgram_absolute", bind, WANT_OK, receiver, &raddr, rlen);
    in_buf(1, &raddr, rlen);
    DONE();
    CASE("listen.dgram", listen, EOPNOTSUPP, receiver, 1);
    long sender = CASE("socket.unix_dgram_sender", socket, WANT_OK, AF_UNIX,
                       SOCK_DGRAM | SOCK_CLOEXEC, 0);
    CALL("bind.unix_abstract_sender", bind, WANT_OK, sender, &saddr, slen);
    in_buf(1, &saddr, slen);
    DONE();
    int other = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    CALL("bind.unix_abstract_in_use", bind, EADDRINUSE, other, &saddr, slen);
    in_buf(1, &saddr, slen);
    DONE();
    memset(&autoaddr, 0, sizeof autoaddr);
    autoaddr.sun_family = AF_UNIX;
    CALL("bind.unix_autobind", bind, WANT_OK, other, &autoaddr, sizeof(sa_family_t));
    in_buf(1, &autoaddr, sizeof(sa_family_t));
    why("only the family: the kernel picks an abstract name");
    DONE();
    memset(&from, 0, sizeof from);
    sockname("getsockname.unix_autobind", 0, WANT_OK, other, &from, sizeof from, NULL);
    volatile_case();
    why("five hex digits chosen by the kernel");
    DONE();
    CALL("bind.null_empty", bind, EINVAL, other, NULL, 0);
    want_status(1, "in", "NULL_POINTER");
    DONE();
    CALL("bind.fault", bind, EFAULT, other, 1, sizeof(struct sockaddr_un));
    want_status(1, "in", "COPY_FAULT");
    DONE();
    CALL("bind.too_long", bind, EINVAL, other, &raddr, 200);
    want_status(1, "in", "INVALID_EXTENT");
    why("longer than sockaddr_storage: refused before anything is read");
    DONE();
    CALL("bind.badf", bind, EBADF, 999, &raddr, rlen);
    in_buf(1, &raddr, rlen);
    DONE();
    CALL("bind.notsock", bind, ENOTSOCK, np[0], &raddr, rlen);
    in_buf(1, &raddr, rlen);
    DONE();

    CALL("sendto.unix_dgram_address", sendto, WANT_OK, sender, one, 9, 0, &raddr, rlen);
    in_buf(1, one, 9);
    in_buf(4, &raddr, rlen);
    DONE();
    memset(buffer, 0, sizeof buffer);
    memset(&from, 0, sizeof from);
    socklen_t flen = sizeof from;
    const socklen_t fcap = flen;
    got = CALL("recvfrom.unix_dgram_address", recvfrom, WANT_OK, receiver, buffer, sizeof buffer,
               MSG_DONTWAIT, &from, &flen);
    in_key("address.capacity", &fcap, sizeof fcap);
    if (got > 0)
        out_buf(1, buffer, (size_t)got);
    out_key("address.length", &flen, sizeof flen);
    out_key("address.data", &from, smaller(flen, fcap));
    why("the sender's abstract name comes back");
    DONE();
    CALL("sendto.zero_length", sendto, WANT_OK, sender, NULL, 0, 0, &raddr, rlen);
    want_status(1, "in", "NULL_POINTER");
    in_buf(4, &raddr, rlen);
    why("an empty datagram from a NULL buffer");
    DONE();
    memset(&from, 0, sizeof from);
    flen = fcap;
    CALL("recvfrom.zero_length", recvfrom, WANT_OK, receiver, buffer, sizeof buffer, MSG_DONTWAIT,
         &from, &flen);
    in_key("address.capacity", &fcap, sizeof fcap);
    out_key("address.length", &flen, sizeof flen);
    out_key("address.data", &from, smaller(flen, fcap));
    why("0 bytes: no data field, the source address still comes back");
    DONE();
    CALL("sendto.missing_path", sendto, ENOENT, sender, one, 9, 0, &missing, mlen);
    in_buf(1, one, 9);
    in_buf(4, &missing, mlen);
    DONE();
    CALL("sendto.no_destination", sendto, ENOTCONN, receiver, one, 9, 0, NULL, 0);
    in_buf(1, one, 9);
    why("an unconnected datagram socket and no address");
    DONE();
    CALL("sendto.buffer_fault", sendto, EFAULT, sender, 1, 8, 0, &raddr, rlen);
    want_status(1, "in", "COPY_FAULT");
    in_buf(4, &raddr, rlen);
    DONE();
    CALL("sendto.address_too_long", sendto, EINVAL, sender, one, 9, 0, &raddr, 200);
    in_buf(1, one, 9);
    want_status(4, "in", "INVALID_EXTENT");
    DONE();
    CALL("sendto.notsock", sendto, ENOTSOCK, np[1], one, 9, 0, &raddr, rlen);
    in_buf(1, one, 9);
    in_buf(4, &raddr, rlen);
    DONE();
    if (sendto((int)sender, "LOST", 4, 0, (struct sockaddr *)&raddr, rlen) != 4)
        ora_fail("net: queue the datagram for recvfrom.length_fault");
    CALL("recvfrom.length_fault", recvfrom, EFAULT, receiver, buffer, sizeof buffer, MSG_DONTWAIT,
         &from, 1);
    want_status(5, "in", "COPY_FAULT");
    why("the datagram is consumed, then storing the address length faults");
    DONE();

    // SCM_CREDENTIALS with a destination name and two iovec elements.
    value = 1;
    sockset("setsockopt.so_passcred", WANT_OK, (int)receiver, SOL_SOCKET, SO_PASSCRED, &value,
            sizeof value);
    DONE();
    sockget("getsockopt.so_passcred", WANT_OK, (int)receiver, SOL_SOCKET, SO_PASSCRED, &value,
            sizeof value);
    DONE();
    struct ucred cred = {.pid = getpid(), .uid = getuid(), .gid = getgid()};
    union {
        char buf[CMSG_SPACE(sizeof(struct ucred))];
        struct cmsghdr align;
    } control;
    union {
        char buf[64];
        struct cmsghdr align;
    } rcontrol;
    char c0[] = "CRED-", c1[] = "PASSING";
    struct iovec iov[2] = {{c0, 5}, {c1, 7}};
    struct msghdr msg, before;
    memset(&control, 0, sizeof control);
    memset(&msg, 0, sizeof msg);
    msg.msg_name = &raddr;
    msg.msg_namelen = rlen;
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    msg.msg_control = control.buf;
    msg.msg_controllen = sizeof control.buf;
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_CREDENTIALS;
    cm->cmsg_len = CMSG_LEN(sizeof cred);
    memcpy(CMSG_DATA(cm), &cred, sizeof cred);
    CALL("sendmsg.scm_credentials", sendmsg, WANT_OK, sender, &msg, 0);
    in_key("arg1.msghdr", &msg, sizeof msg);
    sent_message("arg1.msghdr", &msg, 1);
    volatile_case();
    why("the sender's own pid, uid and gid need no privilege");
    DONE();
    char r0[64];
    struct iovec riov[1] = {{r0, sizeof r0}};
    memset(r0, 0, sizeof r0);
    memset(&rcontrol, 0, sizeof rcontrol);
    memset(&from, 0, sizeof from);
    memset(&msg, 0, sizeof msg);
    msg.msg_name = &from;
    msg.msg_namelen = sizeof from;
    msg.msg_iov = riov;
    msg.msg_iovlen = 1;
    msg.msg_control = rcontrol.buf;
    msg.msg_controllen = sizeof rcontrol.buf;
    memcpy(&before, &msg, sizeof msg);
    got = CALL("recvmsg.scm_credentials", recvmsg, WANT_OK, receiver, &msg, MSG_DONTWAIT);
    in_key("arg1.msghdr", &before, sizeof before);
    in_key("arg1.msghdr.iov", riov, sizeof riov);
    out_key("arg1.msghdr.output", &msg, sizeof msg);
    received_message("arg1.msghdr", &msg, &before, got > 0 ? (size_t)got : 0, 1);
    volatile_case();
    why("the abstract source name and an SCM_CREDENTIALS block come back");
    DONE();
    memset(&from, 0, sizeof from);
    memset(&msg, 0, sizeof msg);
    msg.msg_name = &from;
    msg.msg_namelen = sizeof from;
    msg.msg_iov = riov;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
    memcpy(&before, &msg, sizeof msg);
    CALL("recvmsg.peek_empty", recvmsg, EAGAIN, receiver, &msg, MSG_PEEK | MSG_DONTWAIT);
    in_key("arg1.msghdr", &before, sizeof before);
    in_key("arg1.msghdr.iov", riov, sizeof riov);
    DONE();

    // Datagram association: connect, send without an address, dissolve.
    CALL("connect.unix_dgram", connect, WANT_OK, sender, &raddr, rlen);
    in_buf(1, &raddr, rlen);
    DONE();
    CALL("sendto.dgram_connected", sendto, WANT_OK, sender, one, 9, 0, NULL, 0);
    in_buf(1, one, 9);
    DONE();
    memset(buffer, 0, sizeof buffer);
    memset(&msg, 0, sizeof msg);
    struct iovec whole = {buffer, sizeof buffer};
    msg.msg_iov = &whole;
    msg.msg_iovlen = 1;
    memcpy(&before, &msg, sizeof msg);
    got = CALL("recvmsg.no_name_no_control", recvmsg, WANT_OK, receiver, &msg, MSG_DONTWAIT);
    in_key("arg1.msghdr", &before, sizeof before);
    in_key("arg1.msghdr.iov", &whole, sizeof whole);
    out_key("arg1.msghdr.output", &msg, sizeof msg);
    received_message("arg1.msghdr", &msg, &before, got > 0 ? (size_t)got : 0, 1);
    why("NULL name and control: recorded as NULL pointers at exit");
    DONE();
    struct sockaddr unspec;
    memset(&unspec, 0, sizeof unspec);
    unspec.sa_family = AF_UNSPEC;
    CALL("connect.af_unspec", connect, WANT_OK, sender, &unspec, sizeof unspec);
    in_buf(1, &unspec, sizeof unspec);
    why("AF_UNSPEC dissolves the datagram association");
    DONE();
    CALL("connect.missing_path", connect, ENOENT, sender, &missing, mlen);
    in_buf(1, &missing, mlen);
    DONE();
    int stream = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CALL("connect.wrong_type", connect, EPROTOTYPE, stream, &raddr, rlen);
    in_buf(1, &raddr, rlen);
    why("a stream socket cannot connect to a datagram socket's name");
    DONE();
    close(stream);
    CALL("connect.short_length", connect, EINVAL, sender, &raddr, 1);
    in_buf(1, &raddr, 1);
    DONE();
    CALL("connect.fault", connect, EFAULT, sender, 1, sizeof(struct sockaddr_un));
    want_status(1, "in", "COPY_FAULT");
    DONE();
    CALL("connect.badf", connect, EBADF, 999, &raddr, rlen);
    in_buf(1, &raddr, rlen);
    DONE();

    close(other);
    close((int)sender);
    close((int)receiver);
    unlink(rpath);
}

// One sendmmsg/recvmmsg element's keys.
static const char *mkey(char *out, size_t size, unsigned index, const char *what)
{
    snprintf(out, size, "arg1.mmsg.%u%s", index, what);
    return out;
}

static void sent_mmsg(const struct mmsghdr *vec_in, unsigned count)
{
    char key[64];
    for (unsigned i = 0; i < count; i++) {
        in_key(mkey(key, sizeof key, i, ".header"), &vec_in[i].msg_hdr, sizeof(struct msghdr));
        sent_message(mkey(key, sizeof key, i, ""), &vec_in[i].msg_hdr, 0);
    }
}

static void received_mmsg(const struct mmsghdr *vec, const struct mmsghdr *vec_in,
                          unsigned capacity, long got)
{
    char key[64], prefix[48];
    for (unsigned i = 0; i < capacity; i++) {
        in_key(mkey(key, sizeof key, i, ".header"), &vec_in[i].msg_hdr, sizeof(struct msghdr));
        in_key(mkey(key, sizeof key, i, ".iov"), vec_in[i].msg_hdr.msg_iov,
               vec_in[i].msg_hdr.msg_iovlen * sizeof(struct iovec));
    }
    for (unsigned i = 0; got > 0 && i < (unsigned long)got && i < capacity; i++) {
        out_key(mkey(key, sizeof key, i, ".header"), &vec[i], sizeof vec[i]);
        received_message(mkey(prefix, sizeof prefix, i, ""), &vec[i].msg_hdr,
                         &vec_in[i].msg_hdr, vec[i].msg_len, 0);
    }
}

static void mmsg_cases(void)
{
    int pair[2] = {-1, -1};
    char key[64];

    CALL("socketpair.unix_dgram", socketpair, WANT_OK, AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0,
         pair);
    out_buf(3, pair, sizeof pair);
    DONE();
    char a0[] = "MMSG-A0-", a1[] = "first", b0[] = "MMSG-B0-", b1[] = "second!";
    struct iovec ia[2] = {{a0, 8}, {a1, 5}}, ib[2] = {{b0, 8}, {b1, 7}};
    struct mmsghdr vec[2], vec_in[2];
    memset(vec, 0, sizeof vec);
    vec[0].msg_hdr.msg_iov = ia;
    vec[0].msg_hdr.msg_iovlen = 2;
    vec[1].msg_hdr.msg_iov = ib;
    vec[1].msg_hdr.msg_iovlen = 2;
    memcpy(vec_in, vec, sizeof vec);
    long sent = CALL("sendmmsg.unix_two", sendmmsg, WANT_OK, pair[0], vec, 2, 0);
    sent_mmsg(vec_in, 2);
    for (unsigned i = 0; sent > 0 && i < (unsigned long)sent && i < 2; i++)
        out_key(mkey(key, sizeof key, i, ".header"), &vec[i], sizeof vec[i]);
    why("two datagrams of two elements each; msg_len is written back per message");
    DONE();

    char rbuf[3][2][16];
    struct iovec riov[3][2];
    struct mmsghdr rvec[3], rvec_in[3];
    memset(rbuf, 0, sizeof rbuf);
    memset(rvec, 0, sizeof rvec);
    for (int i = 0; i < 3; i++) {
        riov[i][0].iov_base = rbuf[i][0];
        riov[i][0].iov_len = 8;
        riov[i][1].iov_base = rbuf[i][1];
        riov[i][1].iov_len = 16;
        rvec[i].msg_hdr.msg_iov = riov[i];
        rvec[i].msg_hdr.msg_iovlen = 2;
    }
    memcpy(rvec_in, rvec, sizeof rvec);
    long got = CALL("recvmmsg.unix_dontwait", recvmmsg, WANT_OK, pair[1], rvec, 3, MSG_DONTWAIT,
                    NULL);
    received_mmsg(rvec, rvec_in, 3, got);
    why("three slots, two datagrams queued: the empty third receive ends the call");
    DONE();

    if (send(pair[0], "TIMED", 5, 0) != 5)
        ora_fail("net: queue the datagram for recvmmsg.timeout");
    struct timespec limit = {1, 0}, limit_in = {1, 0};
    memset(rbuf, 0, sizeof rbuf);
    memcpy(rvec, rvec_in, sizeof rvec);
    got = CALL("recvmmsg.timeout", recvmmsg, WANT_OK, pair[1], rvec, 1, 0, &limit);
    received_mmsg(rvec, rvec_in, 1, got);
    in_buf(4, &limit_in, sizeof limit_in);
    out_any(4);
    volatile_case();
    why("a datagram is queued, so the call returns at once and writes back the unused time");
    DONE();
    memcpy(rvec, rvec_in, sizeof rvec);
    CALL("recvmmsg.empty_dontwait", recvmmsg, EAGAIN, pair[1], rvec, 1, MSG_DONTWAIT, NULL);
    received_mmsg(rvec, rvec_in, 1, -1);
    DONE();
    memcpy(rvec, rvec_in, sizeof rvec);
    CALL("recvmmsg.badf", recvmmsg, EBADF, 999, rvec, 1, 0, NULL);
    received_mmsg(rvec, rvec_in, 1, -1);
    DONE();
    CASE("sendmmsg.zero_vlen", sendmmsg, WANT_OK, pair[0], vec, 0, 0);
    CALL("sendmmsg.fault", sendmmsg, EFAULT, pair[0], 1, 1, 0);
    want_status(1, "in", "COPY_FAULT");
    DONE();
    memcpy(vec, vec_in, sizeof vec);
    CALL("sendmmsg.badf", sendmmsg, EBADF, 999, vec, 1, 0);
    sent_mmsg(vec_in, 1);
    DONE();
    close(pair[0]);
    close(pair[1]);
}

// TCP and UDP over 127.0.0.1. Options and argument checks that need no
// interface run first; traffic only when the loopback address can be bound.
static void inet4_cases(void)
{
    static const char tcp_text[] = "TCP-PAYLOAD";
    static const char udp_text[] = "UDP-DATAGRAM-0123456789-ABCDEFGHIJKLMNO";
    struct sockaddr_in lo, srv, peer, from, far, wrong;
    char buffer[128];
    int value = 1, len = 0;
    long got;

    memset(&lo, 0, sizeof lo);
    lo.sin_family = AF_INET;
    lo.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    long l4 = CASE("socket.inet_tcp", socket, WANT_OK, AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    value = 1;
    sockset("setsockopt.so_reuseaddr", WANT_OK, (int)l4, SOL_SOCKET, SO_REUSEADDR, &value,
            sizeof value);
    DONE();
    sockget("getsockopt.so_reuseaddr", WANT_OK, (int)l4, SOL_SOCKET, SO_REUSEADDR, &value,
            sizeof value);
    DONE();
    value = 1;
    sockset("setsockopt.ipv6_on_inet4", ENOPROTOOPT, (int)l4, IPPROTO_IPV6, IPV6_V6ONLY, &value,
            sizeof value);
    why("an IPv6 option on an IPv4 socket");
    DONE();
    int spare = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CALL("bind.inet_short_length", bind, EINVAL, spare, &lo, 8);
    in_buf(1, &lo, 8);
    DONE();
    memcpy(&wrong, &lo, sizeof lo);
    wrong.sin_family = AF_INET6;
    CALL("bind.inet_wrong_family", bind, EAFNOSUPPORT, spare, &wrong, sizeof wrong);
    in_buf(1, &wrong, sizeof wrong);
    why("the protocol rejects an AF_INET6 address on an AF_INET socket with EAFNOSUPPORT; "
        "AppArmor, the guest's major LSM as on Debian, leaves it to the protocol (SELinux "
        "would answer EINVAL first)");
    DONE();
    memset(&far, 0, sizeof far);
    far.sin_family = AF_INET;
    far.sin_addr.s_addr = htonl(0xc0000201); // 192.0.2.1, TEST-NET-1
    CALL("bind.inet_not_local", bind, EADDRNOTAVAIL, spare, &far, sizeof far);
    in_buf(1, &far, sizeof far);
    why("TEST-NET-1 is not a local address; nothing is sent");
    DONE();
    CALL("shutdown.tcp_not_connected", shutdown, ENOTCONN, spare, SHUT_RDWR);
    why("a TCP socket that never connected (the kernel still marks it shut down)");
    DONE();
    close(spare);
    long u2 = CASE("socket.inet_udp_sender", socket, WANT_OK, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC,
                   IPPROTO_UDP);
    value = 1;
    sockset("setsockopt.tcp_on_udp", ENOPROTOOPT, (int)u2, IPPROTO_TCP, TCP_NODELAY, &value,
            sizeof value);
    why("a TCP option on a UDP socket");
    DONE();

    long bound = CALL("bind.inet_loopback", bind, WANT_ANY, l4, &lo, sizeof lo);
    in_buf(1, &lo, sizeof lo);
    why("127.0.0.1 exists only while the loopback interface is up; the TCP and UDP traffic "
        "cases below run only when it is");
    DONE();
    if (bound != 0) {
        close((int)l4);
        close((int)u2);
        return;
    }
    CASE("listen.inet_tcp", listen, WANT_OK, l4, 8);
    memset(&srv, 0, sizeof srv);
    sockname("getsockname.inet_tcp", 0, WANT_OK, (int)l4, &srv, sizeof srv, NULL);
    volatile_case();
    why("the kernel picked the port");
    DONE();

    long c4 = CASE("socket.inet_tcp_nonblock", socket, WANT_OK, AF_INET,
                   SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    value = 1;
    sockset("setsockopt.tcp_nodelay", WANT_OK, (int)c4, IPPROTO_TCP, TCP_NODELAY, &value,
            sizeof value);
    DONE();
    sockget("getsockopt.tcp_nodelay", WANT_OK, (int)c4, IPPROTO_TCP, TCP_NODELAY, &value,
            sizeof value);
    DONE();
    CALL("connect.inet_nonblocking", connect, EINPROGRESS, c4, &srv, sizeof srv);
    in_buf(1, &srv, sizeof srv);
    volatile_case();
    why("a nonblocking connect returns before the handshake completes, even on loopback");
    DONE();
    if (!ready((int)c4, POLLOUT))
        ora_fail("net: the loopback handshake did not complete");
    sockget("getsockopt.so_error_connected", WANT_OK, (int)c4, SOL_SOCKET, SO_ERROR, &value,
            sizeof value);
    why("0: the handshake succeeded");
    DONE();
    CALL("connect.inet_completed", connect, WANT_OK, c4, &srv, sizeof srv);
    in_buf(1, &srv, sizeof srv);
    volatile_case();
    why("the first connect after the handshake completed reports success");
    DONE();
    CALL("connect.inet_isconn", connect, EISCONN, c4, &srv, sizeof srv);
    in_buf(1, &srv, sizeof srv);
    volatile_case();
    DONE();
    if (!ready((int)l4, POLLIN))
        ora_fail("net: no connection to accept");
    memset(&peer, 0, sizeof peer);
    int pcap = sizeof peer, plen = pcap;
    long s4 = CALL("accept4.inet_address", accept4, WANT_OK, l4, &peer, &plen, SOCK_CLOEXEC);
    in_key("arg2.socklen.capacity", &pcap, sizeof pcap);
    out_key("arg2.socklen.output", &plen, sizeof plen);
    out_key("arg1.sockaddr", &peer, smaller((size_t)plen, (size_t)pcap));
    volatile_case();
    DONE();
    memset(&peer, 0, sizeof peer);
    sockname("getpeername.inet_tcp", 1, WANT_OK, (int)c4, &peer, sizeof peer, NULL);
    volatile_case();
    DONE();
    CALL("sendto.tcp_connected", sendto, WANT_OK, c4, tcp_text, sizeof tcp_text - 1, 0, NULL, 0);
    in_buf(1, tcp_text, sizeof tcp_text - 1);
    DONE();
    if (!ready((int)s4, POLLIN))
        ora_fail("net: TCP data did not arrive");
    memset(buffer, 0, sizeof buffer);
    got = CALL("recvfrom.tcp_peek", recvfrom, WANT_OK, s4, buffer, sizeof buffer, MSG_PEEK, NULL,
               NULL);
    if (got > 0)
        out_buf(1, buffer, (size_t)got);
    DONE();
    memset(buffer, 0, sizeof buffer);
    memset(&from, 0, sizeof from);
    socklen_t flen = sizeof from;
    const socklen_t fcap = flen;
    got = CALL("recvfrom.tcp_address", recvfrom, WANT_OK, s4, buffer, sizeof buffer, 0, &from,
               &flen);
    in_key("address.capacity", &fcap, sizeof fcap);
    if (got > 0)
        out_buf(1, buffer, (size_t)got);
    out_key("address.length", &flen, sizeof flen);
    out_key("address.data", &from, smaller(flen, fcap));
    why("TCP reports no source address: the length comes back 0");
    DONE();
    CASE("recvfrom.tcp_dontwait", recvfrom, EAGAIN, s4, buffer, sizeof buffer, MSG_DONTWAIT, NULL,
         NULL);
    CASE("shutdown.tcp_write", shutdown, WANT_OK, c4, SHUT_WR);
    if (!ready((int)s4, POLLIN))
        ora_fail("net: TCP end of stream did not arrive");
    CALL("recvfrom.tcp_eof", recvfrom, WANT_OK, s4, buffer, sizeof buffer, 0, NULL, NULL);
    why("the peer shut down its write side: 0 bytes");
    DONE();
    CALL("sendto.tcp_epipe", sendto, EPIPE, c4, tcp_text, 4, MSG_NOSIGNAL, NULL, 0);
    in_buf(1, tcp_text, 4);
    DONE();

    // A bound port nobody listens on answers with a reset.
    int closed = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in refused;
    socklen_t rlen = sizeof refused;
    memset(&refused, 0, sizeof refused);
    if (closed < 0 || bind(closed, (struct sockaddr *)&lo, sizeof lo) != 0 ||
        getsockname(closed, (struct sockaddr *)&refused, &rlen) != 0) {
        ora_fail("net: bind the refusing port");
    } else {
        int caller = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        CALL("connect.inet_refused", connect, ECONNREFUSED, caller, &refused, sizeof refused);
        in_buf(1, &refused, sizeof refused);
        volatile_case();
        why("bound but not listening: loopback answers the SYN with a reset");
        DONE();
        close(caller);
    }
    if (closed >= 0)
        close(closed);

    // UDP: an addressed datagram truncated on receipt, a connected socket,
    // AF_UNSPEC, and sendmmsg/recvmmsg with names.
    long u1 = CASE("socket.inet_udp", socket, WANT_OK, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    CALL("bind.inet_udp", bind, WANT_OK, u1, &lo, sizeof lo);
    in_buf(1, &lo, sizeof lo);
    DONE();
    struct sockaddr_in a1;
    memset(&a1, 0, sizeof a1);
    sockname("getsockname.inet_udp", 0, WANT_OK, (int)u1, &a1, sizeof a1, &len);
    volatile_case();
    DONE();
    struct timeval bound_wait = {2, 0};
    setsockopt((int)u1, SOL_SOCKET, SO_RCVTIMEO, &bound_wait, sizeof bound_wait);
    CALL("sendto.udp_address", sendto, WANT_OK, u2, udp_text, sizeof udp_text - 1, 0, &a1,
         sizeof a1);
    in_buf(1, udp_text, sizeof udp_text - 1);
    in_buf(4, &a1, sizeof a1);
    volatile_case();
    DONE();
    memset(buffer, 0, sizeof buffer);
    memset(&from, 0, sizeof from);
    flen = fcap;
    got = CALL("recvfrom.udp_msg_trunc", recvfrom, WANT_OK, u1, buffer, 8, MSG_TRUNC, &from,
               &flen);
    in_key("address.capacity", &fcap, sizeof fcap);
    if (got > 0)
        out_buf(1, buffer, smaller((size_t)got, 8));
    out_key("address.length", &flen, sizeof flen);
    out_key("address.data", &from, smaller(flen, fcap));
    volatile_case();
    why("MSG_TRUNC returns the full datagram length; only 8 bytes are written");
    DONE();
    CALL("connect.inet_udp", connect, WANT_OK, u2, &a1, sizeof a1);
    in_buf(1, &a1, sizeof a1);
    volatile_case();
    DONE();
    CALL("sendto.udp_connected", sendto, WANT_OK, u2, udp_text, 13, 0, NULL, 0);
    in_buf(1, udp_text, 13);
    DONE();
    memset(buffer, 0, sizeof buffer);
    got = CALL("recvfrom.udp_connected", recvfrom, WANT_OK, u1, buffer, sizeof buffer, 0, NULL,
               NULL);
    if (got > 0)
        out_buf(1, buffer, (size_t)got);
    DONE();
    struct sockaddr unspec;
    memset(&unspec, 0, sizeof unspec);
    unspec.sa_family = AF_UNSPEC;
    CALL("connect.inet_af_unspec", connect, WANT_OK, u2, &unspec, sizeof unspec);
    in_buf(1, &unspec, sizeof unspec);
    why("AF_UNSPEC dissolves the UDP association");
    DONE();

    char m0[] = "UDP-MMSG-0", m1[] = "UDP-MMSG-1";
    struct iovec mi[2] = {{m0, 10}, {m1, 10}};
    struct mmsghdr vec[2], vec_in[2];
    char key[64];
    memset(vec, 0, sizeof vec);
    for (int i = 0; i < 2; i++) {
        vec[i].msg_hdr.msg_name = &a1;
        vec[i].msg_hdr.msg_namelen = sizeof a1;
        vec[i].msg_hdr.msg_iov = &mi[i];
        vec[i].msg_hdr.msg_iovlen = 1;
    }
    memcpy(vec_in, vec, sizeof vec);
    long sent = CALL("sendmmsg.udp_names", sendmmsg, WANT_OK, u2, vec, 2, 0);
    sent_mmsg(vec_in, 2);
    for (unsigned i = 0; sent > 0 && i < (unsigned long)sent && i < 2; i++)
        out_key(mkey(key, sizeof key, i, ".header"), &vec[i], sizeof vec[i]);
    volatile_case();
    why("each message names its destination");
    DONE();
    char rb[2][16];
    struct sockaddr_in names[2];
    struct iovec ri[2] = {{rb[0], sizeof rb[0]}, {rb[1], sizeof rb[1]}};
    struct mmsghdr rvec[2], rvec_in[2];
    memset(rb, 0, sizeof rb);
    memset(names, 0, sizeof names);
    memset(rvec, 0, sizeof rvec);
    for (int i = 0; i < 2; i++) {
        rvec[i].msg_hdr.msg_name = &names[i];
        rvec[i].msg_hdr.msg_namelen = sizeof names[i];
        rvec[i].msg_hdr.msg_iov = &ri[i];
        rvec[i].msg_hdr.msg_iovlen = 1;
    }
    memcpy(rvec_in, rvec, sizeof rvec);
    got = CALL("recvmmsg.udp_names", recvmmsg, WANT_OK, u1, rvec, 2, 0, NULL);
    received_mmsg(rvec, rvec_in, 2, got);
    volatile_case();
    why("blocking for both datagrams, bounded by a 2 s SO_RCVTIMEO");
    DONE();

    close((int)u1);
    close((int)u2);
    close((int)s4);
    close((int)c4);
    close((int)l4);
}

// TCP and UDP over ::1, when the IPv6 loopback address exists.
static void inet6_cases(void)
{
    struct sockaddr_in6 lo6, srv6, peer6, from6;
    char buffer[64];
    int value = 1;
    long got;

    memset(&lo6, 0, sizeof lo6);
    lo6.sin6_family = AF_INET6;
    lo6.sin6_addr = in6addr_loopback;
    long t6 = CASE("socket.inet6_tcp", socket, WANT_OK, AF_INET6, SOCK_STREAM | SOCK_CLOEXEC,
                   IPPROTO_TCP);
    value = 1;
    sockset("setsockopt.ipv6_v6only", WANT_OK, (int)t6, IPPROTO_IPV6, IPV6_V6ONLY, &value,
            sizeof value);
    DONE();
    sockget("getsockopt.ipv6_v6only", WANT_OK, (int)t6, IPPROTO_IPV6, IPV6_V6ONLY, &value,
            sizeof value);
    DONE();
    long bound = CALL("bind.inet6_loopback", bind, WANT_ANY, t6, &lo6, sizeof lo6);
    in_buf(1, &lo6, sizeof lo6);
    why("::1 exists only while the loopback interface is up with IPv6; the IPv6 traffic cases "
        "run only when it does");
    DONE();
    if (bound != 0) {
        close((int)t6);
        return;
    }
    value = 0;
    sockset("setsockopt.ipv6_v6only_bound", EINVAL, (int)t6, IPPROTO_IPV6, IPV6_V6ONLY, &value,
            sizeof value);
    why("IPV6_V6ONLY cannot change once the socket is bound");
    DONE();
    CASE("listen.inet6_tcp", listen, WANT_OK, t6, 2);
    memset(&srv6, 0, sizeof srv6);
    sockname("getsockname.inet6_tcp", 0, WANT_OK, (int)t6, &srv6, sizeof srv6, NULL);
    volatile_case();
    DONE();
    long c6 = CASE("socket.inet6_tcp_client", socket, WANT_OK, AF_INET6,
                   SOCK_STREAM | SOCK_CLOEXEC, 0);
    CALL("connect.inet6_loopback", connect, WANT_OK, c6, &srv6, sizeof srv6);
    in_buf(1, &srv6, sizeof srv6);
    volatile_case();
    why("a blocking connect over ::1 completes the handshake before returning");
    DONE();
    if (!ready((int)t6, POLLIN))
        ora_fail("net: no IPv6 connection to accept");
    memset(&peer6, 0, sizeof peer6);
    socklen_t plen = sizeof peer6;
    const socklen_t pcap = plen;
    long s6 = CALL("accept.inet6_address", accept, WANT_OK, t6, &peer6, &plen);
    in_key("address.capacity", &pcap, sizeof pcap);
    out_key("address.length", &plen, sizeof plen);
    out_key("address.data", &peer6, smaller(plen, pcap));
    volatile_case();
    DONE();

    long u6 = CASE("socket.inet6_udp", socket, WANT_OK, AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC,
                   IPPROTO_UDP);
    struct sockaddr_in6 self6;
    socklen_t slen = sizeof self6;
    memset(&self6, 0, sizeof self6);
    if (bind((int)u6, (struct sockaddr *)&lo6, sizeof lo6) != 0 ||
        getsockname((int)u6, (struct sockaddr *)&self6, &slen) != 0) {
        ora_fail("net: bind the IPv6 UDP socket");
    } else {
        CALL("sendto.inet6_self", sendto, WANT_OK, u6, "UDP6-SELF", 9, 0, &self6, sizeof self6);
        in_buf(1, "UDP6-SELF", 9);
        in_buf(4, &self6, sizeof self6);
        volatile_case();
        why("a datagram to its own ::1 port");
        DONE();
        if (!ready((int)u6, POLLIN))
            ora_fail("net: the IPv6 datagram did not arrive");
        memset(buffer, 0, sizeof buffer);
        memset(&from6, 0, sizeof from6);
        socklen_t flen = sizeof from6;
        const socklen_t fcap = flen;
        got = CALL("recvfrom.inet6_address", recvfrom, WANT_OK, u6, buffer, sizeof buffer,
                   MSG_DONTWAIT, &from6, &flen);
        in_key("address.capacity", &fcap, sizeof fcap);
        if (got > 0)
            out_buf(1, buffer, (size_t)got);
        out_key("address.length", &flen, sizeof flen);
        out_key("address.data", &from6, smaller(flen, fcap));
        volatile_case();
        DONE();
    }
    close((int)u6);
    close((int)s6);
    close((int)c6);
    close((int)t6);
}

void area_net(void)
{
    if (pipe2(np, O_CLOEXEC) != 0) {
        ora_fail("net: create the non-socket pipe");
        return;
    }
    socket_cases();
    unix_stream_cases();
    unix_dgram_cases();
    mmsg_cases();
    inet4_cases();
    inet6_cases();
    close(np[0]);
    close(np[1]);
}
