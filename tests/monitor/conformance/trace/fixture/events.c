// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// events.c — descriptors that wait and notify: pipes, readiness (poll,
// select, epoll), counters and timers, filesystem notification, ioctl,
// userfaultfd, pidfds and kcmp.
//
// Slots: pipe pipe2 poll ppoll select pselect6 epoll_create epoll_create1
// epoll_ctl epoll_wait epoll_pwait epoll_pwait2 eventfd eventfd2 signalfd
// signalfd4 timerfd_create timerfd_settime timerfd_gettime inotify_init
// inotify_init1 inotify_add_watch inotify_rm_watch fanotify_init
// fanotify_mark ioctl userfaultfd pidfd_open pidfd_getfd pidfd_send_signal
// kcmp.
//
// Child process index: 200 (the pidfd target).
#include "areas.h"

#include <fcntl.h>
#include <linux/kcmp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/fanotify.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>

#ifndef UFFD_USER_MODE_ONLY
#define UFFD_USER_MODE_ONLY 1
#endif
#ifndef PIDFD_NONBLOCK
#define PIDFD_NONBLOCK O_NONBLOCK
#endif
#ifndef PIDFD_THREAD
#define PIDFD_THREAD O_EXCL
#endif
#ifndef PIDFD_SIGNAL_THREAD
#define PIDFD_SIGNAL_THREAD (1UL << 0)
#endif
#ifndef PIDFD_SIGNAL_THREAD_GROUP
#define PIDFD_SIGNAL_THREAD_GROUP (1UL << 1)
#endif
#ifndef FAN_REPORT_FID
#define FAN_REPORT_FID 0x00000200
#endif
#ifndef TFD_TIMER_CANCEL_ON_SET
#define TFD_TIMER_CANCEL_ON_SET (1 << 1)
#endif

// The kernel's sigset_t is one 64-bit word (glibc's is 128 bytes), and its
// struct termios (what TCGETS writes) is 36 bytes (glibc's is 60).
typedef uint64_t ksigset;
struct ktermios {
    uint32_t c_iflag, c_oflag, c_cflag, c_lflag;
    uint8_t c_line, c_cc[19];
};
_Static_assert(sizeof(struct ktermios) == 36, "kernel termios layout");
_Static_assert(sizeof(struct epoll_event) == 12, "packed x86-64 epoll_event");
_Static_assert(sizeof(struct itimerspec) == 32, "itimerspec layout");

// pselect6's sixth argument.
struct sigset_pack {
    const ksigset *mask;
    size_t size;
};

static const ksigset usr2_mask = 1ULL << (SIGUSR2 - 1);
static const ksigset usr1_mask = 1ULL << (SIGUSR1 - 1);
static int rp[2] = {-1, -1}; // a pipe whose read end holds one byte
static int ep[2] = {-1, -1}; // an empty, nonblocking pipe
static int regular = -1;     // ev-file, a regular file in work_dir
static int ev_epoll = -1;    // the epoll instance kcmp inspects

// An optional facility (fanotify, userfaultfd) the guest kernel may be built
// without: every call then fails with ENOSYS whatever its arguments.
static long gated(int missing, long want)
{
    return missing ? ENOSYS : want;
}

// The bitmap bytes the recorder copies for select's fd_set arguments: the
// unsigned long words covering nfds (all requested descriptors are open, so
// the descriptor table is at least that large).
static size_t fdset_bytes(int nfds)
{
    return (size_t)(nfds + 63) / 64 * 8;
}

// A descriptor number below 64 that is not open.
static int closed_fd(void)
{
    for (int fd = 63; fd > 2; fd--)
        if (fcntl(fd, F_GETFD) < 0 && errno == EBADF)
            return fd;
    return -1;
}

static void pipe_cases(void)
{
    int fds[2] = {-1, -1}, packet[2] = {-1, -1}, unused[2] = {-1, -1};

    CALL("pipe.plain", pipe, WANT_OK, fds);
    out_buf(0, fds, sizeof fds);
    DONE();
    rp[0] = fds[0];
    rp[1] = fds[1];
    CALL("pipe.fault", pipe, EFAULT, 1);
    why("the kernel creates the pipe, cannot store the pair and closes it again: no output field");
    DONE();
    CALL("pipe2.cloexec_nonblock", pipe2, WANT_OK, fds, O_CLOEXEC | O_NONBLOCK);
    out_buf(0, fds, sizeof fds);
    DONE();
    ep[0] = fds[0];
    ep[1] = fds[1];
    CALL("pipe2.packet", pipe2, WANT_OK, packet, O_DIRECT | O_CLOEXEC);
    out_buf(0, packet, sizeof packet);
    DONE();
    close(packet[0]);
    close(packet[1]);
    CASE("pipe2.bad_flags", pipe2, EINVAL, unused, O_RDWR);
    CALL("pipe2.fault", pipe2, EFAULT, 1, O_CLOEXEC);
    why("no output field: the pair is recorded only when the call succeeds");
    DONE();
    if (write(rp[1], "R", 1) != 1)
        ora_fail("events: fill the readable pipe");
}

static void poll_cases(void)
{
    struct pollfd set[3] = {{rp[0], POLLIN, 0}, {rp[1], POLLOUT, 0}, {-1, POLLIN, 0}};
    struct pollfd set_in[3], idle = {ep[0], POLLIN, 0}, idle_in;
    struct pollfd closed = {999, POLLIN, 0}, closed_in;
    struct pollfd one = {rp[0], POLLIN, 0}, one_in;
    struct timespec zero = {0, 0}, zero_in, wait = {0, 20000000}, wait_in;
    ksigset mask = usr2_mask;
    struct rlimit limit;

    memcpy(set_in, set, sizeof set);
    memcpy(&idle_in, &idle, sizeof idle);
    memcpy(&closed_in, &closed, sizeof closed);
    memcpy(&one_in, &one, sizeof one);
    memcpy(&zero_in, &zero, sizeof zero);
    memcpy(&wait_in, &wait, sizeof wait);

    CALL("poll.ready", poll, WANT_OK, set, 3, 0);
    in_buf(0, set_in, sizeof set_in);
    out_buf(0, set, sizeof set);
    why("a readable and a writable pipe end; the negative descriptor is skipped");
    DONE();
    CALL("poll.not_ready", poll, WANT_OK, &idle, 1, 0);
    in_buf(0, &idle_in, sizeof idle_in);
    out_buf(0, &idle, sizeof idle);
    DONE();
    memcpy(&idle, &idle_in, sizeof idle);
    CALL("poll.timeout", poll, WANT_OK, &idle, 1, 20);
    in_buf(0, &idle_in, sizeof idle_in);
    out_buf(0, &idle, sizeof idle);
    why("nothing becomes ready within 20 ms");
    DONE();
    CALL("poll.nval", poll, WANT_OK, &closed, 1, 0);
    in_buf(0, &closed_in, sizeof closed_in);
    out_buf(0, &closed, sizeof closed);
    why("a descriptor that is not open reports POLLNVAL and counts as ready");
    DONE();
    CALL("poll.null_empty", poll, WANT_OK, NULL, 0, 0);
    want_status(0, "any", "NULL_POINTER");
    DONE();
    CALL("poll.fault", poll, EFAULT, 1, 1, 0);
    want_status(0, "in", "COPY_FAULT");
    DONE();
    if (getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur < 0x7fffffffULL) {
        CALL("poll.too_many", poll, EINVAL, set, limit.rlim_cur + 1, 0);
        want_status(0, "in", "INVALID_EXTENT");
        why("more entries than RLIMIT_NOFILE: refused, and the recorder copies nothing");
        DONE();
    }

    memcpy(set, set_in, sizeof set);
    CALL("ppoll.zero_timeout_mask", ppoll, WANT_OK, set, 3, &zero, &mask, sizeof mask);
    in_buf(0, set_in, sizeof set_in);
    out_buf(0, set, sizeof set);
    in_buf(2, &zero_in, sizeof zero_in);
    out_buf(2, &zero, sizeof zero);
    in_key("signal.mask", &mask, sizeof mask);
    why("SIGUSR2 is blocked for the duration of the call only; a zero timeout is not written back");
    DONE();
    CALL("ppoll.null_timeout", ppoll, WANT_OK, &one, 1, NULL, NULL, 0);
    in_buf(0, &one_in, sizeof one_in);
    out_buf(0, &one, sizeof one);
    want_status(2, "any", "NULL_POINTER");
    why("the descriptor is ready, so the NULL (infinite) timeout returns at once");
    DONE();
    memcpy(&idle, &idle_in, sizeof idle);
    CALL("ppoll.timeout", ppoll, WANT_OK, &idle, 1, &wait, NULL, sizeof(ksigset));
    in_buf(0, &idle_in, sizeof idle_in);
    out_buf(0, &idle, sizeof idle);
    in_buf(2, &wait_in, sizeof wait_in);
    out_buf(2, &wait, sizeof wait);
    why("the remaining time is written back: zero once the 20 ms expired");
    DONE();
    memcpy(&one, &one_in, sizeof one);
    memcpy(&zero, &zero_in, sizeof zero);
    CALL("ppoll.bad_sigsetsize", ppoll, EINVAL, &one, 1, &zero, &mask, 4);
    in_buf(0, &one_in, sizeof one_in);
    in_buf(2, &zero_in, sizeof zero_in);
    want_status(3, "in", "INVALID_EXTENT");
    why("a sigset size other than 8 is refused; the recorder marks the mask extent invalid");
    DONE();
    CALL("ppoll.timeout_fault", ppoll, EFAULT, &one, 1, 1, NULL, sizeof(ksigset));
    in_buf(0, &one_in, sizeof one_in);
    want_status(2, "in", "COPY_FAULT");
    DONE();
}

static void select_cases(void)
{
    fd_set r, w, e, r_in, w_in, e_in;
    struct timeval tv = {0, 0}, tv_in;
    struct timespec ts = {0, 0}, ts_in;
    ksigset mask = usr2_mask;
    struct sigset_pack pack = {&mask, sizeof mask}, null_mask = {NULL, sizeof mask};
    struct sigset_pack short_pack = {&mask, 4};
    int n = (rp[0] > rp[1] ? rp[0] : rp[1]) + 1;
    size_t bytes = fdset_bytes(n);

    FD_ZERO(&r);
    FD_ZERO(&w);
    FD_ZERO(&e);
    FD_SET(rp[0], &r);
    FD_SET(rp[1], &w);
    memcpy(&r_in, &r, sizeof r);
    memcpy(&w_in, &w, sizeof w);
    memcpy(&e_in, &e, sizeof e);
    memcpy(&tv_in, &tv, sizeof tv);
    CALL("select.ready", select, WANT_OK, n, &r, &w, &e, &tv);
    in_buf(1, &r_in, bytes);
    in_buf(2, &w_in, bytes);
    in_buf(3, &e_in, bytes);
    out_buf(1, &r, bytes);
    out_buf(2, &w, bytes);
    out_buf(3, &e, bytes);
    in_buf(4, &tv_in, sizeof tv_in);
    out_buf(4, &tv, sizeof tv);
    why("the recorder copies the bitmap words covering nfds, not the whole fd_set");
    DONE();

    FD_ZERO(&r);
    FD_SET(ep[0], &r);
    memcpy(&r_in, &r, sizeof r);
    n = ep[0] + 1;
    bytes = fdset_bytes(n);
    tv.tv_sec = 0;
    tv.tv_usec = 20000;
    memcpy(&tv_in, &tv, sizeof tv);
    CALL("select.not_ready", select, WANT_OK, n, &r, NULL, NULL, &tv);
    in_buf(1, &r_in, bytes);
    out_buf(1, &r, bytes);
    in_buf(4, &tv_in, sizeof tv_in);
    out_buf(4, &tv, sizeof tv);
    why("the set comes back empty and the remaining time (zero) is written back");
    DONE();

    FD_ZERO(&r);
    FD_SET(rp[0], &r);
    memcpy(&r_in, &r, sizeof r);
    n = rp[0] + 1;
    bytes = fdset_bytes(n);
    CALL("select.null_timeout", select, WANT_OK, n, &r, NULL, NULL, NULL);
    in_buf(1, &r_in, bytes);
    out_buf(1, &r, bytes);
    why("a ready descriptor: the NULL (infinite) timeout returns at once");
    DONE();
    tv.tv_sec = 0;
    tv.tv_usec = 1000;
    memcpy(&tv_in, &tv, sizeof tv);
    CALL("select.sleep_only", select, WANT_OK, 0, NULL, NULL, NULL, &tv);
    in_buf(4, &tv_in, sizeof tv_in);
    out_buf(4, &tv, sizeof tv);
    why("no sets at all: select as a 1 ms sleep");
    DONE();
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    memcpy(&tv_in, &tv, sizeof tv);
    memcpy(&r, &r_in, sizeof r);
    CALL("select.negative_nfds", select, EINVAL, -1, &r, NULL, NULL, &tv);
    want_status(1, "in", "INVALID_EXTENT");
    in_buf(4, &tv_in, sizeof tv_in);
    out_buf(4, &tv, sizeof tv);
    DONE();
    int hole = closed_fd();
    if (hole > 0) {
        FD_ZERO(&r);
        FD_SET(hole, &r);
        memcpy(&r_in, &r, sizeof r);
        CALL("select.badf", select, EBADF, hole + 1, &r, NULL, NULL, &tv);
        in_buf(1, &r_in, fdset_bytes(hole + 1));
        in_buf(4, &tv_in, sizeof tv_in);
        out_buf(4, &tv, sizeof tv);
        why("the set names a descriptor that is not open");
        DONE();
    }
    CALL("select.fault", select, EFAULT, n, 1, NULL, NULL, NULL);
    want_status(1, "in", "COPY_FAULT");
    DONE();

    FD_ZERO(&r);
    FD_SET(rp[0], &r);
    memcpy(&r_in, &r, sizeof r);
    memcpy(&ts_in, &ts, sizeof ts);
    CALL("pselect6.mask", pselect6, WANT_OK, n, &r, NULL, NULL, &ts, &pack);
    in_buf(1, &r_in, bytes);
    out_buf(1, &r, bytes);
    in_buf(4, &ts_in, sizeof ts_in);
    out_buf(4, &ts, sizeof ts);
    in_key("arg5.sigset_pack", &pack, sizeof pack);
    in_key("signal.mask", &mask, sizeof mask);
    why("SIGUSR2 is blocked for the duration of the call only");
    DONE();
    memcpy(&r, &r_in, sizeof r);
    CALL("pselect6.null_pack", pselect6, WANT_OK, n, &r, NULL, NULL, NULL, NULL);
    in_buf(1, &r_in, bytes);
    out_buf(1, &r, bytes);
    why("no timeout and no mask argument: the ready descriptor returns at once");
    DONE();
    memcpy(&r, &r_in, sizeof r);
    CALL("pselect6.null_mask", pselect6, WANT_OK, n, &r, NULL, NULL, &ts, &null_mask);
    in_buf(1, &r_in, bytes);
    out_buf(1, &r, bytes);
    in_buf(4, &ts_in, sizeof ts_in);
    out_buf(4, &ts, sizeof ts);
    in_key("arg5.sigset_pack", &null_mask, sizeof null_mask);
    why("the pack holds a NULL mask: the signal mask is left alone");
    DONE();
    FD_ZERO(&r);
    FD_SET(ep[0], &r);
    memcpy(&r_in, &r, sizeof r);
    ts.tv_sec = 0;
    ts.tv_nsec = 20000000;
    memcpy(&ts_in, &ts, sizeof ts);
    CALL("pselect6.not_ready", pselect6, WANT_OK, ep[0] + 1, &r, NULL, NULL, &ts, &pack);
    in_buf(1, &r_in, fdset_bytes(ep[0] + 1));
    out_buf(1, &r, fdset_bytes(ep[0] + 1));
    in_buf(4, &ts_in, sizeof ts_in);
    out_buf(4, &ts, sizeof ts);
    in_key("arg5.sigset_pack", &pack, sizeof pack);
    in_key("signal.mask", &mask, sizeof mask);
    why("the 20 ms expire: empty set, remaining time written back");
    DONE();
    ts.tv_sec = 0;
    ts.tv_nsec = 0;
    memcpy(&ts_in, &ts, sizeof ts);
    memcpy(&r, &r_in, sizeof r);
    CALL("pselect6.bad_sigsetsize", pselect6, EINVAL, ep[0] + 1, &r, NULL, NULL, &ts,
         &short_pack);
    in_buf(1, &r_in, fdset_bytes(ep[0] + 1));
    in_buf(4, &ts_in, sizeof ts_in);
    out_buf(4, &ts, sizeof ts);
    in_key("arg5.sigset_pack", &short_pack, sizeof short_pack);
    want_key_status("signal.mask", "INVALID_EXTENT");
    why("a 4-byte sigset is refused before any descriptor is examined");
    DONE();
}

static void epoll_cases(void)
{
    struct epoll_event in_ev = {.events = EPOLLIN, .data.u64 = 0x1111};
    struct epoll_event out_ev = {.events = EPOLLOUT, .data.u64 = 0x2222};
    struct epoll_event edge = {.events = EPOLLIN | EPOLLET, .data.u64 = 0x3333};
    struct epoll_event idle_ev = {.events = EPOLLIN, .data.u64 = 0x4444};
    struct epoll_event nested = {.events = EPOLLIN, .data.u64 = 0x5555};
    struct epoll_event events[4];
    struct timespec zero = {0, 0}, bad_ts = {0, 1000000000};
    ksigset mask = usr2_mask;
    long n;

    long epfd = CALL("epoll_create.size", epoll_create, WANT_OK, 8);
    why("the size hint only has to be positive");
    DONE();
    ev_epoll = (int)epfd;
    CASE("epoll_create.zero_size", epoll_create, EINVAL, 0);
    long idle = CASE("epoll_create1.cloexec", epoll_create1, WANT_OK, EPOLL_CLOEXEC);
    CASE("epoll_create1.bad_flags", epoll_create1, EINVAL, 1);

    CALL("epoll_ctl.add_in", epoll_ctl, WANT_OK, epfd, EPOLL_CTL_ADD, rp[0], &in_ev);
    in_buf(3, &in_ev, sizeof in_ev);
    DONE();
    CALL("epoll_ctl.add_out", epoll_ctl, WANT_OK, epfd, EPOLL_CTL_ADD, rp[1], &out_ev);
    in_buf(3, &out_ev, sizeof out_ev);
    DONE();
    CALL("epoll_ctl.add_existing", epoll_ctl, EEXIST, epfd, EPOLL_CTL_ADD, rp[0], &in_ev);
    in_buf(3, &in_ev, sizeof in_ev);
    DONE();
    memset(events, 0, sizeof events);
    n = CALL("epoll_wait.ready", epoll_wait, WANT_OK, epfd, events, 4, 0);
    out_buf(1, events, n > 0 ? (size_t)n * sizeof events[0] : 0);
    why("both pipe ends are ready; the recorder copies the events the call returned");
    DONE();
    CALL("epoll_ctl.mod_edge", epoll_ctl, WANT_OK, epfd, EPOLL_CTL_MOD, rp[0], &edge);
    in_buf(3, &edge, sizeof edge);
    DONE();
    memset(events, 0, sizeof events);
    n = CALL("epoll_wait.after_mod", epoll_wait, WANT_OK, epfd, events, 4, 0);
    out_buf(1, events, n > 0 ? (size_t)n * sizeof events[0] : 0);
    why("modifying a ready descriptor queues it again with the new data");
    DONE();
    memset(events, 0, sizeof events);
    n = CALL("epoll_pwait.mask", epoll_pwait, WANT_OK, epfd, events, 4, 0, &mask, sizeof mask);
    out_buf(1, events, n > 0 ? (size_t)n * sizeof events[0] : 0);
    in_key("signal.mask", &mask, sizeof mask);
    why("SIGUSR2 is blocked for the duration of the call only");
    DONE();
    memset(events, 0, sizeof events);
    n = CALL("epoll_pwait.null_mask", epoll_pwait, WANT_OK, epfd, events, 4, 0, NULL,
             sizeof mask);
    out_buf(1, events, n > 0 ? (size_t)n * sizeof events[0] : 0);
    DONE();
    CALL("epoll_pwait.bad_sigsetsize", epoll_pwait, EINVAL, epfd, events, 4, 0, &mask, 4);
    want_status(4, "in", "INVALID_EXTENT");
    DONE();
    memset(events, 0, sizeof events);
    n = CALL("epoll_pwait2.zero_timeout", epoll_pwait2, WANT_OK, epfd, events, 4, &zero, &mask,
             sizeof mask);
    in_buf(3, &zero, sizeof zero);
    out_buf(1, events, n > 0 ? (size_t)n * sizeof events[0] : 0);
    in_key("signal.mask", &mask, sizeof mask);
    DONE();
    memset(events, 0, sizeof events);
    n = CALL("epoll_pwait2.null_timeout", epoll_pwait2, WANT_OK, epfd, events, 4, NULL, NULL,
             sizeof mask);
    want_status(3, "in", "NULL_POINTER");
    out_buf(1, events, n > 0 ? (size_t)n * sizeof events[0] : 0);
    why("the level-triggered writable end is always ready: no wait despite the NULL timeout");
    DONE();
    CALL("epoll_pwait2.bad_timeout", epoll_pwait2, EINVAL, epfd, events, 4, &bad_ts, NULL,
         sizeof mask);
    in_buf(3, &bad_ts, sizeof bad_ts);
    why("tv_nsec of one second is out of range");
    DONE();
    CALL("epoll_wait.fault", epoll_wait, EFAULT, epfd, 1, 1, 0);
    why("a ready event cannot be stored: no output field on failure");
    DONE();

    CALL("epoll_ctl.add_idle", epoll_ctl, WANT_OK, idle, EPOLL_CTL_ADD, ep[0], &idle_ev);
    in_buf(3, &idle_ev, sizeof idle_ev);
    DONE();
    memset(events, 0, sizeof events);
    CALL("epoll_wait.empty", epoll_wait, WANT_OK, idle, events, 4, 0);
    out_buf(1, events, 0);
    why("nothing ready: the output field is present with zero bytes");
    DONE();
    CALL("epoll_wait.timeout", epoll_wait, WANT_OK, idle, events, 4, 20);
    out_buf(1, events, 0);
    DONE();
    CASE("epoll_wait.bad_maxevents", epoll_wait, EINVAL, idle, events, 0, 0);
    CASE("epoll_wait.not_epoll", epoll_wait, EINVAL, rp[0], events, 4, 0);
    CALL("epoll_ctl.add_nested", epoll_ctl, WANT_OK, epfd, EPOLL_CTL_ADD, idle, &nested);
    in_buf(3, &nested, sizeof nested);
    why("an epoll instance watched by another one");
    DONE();

    CALL("epoll_ctl.del", epoll_ctl, WANT_OK, epfd, EPOLL_CTL_DEL, rp[1], NULL);
    why("EPOLL_CTL_DEL takes no event: nothing is captured");
    DONE();
    CASE("epoll_ctl.del_missing", epoll_ctl, ENOENT, epfd, EPOLL_CTL_DEL, rp[1], NULL);
    CALL("epoll_ctl.bad_op", epoll_ctl, EINVAL, epfd, 99, ep[0], &in_ev);
    want_status(3, "in", "NO_DECODER");
    why("an unknown operation: its event argument is an explicit gap");
    DONE();
    CALL("epoll_ctl.self", epoll_ctl, EINVAL, epfd, EPOLL_CTL_ADD, epfd, &in_ev);
    in_buf(3, &in_ev, sizeof in_ev);
    DONE();
    CALL("epoll_ctl.regular_file", epoll_ctl, EPERM, epfd, EPOLL_CTL_ADD, regular, &in_ev);
    in_buf(3, &in_ev, sizeof in_ev);
    why("regular files do not support poll");
    DONE();
    CALL("epoll_ctl.fault", epoll_ctl, EFAULT, epfd, EPOLL_CTL_ADD, ep[0], 1);
    want_status(3, "in", "COPY_FAULT");
    DONE();
    CALL("epoll_ctl.badf", epoll_ctl, EBADF, epfd, EPOLL_CTL_ADD, 999, &in_ev);
    in_buf(3, &in_ev, sizeof in_ev);
    DONE();
    CALL("epoll_ctl.not_epoll", epoll_ctl, EINVAL, rp[0], EPOLL_CTL_ADD, ep[0], &in_ev);
    in_buf(3, &in_ev, sizeof in_ev);
    DONE();
    close((int)idle);
}

static void counter_cases(void)
{
    ksigset mask = usr2_mask, other = usr1_mask;
    struct itimerspec set = {{0, 0}, {60, 0}}, rearm = {{1, 0}, {30, 0}}, off, old, now_value;
    struct itimerspec bad = {{0, 0}, {0, 1000000000}}, absolute, wall;
    struct timespec now;

    long efd = CASE("eventfd.initial", eventfd, WANT_OK, 5);
    long efd2 = CASE("eventfd2.semaphore", eventfd2, WANT_OK, 0,
                     EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE);
    CASE("eventfd2.bad_flags", eventfd2, EINVAL, 0, O_RDWR);
    struct pollfd counters[2] = {{(int)efd, POLLIN, 0}, {(int)efd2, POLLIN, 0}}, counters_in[2];
    memcpy(counters_in, counters, sizeof counters);
    CALL("poll.eventfd", poll, WANT_OK, counters, 2, 0);
    in_buf(0, counters_in, sizeof counters_in);
    out_buf(0, counters, sizeof counters);
    why("a counter of 5 is readable, a counter of 0 is not");
    DONE();
    close((int)efd);
    close((int)efd2);

    long sfd = CALL("signalfd.new", signalfd, WANT_OK, -1, &mask, sizeof mask);
    in_key("signal.mask", &mask, sizeof mask);
    why("creating a signalfd does not change the signal mask");
    DONE();
    CALL("signalfd.update", signalfd, WANT_OK, sfd, &other, sizeof other);
    in_key("signal.mask", &other, sizeof other);
    DONE();
    CALL("signalfd.bad_size", signalfd, EINVAL, -1, &mask, 4);
    want_status(1, "in", "INVALID_EXTENT");
    DONE();
    CALL("signalfd.fault", signalfd, EFAULT, -1, 1, sizeof mask);
    want_status(1, "in", "COPY_FAULT");
    DONE();
    long sfd4 = CALL("signalfd4.flags", signalfd4, WANT_OK, -1, &mask, sizeof mask,
                     SFD_CLOEXEC | SFD_NONBLOCK);
    in_key("signal.mask", &mask, sizeof mask);
    DONE();
    CALL("signalfd4.bad_flags", signalfd4, EINVAL, -1, &mask, sizeof mask, 1);
    in_key("signal.mask", &mask, sizeof mask);
    DONE();
    CALL("signalfd4.not_signalfd", signalfd4, EINVAL, rp[0], &mask, sizeof mask, 0);
    in_key("signal.mask", &mask, sizeof mask);
    DONE();
    CALL("signalfd4.badf", signalfd4, EBADF, 999, &mask, sizeof mask, 0);
    in_key("signal.mask", &mask, sizeof mask);
    DONE();
    if (sfd >= 0)
        close((int)sfd);
    if (sfd4 >= 0)
        close((int)sfd4);

    long tfd = CASE("timerfd_create.monotonic", timerfd_create, WANT_OK, CLOCK_MONOTONIC,
                    TFD_CLOEXEC | TFD_NONBLOCK);
    long rtfd = CASE("timerfd_create.realtime", timerfd_create, WANT_OK, CLOCK_REALTIME, 0);
    CASE("timerfd_create.bad_clock", timerfd_create, EINVAL, 99, 0);
    CASE("timerfd_create.bad_flags", timerfd_create, EINVAL, CLOCK_MONOTONIC, 1);
    CALL("timerfd_create.alarm", timerfd_create, EPERM, CLOCK_BOOTTIME_ALARM, TFD_CLOEXEC);
    why("alarm clocks need CAP_WAKE_ALARM: EPERM as UID 1000 (root.c can succeed)");
    DONE();

    memset(&old, 0, sizeof old);
    CALL("timerfd_settime.relative", timerfd_settime, WANT_OK, tfd, 0, &set, &old);
    in_buf(2, &set, sizeof set);
    out_buf(3, &old, sizeof old);
    why("the timer was disarmed: the old value is all zero");
    DONE();
    memset(&old, 0, sizeof old);
    CALL("timerfd_settime.rearm", timerfd_settime, WANT_OK, tfd, 0, &rearm, &old);
    in_buf(2, &rearm, sizeof rearm);
    out_any(3);
    volatile_case();
    why("the old value holds what was left of the first 60 s");
    DONE();
    memset(&now_value, 0, sizeof now_value);
    CALL("timerfd_gettime.armed", timerfd_gettime, WANT_OK, tfd, &now_value);
    out_any(1);
    volatile_case();
    DONE();
    clock_gettime(CLOCK_MONOTONIC, &now);
    memset(&absolute, 0, sizeof absolute);
    absolute.it_value.tv_sec = now.tv_sec + 60;
    absolute.it_value.tv_nsec = now.tv_nsec;
    CALL("timerfd_settime.abstime_null_old", timerfd_settime, WANT_OK, tfd, TFD_TIMER_ABSTIME,
         &absolute, NULL);
    in_buf(2, &absolute, sizeof absolute);
    want_status(3, "out", "NULL_POINTER");
    volatile_case();
    why("an absolute expiry one minute ahead; no old value requested");
    DONE();
    memset(&off, 0, sizeof off);
    memset(&old, 0, sizeof old);
    CALL("timerfd_settime.disarm", timerfd_settime, WANT_OK, tfd, 0, &off, &old);
    in_buf(2, &off, sizeof off);
    out_any(3);
    volatile_case();
    DONE();
    memset(&now_value, 0xa5, sizeof now_value);
    CALL("timerfd_gettime.disarmed", timerfd_gettime, WANT_OK, tfd, &now_value);
    out_buf(1, &now_value, sizeof now_value);
    DONE();
    clock_gettime(CLOCK_REALTIME, &now);
    memset(&wall, 0, sizeof wall);
    wall.it_value.tv_sec = now.tv_sec + 3600;
    memset(&old, 0, sizeof old);
    CALL("timerfd_settime.cancel_on_set", timerfd_settime, WANT_OK, rtfd,
         TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &wall, &old);
    in_buf(2, &wall, sizeof wall);
    out_buf(3, &old, sizeof old);
    volatile_case();
    why("a wall-clock expiry an hour ahead, cancelled if the clock is set");
    DONE();
    CALL("timerfd_settime.bad_nsec", timerfd_settime, EINVAL, tfd, 0, &bad, NULL);
    in_buf(2, &bad, sizeof bad);
    DONE();
    CALL("timerfd_settime.bad_flags", timerfd_settime, EINVAL, tfd, 0x80, &set, NULL);
    in_buf(2, &set, sizeof set);
    DONE();
    CALL("timerfd_settime.fault", timerfd_settime, EFAULT, tfd, 0, 1, NULL);
    want_status(2, "in", "COPY_FAULT");
    DONE();
    CALL("timerfd_settime.not_timerfd", timerfd_settime, EINVAL, rp[0], 0, &set, NULL);
    in_buf(2, &set, sizeof set);
    DONE();
    CASE("timerfd_gettime.badf", timerfd_gettime, EBADF, 999, &now_value);
    CALL("timerfd_gettime.fault", timerfd_gettime, EFAULT, tfd, 1);
    why("no output field: it is recorded only when the call succeeds");
    DONE();
    close((int)tfd);
    close((int)rtfd);
}

static void notify_cases(void)
{
    long ifd = CASE0("inotify_init.plain", inotify_init, WANT_OK);
    long ifd1 = CASE("inotify_init1.flags", inotify_init1, WANT_OK, IN_CLOEXEC | IN_NONBLOCK);
    CASE("inotify_init1.bad_flags", inotify_init1, EINVAL, 1);

    CALL("inotify_add_watch.directory", inotify_add_watch, WANT_OK, ifd1, ".",
         IN_CREATE | IN_DELETE);
    in_str(1, ".");
    DONE();
    long file_wd = CALL("inotify_add_watch.file", inotify_add_watch, WANT_OK, ifd1, "ev-file",
                        IN_MODIFY | IN_CLOSE_WRITE);
    in_str(1, "ev-file");
    DONE();
    CALL("inotify_add_watch.mask_add", inotify_add_watch, WANT_OK, ifd1, "ev-file",
         IN_ATTRIB | IN_MASK_ADD);
    in_str(1, "ev-file");
    why("the same inode returns the same watch descriptor");
    DONE();
    CALL("inotify_add_watch.missing", inotify_add_watch, ENOENT, ifd1, "ev-missing", IN_MODIFY);
    in_str(1, "ev-missing");
    DONE();
    CALL("inotify_add_watch.empty_mask", inotify_add_watch, EINVAL, ifd1, ".", 0);
    in_str(1, ".");
    DONE();
    CALL("inotify_add_watch.onlydir_file", inotify_add_watch, ENOTDIR, ifd1, "ev-file",
         IN_MODIFY | IN_ONLYDIR);
    in_str(1, "ev-file");
    DONE();
    CALL("inotify_add_watch.null_path", inotify_add_watch, EFAULT, ifd1, NULL, IN_MODIFY);
    want_status(1, "in", "NULL_POINTER");
    DONE();
    CALL("inotify_add_watch.not_inotify", inotify_add_watch, EINVAL, rp[0], ".", IN_MODIFY);
    in_str(1, ".");
    DONE();
    CALL("inotify_add_watch.badf", inotify_add_watch, EBADF, 999, ".", IN_MODIFY);
    in_str(1, ".");
    DONE();
    int created = open("ev-created", O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    if (created >= 0)
        close(created);
    else
        ora_fail("events: create ev-created");
    struct pollfd watch = {(int)ifd1, POLLIN, 0}, watch_in;
    memcpy(&watch_in, &watch, sizeof watch);
    CALL("poll.inotify_event", poll, WANT_OK, &watch, 1, 1000);
    in_buf(0, &watch_in, sizeof watch_in);
    out_buf(0, &watch, sizeof watch);
    why("creating ev-created queued an IN_CREATE event");
    DONE();
    CASE("inotify_rm_watch.file", inotify_rm_watch, WANT_OK, ifd1, file_wd);
    CASE("inotify_rm_watch.again", inotify_rm_watch, EINVAL, ifd1, file_wd);
    CASE("inotify_rm_watch.badf", inotify_rm_watch, EBADF, 999, file_wd);
    CASE("inotify_rm_watch.not_inotify", inotify_rm_watch, EINVAL, rp[0], file_wd);
    close((int)ifd);
    close((int)ifd1);

    long fan = CALL("fanotify_init.unprivileged_fid", fanotify_init, WANT_ANY,
                    FAN_CLASS_NOTIF | FAN_REPORT_FID | FAN_CLOEXEC, O_RDONLY);
    why("UID 1000 may create a FAN_REPORT_FID notification group; ENOSYS when the guest kernel is "
        "built without CONFIG_FANOTIFY");
    DONE();
    int missing = fan < 0 && errno == ENOSYS;
    CALL("fanotify_init.no_fid", fanotify_init, gated(missing, EPERM), FAN_CLASS_NOTIF,
         O_RDONLY);
    why("a group without file handles needs CAP_SYS_ADMIN: EPERM as UID 1000 (root.c can succeed)");
    DONE();
    CALL("fanotify_init.unlimited_queue", fanotify_init, gated(missing, EPERM),
         FAN_CLASS_NOTIF | FAN_REPORT_FID | FAN_UNLIMITED_QUEUE, O_RDONLY);
    why("an unlimited queue needs CAP_SYS_ADMIN: EPERM as UID 1000");
    DONE();
    CALL("fanotify_init.bad_flags", fanotify_init, gated(missing, EINVAL),
         FAN_REPORT_FID | 0x80000000U, O_RDONLY);
    DONE();
    if (fan >= 0) {
        long mark = CALL("fanotify_mark.inode", fanotify_mark, WANT_ANY, fan, FAN_MARK_ADD,
                         FAN_MODIFY | FAN_CLOSE_WRITE, AT_FDCWD, "ev-file");
        in_str(4, "ev-file");
        why("an unprivileged group may mark inodes when the filesystem has file handles and an "
            "fsid (tmpfs and ext4 do); EXDEV or EOPNOTSUPP otherwise");
        DONE();
        CALL("fanotify_mark.filesystem", fanotify_mark, EPERM, fan,
             FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_MODIFY, AT_FDCWD, ".");
        in_str(4, ".");
        why("an unprivileged group cannot place filesystem marks (root.c can)");
        DONE();
        CALL("fanotify_mark.mount", fanotify_mark, EPERM, fan, FAN_MARK_ADD | FAN_MARK_MOUNT,
             FAN_MODIFY, AT_FDCWD, ".");
        in_str(4, ".");
        why("an unprivileged group cannot place mount marks (root.c can)");
        DONE();
        if (mark == 0) {
            CALL("fanotify_mark.null_path_dirfd", fanotify_mark, WANT_OK, fan, FAN_MARK_ADD,
                 FAN_MODIFY, regular, NULL);
            want_status(4, "in", "NULL_POINTER");
            why("a NULL pathname marks the object dirfd refers to");
            DONE();
            CALL("fanotify_mark.remove", fanotify_mark, WANT_OK, fan, FAN_MARK_REMOVE,
                 FAN_MODIFY | FAN_CLOSE_WRITE, AT_FDCWD, "ev-file");
            in_str(4, "ev-file");
            DONE();
        }
        CALL("fanotify_mark.missing", fanotify_mark, ENOENT, fan, FAN_MARK_ADD, FAN_MODIFY,
             AT_FDCWD, "ev-missing");
        in_str(4, "ev-missing");
        DONE();
        CALL("fanotify_mark.bad_flags", fanotify_mark, EINVAL, fan, FAN_MARK_ADD | 0x80000000U,
             FAN_MODIFY, AT_FDCWD, "ev-file");
        in_str(4, "ev-file");
        DONE();
        close((int)fan);
    }
    CALL("fanotify_mark.badf", fanotify_mark, gated(missing, EBADF), 999, FAN_MARK_ADD,
         FAN_MODIFY, AT_FDCWD, "ev-file");
    in_str(4, "ev-file");
    DONE();
    CALL("fanotify_mark.not_fanotify", fanotify_mark, gated(missing, EINVAL), rp[0],
         FAN_MARK_ADD, FAN_MODIFY, AT_FDCWD, "ev-file");
    in_str(4, "ev-file");
    DONE();
}

// 0: not a terminal; 1: a terminal whose TCGETS/TIOCGWINSZ/FIONREAD the
// recorder decodes (tty, auxiliary tty and Unix98 pty slave majors); 2: a
// terminal it records as a gap.
static int tty_kind(int fd)
{
    struct stat st;
    if (!isatty(fd))
        return 0;
    if (fstat(fd, &st) != 0 || !S_ISCHR(st.st_mode))
        return 2;
    unsigned int dev_major = major(st.st_rdev);
    return dev_major == 4 || dev_major == 5 || (dev_major >= 136 && dev_major < 144) ? 1 : 2;
}

static long not_tty_errno(int fd)
{
    return fcntl(fd, F_GETFD) < 0 ? EBADF : ENOTTY;
}

static void ioctl_cases(void)
{
    struct ktermios term;
    struct winsize size;
    int avail = -1, on = 1, off = 0, pgrp = 0;
    int in = tty_kind(0), out = tty_kind(1);
    long r;

    // The run's terminal (stdin/stdout): read-only requests.
    memset(&term, 0, sizeof term);
    r = CALL("ioctl.tcgets_stdin", ioctl, in ? WANT_OK : not_tty_errno(0), 0, TCGETS, &term);
    if (in == 1 && r == 0)
        out_buf(2, &term, sizeof term);
    else if (in != 1)
        want_status(2, "in", "NO_DECODER");
    why("reads the terminal settings of the run's PTY; never changes them");
    DONE();
    memset(&size, 0, sizeof size);
    r = CALL("ioctl.tiocgwinsz_stdout", ioctl, out ? WANT_OK : not_tty_errno(1), 1, TIOCGWINSZ,
             &size);
    if (out == 1 && r == 0)
        out_buf(2, &size, sizeof size);
    else if (out != 1)
        want_status(2, "in", "NO_DECODER");
    volatile_case();
    DONE();
    if (in) {
        avail = -1;
        r = CALL("ioctl.fionread_tty", ioctl, WANT_OK, 0, FIONREAD, &avail);
        if (in == 1 && r == 0)
            out_buf(2, &avail, sizeof avail);
        else if (in != 1)
            want_status(2, "in", "NO_DECODER");
        volatile_case();
        why("bytes typed on the terminal and not read yet");
        DONE();
        CALL("ioctl.tcgets_fault", ioctl, EFAULT, 0, TCGETS, 1);
        if (in != 1)
            want_status(2, "in", "NO_DECODER");
        why("a decoded terminal request records its output only on success");
        DONE();
    }
    long pgrp_result = CALL("ioctl.tiocgpgrp", ioctl, WANT_ANY, 0, TIOCGPGRP, &pgrp);
    if (pgrp_result == 0)
        out_buf(2, &pgrp, sizeof pgrp);
    volatile_case();
    why("ENOTTY unless stdin is this session's controlling terminal; on a tty the process "
        "group is recorded at exit (pid_t)");
    DONE();

    // Generic requests on a pipe and a regular file: recorded as gaps.
    CALL("ioctl.fionread_pipe", ioctl, WANT_OK, rp[0], FIONREAD, &avail);
    want_status(2, "in", "NO_DECODER");
    why("only terminal requests are decoded; the pipe's FIONREAD output is an explicit gap");
    DONE();
    CALL("ioctl.fionbio_on", ioctl, WANT_OK, rp[0], FIONBIO, &on);
    want_status(2, "in", "NO_DECODER");
    DONE();
    CALL("ioctl.fionbio_off", ioctl, WANT_OK, rp[0], FIONBIO, &off);
    want_status(2, "in", "NO_DECODER");
    DONE();
    CALL("ioctl.fioclex", ioctl, WANT_OK, rp[0], FIOCLEX, 0);
    want_status(2, "in", "NO_DECODER");
    why("the argument is unused (0): still a gap, not a NULL pointer");
    DONE();
    CALL("ioctl.fionclex", ioctl, WANT_OK, rp[0], FIONCLEX, 0);
    want_status(2, "in", "NO_DECODER");
    DONE();
    CALL("ioctl.fioasync_on", ioctl, WANT_OK, rp[0], FIOASYNC, &on);
    want_status(2, "in", "NO_DECODER");
    why("no owner is set, so no SIGIO is ever sent; switched off again below");
    DONE();
    CALL("ioctl.fioasync_off", ioctl, WANT_OK, rp[0], FIOASYNC, &off);
    want_status(2, "in", "NO_DECODER");
    DONE();
    CALL("ioctl.fionread_file", ioctl, WANT_OK, regular, FIONREAD, &avail);
    want_status(2, "in", "NO_DECODER");
    DONE();
    CALL("ioctl.unknown_file", ioctl, ENOTTY, regular, _IOR('Z', 0x7e, int), &avail);
    want_status(2, "in", "NO_DECODER");
    why("no driver knows the request: ENOTTY, and the argument is recorded as a gap");
    DONE();
    CALL("ioctl.badf", ioctl, EBADF, 999, FIONREAD, &avail);
    want_status(2, "in", "NO_DECODER");
    DONE();
    CALL("ioctl.fionread_fault", ioctl, EFAULT, rp[0], FIONREAD, 1);
    want_status(2, "in", "NO_DECODER");
    DONE();
}

static void userfaultfd_cases(void)
{
    long uffd = CALL("userfaultfd.user_mode_only", userfaultfd, WANT_ANY,
                     UFFD_USER_MODE_ONLY | O_CLOEXEC | O_NONBLOCK);
    why("UID 1000 may handle user-mode faults; ENOSYS when the guest kernel is built without "
        "CONFIG_USERFAULTFD");
    DONE();
    int missing = uffd < 0 && errno == ENOSYS;
    long kernel_want = EPERM;
    FILE *sysctl = fopen("/proc/sys/vm/unprivileged_userfaultfd", "re");
    if (sysctl) {
        int allowed = 0;
        if (fscanf(sysctl, "%d", &allowed) == 1 && allowed)
            kernel_want = WANT_OK;
        fclose(sysctl);
    }
    long kfd = CALL("userfaultfd.kernel_faults", userfaultfd, gated(missing, kernel_want),
                    O_CLOEXEC);
    why("kernel-mode faults need CAP_SYS_PTRACE or vm.unprivileged_userfaultfd=1 (read before "
        "the call): EPERM as UID 1000 by default");
    DONE();
    CALL("userfaultfd.bad_flags", userfaultfd, gated(missing, EINVAL),
         UFFD_USER_MODE_ONLY | O_RDWR);
    DONE();
    if (uffd >= 0)
        close((int)uffd);
    if (kfd >= 0)
        close((int)kfd);
}

static void kcmp_cases(void)
{
    struct kcmp_epoll_slot slot = {.efd = (uint32_t)ev_epoll, .tfd = (uint32_t)rp[0], .toff = 0};
    long self = getpid();

    CALL("kcmp.vm_self", kcmp, WANT_OK, self, self, KCMP_VM, 0, 0);
    volatile_case();
    DONE();
    CALL("kcmp.file_different", kcmp, WANT_OK, self, self, KCMP_FILE, rp[0], ep[0]);
    volatile_case();
    why("1 or 2: the order of two kernel objects, not their addresses");
    DONE();
    CALL("kcmp.epoll_tfd", kcmp, WANT_OK, self, self, KCMP_EPOLL_TFD, rp[0], &slot);
    volatile_case();
    why("idx2 points to a struct kcmp_epoll_slot; the kcmp schema declares no pointer argument, "
        "so nothing is captured");
    DONE();
    CALL("kcmp.bad_type", kcmp, EINVAL, self, self, 99, 0, 0);
    volatile_case();
    DONE();
    CALL("kcmp.badf", kcmp, EBADF, self, self, KCMP_FILE, 999, rp[0]);
    volatile_case();
    DONE();
    CALL("kcmp.missing_pid", kcmp, ESRCH, self, 0x3fffffff, KCMP_FILE, rp[0], rp[0]);
    volatile_case();
    why("0x3fffffff is above any pid_max");
    DONE();
}

static void pidfd_cases(void)
{
    siginfo_t info;
    long self_pid = getpid();
    int status = 0;

    ora_flush();
    pid_t child = fork();
    if (child < 0) {
        ora_fail("events: fork the pidfd child");
        return;
    }
    if (child == 0) {
        // Our own target: wait to be signalled; the alarm ends it if the
        // parent never does.
        ora_child(200);
        alarm(10);
        pause();
        _exit(0);
    }
    role("child", child);

    long pidfd = CALL("pidfd_open.child", pidfd_open, WANT_OK, child, 0);
    volatile_case();
    DONE();
    long self = CALL("pidfd_open.self_nonblock", pidfd_open, WANT_OK, self_pid, PIDFD_NONBLOCK);
    volatile_case();
    DONE();
    long thread = CALL("pidfd_open.thread", pidfd_open, WANT_OK, syscall(SYS_gettid),
                       PIDFD_THREAD);
    volatile_case();
    DONE();
    CALL("pidfd_open.bad_flags", pidfd_open, EINVAL, child, 1);
    volatile_case();
    DONE();
    CASE("pidfd_open.zero_pid", pidfd_open, EINVAL, 0, 0);
    CALL("pidfd_open.missing", pidfd_open, ESRCH, 0x3fffffff, 0);
    why("0x3fffffff is above any pid_max");
    DONE();

    if (pidfd >= 0) {
        long copy = CALL("pidfd_getfd.child_pipe", pidfd_getfd, WANT_OK, pidfd, rp[0], 0);
        why("the parent may ptrace its own child: a copy of the child's inherited pipe end");
        DONE();
        CASE("pidfd_getfd.badf_target", pidfd_getfd, EBADF, pidfd, 999, 0);
        CASE("pidfd_getfd.bad_flags", pidfd_getfd, EINVAL, pidfd, rp[0], 1);
        CASE("pidfd_getfd.not_pidfd", pidfd_getfd, EBADF, rp[0], rp[0], 0);
        if (copy >= 0) {
            CALL("kcmp.file_same", kcmp, WANT_OK, self_pid, self_pid, KCMP_FILE, copy, rp[0]);
            volatile_case();
            why("0: the descriptor taken from the child is the same open file");
            DONE();
            close((int)copy);
        }
        CALL("kcmp.file_child", kcmp, WANT_OK, self_pid, child, KCMP_FILE, rp[0], rp[0]);
        volatile_case();
        why("0: the child inherited the same open file");
        DONE();

        CASE("pidfd_send_signal.probe", pidfd_send_signal, WANT_OK, pidfd, 0, NULL, 0);
        memset(&info, 0, sizeof info);
        info.si_signo = 0;
        info.si_code = SI_QUEUE;
        info.si_pid = (pid_t)self_pid;
        info.si_uid = getuid();
        CALL("pidfd_send_signal.queue_info", pidfd_send_signal, WANT_OK, pidfd, 0, &info, 0);
        in_key("signal.siginfo", &info, sizeof info);
        volatile_case();
        why("signal 0 with an SI_QUEUE siginfo: a permission check, nothing is delivered");
        DONE();
        info.si_code = SI_USER;
        CALL("pidfd_send_signal.forged_info", pidfd_send_signal, EPERM, pidfd, 0, &info, 0);
        in_key("signal.siginfo", &info, sizeof info);
        volatile_case();
        why("a siginfo with si_code >= 0 may only be sent to oneself");
        DONE();
        CASE("pidfd_send_signal.bad_flags", pidfd_send_signal, EINVAL, pidfd, 0, NULL, 0x80);
        CASE("pidfd_send_signal.two_scopes", pidfd_send_signal, EINVAL, pidfd, 0, NULL,
             PIDFD_SIGNAL_THREAD | PIDFD_SIGNAL_THREAD_GROUP);
        CASE("pidfd_send_signal.not_pidfd", pidfd_send_signal, EBADF, rp[0], 0, NULL, 0);
        CASE("pidfd_send_signal.badf", pidfd_send_signal, EBADF, 999, 0, NULL, 0);
        if (self >= 0)
            CASE("pidfd_send_signal.self_probe", pidfd_send_signal, WANT_OK, self, 0, NULL, 0);
        CALL("pidfd_send_signal.terminate", pidfd_send_signal, WANT_OK, pidfd, SIGTERM, NULL, 0);
        why("SIGTERM to our own child, waiting in pause()");
        DONE();
        struct pollfd exited = {(int)pidfd, POLLIN, 0}, exited_in;
        memcpy(&exited_in, &exited, sizeof exited);
        CALL("poll.pidfd_exit", poll, WANT_OK, &exited, 1, 2000);
        in_buf(0, &exited_in, sizeof exited_in);
        out_buf(0, &exited, sizeof exited);
        why("a pidfd becomes readable once its process has exited");
        DONE();
    } else {
        kill(child, SIGKILL);
    }
    pid_t got;
    do
        got = waitpid(child, &status, 0);
    while (got < 0 && errno == EINTR);
    if (got != child || !WIFSIGNALED(status) || WTERMSIG(status) != SIGTERM)
        ora_fail("events: the pidfd child did not end with SIGTERM");
    if (pidfd >= 0) {
        CASE("pidfd_send_signal.reaped", pidfd_send_signal, ESRCH, pidfd, 0, NULL, 0);
        close((int)pidfd);
    }
    if (self >= 0)
        close((int)self);
    if (thread >= 0)
        close((int)thread);
}

void area_events(void)
{
    regular = open("ev-file", O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0600);
    if (regular < 0) {
        ora_fail("events: create ev-file");
        return;
    }
    if (write(regular, "EVENTS", 6) != 6)
        ora_fail("events: write ev-file");
    pipe_cases();
    poll_cases();
    select_cases();
    epoll_cases();
    counter_cases();
    notify_cases();
    ioctl_cases();
    userfaultfd_cases();
    kcmp_cases();
    pidfd_cases();
    close(ev_epoll);
    close(rp[0]);
    close(rp[1]);
    close(ep[0]);
    close(ep[1]);
    close(regular);
}
