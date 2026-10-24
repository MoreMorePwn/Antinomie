// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// impact.c — lateral movement, impact, real-path probes and the --wide scan.
//
// Everything that reaches the network is bounded and aimed at --host (and
// only when that is a private address) or, with --wide, at the documentation
// block 203.0.113.0/24. Everything that rewrites files works on files this
// run just made in its work directory. The commands that would do harm
// (xmrig, shutdown, lvremove, modprobe, ...) are exec stand-ins: this binary
// started with that argument vector, which does nothing.
#include "samples.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static long now_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

// ---- lateral-sim ----------------------------------------------------------------------

#define SWEEP_PORTS 24
#define LOGIN_ATTEMPTS 12

SCENARIO(lateral_sim)
{
    const char *name = "lateral-sim";
    const char *host = sample_host(options);
    if (!sample_is_private(host)) {
        sample_skip(name, "refused: --host %s is not a private address, so no port sweep or login "
                       "burst is sent to it", host);
        return 0;
    }
    // Known hosts first: a connect to port 22 after reading them is the spread shape.
    char directory[600], known[700];
    int read_known = 0;
    if (sample_path(directory, sizeof directory, options->workdir, ".ssh") == 0 &&
        sample_mkdir_p(directory) == 0 && sample_path(known, sizeof known, directory, "known_hosts") == 0 &&
        sample_write_text(known, "10.0.2.2 ssh-ed25519 AAAAANTINOMIEDEMO\n") == 0) {
        char buffer[256];
        int fd = open(known, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            read_known = read(fd, buffer, sizeof buffer) > 0;
            close(fd);
        }
    }
    int started = 0;
    for (int i = 0; i < SWEEP_PORTS; i++)
        started += sample_touch_port(host, 20001 + i) == 0;
    int tried = 0;
    for (int i = 0; i < LOGIN_ATTEMPTS; i++)
        tried += sample_touch_port(host, i % 2 ? 22 : 23) == 0;
    char target[64];
    snprintf(target, sizeof target, "analyst@%s", host);
    char *const ssh[] = {"ssh", "-o", "BatchMode=yes", target, "id", NULL};
    char *const hydra[] = {"hydra", "-l", "root", "-P", "words.txt", "ssh://10.0.2.2", NULL};
    int ran = (sample_spoof(ssh, NULL) == 0) + (sample_spoof(hydra, NULL) == 0);
    sample_pass(name, "%d/%d ports of %s tried, %d/%d login-port connects, known_hosts %s, %d/2 "
                   "stand-ins (ssh, hydra)",
             started, SWEEP_PORTS, host, tried, LOGIN_ATTEMPTS, read_known ? "read" : "unread",
             ran);
    if (!strncmp(host, "127.", 4))
        sample_note(name, "loopback connects are not counted by the scan and login rules; use "
                       "the NAT host or another private address");
    return 0;
}

// ---- impact-sim -------------------------------------------------------------------------

#define STORM_FORKS 230
#define RANSOM_FILES 24
#define NOTE_DIRECTORIES 4
#define BURST_PACKETS 1120

SCENARIO(impact_sim)
{
    const char *name = "impact-sim";
    const char *host = sample_host(options);
    int steps = 0, done = 0;
#define STEP(expression)                                                                           \
    do {                                                                                           \
        steps++;                                                                                   \
        done += (expression) ? 1 : 0;                                                              \
    } while (0)
    char path[700], other[700], directory[600];

    // A fork storm: vfork children that exit at once, reaped as they go.
    long started = now_ms();
    int forked = 0;
    for (int i = 0; i < STORM_FORKS; i++) {
        pid_t child = vfork();
        if (child == 0)
            _exit(0);
        if (child > 0)
            forked++;
        if (i % 8 == 7)
            while (waitpid(-1, NULL, WNOHANG) > 0)
                ;
    }
    while (waitpid(-1, NULL, 0) > 0)
        ;
    long storm_ms = now_ms() - started;
    STEP(forked == STORM_FORKS);

    // Files renamed to one new extension, and a note in several directories.
    if (sample_path(directory, sizeof directory, options->workdir, "victim-docs") == 0 &&
        sample_mkdir_p(directory) == 0) {
        int renamed = 0;
        for (int i = 0; i < RANSOM_FILES; i++) {
            char leaf[64];
            snprintf(leaf, sizeof leaf, "file%02d.txt", i);
            sample_path(path, sizeof path, directory, leaf);
            snprintf(leaf, sizeof leaf, "file%02d.txt.locked", i);
            sample_path(other, sizeof other, directory, leaf);
            if (sample_write_text(path, "ANTINOMIE-DEMO contents\n") == 0 && rename(path, other) == 0)
                renamed++;
        }
        STEP(renamed == RANSOM_FILES);
    }
    int notes = 0;
    for (int i = 0; i < NOTE_DIRECTORIES; i++) {
        char leaf[48];
        snprintf(leaf, sizeof leaf, "victim-docs/sub%d", i);
        if (sample_path(directory, sizeof directory, options->workdir, leaf) == 0 &&
            sample_mkdir_p(directory) == 0 &&
            sample_path(path, sizeof path, directory, "HOW_TO_DECRYPT.txt") == 0 &&
            sample_write_text(path, "ANTINOMIE-DEMO: this is a test note, nothing is encrypted\n") == 0)
            notes++;
    }
    STEP(notes == NOTE_DIRECTORIES);

    // A backup the run made, removed again.
    if (sample_path(directory, sizeof directory, options->workdir, "backups") == 0 &&
        sample_mkdir_p(directory) == 0 && sample_path(path, sizeof path, directory, "database.bak") == 0 &&
        sample_write_text(path, "ANTINOMIE-DEMO backup\n") == 0)
        STEP(unlink(path) == 0);

    // A discard ioctl (BLKDISCARD) on a regular file: ENOTTY, nothing is erased.
    if (sample_path(path, sizeof path, options->workdir, "disk.img") == 0 &&
        sample_write_text(path, "ANTINOMIE-DEMO\n") == 0) {
        int fd = open(path, O_RDWR | O_CLOEXEC);
        if (fd >= 0) {
            unsigned long long range[2] = {0, 4096};
            STEP(ioctl(fd, 0x1277 /* BLKDISCARD */, range) == -1);
            close(fd);
        }
    }

    // A burst of tiny datagrams to the listener, for private addresses only.
    int burst = 0;
    if (sample_is_private(host)) {
        struct sockaddr_in target;
        memset(&target, 0, sizeof target);
        target.sin_family = AF_INET;
        target.sin_port = htons((uint16_t)sample_port(options, SAMPLE_UDP_PORT));
        inet_pton(AF_INET, host, &target.sin_addr);
        int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd >= 0) {
            for (int i = 0; i < BURST_PACKETS; i++)
                if (sendto(fd, "ping", 4, 0, (struct sockaddr *)&target, sizeof target) == 4)
                    burst++;
            close(fd);
        }
        STEP(burst == BURST_PACKETS);
    } else {
        sample_skip(name, "datagram burst refused: --host %s is not a private address", host);
    }

    static const struct spoof tools[] = {
        {"impact.miner", {"xmrig", "-o", "stratum+tcp://pool.antinomie.invalid:3333", "-u",
                          "4ANTINOMIEDEMO", NULL}},
        {"impact.miner_tuning", {"modprobe", "msr", NULL}},
        {"impact.service_stop", {"systemctl", "stop", "antinomie-demo-db", NULL}},
        {"impact.reboot", {"shutdown", "-r", "now", NULL}},
        {"impact.reboot", {"systemctl", "reboot", NULL}},
        {"impact.inhibit_recovery", {"lvremove", "-f", "vg0/snapshot", NULL}},
        {"impact.inhibit_recovery", {"btrfs", "subvolume", "delete", "/mnt/snap", NULL}},
        {"impact.inhibit_recovery", {"zfs", "destroy", "tank/snap", NULL}},
    };
    int ran = sample_spoof_all(name, tools, sizeof tools / sizeof tools[0]);
    steps += (int)(sizeof tools / sizeof tools[0]);
    done += ran;
#undef STEP
    sample_pass(name, "%d/%d impact steps: %d vforks in %ld ms, %d files renamed to .locked, "
                   "%d notes, a backup removed, %d datagrams, %d/%zu stand-ins",
             done, steps, forked, storm_ms, RANSOM_FILES, notes, burst, ran,
             sizeof tools / sizeof tools[0]);
    if (storm_ms > 1000)
        sample_note(name, "the fork storm took %ld ms: impact.fork_bomb needs 200 forks in a second",
                 storm_ms);
    sample_note(name, "nothing was encrypted, mined, stopped or shut down; only files made in this "
                   "run were renamed or removed");
    return 0;
}

// ---- real-path-probes ------------------------------------------------------------------

struct probe {
    const char *rule;
    const char *path;
    int flags;
    // Probes for writing must name something that does not exist.
    int writes;
};

#define W (O_WRONLY | O_NOFOLLOW | O_CLOEXEC)
#define R (O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC)

static const struct probe probes[] = {
    {"persistence.cron", "/etc/cron.d/antinomie-demo", W, 1},
    {"persistence.at_job", "/var/spool/cron/atjobs/antinomie-demo", W, 1},
    {"persistence.systemd", "/etc/systemd/system/antinomie-demo.service", W, 1},
    {"persistence.rc_init", "/etc/init.d/antinomie-demo", W, 1},
    {"persistence.event_script", "/etc/update-motd.d/99-antinomie-demo", W, 1},
    {"persistence.shell_profile", "/etc/profile.d/antinomie-demo.sh", W, 1},
    {"persistence.ssh_authorized_keys", "/etc/ssh/sshd_config.d/antinomie-demo.conf", W, 1},
    {"persistence.xdg_autostart", "/etc/xdg/autostart/antinomie-demo.desktop", W, 1},
    {"persistence.udev", "/etc/udev/rules.d/99-antinomie-demo.rules", W, 1},
    {"persistence.pam", "/etc/pam.d/antinomie-demo", W, 1},
    {"persistence.module_autoload", "/etc/modules-load.d/antinomie-demo.conf", W, 1},
    {"persistence.apt_hook", "/etc/apt/apt.conf.d/99antinomie-demo", W, 1},
    {"persistence.web_shell", "/var/www/antinomie-demo.php", W, 1},
    {"persistence.config_write", "/etc/antinomie-demo.conf", W, 1},
    {"injection.ld_so_preload", "/etc/ld.so.preload", W, 1},
    {"injection.ld_so_conf", "/etc/ld.so.conf.d/antinomie-demo.conf", W, 1},
    {"privilege.sudoers", "/etc/sudoers.d/antinomie-demo", W, 1},
    {"evasion.audit_disable", "/etc/audit/rules.d/antinomie-demo.rules", W, 1},
    {"evasion.log_clear", "/var/log/antinomie-demo.log", W | O_TRUNC, 1},
    {"impact.block_device_write", "/dev/sdz9", W, 1},
    {"impact.miner_tuning", "/sys/kernel/mm/hugepages/antinomie-demo", W, 1},
    {"credential.shadow_read", "/etc/shadow", R, 0},
    {"collection.keylog", "/dev/input/event0", R, 0},
    {"collection.screen_capture", "/dev/fb0", R, 0},
    {"collection.av_capture", "/dev/video0", R, 0},
    {"collection.av_capture", "/dev/snd/pcmC0D0c", R, 0},
};

SCENARIO(real_path_probes)
{
    const char *name = "real-path-probes";
    (void)options;
    int opened = 0, refused = 0, skipped = 0;
    for (size_t i = 0; i < sizeof probes / sizeof probes[0]; i++) {
        const struct probe *probe = &probes[i];
        struct stat info;
        if (probe->writes && lstat(probe->path, &info) == 0) {
            // Never open an existing file for writing, not even without writing to it.
            sample_note(name, "%s exists: not opened for %s", probe->path, probe->rule);
            skipped++;
            continue;
        }
        int fd = open(probe->path, probe->flags);
        if (fd >= 0) {
            // Opened and closed. No read, no write.
            close(fd);
            opened++;
        } else {
            refused++;
        }
    }
    sample_pass(name, "%zu paths probed: %d opened (and closed unread), %d refused, %d skipped "
                   "because they exist", sizeof probes / sizeof probes[0], opened, refused,
             skipped);
    sample_note(name, "write probes name files that do not exist, use no O_CREAT, and are skipped "
                   "if the path exists; read probes never call read()");
    return 0;
}

// ---- net-wide ---------------------------------------------------------------------------------

#define WIDE_HOSTS 12
#define UPLOAD_PACKETS 800
#define UPLOAD_SIZE 1400

SCENARIO(net_wide)
{
    const char *name = "net-wide";
    (void)options;
    char address[32];
    int started = 0;
    // Commonly attacked service ports on three hosts, then one port on twelve.
    for (int i = 0; i < 3; i++) {
        snprintf(address, sizeof address, SAMPLE_TESTNET_PREFIX "%d", 10 + i);
        started += sample_touch_port(address, 6379) == 0;
    }
    for (int i = 0; i < WIDE_HOSTS; i++) {
        snprintf(address, sizeof address, SAMPLE_TESTNET_PREFIX "%d", 20 + i);
        started += sample_touch_port(address, 8080) == 0;
    }
    // A connected UDP socket to a documentation address, sent 1.1 MiB of zeros.
    long sent = 0;
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd >= 0) {
        struct sockaddr_in target;
        memset(&target, 0, sizeof target);
        target.sin_family = AF_INET;
        target.sin_port = htons(9);
        inet_pton(AF_INET, SAMPLE_TESTNET_PREFIX "9", &target.sin_addr);
        static const char zeros[UPLOAD_SIZE];
        if (connect(fd, (struct sockaddr *)&target, sizeof target) == 0)
            for (int i = 0; i < UPLOAD_PACKETS; i++) {
                ssize_t written = send(fd, zeros, sizeof zeros, 0);
                if (written > 0)
                    sent += written;
            }
        close(fd);
    }
    if (started == 0 && sent == 0)
        sample_unavailable(name, "no route toward %s0/24 (%s): the three rules will not fire",
                        SAMPLE_TESTNET_PREFIX, strerror(errno));
    sample_pass(name, "%d connects started toward %s0/24 and %ld bytes of zeros sent to %s9:9",
             started, SAMPLE_TESTNET_PREFIX, sent, SAMPLE_TESTNET_PREFIX);
    sample_note(name, "RFC 5737 documentation addresses: nothing answers, and the packets are "
                   "dropped by the first router");
    return 0;
}
