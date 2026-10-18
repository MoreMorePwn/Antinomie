// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// detect.c — command lines, file names and connections that SigmaHQ Linux
// rules describe. Every command is harmless; the rules match its shape.
#include "torture.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int have(const char *tool)
{
    char path[256];
    const char *dirs[] = {"/usr/bin", "/bin", "/usr/sbin", "/sbin"};
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++) {
        snprintf(path, sizeof path, "%s/%s", dirs[i], tool);
        if (access(path, X_OK) == 0)
            return 1;
    }
    return 0;
}

static long sh(const char *command)
{
    char *argv[] = {"sh", "-c", (char *)command, NULL};
    return run_wait(argv) >= 0;
}

MODULE(detect_sigma)
{
    const char *name = "detect-sigma";
    note(name, "install SigmaHQ Linux in the Rule manager and set the Sigma Python");
    long rounds = scaled(options, 1);
    long ran = 0;
    for (long round = 0; round < rounds; round++) {
        // Discovery (process_creation: uname, id, hostname, groups, ls, find, crontab).
        static const char *discovery[] = {
            "uname -a",
            "uname -m | grep x86_64",
            "id",
            "whoami",
            "hostname",
            "groups",
            "cat /etc/passwd",
            "cat /etc/group",
            "cat /proc/1/cgroup",
            "ls -la /tmp",
            "find /usr/bin -maxdepth 1 -perm -4000",
            "crontab -l",
            "ip addr",
            "who",
            "uptime",
        };
        for (size_t i = 0; i < sizeof discovery / sizeof discovery[0]; i++)
            ran += sh(discovery[i]);
        // Encoded command decoded and piped to a shell: echo antinomie-torture.
        if (have("base64"))
            ran += sh("echo ZWNobyBhbnRpbm9taWUtdG9ydHVyZQo= | base64 -d | sh");
        // A hidden file and a FIFO in /tmp; nohup (file_event / process_creation).
        ran += sh("touch /tmp/.antinomie-torture-hidden && rm -f /tmp/.antinomie-torture-hidden");
        ran += sh("mkfifo /tmp/antinomie-torture-fifo && rm -f /tmp/antinomie-torture-fifo");
        ran += sh("nohup true >/dev/null 2>&1");
        // A very long command line, near what the recorder keeps.
        size_t len = options->level == LEVEL_LIGHT ? 1024 : options->level == LEVEL_HEAVY ? 8192 : 65536;
        char *longline = malloc(len + 64);
        if (longline) {
            int prefix = snprintf(longline, 64, "echo antinomie-torture-long ");
            memset(longline + prefix, 'x', len);
            longline[prefix + len] = 0;
            ran += sh(longline);
            free(longline);
        }
    }
    pass(name, "%ld discovery, decoding and file commands", ran);
    // Execution from /tmp and /dev/shm: a copy of this program.
    char self[4096];
    ssize_t self_len = readlink("/proc/self/exe", self, sizeof self - 1);
    if (self_len > 0) {
        self[self_len] = 0;
        const char *places[] = {"/tmp/antinomie-torture-tmp-exec", "/dev/shm/antinomie-torture-shm-exec"};
        for (size_t i = 0; i < 2; i++) {
            char command[8192];
            snprintf(command, sizeof command, "cp '%s' %s && chmod 700 %s && %s --child instant-exit",
                     self, places[i], places[i], places[i]);
            if (sh(command))
                pass(name, "executed a copy from %s", places[i]);
            unlink(places[i]);
        }
    }
    // network_connection: connects from a shell through /dev/tcp.
    char gateway[64];
    if (have("bash") && default_gateway(gateway, sizeof gateway) == 0) {
        static const int ports[] = {4444, 1337, 31337};
        for (size_t i = 0; i < 3; i++) {
            char command[256];
            snprintf(command, sizeof command,
                     "bash -c 'exec 3<>/dev/tcp/%s/%d' 2>/dev/null; true", gateway, ports[i]);
            sh(command);
        }
        pass(name, "bash /dev/tcp connects to %s on 4444, 1337 and 31337", gateway);
    } else {
        unavailable(name, "no bash or no gateway for network_connection");
    }
    if (need_root(options, name, "chown root + chmod u+s on a copy"))
        sh("cp /bin/true /tmp/antinomie-torture-suid && chown root /tmp/antinomie-torture-suid && "
           "chmod u+s /tmp/antinomie-torture-suid && rm -f /tmp/antinomie-torture-suid");
    count("sigma-shaped commands", (unsigned long long)ran);
    return 0;
}
