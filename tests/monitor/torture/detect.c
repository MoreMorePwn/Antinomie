// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// detect.c — process starts, file names and connections that public SigmaHQ
// Linux rules describe. Every command is harmless; the rules match its shape.
// The commands are the ones the feature sample verified against SigmaHQ.
#include "torture.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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

// Runs a tool directly (not through a shell), so the rule sees its own
// Image and CommandLine.
static int tool(char *const argv[])
{
    if (!have(argv[0]))
        return 0;
    return run_wait(argv) >= 0;
}

MODULE(detect_sigma)
{
    const char *name = "detect-sigma";
    note(name, "install SigmaHQ Linux in the Rule manager and set the Sigma Python");
    if (chdir(options->workdir) < 0) {
        fail(name, "work directory: %s", strerror(errno));
        return 1;
    }
    long rounds = scaled(options, 1), ran = 0;
    for (long round = 0; round < rounds; round++) {
        // Discovery: system, account, group, file, container and network.
        ran += tool((char *[]){"uname", "-a", NULL});
        ran += tool((char *[]){"hostname", NULL});
        ran += tool((char *[]){"uptime", NULL});
        ran += tool((char *[]){"id", NULL});
        ran += tool((char *[]){"groups", NULL});
        ran += tool((char *[]){"who", NULL});
        ran += tool((char *[]){"ip", "addr", NULL});
        ran += tool((char *[]){"find", ".", "-perm", "-4000", "-type", "f", NULL});
        ran += tool((char *[]){"ls", "-R", "/etc/default", NULL});
        ran += tool((char *[]){"cat", "/etc/passwd", NULL});
        ran += tool((char *[]){"cat", "/etc/group", NULL});
        ran += tool((char *[]){"cat", "/proc/1/cgroup", NULL});
        ran += tool((char *[]){"crontab", "-l", NULL});
        ran += tool((char *[]){"mkfifo", "./named-pipe", NULL});
        ran += tool((char *[]){"rm", "-f", "./named-pipe", NULL});
        ran += tool((char *[]){"nohup", "true", NULL});
        // Pipelines whose whole command line the rules read. The decoded
        // text is "echo antinomie-torture".
        ran += tool((char *[]){"sh", "-c", "echo ZWNobyBhbnRpbm9taWUtdG9ydHVyZQo= | base64 -d | sh", NULL});
        ran += tool((char *[]){"sh", "-c", "uname -m | grep x86_64", NULL});
    }
    pass(name, "%ld discovery and decoding commands, each started directly", ran);
    // File names the file_event rules know: a base64 command in a name, and
    // the Triple Cross rootkit's lock file and persistence names.
    int files = 0;
    files += write_file("{echo,YW50aW5vbWllLXRvcnR1cmU=}|{base64,-d}", "", 0, 0600) == 0;
    files += write_file("/tmp/rootlog", "", 0, 0600) == 0;
    unlink("/tmp/rootlog");
    files += write_file("ebpfbackdoor", "", 0, 0600) == 0;
    unlink("ebpfbackdoor");
    pass(name, "%d of 3 rule-named files created and removed", files);
    // Execution from /tmp and /dev/shm: a copy of this program.
    char self[4096];
    ssize_t self_len = readlink("/proc/self/exe", self, sizeof self - 1);
    if (self_len > 0) {
        self[self_len] = 0;
        const char *places[] = {"/tmp/antinomie-torture-tmp-exec", "/dev/shm/antinomie-torture-shm-exec"};
        for (size_t i = 0; i < 2; i++) {
            char *copy[] = {"cp", self, (char *)places[i], NULL};
            if (run_wait(copy) == 0 && chmod(places[i], 0700) == 0) {
                char *start[] = {(char *)places[i], "--child", "instant-exit", NULL};
                if (run_wait(start) == 0)
                    pass(name, "executed a copy from %s", places[i]);
            }
            unlink(places[i]);
        }
    }
    // network_connection: connects to ports malware calls back on. The
    // address is TEST-NET-1 (192.0.2.1, documentation only): nothing answers,
    // and an in-progress connect is already a recorded connection.
    static const int ports[] = {4444, 2222, 888, 6789};
    int started = 0;
    for (size_t i = 0; i < sizeof ports / sizeof ports[0]; i++) {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        struct sockaddr_in target = {.sin_family = AF_INET, .sin_port = htons((uint16_t)ports[i])};
        inet_pton(AF_INET, "192.0.2.1", &target.sin_addr);
        if (fd >= 0 && (connect(fd, (struct sockaddr *)&target, sizeof target) == 0 ||
                        errno == EINPROGRESS))
            started++;
        if (fd >= 0)
            close(fd);
    }
    pass(name, "%d connects to 192.0.2.1 on 4444, 2222, 888 and 6789 (suspicious callback ports)",
         started);
    if (options->public_network && have("bash")) {
        char *bash[] = {"bash", "-c", "exec 3<>/dev/tcp/example.com/80 && echo connected", NULL};
        if (run_wait(bash) == 0)
            pass(name, "bash /dev/tcp connection to example.com (back-connect shell rule)");
    } else {
        note(name, "the bash /dev/tcp rule needs a completed connection: pass --public");
    }
    // A setuid bit set and cleared on an empty file that is never run; the
    // chown only succeeds as root.
    write_file("setuid.bin", "", 0, 0600);
    tool((char *[]){"sh", "-c",
                    "chown root ./setuid.bin 2>/dev/null; chmod u+s ./setuid.bin; chmod u-s ./setuid.bin",
                    NULL});
    count("sigma-shaped commands", (unsigned long long)ran);
    return 0;
}
