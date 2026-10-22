// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
/* A benign program that exercises as many Antinomie views as one run can:
 * triage (processes, files, network, BPF), community-rule detection and
 * static analysis. It contains no malware and no malware signatures; rule
 * matches come from behavior that the rules describe by name or location.
 *
 * Run it only in a disposable Antinomie guest. It copies itself to
 * /tmp/antinomie-feature-sample and keeps all file changes in a fresh
 * /tmp/antinomie-feature-XXXXXX directory, except two empty files that
 * rules look for by name (/tmp/rootlog, /dev/shm/antinomie-shm-true) and,
 * when run as root, /etc/antinomie-feature-sample.conf; it removes them again. Public network requests go only to example.com
 * and well-known IP-check and IDS-test services; --offline skips them.
 *
 * Build with tests/monitor/build-feature-sample.sh. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include "feature-sample-payloads.h"

#define INSTALL_PATH "/tmp/antinomie-feature-sample"
#define USER_AGENT "Mozilla/5.0 (X11; Linux x86_64) AntinomieFeatureSample/1.0"

static volatile unsigned char memory_marker[] = "ANTINOMIE_FEATURE_SAMPLE_v1";
static const char config_text[] =
    "beacon=http://api.ipify.org/?format=json;interval=60;marker=ANTINOMIE_FEATURE_SAMPLE_v1";
static int unavailable;
static int offline;

static void check(const char *label, int success)
{
    int error = success ? 0 : errno;
    printf("%-12s %s errno=%d\n", success ? "PASS" : "UNAVAILABLE", label, error);
    if (!success) unavailable++;
}

/* ---- Encoding routines for static capability detection ---------------- */

static void xor_buffer(uint8_t *data, size_t len, const uint8_t *key, size_t key_len)
{
    for (size_t i = 0; i < len; i++) data[i] ^= key[i % key_len];
}

static size_t base64_encode(const uint8_t *in, size_t len, char *out)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < len) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < len) v |= in[i + 2];
        out[o++] = alphabet[(v >> 18) & 63];
        out[o++] = alphabet[(v >> 12) & 63];
        out[o++] = i + 1 < len ? alphabet[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < len ? alphabet[v & 63] : '=';
    }
    out[o] = 0;
    return o;
}

struct rc4 { uint8_t s[256]; uint8_t i, j; };

static void rc4_init(struct rc4 *state, const uint8_t *key, size_t key_len)
{
    for (int i = 0; i < 256; i++) state->s[i] = (uint8_t)i;
    uint8_t j = 0;
    for (int i = 0; i < 256; i++) {
        j = (uint8_t)(j + state->s[i] + key[i % key_len]);
        uint8_t t = state->s[i];
        state->s[i] = state->s[j];
        state->s[j] = t;
    }
    state->i = state->j = 0;
}

static void rc4_crypt(struct rc4 *state, uint8_t *data, size_t len)
{
    for (size_t n = 0; n < len; n++) {
        state->i = (uint8_t)(state->i + 1);
        state->j = (uint8_t)(state->j + state->s[state->i]);
        uint8_t t = state->s[state->i];
        state->s[state->i] = state->s[state->j];
        state->s[state->j] = t;
        data[n] ^= state->s[(uint8_t)(state->s[state->i] + state->s[state->j])];
    }
}

static uint32_t fnv1a(const uint8_t *data, size_t len)
{
    uint32_t hash = 0x811c9dc5u;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 0x01000193u;
    }
    return hash;
}

/* ---- Helpers ----------------------------------------------------------- */

static int write_file(const char *path, const void *data, size_t len, mode_t mode)
{
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, mode);
    if (fd < 0) return -1;
    ssize_t written = write(fd, data, len);
    close(fd);
    return written == (ssize_t)len ? 0 : -1;
}

static ssize_t read_file(const char *path, char *buffer, size_t size)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t len = read(fd, buffer, size - 1);
    close(fd);
    if (len >= 0) buffer[len] = 0;
    return len;
}

/* copy_file_range, or sendfile where the kernel refuses a cross-filesystem copy. */
static int copy_fd(int in, int out, size_t size)
{
    if (copy_file_range(in, NULL, out, NULL, size, 0) == (ssize_t)size) return 1;
    off_t offset = 0;
    return sendfile(out, in, &offset, size) == (ssize_t)size;
}

static const char *find_tool(const char *name, char *path, size_t size)
{
    static const char *const directories[] = {"/usr/bin", "/bin", "/usr/sbin", "/sbin"};
    for (size_t i = 0; i < sizeof(directories) / sizeof(*directories); i++) {
        snprintf(path, size, "%s/%s", directories[i], name);
        if (access(path, X_OK) == 0) return path;
    }
    return NULL;
}

/* Run a program with its output discarded; returns its exit status. */
static int run(const char *path, char *const argv[])
{
    pid_t child = fork();
    if (child == 0) {
        int null = open("/dev/null", O_WRONLY);
        if (null >= 0) {
            dup2(null, STDOUT_FILENO);
            dup2(null, STDERR_FILENO);
            close(null);
        }
        execv(path, argv);
        _exit(127);
    }
    int status = 0;
    if (child < 0 || waitpid(child, &status, 0) != child) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void run_tool(const char *name, char *const argv[])
{
    char path[64], label[96];
    snprintf(label, sizeof(label), "tool %s", name);
    if (!find_tool(name, path, sizeof(path))) {
        errno = ENOENT;
        check(label, 0);
        return;
    }
    check(label, run(path, argv) >= 0);
}

/* ---- Startup: run from /tmp ------------------------------------------- */

static void install_and_exec(int argc, char **argv)
{
    char self[4096];
    ssize_t len = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (len < 0) return;
    self[len] = 0;
    if (strcmp(self, INSTALL_PATH) != 0) {
        /* A kernel-side copy; a running copy of the target is replaced, not rewritten. */
        int in = open(self, O_RDONLY);
        unlink(INSTALL_PATH);
        int out = open(INSTALL_PATH, O_CREAT | O_EXCL | O_WRONLY, 0755);
        struct stat st;
        int copied = in >= 0 && out >= 0 && fstat(in, &st) == 0 &&
                     sendfile(out, in, NULL, (size_t)st.st_size) == st.st_size;
        if (in >= 0) close(in);
        if (out >= 0) close(out);
        if (!copied) return;
    }
    char **arguments = calloc((size_t)argc + 2, sizeof(char *));
    if (!arguments) return;
    arguments[0] = INSTALL_PATH;
    arguments[1] = "--stage2";
    for (int i = 1; i < argc; i++) arguments[i + 1] = argv[i];
    execv(INSTALL_PATH, arguments);
    free(arguments);
}

/* ---- Evidence ---------------------------------------------------------- */

static void environment_checks(void)
{
    char buffer[8192];
    /* A tracer check in a short-lived child, so no later exec stops on SIGTRAP. */
    pid_t child = fork();
    if (child == 0) _exit(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0 ? 0 : 1);
    int status = 0;
    check("ptrace TRACEME check", child > 0 && waitpid(child, &status, 0) == child);
    ssize_t len = read_file("/proc/self/status", buffer, sizeof(buffer));
    check("read TracerPid", len > 0 && strstr(buffer, "TracerPid:") != NULL);
    len = read_file("/proc/cpuinfo", buffer, sizeof(buffer));
    printf("             hypervisor flag %s\n", len > 0 && strstr(buffer, " hypervisor") ? "present" : "absent");
    len = read_file("/sys/class/dmi/id/product_name", buffer, sizeof(buffer));
    printf("             DMI product %s", len > 0 ? buffer : "unavailable\n");
    printf("             container marker %s\n", access("/.dockerenv", F_OK) == 0 ? "present" : "absent");
}

static void discovery(void)
{
    char buffer[8192];
    struct utsname name;
    check("uname", uname(&name) == 0);
    char host[256];
    check("gethostname", gethostname(host, sizeof(host)) == 0);
    struct passwd *user = getpwuid(getuid());
    printf("             user %s on %s %s %s\n", user ? user->pw_name : "?", host,
           name.sysname, name.release);
    check("read /etc/passwd", read_file("/etc/passwd", buffer, sizeof(buffer)) > 0);
    check("read /etc/os-release", read_file("/etc/os-release", buffer, sizeof(buffer)) > 0);
    check("read /proc/self/maps", read_file("/proc/self/maps", buffer, sizeof(buffer)) > 0);
    int shadow = open("/etc/shadow", O_RDONLY);
    printf("             /etc/shadow open %s\n", shadow >= 0 ? "allowed (root)" : strerror(errno));
    if (shadow >= 0) close(shadow);
    DIR *directory = opendir("/etc");
    int entries = 0;
    if (directory) {
        while (readdir(directory)) entries++;
        closedir(directory);
    }
    check("enumerate /etc", entries > 0);
}

static void tools(void)
{
    run_tool("uname", (char *[]){"uname", "-a", NULL});
    run_tool("hostname", (char *[]){"hostname", NULL});
    run_tool("uptime", (char *[]){"uptime", NULL});
    run_tool("id", (char *[]){"id", NULL});
    run_tool("groups", (char *[]){"groups", NULL});
    run_tool("who", (char *[]){"who", NULL});
    run_tool("ip", (char *[]){"ip", "addr", NULL});
    run_tool("find", (char *[]){"find", ".", "-perm", "-4000", "-type", "f", NULL});
    run_tool("ls", (char *[]){"ls", "-R", "/etc/default", NULL});
    run_tool("cat", (char *[]){"cat", "/etc/passwd", NULL});
    run_tool("cat", (char *[]){"cat", "/etc/group", NULL});
    run_tool("cat", (char *[]){"cat", "/proc/1/cgroup", NULL});
    run_tool("crontab", (char *[]){"crontab", "-l", NULL});
    run_tool("mkfifo", (char *[]){"mkfifo", "./named-pipe", NULL});
    run_tool("rm", (char *[]){"rm", "-f", "./named-pipe", NULL});
    run_tool("nohup", (char *[]){"nohup", "true", NULL});
    run_tool("sh", (char *[]){"sh", "-c", "printf 'shell child\\n' > shell.txt; "
                              "(printf 'grandchild\\n' > grandchild.txt) & wait", NULL});
    /* Pipelines whose whole command line the rules read. The decoded text
     * is "echo antinomie-feature-sample". */
    run_tool("sh", (char *[]){"sh", "-c",
                              "echo ZWNobyBhbnRpbm9taWUtZmVhdHVyZS1zYW1wbGU= | base64 -d | sh", NULL});
    run_tool("sh", (char *[]){"sh", "-c", "uname -m | grep x86_64", NULL});
    /* A setuid bit set and cleared on an empty data file that is never run. */
    write_file("setuid.bin", "", 0, 0600);
    run_tool("sh", (char *[]){"sh", "-c", "chown root ./setuid.bin 2>/dev/null; "
                              "chmod u+s ./setuid.bin; chmod u-s ./setuid.bin", NULL});
}

static void dropped_programs(void)
{
    /* A dropped script, executed from the temporary directory. */
    const char script[] = "#!/bin/sh\necho dropped stage ran > ./stage.out\n";
    check("drop stage.sh", write_file("./stage.sh", script, sizeof(script) - 1, 0700) == 0);
    check("run stage.sh", run("./stage.sh", (char *[]){"stage.sh", NULL}) == 0);

    /* A copy of true executed from shared memory, then removed. */
    char path[64];
    if (find_tool("true", path, sizeof(path))) {
        int in = open(path, O_RDONLY);
        int out = open("/dev/shm/antinomie-shm-true", O_CREAT | O_TRUNC | O_WRONLY, 0700);
        struct stat st;
        int copied = in >= 0 && out >= 0 && fstat(in, &st) == 0 &&
                     copy_fd(in, out, (size_t)st.st_size);
        if (in >= 0) close(in);
        if (out >= 0) close(out);
        check("exec from /dev/shm", copied &&
              run("/dev/shm/antinomie-shm-true", (char *[]){"antinomie-shm-true", NULL}) == 0);
        unlink("/dev/shm/antinomie-shm-true");
    }

    /* Fileless execution: the same program from a memfd under a kernel-thread name. */
    if (find_tool("true", path, sizeof(path))) {
        int memory = (int)syscall(SYS_memfd_create, "antinomie-memfd", 0);
        int in = open(path, O_RDONLY);
        struct stat st;
        int copied = memory >= 0 && in >= 0 && fstat(in, &st) == 0 &&
                     sendfile(memory, in, NULL, (size_t)st.st_size) == st.st_size;
        if (in >= 0) close(in);
        pid_t child = copied ? fork() : -1;
        if (child == 0) {
            char *const arguments[] = {"[kworker/0:1H]", NULL};
            char *const environment[] = {NULL};
            fexecve(memory, arguments, environment);
            _exit(127);
        }
        int status = 0;
        check("fexecve memfd", child > 0 && waitpid(child, &status, 0) == child &&
              WIFEXITED(status) && WEXITSTATUS(status) == 0);
        if (memory >= 0) close(memory);
    }
}

static void file_activity(void)
{
    char buffer[512] = {0};
    int fd = open("notes.txt", O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) { check("create notes.txt", 0); return; }
    const char initial[] = "original line\nunchanged line\n";
    check("write", write(fd, initial, sizeof(initial) - 1) == (ssize_t)sizeof(initial) - 1);
    check("pread original", pread(fd, buffer, sizeof(buffer), 0) > 0);
    const char final[] = "MODIFIED line\nunchanged line\n";
    check("pwrite", pwrite(fd, final, sizeof(final) - 1, 0) == (ssize_t)sizeof(final) - 1);
    struct iovec tail[] = {{"appended ", 9}, {"by writev\n", 10}};
    check("writev", writev(fd, tail, 2) == 19);
    check("fallocate", fallocate(fd, 0, 0, 8192) == 0);
    check("ftruncate", ftruncate(fd, (off_t)(sizeof(final) - 1 + 19)) == 0);
    check("fsync", fsync(fd) == 0);
    check("setuid mode on data file", fchmod(fd, 04600) == 0);
    check("restore mode", fchmod(fd, 0600) == 0);
    check("fchown to self", fchown(fd, getuid(), getgid()) == 0);
    close(fd);

    fd = open("notes.txt", O_RDONLY);
    if (fd >= 0) {
        char first[8], second[64];
        struct iovec parts[] = {{first, sizeof(first)}, {second, sizeof(second)}};
        check("readv", readv(fd, parts, 2) > 0);
        close(fd);
    }
    check("setxattr", setxattr("notes.txt", "user.antinomie", "sample", 6, 0) == 0);
    check("removexattr", removexattr("notes.txt", "user.antinomie") == 0);
    struct timespec old[2] = {{.tv_sec = 978307200}, {.tv_sec = 978307200}};
    check("timestomp (utimensat)", utimensat(AT_FDCWD, "notes.txt", old, 0) == 0);
    check("rename", rename("notes.txt", "notes-renamed.txt") == 0);
    check("hard link", link("notes-renamed.txt", "alias.txt") == 0);
    check("symlink", symlink("notes-renamed.txt", "symbolic.txt") == 0);
    check("unlink alias", unlink("alias.txt") == 0);
    check("mkdir", mkdir("staging", 0700) == 0);
    check("rmdir", rmdir("staging") == 0);

    /* Kernel-mediated copies. */
    int in = open("notes-renamed.txt", O_RDONLY);
    int out = open("copy-range.txt", O_CREAT | O_EXCL | O_WRONLY, 0600);
    check("copy_file_range", in >= 0 && out >= 0 && copy_file_range(in, NULL, out, NULL, 4096, 0) > 0);
    if (out >= 0) close(out);
    out = open("copy-sendfile.txt", O_CREAT | O_EXCL | O_WRONLY, 0600);
    off_t offset = 0;
    check("sendfile", in >= 0 && out >= 0 && sendfile(out, in, &offset, 4096) > 0);
    if (out >= 0) close(out);
    if (in >= 0) close(in);

    /* A shared writable mapping written back with msync. */
    fd = open("mapped.bin", O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd >= 0 && ftruncate(fd, 4096) == 0) {
        char *map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (map != MAP_FAILED) {
            memcpy(map, "written through a shared mapping\n", 33);
            check("msync shared mapping", msync(map, 4096, MS_SYNC) == 0);
            munmap(map, 4096);
        }
    }
    if (fd >= 0) close(fd);

    /* An unnamed file given a name afterwards. */
    fd = open(".", O_TMPFILE | O_RDWR, 0600);
    if (fd >= 0) {
        (void)write(fd, "anonymous then linked\n", 22);
        char proc[64];
        snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
        check("O_TMPFILE linkat", linkat(AT_FDCWD, proc, AT_FDCWD, "tmpfile-linked.txt",
                                         AT_SYMLINK_FOLLOW) == 0);
        close(fd);
    }

    /* Created, written and deleted. */
    check("write deleted.txt", write_file("deleted.txt", "short-lived\n", 12, 0600) == 0);
    check("delete deleted.txt", unlink("deleted.txt") == 0);

    /* Names that file-event rules look for; the files stay empty. */
    check("base64-command file name",
          write_file("{echo,YW50aW5vbWllLWZlYXR1cmUtc2FtcGxl}|{base64,-d}", "", 0, 0600) == 0);
    check("rootkit lock-file name", write_file("/tmp/rootlog", "", 0, 0600) == 0);
    unlink("/tmp/rootlog");
    check("rootkit persistence name", write_file("ebpfbackdoor", "", 0, 0600) == 0);
    unlink("ebpfbackdoor");

    errno = 0;
    fd = open("missing-file", O_RDONLY);
    check("expected ENOENT", fd == -1 && errno == ENOENT);
    errno = 0;
}

static void payloads(void)
{
    /* Embedded data that binwalk finds in the executable, also dropped to disk. */
    check("drop payload.gz", write_file("payload.gz", payload_gzip, sizeof(payload_gzip), 0600) == 0);
    check("drop bundle.zip", write_file("bundle.zip", payload_zip, sizeof(payload_zip), 0600) == 0);
    check("drop image.png", write_file("image.png", payload_png, sizeof(payload_png), 0600) == 0);
    printf("             noise block fnv1a %08x\n", fnv1a(payload_noise, sizeof(payload_noise)));

    /* An "encrypted config": RC4, XOR, then Base64. */
    uint8_t config[sizeof(config_text)];
    memcpy(config, config_text, sizeof(config));
    struct rc4 state;
    static const uint8_t key[] = "antinomie-sample-key";
    rc4_init(&state, key, sizeof(key) - 1);
    rc4_crypt(&state, config, sizeof(config) - 1);
    xor_buffer(config, sizeof(config) - 1, (const uint8_t *)"\x5a\xa5", 2);
    char encoded[sizeof(config) * 2];
    size_t len = base64_encode(config, sizeof(config) - 1, encoded);
    check("write config.enc", write_file("config.enc", encoded, len, 0600) == 0);
}

static void memory_activity(void)
{
    memory_marker[0] = 'A';
    void *rwx = mmap(NULL, 8192, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check("RWX mapping", rwx != MAP_FAILED);
    if (rwx != MAP_FAILED) memcpy(rwx, (const void *)memory_marker, sizeof(memory_marker));
    void *code = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code != MAP_FAILED) {
        memset(code, 0xc3, 16); /* ret */
        check("mprotect RW to RX", mprotect(code, 4096, PROT_READ | PROT_EXEC) == 0);
    }
}

/* Calls the Suspicious view flags, each without effect. */
static void suspicious_calls(void)
{
    check("setresuid no-op", setresuid(-1, -1, -1) == 0);
    check("setresgid no-op", setresgid(-1, -1, -1) == 0);
    char copy[sizeof(memory_marker)];
    struct iovec local = {copy, sizeof(copy)};
    struct iovec remote = {(void *)memory_marker, sizeof(memory_marker)};
    check("process_vm_readv self",
          process_vm_readv(getpid(), &local, 1, &remote, 1, 0) == (ssize_t)sizeof(copy));
    int fd = open("/etc/antinomie-feature-sample.conf", O_CREAT | O_EXCL | O_WRONLY, 0600);
    printf("             /etc configuration write %s\n", fd >= 0 ? "allowed (removed)" : strerror(errno));
    if (fd >= 0) {
        close(fd);
        unlink("/etc/antinomie-feature-sample.conf");
    }
}

static void *worker_thread(void *unused)
{
    (void)unused;
    check("thread file", write_file("thread.txt", "worker thread evidence\n", 23, 0600) == 0);
    struct timespec pause = {.tv_nsec = 200 * 1000 * 1000};
    nanosleep(&pause, NULL);
    return NULL;
}

static void process_activity(void)
{
    check("rename process (prctl)", prctl(PR_SET_NAME, "kworker/u8:3", 0, 0, 0) == 0);
    pthread_t thread;
    int result = pthread_create(&thread, NULL, worker_thread, NULL);
    check("worker thread", result == 0);
    if (result == 0) pthread_join(thread, NULL);

    /* A detached grandchild in its own session. */
    pid_t child = fork();
    if (child == 0) {
        setsid();
        if (fork() == 0) {
            write_file("daemon.txt", "detached daemon evidence\n", 25, 0600);
            sleep(1);
            _exit(0);
        }
        _exit(0);
    }
    int status = 0;
    check("daemonize (double fork)", child > 0 && waitpid(child, &status, 0) == child);
}

/* ---- Network ----------------------------------------------------------- */

static int connect_to(const char *host, const char *port)
{
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM}, *found;
    if (getaddrinfo(host, port, &hints, &found) != 0) return -1;
    int fd = socket(found->ai_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd >= 0 && connect(fd, found->ai_addr, found->ai_addrlen) < 0 && errno == EINPROGRESS) {
        struct pollfd wait = {.fd = fd, .events = POLLOUT};
        int error = 0;
        socklen_t size = sizeof(error);
        if (poll(&wait, 1, 6000) != 1 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) ||
            error) {
            close(fd);
            fd = -1;
        }
    }
    freeaddrinfo(found);
    if (fd >= 0) {
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
        struct timeval timeout = {.tv_sec = 6};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    }
    return fd;
}

static void http_get(const char *host, const char *path)
{
    char label[160], request[512], response[2048];
    snprintf(label, sizeof(label), "HTTP GET http://%s%s", host, path);
    int fd = connect_to(host, "80");
    if (fd < 0) { check(label, 0); return; }
    int len = snprintf(request, sizeof(request),
                       "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n"
                       "Connection: close\r\n\r\n", path, host, USER_AGENT);
    ssize_t received = send(fd, request, (size_t)len, MSG_NOSIGNAL) == len
                           ? recv(fd, response, sizeof(response) - 1, 0) : -1;
    check(label, received >= 12 && !memcmp(response, "HTTP/1.", 7));
    while (received > 0) received = recv(fd, response, sizeof(response), 0);
    close(fd);
}

/* A TLS 1.2 ClientHello naming `host`; the reply is read and discarded. */
static void tls_hello(const char *host)
{
    unsigned char hello[512];
    size_t n = 0, name = strlen(host);
#define PUT(byte) (hello[n++] = (unsigned char)(byte))
#define PUT16(value) (PUT((value) >> 8), PUT(value))
    static const uint16_t suites[] = {0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9, 0x009c, 0x002f};
    static const uint16_t signatures[] = {0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0601};
    PUT(0x16); PUT16(0x0301); PUT16(0);               /* record, length later */
    PUT(0x01); PUT(0); PUT16(0);                      /* ClientHello, length later */
    PUT16(0x0303);
    for (int i = 0; i < 32; i++) PUT(rand());
    PUT(0);                                           /* no session id */
    PUT16(sizeof(suites));
    for (size_t i = 0; i < sizeof(suites) / 2; i++) PUT16(suites[i]);
    PUT(1); PUT(0);                                   /* null compression */
    size_t extensions = n; PUT16(0);
    PUT16(0x0000); PUT16(name + 5); PUT16(name + 3); PUT(0); PUT16(name);
    memcpy(hello + n, host, name); n += name;
    PUT16(0x000a); PUT16(6); PUT16(4); PUT16(0x001d); PUT16(0x0017);
    PUT16(0x000b); PUT16(2); PUT(1); PUT(0);
    PUT16(0x000d); PUT16(sizeof(signatures) + 2); PUT16(sizeof(signatures));
    for (size_t i = 0; i < sizeof(signatures) / 2; i++) PUT16(signatures[i]);
    hello[extensions] = (unsigned char)((n - extensions - 2) >> 8);
    hello[extensions + 1] = (unsigned char)(n - extensions - 2);
    hello[3] = (unsigned char)((n - 5) >> 8); hello[4] = (unsigned char)(n - 5);
    hello[7] = (unsigned char)((n - 9) >> 8); hello[8] = (unsigned char)(n - 9);
#undef PUT
#undef PUT16
    char label[128];
    snprintf(label, sizeof(label), "TLS ClientHello SNI %s", host);
    int fd = connect_to(host, "443");
    unsigned char reply[4096];
    ssize_t received = fd >= 0 && send(fd, hello, n, MSG_NOSIGNAL) == (ssize_t)n
                           ? recv(fd, reply, sizeof(reply), 0) : -1;
    check(label, received > 0 && (reply[0] == 0x16 || reply[0] == 0x15));
    if (fd >= 0) close(fd);
}

static void nameserver(char *address, size_t size)
{
    char buffer[4096], *line;
    snprintf(address, size, "10.0.2.3");
    if (read_file("/etc/resolv.conf", buffer, sizeof(buffer)) <= 0) return;
    for (line = strtok(buffer, "\n"); line; line = strtok(NULL, "\n")) {
        char candidate[64];
        struct in_addr parsed;
        if (sscanf(line, "nameserver %63s", candidate) == 1 && inet_pton(AF_INET, candidate, &parsed) == 1) {
            snprintf(address, size, "%s", candidate);
            return;
        }
    }
}

/* One DNS question sent to the system resolver over UDP. */
static void dns_query(const char *server, const char *query, uint16_t type)
{
    unsigned char packet[512], reply[512];
    size_t n = 0;
    uint16_t id = (uint16_t)rand();
    packet[n++] = (unsigned char)(id >> 8); packet[n++] = (unsigned char)id;
    packet[n++] = 0x01; packet[n++] = 0x00;           /* recursion desired */
    packet[n++] = 0; packet[n++] = 1;                 /* one question */
    memset(packet + n, 0, 6); n += 6;
    for (const char *label = query; *label;) {
        const char *dot = strchr(label, '.');
        size_t len = dot ? (size_t)(dot - label) : strlen(label);
        packet[n++] = (unsigned char)len;
        memcpy(packet + n, label, len); n += len;
        label += len + (dot ? 1 : 0);
    }
    packet[n++] = 0;
    packet[n++] = (unsigned char)(type >> 8); packet[n++] = (unsigned char)type;
    packet[n++] = 0; packet[n++] = 1;                 /* class IN */
    char label[160];
    snprintf(label, sizeof(label), "DNS %s %s via %s", type == 28 ? "AAAA" : "A", query, server);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(53)};
    struct timeval timeout = {.tv_sec = 4};
    ssize_t len = -1;
    if (fd >= 0 && inet_pton(AF_INET, server, &address.sin_addr) == 1) {
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        if (sendto(fd, packet, n, 0, (struct sockaddr *)&address, sizeof(address)) == (ssize_t)n)
            len = recv(fd, reply, sizeof(reply), 0);
    }
    check(label, len >= 12 && reply[0] == packet[0] && reply[1] == packet[1]);
    if (fd >= 0) close(fd);
}

static void network_activity(void)
{
    char server[64];
    nameserver(server, sizeof(server));
    /* Questions only; the answers do not matter to the IDS rules. */
    dns_query(server, "antinomie-feature-sample.ngrok.io", 1);
    dns_query(server, "api.ipify.org", 1);
    dns_query(server, "example.com", 28);
    if (offline) {
        printf("SKIPPED      public requests (--offline)\n");
        return;
    }
    http_get("example.com", "/antinomie-feature-sample?marker=ANTINOMIE_FEATURE_SAMPLE_v1");
    http_get("testmynids.org", "/uid/index.html");
    http_get("api.ipify.org", "/?format=json");
    http_get("icanhazip.com", "/");
    tls_hello("api.ipify.org");
    tls_hello("example.com");
}

/* ---- BPF and seccomp ---------------------------------------------------- */

static void filter_activity(void)
{
    struct bpf_insn code[] = {
        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0},
        {.code = BPF_JMP | BPF_EXIT},
    };
    const char license[] = "GPL"; /* Kernel program-type compatibility declaration. */
    union bpf_attr attributes = {0};
    attributes.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attributes.insn_cnt = sizeof(code) / sizeof(code[0]);
    attributes.insns = (uintptr_t)code;
    attributes.license = (uintptr_t)license;
    int program = (int)syscall(SYS_bpf, BPF_PROG_LOAD, &attributes, sizeof(attributes));
    check("BPF program load", program >= 0);
    if (program >= 0) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        check("BPF socket attach", fd >= 0 && setsockopt(fd, SOL_SOCKET, SO_ATTACH_BPF,
              &program, sizeof(program)) == 0);
        if (fd >= 0) close(fd);
        close(program);
    }
    /* Allow-all, last: no_new_privs would affect the programs run above. */
    struct sock_filter instructions[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    struct sock_fprog filter = {.len = 1, .filter = instructions};
    check("no_new_privs", prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    check("seccomp allow-all filter", syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &filter) == 0);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    int stage2 = argc > 1 && strcmp(argv[1], "--stage2") == 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--offline") == 0) offline = 1;
        else if (strcmp(argv[i], "--help") == 0) {
            printf("usage: %s [--offline]\n", argv[0]);
            return 0;
        }
    }
    if (!stage2) {
        install_and_exec(argc, argv);
        printf("NOTE         could not re-run from %s; continuing in place\n", INSTALL_PATH);
    }
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    char directory[] = "/tmp/antinomie-feature-XXXXXX";
    if (!mkdtemp(directory) || chdir(directory)) { perror("sample directory"); return 1; }
    printf("ANTINOMIE FEATURE SAMPLE pid=%ld directory=%s\n", (long)getpid(), directory);
    memory_activity();
    suspicious_calls();
    environment_checks();
    discovery();
    file_activity();
    payloads();
    tools();
    dropped_programs();
    process_activity();
    network_activity();
    filter_activity();
    /* Let executable acquisition finish while the root task is still live. */
    sleep(2);
    printf("FEATURE SAMPLE DONE unavailable=%d marker=%s directory=%s\n", unavailable,
           (const char *)memory_marker, directory);
    return 0;
}
