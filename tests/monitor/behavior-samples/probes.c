// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// probes.c — anti-analysis checks: VM and sandbox probes, debugger checks,
// long sleeps.
//
// Everything here only reads: DMI strings, /proc and /sys files, the MAC
// address, the uptime and the clock. Antinomie's Evasion rules keep each check
// with the answer the guest gave, so the same sample shows a different row on
// a QEMU guest (revealing answers), on a Stealth-profile guest and on a
// physical machine. The sleeps are requested for a minute or more and cut
// short by a timer within a fraction of a second.
#include "samples.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// Reads up to cap-1 bytes of a small file in one read; returns the length or -1.
static ssize_t read_small(const char *path, char *output, size_t cap)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t got = read(fd, output, cap - 1);
    close(fd);
    if (got < 0)
        return -1;
    output[got] = '\0';
    return got;
}

struct counts {
    int made;
    int answered;
};

static void check(struct counts *counts, const char *path)
{
    char buffer[4096];
    counts->made++;
    if (read_small(path, buffer, sizeof buffer) >= 0)
        counts->answered++;
}

static void exists(struct counts *counts, const char *path)
{
    counts->made++;
    if (access(path, F_OK) == 0)
        counts->answered++;
}

static void noop_handler(int signal_number)
{
    (void)signal_number;
}

// The revealing checks again in a task of their own, then a prompt exit with
// no network, no file write and no new process: the probe-then-exit shape.
static int react(void *context)
{
    (void)context;
    char buffer[4096];
    read_small("/sys/class/dmi/id/sys_vendor", buffer, sizeof buffer);
    read_small("/sys/class/dmi/id/product_name", buffer, sizeof buffer);
    read_small("/proc/cpuinfo", buffer, sizeof buffer);
    read_small("/proc/uptime", buffer, sizeof buffer);
    return 0;
}

static int traceme_child(void *context)
{
    (void)context;
    return ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0 ? 0 : (errno > 0 && errno < 256 ? errno : 1);
}

SCENARIO(sandbox_probe)
{
    const char *name = "sandbox-probe";
    (void)options;
    struct counts dmi = {0}, cpu = {0}, disk = {0}, hyper = {0}, mac = {0}, up = {0};
    struct counts box = {0}, debug = {0};

    static const char *const dmi_files[] = {
        "/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/board_vendor", "/sys/class/dmi/id/bios_vendor",
        "/sys/class/dmi/id/chassis_type"};
    for (size_t i = 0; i < sizeof dmi_files / sizeof dmi_files[0]; i++)
        check(&dmi, dmi_files[i]);

    check(&cpu, "/proc/cpuinfo");

    // The model and vendor of each block device, from /sys/block.
    DIR *block = opendir("/sys/block");
    if (block) {
        struct dirent *entry;
        int devices = 0;
        while (devices < 8 && (entry = readdir(block))) {
            if (entry->d_name[0] == '.')
                continue;
            char path[300];
            snprintf(path, sizeof path, "/sys/block/%.64s/device/model", entry->d_name);
            check(&disk, path);
            snprintf(path, sizeof path, "/sys/block/%.64s/device/vendor", entry->d_name);
            check(&disk, path);
            devices++;
        }
        closedir(block);
    }

    static const char *const hypervisor_files[] = {
        "/sys/hypervisor/type",
        "/sys/devices/system/clocksource/clocksource0/current_clocksource",
        "/sys/bus/pci/devices/0000:00:00.0/vendor",
        "/sys/bus/pci/devices/0000:00:01.0/vendor",
        "/proc/modules",
        "/proc/ioports"};
    for (size_t i = 0; i < sizeof hypervisor_files / sizeof hypervisor_files[0]; i++)
        check(&hyper, hypervisor_files[i]);
    static const char *const hypervisor_presence[] = {
        "/sys/firmware/qemu_fw_cfg", "/sys/bus/virtio", "/sys/module/kvm",
        "/sys/module/virtio_pci", "/dev/vboxguest", "/dev/vmci", "/proc/xen"};
    for (size_t i = 0; i < sizeof hypervisor_presence / sizeof hypervisor_presence[0]; i++)
        exists(&hyper, hypervisor_presence[i]);

    // MAC addresses: the sysfs file of each interface and the ioctl.
    char first_interface[IFNAMSIZ] = "";
    DIR *net = opendir("/sys/class/net");
    if (net) {
        struct dirent *entry;
        int interfaces = 0;
        while (interfaces < 8 && (entry = readdir(net))) {
            if (entry->d_name[0] == '.' || !strcmp(entry->d_name, "lo"))
                continue;
            char path[300];
            snprintf(path, sizeof path, "/sys/class/net/%.64s/address", entry->d_name);
            check(&mac, path);
            if (!first_interface[0])
                snprintf(first_interface, sizeof first_interface, "%.*s", IFNAMSIZ - 1,
                         entry->d_name);
            interfaces++;
        }
        closedir(net);
    }
    if (first_interface[0]) {
        int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd >= 0) {
            struct ifreq request;
            memset(&request, 0, sizeof request);
            snprintf(request.ifr_name, sizeof request.ifr_name, "%s", first_interface);
            mac.made++;
            if (ioctl(fd, SIOCGIFHWADDR, &request) == 0)
                mac.answered++;
            close(fd);
        }
    }

    // Uptime: the file and sysinfo().
    check(&up, "/proc/uptime");
    struct sysinfo info;
    up.made++;
    if (sysinfo(&info) == 0)
        up.answered++;

    // A loop of clock reads, as raw system calls so they are visible to a
    // tracer (the libc versions come from the vDSO and make no call).
    struct timespec now;
    struct timeval day;
    for (int i = 0; i < 48; i++) {
        syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now);
        if (i % 4 == 0)
            syscall(SYS_gettimeofday, &day, NULL);
    }

    exists(&box, "/.dockerenv");
    exists(&box, "/run/.containerenv");
    check(&box, "/proc/1/cgroup");
    check(&box, "/proc/self/cgroup");
    check(&box, "/proc/1/sched");

    check(&debug, "/proc/self/status");
    struct sigaction trap;
    memset(&trap, 0, sizeof trap);
    trap.sa_handler = noop_handler;
    sigemptyset(&trap.sa_mask);
    sigaction(SIGTRAP, &trap, NULL);
    signal(SIGTRAP, SIG_DFL);
    debug.made++;
    if (prctl(PR_GET_DUMPABLE) >= 0)
        debug.answered++;
    int traceme = sample_in_child(traceme_child, NULL, 2000);

    static const struct spoof tools[] = {
        {"discovery.system_info", {"dmidecode", "-s", "system-product-name", NULL}},
        {"discovery.system_info", {"lscpu", NULL}},
        {"discovery.system_info", {"systemd-detect-virt", NULL}},
    };
    int ran = sample_spoof_all(name, tools, sizeof tools / sizeof tools[0]);

    int reacted = sample_in_child(react, NULL, 3000);
    sample_pass(name,
             "dmi %d/%d, cpu %d/%d, disk %d/%d, hypervisor %d/%d, mac %d/%d, uptime %d/%d, "
             "container %d/%d, debugger %d/%d, 48 clock reads, TRACEME child %s, %d stand-in tools",
             dmi.answered, dmi.made, cpu.answered, cpu.made, disk.answered, disk.made,
             hyper.answered, hyper.made, mac.answered, mac.made, up.answered, up.made,
             box.answered, box.made, debug.answered, debug.made,
             traceme == 0 ? "accepted" : "refused", ran);
    sample_note(name, "a task of its own repeated the VM checks and exited without work: %s",
             reacted == 0 ? "exit 0" : "it did not finish");
    sample_note(name, "which answers reveal a VM depends on the guest; a Stealth profile changes them");
    return 0;
}

// ---- debugger checks ------------------------------------------------------------

static int tracer_pid(void)
{
    FILE *status = fopen("/proc/self/status", "r");
    if (!status)
        return -1;
    char row[256];
    int tracer = 0;
    while (fgets(row, sizeof row, status)) {
        if (strncmp(row, "TracerPid:", 10) == 0) {
            tracer = atoi(row + 10);
            break;
        }
    }
    fclose(status);
    return tracer;
}

// Names a debugger or instrumentation tool leaves in the address space.
static int mapping_hits(char *first, size_t cap)
{
    static const char *names[] = {"frida", "gdbserver", "gadget", "libc_database", "xposed"};
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps)
        return -1;
    char row[512];
    int hits = 0;
    while (fgets(row, sizeof row, maps)) {
        for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
            if (strstr(row, names[i])) {
                if (hits == 0)
                    snprintf(first, cap, "%s", names[i]);
                hits++;
                break;
            }
        }
    }
    fclose(maps);
    return hits;
}

SCENARIO(ptrace_antidebug)
{
    const char *name = "ptrace-antidebug";
    (void)options;
    int tracer = tracer_pid();
    char first[64] = "";
    int hits = mapping_hits(first, sizeof first);
    const char *preload = getenv("LD_PRELOAD");

    // TRACEME in a child: the classic "am I being traced?" check without
    // leaving the sample itself in a traced state. EPERM (1) means a tracer
    // is already attached, which a ptrace-based monitor or debugger causes.
    int traceme = sample_in_child(traceme_child, NULL, 2000);
    long dumpable = prctl(PR_GET_DUMPABLE);

    if (tracer > 0)
        sample_note(name, "TracerPid %d: the sample is being traced; this is expected under a "
                       "ptrace monitor", tracer);
    else if (tracer == 0)
        sample_note(name, "TracerPid 0: no tracer attached according to /proc/self/status");
    else
        sample_unavailable(name, "/proc/self/status is unreadable in this guest");
    if (hits > 0)
        sample_note(name, "%d mapping(s) name an instrumentation tool, first %s", hits, first);
    if (preload && *preload)
        sample_note(name, "LD_PRELOAD is set to %s", preload);
    sample_pass(name, "TracerPid %d, %d instrumented mappings, LD_PRELOAD %s, dumpable %ld, "
                   "PTRACE_TRACEME %s",
             tracer, hits < 0 ? 0 : hits, preload && *preload ? "set" : "unset", dumpable,
             traceme == 0   ? "accepted"
             : traceme == 1 ? "refused with EPERM (already traced)"
             : traceme < 0  ? "not attempted"
                            : "refused");
    return 0;
}

// ---- long sleeps ---------------------------------------------------------------

#define SLEEP_SECONDS 90
#define SLEEP_CUT_MS 150

static void arm_cut(void)
{
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = noop_handler;
    sigemptyset(&action.sa_mask);
    sigaction(SIGALRM, &action, NULL); // no SA_RESTART: the sleep returns EINTR
    struct itimerval timer = {.it_value = {.tv_sec = 0, .tv_usec = SLEEP_CUT_MS * 1000}};
    setitimer(ITIMER_REAL, &timer, NULL);
}

static int sleep_nanosleep(void *context)
{
    (void)context;
    struct timespec length = {.tv_sec = SLEEP_SECONDS};
    arm_cut();
    return syscall(SYS_nanosleep, &length, NULL) == -1 && errno == EINTR ? 0 : 1;
}

static int sleep_clock_nanosleep(void *context)
{
    (void)context;
    struct timespec length = {.tv_sec = SLEEP_SECONDS + 30};
    arm_cut();
    return syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &length, NULL) == -1 && errno == EINTR ? 0 : 1;
}

static int sleep_select(void *context)
{
    (void)context;
    struct timeval length = {.tv_sec = SLEEP_SECONDS - 15};
    arm_cut();
    return syscall(SYS_select, 0, NULL, NULL, NULL, &length) == -1 && errno == EINTR ? 0 : 1;
}

static int sleep_poll(void *context)
{
    (void)context;
    arm_cut();
    return syscall(SYS_poll, NULL, 0, 61000) == -1 && errno == EINTR ? 0 : 1;
}

static int sleep_alarm(void *context)
{
    (void)context;
    // alarm(61) is the call; alarm(0) takes it back before anything is waited on.
    alarm(61);
    alarm(0);
    return 0;
}

static int sleep_timerfd(void *context)
{
    (void)context;
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    if (fd < 0)
        return 1;
    struct itimerspec armed = {.it_value = {.tv_sec = 75}};
    struct itimerspec off;
    memset(&off, 0, sizeof off);
    int result = timerfd_settime(fd, 0, &armed, NULL);
    timerfd_settime(fd, 0, &off, NULL);
    close(fd);
    return result == 0 ? 0 : 1;
}

SCENARIO(sleep_evasion)
{
    const char *name = "sleep-evasion";
    (void)options;
    static const struct {
        const char *call;
        int (*body)(void *context);
    } sleepers[] = {
        {"nanosleep", sleep_nanosleep},       {"clock_nanosleep", sleep_clock_nanosleep},
        {"select", sleep_select},             {"poll", sleep_poll},
        {"alarm", sleep_alarm},               {"timerfd_settime", sleep_timerfd},
    };
    int cut = 0;
    for (size_t i = 0; i < sizeof sleepers / sizeof sleepers[0]; i++) {
        // Each sleeper is a task of its own that has done nothing else yet.
        int status = sample_in_child(sleepers[i].body, NULL, 2000);
        if (status == 0)
            cut++;
        else
            sample_note(name, "%s: child ended with %d (a timeout or an unsupported call)",
                     sleepers[i].call, status);
    }
    sample_pass(name, "%d/%zu waits of 60 s or more requested and cut short after %d ms", cut,
             sizeof sleepers / sizeof sleepers[0], SLEEP_CUT_MS);
    sample_note(name, "nothing waits longer than a second; a sleep of 60 s or more is the signal, "
                   "not the time spent");
    return 0;
}
