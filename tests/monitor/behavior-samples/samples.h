// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// samples.h — shared core of the Antinomie behavior samples.
//
// These are deliberately not stress tests. Each scenario reproduces the shape
// of one behaviour an analyst triages, with the harmful part replaced by a
// harmless destination:
//
//   * the default endpoint is the QEMU user-network host 10.0.2.2; --host
//     accepts only numeric IPv4 (no name is ever resolved), and the built-in
//     names are RFC 6761 .invalid with RFC 5737 TEST-NET literals as text,
//   * downloaded content runs only if it matches a pinned SHA-256 of the
//     bundled hello-world payload (download, download-elf); anything else is
//     counted and discarded,
//   * writes stay inside a per-run work directory and are removed afterwards
//     unless --keep is passed (the opt-in --cred-home decoys and the opt-in
//     --real-paths probes, which cannot create or read anything, are the only
//     exceptions),
//   * every loop is bounded by --rounds.
//
// The samples exist to exercise syscall capture, network triage, static
// analysis and detection rules with traffic and file activity that looks like
// real malware but only ever talk to the address they are given.
#ifndef ANTINOMIE_SAMPLES_H
#define ANTINOMIE_SAMPLES_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

// Reserved destinations. The default points at the QEMU user-networking host
// (10.0.2.2), so a listener on the host receives the payload when the VM has
// NAT enabled. Outside QEMU use --host 198.51.100.23 (TEST-NET, unroutable) or
// --host 127.0.0.1 --port 9 (refused) for the offline baseline.
#define SAMPLE_REMOTE_ADDR "10.0.2.2"
#define SAMPLE_REMOTE_HOST "remote.example-host.invalid"
#define SAMPLE_DNS_ADDR "10.0.2.2"
#define SAMPLE_SNI "update.example-cdn.invalid"
#define SAMPLE_EXFIL_DOMAIN "exfil.example-dns.invalid"
#define SAMPLE_UDP_PORT 4444
#define SAMPLE_HTTP_PORT 8080
#define SAMPLE_TLS_PORT 8443
// Side ports of the sinkhole: off-standard HTTP, TLS and SSH, IRC and a shell sink.
#define SAMPLE_ALT_HTTP_PORT 9080
#define SAMPLE_ALT_TLS_PORT 9443
#define SAMPLE_SSH_PORT 2222
#define SAMPLE_IRC_PORT 6667
#define SAMPLE_SHELL_PORT 4445

#define SAMPLE_USER_AGENT                                                                          \
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "                      \
    "Chrome/124.0.0.0 Safari/537.36"

// Pinned payloads served by sinkhole.py. The sample runs a downloaded
// file only when its SHA-256 equals one of these; tests/monitor/
// test-sinkhole.py checks that the sinkhole serves exactly these bytes.
#define SAMPLE_DOWNLOAD_PATH "/install.sh"
#define SAMPLE_DOWNLOAD_SHA256 "4267d61ee8379b7c3b24ede4bc43da16f92d3ef67d2b15459d7ddfca4c74cfd4"
#define SAMPLE_ELF_PATH "/payload.elf"
#define SAMPLE_ELF_SHA256 "1867e9277b4751faa6358579b7b47fc800fb15e1ca8b2fdf5178993638d25f94"
#define SAMPLE_DOWNLOAD_TEXT                                                                       \
    "#!/bin/sh\n"                                                                                  \
    "echo \"hello from demo download\"\n"                                                     \
    "echo download ran > download-marker.txt\n"
// Documentation-only address block (RFC 5737 TEST-NET-3) used by --wide.
#define SAMPLE_TESTNET_PREFIX "203.0.113."

#define SAMPLE_MAX_ROUNDS 50
#define SAMPLE_MAX_DELAY_MS 10000
#define SAMPLE_MAX_GAP_MS 5000
#define SAMPLE_MAX_EVADE_SLEEP_MS 5000

struct options {
    int rounds;
    int delay_ms;
    // NULL/0 means the scenario's own default.
    const char *host;
    int port;
    const char *resolver;
    // Base directory; each run gets <workdir>/<scenario>.
    char workdir[256];
    int keep;
    // cred-read: place decoys under $HOME instead of the work directory.
    int cred_home;
    // 0 means port 53 (or $SAMPLE_DNS_PORT) for the resolver.
    int dns_port;
    // Opt-in scenarios: --wide sends a few packets to documentation addresses,
    // --real-paths opens real system paths in ways that cannot change them.
    int wide;
    int real_paths;
    // The evasive gate: --evade on any binary, --why, --ignore LIST of
    // categories (debugger,vm,container,sandbox), --evade-sleep MS (-1 picks
    // 3.0-4.5 s) and, for tests only, --test-root DIR.
    int evade;
    int why;
    const char *ignore;
    const char *test_root;
    int evade_sleep_ms;
};

// One scenario of the registry. `expect` is the comma-separated list of rule
// ids Antinomie's Suspicious activity should show for it; `notes` says what
// that list depends on (root, a guest, a workdir under /tmp, ...).
struct module {
    const char *name;
    const char *phase;
    const char *summary;
    const char *expect;
    const char *notes;
    // NULL, or the option that must be given for the scenario to run.
    const char *requires;
    int (*run)(const struct options *options);
};

long sample_scaled(const struct options *options, long light);
void sample_delay(int milliseconds);

// One result line, formatted like the workload samples so existing parsers and
// the app's run output read it the same way.
void sample_pass(const char *module, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void sample_note(const char *module, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void sample_unavailable(const char *module, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
void sample_fail(const char *module, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
// A step that was deliberately not run, with the reason.
void sample_skip(const char *module, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

const char *sample_host(const struct options *options);
int sample_port(const struct options *options, int fallback);

// evade.c: run every environment check and print the verdict (EVADE lines on
// stdout and stderr, a GATE line); 1 means "an analysis environment". The tail
// of an evading run (decoy, last look, short sleep) is sample_gate_finish(), which
// main calls after the scorecard so nothing is written after the last check.
int sample_gate_run(const struct options *options, const char *module);
void sample_gate_finish(void);

// Create a directory and any missing parents.
int sample_mkdir_p(const char *path);

// ---- common.c: files, paths, helper processes --------------------------------
int sample_write_all(int fd, const void *buffer, size_t length);
// Create or truncate `path` (mode 0600, no symlinks) and write the text.
int sample_write_text(const char *path, const char *text);
int sample_write_bytes(const char *path, const void *data, size_t length, unsigned mode);
// Like sample_write_text but creates the parent directories first.
int sample_write_nested(const char *path, const char *text);
// base + "/" + relative into output; -1 when it does not fit.
int sample_path(char *output, size_t cap, const char *base, const char *relative);
// The running binary's own path (from /proc/self/exe).
int sample_self_path(char *output, size_t cap);
// Copy at most `limit` bytes; the destination is created with `mode`.
int sample_copy_file(const char *from, const char *to, unsigned mode, size_t limit);
// Run `path` with a chosen argv and optional extra environment strings as a
// child that only exits (SAMPLE_NOOP=mode, see main.c); a NULL mode runs the
// program as it is. Waits at most four
// seconds and kills only that recorded pid. Returns the exit status, or -1.
int sample_spawn(const char *path, char *const argv[], char *const extra_env[], const char *mode,
              const char *cwd);
// sample_spawn that also collects the child's output (stdout and stderr, at most
// cap-1 bytes) into `output`.
int sample_spawn_capture(const char *path, char *const argv[], char *const extra_env[],
                      const char *mode, const char *cwd, char *output, size_t cap);
// sample_spawn of this binary: the argv is only what the process list and the
// syscall trace show, nothing named in it is ever run.
int sample_spoof(char *const argv[], char *const extra_env[]);
// What a helper child does for SAMPLE_NOOP=mode: "exit" nothing; "selfdelete"
// removes its own file when SAMPLE_NOOP_OUT names exactly that file; "compile"
// copies itself to SAMPLE_NOOP_OUT (the stand-in compiler).
int sample_noop(const char *mode);
// True for 10/8, 172.16/12, 192.168/16, 127/8 and 169.254/16 literals.
int sample_is_private(const char *address);
// SHA-256 as 64 lowercase hex characters plus NUL.
void sample_sha256_hex(const void *data, size_t length, char output[65]);
// Fork a child that runs `body(context)` and exits 0; waits at most `limit_ms`.
// Returns the child's exit status, or -1 on a fork failure or a timeout.
int sample_in_child(int (*body)(void *context), void *context, int limit_ms);
// Run a list of spoofed commands (NULL-terminated argv arrays). Returns how many ran.
struct spoof {
    const char *rule;
    char *const argv[10];
};
int sample_spoof_all(const char *module, const struct spoof *list, size_t count);

// Hex-encode at most cap-1 bytes; returns the output length.
size_t sample_hex(const char *input, char *output, size_t cap);
// "id=...&host=...&uid=...&sys=...&arch=..." for a check-in body.
size_t sample_fingerprint(char *output, size_t cap);

// TCP connect with a bounded wait; returns a blocking fd or -1 (errno set).
int sample_dial(const char *host, int port, int timeout_ms);
int sample_send_all(int fd, const void *buffer, size_t length);
ssize_t sample_recv_wait(int fd, void *buffer, size_t length, int timeout_ms);

// Method/path against host:port with the sample User-Agent. A non-NULL
// received counter collects at most four reads of response headers/body.
int sample_http_request(const char *host, int port, const char *method, const char *path,
                     const char *body, size_t body_len, unsigned long long *received);

// Build one DNS question (header + one name + qtype/qclass IN).
size_t sample_dns_build(unsigned char *packet, const char *name, uint16_t type, uint16_t id);
// Send it to the resolver and wait; returns 1 when an answer arrived. The port
// is 53, $SAMPLE_DNS_PORT or --dns-port.
int sample_dns_ask(const char *resolver, const char *name, uint16_t type, int wait_ms);
extern int sample_dns_port;
// Wait for one HTTP response and return its body in `body` (at most `cap`
// bytes, NUL-terminated for convenience). Returns the body length, or -1
// when no complete response arrived. Headers are read first and separately,
// so the body is a read of its own.
ssize_t sample_http_fetch(const char *host, int port, const char *path, unsigned char *body,
                       size_t cap, int *status);
// Non-blocking connect that is closed again at once; returns 0 when it started.
int sample_touch_port(const char *host, int port);
// A small HTTP request with an explicit Host: header, to host:port.
int sample_http_as(const char *host, int port, const char *host_header, const char *method,
                const char *path, const char *body, unsigned long long *received);

#define SCENARIO(id) int scenario_##id(const struct options *options)

SCENARIO(recon);
SCENARIO(discovery);
SCENARIO(sandbox_probe);
SCENARIO(ptrace_antidebug);
SCENARIO(sleep_evasion);
SCENARIO(download);
SCENARIO(download_elf);
SCENARIO(persistence);
SCENARIO(privesc_sim);
SCENARIO(memfd_exec);
SCENARIO(inject_sim);
SCENARIO(evasion_misc);
SCENARIO(cred_read);
SCENARIO(http_beacon);
SCENARIO(beacon_loop);
SCENARIO(dns_tunnel);
SCENARIO(dga);
SCENARIO(tls_sni);
SCENARIO(udp_beacon);
SCENARIO(c2_misc);
SCENARIO(shell_sim);
SCENARIO(exfil_sim);
SCENARIO(collection_sim);
SCENARIO(lateral_sim);
SCENARIO(impact_sim);
SCENARIO(rule_markers);
SCENARIO(real_path_probes);
SCENARIO(evasive);
SCENARIO(net_wide);


#endif
