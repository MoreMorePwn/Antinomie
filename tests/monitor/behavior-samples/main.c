// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// main.c — options, scenario registry, result lines and scorecard.
//
// Built with -DSINGLE_SCENARIO="name" the program is that one behavior
// sample (ant-sample-<name>); without it, it is ant-sample-all and runs every
// scenario in order.
//
// Output contract (one record per line, stable, easy to grep):
//   == <scenario>: <summary> (...)       scenario header
//   EXPECT <scenario> <rule ids>         the rules Antinomie should show for it
//   PASS|NOTE|UNAVAILABLE|FAIL|SKIP <scenario> <message>
//   SCENARIO <scenario> status=... pass=N note=N unavailable=N fail=N skip=N
//   == scorecard: N pass, N note, N unavailable, N fail, N skip
//   SUMMARY scenarios=N ... expected_rules=N
#include "samples.h"

#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define REAL_PATHS "--real-paths"
#define WIDE "--wide"

// Registry order is the order of a run, which follows the phases of the
// activity graph: recon, download, persistence, escalation, hide/inject, C2,
// spread, impact. "-" marks scenarios whose rules have no graph phase.
static const struct module modules[] = {
    {"recon", "recon", "host fingerprint, os-release read, staging file and an exfil POST",
     "discovery.system_info,network.ip_literal",
     "network.ip_literal is a capture rule: it needs the sinkhole (or a NAT guest) and a capture",
     NULL, scenario_recon},
    {"discovery", "recon",
     "user, network, process and file discovery, security-software probes, stand-in tools",
     "discovery.user_enum,discovery.system_info,discovery.network_config,discovery.process_enum,"
     "discovery.file_search,discovery.security_software,discovery.network_scan",
     "network_scan here is the nmap stand-in (exec shape); the connect-based form is lateral-sim",
     NULL, scenario_discovery},
    {"sandbox-probe", "recon",
     "VM and sandbox checks: DMI, cpuinfo, MAC, uptime, clock loop, containers, then exit",
     "evasion.sandbox_probe,evasion.probe_then_exit,evasion.container_check,"
     "evasion.debugger_check,evasion.traceme,discovery.system_info,discovery.network_config",
     "probe_then_exit needs an answer that would show a VM (true in a QEMU guest); "
     "sandbox_probe is MEDIUM only when two or more kinds of check are made",
     NULL, scenario_sandbox_probe},
    {"ptrace-antidebug", "recon", "TracerPid, instrumented mappings and a TRACEME check",
     "evasion.debugger_check,evasion.traceme", NULL, NULL, scenario_ptrace_antidebug},
    {"sleep-evasion", "recon", "sleeps of a minute or more, cut short, and a stalling task",
     "evasion.long_sleep", "MEDIUM because each sleeper is a fresh task that did nothing before",
     NULL, scenario_sleep_evasion},
    {"cred-read", "-", "decoy credential files and presence checks of standard paths",
     "credential.history_read,credential.wallet,credential.kerberos_ccache,"
     "credential.cloud_tokens,credential.ssh_keys,credential.browser_store,network.ip_literal",
     "history_read, wallet, kerberos_ccache, the service-account token (cloud_tokens) and the "
     "private-key header read (ssh_keys) fire from the work directory; browser_store and the "
     "~/.aws, ~/.kube, ~/.ssh and ~/.bitcoin paths need --cred-home",
     NULL, scenario_cred_read},
    {"download", "download",
     "GET a hello-world script, check its pinned SHA-256, write, chmod and run it two ways",
     "execution.dropped_exec,execution.chmod_exec_temp,execution.temp_exec,"
     "execution.download_cradle,process.interpreter,process.exec,network.ip_literal",
     "runs only when the SHA-256 matches; any other server gets a NOTE and no execution; "
     "process.exec is INFO and is counted for every program a scenario starts",
     NULL, scenario_download},
    {"download-elf", "download",
     "GET a tiny hello-world ELF (pinned), write, chmod and run it; a stand-in compiler",
     "c2.elf_download,execution.dropped_exec,execution.chmod_exec_temp,execution.temp_exec,"
     "execution.compile_then_run,network.ip_literal",
     "runs only when the SHA-256 matches; compile_then_run is a copy of this binary named cc",
     NULL, scenario_download_elf},
    {"persistence", "persistence",
     "autostart, systemd user unit, shell profile, authorized_keys, PAM lookalikes and stand-ins",
     "persistence.systemd,persistence.xdg_autostart,persistence.shell_profile,"
     "persistence.ssh_authorized_keys,persistence.pam,persistence.config_write,"
     "persistence.cron,persistence.at_job,persistence.account,persistence.rc_init,"
     "persistence.module,execution.chmod_exec_temp",
     "files are lookalikes under the work directory; cron/at/account/rc_init are exec "
     "stand-ins; persistence.module is a finit_module on an invalid descriptor",
     NULL, scenario_persistence},
    {"privesc-sim", "escalation",
     "setuid bit on a decoy, user namespace, namespace and socket probes, pwnkit and dirty-pipe shapes",
     "privilege.setid_bit,privilege.userns,privilege.container_escape,privilege.pwnkit,"
     "privilege.dirty_pipe,privilege.drop,execution.temp_exec",
     "container_escape from setns needs root to open /proc/1/ns; privilege.drop needs root; "
     "the rest also run unprivileged",
     NULL, scenario_privesc_sim},
    {"memfd-exec", "hide/inject", "anonymous memfd, RWX mapping, self re-exec and fileless exec",
     "process.memfd,execution.memfd_elf,process.memfd_exec,memory.rwx,memory.wx_transition,"
     "memory.rwx_attempt,execution.fileless_exec,execution.dropped_library",
     NULL, NULL, scenario_memfd_exec},
    {"inject-sim", "hide/inject",
     "ptrace and /proc/PID/mem against the sample's own child, LD_PRELOAD in an environment",
     "injection.ptrace_attach,injection.ptrace_poke,process.ptrace,injection.vm_write,"
     "injection.proc_mem_write,credential.proc_mem_read,injection.ld_preload_env,evasion.traceme",
     "the target is always a child this sample forked; a Yama or seccomp policy that refuses "
     "ptrace turns the rows into failed attempts",
     NULL, scenario_inject_sim},
    {"evasion-misc", "hide/inject",
     "masquerading, dumpable, seccomp, history and log clearing, timestomp, hidden entries, stand-ins",
     "evasion.masquerade_kthread,evasion.masquerade_daemon,evasion.dumpable_off,"
     "bpf.seccomp_filter,evasion.hidden_artifact,evasion.history_clear,evasion.timestomp,"
     "evasion.immutable_attr,evasion.self_delete,evasion.log_clear,evasion.kill_list,"
     "evasion.proc_hide_mount,evasion.sysctl_security,evasion.firewall_modify,"
     "evasion.audit_disable,evasion.security_disable,bpf.program,evasion.io_uring_usage,"
     "execution.dropped_exec,execution.temp_exec,execution.chmod_exec_temp",
     "the dangerous calls are made on invalid arguments (EINVAL, ENOENT, EBADF) or as "
     "exec stand-ins; immutable_attr is HIGH on the decoy path",
     NULL, scenario_evasion_misc},
    {"http-beacon", "C2", "periodic HTTP check-ins with a browser User-Agent",
     "network.ip_literal", "a capture rule; the rows are VM-wide unless the sample's own connect is seen",
     NULL, scenario_http_beacon},
    {"beacon-loop", "C2", "nine requests at a steady pace to one host",
     "network.beacon,network.ip_literal", "needs at least 8 requests with a regular gap",
     NULL, scenario_beacon_loop},
    {"dns-tunnel", "C2", "encoded labels over 40 characters and a burst of TXT questions",
     "network.dns_tunnel", "two rows: long labels, and 20 TXT questions within a minute",
     NULL, scenario_dns_tunnel},
    {"dga", "C2", "random-looking names looked up against the sinkhole resolver, mostly NXDOMAIN",
     "network.dga_nxdomain",
     "needs a resolver that answers one name and refuses the rest (the sinkhole does)",
     NULL, scenario_dga},
    {"tls-sni", "C2", "TLS ClientHello with a SNI name that looks like a C2 domain",
     "", "no rule fires by design; read the SNI in the Network tab and the IOC window",
     NULL, scenario_tls_sni},
    {"udp-beacon", "C2", "JSON check-in datagrams to a callback port",
     "", "no rule fires by design; read the datagrams in the Network tab and the IOC window",
     NULL, scenario_udp_beacon},
    {"c2-misc", "C2",
     "off-port HTTP/TLS/SSH, IRC, Tor, web-service names, metadata host header, Stratum text, tunnel stand-ins",
     "network.nonstandard_port,network.irc_c2,network.tor,network.web_service,"
     "credential.cloud_metadata,impact.miner,network.proxy_tunnel,network.ip_literal",
     "names appear only inside payloads sent to the sinkhole; the Tor connect goes to loopback 9050",
     NULL, scenario_c2_misc},
    {"shell-sim", "C2",
     "reverse and bind shell shapes on local sockets, raw socket, socket filter, bpf program",
     "c2.reverse_shell,c2.bind_shell,network.listen_any,network.raw_socket,bpf.socket_filter,"
     "c2.bpf_backdoor,process.interpreter",
     "the shell runs a fixed echo and exits; raw_socket and bpf_backdoor need root, "
     "bpf.socket_filter also fires from a UDP socket",
     NULL, scenario_shell_sim},
    {"exfil-sim", "C2", "sendfile of a decoy to a socket, archive staging, scp and curl -T stand-ins",
     "exfil.file_to_socket,collection.archive_staging,lateral.tool_transfer,network.ip_literal",
     NULL, NULL, scenario_exfil_sim},
    {"collection-sim", "-",
     "clipboard, screen and audio stand-ins, TIOCSTI on a file, a document sweep",
     "collection.clipboard,collection.screen_capture,collection.av_capture,"
     "collection.tty_inject,collection.local_sweep",
     "screen/av/clipboard are exec stand-ins; keylog is in real-path-probes; "
     "local_sweep needs --workdir under /home or /root",
     NULL, scenario_collection_sim},
    {"lateral-sim", "spread",
     "port sweep and login-port bursts against --host (private addresses only), ssh stand-ins",
     "discovery.network_scan,lateral.bruteforce,lateral.ssh_spread",
     "refused for a non-private --host; service_exploit needs several hosts (net-wide)",
     NULL, scenario_lateral_sim},
    {"impact-sim", "impact",
     "fork storm, rename-to-.locked bursts, notes, miner and shutdown stand-ins, a UDP burst",
     "impact.fork_bomb,impact.ransom_rewrite,impact.ransom_note,impact.inhibit_recovery,"
     "impact.service_stop,impact.reboot,impact.miner,impact.miner_tuning,impact.ddos_flood,"
     "impact.block_device_write",
     "ddos_flood is refused for a non-private --host; nothing outside the work directory is deleted",
     NULL, scenario_impact_sim},
    {"rule-markers", "-", "technique and Sigma tag strings plus benign discovery commands",
     "discovery.system_info,discovery.user_enum",
     "the strings are for YARA/Sigma and the Files tab, not for Suspicious activity",
     NULL, scenario_rule_markers},
    {"real-path-probes", "-",
     "opens real system paths that cannot be changed or read: absent names, no create, no read",
     "persistence.cron,persistence.at_job,persistence.systemd,persistence.rc_init,"
     "persistence.event_script,persistence.shell_profile,persistence.ssh_authorized_keys,"
     "persistence.xdg_autostart,persistence.udev,persistence.pam,persistence.module_autoload,"
     "persistence.apt_hook,persistence.web_shell,persistence.config_write,injection.ld_so_preload,"
     "injection.ld_so_conf,privilege.sudoers,evasion.audit_disable,evasion.log_clear,"
     "impact.block_device_write,impact.miner_tuning,credential.shadow_read,collection.keylog,"
     "collection.screen_capture,collection.av_capture",
     "failed opens: each row is one tier down and marked failed; the read-only opens "
     "(shadow, input, fb0, video, snd) succeed only where the node exists and is readable",
     REAL_PATHS, scenario_real_path_probes},
    {"net-wide", "spread",
     "a few packets to documentation addresses (203.0.113.0/24): service ports, a sweep, a 1.1 MiB UDP upload",
     "lateral.service_exploit,discovery.network_scan,exfil.large_upload",
     "the packets leave the guest toward an unroutable block and are dropped",
     WIDE, scenario_net_wide},
};
#define MODULE_COUNT (sizeof modules / sizeof modules[0])

struct tally {
    unsigned pass, note, unavailable, fail, skip;
};

static struct tally totals;
static struct tally per[MODULE_COUNT];
static const char *current_name;

static struct tally *current(void)
{
    if (current_name)
        for (size_t m = 0; m < MODULE_COUNT; m++)
            if (!strcmp(modules[m].name, current_name))
                return &per[m];
    return NULL;
}

long sample_scaled(const struct options *options, long light)
{
    long rounds = options->rounds > 0 ? options->rounds : 1;
    return light * rounds;
}

static void line(const char *tag, const char *module, const char *fmt, va_list args)
{
    printf("%-11s %-17s ", tag, module);
    vprintf(fmt, args);
    putchar('\n');
    fflush(stdout);
}

#define RESULT(fn, tag, field)                                                                     \
    void fn(const char *module, const char *fmt, ...)                                              \
    {                                                                                              \
        va_list args;                                                                              \
        va_start(args, fmt);                                                                       \
        line(tag, module, fmt, args);                                                              \
        va_end(args);                                                                              \
        totals.field++;                                                                            \
        struct tally *own = current();                                                             \
        if (own)                                                                                   \
            own->field++;                                                                          \
    }
RESULT(sample_pass, "PASS", pass)
RESULT(sample_note, "NOTE", note)
RESULT(sample_unavailable, "UNAVAILABLE", unavailable)
RESULT(sample_fail, "FAIL", fail)
RESULT(sample_skip, "SKIP", skip)

static void usage(const char *self, FILE *out)
{
    fprintf(out, "usage: %s [options]%s\n\n", self,
#ifdef SINGLE_SCENARIO
           ""
#else
           "   (a bare run is every scenario; --only a,b selects some)"
#endif
    );
    fprintf(out, "  --rounds N        repetitions per scenario (1-%d, default 3)\n"
           "  --delay MS        pause between rounds (0-%d, default 500)\n"
           "  --host ADDRESS    numeric IPv4 of the listener (default %s, the QEMU NAT host)\n"
           "  --port N          override the scenario's own port\n"
           "  --resolver ADDR   DNS server for the DNS scenarios (default: --host, else %s)\n"
           "  --dns-port N      DNS port (default 53; or set SAMPLE_DNS_PORT)\n"
           "  --workdir DIR     base directory; each run uses DIR/<scenario>\n"
           "  --keep            keep the work directory for evidence inspection\n"
           "  --cred-home       cred-read: plant decoys under $HOME (never overwrites)\n"
           "  --wide            allow net-wide: a few packets to 203.0.113.0/24\n"
           "  --real-paths      allow real-path-probes: opens that cannot create or read\n"
           "  --gap MS          pause between scenarios in a full run (0-%d, default 1000)\n"
           "  --list            print the registry (name, phase, expected rules) and exit\n"
#ifndef SINGLE_SCENARIO
           "  --all | --only a,b  run every scenario, or a comma-separated subset\n"
#endif
           "  --help            this text\n\n",
           SAMPLE_MAX_ROUNDS, SAMPLE_MAX_DELAY_MS, SAMPLE_REMOTE_ADDR, SAMPLE_DNS_ADDR, SAMPLE_MAX_GAP_MS);
    fprintf(out, "Default ports: HTTP %d, TLS %d, UDP %d. Start the sinkhole on the host with\n"
           "  python3 tests/monitor/sinkhole.py\n"
           "and pass the --host it prints. Endpoints are numeric IPv4 only; nothing is resolved.\n"
           "Downloaded content runs only if it matches a pinned hash of the bundled payload.\n"
           "Writes stay in the work directory. Scenarios needing --wide or --real-paths are\n"
           "skipped (with a SKIP line) unless the option is given.\n",
           SAMPLE_HTTP_PORT, SAMPLE_TLS_PORT, SAMPLE_UDP_PORT);
}

static void list_modules(void)
{
    printf("# name\tphase\trequires\texpected-rule-ids\tsummary\n");
    for (size_t m = 0; m < MODULE_COUNT; m++)
        printf("%s\t%s\t%s\t%s\t%s\n", modules[m].name, modules[m].phase,
               modules[m].requires ? modules[m].requires : "-",
               modules[m].expect[0] ? modules[m].expect : "-", modules[m].summary);
}

static void remove_tree(const char *path)
{
    struct stat info;
    if (lstat(path, &info) != 0)
        return;
    if (!S_ISDIR(info.st_mode)) {
        unlink(path);
        return;
    }
    DIR *dir = opendir(path);
    if (!dir && errno == EACCES && chmod(path, 0700) == 0)
        dir = opendir(path);
    if (dir) {
        struct dirent *entry;
        char child[PATH_MAX];
        while ((entry = readdir(dir))) {
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
                continue;
            if (snprintf(child, sizeof child, "%s/%s", path, entry->d_name) >= (int)sizeof child)
                continue;
            remove_tree(child);
        }
        closedir(dir);
    }
    rmdir(path);
}

static int run_module(const struct module *module, const struct options *base)
{
    struct options options = *base;
    current_name = module->name;
    if (module->requires &&
        !((!strcmp(module->requires, WIDE) && base->wide) ||
          (!strcmp(module->requires, REAL_PATHS) && base->real_paths))) {
        printf("== %s: %s (phase %s)\n", module->name, module->summary, module->phase);
        printf("%-11s %-17s %s\n", "EXPECT", module->name,
               module->expect[0] ? module->expect : "-");
        sample_skip(module->name, "not run: pass %s to enable it (%s)", module->requires,
                 module->notes ? module->notes : "opt-in scenario");
        current_name = NULL;
        return 0;
    }
    char template[] = "/tmp/antinomie-sample-XXXXXX";
    if (!base->workdir[0]) {
        if (!mkdtemp(template)) {
            sample_fail(module->name, "work directory: %s", strerror(errno));
            current_name = NULL;
            return 1;
        }
        snprintf(options.workdir, sizeof options.workdir, "%s", template);
    } else {
        int length = snprintf(options.workdir, sizeof options.workdir, "%.200s/%s",
                              base->workdir, module->name);
        if (length < 0 || (size_t)length >= sizeof options.workdir) {
            sample_fail(module->name, "work directory path too long");
            current_name = NULL;
            return 1;
        }
        // The directory is removed afterwards, so never adopt one that exists.
        if (access(options.workdir, F_OK) == 0) {
            sample_fail(module->name, "work directory %s already exists", options.workdir);
            current_name = NULL;
            return 1;
        }
        if (sample_mkdir_p(base->workdir) != 0 || sample_mkdir_p(options.workdir) != 0) {
            sample_fail(module->name, "work directory: %s", strerror(errno));
            current_name = NULL;
            return 1;
        }
    }
    printf("== %s: %s (phase %s, rounds %d, work %s)\n", module->name, module->summary,
           module->phase, options.rounds, options.workdir);
    printf("%-11s %-17s %s\n", "EXPECT", module->name, module->expect[0] ? module->expect : "-");
    if (module->notes)
        printf("%-11s %-17s %s\n", "DEPENDS", module->name, module->notes);
    fflush(stdout);
    int status = module->run(&options);
    fflush(stdout);
    if (!options.keep) {
        remove_tree(options.workdir);
        if (access(options.workdir, F_OK) == 0)
            sample_note(module->name, "cleanup left %s in place", options.workdir);
        // Only removes the base when this run created it and nothing else is
        // in it; an existing --workdir tree is left alone.
        if (base->workdir[0])
            rmdir(base->workdir);
    }
    current_name = NULL;
    return status;
}

static const char *status_of(const struct tally *own, const struct module *module)
{
    if (own->fail)
        return "FAIL";
    if (own->skip && !own->pass)
        return "SKIP";
    if (module->requires && !own->pass)
        return "SKIP";
    if (own->unavailable && !own->pass)
        return "UNAVAILABLE";
    return "PASS";
}

static int compare_ids(const void *left, const void *right)
{
    return strcmp(*(char *const *)left, *(char *const *)right);
}

// Counts the ids of the scenarios that ran; the union is printed once.
static void scorecard(const int *ran)
{
    printf("\n");
    unsigned scenarios = 0;
    for (size_t m = 0; m < MODULE_COUNT; m++) {
        if (!ran[m])
            continue;
        scenarios++;
        const struct tally *own = &per[m];
        printf("%-11s %-17s status=%s pass=%u note=%u unavailable=%u fail=%u skip=%u phase=\"%s\" "
               "expect=%s\n",
               "SCENARIO", modules[m].name, status_of(own, &modules[m]), own->pass, own->note,
               own->unavailable, own->fail, own->skip, modules[m].phase,
               modules[m].expect[0] ? modules[m].expect : "-");
    }
    // The union of the expected ids over the scenarios that actually ran.
    char *seen[256];
    size_t seen_count = 0;
    for (size_t m = 0; m < MODULE_COUNT; m++) {
        if (!ran[m] || (per[m].skip && !per[m].pass))
            continue;
        char copy[2048];
        snprintf(copy, sizeof copy, "%s", modules[m].expect);
        for (char *id = strtok(copy, ","); id; id = strtok(NULL, ",")) {
            int known = 0;
            for (size_t i = 0; i < seen_count; i++)
                known |= !strcmp(seen[i], id);
            if (!known && seen_count < 256) {
                seen[seen_count] = strdup(id);
                if (seen[seen_count])
                    seen_count++;
            }
        }
    }
    qsort(seen, seen_count, sizeof seen[0], compare_ids);
    printf("== scorecard: %u pass, %u note, %u unavailable, %u fail, %u skip\n", totals.pass,
           totals.note, totals.unavailable, totals.fail, totals.skip);
    printf("SUMMARY     scenarios=%u pass=%u note=%u unavailable=%u fail=%u skip=%u "
           "expected_rules=%zu\n",
           scenarios, totals.pass, totals.note, totals.unavailable, totals.fail, totals.skip,
           seen_count);
    // The union, sorted, for a diff against the rule ids Antinomie lists.
    printf("RULES       all               ");
    for (size_t i = 0; i < seen_count; i++)
        printf("%s%s", i ? "," : "", seen[i]);
    printf("\n");
    for (size_t i = 0; i < seen_count; i++)
        free(seen[i]);
    fflush(stdout);
}

static int parse_number(const char *self, const char *name, const char *text, int low, int high,
                        int *value)
{
    char *end = NULL;
    errno = 0;
    long parsed = strtol(text, &end, 10);
    if (errno || end == text || *end || parsed < low || parsed > high) {
        fprintf(stderr, "%s: %s needs a number from %d to %d, not \"%s\"\n", self, name, low, high,
                text);
        return -1;
    }
    *value = (int)parsed;
    return 0;
}

static int valid_address(const char *self, const char *name, const char *text)
{
    unsigned a, b, c, d;
    char extra;
    if (sscanf(text, "%3u.%3u.%3u.%3u%c", &a, &b, &c, &d, &extra) != 4 || a > 255 || b > 255 ||
        c > 255 || d > 255) {
        fprintf(stderr, "%s: %s takes a numeric IPv4 address (no names are resolved), not \"%s\"\n",
                self, name, text);
        return -1;
    }
    return 0;
}

#ifndef SINGLE_SCENARIO
static int wanted(const char *only, const char *name)
{
    size_t length = strlen(name);
    for (const char *at = only; *at;) {
        const char *comma = strchr(at, ',');
        size_t part = comma ? (size_t)(comma - at) : strlen(at);
        if (part == length && !strncmp(at, name, length))
            return 1;
        at += part + (comma ? 1 : 0);
    }
    return 0;
}

static int check_only(const char *self, const char *only)
{
    char copy[1024];
    snprintf(copy, sizeof copy, "%s", only);
    for (char *name = strtok(copy, ","); name; name = strtok(NULL, ",")) {
        int found = 0;
        for (size_t m = 0; m < MODULE_COUNT; m++)
            found |= !strcmp(modules[m].name, name);
        if (!found) {
            fprintf(stderr, "%s: unknown scenario \"%s\"; --list shows the names\n", self, name);
            return -1;
        }
    }
    return 0;
}
#endif

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    // Set for the helper children of sample_spawn() and for the re-executed
    // memfd copy. They return before parsing options so a child can never
    // start another generation.
    const char *noop = getenv("SAMPLE_NOOP");
    const char *memfd_child = getenv("SAMPLE_MEMFD_CHILD");
    if (memfd_child && *memfd_child) {
        printf("PASS        memfd-child       re-executed from an anonymous memfd and exiting\n");
        fflush(stdout);
        return 0;
    }
    if (noop && *noop)
        return sample_noop(noop);
    const char *self = argv[0];
    // Accept --option=value as well as --option value: split each occurrence
    // into two arguments before parsing.
    char **expanded = malloc(sizeof(char *) * (size_t)(2 * argc + 1));
    if (!expanded)
        return 1;
    int expanded_count = 0;
    expanded[expanded_count++] = argv[0];
    for (int i = 1; i < argc; i++) {
        char *equals = argv[i][0] == '-' && argv[i][1] == '-' ? strchr(argv[i], '=') : NULL;
        if (equals) {
            *equals = '\0';
            expanded[expanded_count++] = argv[i];
            expanded[expanded_count++] = equals + 1;
        } else {
            expanded[expanded_count++] = argv[i];
        }
    }
    expanded[expanded_count] = NULL;
    argc = expanded_count;
    argv = expanded;
    struct options options = {.rounds = 3, .delay_ms = 500};
    int gap_ms = 1000;
    const char *only = NULL;
    int all = 0, listing = 0;
    (void)all;
    (void)only;
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        int has_value = i + 1 < argc;
        if (!strcmp(arg, "--help") || !strcmp(arg, "-h")) {
            usage(self, stdout);
            return 0;
        } else if (!strcmp(arg, "--list")) {
            listing = 1;
        } else if (!strcmp(arg, "--keep")) {
            options.keep = 1;
        } else if (!strcmp(arg, "--cred-home")) {
            options.cred_home = 1;
        } else if (!strcmp(arg, "--wide")) {
            options.wide = 1;
        } else if (!strcmp(arg, "--real-paths")) {
            options.real_paths = 1;
#ifndef SINGLE_SCENARIO
        } else if (!strcmp(arg, "--all")) {
            all = 1;
        } else if (!strcmp(arg, "--only") && has_value) {
            only = argv[++i];
            if (check_only(self, only) != 0)
                return 2;
#endif
        } else if (!strcmp(arg, "--rounds") && has_value) {
            if (parse_number(self, arg, argv[++i], 1, SAMPLE_MAX_ROUNDS, &options.rounds) != 0)
                return 2;
        } else if (!strcmp(arg, "--delay") && has_value) {
            if (parse_number(self, arg, argv[++i], 0, SAMPLE_MAX_DELAY_MS, &options.delay_ms) != 0)
                return 2;
        } else if (!strcmp(arg, "--gap") && has_value) {
            if (parse_number(self, arg, argv[++i], 0, SAMPLE_MAX_GAP_MS, &gap_ms) != 0)
                return 2;
        } else if (!strcmp(arg, "--port") && has_value) {
            if (parse_number(self, arg, argv[++i], 1, 65535, &options.port) != 0)
                return 2;
        } else if (!strcmp(arg, "--dns-port") && has_value) {
            if (parse_number(self, arg, argv[++i], 1, 65535, &options.dns_port) != 0)
                return 2;
        } else if (!strcmp(arg, "--host") && has_value) {
            options.host = argv[++i];
            if (valid_address(self, arg, options.host) != 0)
                return 2;
        } else if (!strcmp(arg, "--resolver") && has_value) {
            options.resolver = argv[++i];
            if (valid_address(self, arg, options.resolver) != 0)
                return 2;
        } else if (!strcmp(arg, "--workdir") && has_value) {
            if (snprintf(options.workdir, sizeof options.workdir, "%s", argv[++i]) >=
                (int)sizeof options.workdir) {
                fprintf(stderr, "%s: --workdir is too long\n", self);
                return 2;
            }
        } else {
            fprintf(stderr, "%s: unknown or incomplete option \"%s\"\n\n", self, arg);
            usage(self, stderr);
            return 2;
        }
    }
    if (listing) {
        list_modules();
        return 0;
    }
    if (options.dns_port)
        sample_dns_port = options.dns_port;
    // The listener is usually one machine: --host moves the resolver with it.
    if (options.host && !options.resolver)
        options.resolver = options.host;
    int ran[MODULE_COUNT];
    memset(ran, 0, sizeof ran);
    int status = 0;
#ifdef SINGLE_SCENARIO
    for (size_t m = 0; m < MODULE_COUNT; m++)
        if (!strcmp(modules[m].name, SINGLE_SCENARIO)) {
            ran[m] = 1;
            status |= run_module(&modules[m], &options);
        }
#else
    int first = 1;
    for (size_t m = 0; m < MODULE_COUNT; m++) {
        if (only && !wanted(only, modules[m].name))
            continue;
        // A bare run is the whole storyline, in phase order. The opt-in
        // scenarios appear in it as SKIP lines unless their option is given.
        if (!first)
            sample_delay(gap_ms);
        first = 0;
        ran[m] = 1;
        status |= run_module(&modules[m], &options);
    }
#endif
    scorecard(ran);
    free(expanded);
    return status || totals.fail ? 1 : 0;
}
