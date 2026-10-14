// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
/* Exercise the real static collector through the existing public control API.
 * Reuse the monitor integration driver's bounded framing and transport owner. */
#define main ordinary_integration_main
#include "integration.c"
#undef main
#include <signal.h>
#define TOKEN "0123456789abcdef0123456789abcdef"

int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    struct ant_backing backing = {argv[1], 1024ULL << 20};
    struct ant_memory_region region = {0, backing.size, 0, 0};
    struct ant_options options = {0};
    options.backings = &backing; options.backing_count = 1;
    options.regions = &region; options.region_count = 1;
    options.ram_size = backing.size; options.bootstrap_gpa = 0x30000000;
    options.host_timeout_ms = 1000;
    int error;
    uint64_t started = now_ms();
    do {
        error = ant_init(&options, &client);
        if (!error) break;
        struct timespec delay = {0, 100000000}; nanosleep(&delay, NULL);
    } while (now_ms() - started < 60000);
    if (error) { fprintf(stderr, "attach: %d\n", error); return 3; }
    FILE *file = fopen(argv[2], "rb");
    if (!file || fseek(file, 0, SEEK_END)) return 4;
    long length = ftell(file);
    if (length <= 0 || length > 1048576 || fseek(file, 0, SEEK_SET)) return 5;
    uint8_t *binary = malloc((size_t)length);
    if (!binary || fread(binary, 1, (size_t)length, file) != (size_t)length) return 6;
    fclose(file);
    uint8_t args[16352];
    const char *path = "/tmp/.antinomie-resource-" TOKEN, *cwd = "/";
    unsigned attempts = 0;
    uint64_t deadline = now_ms() + 60000;
    do {
        header(args, ANTC_UPLOAD_EXECUTABLE); put64(args + 8, (uint64_t)length);
        put32(args + 16, strlen(path)); put32(args + 20, 0);
        memcpy(args + 24, path, strlen(path));
        error = command(ANTC_UPLOAD_BEGIN, args, 24 + strlen(path));
        printf("upload begin attempt %u at %llu ms: %d\n", ++attempts,
               (unsigned long long)(now_ms() - started), error); fflush(stdout);
        if (error != -ENOENT) break;
        struct timespec delay = {2, 0}; nanosleep(&delay, NULL);
    } while (now_ms() < deadline);
    if (error || response_len != 8) return 7;
    uint64_t upload = get64(response);
    for (size_t offset = 0; offset < (size_t)length;) {
        size_t size = (size_t)length - offset;
        if (size > 12000) size = 12000;
        header(args, 0); put64(args + 8, upload); put64(args + 16, offset);
        memcpy(args + 24, binary + offset, size);
        checked(ANTC_UPLOAD_CHUNK, args, 24 + size);
        if (response_len != 8 || get64(response) != size) return 8;
        offset += size;
    }
    free(binary); header(args, 0); put64(args + 8, upload);
    checked(ANTC_UPLOAD_COMMIT, args, 16);
    header(args, 0); put32(args + 8, 0); put32(args + 12, 0);
    put32(args + 16, 2); put32(args + 20, 0);
    put32(args + 24, strlen(path)); put32(args + 28, strlen(cwd));
    size_t offset = 32;
    memcpy(args + offset, path, strlen(path)); offset += strlen(path);
    memcpy(args + offset, cwd, strlen(cwd)); offset += strlen(cwd);
    put32(args + offset, strlen(path)); offset += 4;
    memcpy(args + offset, path, strlen(path)); offset += strlen(path);
    put32(args + offset, strlen(TOKEN)); offset += 4;
    memcpy(args + offset, TOKEN, strlen(TOKEN)); offset += strlen(TOKEN);
    do {
        error = command(ANTC_EXEC, args, offset);
        printf("exec at %llu ms: %d\n", (unsigned long long)(now_ms() - started), error); fflush(stdout);
        if (error != -ENOENT) break;
        struct timespec delay = {2, 0}; nanosleep(&delay, NULL);
    } while (now_ms() < deadline);
    if (error) return 18;
    if (response_len != 24 || !get64(response) || !get64(response + 8) || !get32(response + 16)) return 9;
    uint64_t terminal = get64(response);
    char output[4096] = {0}; size_t used = 0;
    deadline = now_ms() + 10000;
    while (!strstr(output, "ANTREADY1 " TOKEN) && now_ms() < deadline) {
        header(args, 0); put64(args + 8, terminal); put32(args + 16, 1024); put32(args + 20, 0);
        checked(ANTC_TERMINAL_READ, args, 24);
        if (response_len < 8 || response_len - 8 != get32(response + 4) || used + response_len - 8 >= sizeof(output)) return 10;
        memcpy(output + used, response + 8, response_len - 8); used += response_len - 8;
    }
    if (!strstr(output, "ANTREADY1 " TOKEN)) return 11;
    header(args, 0); put64(args + 8, terminal); memcpy(args + 16, "1\n", 2);
    checked(ANTC_TERMINAL_INPUT, args, 18);
    if (response_len != 8 || get64(response) != 2) return 12;
    deadline = now_ms() + 10000;
    while (!strstr(output, "ANTRES1 " TOKEN) && now_ms() < deadline) {
        header(args, 0); put64(args + 8, terminal); put32(args + 16, 1024); put32(args + 20, 0);
        checked(ANTC_TERMINAL_READ, args, 24);
        if (response_len < 8 || response_len - 8 != get32(response + 4) || used + response_len - 8 >= sizeof(output)) return 13;
        memcpy(output + used, response + 8, response_len - 8); used += response_len - 8;
    }
    char *sample = strstr(output, "ANTRES1 " TOKEN); if (!sample) return 14;
    uint64_t sequence, total, available, blocks, free_blocks, allowed, fragment;
    int mem_error, disk_error;
    if (sscanf(sample, "ANTRES1 " TOKEN " %" SCNu64 " %d %" SCNu64 " %" SCNu64 " %d %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64,
               &sequence, &mem_error, &total, &available, &disk_error, &blocks, &free_blocks, &allowed, &fragment) != 9 ||
        sequence != 1 || mem_error || disk_error || !total || total >= (1024ULL << 20) ||
        available > total || !blocks || free_blocks > blocks || allowed > free_blocks || !fragment) return 15;
    printf("%s", output);
    header(args, 0); put64(args + 8, terminal); put32(args + 16, SIGKILL); put32(args + 20, 0);
    checked(ANTC_SIGNAL, args, 24);
    deadline = now_ms() + 10000;
    while (now_ms() < deadline) {
        header(args, 0); put64(args + 8, terminal); put32(args + 16, 1024); put32(args + 20, 0);
        error = command(ANTC_TERMINAL_READ, args, 24);
        if (error == -ENOENT || (!error && response_len >= 8 && (get32(response) & 1))) {
            ant_close(client); puts("GUEST RESOURCE CONTROL PASS"); return 0;
        }
        if (error) return 16;
    }
    return 17;
}
