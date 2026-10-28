// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// oracle.c — pending case state and the ANT_EXPECT line printer (oracle.h).
#include "oracle.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>

// Largest data description printed for one argument; larger buffers are
// described by the fixture in pieces or as out_any().
#define ORA_DATA_LIMIT 16384
#define ORA_LINE_SIZE (256 * 1024)

struct pending {
    int active;
    const char *label, *name;
    long nr, want, value;
    int error, argc;
    long args[6];
    uint64_t t0, t1;
    unsigned unchecked;
    int is_volatile;
    long pid, tid;
    int noreturn, wait_status;
    size_t data_len, status_len, extra_len, async_len, recapture_len;
    char data[96 * 1024], status[4096], extra[4096], async[48 * 1024], recapture[2048];
};

static __thread struct pending pending;
static __thread char line[ORA_LINE_SIZE];
static unsigned failures;
static unsigned sequence;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

uint64_t ora_now(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

static void emit(const char *text, size_t len)
{
    // One write per line: a terminal write holds the tty's write lock for the
    // whole buffer, so lines of different processes never interleave.
    while (len > 0) {
        ssize_t written = write(STDOUT_FILENO, text, len);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            _exit(97);
        text += written;
        len -= (size_t)written;
    }
}

static void lined(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void lined(const char *fmt, ...)
{
    va_list args;
    int saved = errno;
    va_start(args, fmt);
    int len = vsnprintf(line, sizeof line, fmt, args);
    va_end(args);
    if (len < 0 || (size_t)len >= sizeof line)
        _exit(96);
    emit(line, (size_t)len);
    errno = saved;
}

void ora_fail(const char *what)
{
    pthread_mutex_lock(&lock);
    failures++;
    pthread_mutex_unlock(&lock);
    lined("ANT_FIXTURE_FAIL {\"what\":\"%s\",\"pid\":%d}\n", what, getpid());
}

unsigned ora_failures(void)
{
    return failures;
}

void ora_flush(void)
{
    fflush(NULL);
}

void ora_make_resident(void)
{
    // The link name on the stack: the image's own pages are not resident yet.
    char link[] = {'/', 'p', 'r', 'o', 'c', '/', 's', 'e', 'l', 'f', '/', 'e', 'x', 'e', 0};
    char line[512], path[256], exe[256] = "";
    ssize_t len = readlink(link, exe, sizeof exe - 1);
    FILE *maps = fopen("/proc/self/maps", "re");

    if (len > 0)
        exe[len] = 0;
    if (!maps)
        return;
    unsigned long image_end = 0;
    while (fgets(line, sizeof line, maps)) {
        unsigned long start, end;
        char perms[8];
        path[0] = 0;
        if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %255s", &start, &end, perms, path) < 3)
            continue;
        // The image's own mappings, the anonymous one right after them
        // (.bss) and the heap; never the stack guard, vsyscall or the
        // program's own mappings, which residency cases leave untouched.
        int image = exe[0] && !strcmp(path, exe);
        int bss = !path[0] && start == image_end;
        int heap = !strcmp(path, "[heap]");
        if (image)
            image_end = end;
        if (perms[0] != 'r' || !(image || bss || heap))
            continue;
        for (unsigned long page = start; page < end; page += 4096)
            (void)*(volatile const char *)page;
    }
    fclose(maps);
}

void ora_child_cold(unsigned index)
{
    // A child's case numbers never collide with its parent's.
    sequence = 1000000 * index;
    failures = 0;
    pending.active = 0;
}

void ora_child(unsigned index)
{
    ora_make_resident();
    ora_child_cold(index);
}

void ora_wait(pid_t child, const char *what)
{
    int status;
    pid_t got;
    do
        got = waitpid(child, &status, 0);
    while (got < 0 && errno == EINTR);
    if (got != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        char text[160];
        snprintf(text, sizeof text, "%s: child status %#x", what, got == child ? status : -1);
        ora_fail(text);
    }
}

static void append(char *buffer, size_t size, size_t *len, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));
static void append(char *buffer, size_t size, size_t *len, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int added = vsnprintf(buffer + *len, size - *len, fmt, args);
    va_end(args);
    if (added < 0 || (size_t)added >= size - *len) {
        ora_fail("oracle line buffer");
        _exit(95);
    }
    *len += (size_t)added;
}

static void hex(char *buffer, size_t size, size_t *len, const void *data, size_t data_len)
{
    static const char digits[] = "0123456789abcdef";
    const unsigned char *bytes = data;
    if (data_len > ORA_DATA_LIMIT || *len + 2 * data_len + 1 > size) {
        ora_fail("oracle data description too large");
        _exit(94);
    }
    for (size_t i = 0; i < data_len; i++) {
        buffer[(*len)++] = digits[bytes[i] >> 4];
        buffer[(*len)++] = digits[bytes[i] & 15];
    }
    buffer[*len] = 0;
}

long ora_call(const char *label, const char *name, long nr, long want, int argc,
              const long args[6])
{
    if (pending.active) {
        char text[200];
        snprintf(text, sizeof text, "case %s started before %s was reported", label,
                 pending.label);
        ora_fail(text);
    }
    memset(&pending, 0, offsetof(struct pending, data));
    pending.data[0] = pending.status[0] = pending.extra[0] = pending.async[0] = 0;
    pending.active = 1;
    pending.label = label;
    pending.name = name;
    pending.nr = nr;
    pending.want = want;
    pending.argc = argc;
    for (int i = 0; i < 6; i++)
        pending.args[i] = i < argc ? args[i] : 0;
    pending.t0 = ora_now();
    long value = syscall(nr, pending.args[0], pending.args[1], pending.args[2], pending.args[3],
                         pending.args[4], pending.args[5]);
    int error = errno;
    pending.t1 = ora_now();
    pending.value = value;
    pending.error = value == -1 ? error : 0;
    errno = error;
    return value;
}

void remote_begin(const char *label, const char *name, long nr, long pid, long tid, uint64_t t0,
                  uint64_t t1, int argc, const long args[6], long ret)
{
    if (pending.active)
        ora_fail("remote case started before the pending case was reported");
    memset(&pending, 0, offsetof(struct pending, data));
    pending.data[0] = pending.status[0] = pending.extra[0] = pending.async[0] = 0;
    pending.active = 1;
    pending.label = label;
    pending.name = name;
    pending.nr = nr;
    pending.want = WANT_ANY;
    pending.argc = argc;
    for (int i = 0; i < 6; i++)
        pending.args[i] = i < argc ? args[i] : 0;
    pending.t0 = t0;
    pending.t1 = t1;
    pending.pid = pid;
    pending.tid = tid;
    pending.value = ret < 0 && ret > -4096 ? -1 : ret;
    pending.error = ret < 0 && ret > -4096 ? (int)-ret : 0;
}

void remote_noreturn(int wait_status)
{
    pending.noreturn = 1;
    pending.wait_status = wait_status;
}

void ora_forget(void)
{
    pending.active = 0;
}

static void data_item(const char *phase, int arg, const char *key, const char *kind,
                      const void *data, size_t len)
{
    if (!pending.active)
        return;
    append(pending.data, sizeof pending.data, &pending.data_len, "%s{\"p\":\"%s\"",
           pending.data_len ? "," : "", phase);
    if (arg >= 0)
        append(pending.data, sizeof pending.data, &pending.data_len, ",\"arg\":%d", arg);
    if (key)
        append(pending.data, sizeof pending.data, &pending.data_len, ",\"key\":\"%s\"", key);
    append(pending.data, sizeof pending.data, &pending.data_len, ",\"kind\":\"%s\",\"hex\":\"",
           kind);
    if (data)
        hex(pending.data, sizeof pending.data, &pending.data_len, data, len);
    append(pending.data, sizeof pending.data, &pending.data_len, "\"}");
}

void in_str(int arg, const char *text)
{
    data_item("in", arg, NULL, "str", text, strlen(text));
}

void out_str(int arg, const char *text)
{
    data_item("out", arg, NULL, "str", text, strlen(text));
}

void in_buf(int arg, const void *data, size_t len)
{
    data_item("in", arg, NULL, "buf", data, len);
}

void out_buf(int arg, const void *data, size_t len)
{
    data_item("out", arg, NULL, "buf", data, len);
}

void any_buf(int arg, const void *data, size_t len)
{
    data_item("any", arg, NULL, "buf", data, len);
}

void in_key(const char *key, const void *data, size_t len)
{
    data_item("in", -1, key, "buf", data, len);
}

void out_key(const char *key, const void *data, size_t len)
{
    data_item("out", -1, key, "buf", data, len);
}

void out_any(int arg)
{
    data_item("out", arg, NULL, "any", NULL, 0);
}

void in_any(int arg)
{
    data_item("in", arg, NULL, "any", NULL, 0);
}

void key_any(const char *key)
{
    data_item("any", -1, key, "any", NULL, 0);
}

void want_status(int arg, const char *phase, const char *status)
{
    if (!pending.active)
        return;
    append(pending.status, sizeof pending.status, &pending.status_len,
           "%s{\"arg\":%d,\"p\":\"%s\",\"status\":\"%s\"}", pending.status_len ? "," : "", arg,
           phase, status);
}

void want_key_status(const char *key, const char *status)
{
    if (!pending.active)
        return;
    append(pending.status, sizeof pending.status, &pending.status_len,
           "%s{\"key\":\"%s\",\"p\":\"any\",\"status\":\"%s\"}", pending.status_len ? "," : "",
           key, status);
}

void want_recapture(const char *key, const char *mark)
{
    if (!pending.active)
        return;
    append(pending.recapture, sizeof pending.recapture, &pending.recapture_len,
           "%s{\"key\":\"%s\",\"mark\":\"%s\"}", pending.recapture_len ? "," : "", key, mark);
}

void allow_status(const char *status, const char *reason)
{
    if (!pending.active)
        return;
    append(pending.extra, sizeof pending.extra, &pending.extra_len,
           ",\"allow\":{\"status\":\"%s\",\"why\":\"%s\"}", status, reason);
}

static void file_item(const char *kind, const struct stat *st)
{
    append(pending.extra, sizeof pending.extra, &pending.extra_len,
           ",\"file\":{\"kind\":\"%s\",\"major\":%u,\"minor\":%u,\"ino\":%llu,\"nlink\":%lu}", kind,
           major(st->st_dev), minor(st->st_dev), (unsigned long long)st->st_ino,
           (unsigned long)st->st_nlink);
}

void file_stat(const char *kind, const struct stat *st)
{
    if (pending.active)
        file_item(kind, st);
}

void file_fd(const char *kind, int fd)
{
    struct stat st;
    if (!pending.active)
        return;
    if (fstat(fd, &st) == 0)
        file_item(kind, &st);
    else
        ora_fail("file_fd fstat");
}

void file_path(const char *kind, const char *path)
{
    struct stat st;
    if (!pending.active)
        return;
    if (lstat(path, &st) == 0)
        file_item(kind, &st);
    else
        ora_fail("file_path lstat");
}

void file_pos(uint64_t offset, uint64_t len)
{
    if (pending.active)
        append(pending.extra, sizeof pending.extra, &pending.extra_len,
               ",\"pos\":{\"offset\":%llu,\"len\":%llu}", (unsigned long long)offset,
               (unsigned long long)len);
}

void file_pos_none(void)
{
    if (pending.active)
        append(pending.extra, sizeof pending.extra, &pending.extra_len, ",\"nopos\":true");
}

void file_written_before(const char *label)
{
    if (pending.active)
        append(pending.extra, sizeof pending.extra, &pending.extra_len, ",\"before\":\"%s\"",
               label);
}

static void copy_end(const char *name, int fd, long long offset, int size)
{
    struct stat st;
    if (fstat(fd, &st) != 0) {
        ora_fail("file_copy fstat");
        return;
    }
    append(pending.extra, sizeof pending.extra, &pending.extra_len,
           ",\"%s\":{\"major\":%u,\"minor\":%u,\"ino\":%llu,\"mode\":%u,\"offset\":%lld", name,
           major(st.st_dev), minor(st.st_dev), (unsigned long long)st.st_ino, (unsigned)st.st_mode,
           offset);
    if (size)
        append(pending.extra, sizeof pending.extra, &pending.extra_len, ",\"size\":%lld",
               (long long)st.st_size);
    append(pending.extra, sizeof pending.extra, &pending.extra_len, "}");
}

void file_copy(const char *kind, int src_fd, long long src_off, int dst_fd, long long dst_off,
               uint64_t len, unsigned mode, uint64_t data_len)
{
    if (!pending.active)
        return;
    append(pending.extra, sizeof pending.extra, &pending.extra_len,
           ",\"copy\":{\"kind\":\"%s\",\"len\":%llu,\"mode\":%u,\"data\":%llu", kind,
           (unsigned long long)len, mode, (unsigned long long)data_len);
    if (src_fd >= 0)
        copy_end("src", src_fd, src_off, 0);
    copy_end("dst", dst_fd, dst_off, 1);
    append(pending.extra, sizeof pending.extra, &pending.extra_len, "}");
}

void async_req(uint64_t user_data, int opcode, long result)
{
    if (!pending.active)
        return;
    append(pending.async, sizeof pending.async, &pending.async_len,
           "%s{\"user_data\":\"0x%llx\",\"op\":%d,\"res\":%ld}", pending.async_len ? "," : "",
           (unsigned long long)user_data, opcode, result);
}

void async_data(uint64_t user_data, const char *key, const void *data, size_t len)
{
    if (!pending.active)
        return;
    append(pending.async, sizeof pending.async, &pending.async_len,
           "%s{\"user_data\":\"0x%llx\",\"key\":\"%s\",\"hex\":\"",
           pending.async_len ? "," : "", (unsigned long long)user_data, key);
    hex(pending.async, sizeof pending.async, &pending.async_len, data, len);
    append(pending.async, sizeof pending.async, &pending.async_len, "\"}");
}

void volatile_case(void)
{
    pending.is_volatile = 1;
}

void why(const char *text)
{
    if (!pending.active) {
        // CASE() already reported its case: a why() after it is lost.
        ora_fail("why() outside a case");
        return;
    }
    append(pending.extra, sizeof pending.extra, &pending.extra_len, ",\"why\":\"%s\"", text);
}

void args_unchecked(unsigned mask)
{
    pending.unchecked = mask;
}

static int fulfilled(long value, int error, long want)
{
    if (want == WANT_ANY)
        return 1;
    if (want == WANT_OK)
        return value >= 0 || (value == -1 && error == 0);
    return value == -1 && error == want;
}

long ora_done(void)
{
    if (!pending.active) {
        ora_fail("DONE without a pending case");
        return -1;
    }
    pending.active = 0;
    long ret = pending.value == -1 && pending.error ? -(long)pending.error : pending.value;
    int ok = fulfilled(pending.value, pending.error, pending.want);
    pthread_mutex_lock(&lock);
    unsigned seq = ++sequence;
    pthread_mutex_unlock(&lock);
    if (pending.noreturn)
        append(pending.extra, sizeof pending.extra, &pending.extra_len,
               ",\"noreturn\":true,\"wait_status\":%d", pending.wait_status);
    if (pending.recapture_len)
        append(pending.extra, sizeof pending.extra, &pending.extra_len, ",\"recapture\":[%s]",
               pending.recapture);
    lined("ANT_EXPECT {\"seq\":%u,\"label\":\"%s\",\"nr\":%ld,\"name\":\"%s\",\"pid\":%ld,"
          "\"tid\":%ld,\"t0\":%llu,\"t1\":%llu,\"argc\":%d,\"args\":[\"%#lx\",\"%#lx\","
          "\"%#lx\",\"%#lx\",\"%#lx\",\"%#lx\"],\"unchecked\":%u,\"ret\":%ld,\"want\":%ld,"
          "\"ok\":%s,\"volatile\":%s,\"data\":[%s],\"status\":[%s],\"async\":[%s]%s}\n",
          seq, pending.label, pending.nr, pending.name,
          pending.pid ? pending.pid : (long)getpid(),
          pending.tid ? pending.tid : syscall(SYS_gettid), (unsigned long long)pending.t0, (unsigned long long)pending.t1, pending.argc,
          pending.args[0], pending.args[1], pending.args[2], pending.args[3], pending.args[4],
          pending.args[5], pending.unchecked, ret, pending.want, ok ? "true" : "false",
          pending.is_volatile ? "true" : "false", pending.data, pending.status, pending.async,
          pending.extra);
    if (!ok) {
        char text[200];
        snprintf(text, sizeof text, "%s returned %ld, wanted %ld", pending.label, ret,
                 pending.want);
        ora_fail(text);
    }
    errno = pending.error;
    return pending.value;
}

void implicit_case(const char *label, const char *name, long nr, uint64_t t0, uint64_t t1,
                   long result)
{
    pthread_mutex_lock(&lock);
    unsigned seq = ++sequence;
    pthread_mutex_unlock(&lock);
    lined("ANT_EXPECT {\"seq\":%u,\"label\":\"%s\",\"nr\":%ld,\"name\":\"%s\",\"pid\":%d,"
          "\"tid\":%ld,\"t0\":%llu,\"t1\":%llu,\"implicit\":true,\"ret\":%ld,\"ok\":true}\n",
          seq, label, nr, name, getpid(), syscall(SYS_gettid), (unsigned long long)t0,
          (unsigned long long)t1, result);
}

void role(const char *name, long id)
{
    lined("ANT_ROLE {\"role\":\"%s\",\"id\":%ld}\n", name, id);
}

void ora_root_device(char *out, size_t size)
{
    char line[512], device[256], target[256];
    snprintf(out, size, "/dev/vda");
    FILE *mounts = fopen("/proc/self/mounts", "re");
    if (!mounts)
        return;
    while (fgets(line, sizeof line, mounts))
        if (sscanf(line, "%255s %255s", device, target) == 2 && !strcmp(target, "/") &&
            !strncmp(device, "/dev/", 5))
            snprintf(out, size, "%s", device);
    fclose(mounts);
}

void group_line(const char *what, const char *name)
{
    lined("ANT_GROUP {\"%s\":\"%s\",\"pid\":%d}\n", what, name, getpid());
}
