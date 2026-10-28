// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// oracle.h — what a conformance fixture tells the checker it did.
//
// Every traced call a fixture makes goes through CALL(), which invokes the raw
// system call with all six registers set, times it with CLOCK_MONOTONIC (the
// clock the guest recorder stamps events with) and keeps a pending case. The
// helpers below then describe what the call was given and what it returned,
// and DONE() prints one line:
//
//   ANT_EXPECT {"seq":..,"label":..,"nr":..,"name":..,"pid":..,"tid":..,
//               "t0":..,"t1":..,"args":["0x..",..6],"ret":..,"want":..,
//               "data":[..],"status":[..],"file":{..},"async":[..],"why":..}
//
// The checker (examples/conformance) finds the recorded invocation with the
// same thread, syscall and arguments inside [t0, t1] and compares it with
// this line. The format is documented in tests/monitor/conformance/README.md.
#ifndef ANTINOMIE_CONFORMANCE_ORACLE_H
#define ANTINOMIE_CONFORMANCE_ORACLE_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

// `want` of a case: what the fixture means to exercise. A result that does
// not match it is a fixture failure (the case did not test what it says).
#define WANT_OK 0       // any result >= 0
#define WANT_ANY (-1)   // environment dependent; the oracle still records it
// Any positive value is the errno the call must fail with.

// Widen every argument to long: syscall() is variadic, an int literal would
// leave the upper half of its register undefined.
#define ORA_L(x) ((long)(x))
#define ORA_ARGS1(a) 1, (long[6]){ORA_L(a)}
#define ORA_ARGS2(a, b) 2, (long[6]){ORA_L(a), ORA_L(b)}
#define ORA_ARGS3(a, b, c) 3, (long[6]){ORA_L(a), ORA_L(b), ORA_L(c)}
#define ORA_ARGS4(a, b, c, d) 4, (long[6]){ORA_L(a), ORA_L(b), ORA_L(c), ORA_L(d)}
#define ORA_ARGS5(a, b, c, d, e) 5, (long[6]){ORA_L(a), ORA_L(b), ORA_L(c), ORA_L(d), ORA_L(e)}
#define ORA_ARGS6(a, b, c, d, e, f)                                                                \
    6, (long[6]) { ORA_L(a), ORA_L(b), ORA_L(c), ORA_L(d), ORA_L(e), ORA_L(f) }
#define ORA_COUNT(...) ORA_COUNT_(__VA_ARGS__, 6, 5, 4, 3, 2, 1, 0)
#define ORA_COUNT_(a, b, c, d, e, f, n, ...) n
#define ORA_JOIN(a, b) ORA_JOIN_(a, b)
#define ORA_JOIN_(a, b) a##b
#define ORA_ARGS(...) ORA_JOIN(ORA_ARGS, ORA_COUNT(__VA_ARGS__))(__VA_ARGS__)

// CALL(label, name, want, args...) starts a case and returns the raw result
// (-1 with errno on failure, like syscall()). CALL0 is the no-argument form.
#define CALL(label, sys, want, ...) ora_call(label, #sys, SYS_##sys, want, ORA_ARGS(__VA_ARGS__))
#define CALL0(label, sys, want) ora_call(label, #sys, SYS_##sys, want, 0, (long[6]){0})
// The same by number, for rows libc has no SYS_ name for.
#define CALLNR(label, name, nr, want, ...) ora_call(label, name, nr, want, ORA_ARGS(__VA_ARGS__))
// CASE: a call with nothing more to describe.
#define CASE(label, sys, want, ...) (CALL(label, sys, want, __VA_ARGS__), DONE())
#define CASE0(label, sys, want) (CALL0(label, sys, want), DONE())
#define DONE() ora_done()

long ora_call(const char *label, const char *name, long nr, long want, int argc,
              const long args[6]);
// Print the pending case and return its raw result (errno restored).
long ora_done(void);
// Drop the pending case of a child that must not report its parent's call.
void ora_forget(void);

// What the call was given (entry) and what it wrote (exit), by argument.
// STR: a NUL-terminated string (compared without its terminator).
void in_str(int arg, const char *text);
void in_buf(int arg, const void *data, size_t len);
void out_buf(int arg, const void *data, size_t len);
void out_str(int arg, const char *text);
// Input the kernel hands over at exit (a kernel-made copy of the operand, as
// for semctl SETALL): either phase.
void any_buf(int arg, const void *data, size_t len);
// The same under an exact recorded key (nested objects: "arg1.iov[0].data").
void in_key(const char *key, const void *data, size_t len);
void out_key(const char *key, const void *data, size_t len);
// A field whose content the program cannot predict (time, random bytes,
// kernel addresses): it must be recorded COMPLETE, its bytes are not compared
// and golden files mask them.
void out_any(int arg);
void in_any(int arg);
void key_any(const char *key);
// A deliberately triggered capture status (COPY_FAULT, NOT_RESIDENT,
// INVALID_EXTENT, NULL_POINTER, ...) for a field of argument `arg` (or -1 for
// any field) and phase "in"/"out"/"any". The checker requires exactly it.
void want_status(int arg, const char *phase, const char *status);
void want_key_status(const char *key, const char *status);
// A field the recorder could not read at entry and captured later (contract
// section 22, the page was not resident): `mark` is "at exit" (read again when
// the call returned) or "kernel copy" (an exec's own copy). A key ending in
// '*' covers every key it starts with. The checker requires exactly these.
void want_recapture(const char *key, const char *mark);
// A call whose capture is allowed to carry non-COMPLETE statuses the checker
// would otherwise reject; `why` documents the reason.
void allow_status(const char *status, const char *why);
// The file a successful open/rename/link/unlink acted on. kind is OPEN,
// RENAME, LINK or UNLINK. fd >= 0 identifies it by descriptor, else by path
// (lstat, so the link itself).
void file_fd(const char *kind, int fd);
void file_path(const char *kind, const char *path);
// The same from a stat taken before the call (UNLINK: the name is gone after).
struct stat;
void file_stat(const char *kind, const struct stat *st);
// Where a read or write of a seekable file began and how much it moved, as
// the kernel's file.position record must say (contract revision 18).
void file_pos(uint64_t offset, uint64_t len);
// The call must carry no file.position record (a pipe).
void file_pos_none(void);
// The write's file.position write order must be lower than that of the case
// `label`: the file system applied this write first (its bytes show it).
void file_written_before(const char *label);
// What an in-kernel copy or allocation moved, as its file.copy record must
// say: kind is SENDFILE, SPLICE, COPY_RANGE, CLONE or FALLOCATE; src_fd < 0
// for an allocation; an offset < 0 for an end without one (a pipe, a
// socket); data_len is the bytes carried as file.copy.data. Both ends are
// identified with fstat, the destination's size after the call included.
void file_copy(const char *kind, int src_fd, long long src_off, int dst_fd, long long dst_off,
               uint64_t len, unsigned mode, uint64_t data_len);
// One io_uring or AIO request this call submitted (or reaped), with the
// result its completion reported.
void async_req(uint64_t user_data, int opcode, long result);
// Bytes one of those requests read or wrote, under its recorded async key
// ("async.payload.input", "async.payload.output", "async.operand.sockaddr"…).
void async_data(uint64_t user_data, const char *key, const void *data, size_t len);
// Output that varies between runs (pids, times): golden files mask it.
void volatile_case(void);
// Why this case is shaped as it is (dangerous calls, expected failures).
void why(const char *text);
// The call's arguments other than these are not compared (kernel-chosen
// values the program passes back, such as addresses). Bit i = argument i.
void args_unchecked(unsigned mask);

// A call the program did not make itself (rt_sigreturn through a signal
// trampoline, restart_syscall after a stop, uretprobe): matched by thread,
// number and time only.
void implicit_case(const char *label, const char *name, long nr, uint64_t t0, uint64_t t1,
                   long result);

// A call made by a task that cannot report it itself: a child that called
// exit/exit_group or execve, or was killed in the call. The child stores its
// pid, tid and the time before the call in shared memory; the parent starts
// the case with them after waiting for the child, adds data descriptions and
// calls DONE(). `ret` is the expected raw result (an execve that succeeded
// returns 0 in the new image); for a call that never returns use
// remote_noreturn() with the child's wait status.
void remote_begin(const char *label, const char *name, long nr, long pid, long tid, uint64_t t0,
                  uint64_t t1, int argc, const long args[6], long ret);
void remote_noreturn(int wait_status);

// A process or thread role for golden files: "child", "worker" (pid or tid).
void role(const char *name, long id);
// Free-form group marker lines for the checker ("ANT_GROUP start user").
void group_line(const char *what, const char *name);
// The block device mounted at / (/dev/vda when /proc/self/mounts names none).
void ora_root_device(char *out, size_t size);

// Touch every page of the program image and its writable data, so the
// recorder's no-fault copies find what the program passes from them. main()
// calls it, and so does ora_child() for a forked child (whose page tables
// start without the parent's entries).
void ora_make_resident(void);

// Monotonic nanoseconds, as the recorder stamps.
uint64_t ora_now(void);
// Fixture failure that is not a traced-call mismatch.
void ora_fail(const char *what);
unsigned ora_failures(void);
// Before fork(): nothing buffered may be printed twice.
void ora_flush(void);
// A forked child's own case numbering.
void ora_child(unsigned index);
// The same without making the image resident, for the residency cases
// (recapture.c), whose children pass literals they never touched.
void ora_child_cold(unsigned index);
// Wait for a child forked by the fixture; nonzero exit adds a failure.
void ora_wait(pid_t child, const char *what);

#endif
