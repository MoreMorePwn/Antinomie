/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 MikiMiku (MoreMorePwn) */
#ifndef ANTINOMIE_MONITOR_CONTROL_H
#define ANTINOMIE_MONITOR_CONTROL_H

/* Application control protocol 1, inside the unchanged V7 command/reply.
 * Every argument begins with u16 version=1, u16 header_len=8, u32 flags.
 * All integers are little endian; strings are byte strings without NUL.
 * No native structure casts. Error replies use transport status -errno and
 * have no payload. Successful replies have the opcode-specific payload below.
 */
#define ANTC_VERSION 1
#define ANTC_HEADER_SIZE 8
#define ANTC_UPLOAD_BEGIN 0x1001
#define ANTC_UPLOAD_CHUNK 0x1002
#define ANTC_UPLOAD_COMMIT 0x1003
#define ANTC_UPLOAD_ABORT 0x1004
#define ANTC_EXEC 0x1010
#define ANTC_TERMINAL_INPUT 0x1011
#define ANTC_TERMINAL_READ 0x1012
#define ANTC_TERMINAL_RESIZE 0x1013
#define ANTC_SIGNAL 0x1014
#define ANTC_STATS 0x1020
#define ANTC_SHUTDOWN 0x1030
#define ANTC_UPLOAD_OVERWRITE 1
#define ANTC_UPLOAD_EXECUTABLE 2

/* BEGIN: header flags=OVERWRITE|EXECUTABLE, u64 total at 8, u32 path_len
 * at 16, u32 reserved=0 at 20, path at 24. Absolute path required.
 * Reply: u64 upload_id. One active upload; creates destination with
 * O_EXCL unless overwrite is explicitly set, then truncates it.
 * CHUNK: header, u64 upload_id at 8, u64 offset at 16, bytes at 24.
 * Reply: u64 bytes_written. Offsets must be contiguous.
 * COMMIT / ABORT: header, u64 upload_id at 8; empty success reply.
 * COMMIT verifies total, fsyncs and closes; ABORT closes (partial destination
 * remains, visibly incomplete). No implicit execution.
 *
 * EXEC: header flags=0, u32 uid at 8, u32 gid at 12, u32 argc at 16,
 * u32 envc at 20, u32 path_len at 24, u32 cwd_len at 28; path then cwd
 * at 32, followed by argc then envc entries, each u32 byte_len + bytes.
 * argc >= 1, explicit argv[0], absolute executable and cwd, no interior NUL.
 * Reply: u64 session_id, u64 task_cookie, u32 pid, u32 reserved=0 (24 bytes).
 * Each launch owns a Unix98 PTY. Target is spawned directly by kernel
 * usermodehelper_exec; no userspace control/helper process.
 *
 * INPUT: header, u64 session_id at 8, bytes at 16.
 * Reply: u64 bytes_written (partial writes possible).
 * READ: header, u64 session_id at 8, u32 capacity at 16,
 * u32 reserved=0 at 20. Reply: u32 flags at 0 (bit0 EOF), u32 count at 4,
 * bytes at 8. No data available is successful count=0, flags=0.
 * RESIZE: header, u64 session_id at 8, u16 rows at 16, u16 cols at 18,
 * u16 pixel_width at 20, u16 pixel_height at 22. Empty success reply.
 * SIGNAL: header, u64 session_id at 8, u32 signal at 16,
 * u32 reserved=0 at 20. Signals launch process group. Empty success reply.
 *
 * STATS: header only. Reply: ten u64 counters in order: stream_id,
 * tasks_created, tasks_live, calls_entered, events_attempted,
 * packets_attempted, packets_failed, copy_faults, schema_gaps,
 * context_failures (80 bytes). Counters persist despite telemetry loss.
 * SHUTDOWN: header only; empty success reply, delayed kernel_power_off.
 */
#endif
