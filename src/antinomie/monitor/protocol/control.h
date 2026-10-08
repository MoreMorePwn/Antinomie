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
/* Contract revision of the guest's observable behaviour (native-schema-slices). */
#define ANTC_REVISION 12
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
#define ANTC_STOP_RUN 0x1015
#define ANTC_RUN_STATUS 0x1016
#define ANTC_RUN_STATUS_SIZE 64
#define ANTC_RUN_ROOT_EXITED 1
#define ANTC_RUN_TREE_EXITED 2
#define ANTC_RUN_STOP_REQUESTED 4
#define ANTC_RUN_ASYNC_COMPLETE 8
#define ANTC_RUN_OBSERVATION_INCOMPLETE 16
#define ANTC_STATS 0x1020
#define ANTC_INFO 0x1021
#define ANTC_INFO_SIZE 160
#define ANTC_SHUTDOWN 0x1030
#define ANTC_PROCESS_LIST 0x1050
#define ANTC_CAPTURE_ATTACH 0x1051
#define ANTC_CAPTURE_ALL 0x1052
#define ANTC_CAPTURE_STOP 0x1053
#define ANTC_CAPTURE_STATUS 0x1054
#define ANTC_PROCESS_PAGE_MAX 64
#define ANTC_PROCESS_ENTRY_SIZE 64
#define ANTC_CAPTURE_STATUS_SIZE 32
#define ANTC_CAPTURE_RETAINED 64
#define ANTC_CAPTURE_ACTIVE 1
#define ANTC_CAPTURE_STOPPED 2
#define ANTC_CAPTURE_TAILS_POSSIBLE 4
#define ANTC_CAPTURE_PROCESS 1
#define ANTC_CAPTURE_USERSPACE 2
#define ANTC_ACQUIRE 0x1040
#define ANTC_SPECIMEN_READ 0x1041
#define ANTC_SPECIMEN_RELEASE 0x1042
#define ANTC_EXEC_SPECIMEN 1
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
 * EXEC: header flags=0 or EXEC_SPECIMEN, u32 uid at 8, u32 gid at 12, u32 argc at 16,
 * u32 envc at 20, u32 path_len at 24, u32 cwd_len at 28; path then cwd
 * at 32, followed by argc then envc entries, each u32 byte_len + bytes.
 * argc >= 1, explicit argv[0], absolute executable and cwd, no interior NUL.
 * Reply: u64 session_id, u64 task_cookie, u32 pid, u32 reserved=0 (24 bytes).
 * Each launch owns a Unix98 PTY. Target is spawned directly by kernel
 * usermodehelper_exec; no userspace control/helper process.
 * EXEC_SPECIMEN appends u32 max_size, u32 timeout_ms after argv/env.
 * Its reply appends the 24-byte acquisition reply to the normal 24 bytes.
 * Acquisition failure never changes the execution result.
 *
 * ACQUIRE: header flags=0, uid at 8, gid at 12, u32 path_len at 16,
 * reserved=0 at 20, absolute path at 24, then u32 max_size, timeout_ms.
 * Acquisition reply: u64 id, u64 size, i32 status, u32 reserved=0.
 * Ready status=0 has nonzero id; unavailable negative errno has id/size=0.
 * max_size is 1..64MiB; timeout_ms is 1..5000. Initial exec captures the
 * opened bprm file; scripts do not prove what an interpreter later reopens.
 * SPECIMEN_READ: header flags=0, u64 id at 8, u64 offset at 16,
 * u32 capacity at 24 (1..16328), u32 reserved=0 at 28. Reply: u64 offset,
 * u64 total_len, u32 count, u32 reserved=0, immutable data at 24.
 * SPECIMEN_RELEASE: header flags=0, u64 id at 8; empty reply.
 * Unknown/stale IDs rejected. Ready handles expire after 180s idle.
 * One active copy, at most four handles, 64MiB global memory reservation.
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
 * STOP_RUN: header flags=0, nonzero u64 root_task_cookie at 8 (16 bytes).
 * Requests SIGTERM for each traced task with this inherited launch cookie,
 * including descendants after root exit or PTY/session reaping. Empty reply.
 * Status 0 means signal requests issued, not proven tree termination; -ESRCH
 * means no signalable matching task. Concurrent forks may escape this pass.
 * RUN_STATUS: header flags=0, nonzero u64 root cookie at 8 (16 bytes).
 * Success: 64-byte reply specified in protocol/run-status.md. Task/tree
 * completion, root wait status, async observations and saving are distinct.
 *
 * STATS: header only. Reply: ten u64 counters in order: stream_id,
 * tasks_created, tasks_live, calls_entered, events_attempted,
 * packets_attempted, packets_failed, copy_faults, schema_gaps,
 * context_failures (80 bytes). Counters persist despite telemetry loss.
 * INFO: header only. Reply (160 bytes): u32 revision at 0 (ANTC_REVISION),
 * u32 reserved=0 at 4, source id at 8 (80 bytes), kernel release at 88
 * (64 bytes), reserved zero at 152. Strings are NUL terminated and padded.
 * The source id is CONFIG_ANTINOMIE_SOURCE_ID, "<revision>:<series sha256>",
 * or empty for an unversioned build. Kernels before revision 9 return
 * -EOPNOTSUPP. INFO is registered before every other opcode, so INFO
 * unsupported while STATS succeeds identifies such a kernel.
 * PROCESS_LIST: header flags=0, u32 after_pid at 8, u32 capacity at 12,
 * 1..64. Non-atomic live pagination of userspace process leaders, ascending
 * PID. Reply: u64 stream_id at 0, u32 count at 8, u32 next_pid at 12
 * (0 ends enumeration), then count 64-byte entries: u64 task_cookie at 0,
 * u64 start_boottime at 8, u32 tgid at 16, u32 parent_tgid at 20,
 * u32 uid/gid/thread_count at 24/28/32, u32 flags=0 at 36, comm[16] at 40
 * (NUL terminated), reserved zeros at 56..63. PID is not authorization.
 * CAPTURE_ATTACH: header flags=0, u64 leader task_cookie at 8,
 * u64 start_boottime at 16, u32 tgid at 24, u32 reserved=0 at 28.
 * Validates live identity, includes current thread group and future descendants
 * only. CAPTURE_ALL: header only; existing/future userspace observations.
 * Both reply with u64 capture_cookie at 0 and u64 stream_id at 8 (16 bytes).
 * One active observer at a time. Capture IDs count up from 1 and are never
 * reused within a boot; there is no per-boot capture limit (revision 12).
 * STOP and STATUS address the 64 most recent captures; an older cookie
 * returns -ESRCH like an unknown one (such a capture has necessarily stopped).
 * Existing launched-run root ownership and PTYs remain unchanged.
 * CAPTURE_STOP / STATUS: header flags=0, u64 capture_cookie at 8.
 * STATUS cookie=0 queries the active observer (all-zero reply if none).
 * STOP requires a nonzero known cookie, is idempotent, never signals tasks.
 * Both return 32-byte status: u64 cookie at 0, u32 flags at 8, u32 mode at 12,
 * u64 start_ns at 16, u64 stop_ns at 24. STOP closes admission; admitted calls
 * and async requests retain their old capture ID and may publish later tails.
 * STOPPED|TAILS_POSSIBLE does not promise delivery/drain or complete capture.
 * ANTT minor 2 / 144-byte header adds capture_cookie at offset 136, preserving
 * launched root cookie at 128. Capture attribution is frozen on admission.
 * SHUTDOWN: header only; empty success reply, delayed kernel_power_off.
 */
#endif
