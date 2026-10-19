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
/* Revision 15: opt-in root-process ELF core acquisition at exit; ABI 9. */
/* Revision 17: kernel-native guest resource sample (RESOURCES), and the
 * credential and file-hash lifecycle records described below. */
#define ANTC_REVISION 17
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
#define ANTC_EXEC_CORE 2
#define ANTC_CORE_STATUS 0x1060
#define ANTC_CORE_READ 0x1061
#define ANTC_CORE_RELEASE 0x1062
#define ANTC_CORE_CAPTURE 0x1063
#define ANTC_CORE_LOOKUP 0x1064
#define ANTC_CORE_CANCEL 0x1065
#define ANTC_CORE_STATUS_SIZE 80
#define ANTC_CORE_ARMED 1
#define ANTC_CORE_COPYING 2
#define ANTC_CORE_READY 3
#define ANTC_CORE_PARTIAL 4
#define ANTC_CORE_UNAVAILABLE 5
#define ANTC_CORE_CANCELED 6
#define ANTC_CORE_ROOT_ONLY 1
#define ANTC_CORE_NATIVE_ELF64 2
#define ANTC_CORE_FILTERED_MEMORY 4
#define ANTC_CORE_COVERAGE_GAP 8
#define ANTC_CORE_MANUAL 0x10
#define ANTC_CORE_PAUSE_RELEASED 0x20
#define ANTC_CORE_RESIDENT_ONLY 0x40
#define ANTC_RESOURCES 0x1070
#define ANTC_RESOURCES_SIZE 96
#define ANTC_RESOURCES_MEMORY_VALID 1
#define ANTC_RESOURCES_FILESYSTEM_VALID 2
#define ANTC_RESOURCES_REFRESHING 4
/* Telemetry lifecycle records (no control command): phase-3 events whose one
 * field is a fixed little-endian structure. Layout names are versioned.
 * lifecycle.creds, layout "antinomie.creds/1", 72 bytes: u32 uid, euid, suid,
 * fsuid at 0/4/8/12, gid, egid, sgid, fsgid at 16/20/24/28 (init user namespace;
 * 0xffffffff unmapped), u32 auid (loginuid) at 32 and u32 session id at 36
 * (0xffffffff unset), u32 reason at 40, u32 flags at 44 (bit0 AUDIT: the kernel
 * tracks loginuid), u64 cap_effective, cap_permitted, cap_inheritable at
 * 48/56/64. Recorded at a task's first traced call (START) and whenever any of
 * these change; the record belongs to the call it happened in.
 * lifecycle.file_hash, layout "antinomie.hash/1", 80 bytes: u8 kind at 0,
 * u8 status at 1, u8 algorithms at 2 (bit0 SHA-256), u8 flags at 3, s32 error
 * at 4, u64 size (bytes at the event) at 8, u64 hashed bytes at 16, u64 size
 * limit at 24 (flag bit2 CACHED: served from a digest of the same inode state
 * hashed earlier), sha256[32] at 32 (zero unless status is OK), u32 queue wait
 * and u32 hashing time in microseconds at 64/68, u32 cumulative records
 * lost since boot at 72 (queue, budget, memory or ring loss), zero at 76.
 * Published after the call returned, by a worker, with the call's identity.
 */
#define ANTC_CREDS_SIZE 72
#define ANTC_CRED_START 1
#define ANTC_CRED_SETUID 2
#define ANTC_CRED_SETGID 3
#define ANTC_CRED_SETRES 4
#define ANTC_CRED_SETFS 5
#define ANTC_CRED_CAPSET 6
#define ANTC_CRED_EXEC_SETID 7
#define ANTC_CRED_EXEC_CAPS 8
#define ANTC_CRED_LOGINUID 9
#define ANTC_CRED_OTHER 10
#define ANTC_CRED_AUDIT 1
#define ANTC_HASH_SIZE 80
#define ANTC_HASH_EXEC 1
#define ANTC_HASH_DELETE 2
#define ANTC_HASH_OK 0
#define ANTC_HASH_TOO_LARGE 1
#define ANTC_HASH_UNSUPPORTED_FS 2
#define ANTC_HASH_NOT_REGULAR 3
#define ANTC_HASH_QUEUE_FULL 4
#define ANTC_HASH_READ_ERROR 5
#define ANTC_HASH_NO_MEMORY 6
#define ANTC_HASH_BUDGET 7
#define ANTC_HASH_SHA256 1
#define ANTC_HASH_INTERPRETER 1
#define ANTC_HASH_CHANGED 2
#define ANTC_HASH_CACHED 4
#define ANTC_HASH_FILE_MAX 16777216
#define ANTC_HASH_PENDING_MAX 67108864
#define ANTC_HASH_QUEUE 16
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
 * EXEC: header flags=EXEC_SPECIMEN|EXEC_CORE (both optional), uid at8,
 * gid at12, argc at16,
 * u32 envc at 20, u32 path_len at 24, u32 cwd_len at 28; path then cwd
 * at 32, followed by argc then envc entries, each u32 byte_len + bytes.
 * argc >= 1, explicit argv[0], absolute executable and cwd, no interior NUL.
 * Reply: u64 session_id, u64 task_cookie, u32 pid, u32 reserved=0 (24 bytes).
 * Each launch owns a Unix98 PTY. Target is spawned directly by kernel
 * usermodehelper_exec; no userspace control/helper process.
 * EXEC_SPECIMEN appends u32 max_size, u32 timeout_ms after argv/env.
 * Its reply appends the 24-byte acquisition reply to the normal 24 bytes.
 * Acquisition failure never changes the execution result.
 * EXEC_CORE appends u32 max_size (1..64MiB), u32 timeout_ms (1..5000),
 * after the optional specimen trailer. Reply appends u64 core_id, u64
 * max_size, i32 status, u32 reserved=0 after optional specimen reply.
 * Arm failure has id/size=0 and negative errno; execution still succeeds.
 * Only the launched root thread group is eligible, native Linux ELF64.
 * CORE_STATUS: header flags=0, u64 id at 8, 16 bytes total. Reply80:
 * u64 id/root_cookie/start_ns/finish_ns/size/expected_size at 0/8/16/24/32/40,
 * u32 state at48, i32 status at52, i32 original wait_status at56,
 * u32 signal/flags/tgid/thread_count/reserved=0 at60/64/68/72/76.
 * Expected size is zero if complete ELF program headers are unavailable.
 * States: ARMED/COPYING/READY/PARTIAL/UNAVAILABLE/CANCELED. READY has
 * status0; PARTIAL retains a prefix with negative errno. Flags identify
 * root-only, native ELF64, Linux coredump_filter and coverage limitations.
 * CORE_READ has the same request/reply layout and bound as SPECIMEN_READ.
 * Only READY/PARTIAL data is readable; it is immutable.
 * CORE_RELEASE: header flags=0, u64 id at8; removes/cancels the handle.
 * Four handles, 128MiB global reservation; terminal handles expire after
 * 180s idle. Armed handles require release; no automatic cancellation of
 * a long running process. Release while copying retains its reservation
 * until capture unwinds. Unknown ids return -ESRCH; ids/root cookies must
 * be revalidated across snapshot epochs. No side-effect retry guarantee.
 * Timeout bounds serialization, not Linux thread rendezvous/page faults.
 * Linux memory filtering applies, so not every mapped byte is included.
 * Revision16 manual acquisition retains the same STATUS80/READ/RELEASE.
 * CORE_CAPTURE: header0, cookie8:u64, start_boot_ns16:u64, tgid24:u32,
 * max_size28:u32, timeout_ms32:u32, policy36:u32=1 (resident-only),
 * nonce_lo40:u64, nonce_hi48:u64; 56 bytes. Reply is the 24-byte arm reply.
 * CORE_LOOKUP: header0, cookie8:u64, start_boot_ns16:u64, tgid24:u32,
 * reserved28:u32=0, nonce_lo32:u64, nonce_hi40:u64; 48 bytes. Reply STATUS80.
 * Both require nonzero cookie/tgid and a nonce that is not all zero.
 * Admission deduplicates retained identical nonce/identity/limits only;
 * LOOKUP is readonly and never starts capture. Unknown admissions are never
 * replayed. A mismatched retained nonce is -EINVAL, absent nonce -ESRCH.
 * CORE_CANCEL: header0, id8:u64; 16 bytes, empty reply. Retains status while
 * cancellation removes our pause ownership; RELEASE then removes evidence.
 * Manual status root_cookie is selected leader cookie; wait_status/signal0.
 * MANUAL/RESIDENT_ONLY flags identify mode. Terminal PAUSE_RELEASED proves
 * our parks are removed, not that the scheduler ran or external stops ended.
 * One manual admission, including late callbacks, owns up to 8MiB auxiliary
 * metadata in addition to the existing 128MiB/four-handle output pool.
 * Native leader identity, 256 threads, 4096 VMAs/extents, 65536 page probes;
 * stopped/traced/exiting/shared-mm or changing groups are unsupported.
 * No signal->core_state, SIGSTOP/SIGCONT, fatal teardown or helper process.
 * Native filtered ELF notes and resident pages are observational. Missing or
 * unscanned pages have p_filesz=0, never fabricated zero bytes; Partial is
 * explicit. Deadlines are cooperative, not hard real-time guarantees.
 * Reattachment cancels in-flight manual sessions before fence acknowledgment;
 * completed immutable buffers remain readable. Snapshot operations must
 * reject an in-flight manual capture before pausing/restoring the VM.
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
 * RESOURCES: header only (8 bytes). Non-blocking: returns the latest completed
 * sample and, if it is older than 500 ms and no refresh runs, queues one on a
 * dedicated worker (at most one in flight). Reply (96 bytes): u64 sequence at 0
 * (0 = no sample yet), u64 age_ms at 8 (U64_MAX if none), u32 flags at 16
 * (MEMORY_VALID, FILESYSTEM_VALID, REFRESHING), s32 fs_error at 20,
 * u64 memory total/available bytes at 24/32 (MemTotal, MemAvailable as in
 * /proc/meminfo), u64 filesystem total/free/available bytes at 40/48/56
 * (statfs of PID 1's root, f_frsize units, free = privileged-free, available =
 * unprivileged), u32 fs_dev at 64 (new_encode_dev), u32 fs_type at 68,
 * u64 fs_id at 72, u64 refresh_pending_ms at 80 (0 when idle), s32 mem_error
 * at 88, zero at 92. A value is meaningful only when its VALID flag is set.
 * SHUTDOWN: header only; empty success reply, delayed kernel_power_off.
 */
#endif
