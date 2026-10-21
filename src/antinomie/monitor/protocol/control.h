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
#define ANTC_RUN_KILL_ESCALATED 32
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
#define ANTC_EXEC_DEBUG 4
/* Optional EXEC flags (revision 17, additive): only for a guest whose
 * TRACER_CAPS lists them; an older guest rejects unknown flags with -EINVAL. */
#define ANTC_EXEC_HASH_ROOT 8
#define ANTC_EXEC_HASH_WRITES 16
#define ANTC_EXEC_SHELL_JOB 32
#define ANTC_CORE_STATUS 0x1060
#define ANTC_CORE_READ 0x1061
#define ANTC_CORE_RELEASE 0x1062
#define ANTC_CORE_CAPTURE 0x1063
#define ANTC_CORE_LOOKUP 0x1064
#define ANTC_CORE_CANCEL 0x1065
/* Revision 17 additions (0.7.0): CORE_CAPS and CORE_STATUS STORED are optional.
 * A host must treat -EOPNOTSUPP from CORE_CAPS as the 64MiB / 5000ms contract
 * and must not send the STORED flag to a guest that did not advertise it. */
#define ANTC_CORE_CAPS 0x1066
#define ANTC_CORE_STATUS_SIZE 80
#define ANTC_CORE_STATUS_STORED 1
#define ANTC_CORE_STATUS_STORED_SIZE 96
#define ANTC_CORE_CAPS_SIZE 48
#define ANTC_CORE_CAPS_BUDGET 1
#define ANTC_CORE_CAPS_STORED 2
#define ANTC_CORE_CAPS_LONG_TIMEOUT 4
#define ANTC_CORE_CAPS_CHUNKED 8
#define ANTC_CORE_CAPS_FAST_READ 16
#define ANTC_CORE_READ_HOLE 1
#define ANTC_CORE_LOGICAL_MAX 17179869184ULL
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
/* Debugger (revision 17, additive): ptrace-free process debug sessions. */
#define ANTC_DEBUG_CAPS 0x1080
#define ANTC_DEBUG_ATTACH 0x1081
#define ANTC_DEBUG_DETACH 0x1082
#define ANTC_DEBUG_STATUS 0x1083
#define ANTC_DEBUG_STOP 0x1084
#define ANTC_DEBUG_CONT 0x1085
#define ANTC_DEBUG_THREADS 0x1086
#define ANTC_DEBUG_REGS_READ 0x1087
#define ANTC_DEBUG_REGS_WRITE 0x1088
#define ANTC_DEBUG_MEM_READ 0x1089
#define ANTC_DEBUG_MEM_WRITE 0x108a
#define ANTC_DEBUG_BP_SET 0x108b
#define ANTC_DEBUG_BP_CLEAR 0x108c
#define ANTC_DEBUG_AUXV 0x108d
#define ANTC_DEBUG_CONFIG 0x108e
#define ANTC_DEBUG_EVENTS 0x108f
#define ANTC_DEBUG_THREAD_CTL 0x1090
#define ANTC_DEBUG_SESSIONS 0x1091
#define ANTC_DEBUG_BP_LIST 0x1092
/* Tracer capabilities (revision 17, additive, optional): the optional EXEC
 * flags this guest accepts and the hashing budget. -EOPNOTSUPP from an older
 * guest means none: the host must then send none of them. */
#define ANTC_TRACER_CAPS 0x10a0
#define ANTC_TRACER_CAPS_SIZE 32
#define ANTC_TRACER_ABI 1
#define ANTC_DEBUG_ABI 1
#define ANTC_DEBUG_CAPS_SIZE 48
#define ANTC_DEBUG_REGSET_SIZE 16
#define ANTC_DEBUG_REGSET_MAX 8
#define ANTC_DEBUG_STATUS_SIZE 96
#define ANTC_DEBUG_THREAD_SIZE 32
#define ANTC_DEBUG_TRANSFER_MAX 16000
#define ANTC_DEBUG_ATTACH_STOP 1
#define ANTC_DEBUG_DETACH_KILL 1
#define ANTC_DEBUG_CONT_STEP 1
#define ANTC_DEBUG_REGS_ALL 1
#define ANTC_DEBUG_ATTACH_ADOPT 2
#define ANTC_DEBUG_CAPS_EXT 1
#define ANTC_DEBUG_CAPS_EXT_SIZE 16
#define ANTC_DEBUG_CONFIG_SIZE 24
#define ANTC_DEBUG_EVENTS_SIZE 32
#define ANTC_DEBUG_EVENT_MAX 8
#define ANTC_DEBUG_EVENT_ENTRY_SIZE 336
#define ANTC_DEBUG_EVENT_PATH_SIZE 256
#define ANTC_DEBUG_EVENTS_CURRENT 1
#define ANTC_DEBUG_THREAD_CTL_SIZE 32
#define ANTC_DEBUG_SESSION_ENTRY_SIZE 72
#define ANTC_DEBUG_BP_LIST_SIZE 24
#define ANTC_DEBUG_BP_ENTRY_SIZE 24
/* thread control actions */
#define ANTC_DEBUG_TCTL_STOP 1
#define ANTC_DEBUG_TCTL_CONT 2
#define ANTC_DEBUG_TCTL_STEP 3
/* session options (CONFIG) */
#define ANTC_DEBUG_OPT_FORK 1
#define ANTC_DEBUG_OPT_EXEC 2
#define ANTC_DEBUG_OPT_NONSTOP 4
/* event flags */
#define ANTC_DEBUG_EVF_SHARED_MM 1
/* status / session flags */
#define ANTC_DEBUG_SF_CHILD_PENDING 1
#define ANTC_DEBUG_SF_SHARED_MM 2
#define ANTC_DEBUG_SF_NONSTOP 4
/* thread entry flags */
#define ANTC_DEBUG_TF_VFORK_WAIT 1
/* capability flags */
#define ANTC_DEBUG_CAP_SW_BREAKPOINT 1
#define ANTC_DEBUG_CAP_HW_SINGLE_STEP 2
#define ANTC_DEBUG_CAP_SHADOW_READS 4
#define ANTC_DEBUG_CAP_MULTI_THREAD 8
#define ANTC_DEBUG_CAP_HW_BREAKPOINT 16
#define ANTC_DEBUG_CAP_HW_WATCHPOINT 32
#define ANTC_DEBUG_CAP_SIGNALS 64
#define ANTC_DEBUG_CAP_BATCH_REGS 128
#define ANTC_DEBUG_CAP_START 256
#define ANTC_DEBUG_CAP_AUXV 512
/* second capability word (CAPS requested with CAPS_EXT) */
#define ANTC_DEBUG_CAP2_FOLLOW 1
#define ANTC_DEBUG_CAP2_NONSTOP 2
#define ANTC_DEBUG_CAP2_ADOPT 4
#define ANTC_DEBUG_CAP2_THREAD_HW 8
/* session states */
#define ANTC_DEBUG_RUNNING 1
#define ANTC_DEBUG_STOPPING 2
#define ANTC_DEBUG_STOPPED 3
#define ANTC_DEBUG_RESUMING 4
#define ANTC_DEBUG_EXITED 5
#define ANTC_DEBUG_EXEC 6
#define ANTC_DEBUG_DETACHING 7
/* stop events */
#define ANTC_DEBUG_EVENT_NONE 0
#define ANTC_DEBUG_EVENT_INTERRUPT 1
#define ANTC_DEBUG_EVENT_BREAKPOINT 2
#define ANTC_DEBUG_EVENT_STEP 3
#define ANTC_DEBUG_EVENT_EXIT 4
#define ANTC_DEBUG_EVENT_EXEC 5
#define ANTC_DEBUG_EVENT_SIGNAL 6
#define ANTC_DEBUG_EVENT_HWBREAK 7
#define ANTC_DEBUG_EVENT_WATCH 8
#define ANTC_DEBUG_EVENT_ENTRY 9
#define ANTC_DEBUG_EVENT_FORK 10
#define ANTC_DEBUG_EVENT_VFORK 11
#define ANTC_DEBUG_EVENT_VFORK_DONE 12
#define ANTC_DEBUG_EVENT_CHILD 13
/* per-thread states */
#define ANTC_DEBUG_THREAD_RUNNING 1
#define ANTC_DEBUG_THREAD_STOPPED 2
#define ANTC_DEBUG_THREAD_GONE 3
/* breakpoint kinds */
#define ANTC_DEBUG_BP_SOFTWARE 1
#define ANTC_DEBUG_BP_HW_EXEC 2
#define ANTC_DEBUG_BP_HW_WRITE 3
#define ANTC_DEBUG_BP_HW_ACCESS 4
/* Telemetry lifecycle records (no control command): phase-3 events whose one
 * field is a fixed little-endian structure. Layout names are versioned.
 * lifecycle.creds, layout "antinomie.creds/2", 96 bytes: u32 uid, euid, suid,
 * fsuid at 0/4/8/12, gid, egid, sgid, fsgid at 16/20/24/28 (init user namespace;
 * 0xffffffff unmapped), u32 auid (loginuid) at 32 and u32 session id at 36
 * (0xffffffff unset), u32 reason at 40, u32 flags at 44 (bit0 AUDIT: the kernel
 * tracks loginuid), u64 cap_effective, cap_permitted, cap_inheritable at
 * 48/56/64, u64 cap_bounding at 72, u64 cap_ambient at 80, u32 securebits at 88
 * and zero at 92. Recorded at a task's first traced call (START) and whenever
 * any of these change (all five capability sets and the securebits); the
 * record belongs to the call it happened in. The first 72 bytes are the
 * layout "antinomie.creds/1" of earlier builds, which the host still reads.
 * lifecycle.file_hash, layout "antinomie.hash/1", 80 bytes: u8 kind at 0,
 * u8 status at 1, u8 algorithms at 2 (bit0 SHA-256), u8 flags at 3, s32 error
 * at 4, u64 size (bytes at the event) at 8, u64 hashed bytes at 16, u64 size
 * limit at 24 (flag bit2 CACHED: served from a digest of the same inode state
 * hashed earlier), sha256[32] at 32 (zero unless status is OK), u32 queue wait
 * and u32 hashing time in microseconds at 64/68, u32 cumulative records
 * lost since boot at 72 (queue, budget, memory or ring loss), zero at 76.
 * Published after the call returned, by a worker, with the call's identity.
 * Kinds: EXEC (1) an executed image; DELETE (2) a file about to be unlinked;
 * WRITE (3) a regular file a task of the run had open for writing, when the
 * last writer of the file closed it (only for a run launched with EXEC flag
 * HASH_WRITES). A WRITE record uses layout "antinomie.hash/2", 112 bytes: the
 * 80 above, then the file at the close: u64 dev at 80 (new_encode_dev),
 * u64 ino at 88, u32 generation at 96, u32 mode at 100, u32 nlink at 104,
 * zero at 108. Its call is the one the closing task made last (close, dup2,
 * exit_group, munmap, or the call a signal ended), since the last close of a
 * file happens when its last reference goes, not necessarily in a call that
 * names it. Pseudo filesystems (proc, sysfs, cgroup, debugfs, tracefs,
 * securityfs, bpf, pstore, efivarfs, selinuxfs, smackfs, binfmt_misc) and
 * files that are not regular publish nothing; a regular file elsewhere that is
 * not read publishes its reason. CHANGED compares the file with its state at
 * that close. With EXEC flag HASH_ROOT the launched program's own image is
 * hashed too, as an EXEC record of the root task with call id 0 and syscall
 * number U64_MAX: the identity of its "lifecycle.launch" event, since the
 * kernel starts the program without a traced execve.
 * lifecycle.file_id, layout "antinomie.fileid/1", 32 bytes (optional, additive:
 * a guest from before it publishes none, a host that does not know it shows an
 * unknown lifecycle field): the identity of the file inode a call acted on, so
 * one file can be followed across names. u8 kind at 0 (OPEN: the file an open
 * returned; RENAME: the inode moved; LINK: the inode that got a new name;
 * UNLINK: the inode whose name was removed; ISSUE: the file an io_uring or AIO
 * request used; EXEC: the executed image), u8 flags at 1 (bit0 directory,
 * bit1 regular file, bit2 symbolic link), zero at 2, u32 nlink at 4 (after the
 * call), u64 dev at 8 (new_encode_dev of the superblock), u64 ino at 16,
 * u32 generation at 24 (i_generation; with dev and ino it tells a reused inode
 * number from the file that held it before), u32 mode at 28 (i_mode). Only
 * calls that succeeded publish one. An io_uring request carries the same
 * record as its operand "async.operand.file_id", with the same layout name; for
 * RENAMEAT, LINKAT and UNLINKAT, which look the name up before they run, nlink is
 * the count the operation leaves if it succeeds.
 * lifecycle.exec_image, layout "antinomie.execimg/1" (optional, additive):
 * published once per execve at the commit point. u32 flags at 0 (bit0
 * INTERPRETER: the image is a script's interpreter, bit1 INTERP_TRUNCATED,
 * bit2 PATH_TRUNCATED), u32 interp_len at 4 and u32 path_len at 8 (bytes
 * including the NUL; 0 = absent), u32 nlink at 12, u64 dev at 16, u64 ino at 24,
 * u32 generation at 32, u32 mode at 36, then at 40 the interpreter exactly as
 * the script's "#!" line names it (bprm->interp), then the resolved path of the
 * image that was loaded (for a script, the interpreter's file), each NUL
 * terminated and cut at 511 bytes. dev, ino, generation and mode are those of
 * the loaded image.
 */
#define ANTC_FILEID_SIZE 32
#define ANTC_FILEID_OPEN 1
#define ANTC_FILEID_RENAME 2
#define ANTC_FILEID_LINK 3
#define ANTC_FILEID_UNLINK 4
#define ANTC_FILEID_ISSUE 5
#define ANTC_FILEID_EXEC 6
#define ANTC_FILEID_DIR 1
#define ANTC_FILEID_REGULAR 2
#define ANTC_FILEID_SYMLINK 4
#define ANTC_EXECIMG_HEADER 40
#define ANTC_EXECIMG_PATH_MAX 512
#define ANTC_EXECIMG_INTERPRETER 1
#define ANTC_EXECIMG_INTERP_TRUNCATED 2
#define ANTC_EXECIMG_PATH_TRUNCATED 4
#define ANTC_CREDS_SIZE 96
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
#define ANTC_CRED_PRCTL 11
#define ANTC_CRED_AUDIT 1
#define ANTC_HASH_SIZE 80
#define ANTC_HASH_EXEC 1
#define ANTC_HASH_DELETE 2
#define ANTC_HASH_WRITE 3
#define ANTC_HASH_WRITE_SIZE 112
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
 * EXEC_CORE appends u32 max_size (1..max_core_bytes from CORE_CAPS, 1..64MiB
 * without it), u32 timeout_ms (1..max_timeout_ms from CORE_CAPS, 1..5000
 * without it),
 * after the optional specimen trailer. Reply appends u64 core_id, u64
 * max_size, i32 status, u32 reserved=0 after optional specimen reply.
 * EXEC_DEBUG (Debug on start; capability DEBUG_START) opens a debug session on
 * the new process before it runs: it parks at its first return to user mode,
 * before its first user instruction (the loader's entry for a dynamic program,
 * the ELF entry for a static one), with event ENTRY. It adds no request bytes.
 * The reply appends u64 start_boot_ns, u64 reserved=0 (16 bytes, after any core
 * reply), the identity ATTACH needs; ATTACH then adopts the session (any nonce)
 * instead of creating one. -EBUSY when another session is live. The program
 * stays parked until the debugger continues it or detaches; STOP_RUN and the
 * Stop escalation end it.
 * EXEC_HASH_ROOT hashes the program's own image at its exec; EXEC_HASH_WRITES
 * hashes the regular files the run writes, when the last writer closes them
 * (see lifecycle.file_hash). EXEC_SHELL_JOB starts the program as a job of a
 * terminal shell that has closed: its parent is init (PID 1), not kthreadd,
 * and it leads its own process group, the terminal's foreground group, in a
 * session whose leader no longer exists (the session id is a PID no process
 * has). None of them adds request or reply bytes.
 * TRACER_CAPS: header only (8 bytes). Reply 32 bytes: u32 abi=1 at 0, u32
 * exec_flags at 4 (the optional EXEC flags this guest accepts: HASH_ROOT,
 * HASH_WRITES, SHELL_JOB), u32 hash file limit at 8 (ANTC_HASH_FILE_MAX), u32 hash queue
 * jobs at 12 (ANTC_HASH_QUEUE), u64 hash queued byte limit at 16
 * (ANTC_HASH_PENDING_MAX), zero at 24.
 * Arm failure has id/size=0 and negative errno; execution still succeeds.
 * Only the launched root thread group is eligible, native Linux ELF64.
 * CORE_STATUS: header flags=0, u64 id at 8, 16 bytes total. Reply80:
 * u64 id/root_cookie/start_ns/finish_ns/size/expected_size at 0/8/16/24/32/40,
 * u32 state at48, i32 status at52, i32 original wait_status at56,
 * u32 signal/flags/tgid/thread_count/reserved=0 at60/64/68/72/76.
 * With header flags=STORED (ANTC_CORE_STATUS_STORED, only for a guest whose
 * CORE_CAPS advertised STATUS_STORED) the reply is 96 bytes: the 80 above, then
 * u64 stored at 80 (bytes held in the buffer, zero until terminal like size)
 * and u64 reserved=0 at 88. Any other header flag is -EINVAL.
 * CORE_CAPS: header only (8 bytes). Reply 48 bytes: u32 abi=1 at 0, u32 flags at
 * 4 (bit0 BUDGET: max_size up to max_core_bytes; bit1 STATUS_STORED; bit2
 * LONG_TIMEOUT: timeout_ms up to max_timeout_ms; bit3 CHUNKED: the buffer grows
 * while it is written, so -ENOMEM means the budget could not be reached; bit4
 * FAST_READ: the guest polls every tick while a finished core is read),
 * u64 max_core_bytes at 8 (per handle, 64MiB..1GiB: half of RAM less 128MiB,
 * clamped), u64 pool_bytes at 16 (sum of the budgets of open handles, twice
 * the maximum), u32 max_handles=4 at 24, u32 max_timeout_ms=60000 at 28,
 * u64 guest_ram_bytes at 32, u64 prealloc_bytes at 40 (an exit core allocates
 * this much when armed; the rest in 8MiB chunks as the core is written).
 * The sink enforces the budget, so the status errno of a core is one reason:
 * -EFBIG stored-byte budget reached, -ENOMEM no memory for another chunk,
 * -ETIMEDOUT deadline, -ECANCELED cancel/release/fence, -E2BIG extent table
 * full or more than 256 threads / 4096 mappings, -EOVERFLOW logical extent past
 * 16GiB, -ENODATA coverage gap, -EINTR signal, -EIO the writer stopped
 * otherwise. Earlier guests reported the first, fourth-from-last and last of
 * these as -EIO or -EFBIG without that distinction.
 * Expected size is zero if complete ELF program headers are unavailable.
 * States: ARMED/COPYING/READY/PARTIAL/UNAVAILABLE/CANCELED. READY has
 * status0; PARTIAL retains a prefix with negative errno. Flags identify
 * root-only, native ELF64, Linux coredump_filter and coverage limitations.
 * CORE_READ has the same request/reply layout and bound as SPECIMEN_READ,
 * except that a core file is sparse and the u32 at reply offset 20 (zero for
 * data) is a flags word: bit0 HOLE (ANTC_CORE_READ_HOLE) means the count bytes
 * at the offset are zeros that were never stored (Linux skips pages that are
 * not resident) and no payload follows (reply length 24); count then names the
 * whole hole up to the next stored byte, at most 1 GiB, and is not bounded by
 * the requested capacity. A data reply never crosses into a hole. size and
 * expected_size are the file's logical extent, at most 16 GiB; the handle's
 * max_size bounds the bytes actually stored (data replies), not that extent.
 * Only READY/PARTIAL data is readable; it is immutable.
 * CORE_RELEASE: header flags=0, u64 id at8; removes/cancels the handle.
 * Four handles; their budgets add up to at most pool_bytes (128MiB on a guest
 * without CORE_CAPS); terminal handles expire after
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
 * STOP_RUN: header flags=0, nonzero u64 root_task_cookie at 8 (16 bytes), or
 * 24 bytes with u32 grace_ms at 16 (0 selects the default, 4000; otherwise
 * 100..30000) and u32 reserved=0 at 20.
 * Requests SIGTERM for each traced task with this inherited launch cookie,
 * including descendants after root exit or PTY/session reaping. Empty reply.
 * Status 0 means signal requests issued, not proven tree termination; -ESRCH
 * means no signalable matching task. Concurrent forks may escape this pass.
 * After the grace period the guest itself sends SIGKILL to every task of the
 * run still alive and repeats it every 250 ms (20 passes at most) while tasks
 * remain, and sets RUN_STATUS flag KILL_ESCALATED (32). A process core being
 * copied is not interrupted: the escalation waits for it, for at most 15 s
 * past the grace period. A later STOP_RUN only brings the deadline forward.
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
 *
 * Debugger (ptrace-free; the target sees no TracerPid, PTRACE_TRACEME still works,
 * and no signal is raised for engine breakpoints or steps). One session at a
 * time. Every request is header (version 1, header_len 8, flags) then the fields
 * below. Replies are little endian. Registers travel as the kernel's regset
 * blobs tagged with their ELF note type (NT_PRSTATUS=1 user_regs_struct,
 * NT_PRFPREG=2 FXSAVE image, NT_X86_XSTATE=0x202), so another architecture adds
 * a per-arch file and no wire change. All memory/register access needs the
 * session STOPPED (else -EBUSY); a stale generation is -ESTALE.
 * CAPS: header only. Reply 48 bytes + regset table: u32 abi(1) at 0, u32 arch
 * (ELF e_machine) at 4, u32 flags at 8, u32 swbp_len_mask at 12 (bit n-1 means
 * a length-n software breakpoint), u32 hw_breakpoints at 16, u32 hw_watchpoints
 * at 20, u32 hw_watch_len_mask at 24, u32 max_threads at 28, u32 max_transfer at
 * 32, u32 regset_count (0..8) at 36, zero at 40; then 16-byte regset entries
 * {u32 nt_type, u32 max_size (0 = query), u32 flags (bit0 writable), u32 0}.
 * ATTACH: flags bit0 STOP_NOW, u64 task_cookie at 8, u64 start_boot_ns at 16,
 * u32 tgid at 24, u32 arch at 28 (must equal CAPS arch), u64 nonce_lo at 32,
 * u64 nonce_hi at 40 (nonzero); 48 bytes. Reply: u64 session_id, u64 generation,
 * u32 thread_count, u32 arch (24 bytes). The same nonce and identity returns the
 * existing session; another request while one exists is -EBUSY (an EXITED or
 * EXEC session is replaced). Mutations are never replayed by the guest.
 * DETACH: flags bit0 KILL, u64 session_id at 8 (16 bytes). Asynchronous: it
 * stops the group, removes breakpoints and resumes (or SIGKILLs); STATUS shows
 * DETACHING until the session is gone (-ESRCH). A group that cannot be stopped
 * stays attached with last_error set.
 * STATUS: u64 session_id at 8 (16 bytes). Reply 96 bytes: u64 session_id at 0,
 * u64 generation at 8, u32 state at 16, u32 flags at 20, u32 live threads at 24,
 * u32 stopped threads at 28, u32 event kind at 32, u32 event tid at 36, u64
 * event pc at 40, u64 event address at 48, u32 wait status (EXITED) at 56,
 * s32 last_error at 60, u32 event sequence at 64, u32 breakpoints at 68, u32
 * event signal at 72 (SIGNAL events), u32 event access at 76 (WATCH events: the
 * BP kind that fired), zero at 80..96. BREAKPOINTS counts every kind.
 * STOP: session_id at 8; asynchronous group stop, reply u64 generation. A
 * breakpoint, step or exit stops the group by itself (all-stop).
 * CONT: flags bit0 STEP, u64 session_id at 8, u64 tid at 16 (STEP: the thread to
 * step, others stay stopped; 0 continue), u32 signal at 24, u32 signal_tid at
 * 28, u64 generation at 32 (40 bytes). Asynchronous; reply u64 generation. A
 * breakpoint under a thread is stepped over with the group stopped. A step is
 * exactly one user instruction: a syscall instruction or a repeated string
 * instruction runs to the instruction after it (a temporary breakpoint, with the
 * rest of the group stopped), never kernel instructions or one iteration.
 * Signals (capability SIGNALS): every signal about to be delivered to a thread
 * of the group stops the group first (event SIGNAL, the number in STATUS and in
 * the thread entry), before the handler frame exists, so the sample never sees
 * the engine's trap flag in it. signal is the number to deliver to signal_tid
 * (0: the thread that reported the stop) when the group resumes; 0 drops the
 * signal that thread stopped on, another number replaces it. A thread stopped on
 * a different signal than the reported one delivers its own. For a thread not
 * stopped on a signal the number is queued to it. STEP with a signal delivered
 * to a handler stops at the handler's first instruction.
 * THREADS: session_id at 8. Reply u32 count at 0, u32 total at 4, then 32-byte
 * entries {u32 tid, u32 state, u32 stop reason, u32 signal (when stopped on
 * one), u64 pc, u64 0}.
 * REGS_READ: session_id at 8, u32 tid at 16, u32 nt_type at 20, u64 generation
 * at 24 (32 bytes). Reply u32 nt_type, u32 length, u64 0, then the blob. With
 * flags bit0 REGS_ALL (capability BATCH_REGS) u32 at 20 is instead a mask of
 * CAPS register-set table indexes, and the reply is u32 count, u32 0, u64 0
 * followed by, for each selected set in table order, the 16-byte header and
 * blob of the single form.
 * REGS_WRITE: the same 32 bytes, u32 length at 32, u32 0 at 36, blob at 40.
 * The kernel validates the blob like its own regset writer. Empty reply.
 * MEM_READ: session_id at 8, u64 address at 16, u32 length (1..16000) at 24,
 * u32 0 at 28, u64 generation at 32 (40 bytes). Reply u32 count, u32 0, bytes at
 * 8. Short reads end at the first unreadable byte; none readable is -EFAULT.
 * MEM_WRITE: the same 40 bytes with the length at 24, bytes at 40. Reply u32
 * count, u32 0. Writes break copy-on-write like a debugger's poke.
 * BP_SET / BP_CLEAR: session_id at 8, u32 kind (1 software, 2 hardware execute,
 * 3 hardware write, 4 hardware access) at 16, u32 length at 20, u64 address at
 * 24, u64 generation at 32 (40 bytes), empty reply. A software breakpoint is
 * written only while the group runs and removed at every stop, and only where
 * the engine's byte is still in place (code the program rewrote is left alone);
 * the sample's own reads through /proc/self/mem see the original bytes. A direct
 * load from its own code can still see the engine's breakpoint byte.
 * Hardware kinds (capabilities HW_BREAKPOINT, HW_WATCHPOINT) use the debug
 * registers through the kernel's own breakpoint facility, per thread and for
 * every thread of the group, and leave no byte in memory: execute has length 1,
 * write and access have length 1, 2, 4 or 8 and an address aligned to it. CAPS
 * hw_breakpoints / hw_watchpoints (4) are one pool of slots shared by all hardware
 * kinds; BP_SET with none left is -ENOSPC, an unsupported or misaligned request
 * -EINVAL / -EOPNOTSUPP. A hit stops the group (events HWBREAK, WATCH; the
 * address is the breakpoint's, the pc is after the access for a watchpoint). The
 * sample cannot see them: they are not ptrace's virtual debug registers, so a
 * tracer of the sample reads zeros, and no SIGTRAP is raised. A thread created
 * while the group runs gets them at the next stop. A hit by a hardware
 * breakpoint does not retrigger when the thread resumes.
 * AUXV: session_id at 8, u64 generation at 16 (24 bytes), session STOPPED (capability
 * AUXV). Reply u32 length, u32 0, then the auxiliary vector the kernel gave the
 * program at exec (pairs of u64, ending with AT_NULL): the base address of a
 * position independent program and of its loader.
 *
 * Debugger, phase 3 (all of it additive: an earlier host never asks for it and an
 * earlier guest answers -EOPNOTSUPP). A host that wants the second capability word
 * sends CAPS with 16 bytes: header, u32 CAPS_EXT at 8, u32 0 at 12; the reply is
 * the same, with u32 flags2 at 40 (CAP2_FOLLOW: CONFIG, EVENTS, child sessions;
 * CAP2_NONSTOP: CONFIG non-stop, THREAD_CTL; CAP2_ADOPT: SESSIONS, BP_LIST, ATTACH
 * ADOPT; CAP2_THREAD_HW: hardware breakpoints reach threads created while the
 * group runs, before their first instruction). Without CAPS_EXT the reply is the
 * phase 2 one. Several sessions can exist at once (a followed child has its own),
 * at most 16; ATTACH of an unrelated process is still -EBUSY while one is live.
 * CONFIG: header flags=0, u64 session_id at 8, u32 options at 16, u32 mask at 20
 * (24 bytes). Options FORK (a fork or vfork of the program is an event: the parent
 * thread stops, the child gets a session of its own parked before its first user
 * instruction, holding a copy of the engine's breakpoint bytes; needs EXEC), EXEC
 * (an exec is an event and the session continues in the new image: breakpoints and
 * debug registers are dropped, the thread that exec'd is the leader, event path
 * names the program), NONSTOP (see below). Only the masked bits change. Reply u32
 * options, u32 supported. NONSTOP changes need the group stopped, -EBUSY otherwise.
 * Child sessions inherit the options. A child session is in state RUNNING until its
 * thread has parked, then STOPPED with event CHILD; STATUS flags bit CHILD_PENDING
 * says no debugger owns it yet. ATTACH with the identity from the fork event (cookie,
 * start time, tgid) and the debugger's own nonce adopts it. A child nobody adopts
 * when its parent session ends runs on free, its bytes taken out; DETACH of a child
 * does the same. A vfork child shares its parent's address space until it execs:
 * it shares the parent's breakpoint table (SHARED_MM), and the parent thread, asleep
 * in vfork, counts as stopped (event VFORK, reported at once; VFORK_DONE when the
 * child has let go). A clone with CLONE_VM that is not a vfork is not followed.
 * Stop events (STATUS, EVENTS, THREADS reason): 10 FORK (the child fields name the
 * new process), 11 VFORK, 12 VFORK_DONE, 5 EXEC (session continues), 13 CHILD (the
 * first stop of a child session; not a report).
 * EVENTS: session_id at 8, u32 ack_seq at 16, u32 max (1..8) at 20, u32 mode at 24
 * (0 queue, 1 CURRENT), u32 0 at 28 (32 bytes). Reply u32 count, u32 dropped, 8
 * zero bytes, then count 336-byte entries {u32 seq, kind, tid, signal at 0/4/8/12,
 * u64 pc at 16, u64 addr at 24, u32 aux at 32 (the BP kind of a watch), u32 flags at
 * 36 (SHARED_MM), u32 child_tgid at 40, u32 parent_tid at 44, u64 child_session,
 * child_cookie, child_start_ns at 48/56/64, u32 path_len at 72, 0 at 76, path[256]
 * at 80}. Queue mode (non-stop): events with seq <= ack_seq are forgotten, then the
 * oldest max unacknowledged events are returned, again on every call until acked;
 * dropped counts events lost to a full queue (64). CURRENT (all-stop): the event of
 * the stop, count 0 when none.
 * Non-stop (option NONSTOP, CAP2_NONSTOP): a thread with an event parks alone and the
 * others run; software breakpoint bytes stay in memory (BP_SET writes, BP_CLEAR
 * restores them at once, a write over one keeps it); memory, breakpoints and AUXV need
 * no stop, registers need the thread stopped; STATUS state stays RUNNING and its
 * event sequence is the latest queued; CONT and STOP are -EOPNOTSUPP.
 * THREAD_CTL: session_id at 8, u32 tid (0 = every thread, STOP and a CONT of all)
 * at 16, u32 action (1 STOP, 2 CONT, 3 STEP) at 20, u32 signal at 24 (delivered to
 * the thread; a thread stopped on a signal drops it when 0), 0 at 28 (32 bytes).
 * Reply u32 threads affected, u32 0. A stopped thread reports its stop as an event
 * (kind INTERRUPT for a STOP). A step is one user instruction (a system call ends at
 * its exit, a string loop is traced in place), reported as event STEP. Breakpoints
 * under a resumed thread fire again: the debugger takes the byte out first.
 * SESSIONS: header only. Reply u32 count, u32 0, then 72-byte entries {u64 id,
 * u32 state, u32 options, u32 tgid, u32 flags (CHILD_PENDING 1, SHARED_MM 2,
 * NONSTOP 4) at 0/8/12/16/20, u64 cookie, start_ns, parent_session at 24/32/40,
 * u32 event kind, event seq, live threads, stopped threads at 48/52/56/60}. A host
 * that lost its sessions (reconnect, restored snapshot, restarted app) finds them
 * here and adopts each with ATTACH flag ADOPT (2): the identity of a live session
 * and a new nonce replace the nonce. The fence of a transport reconnect no longer
 * ends sessions; STATUS, THREADS, EVENTS and BP_LIST describe what is true.
 * BP_LIST: session_id at 8, u64 0 at 16 (24 bytes). Reply u32 count, u32 0, then
 * 24-byte entries {u32 kind, u32 length, u64 address, u32 flags (bit0: the byte is
 * in memory / the debug register is set), u32 0}: software then hardware.
 * STATUS tail (80..96, nonzero only for sessions with options or a parent): u32
 * options at 80, u32 flags at 84 (CHILD_PENDING 1, SHARED_MM 2, NONSTOP 4), u64
 * parent_session at 88. THREADS entry bytes 24..28 are the thread flags
 * (VFORK_WAIT 1) for a session with options.
 * SHUTDOWN: header only; empty success reply, delayed kernel_power_off.
 */
#endif
