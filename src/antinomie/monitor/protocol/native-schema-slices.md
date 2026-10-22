# Native Schema Slice Contract: 2A, 2B, 2G

ANT-T0009 producer/consumer contract, revision 9, 2026-10-08 (Sections 8–16 record revisions 2–9). Section 9 and the 2B fixtures were approved by the user on 2026-10-07.
Status: approved by the user on 2026-10-07, including choice (a) for unknown
socket options (raw `optval` up to `optlen`, capped at 128 KiB). Revision 2
records corrections found while implementing and testing slice 2A; see Section 8.
The V7 transport, the field record wire layout and `native-syscalls.json`
stay authoritative and unchanged. This contract adds kernel capture rules,
host naming rules, probe cases and verifier checks for:

| Slice | Syscalls (native numbers) | Current ledger owner |
|---|---|---|
| 2A | `setsockopt` 54, `getsockopt` 55 | `unhandled_pointer_schema` |
| 2B | `ptrace` 101, `sysfs` 139, `prctl` 157, `keyctl` 250 | `unhandled_selector_schema` (generic `schema.selector_decoder` gap) |
| 2G | the 17 rows without an entry point: 134, 156, 174, 177, 178, 180–185, 205, 211, 212, 214, 215, 236 | `unavailable_prototype` |

## 1. Common Rules

These rules apply to every family below and follow the existing
`native_capture.c` conventions. Field keys and `argN` references are zero-based
register argument indices, as in recorded keys: for `prctl`, `arg1` is the
syscall's `arg2` parameter.

| Rule | Contract |
|---|---|
| Selector dispatch | The kernel decodes the selector argument at entry. Each recognized selector owns an explicit pointer-role table. An unrecognized selector emits one `<family>.unknown_selector` gap with `ANT_NO_DECODER` at entry and copies nothing |
| Ownership mask | Every family returns `ANT_CAPTURE_OWNED` with mask bits for each argument that can carry a pointer for any recognized selector |
| Input phase | Input buffers are copied at entry only |
| Output phase | Output buffers are copied at exit only when the selector's success rule holds (usually `result == 0` or `result >= 0`) and are bounded by the smaller of the declared capacity and the kernel-reported written size |
| Value-result lengths | When a length lives in user memory and the kernel rewrites it (`getsockopt` optlen, regset `iovec.iov_len`), entry saves the snapshot through `ant_capture_set_state` and exit reads the rewritten value; both are recorded |
| Another process's memory | An address that belongs to another address space (ptrace tracee addresses) is recorded as `ANT_ADDRESS_ONLY` with address and length. It is never dereferenced |
| Kernel ceilings | A declared length above the pinned kernel limit is recorded with `ANT_INVALID_EXTENT` and no bytes, as the existing recorder does for every field status other than `ANT_COMPLETE` |
| Config-disabled paths | If the pinned config compiles a selector out (for example `CONFIG_CHECKPOINT_RESTORE=n`), the program's arguments are still captured by UAPI meaning; the returned error records the rejection. No capture claims that the kernel consumed them |
| Strings | `ant_capture_string` with the kernel's own ceiling for that argument |
| Secrets | Key payloads, socket filters and register contents are recorded like any other buffer. Recordings can therefore contain the program's secrets, as `read`/`write` recordings already do |
| Nested pointers | Followed only where this document lists them. Any other pointer inside a captured struct is left as raw bytes |

## 2. Slice 2A: Socket Options

### setsockopt(fd, level, optname, optval, optlen)

| Case | Entry capture | Status |
|---|---|---|
| Known integer option (Section 2.1) | `arg3.optval`, layout `int`, `min(optlen, 4)` bytes | `COMPLETE`, or `INVALID_EXTENT` when `optlen < 4` |
| Known structured option | `arg3.optval` with that option's layout, `min(optlen, sizeof(layout))` bytes | `INVALID_EXTENT` on size mismatch |
| `SO_ATTACH_FILTER`, `SO_ATTACH_REUSEPORT_CBPF` | `arg3.optval` as `sock_fprog`, then nested `arg3.optval.filter` of `len * 8` bytes | `INVALID_EXTENT` when `len == 0` or `len > BPF_MAXINSNS`. The same helper as `seccomp` filter capture |
| `SO_BINDTODEVICE` | `arg3.optval` layout `char[]`, `min(optlen, IFNAMSIZ - 1)` bytes. The kernel copies `optlen` bytes and adds its own NUL, so this is a bounded buffer, not a string | — |
| `TCP_CONGESTION`, `TCP_ULP` | `arg3.optval` layout `char[]`, `min(optlen, 15)` bytes, the same bound as the kernel's `strncpy_from_sockptr` | — |
| Unknown (level, optname) pair | Raw `arg3.optval`, `min(optlen, 128 KiB)` bytes with an empty layout, plus a `sockopt.unknown_option` gap with `ANT_NO_DECODER` | `INVALID_EXTENT` above 128 KiB, the pinned default `optmem_max` |
| `optlen < 0` | no copy; the kernel returns `EINVAL` | — |

### getsockopt(fd, level, optname, optval, optlen *)

| Phase | Capture |
|---|---|
| Entry | `arg4.optlen` (`int`), saved as the capacity. For options whose `optval` is also input (Section 2.2), `arg3.optval_in` of that option's input layout |
| Exit, `result == 0` | `arg4.optlen` again (the written length); `arg3.optval` of `min(written, layout or 128 KiB)` bytes with the option's layout (empty for unknown pairs, whose gap was recorded at entry). The declared length is the written length; a written length above the capacity is `ANT_INVALID_EXTENT`. `SO_GET_FILTER` counts instructions in `optlen`, so its byte count is `written * 8` |
| Exit, error | nothing |

### 2.1 Known option table (initial)

The implementation table is reviewed against the pinned
`net/core/sock.c`, `net/ipv4/ip_sockglue.c`, `net/ipv6/ipv6_sockglue.c` and
`net/ipv4/tcp.c`. Every option those handlers accept as a plain `int` uses the integer class.

| Level | Structured options and layouts |
|---|---|
| `SOL_SOCKET` | `SO_LINGER` `linger`; `SO_RCVTIMEO_OLD`/`SO_SNDTIMEO_OLD` `__kernel_old_timeval`; `SO_RCVTIMEO_NEW`/`SO_SNDTIMEO_NEW` `__kernel_sock_timeval`; `SO_PEERCRED` (get) `ucred`; `SO_PEERNAME` (get) sockaddr, length-bounded; `SO_ATTACH_BPF`, `SO_ATTACH_REUSEPORT_EBPF` `int` fd |
| `IPPROTO_IP` | `IP_OPTIONS` raw ≤ 40 bytes; `IP_ADD_MEMBERSHIP`/`IP_DROP_MEMBERSHIP` `ip_mreq` or `ip_mreqn`, selected by `optlen` |
| `IPPROTO_IPV6` | `IPV6_ADD_MEMBERSHIP`/`IPV6_DROP_MEMBERSHIP` `ipv6_mreq` |
| `IPPROTO_TCP` | `TCP_INFO` (get) `tcp_info`, length-bounded; `TCP_CONGESTION`, `TCP_ULP` bounded `char[]` |

### 2.2 Number collisions

- `SO_GET_FILTER` and `SO_ATTACH_FILTER` share number 26 under `SOL_SOCKET`;
  `setsockopt` means attach and `getsockopt` means get.
- Netfilter commands 64–67 overlap `IPV6_RECVTCLASS` (66) and `IPV6_TCLASS` (67).
  The IP handlers pass to netfilter only options they do not know, so the
  netfilter rule applies only when no option rule matched.

### 2.3 Explicitly Unsupported nested layouts

These keep the top-level raw bytes and add a `NO_DECODER` gap naming the nested pointer:
- netfilter `IPT_SO_SET_REPLACE`/`IP6T_SO_SET_REPLACE` (`counters` pointer)
- `IPT_SO_GET_ENTRIES` (input header)
- `MCAST_MSFILTER`/`IP_MSFILTER` (variable source list; raw by `optlen` only)

## 3. Slice 2B: Selector Families

### 3.1 prctl(option, arg2, arg3, arg4, arg5)

| Option | Pointer role |
|---|---|
| `PR_SET_NAME` | `arg1.name` string, ceiling `TASK_COMM_LEN` (16) |
| `PR_GET_NAME` | exit, `result == 0`: `arg1.name` output, 16 bytes |
| `PR_GET_PDEATHSIG`, `PR_GET_CHILD_SUBREAPER`, `PR_GET_TSC` | exit, `result == 0`: `arg1.value` `int` |
| `PR_GET_TID_ADDRESS` | exit, `result == 0`: `arg1.tid_address`, pointer-size value |
| `PR_GET_AUXV` | exit, `result >= 0`: `arg1.auxv`, `min(arg2, result)` bytes |
| `PR_SET_SECCOMP` with `SECCOMP_MODE_FILTER` | `arg2.program` `sock_fprog` plus filter array (shared helper) |
| `PR_SET_MM` with `PR_SET_MM_MAP` | `arg2.mm_map` `prctl_mm_map` (requires `arg3 == sizeof`), nested `auxv` of `auxv_size` bytes, ceiling `sizeof(mm->saved_auxv)` |
| `PR_SET_MM` with `PR_SET_MM_MAP_SIZE` | exit, `result == 0`: `arg2.size` `unsigned int` |
| `PR_SET_MM` with `PR_SET_MM_AUXV` | `arg2.auxv`, `arg3` bytes, ceiling `sizeof(mm->saved_auxv)` |
| `PR_SET_MM` with address sub-ops (`START_CODE` … `ENV_END`, `BRK`) | scalar; no copy |
| `PR_SET_VMA` with `PR_SET_VMA_ANON_NAME` | `arg4.name` string, ceiling `ANON_VMA_NAME_MAX_LEN` (80) |
| `PR_SET_SYSCALL_USER_DISPATCH` (on) | `arg4.selector` `ANT_ASYNC_UNOBSERVED` marker; the kernel reads it later on every syscall |
| `PR_SCHED_CORE` with `PR_SCHED_CORE_GET` | exit, `result == 0`: `arg4.cookie` `u64` |
| Every other option accepted by pinned `kernel/sys.c` or `security/commoncap.c` | scalar only. This includes non-x86 options (SVE, SME, PAC, PPC, RISC-V, MIPS FP), which are named but return `EINVAL` |
| Unknown option | `prctl.unknown_selector` gap |

### 3.2 ptrace(request, pid, addr, data)

`data` and every struct named below are in the **tracer's** memory and are
captured. Tracee addresses are `ANT_ADDRESS_ONLY`.

| Request | Capture |
|---|---|
| `PEEKTEXT`, `PEEKDATA` | entry: `arg2.tracee_address` address-only (8 bytes); exit, `result == 0`: `arg3.word` `unsigned long` |
| `PEEKUSR` | `addr` is a `struct user` offset (scalar); exit, `result == 0`: `arg3.word` |
| `POKETEXT`, `POKEDATA` | entry: `arg2.tracee_address` address-only; `data` is the written value (scalar) |
| `POKEUSR` | scalar |
| `GETREGS` / `SETREGS` | `arg3.regs` `user_regs_struct`, output on success / input at entry |
| `GETFPREGS` / `SETFPREGS` | `arg3.fpregs` `user_i387_struct` |
| `GETREGSET` / `SETREGSET` | entry: `arg3.iovec`; SET input `iov_base` bytes `min(iov_len, regset ceiling)`; exit, `result == 0`: the rewritten `iov_len`, and for GET the output of that length |
| `GETSIGINFO` / `SETSIGINFO` | `arg3.siginfo` `siginfo_t` |
| `PEEKSIGINFO` | entry: `arg2.args` `ptrace_peeksiginfo_args`; exit, `result > 0`: `arg3.siginfo` `result * sizeof(siginfo_t)` |
| `GETSIGMASK` / `SETSIGMASK` | `addr` is the size (must be 8); `arg3.sigmask` 8 bytes |
| `GETEVENTMSG` | exit, `result == 0`: `arg3.message` `unsigned long` |
| `GET_THREAD_AREA` / `SET_THREAD_AREA` | `arg3.desc` `user_desc` |
| `ARCH_PRCTL` | `data` is the `arch_prctl` code and `addr` the value or output pointer (`do_arch_prctl_64(child, data, addr)`); GET codes: exit output `arg2.value` `unsigned long` (revision 3 correction) |
| `GET_SYSCALL_INFO` | exit, `result > 0`: `arg3.info`, `min(addr, result)` bytes |
| `SECCOMP_GET_FILTER` | exit, `result > 0` and `data != 0`: `arg3.filter` `result * 8` bytes |
| `SECCOMP_GET_METADATA` | entry `arg3.metadata` input; exit output, `min(addr, 16)` bytes |
| `GET_RSEQ_CONFIGURATION` | exit, `result > 0`: `min(addr, result)` bytes |
| `SET`/`GET_SYSCALL_USER_DISPATCH_CONFIG` | `arg3.config` `ptrace_sud_config` (`addr` must equal its size) |
| `TRACEME`, `ATTACH`, `SEIZE`, `INTERRUPT`, `LISTEN`, `CONT`, `SYSCALL`, `SINGLESTEP`, `SINGLEBLOCK`, `SYSEMU*`, `KILL`, `DETACH`, `SETOPTIONS`, `OLDSETOPTIONS` | scalar; for `SEIZE` and `SETOPTIONS` the host decodes `data` as `PTRACE_O_*` flags |
| `GETFPXREGS`, `GETFDPIC` (not native x86-64) | named; no copy |
| Unknown request | `ptrace.unknown_selector` gap |

### 3.3 keyctl(cmd, arg2, arg3, arg4, arg5)

| Command | Capture |
|---|---|
| `JOIN_SESSION_KEYRING` | `arg1.name` string ≤ `KEY_MAX_DESC_SIZE` (4096), or none if NULL |
| `UPDATE` | `arg2.payload` `arg3` bytes, kernel ceiling `PAGE_SIZE` |
| `INSTANTIATE` | `arg2.payload` `arg3` bytes, ceiling 1 MiB − 1 |
| `INSTANTIATE_IOV` | iovec array `arg2`, count `arg3`, plus each buffer (shared vector helper) |
| `DESCRIBE`, `READ`, `GET_SECURITY` | exit, `result >= 0`: `arg2.buffer`, `min(arg3, result)` bytes |
| `SEARCH`, `RESTRICT_KEYRING` | `arg2.type` string ≤ 32; `arg3.description`/`restriction` string ≤ 4096 / `PAGE_SIZE` |
| `DH_COMPUTE` | `arg1.params` `keyctl_dh_params`; `arg4.kdf` `keyctl_kdf_params` with nested `hashname` string ≤ 128 and `otherinfo` of `otherinfolen`; exit `arg2.buffer` `min(arg3, result)`. `CONFIG_KEY_DH_OPERATIONS=n` in the pinned config, so it is expected to return `EOPNOTSUPP` |
| `PKEY_QUERY` | `arg3.info` string ≤ `PAGE_SIZE`; exit, `result == 0`: `arg4.query` `keyctl_pkey_query` |
| `PKEY_ENCRYPT`, `PKEY_DECRYPT`, `PKEY_SIGN` | `arg1.params` `keyctl_pkey_params`; `arg2.info`; `arg3.input` `in_len` bytes; exit `arg4.output` `min(out_len, result)` bytes |
| `PKEY_VERIFY` | as above, with `arg4.signature` input of `in2_len` bytes |
| `CAPABILITIES` | exit, `result >= 0`: `arg1.buffer`, `min(arg2, result)` bytes |
| All other commands accepted by pinned `security/keys/keyctl.c` | scalar |
| Unknown command | `keyctl.unknown_selector` gap |

### 3.4 sysfs(option, arg1, arg2)

| Option | Capture |
|---|---|
| 1 | `arg1.fsname` string, ceiling `PATH_MAX` (the kernel uses `getname`) |
| 2 | exit, `result == 0`: `arg2.fsname` string read up to the NUL the kernel wrote |
| 3 | scalar |
| Other | `sysfs.unknown_selector` gap |

## 4. Slice 2G: Unavailable Prototypes

The pinned `syscall_64.tbl` gives these 17 rows no entry point, so they
return `ENOSYS` in every configuration. The kernel is unchanged: it records the
raw arguments and the existing `schema.argument_metadata` gap with
`ANT_NO_DECODER`, because no prototype exists. The inventory row gains
`"implemented": false`, generated from the table rather than written by hand,
and the host labels the row Not implemented.

## 5. Host Contract

| Item | Contract |
|---|---|
| Selector names | Enum groups `prctl_option`, `ptrace_request`, `keyctl_cmd`, `sysfs_option`, `sockopt_level` use full-width masks so that an exact value matches one name |
| Dependent names | `selector_name(number, index, args) -> Option<String>` names one argument that may depend on another: the optname given the level and direction (slice 2A); the `PR_SET_MM`/`PR_SET_VMA`/`PR_SCHED_CORE` sub-op and the `PTRACE_O_*` flags for `SEIZE`/`SETOPTIONS` (slice 2B). Unknown values render as `Unknown …` plus the raw value |
| Layout labels | The UI shows the kernel's layout string and byte count. Structured decoding of these layouts is outside this slice |

## 6. Fixtures and Verification

| Artifact | Contract |
|---|---|
| Fixture files | `tests/monitor/fixtures/native-schema/{2a,2b,2g}.json`, format in Section 7. A slice's fixture is committed before that slice's kernel coding starts |
| Fixture review | Valid and invalid examples per family (unknown selector, short length, oversize length, NULL, faulting pointer), checked before kernel coding begins |
| Probe cases | In `native-probe.c`, run as UID 1000 in a disposable VM. ptrace targets only the probe's own forked child. Seccomp and `PR_SET_SECCOMP` run in a child that exits. keyctl uses the process keyring only. Sockets are an `AF_UNIX` pair and unconnected `AF_INET`/`AF_INET6` TCP sockets; there is no network I/O. `PR_SET_NAME`/`PR_SET_PDEATHSIG` restore their previous values |
| Verifier | New `--schema-fixtures DIR` compares each probe case's recorded fields with its fixture; a missing or extra field fails the case |
| ENOSYS verdict | New `EXPECTED_ENOSYS` verdict. It counts as covered only for rows with `"implemented": false`; elsewhere `ENOSYS` remains SKIP |
| Ledger | `setsockopt`, `getsockopt`, `ptrace`, `sysfs`, `prctl` and `keyctl` move to `native_capture`; the 17 rows move to `not_implemented_verified` only after a probe run shows `EXPECTED_ENOSYS` for each |
| Rejections | Privileged selectors that return `EPERM` as UID 1000 (for example `PR_SET_MM`) still have to show entry fields that match the fixture. They are reported as an expected rejection, not as a PASS of output capture |

## 7. Fixture Format

```json
{
  "contract": "native-schema-slices.md revision 1",
  "slice": "2a",
  "cases": [
    {
      "label": "sockopt.so_rcvbuf.set",
      "syscall": "setsockopt",
      "result": "zero",
      "fields": [
        {"phase": "entry", "arg": 3, "key": "arg3.optval",
         "layout": "linux-6.12.94/x86_64/int", "size": 4, "captured": 4,
         "declared": 4, "status": "COMPLETE", "data": "00000100"}
      ]
    }
  ]
}
```

| Member | Meaning |
|---|---|
| `label` | Stable case name. The probe prints it as `"label"` in its `ANT_CASE` line; sequential `case_id` values are not stable across probe edits |
| `result` | `zero`, `nonnegative`, `positive`, or `errno:<NAME>`; alternatives separated by `|` when the pinned kernel profiles legitimately differ (ANT-T0022) |
| `fields` | The complete set of fields recorded for that invocation, in both phases. A missing or extra field fails the case |
| `phase` | `entry` or `exit` |
| `size`, `captured`, `declared` | Object size, bytes actually captured, and declared length; `"max"` stands for `U64_MAX`, and `"result"` for the case's return value (revision 3) |
| `process` | Optional note that the case runs in a named child of the probe (revision 3) |
| `status` | `ant_status` name without the `ANT_` prefix |
| `data` | Lowercase hex of the exact captured bytes; `"observed"` means they must equal the hex the probe printed under the same key in the `ANT_CASE` `"observed"` map (for kernel-dependent outputs); `null` means unchecked (for example a struct holding a pointer) |
| `address` | Optional: `"nonzero"`, or `"observed"` to compare with the probe-reported address |

## 8. Revision 2 Corrections (2026-10-07)

| Item | Revision 1 | Revision 2 |
|---|---|---|
| Over-limit lengths | Captured up to the limit | `ANT_INVALID_EXTENT` with no bytes, matching the recorder |
| `SO_BINDTODEVICE` | Listed as an `EPERM` example | Unprivileged binding of an unbound socket succeeds (`sock_bindtoindex_locked` only checks `CAP_NET_RAW` when rebinding); fixture expects success |
| `SO_GET_FILTER` | Separate rule | Shares number 26 with `SO_ATTACH_FILTER`; one rule, selected by direction |
| Netfilter range | Checked before option rules | Checked only when no option rule matched (`IPV6_TCLASS`/`IPV6_RECVTCLASS` are 67/66) |
| Host naming API | `selector_names(number, args) -> Vec<String>` | `selector_name(number, index, args) -> Option<String>`, one argument at a time for the trace view |
| 2G kernel | Raw arguments only | Unchanged kernel; existing `schema.argument_metadata` gap kept |

## 9. Revision 3: 2B Field Rules (2026-10-07)

The 2B fixtures (`tests/monitor/fixtures/native-schema/2b.json`) depend on these
rules, which make Section 3 exact.

| Rule | Contract |
|---|---|
| Truncated outputs | When the kernel returns the full length and copies only up to the caller's capacity (`PR_GET_AUXV`, `KEYCTL_DESCRIBE`/`READ`/`GET_SECURITY`/`CAPABILITIES`, `PTRACE_GET_SYSCALL_INFO`/`GET_RSEQ_CONFIGURATION`), the field's byte count is `min(capacity, result)` and its declared length is `result` |
| NULL output buffer | A NULL output pointer (a length query such as `KEYCTL_READ` with no buffer) records no field |
| Fixed outputs | `PR_GET_NAME` is `char[16]`; `PR_GET_PDEATHSIG`, `PR_GET_CHILD_SUBREAPER` and `PR_GET_TSC` are `int` under key `arg1.value` |
| Tracee addresses | `PEEKTEXT`/`PEEKDATA`/`POKETEXT`/`POKEDATA` record `arg2.tracee_address`, layout `unsigned_long`, 8 bytes, `ANT_ADDRESS_ONLY`, never copied |
| Regsets | Entry: `arg3.iovec` (layout `iovec`); `SETREGSET` adds the input `arg3.iovec.data`. Exit on success: `arg3.iov_len` (`u64`, rewritten by the kernel) and, for `GETREGSET`, `arg3.iovec.data` of that length. The `SETREGSET` input ceiling is the largest x86-64 regset, taken in-kernel from the native regset view |
| Other `ptrace` keys | `arg3.word`, `arg3.regs`, `arg3.fpregs`, `arg3.siginfo`, `arg3.sigmask`, `arg3.message`, `arg3.info`, `arg3.desc`, `arg2.args`, and `arg2.value` for `ARCH_PRCTL`; `PEEKSIGINFO` output layout `siginfo_t[]` |
| Async selector | `PR_SET_SYSCALL_USER_DISPATCH` records `arg4.selector`, layout `u8`, 1 byte, `ANT_ASYNC_UNOBSERVED`, never copied |
| `keyctl` keys | `arg1.name`, `arg2.payload`, `arg2.type`, `arg3.description`, `arg2.buffer`, `arg1.buffer`, `arg1.params`, `arg3.info`; `INSTANTIATE_IOV` uses the shared vector keys `arg2.iov` and `arg2.iov[i].data` |
| `sysfs` keys | `arg1.fsname` (input string, ceiling `PATH_MAX`); `arg2.fsname` (output string read to the NUL the kernel wrote, same ceiling) |

Correction found while writing the probe (2026-10-07): revision 3 first placed
the `PTRACE_ARCH_PRCTL` code in `addr` and the output in `data` (`arg3.value`).
The pinned `arch_ptrace()` passes them the other way round, so the output is
`arg2.value` and the fixture was updated to match.

## 10. Revision 4: Slice 2C (2026-10-07)

Approved by the user on 2026-10-07 together with `tests/monitor/fixtures/native-schema/2c.json`.
The user also chose a root-run step inside the disposable VM for the slice 2H `bpf` probe.
`bpf` is split out into its own slice (2H) and contract because of its size.

### 10.1 mount(dev_name, dir_name, type, flags, data)

| Argument | Capture (entry) |
|---|---|
| `dev_name` | `arg0.dev_name` string, ceiling `PATH_MAX` (`copy_mount_string`) |
| `dir_name` | `arg1.dir_name` string, ceiling `PATH_MAX` |
| `type` | `arg2.type` string, ceiling `PATH_MAX` |
| `flags` | scalar; the host decodes `MS_*` names |
| `data` | `arg4.data`, layout `mount_options`: the readable prefix of one page (`PAGE_SIZE`), as `copy_mount_options()` reads it. If the page has an unreadable part, `arg4.data.tail` records the remainder with `ANT_COPY_FAULT`; a page that is mapped but not resident records `ANT_NOT_RESIDENT` instead (revision 8, Section 15.1). NULL `data` records no field. The UI shows the bytes up to the first NUL as text when they are printable |

### 10.2 quotactl(cmd, special, id, addr) and quotactl_fd(fd, cmd, id, addr)

`cmd` is `QCMD(subcommand, type)`. `quotactl` records `arg1.special`, a
block-device path string with ceiling `PATH_MAX` (NULL is allowed only for
`Q_SYNC`). For both calls, `addr` has these roles:

| Subcommand | `addr` (key `arg3.*` in both calls) |
|---|---|
| `Q_QUOTAON` | `arg3.quota_file` path string, `PATH_MAX` (`quotactl` only; `quotactl_fd` rejects it) |
| `Q_GETFMT` | exit, `result == 0`: `arg3.format` `u32` |
| `Q_GETINFO` / `Q_SETINFO` | `arg3.info` `if_dqinfo` out / in |
| `Q_GETQUOTA` / `Q_GETNEXTQUOTA` / `Q_SETQUOTA` | `arg3.dqblk` `if_dqblk` out / `if_nextdqblk` out / `if_dqblk` in |
| `Q_XQUOTAON` / `Q_XQUOTAOFF` / `Q_XQUOTARM` | `arg3.flags` `u32` in |
| `Q_XGETQSTAT` | exit: `arg3.stat` `fs_quota_stat` |
| `Q_XGETQSTATV` | entry: `arg3.qs_version` 1 byte (the kernel reads only this); exit: `arg3.stat` `fs_quota_statv` |
| `Q_XSETQLIM` / `Q_XGETQUOTA` / `Q_XGETNEXTQUOTA` | `arg3.dquot` `fs_disk_quota` in / out / out |
| `Q_QUOTAOFF`, `Q_SYNC`, `Q_XQUOTASYNC` | scalar |
| Other | `quotactl.unknown_selector` gap |

### 10.3 kexec_load(entry, nr_segments, segments, flags)

| Capture (entry) | Rule |
|---|---|
| `arg2.segments` | `kexec_segment[]`, `nr_segments * 32` bytes; `ANT_INVALID_EXTENT` without copy above `KEXEC_SEGMENT_MAX` (16) |
| `arg2.segments[i].buf` | Each segment's buffer, `bufsz` bytes, bounded like `write()` by `MAX_RW_COUNT`. A large image may exceed the transport rate; that loss is reported, as for `write()`. A zero `bufsz` records no field |

The host decodes `flags` (`KEXEC_ON_CRASH`, `KEXEC_PRESERVE_CONTEXT`, `KEXEC_UPDATE_ELFCOREHDR`, `KEXEC_CRASH_HOTPLUG_SUPPORT`, and the architecture field).

### 10.4 rseq(rseq, rseq_len, flags, sig)

| Phase | Capture |
|---|---|
| Entry | `arg0.rseq`, layout `rseq`, `min(rseq_len, sizeof(struct rseq))` bytes (32 on 6.12), with `rseq_len` as the declared length. The kernel reads only the known fields |
| Exit, registration accepted (`result == 0`, no `RSEQ_FLAG_UNREGISTER`) | `arg0.rseq.updates`: 32 bytes, `ANT_ASYNC_UNOBSERVED`. The kernel writes the CPU, node and mm ids later, on every return to user space |
| Exit, unregistration accepted | `arg0.rseq`: the 32 bytes the kernel just reset |

The host decodes `flags` (`RSEQ_FLAG_UNREGISTER`); this group already exists.

### 10.5 Probe environment for 2C

- `mount` success runs in a forked child that calls
  `unshare(CLONE_NEWUSER | CLONE_NEWNS)` and mounts a 1 MiB tmpfs on the probe's
  private `mnt` directory. This needs `CONFIG_USER_NS` (on since ANT-T0022). The
  mount disappears with the child's namespace.
- `kexec_load` and the privileged `quotactl` paths run as UID 1000 and are
  rejected (`EPERM`, `ENOENT` or `ESRCH`; the guest root is ext4 without quotas,
  so `quotactl_fd` sees quota operations but no enabled quota). Their entry fields are still checked;
  quota output layouts have no runtime coverage, because no quota-enabled
  filesystem exists in the probe VM.
- `rseq` unregistration and re-registration run on a dedicated pthread, which
  registers again immediately; the main thread only sees rejected calls.

## 11. Revision 5: Slice 2H, bpf (2026-10-07)

Approved by the user on 2026-10-07, together with Section 12 and `tests/monitor/fixtures/native-schema/2h.json`
(UID 1000 cases) and `tests/monitor/fixtures/native-schema-root/2h-root.json`
(root-run cases). Both kernel profiles enable `CONFIG_BPF_SYSCALL`, and both keep
unprivileged BPF off, as stock Debian does.

### 11.1 Common rules

| Rule | Contract |
|---|---|
| Attribute block | Entry: `arg1.attr`, layout `bpf_attr`, `min(size, sizeof(union bpf_attr))` bytes, declared `size`. A larger `size` (up to `PAGE_SIZE`, which the kernel requires to be zero-filled) adds `arg1.attr.extension`. Above `PAGE_SIZE`: `ANT_INVALID_EXTENT`, no copy. Nested fields come from the kernel's own snapshot of that block, never from a second read |
| Map-derived sizes | Key, value and batch sizes come from the map object found by `map_fd` (`bpf_map_get()`), using the kernel's rules: per-CPU maps use `round_up(value_size, 8) * num_possible_cpus()`; fd-based maps use 4 bytes; others use `value_size`. If the fd is not a map: `ANT_CONTEXT_MISSING` with no copy |
| Rewritten counts | Lengths the kernel writes back (`batch.count`, `info.info_len`, `test.data_size_out`, `test.ctx_size_out`, `query.prog_cnt`, `task_fd_query.buf_len`) are re-read from the attribute block at exit and recorded as `arg1.attr.<name>` (`u32`) before the output they bound |
| Outputs | Exit, on success, unless stated otherwise |
| Unknown command | Raw `arg1.attr` with an empty layout plus a `bpf.unknown_selector` gap |

### 11.2 Commands

| Command | Nested capture |
|---|---|
| `MAP_CREATE` | none (the map name is inline) |
| `MAP_LOOKUP_ELEM`, `MAP_LOOKUP_AND_DELETE_ELEM` | entry `arg1.attr.key` (key size); exit `arg1.attr.value` (value size) |
| `MAP_UPDATE_ELEM` | entry `arg1.attr.key`, `arg1.attr.value` |
| `MAP_DELETE_ELEM` | entry `arg1.attr.key` |
| `MAP_GET_NEXT_KEY` | entry `arg1.attr.key` (none if NULL: first key); exit `arg1.attr.next_key` |
| `MAP_*_BATCH` | entry `arg1.attr.in_batch` (4 bytes for hash maps, key size otherwise; none if NULL); `UPDATE_BATCH`/`DELETE_BATCH` entry `keys` (and `values` for update) of `count` entries; `LOOKUP_*_BATCH` exit, on success or `ENOENT` (end of map), the rewritten `count`, `out_batch`, `keys` and `values` of that many entries |
| `PROG_LOAD` | entry `arg1.attr.insns` (`insn_cnt * 8`, at most 1,000,000 instructions); `arg1.attr.license` string ≤ 128; `func_info`, `line_info` (`cnt * rec_size`, record size 8–252), `core_relos` (`cnt * rec_size`); `fd_array` address only with a `bpf.fd_array_unbounded` gap (6.12 has no count). Exit, **whatever the result**, when `log_size > 0`: `arg1.attr.log_buf` as the NUL-terminated string the verifier wrote, ceiling `log_size` |
| `BTF_LOAD` | entry `arg1.attr.btf` (`btf_size`, at most 16 MiB); exit, whatever the result, `arg1.attr.btf_log_buf` like the program log |
| `OBJ_PIN`, `OBJ_GET` | entry `arg1.attr.pathname` string, `PATH_MAX` |
| `PROG_TEST_RUN` | entry `data_in` (`data_size_in`), `ctx_in` (`ctx_size_in`); exit rewritten `data_size_out`/`ctx_size_out`, then `data_out`/`ctx_out` of those sizes |
| `OBJ_GET_INFO_BY_FD` | exit rewritten `info_len`, then `arg1.attr.info` of `min(info_len, input info_len)`; pointers inside the info structure are not followed (`bpf.info_nested` gap) |
| `PROG_QUERY` | exit rewritten `prog_cnt`, then `prog_ids` (and `prog_attach_flags`, `link_ids`, `link_attach_flags` when set) of that many `u32` |
| `RAW_TRACEPOINT_OPEN` | entry `arg1.attr.name` string ≤ 128 |
| `TASK_FD_QUERY` | exit rewritten `buf_len`, then `arg1.attr.buf` string |
| `LINK_CREATE` | `kprobe_multi`: `syms` (array of `cnt` string pointers; each string ≤ `KSYM_NAME_LEN`), `addrs`, `cookies` (`cnt * 8`); `uprobe_multi`: `path` string, `offsets`, `ref_ctr_offsets`, `cookies`; `iter_info` (`iter_info_len`); other targets scalar |
| `PROG_ATTACH`, `PROG_DETACH`, `MAP_FREEZE`, `*_GET_NEXT_ID`, `*_GET_FD_BY_ID`, `LINK_UPDATE`, `LINK_DETACH`, `ENABLE_STATS`, `ITER_CREATE`, `PROG_BIND_MAP`, `TOKEN_CREATE` | none beyond `arg1.attr` |

### 11.3 Probe and harness

- The UID 1000 probe adds `bpf` cases that are rejected (`EPERM`, `EINVAL`); their
  attribute blocks and program inputs are still checked.
- The harness then launches the same probe as **root** with `--root-bpf` in the
  same disposable VM. This run creates an array map and a per-CPU array map, loads
  and test-runs a two-instruction socket filter, loads a minimal BTF blob, and
  closes everything before printing `NATIVE PASS`; nothing outlives the process.
  It is verified separately against `native-schema-root/`.
- The fixture format gains `"observed"` for `size`/`captured`/`declared`: the value
  must equal the byte length of the observed data for that field (used for verifier
  logs, whose exact text the kernel decides).
- The fixture format also gains `"when_observed": true` on a field: the field is
  required exactly when the probe reported observed data under its key, and must
  be absent otherwise (used where the guest CPU decides whether state exists).

## 12. Revision 5: Slice 2E, implicit frames (2026-10-07)

Approved together with Section 11. These syscalls take no pointer argument;
their input is a frame on the user stack, located from the caller's saved stack
pointer (`current_pt_regs()->sp` at entry). Fields use argument index 255 and
`context.*` keys. The existing `schema.arch_context` gap is replaced.

### 12.1 rt_sigreturn

| Field (entry) | Rule |
|---|---|
| `context.rt_sigframe` | `struct rt_sigframe` (440 bytes on x86-64: return address, `ucontext`, `siginfo`) at `sp - 8`, where the kernel reads it. The kernel reads the signal mask, flags, alternate stack and `sigcontext` from it |
| `context.fpstate` | If `uc_mcontext.fpstate` is non-NULL: the 512-byte `fxregs_state` it points to |
| `context.fpstate.xstate` | Only if that block carries `FP_XSTATE_MAGIC1`, `512 + 64 <= xstate_size <= min(extended_size, the task's fpstate->user_size)` and `FP_XSTATE_MAGIC2` follows the state (the kernel's own checks): the `xstate_size - 512` bytes that follow. If any check fails the kernel ignores the extension and restores the legacy state only, so no field is recorded (correction while implementing: the draft recorded `ANT_INVALID_EXTENT` for out-of-range sizes, but the kernel does not reject them; on a CPU without XSAVE the frame carries `FP_XSTATE_MAGIC1` with `xstate_size` 512) |

The exit value is the restored `rax` of the interrupted code, not a return value.

### 12.2 uretprobe

| Field (entry) | Rule |
|---|---|
| `context.uretprobe_regs` | The three words the kernel trampoline saved at `sp` (`r11`, `rcx`, `rax`), 24 bytes, as the kernel reads them |

The kernel accepts the call only from its uretprobe trampoline and otherwise kills
the caller with `SIGILL`; the exit value is the probed function's return value.

### 12.3 Probe

- UID 1000 run: a `SIGUSR2` handler installed with `rt_sigaction` copies its
  signal frame and FPU state just before returning; the case covers the `raise()`
  and the trampoline's `rt_sigreturn`. The fixture compares the captured frame
  with those copies.
- Root run: a `perf_event_open` uprobe return probe on a non-inlined probe
  function returning 42 (the uprobe PMU type and `retprobe` bit come from
  `/sys/bus/event_source/devices/uprobe`); calling the function makes the kernel
  trampoline issue `uretprobe`. The event is closed afterwards.

## 13. Revision 6: Slice 2D, nested and stateful variants (2026-10-07)

Approved by the user on 2026-10-07 together with `tests/monitor/fixtures/native-schema/2d.json`.

### 13.1 clone and clone3 writes

A forked child starts with no syscall context, so nothing is recorded in the
child for its own first return. The parent's exit event therefore records every
write that `clone` makes, with the context where it happens:

| Flag | `clone` key | `clone3` key | Capture at the parent's exit (`result > 0`) |
|---|---|---|---|
| `CLONE_PARENT_SETTID` | `arg2.parent_tid` | `arg0.clone_args.parent_tid` | `pid_t` the kernel wrote in the parent |
| `CLONE_PIDFD` | `arg2.pidfd` (the `parent_tid` slot) | `arg0.clone_args.pidfd` | `int` written in the parent |
| `CLONE_CHILD_SETTID` | `arg3.child_tid` | `arg0.clone_args.child_tid` | 4 bytes, `ANT_ASYNC_UNOBSERVED`: the child writes its own TID (this result, as seen in the child's PID namespace) before returning to user space |
| `CLONE_CHILD_CLEARTID` | `arg3.clear_child_tid` | `arg0.clone_args.clear_child_tid` | 4 bytes, `ANT_ASYNC_UNOBSERVED`: zeroed and futex-woken when the child exits |

This replaces the `NO_DECODER` (`clone`) and `CONTEXT_MISSING` (`clone3`) entry
markers. `newsp` and `tls` are values the kernel never dereferences.

### 13.2 semctl GETALL and SETALL

The array length is the set's `sem_nsems`, which only the kernel knows. Two
hooks in `ipc/sem.c` `semctl_main()` hand the recorder the kernel's own copy of
the array: for `SETALL` right after it is copied in, for `GETALL` right before it
is copied out. At exit the recorder emits it as `arg3.array`, layout
`unsigned_short[]`, `nsems * 2` bytes, marked kernel-imported. That is the exact
operand, not a second read of user memory. If the kernel never reached the
copy (an earlier error), no field is recorded; if the stash allocation fails,
`ANT_RESOURCE_EXHAUSTED`. This replaces the `ANT_UNKNOWN_EXTENT` field.

The hook API is `ant_monitor_operand(key, layout, data, size)` (one pending
operand per syscall, freed at exit or task exit); it is a no-op when
`CONFIG_ANTINOMIE` is off.

### 13.3 process_vm_readv and process_vm_writev

Per the user's earlier decision, the other process's memory is never read.
Each remote segment becomes `arg3.remote_iov[i].data`, `iov_len` bytes,
`ANT_ADDRESS_ONLY` (previously `ANT_CONTEXT_MISSING`). Local buffers keep the
shared vector rules: `writev` input at entry, `readv` output at exit bounded by
the result.

### 13.4 Deferred kernel-managed pointers

| Syscall | Capture |
|---|---|
| `set_tid_address(tidptr)` | `arg0.clear_child_tid`, 4 bytes, `ANT_ASYNC_UNOBSERVED`: zeroed and futex-woken when the thread exits |
| `set_robust_list(head, len)` | `arg0.head`, `robust_list_head`, 24 bytes, the registered head as the program wrote it (the kernel stores only the pointer); `arg0.head.traversal`, `ANT_ASYNC_UNOBSERVED`: the kernel walks the list when the thread exits. `len != 24` keeps `ANT_INVALID_EXTENT` with no copy |

These replace the generic `arg0.deferred_exit_address` key.

### 13.5 Outputs on failure

Audit of the pinned kernel: where a syscall can write user output and still
fail (`pipe`/`pipe2`, `socketpair`, `accept`/`accept4`, `getsockopt` and similar),
the failure is that write itself faulting, so the user buffer holds a partial,
unusable copy. Rule: **outputs are captured only on success**, except the
documented interruption cases already in the contract (for example the remaining
time on `EINTR`). Nothing is recorded for a failed call's output buffers. This
closes the earlier "partial error outputs" item as a decision rather than code.

## 14. Revision 7: Slice 2F, asynchronous variants (2026-10-07)

Approved by the user on 2026-10-08 together with `tests/monitor/fixtures/native-schema-async/2f.json`.
Async requests are not syscall invocations, so their fixtures use a separate
format (14.7) matched by the request's `user_data`.

### 14.1 Same-address-space observation

Today a request's user buffers are read only when `current` is the submitting
task. io-wq workers and the SQPOLL thread are threads of the same process and
share its memory, but their reads are recorded as `ANT_ASYNC_UNOBSERVED`. The
rule becomes: a buffer is read when the current task uses the origin's address
space (`current->mm == origin mm`) and the context is not an interrupt. This
covers io_uring reads and writes punted to io-wq or run by SQPOLL. Interrupt
completions stay unobserved (14.2).

### 14.2 AIO reap-time observation

An `O_DIRECT` AIO read completes in interrupt context, where user memory cannot
be read. Such a request is kept in a bounded **reap table** (64 entries per boot)
holding its run, process, iocb address, `aio_data`, buffer and length. When that
process's `io_getevents`/`io_pgetevents` returns the request's event, its context
can read the buffer. The recorder then publishes one more async event,
**stage 7 "Reaped"**, carrying `async.payload.output` with the `res` bytes, and
removes the entry. Entries are dropped, and counted as async loss, when the table
is full or the process exits first. The bytes are what the buffer holds at reap
time, normally exactly what the device wrote. The host names stage 7 "Reaped".

### 14.3 Producer attribution

`io_uring_setup` records the ring creator's run and task cookies on the ring. A
submission from the SQPOLL thread, or from any task outside the creator's
thread group, is attributed to the creator's run and flagged
`ANT_ASYNC_PRODUCER_UNKNOWN`: the shared ring does not say which thread wrote the
SQE. A submission by the creator's own threads keeps its real task identity.

Which process wrote the entry (guest series 0055, revision 17). A process
writes a ring's entries and moves its tail only through a mapping of them.
When the page holding the submitted entry and the ring's first page (head and
tail) are each mapped by at most one user page table, the entry was written
by a thread of the submitting process: the request carries
`ANT_ASYNC_PRODUCER_PROCESS` (`async.flags` bit 3; which thread is not known)
and the run's observation stays complete. A ring with another mapping (kept
across a fork, mapped by a process the descriptor was passed to, a
`MAP_SHARED` buffer of a `NO_MMAP` ring, or mapped twice by one process)
gets `ANT_ASYNC_PRODUCER_UNKNOWN` (bit 1) and makes the run
OBSERVATION_INCOMPLETE, as do the SQPOLL thread's submissions and those from
outside the creator's process. A guest before 0055 flagged every io_uring
submission unknown; a host reads both.

### 14.4 Typed io_uring operands

| Opcode | Operand |
|---|---|
| `BIND` | `async.operand.sockaddr`, `addr_len` bytes, input |
| `FILES_UPDATE` | `async.operand.fds`, `len` × 4 bytes, input |
| `WAITID` | `async.operand.siginfo`, `siginfo_t`, output on success |
| `FUTEX_WAIT`, `FUTEX_WAKE` | `async.operand.futex`, 4 bytes, `ANT_ADDRESS_ONLY` (the kernel compares or wakes; its value is the operation's input) |
| `FUTEX_WAITV` | `async.operand.futexv`, `nr` × `futex_waitv`, input |
| `PROVIDE_BUFFERS` | `async.operand.buffers`, `len` × `nbufs` bytes, `ANT_ADDRESS_ONLY` (reads that select a buffer record their data through the existing iterator capture) |
| `URING_CMD` on a socket, `SOCKET_URING_OP_SETSOCKOPT` | `async.operand.optval`, raw, `optlen` bytes, ceiling 128 KiB (the slice 2A rule for unknown options) |
| `URING_CMD` on a socket, `SOCKET_URING_OP_GETSOCKOPT` | output `async.operand.optval` of the returned length on success |
| `URING_CMD` with any other command | `async.operand.uring_cmd` gap, `ANT_NO_DECODER` (driver-specific) |
| `NOP`, `FSYNC`, `POLL_ADD`, `POLL_REMOVE`, `SYNC_FILE_RANGE`, `TIMEOUT_REMOVE` without update, `ASYNC_CANCEL`, `FALLOCATE`, `CLOSE`, `FADVISE`, `MADVISE`, `SPLICE`, `TEE`, `SHUTDOWN`, `MSG_RING`, `SOCKET`, `FIXED_FD_INSTALL`, `FTRUNCATE`, `LISTEN`, `REMOVE_BUFFERS` | scalar; the SQE is already recorded as `async.submission` |

### 14.5 Cancellation

A canceled request ends with stage 5, as today. The `ASYNC_CANCEL` request's own
completion carries the number canceled. `io_cancel` on an AIO poll request
records the target's cancellation the same way. Fixtures check the full stage
sequence of both the target and the canceling request.

### 14.6 Staging exhaustion

With more than 256 requests in flight, or more than 1024 records waiting to be
published, new requests or records are refused. Each refusal increments the run's
async loss count and sets its incomplete flag (existing behaviour). It is now
verified by a stress run.

### 14.7 Async fixture format

```json
{"label": "2f.uring_read_iowq", "user_data": "0x2f00000000000001",
 "stages": [1, 2, 4], "flags_set": [], "flags_clear": ["PAYLOAD_GAP"],
 "fields": [{"stage": 4, "key": "async.payload.output", "layout": "",
             "size": 32, "status": "COMPLETE", "data": "…"}]}
```

`stages` is the exact set of stages seen for that `user_data`. Fields are checked
on the event of the given stage, with the same tokens as the syscall fixtures
(`"observed"`, `"max"`, `when_observed`). A `run` block checks the run's status
(`async_loss_min`, `incomplete`) for the stress run.

### 14.8 Harness

The headless harness gains a third run, `--async-stress` (UID 1000), after the
root run, so its deliberate async losses do not affect the main run. The verifier
gains `--async-fixtures DIR`.

### 14.9 Clarifications from the independent review (2026-10-08)

These follow the rules above; no fixture changes.

- **Reap matching (14.2).** The AIO ring is writable by the process. A reap entry
  is therefore matched on the ring slot and the result that `aio_complete()`
  wrote, not on event contents read back from the process. Entries are keyed by
  the AIO context, so `mremap` of the ring keeps them. They are dropped when the
  context is freed or the address space exits; an entry whose result is zero or
  negative is dropped without loss.
- **Attribution (14.3).** An attributed request records `async.parent_call_id`
  0: no call of the ring creator submitted it.
- **Ceilings (14.4).** A socket option above 128 KiB records `async.operand.optval`
  as `ANT_INVALID_EXTENT` with its declared size and no bytes, as in slice 2A. A
  `FILES_UPDATE` count above the kernel's fixed-file limit is recorded the same way.
- **semctl (13.2).** `GETALL` records its array only when the copy to the caller
  succeeds (13.5); an array above 1 MiB is `ANT_RESOURCE_EXHAUSTED`.

## 15. Revision 8: ANT-T0009 follow-up fixes (2026-10-08)

The user asked for the problems found during ANT-T0009 to be fixed on
2026-10-08 and chose, for 15.1, to label such fields rather than have the
recorder fault pages in. Fixtures: `fixtures/native-schema/residency.json` and
the case `2f.aio_direct_readv_reaped` in `fixtures/native-schema-async/2f.json`.

### 15.1 Non-resident pages

The recorder copies user memory without faulting. A page that is mapped but has
no page-table entry yet (for example a string in a freshly forked child's
`.rodata`, or an untouched file mapping) fails that copy, although the kernel
faults the page in for the syscall itself. When a copy fails, the recorder
checks the failed range under `mmap_read_trylock`:

| Range | Status |
|---|---|
| Wholly inside readable mappings of the caller | `ANT_NOT_RESIDENT` (12): no bytes, `captured` 0 |
| Not wholly mapped readable, or `mmap_lock` not immediately available, or not task context | `ANT_COPY_FAULT`, as before |

`ANT_NOT_RESIDENT` marks the invocation incomplete like `ANT_COPY_FAULT` and is
counted in the recorder's `copy faults` statistic. Fields read through an
iterator keep `ANT_COPY_FAULT`. The recorder never faults pages in, so a
non-resident value is not recorded even though the syscall used it.

From series 0053 (section 22) the recorder reads such an input again at the
call's exit, still without faulting, and an exec's pointer vector is classified
the same way (an entry pointer on a non-resident page is `ANT_NOT_RESIDENT`
instead of `ANT_COPY_FAULT`).

### 15.2 Async publication pacing

Queued async records are published by one worker. Before each record it waits,
up to 10 ms, until the telemetry ring of the CPU it runs on is at most half
full (`ant_send_room()`, a guest-only addition to the V7 transport API; the wire
format is unchanged). After the wait it publishes anyway and drops are counted
as before. The probe no longer pauses after async cases.

### 15.3 Vectored AIO reads at reap (14.2)

`IOCB_CMD_PREADV` reads are now deferred like `IOCB_CMD_PREAD`. A vectored read
with more than one segment keeps a copy of the iovec array the kernel imported
(at most 1,024 entries) in its reap entry, so later changes to the process's
own array cannot redirect the capture. Its stage 7 event carries the iterator
fields of a stage 4 read: `async.payload.direction`, `async.payload.requested_size`,
`async.payload.result_offset`, `async.payload.iov` (layout `iovec[]`, the kernel
copy) and `async.payload.output` with the `res` bytes in iovec order. A
one-segment `PREADV` is imported as a single buffer and is recorded like `PREAD`.

## 16. Revision 9: kernel revision and source identity (ANT-T0027, 2026-10-08)

From this revision the contract revision is part of the protocol, not only of
this document. `ANTC_REVISION` in the shared control header (`control.h`, the
kernel's `control_wire.h`) is the revision the kernel implements and the host
understands; it is raised with every guest-visible behaviour change recorded
here. The wire layout, record schema 1 and control version 1 are unchanged.

| Part | Rule |
|---|---|
| Source id | `CONFIG_ANTINOMIE_SOURCE_ID` = `"<revision>:<series sha256>"`, embedded with IKCONFIG. The series hash is the SHA-256 of `sha256sum` output over `src/antinomie/core/6.12/*.patch` in name order. `build-monitor-kernel.sh` sets it only when the author tree is clean and its tree equals baseline + series; `ANTINOMIE_DEV_BUILD=1` leaves it empty |
| `ANTC_INFO` (0x1021) | Header only. 160-byte reply: u32 revision, u32 zero, source id (80 bytes, NUL terminated and padded), kernel release (64 bytes, same), 8 zero bytes. Registered before every other opcode |
| Old kernels | Answer `ANTC_INFO` with `-EOPNOTSUPP`. The host then sends `ANTC_STATS`: success means a kernel before revision 9; `-EOPNOTSUPP` means control is not registered yet and the probe repeats after 1 s |
| Bundles and catalog | `antinomie_revision` and `antinomie_source`, both or neither, written by the image builders from the kernel's embedded configuration; not part of the base identity (the configuration hash already is). Builders refuse a kernel without a source id unless `--allow-unversioned` |
| Host | Refuses to import, download, install a build of or start a base whose revision is newer than its own. Labels bases current, outdated, needs a newer app, or no revision. Reports a running kernel whose revision or series differs from its base's record, or that is newer than the host. The boot capture manifest records the kernel's answer as `guest_kernel` |

## 17. Revision 16: live process cores (ANT-T0057, 0.6.0)

Transport ABI9 and revision-15 Core Dump on Exit remain compatible. A live core
uses exact leader task cookie/start_boot_ns/TGID identity within the current boot.
Admission is asynchronous; cooperative task-work callbacks briefly park the
chosen thread group and release their own parks after native ELF serialization.
No fatal core rendezvous, SIGSTOP/SIGCONT or guest helper is used.

| Command / flag | Contract |
|---|---|
| CORE_CAPTURE 0x1063 | 56-octet request, 24-octet admission reply; identity, output/deadline limits, resident policy and a nonzero 128-bit host nonce |
| CORE_LOOKUP 0x1064 | 48-octet request, existing 80-octet STATUS reply; read-only nonce/identity reconciliation; acquisition is never replayed after an unknown admission |
| CORE_CANCEL 0x1065 | 16-octet request, empty reply; retain the record while cancellation releases owned parks |
| MANUAL0x10 / RESIDENT_ONLY0x40 | Live group capture, resident-only page references; root-only flag is unset and manual signal/wait_status are zero |
| PAUSE_RELEASED0x20 | Terminal status proves all capture-owned parks have ended; it does not guarantee scheduling, continued life, or undo an external stop |
| Native ELF data | Explicit frozen-thread input supplies regsets; original VMAs supply NT_FILE. Separate PT_LOAD extents use p_filesz=0 for unavailable/filtered/unscanned memory |
| Limits | 256 threads, 4096 original VMAs/extents, 65536 page probes, at most 64 MiB output and a 5000 ms cooperative deadline; four handles/128 MiB payload reservations plus at most 8 MiB manual auxiliary storage |
| Snapshot boundary | Save/restore rejects queued or in-flight manual guest acquisition. Resumed immutable buffers may checkpoint/adopt into fresh recording directories |
| Reattachment | Cancels in-flight manual work and releases owned parks before fence acknowledgement; completed immutable buffers remain available for read-only adoption |

All request fields retain explicit little-endian framing and zero reserved flags;
their exact offsets are documented in the mirrored control.h. Cancellation polls
terminal STATUS plus PAUSE_RELEASED before RELEASE. Dead/no-mm leaders, tracing,
external stops/freezing, unsupported ABI, shared-mm groups and identity/thread
races are explicitly rejected. Late callbacks cannot park after cancellation;
their references retain bounded metadata until they drain, temporarily preventing
a new manual admission. Shared-file mappings, DMA and external kernel writers
remain outside this process-group freeze, so it is not an atomic VM snapshot.


## 18. Revision 17: credential and file-hash records (0.7.0)

Revision 17 also records what host-side conversion cannot reconstruct: who a
task ran as, and what an executed or deleted file contained. Both are ordinary
phase-3 lifecycle events (the kind that already carries `lifecycle.exec_commit`)
with one fixed-structure field, so the ANTT envelope, ABI 9 and the field
framing are unchanged. No new record kind exists, so no transport version
moves: a host that does not know the keys sees an unknown lifecycle field, and a
recording from before them simply has none. Layouts are versioned by name
(`antinomie.creds/2`, `antinomie.hash/1`) and given byte for byte in the
mirrored `control.h`.

| Record | Key and layout | When | Belongs to |
|---|---|---|---|
| Credentials | `lifecycle.creds`, `antinomie.creds/2`, 96 bytes | A traced task's first traced call (reason START); then each time `uid`, `euid`, `suid`, `fsuid`, the gid equivalents, any of the five capability sets (effective, permitted, inheritable, bounding, ambient) or the `securebits` change in `commit_creds()`; and when the audit login uid is set | The call that made the change; START belongs to the task's first call |
| File hash | `lifecycle.file_hash`, `antinomie.hash/1`, 80 bytes | Successful exec commit (the image the kernel will run); `unlink`/`unlinkat` that succeeded (the file's content as it was) | The call that triggered it, published later by a worker |

Credentials carry the ids in the initial user namespace, the audit login uid and
session id (`0xffffffff` unset, and `flags` bit 0 says whether the kernel tracks
them at all), all five capability sets and the securebits. The first 72 bytes
are the earlier `antinomie.creds/1` layout (three capability sets); a `/2`
record adds the bounding set at 72, the ambient set at 80 and the securebits at
88, and a host reads either. The ambient and bounding sets are what a
privilege-persisting sample changes with `prctl(PR_CAP_AMBIENT)`,
`PR_CAPBSET_DROP` and `PR_SET_SECUREBITS`, so those changes are recorded too.
The change reason is derived from the syscall in progress: setuid/setreuid,
setgid/setregid, setresuid/setresgid, setfsuid/setfsgid, capset, `prctl`
(reason PRCTL), an exec that changed an id (setuid/setgid image), an exec that
changed only capabilities (file capabilities, root exec), the login uid, or
other (for example user namespaces). A change with no id, capability set or
securebits difference writes nothing.

Hashing is SHA-256 only. The SigmaHQ Linux pack has no rule that reads a hash
field, and Sysmon for Linux rules that do read `Hashes` use SHA256, so MD5 would
cost reads without a consumer. Budget and failure rules:

| Rule | Value |
|---|---|
| Largest file read | 16 MiB (`ANTC_HASH_FILE_MAX`); a larger file is not opened and the record says TOO_LARGE with the size |
| Queue | 16 jobs and 64 MiB of queued file bytes; a full queue or byte budget drops the request and records QUEUE_FULL or BUDGET |
| Filesystems | ext4, tmpfs, ramfs; any other is recorded UNSUPPORTED_FS without being opened (a remote or user-space filesystem could block) |
| Other outcomes | NOT_REGULAR, NO_MEMORY, READ_ERROR with the errno, and a `CHANGED` flag when the file's state differs from the call's (see below) |
| Loss | A record that could not be sent is counted; every later record carries the cumulative count |
| Path | The traced task only allocates a 450-byte job and takes path references; a worker on the system unbound workqueue (no workqueue of its own) reopens the file read-only through `kernel_file_open` with no fsnotify event, no access-time update and no file-table accounting, one 64 KiB chunk at a time |
| Repeats | A 32-entry cache keyed by device, inode, generation, size, mtime, ctime and the inode change counter (`i_version`) lets an exec storm of one program read it once; the record is flagged CACHED. An entry lives at most 30 s on the monotonic clock, and a filesystem without a change counter (ramfs) is never cached, because its coarse timestamps cannot tell a rewrite within one tick apart. The wall clock plays no part |
| Worker | If the worker cannot allocate the context it publishes with, it skips the read and counts the loss instead of hashing a file whose record would be thrown away; the allocation is retried for the next job |

**What a digest describes.** The file is read by a worker some time after the
call returned, so the digest is the bytes at hashing time, never at the call.
At the call the tracer records the file's state: device, inode and generation,
size, modification and change time, and the inode change counter (armed by
reading it, so that a later write moves it even when it leaves the coarse
timestamps and the size alone). After the read the worker takes the state again
and sets `CHANGED` if anything differs, including a change that restored the
size and mtime. The residual window is inherent to deferred hashing: on a
filesystem without a change counter (ramfs) a rewrite within one timestamp tick
that keeps the size is not seen, and a write followed by one that restores size
and mtime and lands between the last check and the worker's read cannot be told
from no write. Changes that only touch metadata (chmod, rename, a new link) move
the change time and report `CHANGED` too although the bytes are intact; the
digest is still delivered. The one exception is the unlink of the file by a
traced task, typical of a sample that executes itself and then deletes its
image: a queued or running job whose file matched its state just before the
unlink takes the post-unlink state as its expectation, so the delete does not
read as a write while an earlier modification still does. For a delete record
the state is taken again after the unlink succeeded, for the same reason.

An exec whose image is a script's interpreter sets flag INTERPRETER: the hash
is of the interpreter that ran, which is not the file the call named. The first
exec of a launched root (the usermodehelper exec before any traced call) has no
call to belong to; a guest that offers it hashes it under the launch's identity
when the host asks (section 21). Nothing here starts a process, opens a
descriptor in the guest or registers a BPF program; the pinned dentry and mount
live a few milliseconds longer than they otherwise would, which is the only
guest-observable effect (a deleted file's space is released when its job ends).


## 19. Revision 17: sparse process cores (0.7.0)

A process core is a sparse file: Linux skips the pages that are not resident and
seeks over them, so the file offset of a segment can be far beyond the bytes
that were written. The retained-core buffer of revisions 15 and 16 was a flat
array indexed by file offset and `max_size` long, which bounded the file offset
instead of the data: a process with a large reserved but untouched mapping lost
everything after the first such hole and its core was cut at the data before it
(364,544 bytes in the reported case), although a few megabytes were resident.

The guest now stores only the bytes that were written, in extents, and
`max_size` (at most 64 MiB, unchanged) bounds those bytes. The file's logical
extent has its own bound of 16 GiB (`ANTC_CORE_LOGICAL_MAX`). Gaps of at most 64
bytes (ELF note padding) are stored as zeros; larger gaps are holes, at most
32768 extents per core. The writer is sequential, so a write before the current
end is refused. STATUS `size` and `expected_size` are the logical extent.

CORE_READ replies keep the SPECIMEN_READ layout. The u32 at reply offset 20
(always zero before) is a flags word: bit 0 `HOLE` means the `count` bytes at
the offset were never stored, read as zeros and are not sent (the reply is 24
bytes). `count` then names the whole hole up to the next stored byte, at most
1 GiB, and is not bounded by the requested capacity. A data reply never crosses
into a hole. The host writes a hole as a sparse range of the saved file
(`allocated_size` in `core.json` is the bytes actually written) and includes it
in the digest; a hole uses no recording quota. The same rules apply to live
(manual) cores, which share the sink. A host that reads the flags word as zero
sees the data layout unchanged, so only revision-17 bases send a hole.

Stop's SIGKILL escalation and the `KILL_ESCALATED` run-status flag are specified
in `run-status.md`.

## 20. Revision 17: file identity and exec image records (0.7.0)

Two more lifecycle records, specified in `control.h` and optional like the hash
record: a guest from before them publishes none, a host that does not know them
shows an unknown lifecycle field, and Triage falls back to names.

* `lifecycle.file_id` (`antinomie.fileid/1`, 32 bytes) carries the device,
  inode, inode generation, link count and mode of the file a call acted on, in
  the traced call itself: an `open`/`openat`/`openat2`/`creat` that returned a
  descriptor (kind OPEN), a `rename*` (RENAME: the inode moved), a `link*`
  (LINK) and an `unlink*` (UNLINK, with the links that remain; since series
  0054 also `rmdir` and `unlinkat(AT_REMOVEDIR)`, a directory with no link
  left). Only calls that
  succeeded publish one. An io_uring request carries the same bytes as the
  operand `async.operand.file_id`: OPEN from `IORING_OP_OPENAT`/`OPENAT2` (the
  file the request opened, direct descriptors included), RENAME/LINK/UNLINK
  from `RENAMEAT`/`LINKAT`/`UNLINKAT` (published by the operation itself on the
  worker when it succeeded, with the link count it left; before series 0057
  the name was resolved a moment before the operation, which two requests on
  one file run side by side could both see with all its links),
  and ISSUE for a request that acts on an open regular file
  (`READ*`, `WRITE*`, `FSYNC`, `FTRUNCATE`, `FALLOCATE`, `SYNC_FILE_RANGE`,
  `FADVISE`, and since series 0054 `FSETXATTR`, `FGETXATTR` and the file end
  of a `SPLICE`), once per request. ISSUE is what lets Triage tie a request on a
  registered-table descriptor, or on a descriptor the capture never saw opened,
  to a file. An AIO request on a regular file carries ISSUE too.
* `lifecycle.exec_image` (`antinomie.execimg/1`) is published once per exec at
  the commit point: the image that was loaded (its resolved path and its
  identity) and, for a script, the interpreter exactly as the `#!` line names it
  (`bprm->interp`). The hash record only said that the image was an interpreter.

Both are cut at 511 bytes per string and say so; a name that did not fit is not
shown. The identity is the host's key for one file across names: dev, ino and
generation together, so a name that is reused by a new file is told from the file
that held it.

## 21. Revision 17: written files and the launched image (0.7.0)

Two more hash records, both asked for by the host and so negotiated: the new
optional command `TRACER_CAPS` (0x10a0, header only, 32-byte reply) lists the
optional EXEC flags the guest accepts (`exec_flags`) and its hashing budget. An
older guest answers -EOPNOTSUPP and the host then sends neither flag, which
that guest would reject with -EINVAL; a host that does not know the command
sends neither and the guest records nothing new. The contract revision stays 17.

| EXEC flag | What the guest adds |
|---|---|
| `HASH_ROOT` (8) | The launched program's own image is hashed at its exec commit: an EXEC record of the root task with call id 0 and syscall number `U64_MAX`, the identity of its `lifecycle.launch` event, since the kernel starts the program without a traced execve |
| `HASH_WRITES` (16) | Each regular file a task of the run had open for writing is hashed when the file's last writer lets it go: a WRITE record |

**When a written file is hashed.** `__fput()` puts the file's write access and
then asks the tracer; the file is hashed when the inode's writer count is then
zero, so two descriptors open on one file give one record, after the second
close. That moment is the content the run left behind, as an inotify
`CLOSE_WRITE` reader sees it; a file opened for writing and not written is
hashed all the same. The last close happens when the last reference goes: in
task work after `close()`, at exit (`exit_task_work()`, after the task left the
run's accounting, so the run is found by the task's root cookie), or after the
call that dropped it (`dup2`, `munmap` of a shared mapping). A memfd, which has
no write access to count, is hashed when its last reference goes; an attached
System V shared memory segment (no write methods) is not. Pseudo filesystems
(proc, sysfs, cgroup and cgroup2, debugfs, tracefs, securityfs, bpf, pstore,
efivarfs, selinuxfs, smackfs, binfmt_misc) and files that are not regular publish
nothing; a regular file on another filesystem gets an UNSUPPORTED_FS record.
Writers that are not tasks of the run are not followed: another process, an
io_uring worker (no traced context), the delayed fput worker of a kernel thread.

**The record.** Layout `antinomie.hash/2`, 112 bytes: the `antinomie.hash/1`
record with kind WRITE (3), then the file at the close: device (`new_encode_dev`)
at 80, inode at 88, generation at 96, mode at 100, link count at 104 (0 when every
name was removed before the close), zero at 108. The call it belongs to is the one
the closing task made last (the `close`, the `exit_group`, or the call a signal
ended), which need not name the file: the identity is how the host finds it, the
same key as `lifecycle.file_id`. A host that knows only `/1` drops the record
(its kind is unknown to it). Budget, refusals, the digest cache and the
`CHANGED` comparison are those of section 18; the comparison is with the file as
the last close left it. A refusal decided at the close (too large, queue full,
budget, an unsupported filesystem) is not in a traced call, so the worker
publishes it too, from a bounded list of 64; a refusal that does not fit is
counted as lost.

**Guest-observable effects.** None new in kind: the job holds the file's path
until it is hashed, so the blocks of a file deleted right after its last close
are released a few milliseconds later, and the worker's read uses CPU the
sample can measure, bounded by the budget. No thread, workqueue or file
descriptor appears in the guest.

## 22. Revision 17: inputs read again at exit (0.7.0)

The user approved this change on 2026-10-22. It closes the largest capture gap
of 15.1: a page the program has mapped but not touched (a forked child's
literals, static glibc's start-up `readlink("/proc/self/exe")`, an untouched
file mapping) is recorded `ANT_NOT_RESIDENT` at entry, although the call itself
faults it in. The recorder still never faults: it reads the input again when
the call returns, when the page is usually resident, and says so.

| Rule | Contract |
|---|---|
| Which fields | An input field of the call's own Entry (phase 1) whose status is `ANT_NOT_RESIDENT`, read from the caller's memory (no snapshot, no iterator, not async, not kernel-imported). At most 8 per call, keys under 96 bytes; others stay `ANT_NOT_RESIDENT`. The task context keeps them in place: nothing is allocated |
| Exec vectors | The entry walk of `execve`/`execveat` `argv`/`envp` stops at the first pointer or string on a non-resident page, as before, and keeps the point to resume from (index, and the pointer if it was read) |
| When | At the end of the Exit, after the call's own exit fields. An Exit field with the same argument and key (an in/out buffer) is the call's output and drops the second read; the same key on another argument (`rt_sigprocmask`'s old mask) does not |
| How | Still without faulting. A string is measured again with its ceiling; a buffer is published only if every page reads without a fault at that moment. A field that still cannot be read is not published: the Entry's `ANT_NOT_RESIDENT` stands |
| Record | A normal field of the Exit event with the Entry's key, layout, encoding and argument, direction 1 (input), source 2 (exit), status `ANT_COMPLETE`, and bit 3 (`0x8`, RECAPTURED) in the FIELD_BEGIN flags word (offset 36). A failed exec resumes its vectors: the remaining pointers and strings, each marked |
| Successful exec | The caller's memory is gone (the address space differs from the Entry's), so nothing is read from it. The path is the exec's own copy (`bprm->filename`, the `struct filename` from `getname`; for `execveat` relative to a descriptor the caller's part after `/dev/fd/N/`), source 3 (kernel-imported), address the caller's pointer. The `argv`/`envp` strings from the resume point on are read from the new image's stack, `[arg_start, arg_end)` and `[env_start, env_end)`, which the kernel just wrote and no user code has run on; their address is that of the copy. These carry bit 4 (`0x10`, KERNEL_COPY) too. Pointer values after the resume point are not recorded. An interpreter exec (script, binfmt_misc: `bprm->interp != bprm->filename`) rewrote `argv`, so only `envp` is recovered |
| Exec that failed after the point of no return | The address space was replaced but nothing was committed: nothing is read, the Entry's status stands |
| Statistics | Unchanged: the entry's `ANT_NOT_RESIDENT` still counts as a copy fault |

**What the mark means.** The Entry event was already sent with the field
`ANT_NOT_RESIDENT` and the incomplete header flag. A recaptured field holds
what was in memory after the call, not what the call was given: another thread
can change the buffer while the call runs. It is weaker than an entry capture
and stays distinguishable. A kernel copy is what the kernel used (the path it
opened, the strings it gave the new program), read after the call.

**Host.** Pairing moves a complete recaptured Exit field into the Entry, in
place of the `ANT_NOT_RESIDENT` field with the same argument and key (an exec
string the Entry never reached is added). The field keeps the Entry's object
id and its "capture incomplete" issue is removed, so a call whose only gaps
were recaptured is complete; `FieldSummary::recapture` (`AtExit`,
`KernelCopy`) carries the mark into the trace, Triage, filters, exports and
JSON. A
recaptured field that is not complete (a page reclaimed between the check and
the copy) stays in the Exit as sent.

**Compatibility.** Only the FIELD_BEGIN flags word gains bits; an older host
does not read that word, so it shows such a field as one more Exit field (its
Triage, which reads Entry then Exit, finds the path there) and still reports the
Entry incomplete. A recording from an older guest has no marks and reads as
before. Bits 3 and 4 were zero until now. The contract revision stays 17: the
encoding is additive, 0.7.0 is not released, and revisions change only with
a minor release (`revisions.json`); raising it would make an older 0.7.0 host
refuse new bases although it reads them correctly.

**Guest-observable effects.** None new in kind: the exit reads are no-fault
copies like the entry's (they never change residency, `mincore()` included),
one byte per page to check a buffer and then the copy, and only for calls
whose entry found a non-resident page. A successful exec with a non-resident
path keeps a copy of the path (at most `PATH_MAX`) until the call returns.
