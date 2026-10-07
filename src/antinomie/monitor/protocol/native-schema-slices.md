# Native Schema Slice Contract: 2A, 2B, 2G

ANT-T0009 producer/consumer contract, revision 3, 2026-10-07. Section 9 and the 2B fixtures were approved by the user on 2026-10-07.
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
| `data` | `arg4.data`, layout `mount_options`: the readable prefix of one page (`PAGE_SIZE`), as `copy_mount_options()` reads it. If the page has an unreadable part, `arg4.data.tail` records the remainder with `ANT_COPY_FAULT`; this can also mean a non-resident page the kernel would have faulted in. NULL `data` records no field. The UI shows the bytes up to the first NUL as text when they are printable |

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
