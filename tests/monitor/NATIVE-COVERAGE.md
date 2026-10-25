# Safe Native Syscall Exercise

Baseline: Linux 6.12.94, native x86-64 only. The generated declaration inventory
has 375 named slots; x32, i386 and numeric gaps are not part of that count.

```sh
cc -static -O2 -Wall -Wextra -Werror -pthread \
  tests/monitor/native-probe.c -o work/monitor-native-probe
cargo build --manifest-path src/antinomie/monitor/Cargo.toml \
  -p antinomie-monitor-core --example headless --locked
```

Run the static ELF in a disposable, disconnected, four-vCPU guest through the
normal monitor upload/execute APIs. Do not use a retained analysis VM as a test
fixture. The existing `headless` harness uploads the supplied ELF and sends its
stdin release barrier after `READY`, then waits for `PASS` and saves the run.
Choose a fresh, previously nonexistent `DATA_DIR` below a disposable test root.

```sh
src/antinomie/monitor/target/debug/examples/headless \
  BUNDLE DATA_DIR work/monitor-native-probe
python3 tests/monitor/verify-native-coverage.py RUN_RECORDING_DIR \
  --require-partial-read --schema-fixtures tests/monitor/fixtures/native-schema \
  --async-fixtures tests/monitor/fixtures/native-schema-async \
  --async-run-status HEADLESS_REPORT.json --output work/native-coverage.json
python3 tests/monitor/test-native-coverage.py
```

| Part | Behavior / limitation |
|---|---|
| Private files | Unique `mkdtemp` directory, mode 0700, creation/content/stat/path/xattr operations, cleanup before PASS |
| Descriptor/network cases | Private pipes, eventfd, timerfd, epoll and AF_UNIX socketpair; no external connections |
| Memory/process cases | Private anonymous mapping, read-only identity/resource queries, no-op/mismatched futex, child wait status |
| Linux AIO | Owned aligned buffer and private O_DIRECT file; completion checked before context destruction/free |
| io_uring | Private ring and NOP; registered-buffer write/read each verified against 4096 bytes; an 8192-byte fixed read exercises hot-prefix/cold-tail retry capture.
| Slice 2F async | Fourteen requests matched by `user_data` (`ANT_ASYNC` lines): an io-wq read, O_DIRECT AIO reads (one `PREAD`, one two-segment `PREADV` whose iovec array the probe clears after submission) whose output is recorded at reap (stage 7), an SQPOLL write, typed operands (bind, files_update, waitid, futex, futex_waitv, provide_buffers, socket uring_cmd) and a canceled timeout. There is no pause after them: the kernel paces async publication (contract 15.2) |
| Residency | A path and a 16-byte buffer in mapped but untouched file pages record `NOT_RESIDENT`; an unmapped buffer records `COPY_FAULT` (contract 15.1) |
| Async stress | `--async-stress` is a third run (UID 1000): 300 ten-second timeouts exceed the 256 tracked requests and are canceled together; the run must report async loss and the incomplete flag. With publication paced it no longer causes transport drops; its losses are staging losses |
| Multicore | Four concurrent pthreads pinned to distinct allowed CPUs when four are available; emits the available test CPU count |
| Deadline | 30-second process alarm, including the host release barrier; disposable VM contains resources left by an interrupted run |
| Environmental rejection | ENOSYS, EOPNOTSUPP, EPERM, EACCES and ENODEV are recorded as SKIP, not PASS |
| Invalid pointer | A deliberate write from address 1 must return EFAULT and be recorded as an expected rejection |
| Unsupported safe case | Inventory row remains SKIP, with its reason, rather than blindly invoking a dangerous syscall number |

Each case reports a unique case ID, TID and CLOCK_MONOTONIC invocation interval.
Functional cases are paced by 2 ms after logging to separate semantic testing
from the previous unpaced overflow exercise. Pacing does not make the transport
lossless; lost records remain verification failures.

The verifier checks native name/number agreement, framing and distinct Entry/Exit
pairs with identical stream/task/call identity, matching TID, return value and
timestamps inside the case interval. One pair cannot satisfy repeated cases.
Older transcripts without these fields must be regenerated, not assumed valid.
Capture statuses/incomplete events are reported
separately. Its PASS means this exercise was traced, **not** that every pointer
layout, every async operation or all 375 syscalls were fully tested. The result
explicitly sets `payload_completeness_verified` to false. A future approved safe
case can extend the probe without weakening that distinction.

| Verifier option | Additional acceptance check |
|---|---|
| No strict async option | Checks the syscall cases above; does not certify asynchronous payload contents |
| `--require-fixed-async` | Requires distinct write/read request identities, submission/acceptance/final-completion correlation, result 4096 and byte-exact fixed-buffer payloads |
| `--require-partial-read` | Includes the fixed-buffer checks, then requires byte-exact 8192-byte read output, final result 8192, and at least two observed output ranges with a nonzero continuation offset. A single whole-buffer capture does not establish retry coverage |

The controlled partial-read fixture writes two distinct pages, warms the first
and asks the kernel to evict the second before submission. Cache behavior can
vary: when no actual retry is observed, the strict retry check fails rather than
assuming that path was exercised. On the four-vCPU image #6 it reproduced a
missing prefix (`[4096, 4096]` only); image #7 preserved both observed ranges
(`[0, 4096]` and `[4096, 4096]`) and passed. Image numbers are build checkpoints,
not new transport versions.

The final measured exercise matched 117 syscall types and left 258 inventory
types explicitly SKIP. These counts cover this safe workload, not full semantic
coverage. The verifier's 13 regression tests include cross-identity and repeated
case mismatches, corrupted payloads, duplicate request identities, missing-prefix
capture, and an unobserved retry. The recorded evidence and remaining native
schema/async gaps are listed above.

The guest cleanup check is required before the terminal emits `NATIVE PASS`.
Irreversible system operations such as reboot, global mount changes and module
loading are not executed by this sample. Normal monitor shutdown still owns
QEMU and recording cleanup on a host-test failure.
