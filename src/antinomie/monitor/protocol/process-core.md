# Process core acquisition (guest revision 15)

Opt-in acquisition retains a native Linux x86-64 ELF core of the launched root
thread group before its address space is released. Descendant processes are not
captured. Linux's ELF writer and `coredump_filter` determine included mappings;
omitted mappings remain visible through ELF metadata. No helper process or guest
pathname is involved. An opt-in fatal core is retained by the host instead of
being sent to the guest's `core_pattern` destination.
Linux stops the captured thread group. Other processes can still modify shared
mappings or a separately shared address space during capture.

## Launch

All integers use little-endian encoding. EXEC flag `2` selects process-core
acquisition. Append this trailer after argv/env and any specimen trailer:

| Argument | Type | Meaning |
| --- | --- | --- |
| max_size | u32 | Stored-byte budget: 1..`max_core_bytes` from CORE_CAPS (64 MiB..1 GiB), or 1..64 MiB on a guest without it; the app's default is 256 MiB clamped to the guest |
| timeout_ms | u32 | 1..`max_timeout_ms` from CORE_CAPS (up to 60000), or 1..5000 ms without it; the app's default is 5000 ms + 10 ms per MiB of budget |

The existing 24-byte EXEC result and optional 24-byte specimen result are
followed by a 24-byte core arm result:

| Offset | Type | Meaning |
| --- | --- | --- |
| 0 | u64 | Nonzero retained handle ID; zero on arm failure |
| 8 | u64 | Reserved maximum extent; zero on arm failure |
| 16 | i32 | Zero on success, negative errno on arm failure |
| 20 | u32 | Reserved zero |

Arm failure is separate from execution failure: the program still executes.
An older guest rejects the new flag; the host gates it by guest revision.
App-terminal launches are supported. Desktop shell wrappers cannot yet prove
ownership of the chosen executable and therefore refuse this option.

## Status, read and release

Every request starts with the existing 8-byte control header, flags zero.

| Command | Arguments after header | Return |
| --- | --- | --- |
| CORE_STATUS (0x1060) | u64 handle ID | 80-byte status below; header flags `1` (STORED) appends the stored byte count (96 bytes) |
| CORE_CAPS (0x1066) | none | 48-byte capability reply (see Budget, limits and reasons) |
| CORE_READ (0x1061) | u64 ID, u64 offset, u32 capacity, u32 reserved zero | Specimen-compatible 24-byte framing plus data; capacity 1..16328 |
| CORE_RELEASE (0x1062) | u64 ID | Empty success reply; cancels/removes retained ownership |

| Status offset | Type | Meaning |
| --- | --- | --- |
| 0 | u64 | Handle ID |
| 8 | u64 | Root task cookie |
| 16 / 24 | u64 | Capture start / finish guest monotonic timestamps |
| 32 / 40 | u64 | Retained extent / ELF-declared expected extent |
| 48 | u32 | State: 1 armed, 2 copying, 3 ready, 4 partial, 5 unavailable, 6 canceled |
| 52 | i32 | Capture status, zero or negative errno |
| 56 | i32 | Original Linux wait status |
| 60 | u32 | Fatal signal, or zero for normal exit |
| 64 | u32 | Coverage flags: 1 root only, 2 native ELF64, 4 filtered memory, 8 coverage gap |
| 68 | u32 | Root thread-group PID |
| 72 | u32 | Thread contexts retained in complete ELF notes |
| 76 | u32 | Reserved zero |

Only terminal ready/partial buffers can be read. Read framing returns offset,
total retained size, data length and reserved zero. The host checks every extent,
identity and response length before writing, and hashes the retained prefix.

## Budget, limits and reasons

`max_size` bounds the bytes the guest **stores**, never the file's logical extent:
Linux skips pages that are not resident and the guest keeps the written bytes in
extents, so a core with a far-away stack segment costs only what it holds. The
logical extent has its own bound of 16 GiB.

The guest derives what it accepts from its memory and says so with `CORE_CAPS`
(header only; reply of 48 bytes):

| Offset | Type | Meaning |
| --- | --- | --- |
| 0 | u32 | ABI, 1 |
| 4 | u32 | Flags: 1 BUDGET, 2 STATUS_STORED, 4 LONG_TIMEOUT, 8 CHUNKED, 16 FAST_READ |
| 8 | u64 | Largest budget of one handle: half of RAM less 128 MiB, clamped to 64 MiB..1 GiB |
| 16 | u64 | Pool: the budgets of open handles add up to at most twice that |
| 24 / 28 | u32 | Handles (4) / longest deadline (60000 ms) |
| 32 | u64 | Guest RAM |
| 40 | u64 | Bytes an exit core allocates when armed (64 MiB) |

A 256 MiB guest accepts 64 MiB, 512 MiB accepts 128 MiB, 1 GiB accepts 384 MiB,
2 GiB accepts 896 MiB and 2.25 GiB or more accepts 1 GiB. A guest without
CORE_CAPS answers it with `-EOPNOTSUPP`; the host then keeps the earlier contract
(64 MiB, 5000 ms, 80-byte status, one read at a time) and refuses a larger request
with a message that names the base series it needs. A guest that accepts every
earlier request unchanged needs no revision bump: the contract stays at 17.

The guest buffer is a table of 8 MiB chunks allocated while the core is written.
An exit core allocates the first 64 MiB when it is armed, as before; the rest
comes as the core grows, so an unreachable budget ends the core as a labelled
partial (`-ENOMEM`) instead of failing one large allocation. The ELF header,
program headers and notes lie in the first chunk. The buffer is immutable once the
status is terminal, so reading is idempotent.

The sink is the only budget enforcer, so a status errno means one thing:

| errno | Meaning | Host reason |
| --- | --- | --- |
| `-EFBIG` | stored-byte budget reached | budget |
| `-ENOMEM` | no memory for another chunk | guest memory |
| `-ETIMEDOUT` | serialization deadline | deadline |
| `-ECANCELED` | cancel, release or reattach fence | canceled |
| `-E2BIG` | extent table full, or more than 256 threads / 4096 mappings | guest bounds |
| `-EOVERFLOW` | logical extent past 16 GiB | extent bound |
| `-ENODATA` | thread contexts or pages not covered | coverage |
| `-EINTR` | a signal interrupted the acquisition | interrupted |
| `-EIO` | Linux's writer stopped for another reason | writer stopped |

Earlier guests reported a budget stop as `-EIO`; the split is display-only to a
host that does not read it.

The host records for every core what was requested, accepted, expected (the
ELF-declared extent), saved (bytes on disk, holes excluded) and the logical size,
and a reason `{code, errno, text}` when it is not complete. Host-side reasons are
quota, host disk (a preflight against the stored byte count plus 64 MiB, before
any byte is written), write failure, cancellation and boundary seals; the first
reason found stays. Bytes are never labelled as captured when they are not: the
ELF's program headers keep their declared sizes and the sidecar says why they are
short.

Transfer reads up to eight `CORE_READ`s for consecutive offsets before the first
reply is awaited and joins the replies into one write of at most 256 KiB. A short
reply (the end of an extent) or a hole discards the replies that followed it,
because the host only predicted their offsets; a hole after data waits for the
next burst. The guest polls its control worker at every tick while a finished core
is being read (FAST_READ), so the rate is no longer bounded by its 10 ms poll.

## Limits, lifecycle and recovery

At most four handles can coexist and their budgets add up to at most the pool
(128 MiB on a guest without CORE_CAPS). Completed
handles expire after 180 seconds without access. Thread/VMA metadata is bounded
at 256 threads/4096 mappings. Size, copy errors or serialization timeout produce
explicit partial/unavailable results. Thread rendezvous and faulting page reads
may wait beyond that timeout; it is not a guaranteed exit deadline. SIGKILL
retains immediate Linux teardown and can make process context unavailable.
Linux wait status is preserved; host acquisition adds no synthetic core-dumped
bit. A leader-only thread exit does not kill surviving peers for acquisition.
Contexts of threads that exited before the final capture cannot be recovered;
a remaining dead leader can therefore produce an explicit context coverage gap
even when the retained ELF file has its full declared extent.
Fatal core-producing signals retain their original signal information. Normal
exit and other fatal signals use synthetic `SI_KERNEL` note information; the
original sender information for a non-core fatal signal is unavailable.

Host files live in the run's private `core` directory, linked by `artifacts.json`.
`core.json` records run/VM/boot identity, original executable path, guest status,
retained size, SHA-256, limits and incomplete outcome. Shared recording quotas
apply; cancellation/storage failures retain any available prefix.
Four host disk workers and four queued jobs bound asynchronous core I/O. Each
handle has at most one write in flight (up to 256 KiB), reserved against the
shared quota. The host acknowledges the actual written prefix and digest; final core
and artifact publication require observed durability. While transfer is active,
`core.json` describes a checkpoint prefix; the file can contain later recorded
data until final size/hash publication.

Full checkpoints persist bounded handle ownership tied to the saved run, root
cookie and PID. Restore/reconnect allocates fresh host run directories and checks
the guest STATUS identity before reading. It never replays EXEC/arm commands or
appends to the earlier observation timeline. Old checkpoints without ownership
metadata report interruption instead of guessing a handle.
