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
| max_size | u32 | 1..64 MiB retained extent; host default 64 MiB |
| timeout_ms | u32 | 1..5000 ms serialization budget; host default 5000 |

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
| CORE_STATUS (0x1060) | u64 handle ID | Exactly 80-byte status below |
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

## Limits, lifecycle and recovery

At most four handles and 128 MiB of reserved guest buffers can coexist. Completed
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
handle has at most one 16,328-byte write in flight, reserved against the shared
quota. The host acknowledges the actual written prefix and digest; final core
and artifact publication require observed durability. While transfer is active,
`core.json` describes a checkpoint prefix; the file can contain later recorded
data until final size/hash publication.

Full checkpoints persist bounded handle ownership tied to the saved run, root
cookie and PID. Restore/reconnect allocates fresh host run directories and checks
the guest STATUS identity before reading. It never replays EXEC/arm commands or
appends to the earlier observation timeline. Old checkpoints without ownership
metadata report interruption instead of guessing a handle.
