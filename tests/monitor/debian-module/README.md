# Debian module ABI qualification

This check boots a disposable Debian Minimal base with four vCPUs and 2 GiB
of RAM through the application's backend. It verifies the distribution's
signed modules and an out-of-tree module built against unmodified Debian
headers. Use the shared build and VM locks when running it alongside other
project work.

```sh
cargo build --manifest-path src/antinomie/monitor/Cargo.toml \
    --release --locked -j2 -p antinomie-monitor-core --example stealth-check
src/antinomie/monitor/target/release/examples/stealth-check abi \
    /path/to/debian-minimal-bundle /path/to/new-test-data \
    tests/monitor /path/to/pinned-header-debs
```

| Input | Requirement |
| --- | --- |
| Base bundle | Current stock-profile Debian Minimal kernel, its symbols, and genuine Debian modules |
| Test data | A new directory; the check refuses an existing directory |
| Fixtures | `tests/monitor`, containing the three `debian-*.sh` scripts and this module |
| Header packages | `linux-headers-6.12.94+deb13-amd64_6.12.94-1_amd64.deb`, `linux-headers-6.12.94+deb13-common_6.12.94-1_all.deb`, and `linux-kbuild-6.12.94+deb13_6.12.94-1_amd64.deb`, verified against the pinned Debian package index |

The benign qualification VM uses NAT to install `make`, `gcc`, and `bpftrace`.
The build and probe scripts run inside that VM as root. Do not run those
scripts on the host or in a VM containing untrusted samples.
Header packages are staged in the guest's `/dev/shm`; the package install
and module build use its normal filesystem. This keeps disk flush latency out
of the header upload and is not an acceptance test for disk-backed uploads.

The phases are:

1. Load genuine signed filesystem, firewall, and cryptography modules; require
   module BTF and an untainted kernel. Check that recorder functions are absent
   from tracefs. Prove systemd's BPF LSM filesystem restriction denies a read
   which succeeds outside the restricted service.
2. Install the pinned headers and build `module_fixture.ko` against them in the
   guest. The fixture uses `task_struct` and exposes a temporary proc entry.
3. Load, exercise, and unload the fixture, then run a BTF fentry probe on
   `vfs_read` and require a positive count. Finally, inspect the saved recording
   for successful module-load, module-unload, and BPF calls.

Each phase's terminal output is saved in the new data directory. The unsigned
out-of-tree fixture may taint the kernel; the genuine-module taint check runs
before it. A successful run does not replace the build-time export CRC and
byte-for-byte BTF comparison or the full guest regression tier.
