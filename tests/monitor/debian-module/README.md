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

With `-` instead of the header packages only phase 1 runs; a profile can
follow, for example `transparent disk=sata` to check another disk bus.

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
and module build use its normal filesystem. The guest writes an upload on its
control worker: while the host's storage stalls (a busy or nearly full host
disk), the guest's own disk writes wait for it, the worker answers nothing
and the host reports the command as timed out. Staging in RAM keeps that host
condition out of this check; it is not an acceptance test for disk-backed
uploads.

The phases are:

1. Load genuine signed filesystem, firewall, and cryptography modules; require
   module BTF and an untainted kernel. Check that recorder functions are absent
   from tracefs. Prove systemd's BPF LSM filesystem restriction denies a read
   which succeeds outside the restricted service, and that the boot journal
   has no BPF LSM failure. On a BIOS installation, grub-pc's debconf answer
   must name an existing disk of this VM.
2. Install the pinned headers and build `module_fixture.ko` against them in the
   guest. The fixture uses `task_struct` and exposes a temporary proc entry.
3. Boot the VM again (installing the tools and building the module record
   every byte dpkg and the compiler write, more than a boot's quota), load,
   exercise, and unload the fixture kept on the disk, then run a BTF fentry
   probe on `vfs_read` and require a positive count. Finally, inspect that
   boot's saved recording for successful module-load, module-unload, and BPF
   calls.

Each phase's terminal output is saved in the new data directory. The unsigned
out-of-tree fixture may taint the kernel; the genuine-module taint check runs
before it. A successful run does not replace the build-time export CRC and
byte-for-byte BTF comparison or the full guest regression tier.
