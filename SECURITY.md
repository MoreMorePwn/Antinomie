# Security policy

Antinomie runs untrusted programs in QEMU virtual machines and parses what they
produce on the host. Reports about anything that weakens that boundary are
welcome. The [security model](docs/security.md) describes what Antinomie does
and does not protect against.

## Supported versions

| Version | Supported |
|---|---|
| 0.7.x (latest release) | Yes |
| `release-*` development branches | Fixes land here first; not a supported release |
| 0.6.x and earlier | No; upgrade to the latest release |

Security fixes are released as a new patch version. Older releases are not
patched.

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.** Report it privately through
GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**
(<https://github.com/MoreMorePwn/Antinomie/security/advisories/new>).

Please include:

- the Antinomie version (`antinomie --version`), the base name and revision,
  and the host distribution;
- the affected component (host app, a parser or sandboxed worker, the
  shared-memory transport, the guest kernel patches, the base builders, the
  release or install scripts) and the impact;
- steps or a minimal reproducer. Prefer a harmless program that triggers the
  problem over live malware. If a real sample is needed, give its SHA-256 and
  say so in the report rather than attaching it; arrangements can be made
  privately.

Mark any recording, PCAP or disk image you share as confidential, and remove
credentials and personal data from it first.

## What to expect

- An acknowledgement within 7 days.
- An assessment and, for a confirmed issue, a planned fix within 30 days of the
  report, or an explanation of why it takes longer.
- A GitHub security advisory and a patch release once a fix is available.
  Reporters are credited unless they ask not to be.

Please allow time for a fix before disclosing publicly; 90 days from the report
is the default.

## In scope

- A program in a guest reaching the host through Antinomie's own code: the
  transport, its parsers, the control channel or the host app.
- Bypassing a sandbox the host uses for analysis (bubblewrap, `prlimit`), or a
  parser of recordings, captures, disk images or archives that can be driven to
  run code or write outside its directory.
- A route or network mode that sends traffic somewhere other than documented,
  including any fallback to the Internet that the user did not choose.
- Integrity of downloads: bases, rules and analysis tools that are not checked
  against their recorded SHA-256 values, and problems in the release archive or
  `install.sh`.
- Secrets or private data written where the documentation says they are not.

## Out of scope

- Escapes from QEMU or KVM themselves; report those to the
  [QEMU project](https://www.qemu.org/contribute/security-process/) or your
  kernel vendor.
- A sample detecting that it runs in Antinomie. Stealth limits are documented;
  new detection methods are welcome as ordinary issues.
- Guest root or a guest kernel exploit tampering with that guest's own
  telemetry, which the [security model](docs/security.md) describes as a known
  limit.
- Vulnerabilities in third-party tools Antinomie can install (Ghidra, capa,
  Volatility 3, Tor and others); report them upstream.
