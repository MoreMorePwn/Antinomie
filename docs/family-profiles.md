# Family profiles

A family profile names a malware family from what a run did: the findings of
Suspicious activity, the files it touched, the addresses it contacted, the
command lines it ran, and the Sigma and YARA rules that matched. Profiles are
data, not code. They sit beside the rule packs and give Triage's Summary, the
run report and Auto mode's label a family when no rule names one, or when the
rules name the wrong one.

A profile matches when its threshold is met, for example "at least 3 markers,
at least 1 of them distinctive". The match is a family candidate like one from
a family rule. Its source lists what was seen:

```
Kaiji: behaviour profile Kaiji · 6 of 9 markers: path_regex ..., path /etc/32676, ...
```

A matched profile is strong evidence of the run itself: with medium or high
behaviour it makes the default label `malicious` (see the label table in
`docs/auto-mode.md`). Its points (100, plus 25 for each unit of matched weight,
at most 300) outrank one or two rules that name another family; that family is
then "also named".

## Where profiles live

- **Shipped profiles:** `src/antinomie/monitor/crates/monitor-core/assets/rules/families/*.toml`,
  one file per family, built into the program. 0.9.1 ships BillGates, BPFDoor,
  Chaos, Dofloo, Kaiji, Kinsing, Mettle, Mirai, Prometei, RotaJakiro, Sliver,
  Tsunami, VPNFilter, XMRig and XorDDoS.
- **Your own profiles:** TOML files in `<data>/rules/families/`, where
  `<data>` is the data folder (the window's, or `antinomie-cli --data-dir`;
  the rule packs are in `<data>/rules/packs/` next to it). They are read when
  Triage builds its Summary and when a report is written. A profile whose name
  matches a shipped one (case ignored) replaces it; files are read in name
  order. A file that cannot be used (bad TOML, an unknown key, a bad pattern,
  over 256 KiB) is skipped and the others still load.

## Format

A file holds one or more `[[profile]]` tables. Each has:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `name` | string | required | The family name the candidate gets, as reports should spell it. |
| `platforms` | list of strings | `["linux"]` | The programs it is for. Antinomie runs Linux programs, so a profile without `linux` (or `any`) is skipped. |
| `min_markers` | integer | 1 | How many markers must be seen. At least `min_distinctive`, at most the number of markers. |
| `min_distinctive` | integer | 1 | How many of them must be distinctive. At least 1: a family is never named on generic markers alone. |
| `min_weight` | integer | 0 | The least total weight of the markers seen. |
| `references` | list of strings | `[]` | The public reports the markers come from. Shipped profiles always cite them. |
| `[[profile.marker]]` | tables | required | The markers, at least one. |

Each marker has exactly one of these keys, and optionally `weight` (1 to 10,
default 1) and `distinctive` (default `false`):

| Key | Matches when |
|---|---|
| `finding` | a Suspicious activity finding with this rule id was seen (`evasion.watchdog_disable`) |
| `path` | a file path the run opened, read, created, wrote, renamed, executed or looked up contains this text |
| `path_regex` | such a path matches this regular expression |
| `url` | a URL, domain or endpoint the run contacted contains this text (case ignored) |
| `url_regex` | such a URL, domain or endpoint matches this regular expression |
| `command` | a command line of a process of the run contains this text |
| `command_regex` | such a command line matches this regular expression |
| `sigma` | a Sigma rule with this id matched (case ignored) |
| `yara_tag` | the run's YARA rules gave this tag (`Mirai-like`, `UPX`, `Go binary`; case ignored) |
| `yara_rule` | a YARA rule whose name matches this regular expression matched |

Regular expressions use the Rust `regex` syntax; in TOML, write `\\` for a
backslash or use a literal string in single quotes.

Paths a run only deleted, or only changed the attributes of, do not count: a
bot that removes rival miners unlinks their files (`/tmp/kinsing`), which says
nothing about its own family. URLs are written `http://host/path?query` as the
report's indicators show them.

Mark a marker distinctive only when nothing but this family is known to show
it: a file name, a URL path or a command line from a public report. A finding
such as `persistence.cron` is a generic marker; give it weight 1.

## Example

```toml
# Mybot: a made-up IoT bot.
[[profile]]
name = "Mybot"
references = ["Example Lab, \"Mybot analysis\", 2026-01-01"]
min_markers = 3
min_distinctive = 1

[[profile.marker]]
# Its lock file (Example Lab 2026).
path = "/tmp/.mybot.lock"
weight = 3
distinctive = true

[[profile.marker]]
# The C2 polls /gate.php?id=<bot id> (Example Lab 2026).
url_regex = '/gate\.php\?id=[0-9a-f]{16}$'
weight = 2
distinctive = true

[[profile.marker]]
finding = "evasion.watchdog_disable"
weight = 2

[[profile.marker]]
finding = "persistence.cron"
```

## Rules that name no family

Besides profiles, two lists in the code decide what a rule's name is worth:

- **Rules known to match other programs** (`DOUBTFUL_RULES`): their family is
  listed as "also named" in the Summary and the report, is never the run's
  family and is no family evidence for the label. 0.9.1 lists
  `MIRAI_OHSHIT_payload` (its string `glibc.malloc.top` is part of a glibc
  setting name in every statically linked glibc program) and
  `MIRAI_TELNETCURL_payload` (its author calls it a lineage marker, not a
  family discriminator).
- **Families with no Linux variant** (RemcosRAT, Agent Tesla, AsyncRAT and
  other Windows families): a rule name, a `family` meta or an IDS message that
  names one never names the family of a Linux program.
