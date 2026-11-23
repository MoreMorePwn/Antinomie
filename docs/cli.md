# Command line guide

[← Back to the overview](../README.md)

`antinomie-cli` is Antinomie without a window. It does what the window does with
bases, VMs, runs, Triage and reports, and it adds Auto mode, where a sample goes in
and a report and a label come out. Use it for scripts, for a server with no display
and for a queue of samples.

This page is a guide by task: set up, analyse one sample, run Auto mode, script it.
Every command here is in the [command reference](cli-reference.md), which lists every
command, argument and option and is generated from the program itself. The notes at
the end of this page keep the finer points of each command.

- [What the CLI is](#what-the-cli-is)
- [First setup](#first-setup)
- [Analyse one sample by hand](#analyse-one-sample-by-hand)
- [Auto mode](#auto-mode)
- [Scripting recipes](#scripting-recipes)
- [Exit codes](#exit-codes)
- [Integrity and custody](#integrity-and-custody)
- [Troubleshooting](#troubleshooting)
- [Where next](#where-next)
- [Command notes](#command-notes) and [Auto mode commands in detail](#auto-mode-commands-in-detail)

## What the CLI is

`antinomie-cli` is the headless front end: the same engine as the window, with no
display. It ships beside `antinomie-monitor` and does not link the GUI libraries.
It links the same Triage scan (the `antinomie-triage` library), so a recording
made from the command line also keeps the earlier bytes of the files a run
changed: the program that ran the VM copies them when the boot ends.
The grammar is `antinomie-cli [GLOBAL FLAGS] GROUP COMMAND [FLAGS] [ARGS]`; the
global flags may also follow the command.


**Install.** The release archive holds `antinomie-monitor` (the window) and
`antinomie-cli` side by side. `./install.sh` puts both on your path as `antinomie` and
`antinomie-cli` in `~/.local/bin` (`./install.sh --uninstall` removes them; your data
stays). Or run `./antinomie-cli` from the unpacked folder. `antinomie-cli --version`
prints the app version; `antinomie-cli --help` lists the commands, and `antinomie-cli
GROUP --help` lists the commands of a group. QEMU, bubblewrap and the other tools are the
same as for the window (see [Dependencies and analysis tools](usage.md#dependencies-and-analysis-tools));
the CLI needs no display, GTK or window system.

### One engine, one data folder

The CLI and the window are the same engine. They read and write the same data folder,
`~/antinomie` by default, so a base you installed in the window is there for the CLI and a
recording a command made opens in the window. `--data-dir PATH` selects another folder.
For automation, give it a folder of its own (`~/auto`, `/var/lib/antinomie`), never the
window's.

**Who owns the folder.** One process owns a data folder at a time: the window, the
daemon (`auto daemon`) or a command that needs the engine (for example `vm start`,
`run exec`, `config set`). The owner is written to `run/owner.json`; a record whose process is
gone is ignored. `antinomie-cli doctor` shows it as `data_dir.owner`.

A second process that needs the engine on the same folder is refused with **exit 21**, and
the message names the owner (its pid, whether it is the window, the daemon or a command, and
since when). Close the owner, or use a folder of your own for the second one.

Some commands never need the engine, so they work beside the window or the daemon:

- the reads of the library and the recordings: `recording list`, `recording show`,
  `recording export`, `triage`, `report`, `detect` (without `--save`), `sample list`,
  `sample show`, `sample tag`, `sample verify`, `custody verify`;
- `config path`, `config get` and `config validate`, `rules list`, `rules catalog`, `rules
  install` and `rules update`, `tools list`, `tools install` and `tools update`, and the `ioc`
  commands;
- the `auto` commands, when a daemon answers; without one the reads (`auto status`, `auto list`,
  `auto result` and the like) read the run store directly.

When a daemon runs, the commands that need the engine go to it where they can (see
[Command notes](#command-notes)). `--direct` keeps a command in its own process and
`--daemon` insists on the daemon (exit 21 when none answers).

### Output formats

`-o human|json|ndjson` (also `--format`) chooses the output. The default is `human` on a
terminal and `json` when the output is a pipe or a file, so a script gets JSON without
asking.

**Output.** `json` prints exactly one document on standard output:
`{"api_version":1,"ok":true,"result":...}`, or on failure (with a non-zero exit)
`{"api_version":1,"ok":false,"error":{"code":...,"message":...,"retryable":...,"details":...}}`.
A list result is `{"items":[...],"next_cursor":...}`. `ndjson` prints one object
per line: a list command prints its items and then a last line
`{"result":{"count":N,"next_cursor":...}}`; any other command prints
`{"result":...}`; a failure prints `{"error":...}`. Log lines stay on standard error.


Colour is `--color auto|always|never`; `NO_COLOR` is honoured. `-q` shows only errors on
standard error, `-v` and `-vv` show more, and `--log-format text|json` sets the log lines.
`--timeout SECONDS` limits the whole command (exit 14 when it passes).

### The global flags

The global flags may come before or after the command.

| Global flag | Meaning |
|---|---|
| `--data-dir PATH` | Data directory (default `$HOME/antinomie`; `~` is expanded). Use a directory of its own for automation, never the one the window uses |
| `--bundle PATH`, `--qemu PATH`, `--qemu-img PATH`, `--tcg`, `--no-headless` | Engine options, as in the window. The CLI is headless unless `--no-headless` is given |
| `--boot-wait SECONDS`, `--tcg-multiplier N` | The waits of a VM start and a launch for this command, over `settings.json`'s `start` section (the window's **Tools > Settings > Advanced**, VM start and guest connection timeouts; `config set start.boot_wait_secs 120`). `--boot-wait` (5 to 600, default 60) is how long a launch waits at KVM speed for a Debian guest to finish booting before it starts the program anyway; `--tcg-multiplier` (1 to 100, default 10) is how many times longer every start wait, that boot wait and each guest command may take under TCG. They matter to the commands that start an engine with a VM: `vm start`, `run exec --start`, `snapshot restore`, `auto daemon` |
| `--socket PATH` | The daemon's socket. Without it a command uses `[daemon] socket` of `<data>/service.toml`, else `<data>/run/antinomie.sock` (the same rule the daemon follows) |
| `--daemon`, `--direct` | `--daemon` requires a running daemon (exit 21 when none answers), `--direct` never uses one. Without either, the `auto` commands and the reads (`recording list`, `recording show`, `recording export`, `triage`, `sample list`, `sample show`, `sample tag`, `custody verify` without `--export`, `vm list`, `base list`) use the daemon when one answers and work in the calling process when none does. The other commands always run in the calling process and take the lock (`--direct` and `--daemon` conflict) |
| `-o, --format human\|json\|ndjson` | Output format; `human` on a terminal, `json` otherwise |
| `--color auto\|always\|never` | Colour of human output; `NO_COLOR` is honoured |
| `-q`, `-v`, `-vv`, `--log-format text\|json` | Log lines on standard error; for `auto daemon` the flags win over `[log]` in `service.toml` |
| `--timeout SECONDS` | Overall limit of the command |


## First setup

Do this once on a new machine or a new data folder. Add `--data-dir` to every command
if you use a folder other than `~/antinomie`.

### 1. Check the machine

```sh
antinomie-cli doctor
antinomie-cli doctor --require qemu,qemu-img,bubblewrap,kvm
antinomie-cli capabilities
```

`doctor` lists each runtime tool and who owns the data folder, and exits 20 when a required
tool is missing. Without `--require` it checks the tools the window also treats as
required. For an unattended host say what you need, as in the second line. A missing KVM is
only a warning by default: VMs then run with TCG, slowly. The tool names are in the
[command notes](#command-notes).

`capabilities` prints the API version, the app version, the number of lanes, the report
formats and the accelerator (`kvm` or `tcg`). When a daemon answers, it prints the daemon's
whole answer: also the accepted types and architectures, the routes, the static checks, the
detection engines, the IOC datasets and the run API features.

### 2. Get a base

A base is the guest system a VM boots from. The catalog is off until you allow it:

```sh
antinomie-cli config set outbound_catalog true
antinomie-cli base list --remote
antinomie-cli base download ID --wait
antinomie-cli base list
```

`config set outbound_catalog true` is the same switch as **Settings > Detection > Allow
outbound catalog and rule downloads** in the window. Without it, `base list --remote` and
`base download` exit 5. Set it before a daemon starts: `config set` takes the data-directory
lock.

**Picking the current base.** `base list --remote` puts the bases built for this app first
and gives each one its architecture, its guest contract revision and what it is for: `for
Antinomie 0.9.0`, `for Antinomie 0.8.0, outdated` or `needs Antinomie ... or newer`. With
`-o json` each item has `status`: `current`, `outdated`, `needs_newer_app` or `legacy`. Pick
a `current` base of the architecture you analyse. The first row is the best one:

```sh
antinomie-cli base list --remote -o json | jq -r '[.result.items[] | select(.status == "current")][0].id'
```

`base download ID` takes the identity from the first column, or the first characters of it
(4 or more). It waits for the end in direct mode, because leaving would cancel it.

You can also install a boot-bundle folder you already have, or build one:

```sh
antinomie-cli base install ./bases/busybox
antinomie-cli base build --profile busybox
```

`base install DIR` installs a folder that holds `bundle.json`, the kernel and the disk.
`base build` makes one here (`--profile busybox|busybox-extra|debian-minimal|debian-xfce`).
A base is named by its identity, the start of it (4 characters or more) or its label.

### 3. Make a VM

```sh
antinomie-cli vm create lab --base busybox --network routed
antinomie-cli vm list
antinomie-cli vm status lab
```

The defaults are the window's: 4 CPUs, 2048 MiB of RAM, 8 GiB of disk, a disconnected
network and the Realistic desktop device profile. `--base` may be left out when exactly one
base is installed.

| `--network` | What the VM gets |
|---|---|
| `disconnected` (default) | A network card with nothing behind it |
| `isolated` | QEMU user networking with `restrict=on`: the guest has a network, and nothing leaves |
| `routed` | The per-run route gateway: each run chooses where its traffic goes (`run exec --route`); between runs nothing leaves |
| `nat` | QEMU user networking: the guest reaches out through this computer |

Use `routed` for malware you want to run with a route (`drop`, `internet`, `inet_sim`,
`tor`, `vpn`, `socks5`). The routes are explained in [Network routes](usage.md#network-routes).

`--stealth` chooses what the guest sees of the machine: `realistic-desktop` (default),
`realistic-laptop`, `realistic-server`, `iot` or `transparent`. `iot` is the IoT device
(Raspberry Pi), which only an arm64 VM presents: on an x86-64 base the VM keeps it but starts
as Normal QEMU, and `vm create` says so in a `note`. A Debian base needs a guest account:
give the password as one line on standard input with `--password-stdin` (never on the command
line), and the account name with `--user`.

```sh
printf '%s\n' "$PASSWORD" | antinomie-cli vm create lab --base debian --user analyst --password-stdin
```

A VM lives as long as the command: in direct mode the engine runs inside the command and
stops the VM when the command ends. `vm start lab` boots it, shows how long the guest took
to answer and stops it again; `--hold 60` keeps it up for 60 seconds. Keeping a VM up between
commands is what the daemon is for.

### 4. Tools, rules and datasets

Static analysis, detection and Triage use optional tools, rule packs and indicator datasets.
All of them take no engine lock, so they work beside the window or a daemon.

```sh
antinomie-cli tools list
antinomie-cli tools install capa floss ghidra die
antinomie-cli rules list
antinomie-cli rules catalog
antinomie-cli rules install yara-forge-core
antinomie-cli ioc datasets list
```

`tools install ID...` downloads, checks (SHA-256) and unpacks tools into `<data>/tools/<id>/`
as **Tools > Analysis tools** does, and resumes a cut download. `rules install ID...`
downloads catalog packs with their default options, as **Tools > Detection rules** does.
Running the command is the consent to download, so these two need no `outbound_catalog` switch.

The IOC datasets of abuse.ch (ThreatFox, the URLhaus datasets, Feodo Tracker and the SSLBL
lists) feed Triage, the reports and Auto's Check online. ThreatFox and the URLhaus datasets
need the abuse.ch key, which you give on standard input, never as an argument:

```sh
antinomie-cli config api-key set abusech < abusech-key.txt
antinomie-cli ioc datasets update
antinomie-cli config api-key show
```

`config api-key show` prints which keys are stored, each as its last four characters; `clear
SERVICE` forgets one. The key is stored in `<data>/api-keys.json` (mode 0600), the file of the
window's **Tools > API keys**, and never appears in a log, an error or a report. See
[the abuse.ch key](service-config.md#the-abusech-key).

## Analyse one sample by hand

This is the low-level path: you add the sample, run it in a VM, and then read the
recording. Auto mode does the same in one command, with a revert to a clean snapshot first.
Run samples only in the lab VM you made for it.

### 1. Add the sample

```sh
antinomie-cli sample add ./sample.elf --tag category=botnet
antinomie-cli sample list
antinomie-cli sample show SHA256 --runs
```

`sample add` hashes and archives the file in the library, never runs it, and prints its
SHA-256. A tag is `verdict=`, `category=`, `technique=` or `custom=` plus a value, or a bare
custom value. `--name` names the file in the library, and `--delete-original` removes the
file once the archive read back and matched.

### 2. Run it

```sh
antinomie-cli run exec SHA256 --vm lab --start --net-capture --route inet_sim
```

`run exec SAMPLE` uploads one library sample into a VM, runs it and waits until the
recording is complete and settled. `SAMPLE` is a SHA-256 from `sample list`, or a file, which
is added to the library first. The common flags:

| Flag | What it does |
|---|---|
| `--vm ID` | The VM (optional when there is one). |
| `--start` | Boot a stopped VM; without it a stopped VM is refused. |
| `--route drop\|internet\|inet_sim\|tor\|vpn\|socks5` | Where the traffic goes. A routed VM only. |
| `--net-capture` | Record the VM's network traffic. |
| `--args A B ...` (or after `--`), `--env K=V`, `--as user\|root\|UID:GID` | The program's arguments, environment and user. `user` is UID 1000. |
| `--memory-dump`, `--core-dump` | Take the VM's memory, or a core of the program, when its tree has ended. |
| `--dump-trigger low\|medium\|high` with `--dump-kind core\|memory\|both` | Take a dump while the program runs, when the live Triage rules match at that tier or above. Off by default; `--dump-kind` defaults to `core`. |
| `--core-nonresident` | The trigger's cores also read pages that are not in memory. Needs a core trigger and a revision-22 base. |
| `--static CHECKS` | The guest-side static analysis too (the names `analyze --help` lists). |
| `--load-into PROGRAM` | The sample is a shared library: PROGRAM (an absolute guest path) runs with `LD_PRELOAD` set to it. |
| `--screenshot-every SECONDS` | A picture of the VM screen every SECONDS (1 to 999), and one when the tree ends. `--screenshot-max-pictures` and `--screenshot-max-mib` set the limits. |
| `--timeout-run SECONDS` | How long the program may run (default 300), after which it is told to stop. |
| `--events` | Print the progress, one event per line, then the result. Implies `-o ndjson`. |

The result says `outcome`: `succeeded` (exit 0), `partial` (exit 11: a piece of evidence
finished incomplete) or `failed` (exit 10, with `failure.code`). It names the run (its id is
what the next commands take), the evidence and its paths, the time per stage and the end of
the program's output. The program runs in the app terminal as `/tmp/<sha8>-<name>`.

If the command cannot start because the VM is stopped, add `--start`. If the VM needs a
route, create it with `--network routed` first. A Debian guest is given the boot wait before
the program starts, and under TCG every wait is longer (see `--boot-wait` and
`--tcg-multiplier`).

### 3. Read the result

`RUN` below is the run's id or its first characters (4 or more), `vm:boot:run`, a run key or
the run's folder. Every VM of the data folder is searched. These commands take no engine
lock, so they work while the window is open.

```sh
antinomie-cli recording list --limit 5
antinomie-cli recording show RUN --summary
antinomie-cli triage RUN
antinomie-cli detect RUN --engine yara,sigma,ids
antinomie-cli report RUN --formats html,json --out ./report
```

- `triage RUN` indexes the whole run the way the window's Triage does and prints its
  Summary: the assessment and why, the counts, the families, the techniques, the key behaviours
  and the detections. `--parts LIST` adds report parts to the result. It writes nothing into
  the recording but the index Triage keeps there.
- `detect RUN` runs YARA, Sigma and IDS over the run's evidence as the Detection tab does. YARA
  needs the static analysis of the run's sample (`run exec --static`), IDS needs a capture
  (`run exec --net-capture`) and Sigma needs the event journal the index writes; an engine
  without its evidence is listed as not scanned, with the reason. Without `--save` nothing is
  written into the recording; `--out DIR` writes each engine's full result. `--save` keeps the
  results in the recording and takes the engine lock. `detect` exits 1 when an engine failed.
- `report RUN` writes the files of the window's **Export report**. `--formats` is a list of
  `html`, `pdf`, `json`, `misp`, `stix`, `md` (or `all`); `--parts` is a list of `summary`,
  `indicators`, `attack`, `processes`, `findings`, `files`, `file_activity`, `network`,
  `detections`, `evidence`, `custody`, `static_analysis` (or `all`). By default they are
  the export choices of `settings.json`: HTML and PDF, every part, defanged. `--defang` and
  `--no-defang` choose how indicators are written (`hxxp://example[.]com`). `--evidence-bundle`
  also writes the zip with the captures, the files the run dropped (in an inner AES-256 zip
  with the password `infected`), the custody export and a SHA-256 manifest. `--include-content`
  keeps a clipped preview of what the sample read. The files go to `--out` (default
  `report-<first 8 characters of the run id>`), never into the recording. See [Triage
  report export](triage-report.md).
- `recording list` lists the recordings, newest first. `--vm`, `--sample`, `--run` (the Auto run
  that made it), `--state`, `--since 24h` and `--limit` filter it. `recording show RUN
  [--summary]` shows one recording and whether it is `live`, `finalizing`, `complete` or
  `interrupted`.
- `recording export RUN --out DIR` writes the parts (`trace`, `processes`, `findings`,
  `indicators`, `files`, `network`, `timeline`, `analysis`, `custody`, `artifacts`) as
  `*.ndjson` files, one row per line, for your own tools. The bytes the sample produced are
  written only with `--sensitive`.

The window and Auto mode build a run's Triage digest on their own. For a run older than a week, or after an
interruption, `digest RUN` or `digest --pending` builds it (it takes the engine lock).

To look at a file without a VM, `antinomie-cli analyze FILE` adds it to the library and runs the
static analysis on the host, in bubblewrap. See [Command notes](#command-notes).

## Auto mode

Auto mode runs samples unattended: a sample goes in, it runs in a VM that is reset to a
clean snapshot first, the recording is analysed, and a report and a label come out. The
pipeline, the host work pool and the failure codes are explained in [Auto mode](auto-mode.md).
This section is the command side.

### Make the lane

A lane is one VM kept for automation, with a clean snapshot that every run starts from. Use a
data folder of its own.

```sh
antinomie-cli --data-dir ~/auto base install ./bases/busybox
antinomie-cli --data-dir ~/auto auto init --base busybox
antinomie-cli --data-dir ~/auto auto submit ./sample.elf --verdict-exit --out ./report
echo $?     # 0 clean_observed, 30 suspicious, 31 malicious, 32 inconclusive, 10 failed, 11 partial
```

`auto init` creates the lane VM (default name `auto-1`, 2 CPUs, 4096 MiB, 40 GiB) on a routed
network, boots it once, waits until the guest has finished booting, stops it, takes the Disk
snapshot `auto-clean` and writes `<data>/service/lanes/lane-1.json`. A Debian base needs a
guest account (`--user NAME --password-stdin`). `auto init` runs in the calling process, so stop
the daemon first. `--replace` makes a new lane VM for an existing lane and keeps the old VM for
you to delete. `auto lane list` shows the lane and whether it is quarantined; `auto lane reset
--yes` reverts the VM to its clean snapshot now.

A run uses the built-in preset Standard unless it names another. The report files (HTML and
JSON by default) are in `./report`. Without a daemon, `auto submit` runs the run in the
command itself, owns the data folder while it runs and exits with the run's code.

### Presets

A preset is a named set of run options to start from. Six are built in and always there:

| Name | What it is for | Route | Run time |
|---|---|---|---|
| `standard` | The default: 11 Triage static checks, YARA, Sigma and IDS, HTML and JSON reports | None (drop) | 5 min |
| `simulated-network` | Five minutes, fake internet services (InetSim), a core when a High rule matches (needs `evidence.core_dump`) | InetSim | 5 min |
| `quick-look` | Two minutes, nothing leaves the lab, five static checks and YARA | None (drop) | 2 min |
| `deep` | Fifteen minutes on InetSim, dumps when suspicious, deep static analysis, PDF and an evidence bundle (needs `evidence.core_dump` and `evidence.memory_dump`) | InetSim | 15 min |
| `interactive` | Ten minutes, nothing leaves the lab, taking control allowed | None (drop) | 10 min |
| `live-network` | Ten minutes through Tor (a live route is not set up on this node in this version) | Tor | 10 min |

```sh
antinomie-cli auto preset list
antinomie-cli auto preset show standard > ~/auto/presets/mine.toml
antinomie-cli config validate
antinomie-cli auto submit ./sample.elf --preset mine
```

`auto preset list` lists the presets with the permissions their options need and whether you can
run them as they are. `auto preset show NAME` prints a preset as a preset file (TOML, its name
and digest as comments). Save it as `<data>/presets/<another name>.toml` and edit it: your
own presets are the files of `<data>/presets/`, and the file name is the preset name. The
built-in names, and `custom`, may not be used. `config validate` checks `service.toml`, the
built-in presets and `presets/*.toml` without starting anything, prints each problem as
`file:line:column` and exits 4 on an error (`--preset NAME` checks one). A running daemon reads
the presets again on `SIGHUP`; runs already queued keep the preset they were submitted with.

**Custom.** A flag of `auto submit` that changes a preset value (`--timeout-run`, `--args`,
`--env`, `--as`, `--route`, `--static`, `--formats`, ...) makes the run **Custom**: it stores the
preset it was based on and the keys it changed. Only your permissions and the node's limits stop
you. `auto rerun RUN --override program.run_time_s=60` changes one option of an earlier run.
Every key of a preset is in [service configuration](service-config.md), and the full list of
presets is in [Auto mode](auto-mode.md#presets).

### Submit and follow

```sh
antinomie-cli auto submit ./sample.elf --preset quick-look --label case=1042
antinomie-cli auto status
antinomie-cli auto wait RUN --verdict-exit
antinomie-cli auto result RUN
antinomie-cli auto fetch RUN json --out ./report.json
antinomie-cli auto events RUN --follow
antinomie-cli auto cancel RUN --reason "wrong sample"
antinomie-cli auto rerun RUN --preset deep
```

| Command | What it does |
|---|---|
| `auto submit FILE` (or `--sha256 HEX`) | Uploads the file to the daemon and queues a run; prints the run. `--wait` waits for the end and exits with the run's code; `--follow` also prints the run's events as NDJSON; `--verdict-exit` waits and exits 30, 31 or 32 for a succeeded run labelled suspicious, malicious or inconclusive; `--out DIR` copies the report files there. `--idempotency-key K` makes a repeated submit within 24 hours return the first run. A rejected run exits 13. |
| `auto status [RUN]` | One run, or the queue and the lanes. |
| `auto list` | Runs, newest first: `--state`, `--outcome`, `--sha256`, `--label K[=V]`, `--since 24h`, `--limit`, `--cursor`. |
| `auto wait RUN...` | Waits until the runs have ended (`--timeout` bounds it, exit 14) and exits with the worst code. |
| `auto events RUN` | The run's stored events; `--follow` keeps printing until the run ends; `--since SEQ` resumes; `--types run.stage,run.state` filters. `auto events --all --follow` follows every run and the engine. |
| `auto result RUN` | The outcome, the label with its score and basis, and the paths of the report files. |
| `auto artifacts RUN`, `auto fetch RUN KIND [--out PATH\|-]` | The run's artifacts; copy one (`html`, `json`, `pdf`, `misp`, `stix`, `md`, or `report.bundle`) to a file, a folder or standard output (`-`). |
| `auto cancel RUN [--reason TEXT]` | A queued run is cancelled at once; a running one stops its run and VM and ends `cancelled` (its recording is kept). |
| `auto rerun RUN` | A new run from a finished one, with `repeat_of` set. |
| `auto queue status\|pause\|resume` | The queue; a paused queue starts no run (running runs finish). |

The label of a succeeded run is one of `malicious`, `suspicious`, `clean_observed` and
`inconclusive`, with an optional score and a `basis` sentence that says why. `clean_observed`
means "nothing seen in this run", not "clean".

### The daemon

```sh
antinomie-cli --data-dir ~/auto auto daemon
```

`auto daemon` runs in the foreground until it is stopped (`--foreground` is accepted and is the
only mode). It owns the data folder, reads `service.toml` and the presets, finishes what a crash
left behind, runs the queue on its lane and serves the run API on `<data>/run/antinomie.sock`. The
`auto` commands then talk to it over that socket. `SIGTERM` or Ctrl-C stops it cleanly,
`SIGHUP` reads the configuration again and `SIGUSR1` writes the queue's state to the log (the
table is in [Auto mode commands in detail](#auto-mode-commands-in-detail)).

For a daemon that stays up, use systemd: `packaging/antinomie-auto.service` is a system unit for a
dedicated user, and `packaging/antinomie-auto.user.service` is a user unit. Both run `antinomie-cli
auto daemon`. The steps are in [Run it under systemd](auto-mode.md#run-it-under-systemd). The
example configuration is `packaging/service.toml.example`. Before you leave it running, read
[Unattended use](security.md#unattended-use).

**Queue and lanes.** Runs wait in a queue and go to a free lane whose base and architecture can
run them; `[daemon] lanes = N` in `service.toml` runs lanes 1 to N. Make lane 2 to 4 with `auto
init --lane N`. `--priority 0` to `9` lets a run start first. `auto queue pause` starts no new
run. See [Several lanes](auto-mode.md#several-lanes).

**Watch folders.** Add a folder to `service.toml` and every stable file dropped in it becomes a
run of the preset you name, run unchanged:

```toml
[[inbox.watch]]
path = "/srv/drop/default"
preset = "standard"
```

Files that are still growing, links, devices and files of other users are never taken, and a file
the intake rejects moves to `rejected/` with a `.reason` file. `auto watch list` shows each
folder's state, and `auto watch scan` scans every folder now (it needs the daemon). The rules and
keys are in [Watch folders](auto-mode.md#watch-folders) and [service
configuration](service-config.md#watch-folders).

### Retention and deleting

The daemon cleans up after itself once an hour: a recording is deleted 14 days after its run
ended, the oldest recordings go first above 200 GiB, a run's record and artifacts go after 90
days, staged uploads after 24 hours and rejected inbox files after 7 days (`[retention]` in
`service.toml`). It never touches a run that has not ended, a recording that is being read or
written, the sample library or the custody chain.

```sh
antinomie-cli auto gc --dry-run
antinomie-cli auto gc
antinomie-cli auto delete RUN
antinomie-cli auto delete RUN --with-recording
```

`auto gc` applies retention now and prints what was deleted and what was skipped and why;
`--dry-run` deletes nothing. A plain `auto delete RUN` removes the run's record, events and
artifacts and **keeps the recording** (and the sample stays in the library).
`--with-recording` also deletes the run's recording, and the recording of each earlier attempt
that launched, and the run's static analyses (`<data>/analyses/<id>`, 5 to 18 MB a run). A
recording a client is reading, or that is still being written, is refused.

A plain `auto delete` says what it kept: a `kept recording PATH (SIZE)` line and a `kept analysis
PATH (SIZE)` line for each folder (in JSON, `.result.kept[]` with `what`, `path` and `bytes`;
`.result.removed[]` lists what `--with-recording` removed). The analyses of a run whose record is
gone are removed by the next `auto gc` (the hourly pass of the daemon too) and listed in its output
as `analysis` rows; `auto gc --dry-run` shows them first. Only the analyses an Auto run made
(marked with the run's id) are touched; an analysis from the window or `auto analyze`, and the
analyses of runs made before 0.9.1, stay.

## Scripting recipes

The recipes use `jq`. A script gets JSON on standard output by default, and the exit code
tells it what happened. Quote every variable. These recipes need a daemon running on the
data folder (`auto daemon`), so `auto submit` queues a run instead of running it.

### Submit a folder and wait for all

```sh
#!/bin/sh
# Queue every file of ./samples and wait for all the runs.
set -eu
ids=""
for f in ./samples/*; do
  id=$(antinomie-cli --daemon auto submit "$f" -o json | jq -r '.result.run.id')
  ids="$ids $id"
done
status=0
# shellcheck disable=SC2086
antinomie-cli auto wait $ids --verdict-exit || status=$?
echo "worst exit code: $status"
exit "$status"
```

`auto wait` exits with the worst code of the runs (see [Exit codes](#exit-codes)). Under `set -e` a non-zero code would
stop the script at once, so the recipe keeps it in `status`.

### Collect JSON reports into a folder

```sh
#!/bin/sh
# Copy the JSON report of every run of the last 24 hours into ./reports.
set -eu
mkdir -p reports
antinomie-cli auto list --since 24h --limit 200 -o json \
  | jq -r '.result.items[] | select(.state == "succeeded" or .state == "partial") | .id' \
  | while read -r id; do
      antinomie-cli auto fetch "$id" json --out "reports/$id.json"
    done
```

### Fail a CI job on a malicious label

```sh
#!/bin/sh
# Exit non-zero when the sample is suspicious or malicious.
antinomie-cli --data-dir "$HOME/auto" auto submit "$1" --verdict-exit --out ./report
status=$?
case "$status" in
  0)  echo "clean_observed" ;;
  30) echo "suspicious: see ./report"; exit 1 ;;
  31) echo "malicious: see ./report"; exit 1 ;;
  32) echo "inconclusive: look at the report"; exit 1 ;;
  *)  echo "the run did not finish well (exit $status)"; exit "$status" ;;
esac
```

The run's state comes first: a partial or failed run exits 11 or 10 whatever its label.

### Read a run's events as NDJSON

```sh
antinomie-cli auto events "$RUN" --follow -o ndjson \
  | jq -c 'select(.type != null) | {seq, type, stage: .data.stage}'
```

Every line is one event with `seq`, `ts_ms`, `type` and `data`. With `--follow` the stream ends when
the run ends. A list command prints its items and then a last line `{"result":{"count":N,...}}`, which
the filter `select(.type != null)` leaves out.

### Triage several runs and print the assessment and families

```sh
for run in "$@"; do
  antinomie-cli triage "$run" -o json \
    | jq -r --arg run "$run" '[$run, .result.summary.assessment, (.result.summary.families | join(","))] | @tsv'
done
```

`triage` prints the recording's assessment (`matched_indicators`, `suspicious_behaviour`,
`observed_only`, `no_findings` or `inconclusive`) and its families. The label of an Auto run is in
`auto result RUN -o json` as `.result.run.assessment.label`.

### Where the run is in the answer

The commands do not wrap a run alike, so a script reads the run's id and state at different paths:

| Command | The run is at |
|---|---|
| `auto submit` | `.result.run` (beside `.result.replayed` and `.result.reports`) |
| `auto result` | `.result.run` (beside `.result.files`) |
| `auto status RUN` | `.result` itself (`.result.state`, `.result.id`) |

The shapes stay as they are in 0.9.1; 0.9.2 may make them alike.

## Exit codes

| Code | Name | Meaning |
|---|---|---|
| 0 | ok | Success |
| 1 | failed | Other failure, and a check that found damage: `sample verify` or `custody verify` that does not verify, `detect` with an engine that failed |
| 2 | usage | Bad arguments |
| 3 | not_found | Sample, run, VM, base or run does not exist |
| 4 | invalid | The arguments were refused (`invalid_argument`, `precondition_failed`, `conflict`, `payload_too_large`) |
| 5 | denied | `permission_denied` (a permission, or a file permission), `preset_denied`, `limit_exceeded`, `unavailable_on_node` |
| 10 | run_failed | A waited run (or `run exec`) failed |
| 11 | run_partial | A waited run (or `run exec`) ended partial |
| 12, 13 | run_cancelled, run_rejected | A waited run was cancelled, or a submitted run was rejected |
| 14 | wait_timeout | A wait ran out: the engine did not answer in time, or `--timeout` passed (the run is still queued or running; `run exec` stops the VM) |
| 20 | dependency | A required tool is missing; `doctor` shows which |
| 21 | busy | The data directory is owned by another process, or the daemon is starting or stopping; also `unavailable` (retryable), such as a failed download |
| 22 | quota | `quota_exceeded` |
| 30 to 32 | suspicious, malicious, inconclusive | With `--verdict-exit` only: the waited run succeeded and its label is `suspicious` (30), `malicious` (31) or `inconclusive` (32). The run's state comes first: a partial or failed run exits 11 or 10 whatever its label |
| 130 | interrupted | Interrupted with Ctrl-C |

## Integrity and custody

Every sample in the library has a custody chain: a log of what was done with it, each entry
linked to the one before. These commands check it. They take no engine lock.

```sh
antinomie-cli sample verify
antinomie-cli sample verify SHA256
antinomie-cli custody verify
antinomie-cli custody verify SHA256 --export ./custody.json
antinomie-cli custody verify SHA256 --export ./custody.html --sign minisign --key ~/keys/lab.key
```

- `sample verify [SHA256]` checks that each archive still matches its hash. It exits 1 when one
  does not.
- `custody verify [SHA256]` checks the custody chain of one sample, or every chain and the library
  index when no SHA-256 is given. It exits 1 when something does not verify.
- `--export PATH` writes the custody record of the sample: JSON with `verify-custody.py` beside it,
  or a readable page for a path that ends in `.html`. `--sign minisign|ssh --key KEY` signs it with
  your own key; Antinomie never reads the key, it asks `minisign` or `ssh-keygen` to sign.
- `sample remove SHA256 --yes` deletes the archive; the record and its custody log stay.
- The evidence bundle of `report --evidence-bundle` holds the sample's custody export and a SHA-256
  manifest of its files.

## Troubleshooting

**Exit 21: "data folder is in use".** One process owns a data folder at a time, and the message names
it. If the window is open, close it, or give the command a folder of its own with `--data-dir`. If it
is a daemon, use the `auto` commands, which talk to it, or stop it. Reads of the library and the
recordings (`recording`, `triage`, `report`, `sample`, `custody verify`) work beside the owner. A
record whose process is gone is ignored. Exit 21 also means a download failed and can be retried, or
the daemon is starting or stopping.

**Exit 5: the catalog is off.** `base list --remote`, `base download` and `ioc datasets update` need the
switch. Run `antinomie-cli config set outbound_catalog true`. ThreatFox and the URLhaus datasets also need
the abuse.ch key (`config api-key set abusech < key.txt`); without it nothing is downloaded and exit 5 names
them. The key-free datasets can still be named. `rules catalog`, `rules install` and `tools install` need no
switch.

**No KVM.** A missing KVM is a warning in `doctor`, and VMs then run with TCG, slowly: add yourself to the
`kvm` group, or enable virtualisation in the firmware, to get KVM back. `--tcg` forces software emulation.
Under TCG every start wait is longer; raise it with `--boot-wait` (5 to 600 seconds) and `--tcg-multiplier`
(1 to 100, default 10). `doctor --require kvm` exits 20 on a host that must have it. A daemon whose
`service.toml` has `[resources] require_kvm = true` (the default) keeps its runs waiting until `/dev/kvm` is
usable; set it to `false` to run with TCG.

**A preset is refused.** `preset_denied` (exit 5) means the name is not a preset the node knows: check `auto
preset list`. `permission_denied` lists every missing permission in `details.needs`; `unavailable_on_node`
means the node cannot do it (a live route is not set up in this version); `limit_exceeded` means a value is
above a limit. `invalid_argument` or `unsupported` (exit 4) is a value out of range or a reserved key. Run
`config validate` to see problems in your own presets with their `file:line:column`.

**A route is not set up.** `run exec --route` works on a VM whose network is `routed` only:
make the VM with `vm create NAME --network routed`. `auto submit --route` takes `drop` or `inet_sim` in
this version. `tor`, `vpn` and `socks5` need their own setup (see [Network routes](usage.md#network-routes)).

**The disk is full.** The daemon pauses the queue (`low_disk`), stops the running program within a minute and
ends the run `partial`; a run whose recording could not be finished ends `recording_failed`. Free space under
the data folder and the pause lifts by itself. `antinomie-cli auto gc --dry-run` shows what retention would
delete and `auto gc` deletes it; `auto delete RUN --with-recording` removes one run's recording; `vm delete ID
--yes` and `base delete ID --yes` free a VM or a base; `snapshot delete` frees a snapshot. A failed download
leaves the previous copy in place. Check `df` of the data folder first. See [Auto mode troubleshooting](auto-mode.md#troubleshooting).

**A destructive command exits 4.** `base delete`, `vm reset`, `vm delete`, `snapshot restore`, `snapshot
delete` and `sample remove` refuse without `--yes`.

**A command waited too long.** Exit 14 means `--timeout` passed, or the engine did not answer in time; the
run is still queued or running (`run exec` stops the VM). Look with `auto status RUN`.

The [Auto mode](auto-mode.md#troubleshooting) page has the failure codes of runs and more fixes.

## Where next

- [Auto mode](auto-mode.md): the pipeline, presets, retention and failure codes.
- [Service configuration](service-config.md): `service.toml` and the preset files, key by key.
- [Run API, version 1](run-api-1.md): the wire contract, for programs that talk to the daemon.
- [Family profiles](family-profiles.md): a family named by your own files, in Triage and the reports.
- [User guide](usage.md): the window, and the tools the CLI shares with it.
- [Command reference](cli-reference.md): every command and option.

## Command notes

This is the list of commands in this build, with the finer points of each: the lock a command takes, what
it writes, its limits and how it behaves with a daemon. `antinomie-cli --help` shows the same commands.

**Commands in this build.** This list is what `antinomie-cli --help` shows; the
`auto` commands are in [Auto mode commands in detail](#auto-mode-commands-in-detail) below, and the walk-through from
install to a daemon is [First setup](#first-setup). The web layer is not shipped yet.

- `doctor [--require tool,...]` lists the runtime tools and exits 20 when a
  required one is missing. Without `--require` the tools the window also treats as
  required count; a missing KVM is a warning (VMs then run with TCG). Tool names:
  `qemu`, `qemu-img`, `gtk`, `kvm`, `curl`, `debian-account`, `bubblewrap`,
  `tshark`, `prlimit`, `suricata`, `python-venv`, `wireshark`, `binwalk`, `file-chooser`.
  The `open-files` row is the open-file limit a daemon or a command started now
  gets (the command line raises its soft limit to the hard one, at most 65,536): a
  warning, never a missing tool, when it stays below 4,096 (`soft_limit`,
  `hard_limit`); raise the hard limit (`ulimit -Hn`, `LimitNOFILE=` in a unit).
- `capabilities` prints the API version, the app version and revision, the lane
  count, the report formats and the accelerator (`kvm` or `tcg`). When a daemon
  answers, it prints the daemon's whole answer instead: also the accepted types and
  architectures, the routes, the static checks, the detection engines, the IOC
  datasets, the queries and the run API `features` it serves. Without a daemon
  `features` is empty: no run API is served.
- `doctor` also reports who owns the data directory (`data_dir.owner`, from
  `run/owner.json`, ignored when its process is gone). A command that needs the
  engine while the window owns the directory exits 21 and names the window.
- **Bases.** `base list` lists the installed bases (`--remote` fetches and lists the
  catalog's; needs `config set outbound_catalog true`, exit 5 otherwise). The remote
  list puts this app's bases first and shows each one's architecture, guest contract
  revision and what it is for, as the window's base list does: `for Antinomie 0.9.0`,
  `for Antinomie 0.8.0, outdated` or `needs Antinomie … or newer`. The JSON adds
  `arch`, `min_app_version`, `built_with` and `status` (`current`, `outdated`,
  `needs_newer_app`, `legacy`). `base install
  DIR` installs a boot-bundle folder. `base download ID [--wait]` fetches one from the
  catalog and `base build [--profile busybox|busybox-extra|debian-minimal|debian-xfce] [--engine
  automatic|native|podman|docker|qemu] [--name N]` builds one here; both wait for the
  end in direct mode, because leaving would cancel them. `base delete ID --yes` removes a
  base no VM uses. A base is named by its identity, the start of it (4 characters or
  more) or its label.
- **VMs.** `vm list`, `vm status ID` (state, boot, guest kernel, snapshots, a pending
  disk layer), `vm create NAME [--base ID] [--cpus N] [--ram-mib N] [--disk-gib N]
  [--network disconnected|isolated|routed|nat] [--stealth realistic-desktop|
  realistic-laptop|realistic-server|iot|transparent] [--user NAME] [--password-stdin]`,
  `vm start ID [--wait] [--hold [SECONDS]]`, `vm stop ID`, `vm reset ID --yes`,
  `vm duplicate ID NAME` and `vm delete ID --yes`. A VM is named by its identity or
  its name. The defaults are the window's (4 CPUs, 2048 MiB, 8 GiB, disconnected,
  realistic desktop). `iot` is the IoT device (Raspberry Pi), which only an arm64 VM
  presents: on an x86-64 base the VM keeps it but starts as Normal QEMU, and `vm create`
  says so in a `note`. An arm64 VM gets no uptime from its preset. A Debian base needs a guest account: give the password as one
  line on standard input with `--password-stdin` (never on the command line); a base
  with no account refuses the flag. `vm reset` is refused for a VM that has snapshots
  (duplicate it first). Every destructive command (`base delete`, `vm reset`, `vm
  delete`, `snapshot restore`, `snapshot delete`) refuses without `--yes` and exits 4.
- **Snapshots.** `snapshot list VM`, `snapshot create VM NAME [--mode disk|full]
  [--description TEXT]`, `snapshot restore VM ID [--cold-boot] --yes` and `snapshot
  delete VM ID --yes`. A Disk snapshot keeps the stopped VM's disk; a Full one also keeps
  the memory of the running guest. A snapshot is named by its identity or its name.
- **Run a program.** `run exec SAMPLE` uploads one library sample into a VM, runs it, and
  waits until the recording is complete and settled. `SAMPLE` is a SHA-256 from `sample
  list`, or a file, which is added to the library first. The low-level form of what an
  Auto run does: no revert, no triage, no report. Flags: `--vm ID` (optional when there is
  one VM), `--start` (boot a stopped VM; without it a stopped VM is refused), `--args A B
  ...` (or after `--`), `--env K=V`, `--as user|root|UID:GID` (`user` is UID 1000),
  `--route drop|internet|inet_sim|tor|vpn|socks5` (a routed VM only), `--timeout-run
  SECONDS` (default 300: the run is then told to stop), `--net-capture`, `--memory-dump`,
  `--core-dump`, `--screenshot-every SECONDS` (a picture of the VM screen every SECONDS, 1 to 999, and one when the tree ends; see *Timed screenshots* in the [user guide](usage.md); the headless engine keeps QEMU's VNC display on a private socket for it), `--screenshot-max-pictures N` and `--screenshot-max-mib MIB` (the series' limits, 10 to 5,000 pictures and 16 to 4,096 MiB; 500 and 256 MiB by default), `--dump-trigger low|medium|high` (take a dump when the live Triage rules match at that tier or above, as the window's **Dump when suspicious activity is seen**; default off) with `--dump-kind core|memory|both` (default `core`; a core needs a revision-16 base), `--core-nonresident` (the trigger's cores also read pages that are not in memory, as **Read non-resident pages**; needs a core trigger and a revision-22 base), `--static CHECKS` (the guest-side analysis too), `--load-into PROGRAM` (the sample is a shared library: it is uploaded, then the guest program PROGRAM, an absolute path, runs with `LD_PRELOAD` set to it, and the run is linked to the library sample) and `--wait` (always on in
  direct mode). The program runs in the app terminal as `/tmp/<sha8>-<name>`; the end of
  its output is in the result. The wait covers the evidence the way the window's runs do
  (network capture, memory dump and core finished, up to 300 s), then stops the VM and
  waits until the recording is final: the stop is saved and the disk layer is gone. A
  `--static` analysis that is still running when the 300 s end does not fail the run: the
  recording is saved without it, the outcome stays `succeeded` and the result lists
  `pending: ["analysis"]` (an Auto run has `run.pending`); any other evidence still
  pending at 300 s is `recording_failed`.
  The result says `outcome`: `succeeded` (exit 0), `partial` (exit 11: a piece of evidence
  finished incomplete), or `failed` (exit 10, with `failure.code` such as `no_vm`,
  `upload_failed`, `launch_failed`, `guest_lost`, `recording_failed`, `internal`). It also
  gives the run (state, exit status, why it ended: `exited` or `run_limit`; for a launch the
  guest refused, `failure.run_id` and `run.id` name its "Failed to start" record (always kept), and `failure.detail` the explanation), the evidence
  states and paths, the time per stage and the output. The launch carries the library's copy of the sample as its host copy (read only; a private file removed when the run ends), so a program the guest refuses still gets static analysis. With `--dump-trigger` it also has a
  `triggers` object: what was armed (`tier`, `memory`, `core`), `fired`, each match (`rule`,
  `tier`, `pid`, `syscall`, and the `core` and `memory` dump with `state`, `size` and `path`),
  the counts of matches missed, skipped over the budget or lost, and `notes` (the run is
  noted "armed, but no rule of that tier matched" when nothing fired). `--events` prints the progress as it
  happens, one event of the run API per line (`run.stage`, `run.progress`, `run.program`,
  `run.warning`, `run.trigger`, `run.finished`; `run_id` is null, `seq` counts from 1), then the result;
  it implies `-o ndjson`. `--timeout SECONDS` limits the whole command (exit 14).
  While the guest finishes mounting its disk the upload is tried again once a second, and
  `run.progress` says so at most every five seconds, with the count of tries.
  **Under TCG** (every arm64 VM on an x86-64 host) the upload, launch and guest-answer
  waits, and the minute after which an unanswered guest command is `internal`, are
  stretched by the same factor as the engine's own waits: the TCG multiplier times the host
  load factor. The time the engine reports waiting for a Debian guest to finish booting
  does not count as silence. The `Start` of the VM is the same: its 180 s is a limit on
  silence, and under TCG the time the engine reports waiting for the guest to connect does
  not count against it (at most 30 minutes in all); under KVM it is 180 s as before.
  If the engine still answers a launch after the run gave up
  on it, the VM is stopped (which ends the program), the result names that run and a
  `late_launch` warning says what happened.
- **Run digests.** `digest RUN` builds the Triage digest of one finished run, and
  `digest --pending` builds it for every finished run that has none (or whose digest
  was made while its recording was still being written and has changed since), one at
  a time. It is the same build the window and Auto mode run on their own; use it for
  runs older than a week, which the window leaves alone, or after an interruption
  (nothing is written until the digest is whole, so running it again is safe). `--max-calls`
  (default 400000) and `--max-seconds` (default 1200) are the budget of one build. It
  writes the digest into the run's folder, so it takes the engine lock (exit 21 while a
  window or daemon owns the data directory); the result lists each run as `built`,
  `built_partial` (with the reasons), `current` (nothing to do), `busy` (another build
  of the run holds it) or `unreadable`.
- **Triage, detection and reports of a saved run.** `triage RUN [--parts LIST]`,
  `detect RUN [--engine yara,sigma,ids] [--out DIR] [--save]` and `report RUN
  [--formats html,pdf,json,misp,stix,md] [--parts LIST] [--evidence-bundle] [--defang |
  --no-defang] [--include-content] [--out DIR]` read a saved run with no window.
  `RUN` is the run's id or its first characters (4 or more), `vm:boot:run`, a run
  key, or the run's folder; every VM of the data directory is searched. Each command
  indexes the whole run the way Triage does when the run is selected, with the
  data directory's `settings.json` (the window's defaults when there is none) and
  with `dig` and `whois` lookups off (TShark's installed GeoIP fields stay); the
  progress goes to standard error and Ctrl-C stops it (exit 130).
  `triage` prints Triage's Summary as the query API serves it
  (`recording.summary`): the assessment and its basis, the counts, the
  families, the techniques, the key behaviours and the detections, and it writes
  nothing into the recording; `--parts` adds report parts to the result (`summary`, `indicators`, `attack`,
  `processes`, `findings`, `files`, `file_activity`, `network`, `detections`,
  `evidence`, `custody`, `static_analysis`, or `all`). `report` writes the files the window's
  **Export report** writes for the same run and choices (see
  [Triage report export](triage-report.md)); formats and parts default to the
  export choices in `settings.json` (HTML and PDF, every part, defanged), and the
  files go to `--out` (default `report-<first 8 characters of the run id>` in the
  current folder), never into the recording. A run an Auto job made already has
  its whole report (the job's `report-<sha8>.json`): when that report is current
  (the same app and schema, and the recording, its digest and its detection scans
  have not changed since), `report` writes the chosen formats and parts from it
  and does not read the recording again, and the result names it in
  `from_report`; with `--evidence-bundle` or `--include-content`, or when the
  report is missing or stale, the run is indexed as before and standard error
  says why. A recording over 1 GB that has to be read is warned about on standard error first (and the JSON result carries `large_recording` with its size and the estimated seconds). The
  `static_analysis` part (in `all`) is the sample's static analysis: one row per
  check (identification, packing and unpacking, strings, entropy, static YARA,
  capa, ...) with its state, summary and tools, then each check's first 100 rows;
  STIX gets it as a `malware-analysis` of the file and a `note`, MISP as one
  comment per check. `detect` runs the engines over the
  run's evidence as the Detection tab does: the same evidence check, the same frozen
  rule selection and the same sandbox. YARA needs the static analysis of the run's
  sample (`run exec --static`), IDS a capture (`run exec --net-capture`), Sigma the
  event journal the index writes; an engine without its evidence is listed as not
  scanned, with the reason. Without `--save` nothing is written into the recording:
  the matches are printed and `--out DIR` writes each engine's full result as
  `detection-<engine>.json`. `--save` keeps the results where the Detection tab keeps
  them and adds them to the run's digest, so a later `report` lists them; it takes
  the engine lock (exit 21 while the window owns the data directory). `detect` exits
  1 when an engine failed. Apart from `detect --save`, these commands take no lock.
  `report`, `detect` and `triage --parts` write nothing into the recording but the
  index Triage keeps there (its event and finding journals), as the window does
  when it shows the run; `triage` without `--parts` writes nothing.
  The files and network rows are the window's: a socket read or write names its peer (`socket → 189.53.235.111:8080 (tcp)`), a pipe or another descriptor its kind, and socket I/O is network traffic, not a file change, so it is listed under Other and not counted as read or written.
- **Look at recordings.** A recording is what the engine captured while a program
  ran (`run exec` makes one, and so does every run of Auto mode). `recording list
  [--vm ID] [--sample SHA256] [--run ID] [--state STATE] [--since SPAN] [--limit N]
  [--cursor C]` lists the recordings of the data directory, newest first (`--since` takes a span such as `90m`, `24h` or `7d`, or a
  Unix time in milliseconds). A run held open for a persisted copy (see *Copies of
  the program outside the recorded tree*) shows `held` in the STATE column, and its
  JSON item has `held` ("Held: persisted copy running (pid 1050, .e)") beside
  `state`, which still says how its tree ended. `recording show RUN [--summary]` shows one recording: its state,
  whether its recording is `live`, `finalizing`, `complete` or `interrupted`, its
  evidence and `generation`; `--summary` adds the Triage summary. `recording export RUN --out
  DIR [--part LIST] [--sensitive]` writes the parts `trace`, `processes`,
  `findings`, `indicators`, `files`, `network`, `timeline`, `analysis`, `custody`
  and `artifacts` (default: all) as `*.ndjson` files, one row per line (a `trace` row's `nr` is the number the guest used for the call; `args_preview` holds the engine's raw argument previews, and the decoded records are in the Syscall Trace's own JSON export), and the
  retained evidence files of `artifacts` into `DIR` and nowhere else; the bytes the
  sample produced are written only with `--sensitive`: the capture, memory and core
  files and file copies (`artifacts/`), the contents of changed files (`files/`), the
  captured bytes of calls (`captured/`, named by `captured.ndjson`) and the frames of
  the recorded packets (`network-packets-<capture>.ndjson`, one `{n, frame_len,
  bytes_b64}` line per packet). The frames are capped at 100 000 packets and the
  captured bytes at 10 000 fields and 256 MiB per export; a file list entry says
  `truncated` when a cap was reached. With a daemon each of these reads is written to
  its service log; `--no-triage` leaves out the
  parts that need the Triage index (findings, indicators, files, network, timeline), so
  a very large recording is not indexed in full. `RUN` is as for `triage`.
  These commands are the read-only query API of the run API (`docs/run-api-1.md`,
  "Recording queries"): they take no engine lock and write nothing into a recording,
  so they work while the window is open. A recording that is still being written
  (`live`) can be listed, shown and exported in its core parts, but its Triage parts
  (summary, findings, indicators, files, network, timeline) are refused with exit 4
  until it is saved. The first Triage part of a run indexes it, with progress lines
  on standard error; Ctrl-C stops (exit 130) and `--timeout SECONDS` limits the wait
  (exit 14).
  **With a daemon** (`auto daemon`) at the socket these commands, `triage`, `sample
  list|show|tag`, `custody verify` (without `--export`), `vm list` and `base list`
  ask the daemon and print the same objects; `--direct` keeps them in the command and
  `--daemon` insists on the daemon. Every read of `recording export` has its own deadline (10 s
  light, 60 s heavy, per page), never one for the whole export; a read that passes it is
  asked again twice before the export stops, with exit 21 and `details.part`, `details.op`
  and `details.parts_done` naming where, and the files already written stay in `--out`.
  `recording export` still writes only under `--out`: the
  command asks the daemon for the rows and the bytes and writes the files itself, so no
  path is sent to the daemon. `triage --parts` builds its report parts in the command
  from the recording folder (no lock is needed). `vm list` and `base list` from the
  daemon print the contract's summaries (id, name, base, lane; identity, name,
  architecture), fewer columns than direct mode, which needs the lock and so cannot
  run beside a daemon. `recording list` shows in `from_run` the Auto-mode run that made a
  recording, and `--run` finds its recordings, both through the daemon and in
  direct mode (the command reads the run store without writing). With a daemon `sample add FILE`
  uploads the file and adds it as the socket's caller (`local:<uid>`);
  `--delete-original` then removes the file after the daemon reported the same
  SHA-256. `sample verify`, `sample remove` and `custody verify --export` work in the
  command: they read or write files by path.
- **A VM lives as long as the command.** In direct mode the engine runs inside the
  command and stops the VM when the command ends, so `vm start` boots the guest, waits
  until it answers, reports how long that took and stops it again; `--hold` keeps it
  up for that many seconds, or until Ctrl-C (exit 130) when no number is given. `vm
  stop` stops a VM this process started, and says so when there is none. `snapshot
  create --mode full` boots the VM first, and `snapshot restore` shows the restored
  guest answering and stops it. None of them stops or saves the guest before it has
  finished booting: the guest answers from its initramfs already, which may still be
  growing the root file system to the VM's disk, and a VM stopped or saved then keeps
  a half-grown file system that crashes the guest kernel at its next boot. The wait is
  the boot wait (`--boot-wait`, stretched under TCG); a guest that does not finish
  booting in it fails the command. Keeping a VM up between commands is what the daemon
  (the daemon, `auto daemon`; see [Auto mode commands in detail](#auto-mode-commands-in-detail)) is for. Progress lines go to standard error, Ctrl-C
  stops the VM cleanly, and `--timeout SECONDS` limits the waits (exit 14).
- `sample add FILE... [--name N] [--tag K=V] [--delete-original]` hashes and archives
  files in the library (never runs them) and prints the SHA-256 of each; a tag is
  `verdict=`, `category=`, `technique=` or `custom=` plus a value, or a bare custom
  value. `sample list [--q TEXT] [--tag K=V] [--limit N] [--cursor C] [--all]
  [--custody]`, `sample show SHA256 [--origins] [--events] [--runs]`,
  `sample tag SHA256 TAG... [--remove]`, `sample verify [SHA256]` (exit 1 when an
  archive does not match its hash) and `sample remove SHA256 --yes` (deletes the
  archive; the record and its custody log stay). A sample is the `Sample` object
  of the run API: `sha256`, `size`, `type`, `architecture`, `name`, `tags`,
  `first_seen_ms`, `run_count`, `last_run`, `custody_ok` (null unless
  `--custody` or `show`). `run_count` and the `--runs` list count every run in the
  recordings of all VMs that executed the sample or loaded it as a preloaded
  library, whether or not the window ever opened them. These commands and `custody verify` need no engine
  lock, so they work while the window is open.
- `custody verify [SHA256] [--export PATH] [--sign minisign|ssh --key KEY]` checks
  the custody chain of one sample, or every chain and the library index when no
  SHA-256 is given (exit 1 when something does not verify). `--export` writes the
  custody record of the sample (JSON with `verify-custody.py` beside it, or a
  readable page for a `.html` path), optionally signed with your own key.
- `analyze FILE [--checks LIST] [--time-limit-min N] [--out DIR]` adds the file to the
  sample library, runs the static analysis of that copy on the host, with no VM, and
  prints a summary of each check. It starts the engine itself (so it needs the data
  directory to be free: exit 21 names the owner) and needs bubblewrap. The report folder
  is `<data>/analyses/<report id>`; `--out` also copies it, and the folders of any
  unpacked layers, into `DIR`. `--checks` takes the names metadata, structures,
  strings, regex, entropy, hardening, rules, identification, capabilities,
  disassembly, decompilation, embedded, floss, unpacking; the default is the
  triage set.
- `rules list [--engine yara|sigma|ids]` lists the installed rule packs and
  custom groups with their state; `rules enable ID` and `rules disable ID` switch
  one (`pack:ID` or `group:ID` when an id names both). Changing the selection
  takes the data-directory lock; listing does not.
- **Rule packs from the catalog.** `rules catalog` checks the rules catalog and
  lists its packs (`id`, engine, the catalog's version, the installed one).
  `rules install ID...` downloads, checks, filters and indexes catalog packs with
  their default options, through the same code as **Tools > Detection rules**
  (for example `rules install yara-forge-core`); the registry changes only once a
  pack is complete, so a failed install keeps what was there. `rules update
  [ID...]` installs the catalog's newer version of the installed packs (only the
  named ones when ids are given) with the options they were installed with.
  Running the command is the consent to download; Ctrl-C stops it. No engine lock:
  a daemon may run meanwhile, and its next scan uses the new selection.
- **Analysis tools.** `tools list` lists the optional static-analysis tools (capa,
  FLOSS, Ghidra, Detect It Easy, UPX, Volatility 3, Sigma, Magika, ...): the
  version this app pins, the version Antinomie installed and a system copy, which
  takes precedence. `tools install ID...` downloads, checks (SHA-256) and unpacks
  them into `<data>/tools/<id>/` exactly as **Tools > Analysis tools** does, and
  resumes a cut download (`tools install capa floss ghidra die`). `tools update
  [ID...]` installs again each tool Antinomie installed at another version than
  the pinned one. No engine lock: each static analysis looks its tools up when it
  starts, so a daemon's next run uses a tool installed now. The network routes'
  programs (Tor, wireproxy) are set up with the routes, not here.
- `ioc datasets list` lists the abuse.ch IOC datasets (ThreatFox, URLhaus dump,
  URLhaus payloads, Feodo Tracker, SSLBL JA3, SSLBL certificates, URLhaus recent):
  `name`, `state` (`loaded`, `old` past 14 days, `not_downloaded`, `failed`,
  `update_failed`, `off`), `records`, `fetched` date, `needs_key`, the source and
  the stored `file`; the human form also says whether the abuse.ch key is stored.
  `ioc datasets update [NAME...]` downloads the named datasets, or every one that
  is switched on, with the window's own code (**Tools > Detection rules > IOC**):
  the same sources and checks, the same files in `<data>/ioc/feeds/<name>/`, which
  Triage, the reports and an Auto run's Check online read. It needs `config set
  outbound_catalog true` (**Settings > Detection > Allow outbound catalog and rule
  downloads** in the window; exit 5 otherwise); ThreatFox and the URLhaus datasets
  need the abuse.ch key (`config api-key set abusech`): without it nothing is
  downloaded and exit 5 names them (the key-free datasets can still be named). The
  key goes to `curl` on standard input only and is removed from every message.
  Progress goes to standard error; a failed download keeps the previous copy and
  exits 21 (`unavailable`, retryable) with each dataset's result in
  `details.datasets`; another update in progress (the window or another `ioc
  datasets update`) is exit 21 too; Ctrl-C stops (exit 130). An unknown name is
  exit 3, a dataset that is switched off exit 4. `ioc datasets enable NAME` and
  `disable NAME` switch one on or off (an `off` dataset is not downloaded or used;
  its copy stays). The `ioc` commands take no engine lock, so they run while the
  window or a daemon owns the data directory, from cron or a systemd timer as well
  (Antinomie installs none).
- `config path` prints the paths of `settings.json`, `service.toml` and `presets/`.
  `config get [KEY]` prints one engine setting, or all of them; a dotted key reaches
  into an object (`disks.hide_dotfiles`) and the command takes no lock.
  `config set KEY VALUE` changes one (the value is JSON when it parses, else text) and
  takes the engine lock, so it refuses while the window owns the data directory.
  `settings.json` is the file the window itself now uses for its engine settings,
  including the VM start waits (`start.boot_wait_secs`, `start.tcg_multiplier`,
  `start.network_wait_secs`, `start.guest_connect_secs`, `start.kvm_fallback`), the
  capture quota (`quota_gib`), the VM shutdown timeout (`shutdown_timeout_s`) and the
  caps on earlier file bytes (`file_before_file_mib`, `file_before_run_mib`), which the
  CLI and the daemon start their engine with.
  `config validate [--preset NAME]` checks `service.toml`, the six built-in
  presets and `presets/*.toml` without starting anything (see
  [service configuration](service-config.md)); it prints each problem as
  `file:line:column` and exits 4 when there is an error. A `policies/`
  folder is an error that names the new key of each old one.
  `config api-key set abusech|malshare` reads a key from standard input (its
  first line; never an argument or the environment) and stores it in
  `<data>/api-keys.json` (mode 0600, the file of the window's **Tools > API
  keys**); `config api-key clear SERVICE` forgets it and `config api-key show`
  prints which keys are stored, each as its last four characters. The abuse.ch
  key is the one an Auto run with `[detection] check_online = true` uses (see
  [service configuration](service-config.md#the-abusech-key)).
- Watch folders (`auto watch`), retention (`auto gc`), result files (`[results]`) and
  the finish hook (`[notify] on_finish`) ship in 0.9.1 and are described under
  [Auto mode commands in detail](#auto-mode-commands-in-detail). Webhooks are not part of this version. The run contract is
  written down in [Run API, version 1](run-api-1.md).


## Auto mode commands in detail

Auto mode runs samples unattended: a sample goes in, it runs in a VM that is
reset to a clean snapshot first, the recording is analysed, and a report and a
label come out. Give it a data folder of its own (`--data-dir`), never the one
the window uses: one process owns a data folder at a time, and the daemon keeps
it for as long as it runs.

The pipeline, presets, retention, failure codes and troubleshooting are in
[Auto mode](auto-mode.md); this section lists the commands.

**Pipelining.** The VM is free as soon as a run's recording is collected: the
next run starts in the VM while the previous run's host work (each static tool,
the Triage scan, detection, the label and the report) runs in the host work
pool, at most `[daemon] host_workers` items at once (2), first come, first
served by run arrival. Each item may take twice its expected time
(`[daemon] host_time_factor`); `auto status <run>` lists the items with their
state, expected time and limit, and `auto status` the pool's queue
([Auto mode](auto-mode.md#the-host-work-pool)).

**The daemon.** `antinomie-cli --data-dir ~/auto auto daemon` runs in the
foreground until it is stopped; put it in the background with your service
manager or `&`. It owns the data folder (`run/owner.json` says "daemon" and names
its socket), so the window, another daemon or a command that needs the engine on
that folder is refused with exit 21 and told who owns it. It reads
`service.toml` and `presets/` (see [service configuration](service-config.md)),
finishes what a crash left behind, runs the queue one run at a time on its lane,
and serves the run API on `<data>/run/antinomie.sock`.

| Signal | What the daemon does |
|---|---|
| `SIGTERM` or Ctrl-C | Stops taking runs (queued runs stay queued). A run that is past its VM stages finishes its analysis and report first, for up to 120 s (`[daemon] shutdown_host_grace_s`). A run still in the VM is stopped and put back in the queue without using an attempt |
| a second one within 5 s | Stops at once, VM included (exit 130); the next start finishes the rest |
| `SIGHUP` | Reads `presets/` and `service.toml` again; a file with an error keeps the old settings. Runs already queued keep the preset they were submitted with |
| `SIGUSR1` | Writes the queue's state to the log |

**Setting up the lane.** A lane is one VM kept for automation, with a clean
snapshot that every run starts from.

```text
antinomie-cli --data-dir ~/auto base install ./bases/busybox
antinomie-cli --data-dir ~/auto auto init --base busybox --cpus 2 --ram-mib 2048
```

`auto init` creates the lane VM (`--name`, default `auto-1`) on a routed network
(each run chooses where its traffic goes; between runs nothing leaves), boots it
once and waits for the guest to answer and to finish booting (its root file system
mounted, so the initramfs no longer grows it to the lane disk; a Debian guest's
start-up finished), stops it, waits until its disk has settled,
takes the Disk snapshot `auto-clean` (`--snapshot`) and writes
`<data>/service/lanes/lane-1.json`. The lane group is the base's architecture
(`x86_64`, or `arm64` for an arm64 base). With another VM name or snapshot than
`auto-1` and `auto-clean`, or another lane group than `x86_64`, it writes them as
`[lanes] vm`, `revert_to` and `group` of `service.toml`: a new file, or a table
added to a file that has no `[lanes]` table (an operator's `[lanes]` table is left
alone, and the command prints the lines to change). The presets need no file: the
six built-in presets take the node's lane group and accept its architecture, so
on an x86-64 node Standard accepts ELF x86-64 programs and shell scripts, and
after `auto init` on an arm64 base it accepts arm64 programs and shell scripts.
Architectures have one spelling in `service.toml`, the presets, the CLI and the
run API: `x86_64`, `x86`, `arm64`, `arm`, `mips`, `powerpc`, `sparc`, `riscv`,
`superh`, `m68k`, `other`; the older spellings (`AArch64`, `aarch64`, `ARM`,
`x86-64`, `amd64`, ...) are still read. A Debian
base needs a guest account: `--user NAME --password-stdin`, the password on
standard input. A guest kernel that crashes in that first boot (the console shows
a kernel `BUG` or oops, or the guest could not grow its file system) fails `auto
init` without a clean snapshot. `auto init` runs in the calling process, so stop the daemon first;
`--replace` makes a new lane VM for an existing lane (a new base) and keeps the old
VM for you to delete. `auto lane list` shows the lane, whether it is quarantined and
what would keep it from a run; `auto lane reset --yes` reverts the VM to its clean
snapshot now and lifts a quarantine when that works; `auto lane unquarantine` lifts
it without reverting when the checks pass (the clean snapshot is there, the VM is
stopped, nothing is still being saved).

**Several lanes.** `auto init --lane N` (2 to 4) makes another lane: its VM
(`auto-N` by default) lives in `<data>/lanes/N/`, is built on a base of the data
folder and writes `<data>/service/lanes/lane-N.json`. With `[daemon] lanes = N`
in `service.toml` the daemon runs lanes 1 to N, one engine and one VM each, and
starts a lane only when the machine has the memory for every lane VM (the log
and `auto lane list` say why a lane did not start). A run goes to a free lane
whose base and architecture can run it, the least recently used first; every
lane's host work goes to the one host work pool. `auto status` and `capabilities`
show every lane; `auto lane reset` and `unquarantine` take `--lane lane-N`. A recording
stays in its lane's folder, and the read commands given the data folder
(`recording list`, `recording show`, `recording export`, `triage`, `detect`, `report`, `sample show
--runs`) find the runs of every lane, directly and through the daemon. See
[Auto mode](auto-mode.md#several-lanes).

**Submitting and following runs.**

| Command | What it does |
|---|---|
| `auto submit FILE` (or `--sha256 HEX`) | Uploads the file to the daemon and queues a run; prints the run. `--preset` (the preset, default `standard`), `--priority`, `--label K=V`, `--timeout-run S`, `--args ...`, `--env K=V` (replaces the preset's environment), `--as user\|root\|nobody\|UID:GID`, `--route drop\|inet_sim` (a live route is not set up on this node in 0.9.0, whereas `run exec --route` takes all six), `--static none\|triage\|CHECKS`, `--no-static`, `--formats html,pdf,json,misp,stix,md`, `--evidence-bundle`, `--defang`/`--no-defang`, `--screenshot-every S` (a picture of the VM screen every S seconds, 1 to 999, `record.screenshot_every_s`; 0 turns it off), `--idempotency-key K`, `--name`. A flag that changes a preset value makes the run Custom; only your permissions and the node limit what a run may change. `--wait` waits for the end and exits with the run's code; `--follow` also prints the run's events as NDJSON; `--verdict-exit` waits and exits 30, 31 or 32 for a succeeded run labelled suspicious, malicious or inconclusive; `--out DIR` copies the report files there. A rejected run exits 13 |
| `auto status [RUN]` | One run, or the queue and the lanes |
| `auto list` | Runs, newest first: `--state`, `--outcome`, `--sha256`, `--label K[=V]`, `--since 24h`, `--limit`, `--cursor` |
| `auto wait RUN...` | Waits until the runs have ended (`--timeout` bounds it, exit 14) and exits with the worst code; `--verdict-exit` as above |
| `auto events RUN` | The run's stored events; `--since SEQ` starts after an event, `--follow` keeps printing new ones until the run ends, `--types run.stage,run.state` filters. `auto events --all --follow [--since GSEQ]` follows every run and the engine |
| `auto result RUN` | The outcome, the label, its score and basis sentence, and the paths of the report files |
| `auto artifacts RUN`, `auto fetch RUN KIND [--out PATH\|-]` | The run's artifacts; copy one (`html`, `json`, ..., or `report.bundle`) to a file, a folder or standard output |
| `auto cancel RUN [--reason TEXT]` | A queued run is cancelled at once; a running one stops its run and VM and ends `cancelled` (its recording is kept) |
| `auto rerun RUN [--preset NAME] [--override TABLE.KEY=VALUE] [--priority N]` | Run again: a new run from a finished one, with `repeat_of` set: the preset as it is now, or a Custom run's resolved options; `--preset` uses another preset as it is now instead; `--override program.run_time_s=60` changes one option; `--priority` replaces the old run's priority (kept otherwise, lowered to your `priority_max` when above it) |
| `auto queue status\|pause\|resume` | The queue; a paused queue starts no run (running runs finish) |
| `auto preset list`, `auto preset show NAME` | The presets (six built in, and `presets/*.toml`) with the permissions their options need and whether you can run them as they are; `show` prints the preset as a preset file (TOML, its name and digest as comments) that you can save as `presets/<another name>.toml` and edit; JSON with `-o json` |
| `auto delete RUN [--with-recording]` | Removes a finished run: its record, events and artifacts (the sample stays in the library). `--with-recording` also deletes the run's recording, and the run of each earlier attempt that launched, through the run deletion the window uses; a recording a client is reading, or still being written, is refused |
| `auto gc [--dry-run]` | Applies retention now (below) and prints what was deleted and what was skipped and why; `--dry-run` deletes nothing. Works with a daemon, or on its own when none runs |
| `auto watch list` | The watch folders: state, files taken, files rejected, entries refused and why. Without a daemon, the folders `service.toml` names |
| `auto watch scan` | Scans every watch folder now (a file still has to be steady for 3 seconds). Needs the daemon |

Without a daemon, the reading commands read the run store directly (they work
beside the window), `cancel` and `queue pause/resume` take the data folder for a
moment, and **`auto submit` runs the run in the command itself**: it owns the data
folder while the run runs and exits with the run's code, so one command takes an ELF
to a report:

```text
antinomie-cli --data-dir ~/auto auto submit ./sample.elf --verdict-exit --out ./report
echo $?     # 0 clean_observed, 30 suspicious, 31 malicious, 32 inconclusive, 10 failed, 11 partial
```

**Watch folders.** Name a folder in `service.toml` and every file dropped into it
becomes a run:

```toml
[[inbox.watch]]
path = "/srv/drop/default"
preset = "standard"
delete_after = "move"       # processed files go to <data>/inbox/processed/
```

A file is taken about 3 seconds after it stops changing, so a file being copied in
is never read half-way, and names ending `.part`, `.tmp`, `.crdownload` or starting
with `.` are waited for. The daemon opens each file from inside the folder without
following links, and refuses what could lead out of it: a symbolic link, a device or
FIFO, a file with more than one hard link, a file of another user. It uses the
folder only when it is yours and no one else can write to it (a group-writable folder
needs `allow_group_write = true`; a folder anyone can write to is never used).
Refused entries are left alone and listed by `auto watch list`. A file the intake
rejects (wrong type, too large, a duplicate the preset denies) goes to
`<data>/inbox/rejected/` with a `.reason` file and is not tried again. More than
`watch_rate` (10) files a minute pauses the folder for a minute and raises an
`engine.alert` `watch_flood`. `preset_by_dir = true` makes a subfolder named after
a preset use that preset; other subfolders are ignored. The runs carry the label
`watch=<folder name>` and the custody actor `auto:preset-<preset>`. The keys are
in [service configuration](service-config.md#watch-folders).

**Results and the hook.** With `[results] dir` set, each run that ends leaves
`<dir>/<date>/<sha8>-<runid>/` with its `job.json` and its reports, for a program
that polls a folder. With `[notify] on_finish = ["/path/to/hook"]` the daemon runs
that program when a run ends, without a shell and with only `ANTINOMIE_RUN_ID`,
`ANTINOMIE_STATE`, `ANTINOMIE_LABEL`, `ANTINOMIE_SHA256` and
`ANTINOMIE_RESULT_JSON` (the path of `job.json`) in its environment. It has 30
seconds, runs as the daemon's user, and what it prints goes to the run's `job.log`.
A failing hook never fails a run; it raises an `engine.alert` `hook_failed`.

**Retention.** The daemon cleans up after itself once an hour: a recording is
deleted 14 days after its run ended (through the window's own run deletion; a failed
run's is kept until its record goes), the oldest recordings go first above 200 GiB,
a run's record and artifacts go after 90 days, staged uploads after 24 hours and
rejected inbox files after 7 days (`[retention]` in `service.toml`). It never
touches a run that has not ended, a recording that is being read through the API or
written, the sample library or the custody chain. `auto gc --dry-run` shows the
plan first; every deletion is logged with the run and run id.

**The label.** A succeeded run has an assessment: the raw Triage assessment, the
highest tier, a label (`malicious`, `suspicious`, `clean_observed`,
`inconclusive`), an optional score and the `basis` sentence that says why.
`clean_observed` means "nothing seen in this run", not "clean". With `[verdict]
tag_library = true` in a preset, the sample also gets the library tags
`auto:label=<label>` and `auto:preset=<name>`, recorded in its custody chain under
the actor `auto:preset-<name>`.

**Who can talk to the daemon.** Only you. The socket file can be opened only by
its owner (mode 0600, in a folder only you can enter, 0700), and on every
connection the daemon asks the system which user is on the other end and closes
the connection, without a word, unless it is the user the daemon runs as. Every
local client therefore acts as you, with every right. The daemon never opens a
file a client names: a sample travels over the socket in pieces and is checked and
stored by the daemon, and a report path it hands back is checked to be inside the
run's own folder. Each request is checked strictly (an unknown field is an error
that names it), and the socket has limits so a broken or hostile local program
cannot wear the daemon down: 2 MiB per message, 16 requests at a time and 50 a
second per connection, 64 connections, 64 event subscriptions, idle connections
closed after 5 minutes, and a client that stops reading is dropped. Nothing the
daemon does contacts the network on its own; a sample's traffic is dropped unless
its preset chooses the simulated internet (`inet_sim`).

**Event streams.** Every change of a run is an event with a number: `seq` counts
the events of one run, `gseq` counts every event of the daemon and never repeats.
A client that lost its connection asks for the events after the last number it
saw and gets each one exactly once, then the new ones as they happen.

