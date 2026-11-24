<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Generated from the command definitions of antinomie-cli. Do not edit: run
UPDATE_CLI_REFERENCE=1 cargo test --release -p antinomie-cli the_checked_in_cli_reference_is_current -->

# Command reference

Every command of `antinomie-cli`, with its arguments and options. The file is generated from the
program's own command definitions, so it matches the build it comes from; a test fails when it
is stale. For a guide by task, read the [command-line guide](cli.md).

Written for `antinomie-cli 0.9.1`.

## Global options

Global options go before or after the command. They apply to every command.

- `--data-dir <PATH>`: Data directory \[default: $HOME/antinomie\]; `~` is expanded
- `--bundle <PATH>`: Boot bundle folder, for engine commands \[default: $ANTINOMIE_BUNDLE or images\]
- `--socket <PATH>`: Daemon socket \[default: \<data\>/run/antinomie.sock\]
- `--direct`: Run the command in this process, taking the data-directory lock, even when a daemon could serve it
- `--daemon`: Send the command to the running daemon (an `auto` command, a read such as `run list` or `sample list`); fail when none answers
- `-o, --format <FORMAT>`: Output format \[default: human on a terminal, json otherwise\] (values: `human`, `json`, `ndjson`)
- `--color <WHEN>`: Colour in human output; NO_COLOR is honoured (values: `auto`, `always`, `never`; default: `auto`)
- `-q, --quiet`: Only errors on stderr; results still print
- `-v, --verbose`: Raise the log level on stderr (-v debug, -vv trace)
- `--log-format <FORMAT>`: Log line format on stderr \[default: `[log] format` of service.toml for `auto daemon`, else text\]. The flag wins over the file (values: `text`, `json`)
- `--timeout <SECONDS>`: Overall limit for the command
- `--tcg`: Force software emulation (TCG)
- `--boot-wait <SECONDS>`: Seconds a launch waits at KVM speed for a systemd guest (Debian) to finish booting before it starts the program anyway, 5 to 600; stretched by the TCG multiplier under TCG \[default: settings.json `start.boot_wait_secs`, else 60\]
- `--tcg-multiplier <N>`: How many times longer every VM start wait, the boot wait and each guest command may take under TCG software emulation, 1 to 100 \[default: settings.json `start.tcg_multiplier`, else 10\]
- `--qemu <PATH>`: QEMU system emulator \[default: qemu-system-x86_64\]
- `--qemu-img <PATH>`: qemu-img \[default: qemu-img\]
- `--no-headless`: Let QEMU open its window (the CLI default is headless)

## Commands

- `doctor`: Check the machine for the tools the engine needs
- `capabilities`: Print what this build and machine can do
- `config`: Paths and settings of the data directory
- `analyze`: Static analysis of a host file, no VM; takes the engine lock
- `rules`: Rule packs and groups: list, enable, disable; the catalog's packs: catalog, install, update
- `tools`: The optional analysis tools (capa, FLOSS, Ghidra, Detect It Easy, ...): list, install, update, as Tools \> Analysis tools does. No engine lock
- `ioc`: The abuse.ch IOC datasets: `ioc datasets list`, `update [NAME...]`, `enable`, `disable`. The window's files; no engine lock, so a daemon may serve meanwhile. An Auto run's Check online needs them
- `base`: Bases: list, install, download, build, delete; takes the engine lock (`list` asks the daemon when one answers)
- `vm`: VMs: create, start, stop, status, reset, duplicate, delete; takes the engine lock (`list` asks the daemon when one answers)
- `snapshot`: VM snapshots: list, create, restore, delete; takes the engine lock
- `run`: Run a library sample in a VM: `run exec`; takes the engine lock
- `recording`: The recordings of the data directory: list, show, export; no engine lock needed. Each asks the daemon when one answers
- `sample`: Samples in the library; no engine lock needed. `list`, `show` and `tag` ask the daemon when one answers
- `custody`: Custody chains of the samples; no engine lock needed. `verify` asks the daemon when one answers (not with `--export`)
- `triage`: Index a saved run as Triage does and print its summary: the assessment, the counts and the key behaviours. No engine lock needed. Asks the daemon when one answers
- `detect`: Run YARA, Sigma and IDS over a saved run's evidence; no engine lock needed unless --save keeps the results in the recording
- `digest`: Build the Triage digest of a finished run (or of every run that has none, with --pending): a budgeted read, marked partial when the budget ended it or telemetry was lost. Takes the engine lock
- `report`: Write a saved run's report (HTML, PDF, JSON, MISP, STIX, Markdown), the same files the window's Export report writes. No engine lock needed
- `auto`: Auto mode: the daemon, the lanes, runs and their results

### antinomie-cli doctor

Check the machine for the tools the engine needs

```text
Usage: antinomie-cli doctor [OPTIONS]
```

Options:

- `--require <TOOL>`: Tools that must be present, comma separated (see the `tool` column); default: every check the app treats as required

### antinomie-cli capabilities

Print what this build and machine can do

```text
Usage: antinomie-cli capabilities [OPTIONS]
```

### antinomie-cli config

Paths and settings of the data directory

```text
Usage: antinomie-cli config [OPTIONS] <COMMAND>
```

Commands:

- `antinomie-cli config path`: Print the paths of `settings.json`, `service.toml` and `policies/`
- `antinomie-cli config get`: Print one setting, or all of them. A dotted KEY reaches into an object (`disks.hide_dotfiles`). Reads the file; takes no lock
- `antinomie-cli config set`: Change one setting. VALUE is JSON when it parses (`true`, `12`), else text. Takes the engine lock, so it refuses while a window or daemon runs
- `antinomie-cli config validate`: Check `service.toml` and the presets (the six built in and `presets/*.toml`): unknown keys, the node ceilings, the keys this version reserves, live routes, and the lanes against the lane VM (its network and snapshots). A `policies/` folder is an error naming the new key of each old one. Prints each problem with its line; exit 4 when there is an error. Reads only
- `antinomie-cli config api-key`: Store, remove or show the node's API keys in `<data>/api-keys.json` (mode 0600; the file the desktop's Tools \> API keys writes). The abuse.ch Auth-Key is the one an Auto run with `[detection] check_online = true` uses; the service reads it at each run, so no restart is needed. Never prints a key, only its last four characters

#### antinomie-cli config path

Print the paths of `settings.json`, `service.toml` and `policies/`

```text
Usage: antinomie-cli config path [OPTIONS]
```

#### antinomie-cli config get

Print one setting, or all of them. A dotted KEY reaches into an object (`disks.hide_dotfiles`). Reads the file; takes no lock

```text
Usage: antinomie-cli config get [OPTIONS] [KEY]
```

Arguments:

- `<KEY>`: The setting; a dotted key reaches into an object. Without one, every setting

#### antinomie-cli config set

Change one setting. VALUE is JSON when it parses (`true`, `12`), else text. Takes the engine lock, so it refuses while a window or daemon runs

```text
Usage: antinomie-cli config set [OPTIONS] <KEY> <VALUE>
```

Arguments:

- `<KEY>`: The setting, for example `outbound_catalog` or `start.boot_wait_secs` (required)
- `<VALUE>`: The new value: JSON when it parses, else text (required)

#### antinomie-cli config validate

Check `service.toml` and the presets (the six built in and `presets/*.toml`): unknown keys, the node ceilings, the keys this version reserves, live routes, and the lanes against the lane VM (its network and snapshots). A `policies/` folder is an error naming the new key of each old one. Prints each problem with its line; exit 4 when there is an error. Reads only

```text
Usage: antinomie-cli config validate [OPTIONS]
```

Options:

- `--preset <PRESET>`: Check this preset only (its file, or a built-in one; the service file is still checked)

#### antinomie-cli config api-key

Store, remove or show the node's API keys in `<data>/api-keys.json` (mode 0600; the file the desktop's Tools \> API keys writes). The abuse.ch Auth-Key is the one an Auto run with `[detection] check_online = true` uses; the service reads it at each run, so no restart is needed. Never prints a key, only its last four characters

```text
Usage: antinomie-cli config api-key [OPTIONS] <COMMAND>
```

Commands:

- `antinomie-cli config api-key set`: Read the key from standard input (its first line) and store it. It is never taken from an argument or the environment, where `ps` or the shell history would show it: `antinomie-cli config api-key set abusech < key.txt`
- `antinomie-cli config api-key clear`: Forget the key
- `antinomie-cli config api-key show`: Which keys are stored, each as its last four characters

##### antinomie-cli config api-key set

Read the key from standard input (its first line) and store it. It is never taken from an argument or the environment, where `ps` or the shell history would show it: `antinomie-cli config api-key set abusech < key.txt`

```text
Usage: antinomie-cli config api-key set [OPTIONS] <SERVICE>
```

Arguments:

- `<SERVICE>`: The service the key is for (required; values: `abusech`, `malshare`)
  - `abusech`: The abuse.ch Auth-Key: Check online (ThreatFox, URLhaus), MalwareBazaar, the IOC datasets
  - `malshare`: The MalShare API key (desktop sample downloads)

##### antinomie-cli config api-key clear

Forget the key

```text
Usage: antinomie-cli config api-key clear [OPTIONS] <SERVICE>
```

Arguments:

- `<SERVICE>`: The service whose key is forgotten (required; values: `abusech`, `malshare`)
  - `abusech`: The abuse.ch Auth-Key: Check online (ThreatFox, URLhaus), MalwareBazaar, the IOC datasets
  - `malshare`: The MalShare API key (desktop sample downloads)

##### antinomie-cli config api-key show

Which keys are stored, each as its last four characters

```text
Usage: antinomie-cli config api-key show [OPTIONS]
```

### antinomie-cli analyze

Static analysis of a host file, no VM; takes the engine lock

```text
Usage: antinomie-cli analyze [OPTIONS] <FILE>
```

Arguments:

- `<FILE>`: The file to analyse. It is added to the sample library; the original is not changed (required)

Options:

- `--checks <LIST>`: Checks to run, comma separated (default: the triage set). Names: metadata, structures, strings, regex, entropy, hardening, rules, identification, capabilities, disassembly, decompilation, embedded, floss, unpacking
- `--time-limit-min <N>`: Minutes each analysis tool may run (0: each tool's own limit) (default: `0`)
- `--out <DIR>`: Also copy the report folder(s) into this directory, one folder per report

### antinomie-cli rules

Rule packs and groups: list, enable, disable; the catalog's packs: catalog, install, update

```text
Usage: antinomie-cli rules [OPTIONS] <COMMAND>
```

Commands:

- `antinomie-cli rules list`: List installed rule packs and groups and whether they are enabled
- `antinomie-cli rules enable`: Enable a pack or group. Use `pack:ID` or `group:ID` when an id names both
- `antinomie-cli rules disable`: Disable a pack or group
- `antinomie-cli rules catalog`: Check the rules catalog and list its packs with the installed version
- `antinomie-cli rules install`: Download, check, filter and install catalog packs (their default options), as Tools \> Rules does: for example yara-forge-core
- `antinomie-cli rules update`: Install the catalog's newer version of installed packs (only the named ones when ids are given), with the options they were installed with

#### antinomie-cli rules list

List installed rule packs and groups and whether they are enabled

```text
Usage: antinomie-cli rules list [OPTIONS]
```

Options:

- `--engine <ENGINE>`: Only this engine: yara, sigma or ids (Suricata)

#### antinomie-cli rules enable

Enable a pack or group. Use `pack:ID` or `group:ID` when an id names both

```text
Usage: antinomie-cli rules enable [OPTIONS] <ID>
```

Arguments:

- `<ID>`: The pack or group id (required)

#### antinomie-cli rules disable

Disable a pack or group

```text
Usage: antinomie-cli rules disable [OPTIONS] <ID>
```

Arguments:

- `<ID>`: The pack or group id (required)

#### antinomie-cli rules catalog

Check the rules catalog and list its packs with the installed version

```text
Usage: antinomie-cli rules catalog [OPTIONS]
```

#### antinomie-cli rules install

Download, check, filter and install catalog packs (their default options), as Tools \> Rules does: for example yara-forge-core

```text
Usage: antinomie-cli rules install [OPTIONS] <ID>...
```

Arguments:

- `<ID>...`: Catalog pack ids (`rules catalog`) (required)

#### antinomie-cli rules update

Install the catalog's newer version of installed packs (only the named ones when ids are given), with the options they were installed with

```text
Usage: antinomie-cli rules update [OPTIONS] [ID]...
```

Arguments:

- `<ID>...`: Installed pack ids; without one, every installed pack

### antinomie-cli tools

The optional analysis tools (capa, FLOSS, Ghidra, Detect It Easy, ...): list, install, update, as Tools \> Analysis tools does. No engine lock

```text
Usage: antinomie-cli tools [OPTIONS] <COMMAND>
```

Commands:

- `antinomie-cli tools list`: List the analysis tools: the version Antinomie installs, the one it installed, and a system copy that takes precedence
- `antinomie-cli tools install`: Download, check (SHA-256) and unpack tools into \<data\>/tools/\<id\>, as Tools \> Analysis tools does: capa, floss, ghidra, die, upx, ...
- `antinomie-cli tools update`: Install again each tool Antinomie installed whose version is not the one this app pins (only the named ones when ids are given)

#### antinomie-cli tools list

List the analysis tools: the version Antinomie installs, the one it installed, and a system copy that takes precedence

```text
Usage: antinomie-cli tools list [OPTIONS]
```

#### antinomie-cli tools install

Download, check (SHA-256) and unpack tools into \<data\>/tools/\<id\>, as Tools \> Analysis tools does: capa, floss, ghidra, die, upx, ...

```text
Usage: antinomie-cli tools install [OPTIONS] <ID>...
```

Arguments:

- `<ID>...`: Tool ids (`tools list`) (required)

#### antinomie-cli tools update

Install again each tool Antinomie installed whose version is not the one this app pins (only the named ones when ids are given)

```text
Usage: antinomie-cli tools update [OPTIONS] [ID]...
```

Arguments:

- `<ID>...`: Tool ids (`tools list`); without one, every tool that needs it

### antinomie-cli ioc

The abuse.ch IOC datasets: `ioc datasets list`, `update [NAME...]`, `enable`, `disable`. The window's files; no engine lock, so a daemon may serve meanwhile. An Auto run's Check online needs them

```text
Usage: antinomie-cli ioc [OPTIONS] <COMMAND>
```

Commands:

- `antinomie-cli ioc datasets`: The abuse.ch datasets the indicators of a run are matched against (ThreatFox, URLhaus, Feodo Tracker, SSLBL), kept in `<data>/ioc/`, the folder the window's Tools \> Detection rules \> IOC uses. An Auto run's Check online needs at least one of them

#### antinomie-cli ioc datasets

The abuse.ch datasets the indicators of a run are matched against (ThreatFox, URLhaus, Feodo Tracker, SSLBL), kept in `<data>/ioc/`, the folder the window's Tools \> Detection rules \> IOC uses. An Auto run's Check online needs at least one of them

```text
Usage: antinomie-cli ioc datasets [OPTIONS] <COMMAND>
```

Commands:

- `antinomie-cli ioc datasets list`: Every dataset: switched on or off, the stored copy's records and date, whether it needs the abuse.ch Auth-Key. Reads only
- `antinomie-cli ioc datasets update`: Download NAME..., or every dataset that is switched on, from abuse.ch. Needs `config set outbound_catalog true` (the window's Allow outbound catalog and rule downloads; exit 5 otherwise) and, for ThreatFox and the URLhaus datasets, the abuse.ch Auth-Key stored with `config api-key set abusech` (without it nothing is downloaded, exit 5). A failed download keeps the previous copy (exit 21); Ctrl-C stops (exit 130). No engine lock: run it while a daemon serves, or from cron or a systemd timer
- `antinomie-cli ioc datasets enable`: Switch a dataset on: `update` downloads it and matching uses it
- `antinomie-cli ioc datasets disable`: Switch a dataset off: not downloaded, not used; its copy stays

##### antinomie-cli ioc datasets list

Every dataset: switched on or off, the stored copy's records and date, whether it needs the abuse.ch Auth-Key. Reads only

```text
Usage: antinomie-cli ioc datasets list [OPTIONS]
```

##### antinomie-cli ioc datasets update

Download NAME..., or every dataset that is switched on, from abuse.ch. Needs `config set outbound_catalog true` (the window's Allow outbound catalog and rule downloads; exit 5 otherwise) and, for ThreatFox and the URLhaus datasets, the abuse.ch Auth-Key stored with `config api-key set abusech` (without it nothing is downloaded, exit 5). A failed download keeps the previous copy (exit 21); Ctrl-C stops (exit 130). No engine lock: run it while a daemon serves, or from cron or a systemd timer

```text
Usage: antinomie-cli ioc datasets update [OPTIONS] [NAMES]...
```

Arguments:

- `<NAMES>...`: Dataset names as `ioc datasets list` shows them (`threatfox`, `feodo`, ...)

##### antinomie-cli ioc datasets enable

Switch a dataset on: `update` downloads it and matching uses it

```text
Usage: antinomie-cli ioc datasets enable [OPTIONS] <NAME>
```

Arguments:

- `<NAME>`: The dataset name, as `ioc datasets list` shows it (required)

##### antinomie-cli ioc datasets disable

Switch a dataset off: not downloaded, not used; its copy stays

```text
Usage: antinomie-cli ioc datasets disable [OPTIONS] <NAME>
```

Arguments:

- `<NAME>`: The dataset name, as `ioc datasets list` shows it (required)

### antinomie-cli base

Bases: list, install, download, build, delete; takes the engine lock (`list` asks the daemon when one answers)

```text
Usage: antinomie-cli base [OPTIONS] <COMMAND>
```

Commands:

- `antinomie-cli base list`: List the installed bases, or with --remote the ones the catalog offers
- `antinomie-cli base install`: Install a base from a boot-bundle folder
- `antinomie-cli base download`: Download a base from the catalog (needs `outbound_catalog`)
- `antinomie-cli base build`: Build a base on this machine
- `antinomie-cli base delete`: Delete an installed base; refused while a VM uses it

#### antinomie-cli base list

List the installed bases, or with --remote the ones the catalog offers

```text
Usage: antinomie-cli base list [OPTIONS]
```

Options:

- `--remote`: Fetch and list the bases the public catalog advertises (needs `outbound_catalog`; uses the network)

#### antinomie-cli base install

Install a base from a boot-bundle folder

```text
Usage: antinomie-cli base install [OPTIONS] <DIR>
```

Arguments:

- `<DIR>`: The folder holding the bundle (`bundle.json`, kernel, disk) (required)

#### antinomie-cli base download

Download a base from the catalog (needs `outbound_catalog`)

```text
Usage: antinomie-cli base download [OPTIONS] <ID>
```

Arguments:

- `<ID>`: The catalog identity (see `base list --remote`), or the start of it (required)

Options:

- `--wait`: Wait for the download. Always on in direct mode: leaving would cancel it

#### antinomie-cli base build

Build a base on this machine

```text
Usage: antinomie-cli base build [OPTIONS]
```

Options:

- `--profile <PROFILE>`: What to build: busybox, busybox-extra (BusyBox as a camera or DVR), debian-minimal or debian-xfce (default: `busybox`)
- `--engine <ENGINE>`: Where the build runs (values: `automatic`, `native`, `podman`, `docker`, `qemu`; default: `automatic`)
- `--name <NAME>`: Display name of the base (default: automatic)
- `--wait`: Wait for the build. Always on in direct mode: leaving would cancel it

#### antinomie-cli base delete

Delete an installed base; refused while a VM uses it

```text
Usage: antinomie-cli base delete [OPTIONS] <ID>
```

Arguments:

- `<ID>`: The base identity (or the start of it, 4 characters or more) or its label (required)

Options:

- `--yes`: Confirm the deletion

### antinomie-cli vm

VMs: create, start, stop, status, reset, duplicate, delete; takes the engine lock (`list` asks the daemon when one answers)

```text
Usage: antinomie-cli vm [OPTIONS] <COMMAND>
```

Commands:

- `antinomie-cli vm list`: List the VMs
- `antinomie-cli vm create`: Create a VM from an installed base
- `antinomie-cli vm start`: Boot a VM, wait for the guest to answer, and stop it again (or hold it). Under TCG the start waits are stretched by `--tcg-multiplier`
- `antinomie-cli vm stop`: Stop the VM and wait until its recording is final
- `antinomie-cli vm status`: Show a VM: state, boot, guest kernel, snapshots, pending disk layer
- `antinomie-cli vm reset`: Reset a VM's disk to its base; refused when the VM has snapshots
- `antinomie-cli vm duplicate`: Copy a VM with an independent disk and no history
- `antinomie-cli vm delete`: Delete a VM's disk and configuration (recordings stay)

#### antinomie-cli vm list

List the VMs

```text
Usage: antinomie-cli vm list [OPTIONS]
```

#### antinomie-cli vm create

Create a VM from an installed base

```text
Usage: antinomie-cli vm create [OPTIONS] <NAME>
```

Arguments:

- `<NAME>`: The VM's name (required)

Options:

- `--base <ID>`: The base (identity, start of it, or label); optional when exactly one is installed
- `--cpus <CPUS>`: Virtual CPUs (default: `4`)
- `--ram-mib <N>`: Guest RAM in MiB (default: `2048`)
- `--disk-gib <N>`: Disk size in GiB (default: `8`)
- `--network <NETWORK>`: disconnected, isolated, routed or nat. Only a routed VM lets each run choose its route (default: `disconnected`)
- `--stealth <PRESET>`: What the guest sees of the machine: realistic-desktop, realistic-laptop, realistic-server, iot (a Raspberry Pi; arm64 bases only, an x86-64 VM starts as Normal QEMU) or transparent (default: `realistic-desktop`)
- `--user <NAME>`: Guest account name (bases that need an account) (default: `analyst`)
- `--password-stdin`: Read the guest account password from standard input (one line). It is never taken from the command line

#### antinomie-cli vm start

Boot a VM, wait for the guest to answer, and stop it again (or hold it). Under TCG the start waits are stretched by `--tcg-multiplier`

```text
Usage: antinomie-cli vm start [OPTIONS] <ID>
```

Arguments:

- `<ID>`: The VM's identity or name (required)

Options:

- `--wait`: Wait for the guest to answer. Always on in direct mode
- `--hold <SECONDS>`: Keep the VM running this many seconds before stopping it; without a number, until interrupted (exit 130)

#### antinomie-cli vm stop

Stop the VM and wait until its recording is final

```text
Usage: antinomie-cli vm stop [OPTIONS] <ID>
```

Arguments:

- `<ID>`: The VM's identity or name (required)

#### antinomie-cli vm status

Show a VM: state, boot, guest kernel, snapshots, pending disk layer

```text
Usage: antinomie-cli vm status [OPTIONS] <ID>
```

Arguments:

- `<ID>`: The VM's identity or name (required)

#### antinomie-cli vm reset

Reset a VM's disk to its base; refused when the VM has snapshots

```text
Usage: antinomie-cli vm reset [OPTIONS] <ID>
```

Arguments:

- `<ID>`: The VM's identity or name (required)

Options:

- `--yes`: Confirm: the disk is replaced

#### antinomie-cli vm duplicate

Copy a VM with an independent disk and no history

```text
Usage: antinomie-cli vm duplicate [OPTIONS] <ID> <NAME>
```

Arguments:

- `<ID>`: The VM to copy: its identity or name (required)
- `<NAME>`: The new VM's name (required)

#### antinomie-cli vm delete

Delete a VM's disk and configuration (recordings stay)

```text
Usage: antinomie-cli vm delete [OPTIONS] <ID>
```

Arguments:

- `<ID>`: The VM's identity or name (required)

Options:

- `--yes`: Confirm the deletion

### antinomie-cli snapshot

VM snapshots: list, create, restore, delete; takes the engine lock

```text
Usage: antinomie-cli snapshot [OPTIONS] <COMMAND>
```

Commands:

- `antinomie-cli snapshot list`: List a VM's snapshots
- `antinomie-cli snapshot create`: Take a snapshot of a VM
- `antinomie-cli snapshot restore`: Return a VM to a snapshot, boot it and stop it again
- `antinomie-cli snapshot delete`: Delete (hide) a snapshot; layers other snapshots need stay on disk

#### antinomie-cli snapshot list

List a VM's snapshots

```text
Usage: antinomie-cli snapshot list [OPTIONS] <VM>
```

Arguments:

- `<VM>`: The VM's identity or name (required)

#### antinomie-cli snapshot create

Take a snapshot of a VM

```text
Usage: antinomie-cli snapshot create [OPTIONS] <VM> <NAME>
```

Arguments:

- `<VM>`: The VM's identity or name (required)
- `<NAME>`: The snapshot's name (required)

Options:

- `--mode <MODE>`: What the snapshot keeps (values: `disk`, `full`; default: `disk`)
  - `disk`: The disk of the stopped VM; restoring boots the guest afresh
  - `full`: Disk and memory of the running guest, saved once it has finished booting; restoring resumes it
- `--description <DESCRIPTION>`: A note kept with the snapshot (default: ``)

#### antinomie-cli snapshot restore

Return a VM to a snapshot, boot it and stop it again

```text
Usage: antinomie-cli snapshot restore [OPTIONS] <VM> <ID>
```

Arguments:

- `<VM>`: The VM's identity or name (required)
- `<ID>`: The snapshot identity or name (required)

Options:

- `--cold-boot`: Boot the guest from the snapshot's disk instead of resuming a Full snapshot's memory (a Disk snapshot always boots)
- `--yes`: Confirm: the VM's current state is replaced

#### antinomie-cli snapshot delete

Delete (hide) a snapshot; layers other snapshots need stay on disk

```text
Usage: antinomie-cli snapshot delete [OPTIONS] <VM> <ID>
```

Arguments:

- `<VM>`: The VM's identity or name (required)
- `<ID>`: The snapshot identity or name (required)

Options:

- `--yes`: Confirm the deletion

### antinomie-cli run

Run a library sample in a VM: `run exec`; takes the engine lock

```text
Usage: antinomie-cli run [OPTIONS] <COMMAND>
```

Commands:

- `antinomie-cli run exec`: Upload a library sample into a VM, run it and wait for a settled recording

#### antinomie-cli run exec

Upload a library sample into a VM, run it and wait for a settled recording

```text
Usage: antinomie-cli run exec [OPTIONS] <SAMPLE> [-- <ARG>...]
```

Arguments:

- `<SAMPLE>`: The sample: its SHA-256 (see `sample list`), or a file, which is added to the library first (required)
- `<ARG>...`: More arguments for the program, after `--`

Options:

- `--vm <ID>`: The VM; optional when exactly one exists
- `--start`: Boot the VM when it is stopped (otherwise a stopped VM is refused). A Debian guest is given the boot wait before the program starts; under TCG every wait is stretched by the TCG multiplier (see the global `--boot-wait` and `--tcg-multiplier`)
- `--args <ARG>`: Arguments for the program. More can follow `--`
- `--env <K=V>`: Environment for the program, as K=V; repeat for several. Without a PATH, the usual one is set
- `--load-into <PROGRAM>`: Treat the sample as a shared library: upload it, then run PROGRAM (a path in the guest) with `LD_PRELOAD` set to the uploaded library, instead of running the sample itself. The run is linked to the library sample
- `--as <WHO>`: Who runs it: `user` (UID 1000, the default), `root`, or UID:GID (default: `user`)
- `--route <ROUTE>`: Where the program's network traffic goes on a routed VM: drop, internet, inet_sim, tor, vpn or socks5 (default: the VM's setting)
- `--timeout-run <S>`: Seconds the program may run before it is told to stop (default: `300`)
- `--net-capture`: Record the VM's network traffic for the run
- `--memory-dump`: Take the VM's memory when the program's tree has ended
- `--screenshot-every <SECONDS>`: Take a screenshot of the VM screen every SECONDS (1 to 999) while the program runs, and one when its tree ends; a screen that has not changed is skipped. The pictures are the run's `screenshots/` files, named by the time since the run started
- `--screenshot-max-pictures <N>`: Keep at most N pictures of --screenshot-every for this run (10 to 5000; default 500). The series ends with a note when it is reached
- `--screenshot-max-mib <MIB>`: Keep at most MIB MiB of pictures of --screenshot-every for this run (16 to 4096; default 256)
- `--core-dump`: Take a core of the program before its address space exits
- `--dump-trigger <TIER>`: Take a dump while the program runs, when the live Triage rules match at this tier or above (low, medium or high; default off). What it takes is --dump-kind. The program is not stopped. The result's `triggers` says what fired (rule, tier, dump state and path) or that it was armed and nothing matched. Needs a revision-16 base for a core
- `--dump-kind <KIND>`: What --dump-trigger takes: core (the process that made the call, the default), memory (the VM's RAM) or both. Bounded by the core budget and the memory cap of the UI's defaults
- `--core-nonresident`: Make the cores --dump-trigger takes read the pages that are not in memory too (swapped out, or file pages the kernel dropped): slower, bounded by the core budget and deadline. Needs --dump-trigger with core or both, and a base of guest contract revision 22 (an older one reads resident pages only and the run says so). An exit core (--core-dump) always reads resident pages
- `--start-persistence`: When the program's tree ends at least 30 s before --timeout-run after installing persistence (systemd units, init.d scripts, rc.local, cron lines, shell profiles, autostart entries), start those entries in the same run, as a boot or login would, and keep the run going until --timeout-run. The result's run says what was started
- `--static <CHECKS>`: Run the guest-side static analysis too, with these checks (comma separated; see `analyze --help`)
- `--wait`: Wait for the result. Always on in direct mode: leaving would stop the VM
- `--events`: Print the progress as it happens, one event (design 5.5) per line, then the result; implies `-o ndjson`

### antinomie-cli recording

The recordings of the data directory: list, show, export; no engine lock needed. Each asks the daemon when one answers

```text
Usage: antinomie-cli recording [OPTIONS] <COMMAND>
```

Commands:

- `antinomie-cli recording list`: List the recordings of the data directory; no engine lock needed. Asks the daemon when one answers
- `antinomie-cli recording show`: Show one recording: its state, phase and artifacts; `--summary` adds the Triage summary. No engine lock needed. Asks the daemon when one answers
- `antinomie-cli recording export`: Write a recording as NDJSON and evidence files into --out. No engine lock needed. Asks the daemon when one answers; the files are written by this command, never by the daemon

#### antinomie-cli recording list

List the recordings of the data directory; no engine lock needed. Asks the daemon when one answers

```text
Usage: antinomie-cli recording list [OPTIONS]
```

Options:

- `--vm <ID>`: Only runs of this VM
- `--sample <SHA256>`: Only runs of this library sample (SHA-256)
- `--run <RUN>`: Only recordings made by this run of Auto mode (`r_...`)
- `--state <STATE>`: Only runs in this state (running, finished, stopped, interrupted, ...)
- `--since <SPAN>`: Only runs started since then: a span such as 90m, 24h or 7d, or a Unix time in milliseconds
- `--limit <N>`: Rows to return (1 to 500)
- `--cursor <CURSOR>`: Where the last page stopped (`next_cursor`)

#### antinomie-cli recording show

Show one recording: its state, phase and artifacts; `--summary` adds the Triage summary. No engine lock needed. Asks the daemon when one answers

```text
Usage: antinomie-cli recording show [OPTIONS] <RUN>
```

Arguments:

- `<RUN>`: The run: its id or the first characters of it (see `antinomie-cli run exec`'s result), an Auto run id (r_...), vm:boot:run, a run key, or the run's folder (required)

Options:

- `--summary`: Add the Triage summary (`recording.summary`); indexes the run first

#### antinomie-cli recording export

Write a recording as NDJSON and evidence files into --out. No engine lock needed. Asks the daemon when one answers; the files are written by this command, never by the daemon

```text
Usage: antinomie-cli recording export [OPTIONS] --out <DIR> <RUN>
```

Arguments:

- `<RUN>`: The run: its id or the first characters of it (see `antinomie-cli run exec`'s result), an Auto run id (r_...), vm:boot:run, a run key, or the run's folder (required)

Options:

- `--part <LIST>`: Parts to write, comma separated: trace, processes, findings, indicators, files, network, timeline, analysis, custody, artifacts. Default: all but the bytes of sensitive evidence
- `--sensitive`: Also write the bytes the sample produced: the frames of the recorded packets (part network), the captured bytes of calls (part trace), the capture, memory and core files and file copies (part artifacts) and the contents of changed files (part files). With a daemon each read is written to its service log
- `--no-triage`: Leave out the parts that need the Triage index (findings, indicators, files, network, timeline), so a very large recording is not indexed in full. Naming one of them with --part is an error
- `--out <DIR>`: The folder to write into; created when missing. Nothing is written anywhere else (required)

### antinomie-cli sample

Samples in the library; no engine lock needed. `list`, `show` and `tag` ask the daemon when one answers

```text
Usage: antinomie-cli sample [OPTIONS] <COMMAND>
```

Commands:

- `antinomie-cli sample add`: Add files to the library (hashed and archived, never run)
- `antinomie-cli sample list`: List samples, newest first
- `antinomie-cli sample show`: Show one sample
- `antinomie-cli sample tag`: Add or remove tags
- `antinomie-cli sample verify`: Read archives back and compare their SHA-256
- `antinomie-cli sample remove`: Delete a sample's archive (the record and its custody log stay)

#### antinomie-cli sample add

Add files to the library (hashed and archived, never run)

```text
Usage: antinomie-cli sample add [OPTIONS] <FILE>...
```

Arguments:

- `<FILE>...`: The files to add. They are hashed and archived, never run (required)

Options:

- `--name <NAME>`: Library name (one file only; default: the file name)
- `--tag <K=V>`: Tag as KIND=VALUE (verdict, category, technique, custom) or a bare custom value
- `--delete-original`: Delete the original after the archive read back and matched
- `--archive-password <PASSWORD>`: The password of a ZIP with one encrypted file, which is opened in memory and added as the sample \[default: `infected`\]
- `--archive-password-stdin`: Read the ZIP password from one line of standard input
- `--entry <NAME>`: The file to take from a ZIP of several
- `--keep-archive`: Add a ZIP as the sample itself; open nothing

#### antinomie-cli sample list

List samples, newest first

```text
Usage: antinomie-cli sample list [OPTIONS]
```

Options:

- `--q <Q>`: Text in the name, SHA-256, type, architecture or a tag
- `--tag <K=V>`: Only samples with this tag (KIND=VALUE); repeat to require several
- `--limit <LIMIT>`: At most this many samples (default: `100`)
- `--cursor <CURSOR>`: Continue after the `next_cursor` of an earlier page
- `--all`: Include samples whose archive was removed
- `--custody`: Fill `custody_ok` by checking every chain (otherwise it is null)

#### antinomie-cli sample show

Show one sample

```text
Usage: antinomie-cli sample show [OPTIONS] <SHA256>
```

Arguments:

- `<SHA256>`: The sample's SHA-256 (required)

Options:

- `--origins`: Add the routes that brought the sample in
- `--events`: Add the custody events
- `--runs`: Add the runs the library knows

#### antinomie-cli sample tag

Add or remove tags

```text
Usage: antinomie-cli sample tag [OPTIONS] <SHA256> <TAG>...
```

Arguments:

- `<SHA256>`: The sample's SHA-256 (required)
- `<TAG>...`: Tags as KIND=VALUE (verdict, category, technique, custom) or a bare custom value (required)

Options:

- `--remove`: Remove the tags instead of adding them

#### antinomie-cli sample verify

Read archives back and compare their SHA-256

```text
Usage: antinomie-cli sample verify [OPTIONS] [SHA256]
```

Arguments:

- `<SHA256>`: One sample; default: every sample that has an archive

#### antinomie-cli sample remove

Delete a sample's archive (the record and its custody log stay)

```text
Usage: antinomie-cli sample remove [OPTIONS] <SHA256>
```

Arguments:

- `<SHA256>`: The sample's SHA-256 (required)

Options:

- `--yes`: Confirm the deletion

### antinomie-cli custody

Custody chains of the samples; no engine lock needed. `verify` asks the daemon when one answers (not with `--export`)

```text
Usage: antinomie-cli custody [OPTIONS] <COMMAND>
```

Commands:

- `antinomie-cli custody verify`: Check one sample's custody chain, or every chain and the library index

#### antinomie-cli custody verify

Check one sample's custody chain, or every chain and the library index

```text
Usage: antinomie-cli custody verify [OPTIONS] [SHA256]
```

Arguments:

- `<SHA256>`: One sample; default: the whole library

Options:

- `--export <PATH>`: Write the custody record of the sample to this file (`.html` writes the readable page, anything else JSON with the verifier beside it)
- `--sign <SIGN>`: Sign the export with your own key (needs --key) (values: `minisign`, `ssh`)
- `--key <PATH>`: The key file `minisign -s` or `ssh-keygen -Y sign` uses; never read by Antinomie

### antinomie-cli triage

Index a saved run as Triage does and print its summary: the assessment, the counts and the key behaviours. No engine lock needed. Asks the daemon when one answers

```text
Usage: antinomie-cli triage [OPTIONS] <RUN>
```

Arguments:

- `<RUN>`: The run: its id or the first characters of it (see `antinomie-cli run exec`'s result), an Auto run id (r_...), vm:boot:run, a run key, or the run's folder (required)

Options:

- `--parts <LIST>`: Report parts to add to the result, comma separated (see `report --help`); the summary is always there

### antinomie-cli detect

Run YARA, Sigma and IDS over a saved run's evidence; no engine lock needed unless --save keeps the results in the recording

```text
Usage: antinomie-cli detect [OPTIONS] <RUN>
```

Arguments:

- `<RUN>`: The run: its id or the first characters of it (see `antinomie-cli run exec`'s result), an Auto run id (r_...), vm:boot:run, a run key, or the run's folder (required)

Options:

- `--engine <LIST>`: Engines, comma separated: yara, sigma, ids \[default: all three\]
- `--out <DIR>`: Write each engine's full result to DIR/detection-\<engine\>.json
- `--save`: Keep the results in the recording (triage-detection/) and in its digest, as the Detection tab does. Takes the engine lock, so it is refused while a window or a daemon owns the data directory

### antinomie-cli digest

Build the Triage digest of a finished run (or of every run that has none, with --pending): a budgeted read, marked partial when the budget ended it or telemetry was lost. Takes the engine lock

```text
Usage: antinomie-cli digest [OPTIONS] [RUN]
```

Arguments:

- `<RUN>`: The run: its id or the first characters of it (see `antinomie-cli run exec`'s result), an Auto run id (r_...), vm:boot:run, a run key, or the run's folder

Options:

- `--pending`: Build the digest of every finished run that has none (or whose digest was made while its recording was still being written), one at a time
- `--max-calls <CALLS>`: Most calls of a run one digest reads before it is marked partial (default: `400000`)
- `--max-seconds <SECONDS>`: Most seconds one digest may take before it is marked partial (default: `1200`)

### antinomie-cli report

Write a saved run's report (HTML, PDF, JSON, MISP, STIX, Markdown), the same files the window's Export report writes. No engine lock needed

```text
Usage: antinomie-cli report [OPTIONS] <RUN>
```

Arguments:

- `<RUN>`: The run: its id or the first characters of it (see `antinomie-cli run exec`'s result), an Auto run id (r_...), vm:boot:run, a run key, or the run's folder (required)

Options:

- `--formats <LIST>`: Formats, comma separated: html, pdf, json, misp, stix, md (or all) \[default: the data directory's export choices, HTML and PDF unless set\]. (`--format` is the global output format.)
- `--parts <LIST>`: Parts, comma separated: summary, indicators, attack, processes, findings, files, file_activity, network, detections, evidence, custody, static_analysis (or all) \[default: the export choices, every part unless set\]
- `--evidence-bundle`: Also write the evidence bundle (.zip next to the report): the captures, the files the run dropped in an inner AES-256 zip (password: infected), the sample's custody export and a SHA-256 manifest. (`--bundle` is the global boot-bundle folder.)
- `--defang`: Defang indicators in HTML, PDF and Markdown (hxxp://example\[.\]com)
- `--no-defang`: Keep indicators as they are in every format
- `--include-content`: Keep a clipped, escaped preview of what the sample read in the Read files rows (never of a file the run wrote)
- `--out <DIR>`: Folder for the files \[default: report-\<first 8 of the run id\> in the current folder\]. Created when missing

### antinomie-cli auto

Auto mode: the daemon, the lanes, runs and their results

```text
Usage: antinomie-cli auto [OPTIONS] <COMMAND>
```

Commands:

- `antinomie-cli auto init`: Make a lane: create the lane VM (routed), boot it once, stop it, take its clean snapshot, write service/lanes/lane-N.json and, for lane 1 with another VM name or snapshot, the \[lanes\] of a new service.toml. The presets need no file: six are built in. `--lane N` (2 to 4) makes another lane, in \<data\>/lanes/N/, for `daemon.lanes`. Runs in this process: stop the daemon first
- `antinomie-cli auto daemon`: Run the daemon in the foreground until SIGTERM or SIGINT: it owns the data folder, runs the queue on its lanes (one by default; `[daemon] lanes` in service.toml) and serves the local socket (owner only). Put it in the background with a service manager or `&`
- `antinomie-cli auto submit`: Submit a file (or a library sample) as a run. Without a daemon, the run runs in this process and the command exits with its code
- `antinomie-cli auto status`: One run, or the queue and the lanes
- `antinomie-cli auto list`: Runs, newest first
- `antinomie-cli auto wait`: Wait until the runs have ended; exit with the worst code
- `antinomie-cli auto events`: A run's events (or every run's with --all), stored and, with --follow, live
- `antinomie-cli auto result`: A run's outcome, label and report files
- `antinomie-cli auto artifacts`: A run's artifacts
- `antinomie-cli auto fetch`: Copy one report or artifact of a run
- `antinomie-cli auto cancel`: Cancel a run that waits or runs
- `antinomie-cli auto rerun`: A new run from a finished one: its resolved options (or another preset's, `--preset`), with `--override` on top
- `antinomie-cli auto queue`: The queue: status, pause, resume
- `antinomie-cli auto lane`: The lanes: list, reset, unquarantine (`--lane lane-N`)
- `antinomie-cli auto preset`: The presets: `list` (the six built-in ones and presets/\*.toml, with the permissions their options need) and `show NAME` (every option)
- `antinomie-cli auto watch`: The watch folders: their state, and a scan now
- `antinomie-cli auto gc`: Apply retention now (recordings, run records, rejected files, staged uploads); `--dry-run` only prints the plan
- `antinomie-cli auto delete`: Delete a finished run's record and artifacts (the sample stays)

#### antinomie-cli auto init

Make a lane: create the lane VM (routed), boot it once, stop it, take its clean snapshot, write service/lanes/lane-N.json and, for lane 1 with another VM name or snapshot, the \[lanes\] of a new service.toml. The presets need no file: six are built in. `--lane N` (2 to 4) makes another lane, in \<data\>/lanes/N/, for `daemon.lanes`. Runs in this process: stop the daemon first

```text
Usage: antinomie-cli auto init [OPTIONS]
```

Options:

- `--base <ID>`: The base (identity, start of it, or label); optional when exactly one is installed
- `--lane <N>`: The lane to make: 1 (the data folder) to 4 (`<data>/lanes/N/`), for `daemon.lanes` in service.toml (default: `1`)
- `--name <NAME>`: The lane VM's name (`[lanes] vm` of service.toml for lane 1) \[default: auto-N\]
- `--cpus <CPUS>`: Virtual CPUs (default: `2`)
- `--ram-mib <N>`: Guest RAM in MiB (default: `4096`)
- `--disk-gib <N>`: Disk size in GiB (default: `40`)
- `--stealth <PRESET>`: realistic-desktop, realistic-laptop, realistic-server or transparent (default: `realistic-desktop`)
- `--user <NAME>`: Guest account name (bases that need an account) (default: `analyst`)
- `--password-stdin`: Read the guest account password from standard input (one line)
- `--snapshot <SNAPSHOT>`: The clean snapshot's name (`[lanes] revert_to` of service.toml) (default: `auto-clean`)
- `--replace`: Replace an existing lane with a new VM (for a new base). The old VM is kept; delete it with `vm delete` when you no longer need it

#### antinomie-cli auto daemon

Run the daemon in the foreground until SIGTERM or SIGINT: it owns the data folder, runs the queue on its lanes (one by default; `[daemon] lanes` in service.toml) and serves the local socket (owner only). Put it in the background with a service manager or `&`

```text
Usage: antinomie-cli auto daemon [OPTIONS]
```

Options:

- `--config <PATH>`: The service configuration \[default: \<data\>/service.toml\]
- `--foreground`: Run in the foreground (the only mode; accepted for the design's grammar)

#### antinomie-cli auto submit

Submit a file (or a library sample) as a run. Without a daemon, the run runs in this process and the command exits with its code

```text
Usage: antinomie-cli auto submit [OPTIONS] [FILE]
```

Arguments:

- `<FILE>`: The file to analyse. It is read once and stored in the library; the original is not changed

Options:

- `--sha256 <HEX>`: A sample already in the library, by its SHA-256
- `--preset <PRESET>`: The preset \[default: standard\]; the other flags change its options (the run is then Custom)
- `--priority <PRIORITY>`: 0 to 9; higher starts first
- `--label <KEY=VALUE>`: A label of the run (repeatable)
- `--timeout-run <SECONDS>`: The run time in seconds, 5 to 1800 (`program.run_time_s`)
- `--screenshot-every <SECONDS>`: Take a screenshot of the VM screen every SECONDS while the program runs (`record.screenshot_every_s`: 1 to 999; 0 turns it off). The pictures are the recording's `screenshot` artifacts
- `--start-persistence`: Start what the program installed as persistence when its tree ends early, and hold the run until its run time (`program.start_persistence = true`)
- `--no-start-persistence`: Do not start the program's persistence (`program.start_persistence = false`)
- `--args <ARG>`: Program arguments (`program.arguments`)
- `--load-into <PROGRAM>`: The sample is a shared library: run this program in the guest (an absolute path to a dynamically linked program, for example `/bin/ls` on a Debian base; BusyBox programs are static, so there use the loader `/lib/ld-linux-x86-64.so.2` with `--args /lib/libc.so.6`) with the library in `LD_PRELOAD` (`program.load_into`). A sample that is a program runs as usual
- `--env <KEY=VALUE>`: An environment entry (repeatable); replaces the preset's environment (a PATH is added when none is given)
- `--as <WHO>`: `user`, `root`, `nobody` or `UID:GID` (root or an id below 1000 needs the run.as_root permission)
- `--route <ROUTE>`: `drop` or `inet_sim` (a live route is not set up on this node)
- `--static <CHECKS>`: Static checks on the host: `none`, `triage`, or names (`strings,entropy`)
- `--no-static`: Run no static checks (the same as `--static none`)
- `--fresh-static`: Run every static check again instead of reusing a complete result of the same file made with the same tools, rules and limits
- `--force-capa`: Run capa even when its history predicts it will not finish within 1.5 times its limit on a file like this one
- `--formats <F,...>`: Report formats: html, pdf, json, misp, stix, md (`--format` is the output format of this command)
- `--evidence-bundle`: Also write the evidence bundle zip (`--bundle` is the boot bundle)
- `--defang`: Defang indicators in the HTML, PDF and Markdown reports (hxxp://example\[.\]com)
- `--no-defang`: Keep indicators as they are in every report format
- `--idempotency-key <KEY>`: The same key and spec within 24 hours returns the first run
- `--name <NAME>`: The file name the run shows \[default: the file's name\]
- `--wait`: Wait until the run has ended; exit with its code
- `--follow`: Print the run's events as NDJSON until it has ended (implies --wait)
- `--verdict-exit`: Wait, and exit 30, 31 or 32 when the succeeded run is labelled suspicious, malicious or inconclusive
- `--out <DIR>`: Copy the report files into this folder once the run has ended (implies --wait)

#### antinomie-cli auto status

One run, or the queue and the lanes

```text
Usage: antinomie-cli auto status [OPTIONS] [RUN]
```

Arguments:

- `<RUN>`: A run; without one, the queue and the lanes

#### antinomie-cli auto list

Runs, newest first

```text
Usage: antinomie-cli auto list [OPTIONS]
```

Options:

- `--state <STATE>`: Only runs in this state: queued, running, cancelling, succeeded, partial, failed, cancelled or rejected
- `--outcome <OUTCOME>`: Only runs with this outcome: succeeded, partial, failed, cancelled or rejected
- `--sha256 <HEX>`: Only runs of this sample (SHA-256)
- `--label <LABEL>`: A label `KEY` or `KEY=VALUE` of the spec
- `--since <WHEN>`: Only runs newer than this: `30m`, `24h`, `7d`, or a time in Unix ms
- `--limit <LIMIT>`: At most this many runs (default: `50`)
- `--cursor <CURSOR>`: Where the last page stopped (`next_cursor`)

#### antinomie-cli auto wait

Wait until the runs have ended; exit with the worst code

```text
Usage: antinomie-cli auto wait [OPTIONS] <RUNS>...
```

Arguments:

- `<RUNS>...`: The runs to wait for (required)

Options:

- `--verdict-exit`: Exit 30, 31 or 32 for a succeeded run labelled suspicious, malicious or inconclusive

#### antinomie-cli auto events

A run's events (or every run's with --all), stored and, with --follow, live

```text
Usage: antinomie-cli auto events [OPTIONS] [RUN]
```

Arguments:

- `<RUN>`: The run; with `--all`, none

Options:

- `--all`: Every run and the engine (resume by `gseq`)
- `--since <SEQ>`: Resume after this `seq` (one run) or `gseq` (`--all`)
- `--follow`: Keep printing events as they happen (one run: until it ends)
- `--types <T,...>`: Only these event types, comma-separated (`run.state,run.stage`)

#### antinomie-cli auto result

A run's outcome, label and report files

```text
Usage: antinomie-cli auto result [OPTIONS] <RUN>
```

Arguments:

- `<RUN>`: The run's id (`r_...`) (required)

#### antinomie-cli auto artifacts

A run's artifacts

```text
Usage: antinomie-cli auto artifacts [OPTIONS] <RUN>
```

Arguments:

- `<RUN>`: The run's id (`r_...`) (required)

#### antinomie-cli auto fetch

Copy one report or artifact of a run

```text
Usage: antinomie-cli auto fetch [OPTIONS] <RUN> <KIND>
```

Arguments:

- `<RUN>`: The run's id (`r_...`) (required)
- `<KIND>`: `html`, `pdf`, `json`, `misp`, `stix`, `md` (or `report.html` ...), or another artifact kind (`report.bundle`) (required)

Options:

- `--out <PATH>`: A file or a folder to write to; `-` writes to standard output

#### antinomie-cli auto cancel

Cancel a run that waits or runs

```text
Usage: antinomie-cli auto cancel [OPTIONS] <RUN>
```

Arguments:

- `<RUN>`: The run's id (`r_...`) (required)

Options:

- `--reason <REASON>`: Why; kept with the run

#### antinomie-cli auto rerun

A new run from a finished one: its resolved options (or another preset's, `--preset`), with `--override` on top

```text
Usage: antinomie-cli auto rerun [OPTIONS] <RUN>
```

Arguments:

- `<RUN>`: The finished run to run again (required)

Options:

- `--preset <PRESET>`: Another preset, as it is now, instead of the run's own options
- `--override <KEY=VALUE>`: Change one option, a dotted preset key (`program.run_time_s=60`, `network.route=inet_sim`); the value is JSON when it parses, else text
- `--priority <PRIORITY>`: 0 to 9 \[default: the run's own, lowered to your highest priority when above it\]

#### antinomie-cli auto queue

The queue: status, pause, resume

```text
Usage: antinomie-cli auto queue [OPTIONS] <COMMAND>
```

Commands:

- `antinomie-cli auto queue status`: The queue and the lanes
- `antinomie-cli auto queue pause`: Start no new run (the runs in progress finish)
- `antinomie-cli auto queue resume`: Start runs again

##### antinomie-cli auto queue status

The queue and the lanes

```text
Usage: antinomie-cli auto queue status [OPTIONS]
```

##### antinomie-cli auto queue pause

Start no new run (the runs in progress finish)

```text
Usage: antinomie-cli auto queue pause [OPTIONS]
```

##### antinomie-cli auto queue resume

Start runs again

```text
Usage: antinomie-cli auto queue resume [OPTIONS]
```

#### antinomie-cli auto lane

The lanes: list, reset, unquarantine (`--lane lane-N`)

```text
Usage: antinomie-cli auto lane [OPTIONS] <COMMAND>
```

Commands:

- `antinomie-cli auto lane list`: The lanes, their VM, quarantine and what keeps them from a run
- `antinomie-cli auto lane reset`: Revert the lane VM to its clean snapshot now; lifts a quarantine when the revert works
- `antinomie-cli auto lane unquarantine`: Lift a quarantine without reverting, when the checks pass (the clean snapshot is there, the VM is stopped, nothing is pending)

##### antinomie-cli auto lane list

The lanes, their VM, quarantine and what keeps them from a run

```text
Usage: antinomie-cli auto lane list [OPTIONS]
```

##### antinomie-cli auto lane reset

Revert the lane VM to its clean snapshot now; lifts a quarantine when the revert works

```text
Usage: antinomie-cli auto lane reset [OPTIONS]
```

Options:

- `--lane <LANE>`: The lane, `lane-N` (or N) \[default: lane-1\]
- `--yes`: Confirm (`reset` needs it; `unquarantine` accepts it and does not)

##### antinomie-cli auto lane unquarantine

Lift a quarantine without reverting, when the checks pass (the clean snapshot is there, the VM is stopped, nothing is pending)

```text
Usage: antinomie-cli auto lane unquarantine [OPTIONS]
```

Options:

- `--lane <LANE>`: The lane, `lane-N` (or N) \[default: lane-1\]
- `--yes`: Confirm (`reset` needs it; `unquarantine` accepts it and does not)

#### antinomie-cli auto preset

The presets: `list` (the six built-in ones and presets/\*.toml, with the permissions their options need) and `show NAME` (every option)

```text
Usage: antinomie-cli auto preset [OPTIONS] <COMMAND>
```

Commands:

- `antinomie-cli auto preset list`: Every preset, with what its options need
- `antinomie-cli auto preset show`: One preset with every option, as its file has them

##### antinomie-cli auto preset list

Every preset, with what its options need

```text
Usage: antinomie-cli auto preset list [OPTIONS]
```

##### antinomie-cli auto preset show

One preset with every option, as its file has them

```text
Usage: antinomie-cli auto preset show [OPTIONS] <NAME>
```

Arguments:

- `<NAME>`: The preset's name (`standard`, ...) (required)

#### antinomie-cli auto watch

The watch folders: their state, and a scan now

```text
Usage: antinomie-cli auto watch [OPTIONS] <COMMAND>
```

Commands:

- `antinomie-cli auto watch list`: The watch folders of the daemon: their state, the files taken and refused. Without a daemon: the folders `service.toml` names
- `antinomie-cli auto watch scan`: Scan every watch folder now (a file is still taken only after its size has been steady for 3 seconds). Needs the daemon

##### antinomie-cli auto watch list

The watch folders of the daemon: their state, the files taken and refused. Without a daemon: the folders `service.toml` names

```text
Usage: antinomie-cli auto watch list [OPTIONS]
```

##### antinomie-cli auto watch scan

Scan every watch folder now (a file is still taken only after its size has been steady for 3 seconds). Needs the daemon

```text
Usage: antinomie-cli auto watch scan [OPTIONS]
```

#### antinomie-cli auto gc

Apply retention now (recordings, run records, rejected files, staged uploads); `--dry-run` only prints the plan

```text
Usage: antinomie-cli auto gc [OPTIONS]
```

Options:

- `--dry-run`: Print what retention would delete and delete nothing

#### antinomie-cli auto delete

Delete a finished run's record and artifacts (the sample stays)

```text
Usage: antinomie-cli auto delete [OPTIONS] <RUN>
```

Arguments:

- `<RUN>`: The finished run's id (`r_...`) (required)

Options:

- `--with-recording`: Also delete the run's recording (through the same run deletion the window uses); the sample stays in the library either way
