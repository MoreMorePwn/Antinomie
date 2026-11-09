# Triage report export

[← Back to the overview](../README.md)

**Export report…** (the button at the right of the Triage tab row) writes the
whole Triage of the selected run as a report. It needs the run's saved
recording. The report is of the whole run, not of what the tables show: the
export reads the recording again with every filter, sort and page cleared. The
one default it keeps is Triage's: Hide stdio and Hide library are on, and
failed attempts are not listed as changes. Each Triage table keeps at most
2 000 rows per tab (**Settings > Advanced > Triage: rows per table**, 100 to
100 000); the report says how many more matched (`omitted`) and reads "First
2,000 of 10,897 rows".

Nothing in a report is a verdict. The Summary states what Triage observed (for
example "1 indicator matched a stored dataset", "the worst rule fired at HIGH
tier") and says so.

## The dialog

| Control | Meaning |
|---|---|
| Sections | One checkbox each: Summary, Indicators of compromise, ATT&CK techniques, Processes, Suspicious activity, Files (every tab), File activity and reconstruction, Network, Detection engines, Evidence references, Custody log head. An unchecked section is absent from every format. |
| Formats | HTML, PDF, Markdown, JSON, MISP, STIX 2.1. |
| Evidence bundle | A `.zip` next to the report (see below). |
| Defang indicators | On by default, like the sample report's. HTML and PDF only: `hxxp://example[.]com`, `203[.]0[.]113[.]5`. JSON, MISP and STIX keep raw values. |
| Folder | Where the files go. Empty means `<recording>/report/`. |

The window's title names the sample and the first eight characters of the run
it writes (`Export report: elf-9701ae72 [43b0b44a]`). It stays bound to that
run: pick another run in Triage with the window open and it follows the new
run (its list of written files is cleared), so Export always writes the run in
its title. The window sits where it opened, so its close button does not move
as the list of written files appears; **Close** and Escape close it, and its
✕ and Escape do nothing while an export is writing (**Cancel** stops it). The
list of written files shows every file, with the folder, **Copy path** and
**Open folder**. After an export, **Export** stays off until a choice changes,
so one click never writes a second set.

While the report is being made the window says what it is doing and for how
long: `Indexing the telemetry: 1.2 GiB of 3.3 GiB (36%)`, `Reading the calls,
pass 1 of 2: 82,000 of 1,791,320 (4%)`, then `Building the report...`. When
Triage has already indexed the whole run (no filter, sort or page set on its
tables) and the recording has not changed since, the export builds from that
index and says `Using the index Triage already made...`; it does not read the
recording a second time. Cancel stops at the next step and the files are not
written.

A run that never started (the guest refused the launch, the Tor route did not
come up) has no recording: it is in the run picker as `(not started)`, Triage
shows why, and **Export report…** there writes a short report with the failure,
the request, the route, the static analysis there is and the sample's identity,
in HTML, PDF, Markdown, JSON, MISP or STIX (Formats, Defang and Folder only).
The failure is said once ("Not started: the Tor route did not become ready in
120 s"); the route's log and its last lines are a separate "Failure detail"
note. Only paths on this computer are cut to their file name; the guest paths
of the request (`/proc/net/tcp`, `/etc/shadow`) stay whole. MISP and STIX of
such a run carry the sample as a file and a note that the run did not start: no
`malware` or `malware-analysis` object, `to_ids` off, and the MISP tag
`antinomie:assessment="not_started"`.

The choices are remembered between exports. Files are never overwritten (a
counter is added to the name), are owner-only (0600) and are named
`antinomie-report-<run>-<yyyymmdd-hhmmss>Z` (the time is UTC) plus `.html`, `.pdf`, `.md`,
`.json`, `.misp.json`, `.stix.json` or `-evidence.zip`.

## From the command line

`antinomie-cli report RUN` writes the same report with no window (see "Command
line" in [usage](usage.md)): it indexes the whole run the way Triage does when
the run is selected and runs the same export job as the dialog, so for the same
run and choices the files are the same, apart from the time they were made.
`--formats`, `--parts`, `--evidence-bundle`, `--defang` or `--no-defang`,
`--include-content` and `--out DIR` are the dialog's choices; what is not given
comes from the export choices the window keeps in the data directory's
`settings.json`. The files go to `--out` (default `report-<first 8 characters of
the run id>` in the current folder), not into the recording. Detections are in
the report when the run's Detection tab, or `antinomie-cli detect RUN --save`,
has scanned it.

## What a report holds, in order

1. **At a glance**: the sample, its SHA-256 and size, the family (a link to its
   evidence), how the run ended, when and for how long, the route, base image,
   kernel and guest architecture; then the Summary's statement, the findings by tier (each count
   opens Suspicious activity; INFO findings the index does not list are counted
   and said), what was observed (each count opens its section), the **Key
   findings** table (# is the row's own number; a row links to its finding, and
   folded findings of one rule to their shared row; Tier, Rule, Behaviour, Object, Process, Count, First
   seen, ATT&CK; up to 10, worst first), the **Family evidence** table (Family,
   Engine, Rule, Pack, Strength, Count), the key behaviours, up to eight
   indicators worth sharing, and the notes about the run.
2. **Indicators of compromise**: the ones MISP and STIX carry first, then the
   ones they leave out with the reason; a Tor stand-in address names the domain
   it stands for.
3. **ATT&CK techniques**, 4. **Processes** (with the parent, the files each
   wrote and the findings in it), 5. **Suspicious activity** (a rule that fired
   four times or more with one tier and result is one row with the count, the
   first object and process and how many others; the JSON lists every finding),
   6. **Files** (what the run wrote or changed first, with its lifecycle and
   reconstruction, then Executed, Created, Deleted, Renamed, Written,
   Attributes, Opened, Read, Metadata probed and Other; empty tabs are one
   line), 7. **Network** (Endpoints with the name a stand-in address stands for
   and no country for private and reserved addresses, Domains, URLs, TLS),
   8. **Detection engines** (one strength vocabulary, the family a rule names,
   and the credits each rule's licence asks for in a table under it),
   9. **Evidence references**, 10. **Custody log**, 11. **Notes**, and an
   **Appendix: Environment** (rule packs and tools one per row with their full
   versions).

Times in tables read `+5.463 s · 17:38:21.480`: the time since the run's first
call, then the time of day; the date and the zone are said once at the top.

## Links inside a report

Every entry is an anchor and every mention of it a link, in the HTML, the PDF
and the Markdown: a process `proc-<pid>` (`proc-<pid>-2` for a second process
with the same pid), a file `file-<12 hex digits of its path's hash>` (by path:
one hash can sit at many paths), an endpoint `ep-<address>-<port>`, a domain
`dom-<name>`, a behaviour rule `rule-<id>` (on its first finding), a finding
`finding-<n>`, a detection `det-<engine>-<rule>`, a technique
`attack-<Txxxx>` and an indicator `ioc-<n>`. A key finding links to its row,
its process, its object and its techniques; a path in any Files tab links to
the file's entry (its first row: what the run wrote, else the first tab that
lists it); a process, a file, an endpoint and an indicator list the findings
about them. A link whose entry is not in the document (a section left out, a
row past the cap) is plain text, so no link is ever dangling. The PDF has a
**Contents** block with the page of each section and of every sub-heading in it
(the same entries as the bookmarks), every entry is a named destination, and every link a link annotation; the
HTML highlights the row a link jumps to; the Markdown uses `<a id>` anchors and
`[text](#id)` links (GitHub keeps both). The JSON carries the same ids (`id`)
and links (`*_ref`, `*_refs`), and each one names an id of the same file.

## Formats

- **HTML** is one self-contained file: inline CSS (light and dark by
  `prefers-color-scheme`, print styles), no script, and no link or reference to
  another file or address; its only links are to its own anchors. Rule
  references are written without their scheme (the JSON, MISP and STIX keep
  them whole). It is also well-formed XML.
- **Markdown** is the same document as GitHub-flavoured pipe tables, with the
  same anchors and links.
- Column titles in the HTML and PDF tables never break inside a word: a title wraps
  only at spaces, a table whose longest words side by side are wider than a page
  takes a smaller font a step at a time and, as a last resort, is split into column
  groups with its first column repeated. The ATT&CK section has a **Tactic** column
  (named in text, with the colour as a chip in HTML and a bar in PDF).
- A run that used nine tenths of its recording quota says "Recording quota
  reached at <time>; from then on only suspicious-activity calls were kept, N calls
  dropped" as information, and the report no longer says the recording "was still
  being written" after the run ended; it names what is missing. A note lists each
  kind of call the guest recorded without decoding an argument ("ioctl request
  0x5421 (arg2.ioctl) x200"), and when every process ended within 10 s the summary
  says "The sample's process tree ended after N ms (P processes). Last failing step:
  ..." with the last refused create, write, delete, rename, link, permission change
  or exec.
- **PDF** is the same layout on A4 landscape pages: a contents block, the same
  sections in the same order, internal links, tables with repeated header rows,
  bookmarks per section, page
  numbers and the document title. It is written by Antinomie itself with the
  standard Helvetica and Courier fonts: no browser, no network and no embedded
  font. Characters outside Latin-1 (and the few Windows-1252 extras) print as
  `?` in the PDF, except a few symbols that have a plain spelling (`->` for the
  arrow of a lifecycle cell, `~`, `<=`, `>=`); the JSON keeps them all. A table
  cell is cut after 24 lines; a long rule name or path breaks after a `_`,
  `/`, `.`, `-` or `:` rather than inside a word. HTML and PDF show at most 1 000 rows per table
  (200 for each Files tab, where identical rows are folded into one with a
  count and the first and last time); the JSON keeps all the rows the index held.
  The PDF has the report's kind, subject and keywords in its properties, a
  running header after the first page, and "Generated <time> - Page N of M" as
  its footer. The title names the family, the highest tier and the run
  (`Antinomie Triage report: elf-fd1b20ee5bd4 - BPFDoor · HIGH · run f9c3d854`).
- Times in a document are in the zone the app shows (the overview says which),
  with the date; a time marked `~` is estimated from the guest clock and `+N s`
  is the time since the run's first call. Every table writes a time as
  `+5.463 s · 17:38:21.480` (the Network and Indicators tables too). File names carry the UTC time and a
  trailing `Z`.
- The overview says how the run ended in the app's words ("Stopped by you at 6
  min 25 s · root exited 0", "Ran for 1 min 20 s · exit 255", "Ended by VM
  stop"), when and for how long, what it ran (the sample, or the command when the
  run started a program that is not a library sample, with a preloaded library
  named as such) and the environment it was recorded on (base image, kernel,
  VM, stealth profile, route, rule packs, tools). The Summary names the families
  the way Triage's Summary does (Elastic and curated rule names, `family`
  metadata, IDS messages, the sample's MalwareBazaar record), counts findings by
  tier and lists the key findings. The Files > Read files table keeps the size of
  each read, not what was read.
- **JSON** is the versioned machine-readable form, described below.
- **MISP** is one event in MISP's core format (`{"Event": {...}}`): the sample
  as a `file` object (`sha256`, `filename`, `size-in-bytes`; `to_ids` only when
  a dataset matched or a rule named a family), an `antinomie:family="..."` tag
  for each family the report names (the strongest; a family fewer or weaker
  rules named is only said in the document and the JSON's
  `summary.other_families`), each indicator as an attribute (`ip-dst|port`,
  `domain`, `url`, `hostname`, `ja3-fingerprint-md5`, `x509-fingerprint-sha1`,
  `sha256`, `filename|sha256`; a hash seen through a folder such as `/tmp`, with
  no file name of its own, is `sha256` alone) with `to_ids` true only for indicators a stored
  dataset matched, a `misp-galaxy:mitre-attack-pattern="Name - Txxxx"` tag and
  a `Galaxy`/`GalaxyCluster` entry per ATT&CK technique. The event is
  unpublished with distribution 0 (your organisation only). The cluster uuids
  are derived from the technique id; MISP matches clusters by their tag name
  when its ATT&CK galaxy is loaded. URL indicators carry the cleartext scheme
  `http://`, since only cleartext HTTP is indexed as a URL. Each matching
  detection rule is a `comment` attribute that names the rule (without the
  pack's `sNNN::` number), its author, licence and source.
- **STIX 2.1** is a bundle: an `identity`, the sample as a `file` and a
  `malware` object, a `malware-analysis` (result `suspicious` when an indicator
  matched or a HIGH or MEDIUM rule fired, else `unknown`), an `indicator` for
  each indicator that STIX can pattern (endpoint, domain, URL, TLS server name
  or certificate hash, file hash; JA3 and JA4 have no standard pattern and are
  left out), an `attack-pattern` with a `mitre-attack` external reference for
  each technique, and `relationship`s (indicator `indicates` malware, malware
  `uses` attack-pattern), a `note` for each matching detection rule that
  names the rule's author, licence and source, and a `report` that lists the
  objects. When the rules name a family, the `malware` object is that family
  (`is_family` true) and the sample is its `file`. Object ids are version-5
  UUIDs of the content, so a second export of the same run has the same ids; an
  indicator pattern appears once, with the paths it was seen at in its
  description. MISP and STIX carry only indicators a consumer can match: the
  guest's own resolver, the Tor gateway's stand-in addresses (198.18.0.0/15; the
  name they stand for is the indicator), other private addresses, files with no
  content kept and programs of the base image the run only started stay in the
  document and the JSON (`not_shared` says why) but not in these two.

## Evidence bundle

`<name>-evidence.zip` (not encrypted, so its manifest can be read) holds:

- `capture/` the run's packet captures, unchanged;
- `dropped-files.zip`: the files the run created or changed whose bytes the
  recording holds completely, named `<sha256>.bin`, with `files.json` mapping
  each to its guest path. The archive is **AES-256 (WinZip AE-2) with the
  password `infected`**, the same convention and encryption the sample library
  uses. 7-Zip, p7zip, WinZip and `pyzipper` open it; Info-ZIP `unzip` and
  Python's `zipfile` cannot read AES. At most 64 MiB per file and 512 MiB in
  all; a file over a limit, or with bytes the recording does not hold, is
  listed in the manifest as skipped, with the reason;
- `custody/` the sample's custody record as JSON, with its verifier script
  (the same export the Samples page makes; the export is noted in the custody
  log);
- `README.txt` (what each file is, how to check the manifest, the password, and why the archive's member times are zero);
- `manifest.json` (every file with its size and SHA-256, the dropped files and
  their entries, what was skipped) and `manifest.sha256`
  (`sha256sum -c` format; extract the bundle and run
  `sha256sum -c manifest.sha256`).

## JSON schema, version 2

`docs/triage-report-schema-2.json` is the JSON Schema (2020-12). Every export
has `schema` = `antinomie-triage-report` and `schema_version` = 2. The version
changes only when a field changes meaning or goes away; a new optional field
does not change it, so read with unknown fields ignored. Version 2 changed
`summary.key_findings` from sentences to objects (the sentences are
`summary.key_findings_text`, for one version) and `summary.families` to the
families the report names (the others are `summary.other_families`), and added
the anchors and links. `docs/triage-report-schema-1.json` describes version 1.

| Key | Content |
|---|---|
| `generated_ms`, `app`, `run` | When, by which version, for which run (`vm_id`, `boot_id`, `run_id`, `started_ms`, `finished`, and when known `state` in the app's words, `exit`, `stopped_by_user`, `ended_ms`, `duration_ms`, `command`, `route`, `environment` as name and value pairs). |
| `sample` | `name`, `sha256`, `size` of the library sample the run executed, when there is one; `role` is `preloaded library` when the run started another program with this library in `LD_PRELOAD`. A run that started a command which is no library sample has `null` and `run.command`. |
| `summary` | `assessment` (`matched_indicators`, `suspicious_behaviour`, `observed_only`, `no_findings`), `statement`, `highest_tier`, `families` (the families the report names) with `family_sources` (who named each) and `other_families`, `tiers` (findings by tier as the app counts them; `info_not_listed` INFO findings are not in `findings`), `key_findings` (objects: `tier`, `rule`, `title`, `target`, `process`, `pid`, `cookie`, `count`, `first_ms`, `relative_ms`, `attack`, `why`, `finding` and the links `finding_ref`, `process_ref`, `target_ref`, `attack_refs`), `key_findings_text`, `key_findings_total`, `key_behaviours` (HIGH and MEDIUM rules), `counts`. |
| `indicators` | `id` (`ioc-<n>`), `kind` (`endpoint`, `domain`, `url`, `tls`, `file`), `value`, the dataset answer (`verdict`, `matched`, `dataset`, `record_id`, `family`, `confidence`, `reference`), where it was seen (`pids`), and per kind `url`, `sni`/`ja3`/`ja4`/`cert_sha1`, `sha256`/`md5`/`sha1`/`path`, `stand_in` (the name a Tor stand-in address was handed out for), `not_shared` (why MISP and STIX leave it out) and `base_noise` (the reason, when the row is the base image's own clock sync, DHCP, apt traffic or the guest's resolver; such rows are left out of the document tables, MISP and STIX); `target_ref`, `process_refs`, `finding_refs`. Raw values. |
| `attack` | Techniques the run's rules cite: `id`, `name`, `rules`, `count`, `rule_refs` (one per rule: its first finding's `rule-…` or its detection's `det-…`). |
| `processes`, `findings` | A table: `columns`, `rows` (text), `omitted`, `indicator_columns`, and `data`: one object per row with its `id`, typed values (`pid`, `cookie`, `parent_pid`, `depth`, `time_ms`, `relative_ms`, `last_ms`, `last_relative_ms`, `count`, `bytes`, `path`, `endpoint`, `domain`, `rule`, `tier`, `target`, `attack`) and links (`process_ref`, `parent_ref`, `target_ref`, `domain_ref`, `endpoint_refs`, `attack_refs`, `finding_refs`, `file_refs`). Empty values are left out. In `processes` the first cell is the process alone: the tree is the row order and `depth` (the documents indent a child under its parent). The Network tables carry the same typed times (`time_ms`, `relative_ms` for the first packet, `last_ms`, `last_relative_ms` for the last). |
| `files` | `tabs`: one named table for each Files tab. |
| `file_activity` | Per created or changed file: `id`, `path`, `created`, `changed`, `deleted`, `final_size`, `guest_sha256`, `reconstruction` (`complete` or `incomplete`), `bytes_written`, `bytes_not_captured`, `bytes_unknown`, `bundle_entry`, `process_ref`, `finding_refs`. |
| `network` | Named tables: Endpoints, Domains, URLs, TLS. The Endpoints table has a `Source` column: the process that made the flow as `name (pid · tid)`, `Base image background: NTP` (or DHCP, apt) or `Unattributed`, matched on the host from the run's recorded network calls. A row whose Source names a process also carries its `pid` and `cookie` in `data` and a `process_ref` to that process, and the HTML and PDF link the cell. |
| `detections` | Matches of the YARA, IDS and Sigma engines whose reports are complete (from the run's Triage digest): `id`, `engine`, `rule_id`, `title`, `severity`, `mitre`, `count`, and the rule's `author` (as the rule gives it), `license`, `source` (the rule pack) and `reference` (the rule's own link), for YARA `strength` (`strong`, `weak`, `wrong platform`), `family` (the family the rule names) and `attack_refs`. A rule's licence asks that its author stay with every message that reports a match, so every format carries them (the HTML and PDF show the pack's own `sNNN::` number only in the JSON). |
| `evidence` | The run folder's files and folders: `kind` (`telemetry`, `network capture`, `static analysis`, `ebpf programs`, ...), `path`, `size`, `sha256` (files up to 64 MiB), `files` (a folder's file count). |
| `custody` | The sample's custody log head hash, entry count and whether the chain verified. |
| `notes` | What the report could not say. |

A part that was not chosen is `null`. `tests/monitor/test-report-export.py`
checks an export of a recorded fixture run with the OASIS `stix2` library,
`jsonschema`, `qpdf`, `xmllint` and `7z`.
