# Triage report export

[← Back to the overview](../README.md)

**Export report…** (the button at the right of the Triage tab row) writes the
whole Triage of the selected run as a report. It needs the run's saved
recording. The report is of the whole run, not of what the tables show: the
export reads the recording again with every filter, sort and page cleared. The
one default it keeps is Triage's: Hide stdio and Hide library are on, and
failed attempts are not listed as changes. Each Triage table keeps at most
2 000 rows per tab; the report says how many more matched (`omitted`).

Nothing in a report is a verdict. The Summary states what Triage observed (for
example "1 indicator matched a stored dataset", "the worst rule fired at HIGH
tier") and says so.

## The dialog

| Control | Meaning |
|---|---|
| Sections | One checkbox each: Summary, Indicators of compromise, ATT&CK techniques, Processes, Suspicious activity, Files (every tab), File activity and reconstruction, Network, Detection engines, Evidence references, Custody log head. An unchecked section is absent from every format. |
| Formats | HTML, PDF, JSON, MISP, STIX 2.1. |
| Evidence bundle | A `.zip` next to the report (see below). |
| Defang indicators | HTML and PDF only: `hxxp://example[.]com`, `203[.]0[.]113[.]5`. JSON, MISP and STIX keep raw values. |
| Folder | Where the files go. Empty means `<recording>/report/`. |

The choices are remembered between exports. Files are never overwritten (a
counter is added to the name), are owner-only (0600) and are named
`antinomie-report-<run>-<yyyymmdd-hhmmss>` plus `.html`, `.pdf`, `.json`,
`.misp.json`, `.stix.json` or `-evidence.zip`.

## Formats

- **HTML** is one self-contained file: inline CSS (light and dark by
  `prefers-color-scheme`, print styles), no script, no link and no reference to
  another file or address. It is also well-formed XML.
- **PDF** is the same layout on A4 landscape pages: the same sections in the
  same order, tables with repeated header rows, bookmarks per section, page
  numbers and the document title. It is written by Antinomie itself with the
  standard Helvetica and Courier fonts: no browser, no network and no embedded
  font. Characters outside Latin-1 (and the few Windows-1252 extras) print as
  `?` in the PDF; the JSON keeps them. A table cell is cut after 24 lines.
  HTML and PDF show at most 1 000 rows per table; the JSON keeps all the rows
  the index held.
- **JSON** is the versioned machine-readable form, described below.
- **MISP** is one event in MISP's core format (`{"Event": {...}}`): the sample
  as `sha256` and `filename`, each indicator as an attribute (`ip-dst|port`,
  `domain`, `url`, `hostname`, `ja3-fingerprint-md5`, `x509-fingerprint-sha1`,
  `sha256`, `filename|sha256`) with `to_ids` true only for indicators a stored
  dataset matched, a `misp-galaxy:mitre-attack-pattern="Name - Txxxx"` tag and
  a `Galaxy`/`GalaxyCluster` entry per ATT&CK technique. The event is
  unpublished with distribution 0 (your organisation only). The cluster uuids
  are derived from the technique id; MISP matches clusters by their tag name
  when its ATT&CK galaxy is loaded. URL indicators carry the cleartext scheme
  `http://`, since only cleartext HTTP is indexed as a URL. Each matching
  detection rule is a `comment` attribute that names the rule, its author,
  licence and source.
- **STIX 2.1** is a bundle: an `identity`, the sample as a `file` and a
  `malware` object, a `malware-analysis` (result `suspicious` when an indicator
  matched or a HIGH or MEDIUM rule fired, else `unknown`), an `indicator` for
  each indicator that STIX can pattern (endpoint, domain, URL, TLS server name
  or certificate hash, file hash; JA3 and JA4 have no standard pattern and are
  left out), an `attack-pattern` with a `mitre-attack` external reference for
  each technique, and `relationship`s (indicator `indicates` malware, malware
  `uses` attack-pattern), and a `note` for each matching detection rule that
  names the rule's author, licence and source. Object ids are version-5 UUIDs of the content, so a
  second export of the same run has the same ids.

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
- `manifest.json` (every file with its size and SHA-256, the dropped files and
  their entries, what was skipped) and `manifest.sha256`
  (`sha256sum -c` format; extract the bundle and run
  `sha256sum -c manifest.sha256`).

## JSON schema, version 1

`docs/triage-report-schema-1.json` is the JSON Schema (2020-12). Every export
has `schema` = `antinomie-triage-report` and `schema_version` = 1. The version
changes only when a field changes meaning or goes away; a new optional field
does not change it, so read with unknown fields ignored.

| Key | Content |
|---|---|
| `generated_ms`, `app`, `run` | When, by which version, for which run (`vm_id`, `boot_id`, `run_id`, `started_ms`, `finished`). |
| `sample` | `name`, `sha256`, `size` of the sample the run executed, when known. |
| `summary` | `assessment` (`matched_indicators`, `suspicious_behaviour`, `observed_only`, `no_findings`), `statement`, `highest_tier`, `families` (named by dataset matches), `key_behaviours` (HIGH and MEDIUM rules), `counts`. |
| `indicators` | `kind` (`endpoint`, `domain`, `url`, `tls`, `file`), `value`, the dataset answer (`verdict`, `matched`, `dataset`, `record_id`, `family`, `confidence`, `reference`), where it was seen, and per kind `url`, `sni`/`ja3`/`ja4`/`cert_sha1`, `sha256`/`md5`/`sha1`/`path`. Raw values. |
| `attack` | Techniques the run's rules cite: `id`, `name`, `rules`, `count`. |
| `processes`, `findings` | A table: `columns`, `rows` (text), `omitted`, `indicator_columns`. |
| `files` | `tabs`: one named table for each Files tab. |
| `file_activity` | Per created or changed file: `path`, `created`, `changed`, `deleted`, `final_size`, `guest_sha256`, `reconstruction` (`complete` or `incomplete`), `bytes_written`, `bytes_not_captured`, `bytes_unknown`, `bundle_entry`. |
| `network` | Named tables: Endpoints, Domains, URLs, TLS. |
| `detections` | Matches of the YARA, IDS and Sigma engines whose reports are complete (from the run's Triage digest): `engine`, `rule_id`, `title`, `severity`, `mitre`, `count`, and the rule's `author` (as the rule gives it), `license`, `source` (the rule pack) and `reference` (the rule's own link). A rule's licence asks that its author stay with every message that reports a match, so every format carries them (the HTML and PDF write the reference without its scheme, as they hold no links). |
| `evidence` | The run folder's files and folders: `kind`, `path`, `size`, `sha256` (files up to 64 MiB). |
| `custody` | The sample's custody log head hash, entry count and whether the chain verified. |
| `notes` | What the report could not say. |

A part that was not chosen is `null`. `tests/monitor/test-report-export.py`
checks an export of a recorded fixture run with the OASIS `stix2` library,
`jsonschema`, `qpdf`, `xmllint` and `7z`.
