# Sample report export

[← Back to the overview](../README.md)

**Export report…** (in a sample's header in Library > Samples, and in the
right-click menu of a row of the Samples list) writes a report of one library
sample. It reads the sample the way its window does (the library record, every
VM's runs of it, the newest finished static report, the runs' Triage digests,
the lineage, the custody log, the notes) and compares it with the rest of the
library. The report is built once and written in the formats you tick.

Nothing in a report is a verdict. The per-run assessment is the run report's:
`matched_indicators`, `suspicious_behaviour`, `observed_only`, `no_findings`,
or `not_read` for a run Triage has not read. A report never holds the sample's
bytes: the sample is named by its hashes, similar samples by hash and a count
of what they share, and FLOSS strings are cut to 160 characters (100 listed).

## Contents

Identity (hashes, type, size, names, tags, origins, first and last seen), static
analysis (every check with its state and reason, packer and unpack layers,
capa capabilities, FLOSS strings), rules that matched (the static YARA scan and
the runs' YARA, Sigma and IDS reports, each with author, licence, source and
reference), every run (start, exit, assessment, tier, counts, the path of the
run's own Triage report when it has been exported), lineage (parents and
children with hashes, or the reason there are none), indicators merged across
the runs (with how each was observed, first and last seen, whether every run had it, and the
dataset records that list it, as in the sample window's IOCs tab), ATT&CK techniques
(with their tactics), the custody log with its verification result,
notes, and similar samples.

## Formats

- **HTML** and **PDF** use the run report's page model and writers: one
  self-contained file, no script. Each rule's row is an anchor (`det-…`, as
  in the run report), each run's `run-<n>` and each indicator's `ioc-<n>`;
  a rule's runs, an indicator's runs and a technique's rules link to them. A
  run's own report (the export with the most sections, the newest of those) is
  named by its path inside the data folder and, in the HTML and Markdown,
  linked relative to the data folder's `sample-reports` folder, where the
  report is written unless you choose another.
- **Markdown** is the same document as pipe tables with the same anchors
  (`<a id>`) and links; text is escaped, hashes and paths are code spans.
- **JSON** is `docs/sample-report-schema-1.json` (`antinomie-sample-report`,
  `schema_version` 1). New optional fields do not change the version.
- **MISP** is one event: the sample's `sha256`, `sha1`, `md5`, `tlsh`,
  `filename`, `size-in-bytes` (the hashes `to_ids` only when a run was
  suspicious, a dataset matched or a rule named a family), parents and children
  by hash, the merged indicators (`to_ids` only for those a dataset matched), a
  `comment` per rule
  with its credit, per-run comments, the custody head, and an ATT&CK galaxy
  cluster per technique.
- **STIX 2.1** is a bundle: identity, the sample as `file` and `malware` (a
  family `malware` it is a `variant-of`), a `malware-analysis`, parent and
  child `file`s, `indicator`s with `indicates` relationships, `attack-pattern`s,
  a `note` per rule that names its author, licence and source, and a `note`
  with the custody head.

## Options

HTML, PDF and Markdown defang indicators by default (`hxxp://example[.]com`);
untick the option for raw values. JSON, MISP and STIX always keep raw values.
Row caps: HTML, PDF and Markdown show at most 1 000 rows per table; every list
keeps at most 5 000 rows; both say how many were left out.

Files go to the folder you give (empty: `<data folder>/sample-reports/`), are
never overwritten, are owner-only (0600), and are named
`antinomie-sample-report-<sha8>-<yyyymmdd-hhmmss>Z` (the time is UTC) plus the format's ending.
No format carries a path on this computer: the custody log's "added", "original deleted" and "recorded before" entries and the Origins table name the file, not its folder. A rule the static scan and a run both matched is one row ("static scan + runs 1, 4"), and a sample with no recorded family lists the families its matched rules name. The Rules table says how much each match says in the run report's words (`strong (score 100)`, `weak`, `Sigma high`), names the family a rule names, leaves Title out when it repeats the rule, and lists each rule's author, licence, pack and reference in a credits table under it. The merged indicators say whether MISP and STIX carry each one.
Writing them adds an `Exported` entry to the sample's custody log (after the
head the report shows).

`tests/monitor/test-sample-report-export.py` checks an export of a fixture
sample with `jsonschema`, `stix2`, `qpdf` and an XML parser.
