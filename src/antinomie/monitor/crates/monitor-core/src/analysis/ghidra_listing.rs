// SPDX-License-Identifier: GPL-3.0-only
//! Ghidra's disassembly listing, exported by the same headless run as the
//! decompilation. The post-script writes one tab-separated line per function
//! start and per instruction; this module streams that text into listing rows
//! under the listing size bound, so a 128 MiB specimen never has to fit in
//! memory.
//!
//! Export lines (addresses in hex, Ghidra's own image base):
//!
//! | Line | Fields |
//! |---|---|
//! | `@@ANTINOMIE-ARCH` | language id, processor, endian, pointer bits, compiler spec |
//! | `@@ANTINOMIE-BASE` | image base, decimal (also read by the decompilation parser) |
//! | `@@ANTINOMIE-TIMEOUT`, `@@ANTINOMIE-LISTING-SIZE` | the export stopped at its time or size bound |
//! | `F` | address, size in octets, name |
//! | `I` | address, bytes (hex), mnemonic, operands, function name, label, targets, xrefs |
//!
//! `targets` and `xrefs` are comma-separated `address:kind` pairs (kind `c`
//! call, `j` jump, `d` data, `o` other).
use super::listing::{LISTING_MAX_SIZE, ListingWriter, REFERENCES_MAX};
use super::*;
use object::{Object, ObjectSection};
use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
    path::Path,
};

pub(super) const MARK_ARCH: &str = "@@ANTINOMIE-ARCH\t";
const MARK_BASE: &str = "@@ANTINOMIE-BASE\t";
const MARK_TIMEOUT: &str = "@@ANTINOMIE-TIMEOUT";
const MARK_SIZE: &str = "@@ANTINOMIE-LISTING-SIZE";
/// Longest export line read; a longer one is skipped.
const LINE_MAX: u64 = 16 * 1024;
/// Octets of export text the script writes before it stops.
pub(super) const EXPORT_MAX_SIZE: u64 = 48 * 1024 * 1024;

/// Imports of the post-script; spliced in at `//@@LISTING-IMPORTS`.
pub(super) const JAVA_IMPORTS: &str = r#"import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
"#;

/// Members of the post-script class; spliced in at `//@@LISTING-METHODS`.
/// `exportListing(path, maxBytes, budgetMillis)` is called before the
/// decompiler runs, so a decompilation that times out still leaves a listing.
pub(super) const JAVA_METHODS: &str = r#"
    private static String clean(String text) {
        return text == null ? "" : text.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    private static char kindOf(Reference reference) {
        if (reference.getReferenceType().isCall()) {
            return 'c';
        }
        if (reference.getReferenceType().isJump()) {
            return 'j';
        }
        if (reference.getReferenceType().isData()) {
            return 'd';
        }
        return 'o';
    }

    private void exportListing(String path, long maxBytes, long budgetMillis) throws Exception {
        long begin = System.currentTimeMillis();
        long written = 0;
        long count = 0;
        Listing listing = currentProgram.getListing();
        ReferenceManager references = currentProgram.getReferenceManager();
        try (PrintWriter out = new PrintWriter(new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(path), "UTF-8")))) {
            Language language = currentProgram.getLanguage();
            out.println("@@ANTINOMIE-ARCH\t" + clean(language.getLanguageID().getIdAsString()) + "\t"
                    + clean(language.getProcessor().toString()) + "\t"
                    + (language.isBigEndian() ? "big" : "little") + "\t"
                    + language.getDefaultSpace().getSize() + "\t"
                    + clean(currentProgram.getCompilerSpec().getCompilerSpecID().toString()));
            out.println("@@ANTINOMIE-BASE\t" + currentProgram.getImageBase().getOffset());
            InstructionIterator instructions = listing.getInstructions(true);
            while (instructions.hasNext() && !monitor.isCancelled()) {
                if ((count++ & 1023) == 0 && System.currentTimeMillis() - begin > budgetMillis) {
                    out.println("@@ANTINOMIE-TIMEOUT");
                    break;
                }
                if (written > maxBytes) {
                    out.println("@@ANTINOMIE-LISTING-SIZE");
                    break;
                }
                Instruction instruction = instructions.next();
                Address address = instruction.getAddress();
                Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
                boolean entry = function != null && function.getEntryPoint().equals(address);
                StringBuilder line = new StringBuilder();
                if (entry) {
                    line.append("F\t").append(Long.toHexString(address.getOffset())).append('\t')
                            .append(function.getBody().getNumAddresses()).append('\t')
                            .append(clean(function.getName())).append('\n');
                }
                String text = instruction.toString();
                int space = text.indexOf(' ');
                String mnemonic = space < 0 ? text : text.substring(0, space);
                String operands = space < 0 ? "" : text.substring(space + 1).trim();
                StringBuilder bytes = new StringBuilder();
                for (byte value : instruction.getBytes()) {
                    bytes.append(String.format("%02x", value & 0xff));
                }
                String label = "";
                if (!entry) {
                    Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
                    if (symbol != null && symbol.getSource() != SourceType.DEFAULT) {
                        label = clean(symbol.getName());
                    }
                }
                java.util.List<String> targets = new java.util.ArrayList<>();
                for (Reference reference : instruction.getReferencesFrom()) {
                    if (targets.size() >= 16) {
                        break;
                    }
                    if (reference.getReferenceType().isFallthrough()
                            || !reference.getToAddress().isMemoryAddress()) {
                        continue;
                    }
                    targets.add(Long.toHexString(reference.getToAddress().getOffset()) + ":"
                            + kindOf(reference));
                }
                java.util.List<String> sources = new java.util.ArrayList<>();
                if (references.hasReferencesTo(address)) {
                    ReferenceIterator incoming = references.getReferencesTo(address);
                    while (incoming.hasNext() && sources.size() < 16) {
                        Reference reference = incoming.next();
                        if (reference.getReferenceType().isFallthrough()
                                || !reference.getFromAddress().isMemoryAddress()) {
                            continue;
                        }
                        sources.add(Long.toHexString(reference.getFromAddress().getOffset()) + ":"
                                + kindOf(reference));
                    }
                }
                line.append("I\t").append(Long.toHexString(address.getOffset())).append('\t')
                        .append(bytes).append('\t').append(clean(mnemonic)).append('\t')
                        .append(clean(operands)).append('\t')
                        .append(function == null ? "" : clean(function.getName())).append('\t')
                        .append(label).append('\t').append(String.join(",", targets)).append('\t')
                        .append(String.join(",", sources)).append('\n');
                out.print(line);
                written += line.length();
            }
        }
    }
"#;

/// Where Ghidra says the program is, and what the listing holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ListingSummary {
    pub language: String,
    pub endian: String,
    pub pointer_bits: u32,
    pub functions: u64,
    pub instructions: u64,
    /// Why the export stopped short: empty when it is whole.
    pub note: String,
}

/// A run of object addresses that has bytes in the file.
struct FileSpan {
    address: u64,
    end: u64,
    offset: u64,
}

fn file_spans(file: &object::File) -> Vec<FileSpan> {
    let mut spans: Vec<FileSpan> = file
        .sections()
        .filter_map(|section| {
            let (offset, size) = section.file_range()?;
            (section.address() != 0 && size > 0).then(|| FileSpan {
                address: section.address(),
                end: section.address().saturating_add(size),
                offset,
            })
        })
        .collect();
    spans.sort_by_key(|span| span.address);
    spans
}

fn file_range(spans: &[FileSpan], address: u64, len: u64) -> Option<AnalysisRange> {
    let index = spans.partition_point(|span| span.address <= address);
    let span = spans.get(index.checked_sub(1)?)?;
    (address.saturating_add(len) <= span.end).then(|| AnalysisRange {
        offset: span.offset + (address - span.address),
        len,
    })
}

/// Read one bounded line; false at the end of the input. A line over
/// `LINE_MAX` is cut and its rest skipped, so it fails to parse as a row.
fn read_line(input: &mut impl BufRead, line: &mut Vec<u8>) -> std::io::Result<bool> {
    line.clear();
    let read = input.take(LINE_MAX).read_until(b'\n', line)?;
    if read == 0 {
        return Ok(false);
    }
    if line.last() != Some(&b'\n') && read as u64 == LINE_MAX {
        let mut rest = Vec::new();
        input.read_until(b'\n', &mut rest)?;
        line.clear();
    }
    Ok(true)
}

fn references(text: &str, base: Option<u64>, object_base: u64) -> Vec<AnalysisReference> {
    text.split(',')
        .filter_map(|part| {
            let (address, kind) = part.split_once(':')?;
            let address = u64::from_str_radix(address, 16).ok()?;
            Some(AnalysisReference {
                address: rebase(address, base, object_base),
                kind: match kind {
                    "c" => AnalysisReferenceKind::Call,
                    "j" => AnalysisReferenceKind::Jump,
                    "d" => AnalysisReferenceKind::Data,
                    _ => AnalysisReferenceKind::Other,
                },
            })
        })
        .take(REFERENCES_MAX)
        .collect()
}

/// Map an address of Ghidra's own load back to the object's addresses (a
/// rebased image reports addresses relative to Ghidra's base).
fn rebase(address: u64, base: Option<u64>, object_base: u64) -> u64 {
    match base {
        Some(base) => address.wrapping_sub(base).wrapping_add(object_base),
        None => address,
    }
}

fn spaced_hex(compact: &str) -> String {
    let mut text = String::with_capacity(compact.len() * 3 / 2);
    for (index, pair) in compact.as_bytes().chunks(2).enumerate() {
        if index > 0 {
            text.push(' ');
        }
        text.push_str(&String::from_utf8_lossy(pair));
    }
    text
}

fn location(address: u64, file_range: Option<AnalysisRange>) -> Option<AnalysisLocation> {
    Some(AnalysisLocation {
        kind: AnalysisAddressKind::ObjectAddress,
        value: address,
        file_range,
    })
}

/// Stream Ghidra's export at `export` into the Disassembly-kind listing
/// `ghidra-disassembly.jsonl` in `listings`. `object_base` is where the
/// object's addresses start (see `decompile::object_base`).
pub(super) fn write_listing(
    listings: &Path,
    export: &Path,
    specimen: &[u8],
    object_base: u64,
) -> Result<(AnalysisListing, ListingSummary), String> {
    write_listing_with(listings, export, specimen, object_base, LISTING_MAX_SIZE)
}

/// [`write_listing`] under a smaller size bound.
fn write_listing_with(
    listings: &Path,
    export: &Path,
    specimen: &[u8],
    object_base: u64,
    limit: u64,
) -> Result<(AnalysisListing, ListingSummary), String> {
    let mut writer =
        ListingWriter::create_named(listings, super::listing::GHIDRA_DISASSEMBLY_FILE, limit)?;
    let spans = object::File::parse(specimen)
        .map(|file| file_spans(&file))
        .unwrap_or_default();
    let mut input = BufReader::new(File::open(export).map_err(|e| format!("Ghidra listing: {e}"))?);
    let mut summary = ListingSummary::default();
    let mut base = None;
    let mut line = Vec::new();
    let mut full = false;
    while read_line(&mut input, &mut line).map_err(|e| format!("Ghidra listing: {e}"))? {
        let Ok(text) = std::str::from_utf8(&line) else {
            continue;
        };
        let text = text.trim_end_matches(['\n', '\r']);
        if let Some(rest) = text.strip_prefix(MARK_ARCH) {
            let mut fields = rest.split('\t');
            summary.language = fields.next().unwrap_or("").to_owned();
            let _processor = fields.next();
            summary.endian = fields.next().unwrap_or("").to_owned();
            summary.pointer_bits = fields.next().and_then(|b| b.parse().ok()).unwrap_or(0);
        } else if let Some(rest) = text.strip_prefix(MARK_BASE) {
            base = rest.trim().parse::<u64>().ok();
        } else if text.starts_with(MARK_TIMEOUT) {
            summary.note = "Ghidra's time budget for the listing ran out".into();
        } else if text.starts_with(MARK_SIZE) {
            summary.note = "Ghidra's listing reached its size bound".into();
        } else if let Some(rest) = text.strip_prefix("F\t") {
            let mut fields = rest.splitn(3, '\t');
            let address = fields.next().and_then(|a| u64::from_str_radix(a, 16).ok());
            let size = fields.next().and_then(|s| s.parse::<u64>().ok());
            let (Some(address), Some(size), Some(name)) = (address, size, fields.next()) else {
                continue;
            };
            let address = rebase(address, base, object_base);
            summary.functions += 1;
            if !writer.push(
                name,
                name,
                location(address, None),
                AnalysisData::Function {
                    name: name.to_owned(),
                    address,
                    size,
                },
            ) {
                full = true;
                break;
            }
        } else if let Some(rest) = text.strip_prefix("I\t") {
            let fields: Vec<&str> = rest.split('\t').collect();
            let [
                address,
                bytes,
                mnemonic,
                operands,
                function,
                label,
                targets,
                xrefs,
            ] = fields[..]
            else {
                continue;
            };
            let Ok(address) = u64::from_str_radix(address, 16) else {
                continue;
            };
            if bytes.len() % 2 != 0 || !bytes.bytes().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            // Twenty octets show; no real instruction is longer.
            let bytes = &bytes[..bytes.len().min(40)];
            let address = rebase(address, base, object_base);
            let value = if operands.is_empty() {
                mnemonic.to_owned()
            } else {
                format!("{mnemonic} {operands}")
            };
            summary.instructions += 1;
            if !writer.push(
                function,
                value,
                location(
                    address,
                    file_range(&spans, address, (bytes.len() / 2) as u64),
                ),
                AnalysisData::Instruction {
                    address,
                    bytes: spaced_hex(bytes),
                    mnemonic: mnemonic.to_owned(),
                    operands: operands.to_owned(),
                    function: (!function.is_empty()).then(|| function.to_owned()),
                    label: (!label.is_empty()).then(|| label.to_owned()),
                    targets: references(targets, base, object_base),
                    xrefs: references(xrefs, base, object_base),
                },
            ) {
                full = true;
                break;
            }
        }
    }
    if full {
        summary.note = format!(
            "The listing reached its {} limit; later code is not listed",
            crate::byte_size::short_size(limit)
        );
    }
    let listing = writer.finish(full || !summary.note.is_empty())?;
    Ok((listing, summary))
}

#[cfg(test)]
mod tests;
