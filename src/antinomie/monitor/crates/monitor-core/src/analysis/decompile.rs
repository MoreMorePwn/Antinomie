// SPDX-License-Identifier: MIT
//! Decompilation through a locally installed decompiler: Ghidra headless
//! when present, otherwise radare2's pseudo-code. Each function becomes a
//! header row followed by one row per source line.
use super::listing::{LISTING_MAX_SIZE, ListingWriter};
use super::tools;
use super::*;
use object::{Object, ObjectSegment};
use std::{collections::BTreeMap, fs, path::Path, time::Duration};

const GHIDRA_MANAGED: &str = "/opt/antinomie-tools/ghidra/ghidra/support/analyzeHeadless";
/// The JDK installed next to an Antinomie-installed Ghidra.
const MANAGED_JDK: &str = "/opt/antinomie-tools/ghidra/jdk";
const MARK_FUNCTION: &str = "@@ANTINOMIE-FUNCTION\t";
const MARK_BASE: &str = "@@ANTINOMIE-BASE\t";
const MARK_TIMEOUT: &str = "@@ANTINOMIE-TIMEOUT";

/// Ghidra post-script: decompile every function within a time budget.
const GHIDRA_SCRIPT: &str = r#"// SPDX-License-Identifier: MIT
// Antinomie: export Ghidra's decompilation of every function as plain text.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;

public class AntinomieExport extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        long budget = Long.parseLong(args[1]) * 1000L;
        long start = System.currentTimeMillis();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(args[0]), "UTF-8")))) {
            out.println("@@ANTINOMIE-BASE\t" + currentProgram.getImageBase().getOffset());
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                if (System.currentTimeMillis() - start > budget) {
                    out.println("@@ANTINOMIE-TIMEOUT");
                    break;
                }
                Function function = functions.next();
                if (function.isThunk() || function.isExternal()) {
                    continue;
                }
                out.println("@@ANTINOMIE-FUNCTION\t" + function.getEntryPoint().getOffset() + "\t"
                        + function.getBody().getNumAddresses() + "\t" + function.getName());
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                if (result != null && result.decompileCompleted()) {
                    out.println(result.getDecompiledFunction().getC());
                } else {
                    out.println("// decompilation failed: "
                            + (result == null ? "no result" : result.getErrorMessage()));
                }
                out.flush();
            }
        }
        decompiler.dispose();
    }
}
"#;

/// Where the object's addresses start: a decompiler that rebases the image
/// reports addresses relative to its own base, mapped back with this.
fn object_base(specimen: &[u8]) -> u64 {
    let Ok(file) = object::File::parse(specimen) else {
        return 0;
    };
    if file.format() == object::BinaryFormat::Pe {
        return file.relative_address_base();
    }
    file.segments()
        .filter(|segment| segment.size() > 0)
        .map(|segment| segment.address())
        .min()
        .map_or(0, |address| address & !0xfff)
}

pub(super) fn decompile(section: &mut AnalysisSection, specimen: &[u8], listings: &Path) {
    if object::File::parse(specimen).is_err() {
        section.state = AnalysisSectionState::Unavailable;
        section.summary =
            "decompilation needs a recognized object format (ELF, PE or Mach-O)".into();
        return;
    }
    let result = if let Some(ghidra) =
        tools::find_tool(crate::analysis_tools::GHIDRA_SYSTEM, GHIDRA_MANAGED)
    {
        ghidra_run(section, specimen, listings, ghidra)
    } else if let Some(r2) = tools::find(crate::analysis_tools::RADARE2_SYSTEM) {
        radare2_run(section, listings, r2)
    } else {
        Err("no decompiler installed: install Ghidra from Tools > Analysis tools (or with apt install ghidra, or radare2); Antinomie runs it locally inside the analysis sandbox".into())
    };
    if let Err(error) = result {
        section.state = AnalysisSectionState::Unavailable;
        section.summary = error;
    }
}

fn ghidra_run(
    section: &mut AnalysisSection,
    specimen: &[u8],
    listings: &Path,
    ghidra: &str,
) -> Result<(), String> {
    for directory in [
        "/tmp/ghidra-home",
        "/tmp/ghidra-project",
        "/tmp/ghidra-scripts",
    ] {
        fs::create_dir_all(directory).map_err(|e| format!("{directory}: {e}"))?;
    }
    fs::write("/tmp/ghidra-scripts/AntinomieExport.java", GHIDRA_SCRIPT)
        .map_err(|e| format!("decompiler script: {e}"))?;
    let budget = super::worker::DECOMPILER_SECONDS;
    let analysis = (budget / 2).to_string();
    let export = (budget / 2 - 60).to_string();
    let run = tools::run_with(
        ghidra,
        &[
            "/tmp/ghidra-project",
            "antinomie",
            "-import",
            "/input/specimen",
            "-scriptPath",
            "/tmp/ghidra-scripts",
            "-postScript",
            "AntinomieExport.java",
            "/tmp/decompiled.txt",
            &export,
            "-analysisTimeoutPerFile",
            &analysis,
            "-max-cpu",
            "4",
        ],
        &if ghidra == GHIDRA_MANAGED {
            vec![
                ("HOME", "/tmp/ghidra-home"),
                ("JAVA_HOME", MANAGED_JDK),
                ("PATH", "/opt/antinomie-tools/ghidra/jdk/bin:/usr/bin:/bin"),
            ]
        } else {
            vec![("HOME", "/tmp/ghidra-home")]
        },
        Duration::from_secs(budget),
        1024 * 1024,
        true,
    )?;
    if !run.success || run.timed_out {
        // Diagnostics for worker.log: the end of Ghidra's own output.
        let tail: Vec<&str> = run.stdout.lines().rev().take(40).collect();
        eprintln!("Ghidra output (last lines):");
        for line in tail.iter().rev() {
            eprintln!("  {line}");
        }
    }
    let text = fs::read("/tmp/decompiled.txt").map_err(|_| {
        if run.timed_out {
            "Ghidra ran out of time before exporting any function".to_string()
        } else {
            format!(
                "Ghidra produced no decompilation ({}); see its output in worker.log",
                if run.success {
                    "export missing"
                } else {
                    "analysis failed"
                }
            )
        }
    })?;
    let text = String::from_utf8_lossy(&text[..text.len().min(LISTING_MAX_SIZE as usize)]);
    let version = ghidra_version(ghidra);
    let (functions, lines, listing) =
        write_source(listings, &text, object_base(specimen), run.timed_out)?;
    finish(section, listing, version, functions, lines, "Ghidra");
    // Keep the actual project database, not merely the decompiled preview.
    // Analysis still writes into bounded tmpfs; only a checked bundle crosses
    // into retained output after Ghidra has closed its database.
    let retained = if run.success && !run.timed_out {
        super::export::copy_project(
            Path::new("/tmp/ghidra-project"),
            Path::new("/output/artifacts/ghidra"),
        )
    } else {
        Err("Ghidra did not finish cleanly; native project is unavailable".into())
    };
    if let Err(error) = retained {
        section.state = AnalysisSectionState::Partial;
        section
            .summary
            .push_str(&format!("; native project not retained: {error}"));
    } else {
        section
            .summary
            .push_str("; native Ghidra project retained for export/open");
    }
    Ok(())
}

fn ghidra_version(analyze_headless: &str) -> String {
    let properties = Path::new(analyze_headless)
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("Ghidra/application.properties"));
    properties
        .and_then(|path| fs::read_to_string(path).ok())
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("application.version=").map(str::to_owned))
        })
        .map_or("Ghidra".into(), |version| format!("Ghidra {version}"))
}

fn radare2_run(section: &mut AnalysisSection, listings: &Path, r2: &str) -> Result<(), String> {
    let budget = Duration::from_secs(super::worker::DECOMPILER_SECONDS / 2);
    let list = tools::run(
        r2,
        &[
            "-q",
            "-e",
            "bin.relocs.apply=true",
            "-e",
            "scr.color=0",
            "-c",
            "aaa;aflj",
            "/input/specimen",
        ],
        &[("HOME", "/tmp")],
        budget,
        16 * 1024 * 1024,
    )?;
    let functions: Vec<serde_json::Value> = list
        .stdout
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str(line).ok())
        .ok_or("radare2 listed no functions")?;
    let mut names = BTreeMap::new();
    let mut script = String::from("e scr.color=0\naaa\n");
    for function in functions.iter().take(4000) {
        let address = function
            .get("addr")
            .or_else(|| function.get("offset"))
            .and_then(serde_json::Value::as_u64);
        let (Some(address), Some(name)) = (address, function.get("name").and_then(|n| n.as_str()))
        else {
            continue;
        };
        let size = function
            .get("size")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        names.insert(address, (name.to_owned(), size));
        script.push_str(&format!("?e ANTINOMIE-FN-{address}\npdc @ {address}\n"));
    }
    fs::write("/tmp/antinomie.r2", script).map_err(|e| format!("radare2 script: {e}"))?;
    let run = tools::run(
        r2,
        &[
            "-q",
            "-e",
            "bin.relocs.apply=true",
            "-i",
            "/tmp/antinomie.r2",
            "/input/specimen",
        ],
        &[("HOME", "/tmp")],
        budget,
        LISTING_MAX_SIZE as usize / 2,
    )?;
    // Re-mark the output in the Ghidra export format.
    let mut text = String::new();
    for line in run.stdout.lines() {
        if let Some(address) = line
            .strip_prefix("ANTINOMIE-FN-")
            .and_then(|a| a.trim().parse::<u64>().ok())
        {
            let (name, size) = names.get(&address).cloned().unwrap_or_default();
            text.push_str(&format!("{MARK_FUNCTION}{address}\t{size}\t{name}\n"));
        } else {
            text.push_str(line);
            text.push('\n');
        }
    }
    let version = tools::version(r2, &["-v"]);
    let (functions, lines, listing) =
        write_source(listings, &text, 0, run.timed_out || run.truncated)?;
    finish(
        section,
        listing,
        format!("{version} (pdc pseudo-code)"),
        functions,
        lines,
        "radare2",
    );
    Ok(())
}

/// Turn marked decompiler text into listing rows.
fn write_source(
    listings: &Path,
    text: &str,
    object_base: u64,
    cut_short: bool,
) -> Result<(u64, u64, AnalysisListing), String> {
    let mut writer =
        ListingWriter::create(listings, AnalysisKind::Decompilation, LISTING_MAX_SIZE)?;
    let mut base = None;
    let mut function: Option<String> = None;
    let mut line_number = 0u32;
    let (mut functions, mut lines) = (0u64, 0u64);
    let mut full = false;
    let mut timed_out = cut_short;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix(MARK_BASE) {
            base = value.trim().parse::<u64>().ok();
            continue;
        }
        if line.starts_with(MARK_TIMEOUT) {
            timed_out = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix(MARK_FUNCTION) {
            let mut fields = rest.splitn(3, '\t');
            let address = fields
                .next()
                .and_then(|a| a.parse::<u64>().ok())
                .unwrap_or(0);
            let size = fields
                .next()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let name = fields.next().unwrap_or("").to_owned();
            let address = match base {
                Some(base) => address.wrapping_sub(base).wrapping_add(object_base),
                None => address,
            };
            line_number = 0;
            functions += 1;
            full |= !writer.push(
                name.clone(),
                name.clone(),
                Some(AnalysisLocation {
                    kind: AnalysisAddressKind::ObjectAddress,
                    value: address,
                    file_range: None,
                }),
                AnalysisData::Function {
                    name: name.clone(),
                    address,
                    size,
                },
            );
            function = Some(name);
            if full {
                break;
            }
            continue;
        }
        let Some(name) = &function else {
            continue;
        };
        // Ghidra opens each function with a blank line; keep inner blanks.
        if line_number == 0 && line.trim().is_empty() {
            continue;
        }
        line_number += 1;
        lines += 1;
        if !writer.push(
            name.clone(),
            line.trim_end(),
            None,
            AnalysisData::SourceLine {
                function: name.clone(),
                address: None,
                line: line_number,
            },
        ) {
            full = true;
            break;
        }
    }
    let listing = writer.finish(full || timed_out)?;
    Ok((functions, lines, listing))
}

fn finish(
    section: &mut AnalysisSection,
    listing: AnalysisListing,
    tool: String,
    functions: u64,
    lines: u64,
    name: &str,
) {
    if functions == 0 {
        section.state = AnalysisSectionState::Unavailable;
        section.summary = format!("{name} found no functions to decompile");
        section.tools.push(tool);
        return;
    }
    section.state = if listing.truncated {
        AnalysisSectionState::Partial
    } else {
        AnalysisSectionState::Complete
    };
    section.summary = format!(
        "{functions} functions, {lines} lines of {name} output; decompiled code is a reconstruction, not the original source{}",
        if listing.truncated {
            "; time or size budget reached, later functions omitted"
        } else {
            ""
        }
    );
    section.listing = Some(listing);
    section.tools.push(tool);
}

/// One PT_LOAD extent from an ELF core. `filesz` bytes at `file_offset` are
/// the captured image. `memsz - filesz` is an unavailable tail, not zeros.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseLoadExtent {
    pub vaddr: u64,
    pub file_offset: u64,
    pub filesz: u64,
    pub memsz: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseCorePlan {
    pub extents: Vec<SparseLoadExtent>,
}

impl SparseCorePlan {
    pub fn captured_bytes(&self) -> u64 {
        self.extents.iter().map(|extent| extent.filesz).sum()
    }

    pub fn unavailable_tails(&self) -> u64 {
        self.extents
            .iter()
            .map(|extent| extent.memsz.saturating_sub(extent.filesz))
            .sum()
    }
}

/// Loadable extents of an ELF core. This does not treat the core as an
/// executable and does not fill holes.
pub fn sparse_core_plan(bytes: &[u8]) -> Result<SparseCorePlan, String> {
    let file = object::File::parse(bytes).map_err(|error| error.to_string())?;
    if file.format() != object::BinaryFormat::Elf {
        return Err("sparse core load needs an ELF core".into());
    }
    let mut extents = Vec::new();
    for segment in file.segments() {
        let (file_offset, filesz) = segment.file_range();
        let memsz = segment.size();
        if memsz == 0 && filesz == 0 {
            continue;
        }
        extents.push(SparseLoadExtent {
            vaddr: segment.address(),
            file_offset,
            filesz,
            memsz,
        });
    }
    if extents.is_empty() {
        return Err("ELF core has no loadable segments".into());
    }
    Ok(SparseCorePlan { extents })
}

/// ELF image of captured PT_LOAD bytes at their original virtual addresses.
/// Uncaptured tails are omitted, not stored as zero-filled holes.
pub fn synthetic_captured_elf(core: &[u8], plan: &SparseCorePlan) -> Result<Vec<u8>, String> {
    let captured: Vec<_> = plan
        .extents
        .iter()
        .filter(|extent| extent.filesz > 0)
        .collect();
    if captured.is_empty() {
        return Err("core has no captured PT_LOAD bytes".into());
    }
    let phnum = captured.len();
    if phnum > u16::MAX as usize {
        return Err("too many captured extents".into());
    }
    let data_off = 64 + phnum * 56;
    let mut image = vec![0u8; data_off];
    image[0..4].copy_from_slice(b"\x7fELF");
    image[4] = 2;
    image[5] = 1;
    image[6] = 1;
    image[16..18].copy_from_slice(&4u16.to_le_bytes());
    image[18..20].copy_from_slice(&62u16.to_le_bytes());
    image[20..24].copy_from_slice(&1u32.to_le_bytes());
    image[32..40].copy_from_slice(&64u64.to_le_bytes());
    image[52..54].copy_from_slice(&64u16.to_le_bytes());
    image[54..56].copy_from_slice(&56u16.to_le_bytes());
    image[56..58].copy_from_slice(&(phnum as u16).to_le_bytes());
    let mut cursor = data_off as u64;
    for (index, extent) in captured.iter().enumerate() {
        let start = extent.file_offset as usize;
        let end = start.saturating_add(extent.filesz as usize);
        let bytes = core
            .get(start..end)
            .ok_or("captured extent is outside the core file")?;
        let at = 64 + index * 56;
        image[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
        image[at + 4..at + 8].copy_from_slice(&5u32.to_le_bytes());
        image[at + 8..at + 16].copy_from_slice(&cursor.to_le_bytes());
        image[at + 16..at + 24].copy_from_slice(&extent.vaddr.to_le_bytes());
        image[at + 24..at + 32].copy_from_slice(&extent.vaddr.to_le_bytes());
        image[at + 32..at + 40].copy_from_slice(&extent.filesz.to_le_bytes());
        // Same size as the captured bytes: the unavailable tail is absent.
        image[at + 40..at + 48].copy_from_slice(&extent.filesz.to_le_bytes());
        image[at + 48..at + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        image.extend_from_slice(bytes);
        cursor = cursor.saturating_add(extent.filesz);
    }
    Ok(image)
}

const CORE_SCRIPT: &str = r#"// SPDX-License-Identifier: MIT
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;

public class AntinomieCoreExport extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        long budget = Long.parseLong(args[1]) * 1000L;
        long start = System.currentTimeMillis();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(args[0]), "UTF-8")))) {
            out.println("@@ANTINOMIE-BASE\t" + currentProgram.getImageBase().getOffset());
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                if (System.currentTimeMillis() - start > budget) {
                    out.println("@@ANTINOMIE-TIMEOUT");
                    break;
                }
                Function function = functions.next();
                if (function.isThunk() || function.isExternal()) continue;
                out.println("@@ANTINOMIE-FUNCTION\t" + function.getEntryPoint().getOffset() + "\t"
                        + function.getBody().getNumAddresses() + "\t" + function.getName());
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                if (result != null && result.decompileCompleted()) {
                    out.println(result.getDecompiledFunction().getC());
                } else {
                    out.println("// decompilation failed");
                }
                out.flush();
            }
        }
        decompiler.dispose();
    }
}
"#;

/// Decompile captured core bytes through the analysis tool runner.
/// The original core file is not imported as an executable. A mappings text
/// file is not consulted. Returns the export text only after a successful run.
pub fn decompile_captured_core(
    core_path: &Path,
    work: &Path,
    tools_dir: &Path,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<String, String> {
    use std::sync::atomic::Ordering;
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    let core = fs::read(core_path).map_err(|error| error.to_string())?;
    if core.len() > 64 * 1024 * 1024 {
        return Err("core exceeds the 64 MiB decompile bound".into());
    }
    let plan = sparse_core_plan(&core)?;
    let image = synthetic_captured_elf(&core, &plan)?;
    fs::create_dir_all(work).map_err(|error| error.to_string())?;
    let image_path = work.join("captured-image.elf");
    fs::write(&image_path, &image).map_err(|error| error.to_string())?;
    let plan_note = format!(
        "captured {} octets across {} extents; {} unavailable tail octets omitted",
        plan.captured_bytes(),
        plan.extents.len(),
        plan.unavailable_tails()
    );
    fs::write(work.join("sparse-plan.txt"), &plan_note).map_err(|error| error.to_string())?;
    let ghidra = find_ghidra(tools_dir)?;
    let scripts = work.join("ghidra-scripts");
    let project = work.join("ghidra-project");
    fs::create_dir_all(&scripts).map_err(|error| error.to_string())?;
    fs::create_dir_all(&project).map_err(|error| error.to_string())?;
    fs::write(scripts.join("AntinomieCoreExport.java"), CORE_SCRIPT)
        .map_err(|error| error.to_string())?;
    let export = work.join("decompiled.txt");
    let _ = fs::remove_file(&export);
    let home = work.join("ghidra-home");
    fs::create_dir_all(&home).map_err(|error| error.to_string())?;
    let export_s = export.to_string_lossy().into_owned();
    let project_s = project.to_string_lossy().into_owned();
    let scripts_s = scripts.to_string_lossy().into_owned();
    let image_s = image_path.to_string_lossy().into_owned();
    let home_s = home.to_string_lossy().into_owned();
    let ghidra_s = ghidra.to_string_lossy().into_owned();
    let mut env = vec![("HOME", home_s.as_str())];
    let java_home;
    if ghidra_s.contains("antinomie-tools") {
        java_home = "/opt/antinomie-tools/ghidra/jdk".to_string();
        env.push(("JAVA_HOME", java_home.as_str()));
    }
    let run = tools::run_cancellable(
        &ghidra_s,
        &[
            &project_s,
            "antinomie",
            "-import",
            &image_s,
            "-overwrite",
            "-scriptPath",
            &scripts_s,
            "-postScript",
            "AntinomieCoreExport.java",
            &export_s,
            "90",
            "-analysisTimeoutPerFile",
            "90",
            "-max-cpu",
            "4",
        ],
        &env,
        Duration::from_secs(180),
        64 * 1024,
        false,
        cancel,
    )?;
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    if !run.success || run.timed_out {
        return Err(format!(
            "Ghidra decompilation failed (success={}, timed_out={}). sparse-plan.txt is not a load result.",
            run.success, run.timed_out
        ));
    }
    let text = fs::read_to_string(&export).map_err(|_| {
        "Ghidra produced no decompilation. The sparse plan file is not a result.".to_string()
    })?;
    if !text
        .lines()
        .any(|line| line.starts_with("@@ANTINOMIE-FUNCTION"))
        && !text.contains("@@ANTINOMIE-TIMEOUT")
        && !text.contains("@@ANTINOMIE-BASE")
    {
        return Err("Ghidra export has no function marker.".into());
    }
    Ok(text)
}

fn find_ghidra(tools_dir: &Path) -> Result<std::path::PathBuf, String> {
    for candidate in crate::analysis_tools::system_candidates("ghidra") {
        let path = Path::new(candidate);
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
    }
    let managed = tools_dir.join("ghidra/ghidra/support/analyzeHeadless");
    if managed.is_file() {
        Ok(managed)
    } else {
        Err("Ghidra is not installed. Install it from Tools, or with apt install ghidra.".into())
    }
}

#[cfg(test)]
mod sparse_tests {
    use super::*;

    fn elf_core() -> Vec<u8> {
        let payload = [0xdeu8, 0xad, 0xbe, 0xef, 0x11, 0x22];
        let phnum = 2usize;
        let data_off = 64 + phnum * 56;
        let mut image = vec![0u8; data_off];
        image[0..4].copy_from_slice(b"\x7fELF");
        image[4] = 2;
        image[5] = 1;
        image[6] = 1;
        image[16..18].copy_from_slice(&4u16.to_le_bytes());
        image[18..20].copy_from_slice(&62u16.to_le_bytes());
        image[20..24].copy_from_slice(&1u32.to_le_bytes());
        image[32..40].copy_from_slice(&64u64.to_le_bytes());
        image[52..54].copy_from_slice(&64u16.to_le_bytes());
        image[54..56].copy_from_slice(&56u16.to_le_bytes());
        image[56..58].copy_from_slice(&2u16.to_le_bytes());
        let rows = [
            (data_off as u64, 0x400000u64, 4u64, 4u64),
            (data_off as u64 + 4, 0x401000, 2, 0x1000),
        ];
        for (index, (offset, vaddr, filesz, memsz)) in rows.iter().enumerate() {
            let at = 64 + index * 56;
            image[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
            image[at + 4..at + 8].copy_from_slice(&5u32.to_le_bytes());
            image[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
            image[at + 16..at + 24].copy_from_slice(&vaddr.to_le_bytes());
            image[at + 24..at + 32].copy_from_slice(&vaddr.to_le_bytes());
            image[at + 32..at + 40].copy_from_slice(&filesz.to_le_bytes());
            image[at + 40..at + 48].copy_from_slice(&memsz.to_le_bytes());
            image[at + 48..at + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        }
        image.extend_from_slice(&payload);
        image
    }

    #[test]
    fn captured_bytes_keep_their_virtual_address_and_holes_are_omitted() {
        let core = elf_core();
        let plan = sparse_core_plan(&core).unwrap();
        assert_eq!(plan.extents.len(), 2);
        assert_eq!(plan.extents[0].vaddr, 0x400000);
        assert_eq!(plan.extents[0].filesz, 4);
        assert_eq!(plan.extents[1].vaddr, 0x401000);
        assert_eq!(plan.extents[1].filesz, 2);
        assert_eq!(plan.extents[1].memsz, 0x1000);
        assert_eq!(plan.unavailable_tails(), 0x1000 - 2);
        let image = synthetic_captured_elf(&core, &plan).unwrap();
        let loaded = sparse_core_plan(&image).unwrap();
        assert_eq!(loaded.extents[0].vaddr, 0x400000);
        assert_eq!(loaded.extents[0].filesz, 4);
        assert_eq!(loaded.extents[0].memsz, 4);
        assert_eq!(loaded.extents[1].vaddr, 0x401000);
        assert_eq!(loaded.extents[1].filesz, 2);
        assert_eq!(loaded.unavailable_tails(), 0);
        assert!(
            !image
                .windows(4)
                .any(|window| window == [0, 0, 0, 0] && false)
        );
        assert_eq!(image.len(), 64 + 112 + 6);
    }
}
