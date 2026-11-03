// SPDX-License-Identifier: GPL-3.0-only
//! Names for core mappings, the way /proc/PID/maps shows them. A core's
//! NT_FILE note names file-backed mappings only; the stack, vDSO, vvar and
//! heap are recognised from data the core already holds (registers, auxv and
//! the executable's extents). Anything else without a file is "anonymous".
use antinomie_monitor_core::core_dump::{CoreDump, CoreMapping};

const AT_PHDR: u64 = 3;
const AT_ENTRY: u64 = 9;
const AT_EXECFN: u64 = 31;
const AT_SYSINFO_EHDR: u64 = 33;
const VSYSCALL_PAGE: u64 = 0xffff_ffff_ff60_0000;

pub(super) const ANONYMOUS: &str = "anonymous";

/// One mapping's name and how it was found.
#[derive(Clone, Debug)]
pub(super) struct MappingLabel {
    pub(super) name: String,
    pub(super) how: String,
}

impl MappingLabel {
    /// True for the names that stand for no file.
    pub(super) fn is_unnamed(&self) -> bool {
        self.name == ANONYMOUS
    }

    /// True for an inferred "[stack]", "[heap]", "[vdso]" or "[vvar]".
    pub(super) fn is_special(&self) -> bool {
        self.name.starts_with('[')
    }
}

fn auxv(core: &CoreDump, key: u64) -> Option<u64> {
    core.auxv
        .iter()
        .find(|(entry, value)| *entry == key && *value != 0)
        .map(|(_, value)| *value)
}

fn contains(mapping: &CoreMapping, address: u64) -> bool {
    mapping.start <= address && address < mapping.end()
}

fn file_names(core: &CoreDump, mapping: &CoreMapping) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    for file in &core.files {
        let path = file.path.trim();
        if !path.is_empty()
            && file.start < mapping.end()
            && mapping.start < file.end
            && !paths.iter().any(|existing| existing == path)
        {
            paths.push(path.to_owned());
        }
    }
    paths
}

fn is_file_backed(core: &CoreDump, mapping: &CoreMapping) -> bool {
    !file_names(core, mapping).is_empty()
}

fn writable(mapping: &CoreMapping) -> bool {
    mapping.flags & 2 != 0
}

fn stack_index(core: &CoreDump) -> Option<(usize, &'static str)> {
    let find = |address: u64| core.mappings.iter().position(|m| contains(m, address));
    if let Some(index) = core.threads.first().and_then(|thread| {
        ["rsp", "esp", "sp"]
            .iter()
            .find_map(|name| thread.register(name))
            .and_then(find)
    }) {
        return Some((index, "contains the saved stack pointer"));
    }
    auxv(core, AT_EXECFN).and_then(find).map(|index| {
        (
            index,
            "contains the program path (auxv AT_EXECFN), which sits on the stack",
        )
    })
}

fn heap_index(core: &CoreDump, taken: &[Option<&'static str>]) -> Option<(usize, &'static str)> {
    // The executable is the file behind the program headers (or entry point).
    let anchor = auxv(core, AT_PHDR)
        .or_else(|| auxv(core, AT_ENTRY))
        .and_then(|address| core.mappings.iter().find(|m| contains(m, address)))?;
    let program = file_names(core, anchor).into_iter().next()?;
    let program_end = core
        .files
        .iter()
        .filter(|file| file.path.trim() == program)
        .map(|file| file.end)
        .max()?;
    let mut candidates = Vec::new();
    for (index, mapping) in core.mappings.iter().enumerate() {
        if mapping.end() <= program_end && mapping.start < program_end {
            continue;
        }
        if is_file_backed(core, mapping) {
            break;
        }
        if taken[index].is_some() || !writable(mapping) || mapping.flags & 4 == 0 {
            continue;
        }
        candidates.push(index);
    }
    // A first anonymous extent that starts right at the program's end is its
    // .bss; the heap is the next one, or the lone one only as a last resort.
    let adjacent = |index: usize| core.mappings[index].start == program_end;
    let after = match candidates.as_slice() {
        [] => None,
        [only] if adjacent(*only) => None,
        [only] => Some(*only),
        [first, second, ..] if adjacent(*first) => Some(*second),
        [first, ..] => Some(*first),
    };
    if let Some(index) = after {
        return Some((index, "follows the program data (brk)"));
    }
    // A program the kernel placed in the mmap area (static PIE) has its brk
    // heap below it: the lowest writable anonymous mapping.
    let program_start = core
        .files
        .iter()
        .filter(|file| file.path.trim() == program)
        .map(|file| file.start)
        .min()?;
    core.mappings
        .iter()
        .position(|m| {
            m.end() <= program_start && !is_file_backed(core, m) && writable(m) && m.flags & 4 != 0
        })
        .filter(|index| taken[*index].is_none())
        .map(|index| {
            (
                index,
                "is the lowest writable anonymous mapping, below the program (brk)",
            )
        })
        .or_else(|| {
            candidates
                .first()
                .map(|index| (*index, "follows the program data (brk)"))
        })
}

/// The label of every mapping, indexed like `CoreDump::mappings`.
pub(super) fn mapping_labels(core: &CoreDump) -> Vec<MappingLabel> {
    let mut special: Vec<Option<&'static str>> = vec![None; core.mappings.len()];
    let mut names: Vec<&'static str> = vec![""; core.mappings.len()];
    fn mark(
        special: &mut [Option<&'static str>],
        names: &mut [&'static str],
        index: usize,
        name: &'static str,
        how: &'static str,
    ) {
        if special[index].is_none() {
            special[index] = Some(how);
            names[index] = name;
        }
    }
    if let Some((index, how)) = stack_index(core) {
        if !is_file_backed(core, &core.mappings[index]) {
            mark(&mut special, &mut names, index, "[stack]", how);
        }
    }
    if let Some(address) = auxv(core, AT_SYSINFO_EHDR) {
        if let Some(vdso) = core.mappings.iter().position(|m| contains(m, address)) {
            if !is_file_backed(core, &core.mappings[vdso]) {
                mark(
                    &mut special,
                    &mut names,
                    vdso,
                    "[vdso]",
                    "contains the auxv AT_SYSINFO_EHDR address",
                );
                let start = core.mappings[vdso].start;
                if let Some(vvar) = core
                    .mappings
                    .iter()
                    .position(|m| m.end() == start && !is_file_backed(core, m))
                {
                    mark(
                        &mut special,
                        &mut names,
                        vvar,
                        "[vvar]",
                        "ends where the vDSO (auxv AT_SYSINFO_EHDR) starts",
                    );
                }
            }
        }
    }
    // The fixed legacy vsyscall page of x86-64.
    if let Some(index) = core
        .mappings
        .iter()
        .position(|m| m.start == VSYSCALL_PAGE && !is_file_backed(core, m))
    {
        mark(
            &mut special,
            &mut names,
            index,
            "[vsyscall]",
            "sits at the fixed x86-64 vsyscall address 0xffffffffff600000",
        );
    }
    if let Some((index, how)) = heap_index(core, &special) {
        mark(&mut special, &mut names, index, "[heap]", how);
    }
    core.mappings
        .iter()
        .enumerate()
        .map(|(index, mapping)| {
            if let Some(how) = special[index] {
                return MappingLabel {
                    name: names[index].to_owned(),
                    how: format!("Inferred: this mapping {how}."),
                };
            }
            let paths = file_names(core, mapping);
            match paths.as_slice() {
                [] => MappingLabel {
                    name: ANONYMOUS.into(),
                    how: "Anonymous: no NT_FILE name overlaps this mapping and it is not the \
                          stack, vDSO, vvar or heap."
                        .into(),
                },
                [one] => MappingLabel {
                    name: one.clone(),
                    how: one.clone(),
                },
                [first, rest @ ..] => MappingLabel {
                    name: format!("{first} (+{} file extents)", rest.len()),
                    how: paths.join("\n"),
                },
            }
        })
        .collect()
}

/// The name of one mapping; for many mappings use `mapping_labels`.
pub(super) fn mapping_name(core: &CoreDump, mapping: &CoreMapping) -> String {
    core.mappings
        .iter()
        .position(|candidate| std::ptr::eq(candidate, mapping))
        .or_else(|| {
            core.mappings
                .iter()
                .position(|c| c.start == mapping.start && c.memory_size == mapping.memory_size)
        })
        .map(|index| mapping_labels(core).swap_remove(index).name)
        .unwrap_or_else(|| ANONYMOUS.into())
}

/// "Captured at exit (no signal)" for signal 0.
pub(super) fn signal_text(signal: u16) -> String {
    if signal == 0 {
        "Captured at exit (no signal)".into()
    } else {
        format!("signal {signal}")
    }
}
