// SPDX-License-Identifier: GPL-3.0-only
//! What MemNixFS's messages mean for a result: why a run is only partial,
//! why it failed, and why the tool cannot start on this system.

/// Added to a result of a dump that has no symbol table of its own.
pub(super) const NO_SYMBOLS_NOTE: &str = "This dump has no saved symbol table: MemNixFS rebuilt \
     what it needs from the kernel's own BTF and kallsyms, which can leave some structures \
     unreadable.";

/// Added to a result of a dump without a header.
pub(super) const RAW_NOTE: &str = "The dump has no header, so MemNixFS assumed one flat \
     physical-memory image starting at address 0; if it is not, addresses are shifted.";

/// Text without terminal color sequences (`ESC [ ... m`).
pub(super) fn strip_colors(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// MemNixFS's line for a table it believes is for another kernel.
pub(super) const MISMATCH_MARKER: &str = "ISF/dump MISMATCH";

/// Warnings of a finished run that make its result partial, in plain words.
/// `banner_verified`: the table's own banner is the dump's, so MemNixFS's
/// mismatch line is a false alarm.
pub(super) fn partial_notes(log: &str, banner_verified: bool) -> Vec<String> {
    const KNOWN: &[(&str, &str)] = &[
        (
            MISMATCH_MARKER,
            "MemNixFS could not match the symbol table to this dump's kernel banner; it used \
             the table's structure offsets as they are.",
        ),
        (
            "DTB unvalidated",
            "The kernel's page-table root was not validated, so what is read from kernel \
             virtual memory (loaded modules, kernel log, symbol lookups) may be wrong or \
             missing.",
        ),
        (
            "modules: read state",
            "The kernel's list of loaded modules could not be read.",
        ),
        (
            "cannot read nsproxy.mnt_ns",
            "Mount namespaces could not be read, so mounts are missing.",
        ),
    ];
    let mut notes: Vec<String> = Vec::new();
    let mut other = 0;
    for line in log.lines() {
        let line = line.trim();
        if banner_verified && line.contains(MISMATCH_MARKER) {
            continue;
        }
        if let Some((_, note)) = KNOWN.iter().find(|(marker, _)| line.contains(marker)) {
            if !notes.iter().any(|known| known == note) {
                notes.push((*note).to_owned());
            }
        } else if let Some(warning) = line.strip_prefix("[WRN]")
            && other < 4
        {
            let warning: String = warning.trim().chars().take(200).collect();
            let note = format!("MemNixFS warning: {warning}");
            if !warning.is_empty() && !notes.contains(&note) {
                notes.push(note);
                other += 1;
            }
        }
    }
    notes
}

/// The reason a run failed: MemNixFS's own error when it gave one.
pub(super) fn failure(error: &str, log: &str) -> String {
    if log.contains("No ISF found") {
        return "MemNixFS found no symbol table for this kernel, and the dump has no usable \
                BTF to rebuild one from. Dumps taken by Antinomie carry their base's table; \
                import this dump together with the table of the kernel it came from."
            .into();
    }
    let tool = log
        .lines()
        .rev()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("Error:"))
        .map(|line| line.trim().to_owned());
    let own = error.lines().next().unwrap_or("MemNixFS failed").to_owned();
    match tool {
        Some(tool) => format!("MemNixFS: {tool}"),
        None => own,
    }
}

/// Why MemNixFS does not start, from its dynamic loader's message, with the
/// package that fixes it on Debian and Ubuntu.
pub(super) fn startup_problem(stderr: &str) -> String {
    const PACKAGES: &[(&str, &str)] = &[
        ("libyara.so", "libyara10"),
        ("libsnappy.so", "libsnappy1v5"),
        ("liblzma.so", "liblzma5"),
        ("libmagic.so", "libmagic1"),
        ("libjansson.so", "libjansson4"),
        ("libcrypto.so", "libssl3"),
        ("libstdc++.so", "libstdc++6"),
        ("libfuse3.so", "libfuse3-3"),
        ("libfmt.so", "libfmt9"),
        ("libz.so", "zlib1g"),
        ("libzstd.so", "libzstd1"),
        ("libbz2.so", "libbz2-1.0"),
    ];
    let last = stderr.lines().last().unwrap_or("it did not start").trim();
    if let Some(rest) = stderr
        .split("error while loading shared libraries: ")
        .nth(1)
    {
        let library = rest.split(':').next().unwrap_or(rest).trim();
        return match PACKAGES
            .iter()
            .find(|(prefix, _)| library.starts_with(prefix))
        {
            Some((_, package)) => format!(
                "MemNixFS needs the system library {library}; on Debian/Ubuntu: \
                 sudo apt install {package}"
            ),
            None => format!("MemNixFS needs the system library {library}"),
        };
    }
    if stderr.contains("GLIBC_") || stderr.contains("GLIBCXX_") {
        return "MemNixFS was built for Ubuntu 24.04 and needs glibc 2.38 or newer (Ubuntu \
                24.04, Debian 13 or newer); this system's C library is older"
            .into();
    }
    format!("MemNixFS does not start: {last}")
}
