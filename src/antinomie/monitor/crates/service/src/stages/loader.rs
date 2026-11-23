// SPDX-License-Identifier: GPL-3.0-only
//! The sample's dynamic loader against the lane's base (ANT-T0556 A51, E13).
//! A base whose `bundle.json` lists the program interpreters it has
//! (`program_interpreters`: BusyBox bases built with glibc's runtime) refuses,
//! in `prechecks` and before the VM starts, a dynamically linked program whose
//! PT_INTERP is not among them, naming the loader and its C library (uClibc,
//! Android's bionic, musl, or glibc of another architecture). A base without
//! the list (older bases, the Debian bases) is not judged here: the guest
//! reports a missing loader at launch, as before.
use antinomie_monitor_core::analysis::{SampleElf, c_library, loader_hint};
use std::path::Path;

/// The `program_interpreters` of the base in `directory`; `None` when its
/// bundle has no such list or cannot be read.
pub fn base_interpreters(directory: &Path) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(directory.join("bundle.json")).ok()?;
    let bundle: serde_json::Value = serde_json::from_str(&text).ok()?;
    bundle
        .get("program_interpreters")?
        .as_array()?
        .iter()
        .map(|path| path.as_str().map(str::to_owned))
        .collect()
}

/// A loader the lane's base lacks: the program's PT_INTERP and the sentence
/// that says so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingLoader {
    pub interpreter: String,
    pub why: String,
}

/// Why a base with these `interpreters` cannot start the program whose
/// front bytes are `head`: its loader is not among them. `None` for a static
/// program, a file that is not an ELF, or a loader the base has.
pub fn missing_loader(head: &[u8], interpreters: &[String]) -> Option<MissingLoader> {
    let interpreter = SampleElf::of_head(head)?.interpreter?;
    if interpreters.contains(&interpreter) {
        return None;
    }
    let library =
        c_library(&interpreter).map_or(String::new(), |name| format!(" ({name}'s dynamic loader)"));
    let why = format!(
        "the program needs the program interpreter {interpreter}{library}, which the lane's base does not have (it has {}), so it cannot start on this node.{}",
        interpreters.join(", "),
        loader_hint(&interpreter)
    );
    Some(MissingLoader { interpreter, why })
}
