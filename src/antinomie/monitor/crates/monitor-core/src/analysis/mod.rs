// SPDX-License-Identifier: GPL-3.0-only
mod export;
mod types;
pub use export::{
    AnalysisExportFormat, copy_project, export_analysis, ghidra_open_command,
    ghidra_open_exported_project, retained_ghidra_project,
};
pub use types::*;
mod binwalk;
mod bounds;
mod capa;
mod decompile;
pub mod detection;
mod disasm;
mod elf_facts;
mod floss;
mod ghidra_listing;
mod ident;
mod limits;
mod listing;
mod progress;
pub mod properties;
mod rules;
mod sealed;
mod segments;
mod specimen;
mod strings;
pub(crate) mod tools;
mod unpack;
mod worker;
pub use decompile::{decompile_captured_core, sparse_core_plan, synthetic_captured_elf};
pub use disasm::{ARCHITECTURE_MARK, DecodedInstruction, decode_window};
pub use limits::{AnalysisLimits, LIMIT_FIELDS, LimitField, LimitSetting, fixed_limits_text};
pub use listing::{
    LISTING_PAGE_MAX_ROWS, ghidra_row_of, read_ghidra_disassembly_page, read_listing_page,
    read_listing_page_sorted, read_listing_page_with,
};
pub use specimen::read_specimen_range;
/// Keep the retained specimens under `directory` only as encrypted archives.
pub fn seal_retained_specimens(directory: &std::path::Path) -> Vec<String> {
    sealed::seal_tree(directory)
}
pub(crate) use strings::{find_strings, find_strings_min};
pub use unpack::{PackerVerdict, UnpackLayer, packer_verdict, unpack_layers};
pub use worker::worker_main_if_requested;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz {
    pub use super::binwalk::fuzz_parse as binwalk;
    pub use super::capa::fuzz_mapping as capa;
    pub use super::floss::fuzz_parse as floss;
    pub use super::unpack::fuzz_unpack as unpack;
    pub use super::worker::fuzz_section as section;
}
pub(crate) mod jobs;
pub(crate) mod validation;
pub use jobs::open_report;
