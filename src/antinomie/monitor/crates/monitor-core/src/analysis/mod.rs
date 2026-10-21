// SPDX-License-Identifier: MIT
mod export;
mod types;
pub use export::{
    AnalysisExportFormat, copy_project, export_analysis, ghidra_open_command,
    ghidra_open_exported_project, retained_ghidra_project,
};
pub use types::*;
mod binwalk;
mod capa;
mod decompile;
pub mod detection;
mod disasm;
mod ident;
mod listing;
mod progress;
pub mod properties;
mod rules;
mod segments;
mod specimen;
pub(crate) mod tools;
mod worker;
pub use decompile::{decompile_captured_core, sparse_core_plan, synthetic_captured_elf};
pub use disasm::{DecodedInstruction, decode_window};
pub use listing::{
    LISTING_PAGE_MAX_ROWS, read_listing_page, read_listing_page_sorted, read_listing_page_with,
};
pub use specimen::read_specimen_range;
pub(crate) use worker::find_strings;
pub use worker::worker_main_if_requested;
pub(crate) mod jobs;
pub(crate) mod validation;
pub use jobs::open_report;
