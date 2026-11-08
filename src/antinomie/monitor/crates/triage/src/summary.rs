// SPDX-License-Identifier: GPL-3.0-only
//! The model of Triage > Summary: key findings and behaviour tags, the
//! indicators the Summary lists and exports, the sample facts, rule texts,
//! and the Relationships graph built from the scan. The boxes that draw them
//! are the GUI's.
pub mod indicators;
pub mod insight;
pub mod relations;
pub mod rule_text;
pub mod sample;
