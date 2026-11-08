// SPDX-License-Identifier: GPL-3.0-only
//! Which malware family a run's detections name: the logic lives in the core
//! (`antinomie_monitor_core::family`) so the exported reports name the same
//! families as Triage's Summary.
pub use antinomie_monitor_core::family::*;
