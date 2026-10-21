// SPDX-License-Identifier: MIT
//! The sandboxed ext4 reader.
//!
//! The image is attacker-controlled content, so every byte of `ext4-view`
//! parsing runs in a worker: a second mode of `antinomie-monitor`
//! (`--disk-reader`, [`worker_main_if_requested`]) under bubblewrap and
//! `prlimit` with the image bind-mounted read-only at `/image` and one
//! writable folder at `/out`. [`Reader`] is the parent's handle: it starts the
//! worker lazily, sends one JSON request at a time and kills and respawns the
//! worker when it stops answering. [`image`] holds the filesystem logic and
//! [`serve`] the line protocol, both usable without a sandbox in tests.
pub mod client;
mod content;
mod diff;
mod glob;
pub mod image;
pub mod protocol;
pub mod qcow2;
pub mod serve;

pub use client::Reader;
pub use protocol::*;
pub use serve::worker_main_if_requested;

#[cfg(test)]
mod content_diff_tests;
#[cfg(test)]
mod sandbox_tests;
#[cfg(test)]
mod tests;
