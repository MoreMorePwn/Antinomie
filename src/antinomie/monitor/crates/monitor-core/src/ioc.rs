// SPDX-License-Identifier: GPL-3.0-only
//! Indicators of compromise: the abuse.ch datasets kept on this machine, and
//! the matching of a run's indicators against them. Matching is offline; the
//! only network traffic is the manual dataset update and the optional online
//! check.
pub mod baseline;
pub mod disk;
pub mod download;
pub mod export;
pub mod feeds;
pub mod indicator;
pub mod kind;
pub mod online;
pub mod records;
pub mod strings;
pub mod verdict;

/// What a hash line says of a file with no bytes, in place of "no hash".
pub const EMPTY_FILE: &str = "empty file";
/// SHA-256 of zero bytes: a file whose digest is this is empty.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Why a file has no hash, as a line: "empty file", else "no hash: why".
pub fn no_hash_text(why: &str) -> String {
    if why == EMPTY_FILE {
        EMPTY_FILE.to_owned()
    } else {
        format!("no hash: {why}")
    }
}

pub use self::{
    download::{Outcome, summary as update_summary, update_all, update_feed},
    feeds::{FEEDS, FeedMeta, FeedStatus, STALE_DAYS, status},
    kind::Kind,
};
