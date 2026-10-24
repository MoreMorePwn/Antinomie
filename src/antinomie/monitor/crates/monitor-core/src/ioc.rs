// SPDX-License-Identifier: GPL-3.0-only
//! Indicators of compromise: the abuse.ch datasets kept on this machine, and
//! the matching of a run's indicators against them. Matching is offline; the
//! only network traffic is the manual dataset update and the optional online
//! check.
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

pub use self::{
    download::{Outcome, summary as update_summary, update_all, update_feed},
    feeds::{FEEDS, FeedMeta, FeedStatus, STALE_DAYS, status},
    kind::Kind,
};
