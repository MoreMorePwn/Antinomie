// SPDX-License-Identifier: GPL-3.0-only
//! File checks for code that runs every frame.
//!
//! A `stat` is cheap on a local disk and not on a network or DrvFs mount, and
//! a frame asks again 60 times a second. These answers are reused for a
//! second, the way the packet list already throttles its size check.
use std::{
    cell::RefCell,
    collections::HashMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const KEEP: Duration = Duration::from_secs(1);
const MOST: usize = 256;

#[derive(Clone)]
struct Seen {
    at: Instant,
    is_file: bool,
    len: Result<u64, String>,
}

thread_local! {
    static SEEN: RefCell<HashMap<PathBuf, Seen>> = RefCell::new(HashMap::new());
}

fn seen(path: &Path) -> Seen {
    SEEN.with(|cell| {
        let mut map = cell.borrow_mut();
        if let Some(known) = map.get(path).filter(|known| known.at.elapsed() < KEEP) {
            return known.clone();
        }
        if map.len() >= MOST {
            map.retain(|_, known| known.at.elapsed() < KEEP);
        }
        let found = match std::fs::metadata(path) {
            Ok(meta) => Seen {
                at: Instant::now(),
                is_file: meta.is_file(),
                len: Ok(meta.len()),
            },
            Err(error) => Seen {
                at: Instant::now(),
                is_file: false,
                len: Err(error.to_string()),
            },
        };
        map.insert(path.to_path_buf(), found.clone());
        found
    })
}

/// [`Path::is_file`], looked up at most once a second per path.
pub(crate) fn is_file(path: &Path) -> bool {
    seen(path).is_file
}

/// The size of the file at `path`, or why it cannot be had; looked up at most
/// once a second per path.
pub(crate) fn len(path: &Path) -> Result<u64, String> {
    seen(path).len
}
