// SPDX-License-Identifier: GPL-3.0-only
//! Check a file's earlier bytes against the base image it came from.
//! Usage: file-before-check RUN_DIR GUEST_PATH EXPECTED_FILE
//!
//! Reads the run's recording for the inode the guest named for GUEST_PATH,
//! finds the boot's `disk-start.json`, asks the starting disk (through the
//! sandboxed reader, this executable serving `--disk-reader`) for the file's
//! earlier bytes, and compares them with EXPECTED_FILE (taken from the base
//! image by another tool). Prints a JSON line; exits 1 when they differ.
use antinomie_monitor_core::{
    disks::reader::worker_main_if_requested,
    file_before::{Before, Resolver, Wanted},
    kernel_notes, recording,
};
use std::path::PathBuf;

fn run() -> Result<serde_json::Value, String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [run_dir, guest_path, expected] = args.as_slice() else {
        return Err("usage: file-before-check RUN_DIR GUEST_PATH EXPECTED_FILE".into());
    };
    let run_dir = PathBuf::from(run_dir);
    let expected = std::fs::read(expected).map_err(|error| error.to_string())?;
    // The inode the guest recorded for the path, from the first call that
    // names both.
    let rec = recording::open_recording(&run_dir).map_err(|error| error.to_string())?;
    let mut key = None;
    let mut cursor = 0;
    'pages: loop {
        let page = rec
            .invocation_page(cursor, 256)
            .map_err(|error| error.to_string())?;
        for call in &page.invocations {
            let names_path = [call.entry.as_ref(), call.exit.as_ref()]
                .into_iter()
                .flatten()
                .flat_map(|event| &event.fields)
                .any(|field| field.preview.starts_with(guest_path.as_bytes()));
            if names_path && let Some(id) = call.kernel_notes.iter().find_map(kernel_notes::file_id)
            {
                key = Some(id.key);
                break 'pages;
            }
        }
        match page.next_offset {
            Some(next) => cursor = next,
            None => break,
        }
    }
    let boot = std::fs::read_to_string(run_dir.join("run.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|value| value["boot_id"].as_str().map(str::to_owned))
        .unwrap_or_default();
    let mut resolver = Resolver::new(&[(run_dir.clone(), boot)], None);
    let (before, file) = resolver.resolve(&Wanted {
        path: guest_path,
        names: &[],
        key,
        created: false,
        first_segment: 0,
        last_segment: 0,
    });
    let bytes = match (&before, &file) {
        (Before::OnDisk { size, .. }, Some(file)) => file
            .disk
            .read(&file.path, 0, *size)
            .map_err(|error| format!("read: {error}"))?,
        _ => Vec::new(),
    };
    Ok(serde_json::json!({
        "path": guest_path,
        "inode_from_trace": key.map(|key| (key.ino, key.generation)),
        "before": format!("{before:?}"),
        "bytes": bytes.len(),
        "matches_base": bytes == expected && !expected.is_empty(),
    }))
}

fn main() {
    if let Some(code) = worker_main_if_requested() {
        std::process::exit(code);
    }
    match run() {
        Ok(value) => {
            println!("{value}");
            if value["matches_base"] != true {
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("file-before-check: {error}");
            std::process::exit(2);
        }
    }
}
