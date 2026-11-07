// SPDX-License-Identifier: GPL-3.0-only
//! When an index of a recording is out of date.
use super::*;

/// The answer of an index thread that found the recording as the last index saw it.
pub const UNCHANGED: &str = "unchanged";

pub const HOST_TIME_NOTE: &str = "Times use the host timezone. ~ marks a guest event time estimated from a host receipt/start anchor, including transport latency.";
pub const NETWORK_TIME_NOTE: &str = "Packet timestamps use QEMU's capture clock, displayed in the host timezone. They may differ from the host run clock; capture ownership determines which run is indexed.";

/// Format of the file indexes built from a recording: which tabs exist and
/// what their rows and counts mean. It is part of the source stamp, so an
/// index made by an older format is never mistaken for current and is
/// rebuilt from the recording.
pub const FILE_INDEX_VERSION: u32 = 4;

/// What an index of the recording depends on, as a string: size and
/// modification time of the files it reads, and the request facts that
/// change its meaning. Equal strings mean a new index would be the same.
pub fn source_stamp(
    directory: &Path,
    pcap: Option<&Path>,
    pcap_open: bool,
    request: &ScanRequest,
) -> String {
    use std::os::unix::fs::MetadataExt;
    let file = |path: &Path| {
        std::fs::metadata(path).map_or_else(
            |_| "-".to_owned(),
            |meta| {
                format!(
                    "{}.{}.{}.{}",
                    meta.len(),
                    meta.mtime(),
                    meta.mtime_nsec(),
                    meta.ino()
                )
            },
        )
    };
    let page_rows = request.rows();
    let mut stamp = format!(
        "files-v{FILE_INDEX_VERSION}|rows={}|{pcap_open}|{}|{}|{:?}|{}|{:?}|{}/{}|rebuild={}/{}|rev={:?}",
        page_rows,
        request.run_finished,
        request.recording_open,
        request.started_ms,
        request.root_cookie,
        request
            .clock_anchor
            .map(|clock| (clock.guest_ns, clock.host_us)),
        request.write_limits.per_file,
        request.write_limits.per_run,
        request.retention.per_file,
        request.retention.per_run,
        request.kernel_revision,
    );
    for name in [
        "telemetry.raw",
        "artifacts.json",
        "run.json",
        "manifest.json",
    ] {
        stamp.push('|');
        stamp.push_str(&file(&directory.join(name)));
    }
    // What the IOC list depends on besides the recording: the datasets, the
    // false positives, the online answers kept with the run and the sample.
    if let Some(dir) = &request.data_dir {
        stamp.push_str(&format!(
            "|ioc={}|{}",
            ioc_scan::signature(dir),
            file(&dir.join("known-false-positives.json"))
        ));
    }
    stamp.push_str(&format!(
        "|{}|{}",
        file(&directory.join("ioc-online.json")),
        request
            .report
            .as_ref()
            .map_or_else(String::new, |report| format!(
                "{}.{:?}.{}",
                report.id,
                report.state,
                report
                    .sections
                    .iter()
                    .map(|s| s.entries.len())
                    .sum::<usize>()
            ))
    ));
    if let Some(pcap) = pcap {
        stamp.push_str(&format!("|{}={}", pcap.display(), file(pcap)));
    }
    stamp
}
