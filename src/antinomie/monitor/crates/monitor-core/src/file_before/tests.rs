// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::disk_start::{Layer, Via};

fn record(start: Start) -> DiskStart {
    DiskStart {
        format: 1,
        boot_id: "b".into(),
        via: Via::Start,
        start,
    }
}

#[test]
fn a_start_that_was_not_kept_says_why() {
    let changed = StartDisk::open(&record(Start::Changed), None).unwrap_err();
    assert!(changed.contains("earlier boots"), "{changed}");
    let unknown = StartDisk::open(&record(Start::Unknown("no base".into())), None).unwrap_err();
    assert!(unknown.contains("no base"), "{unknown}");
    let gone = Start::Frozen(Frozen {
        layers: vec![Layer {
            path: "/nonexistent/base.qcow2".into(),
            size: 1,
            mtime_ns: 1,
        }],
    });
    assert!(
        StartDisk::open(&record(gone), None)
            .unwrap_err()
            .contains("gone")
    );
}

#[test]
fn a_resolver_without_records_or_for_a_created_file_does_not_read_a_disk() {
    let mut resolver = Resolver::new(&[], None);
    let wanted = |created| Wanted {
        path: "/etc/x",
        names: &[],
        key: None,
        created,
        first_segment: 0,
        last_segment: 3,
    };
    assert_eq!(resolver.resolve(&wanted(true)).0, Before::Created);
    assert!(matches!(
        resolver.resolve(&wanted(false)).0,
        Before::Unavailable(_)
    ));
}
