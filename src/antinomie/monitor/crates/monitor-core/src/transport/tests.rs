// SPDX-License-Identifier: MIT
use super::*;

#[test]
fn a_negative_return_is_the_errno_it_carries_and_a_count_passes_through() {
    assert_eq!(check(0), Ok(0));
    assert_eq!(check(17), Ok(17));
    let message = check(-2).unwrap_err();
    assert!(message.starts_with("transport: "), "{message}");
    assert!(message.contains("No such file"), "{message}");
    assert_ne!(check(-12), check(-2), "different errors read differently");
}

#[test]
fn a_ram_path_with_a_nul_or_that_does_not_exist_is_refused_without_a_client() {
    assert_eq!(
        Transport::open(Path::new("/home/user/a\0b"), 1 << 28, 0x1000).err(),
        Some("RAM path contains NUL".to_owned())
    );
    let missing = Transport::open(Path::new("/nonexistent/ram.bin"), 1 << 28, 0x1000);
    assert!(missing.is_err());
    let pending = Transport::open_pending(Path::new("/nonexistent/ram.bin"), 1 << 28, 0x1000);
    assert!(pending.is_err());
    // A failed open registers no client, so a heartbeat has nothing to touch.
    heartbeat_on_this_thread();
}

#[test]
fn the_c_layouts_the_host_passes_keep_their_documented_sizes() {
    assert_eq!(std::mem::size_of::<Stats>(), 80);
    assert_eq!(std::mem::size_of::<ResumeInfo>(), 32);
    let info = ResumeInfo::default();
    assert_eq!(
        (
            info.attachment,
            info.sequence_floor,
            info.discarded_request_bytes,
            info.discarded_reply_bytes
        ),
        (0, 0, 0, 0)
    );
}
