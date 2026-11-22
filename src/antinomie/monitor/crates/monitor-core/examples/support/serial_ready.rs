// SPDX-License-Identifier: GPL-3.0-only
//! The wait for a guest's serial banner, shared by the VM check examples.
//!
//! The guest kernel prints on the same console as userspace, so one of its
//! timestamped lines ("[    3.08] rcS (94) used greatest stack depth") can
//! land in the middle of the banner a base's init writes ("BusyBox guest re",
//! the kernel line, "ady"). A plain search then never finds the banner and a
//! healthy, connected guest looks like one that never started.

/// Whether the serial `log` holds `marker`, as written or once the
/// timestamped kernel lines are taken out of it.
#[allow(dead_code)]
pub fn ready(log: &[u8], marker: &[u8]) -> bool {
    let contains = |bytes: &[u8]| bytes.windows(marker.len()).any(|part| part == marker);
    if contains(log) {
        return true;
    }
    let mut console = Vec::with_capacity(log.len());
    let mut index = 0;
    while index < log.len() {
        if log[index] == b'[' {
            let rest = &log[index + 1..];
            let digits = rest
                .iter()
                .take_while(|byte| byte.is_ascii_digit() || **byte == b' ' || **byte == b'.')
                .count();
            if digits > 0 && rest[..digits].contains(&b'.') && rest.get(digits) == Some(&b']') {
                index = rest
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(log.len(), |end| index + end + 2);
                continue;
            }
        }
        console.push(log[index]);
        index += 1;
    }
    contains(&console)
}

#[cfg(test)]
mod tests {
    use super::ready;

    #[test]
    fn a_kernel_line_inside_the_banner_does_not_hide_it() {
        let split = b"mount: x\nBusyBox guest re[    3.084665] rcS (94) used greatest stack depth: 13200 bytes left\nady\n\n\nBusyBox v1.37.0";
        assert!(ready(split, b"BusyBox guest ready"));
    }

    #[test]
    fn a_whole_banner_and_a_missing_one() {
        assert!(ready(b"BusyBox guest ready\n", b"BusyBox guest ready"));
        assert!(!ready(
            b"[    1.0] boot\nBusyBox guest re\n",
            b"BusyBox guest ready"
        ));
        assert!(!ready(b"", b"BusyBox guest ready"));
    }
}
