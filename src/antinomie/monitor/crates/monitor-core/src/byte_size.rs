//! One text form for every user-visible size: the exact byte count and, from
//! 1024 bytes up, a rounded figure in 1024-based units.

/// A size as the exact byte count and, from 1024 bytes up, a rounded figure
/// in 1024-based units: `16080 bytes (15.7 KB)`.
pub fn file_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes} byte{}", if bytes == 1 { "" } else { "s" });
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    // 1048575 bytes is 1023.999 KB: judge the rounded figure, so it reads
    // 1.0 MB and never 1024.0 KB.
    while (value * 10.0).round() >= 10240.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{bytes} bytes ({value:.1} {})", UNITS[unit])
}

/// Only the rounded figure of [`file_size`], for a small control: `15.7 KB`,
/// and `512 bytes` below 1024.
pub fn short_size(bytes: u64) -> String {
    let full = file_size(bytes);
    match full.split_once('(') {
        Some((_, rounded)) => rounded.trim_end_matches(')').to_owned(),
        None => full,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_sizes_keep_only_the_rounded_figure() {
        for (bytes, text) in [
            (0, "0 bytes"),
            (1, "1 byte"),
            (1023, "1023 bytes"),
            (4096, "4.0 KB"),
            (4_123_755, "3.9 MB"),
            (32_448_097, "30.9 MB"),
            (5 * 1024 * 1024 * 1024, "5.0 GB"),
        ] {
            assert_eq!(short_size(bytes), text);
        }
    }

    #[test]
    fn file_sizes_show_the_byte_count_and_a_rounded_unit() {
        for (bytes, text) in [
            (0, "0 bytes"),
            (1, "1 byte"),
            (1023, "1023 bytes"),
            (1024, "1024 bytes (1.0 KB)"),
            (4096, "4096 bytes (4.0 KB)"),
            (16_080, "16080 bytes (15.7 KB)"),
            (1_048_575, "1048575 bytes (1.0 MB)"),
            (1_048_576, "1048576 bytes (1.0 MB)"),
            (1_572_864, "1572864 bytes (1.5 MB)"),
            (5 * 1024 * 1024 * 1024, "5368709120 bytes (5.0 GB)"),
            (3 * 1024_u64.pow(4), "3298534883328 bytes (3.0 TB)"),
            (u64::MAX, "18446744073709551615 bytes (16777216.0 TB)"),
        ] {
            assert_eq!(file_size(bytes), text);
        }
    }
}
