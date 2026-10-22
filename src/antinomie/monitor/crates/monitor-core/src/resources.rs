// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Bounded Linux host resource measurements, independent of guest telemetry.
use crate::api::VmResources;
use std::{fs::File, io::Read, path::Path, time::Instant};

#[derive(Default)]
pub(crate) struct ResourceSampler {
    previous: Option<(u64, u64, Instant)>,
    sample_sequence: u64,
}

struct ProcessStat {
    cpu_ticks: u64,
    start_ticks: u64,
    resident_pages: u64,
}

fn read_small(path: &Path) -> Result<String, String> {
    let mut text = String::new();
    File::open(path)
        .and_then(|file| file.take(16385).read_to_string(&mut text))
        .map_err(|error| error.to_string())?;
    if text.len() > 16384 {
        return Err("host process metadata exceeds its size limit".into());
    }
    Ok(text)
}

fn process_stat(text: &str) -> Result<ProcessStat, String> {
    // comm can contain spaces and parentheses: the final ')' closes field 2.
    let (_, fields) = text.rsplit_once(')').ok_or("invalid host process stat")?;
    let fields: Vec<_> = fields.split_whitespace().take(22).collect();
    let value = |index: usize| -> Result<u64, String> {
        fields
            .get(index)
            .ok_or_else(|| "truncated host process stat".to_owned())?
            .parse()
            .map_err(|_| "invalid host process counter".to_owned())
    };
    Ok(ProcessStat {
        cpu_ticks: value(11)?
            .checked_add(value(12)?)
            .ok_or("host CPU counter overflow")?,
        start_ticks: value(19)?,
        resident_pages: value(21)?,
    })
}

fn memory_total(text: &str) -> Result<u64, String> {
    memory_field(text, "MemTotal")?
        .filter(|&size| size != 0)
        .ok_or_else(|| "host memory total is missing or zero".into())
}

fn memory_field(text: &str, name: &str) -> Result<Option<u64>, String> {
    let mut values = text.lines().filter_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key == name).then_some(value)
    });
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(format!("duplicate host {name} field"));
    }
    let mut fields = value.split_whitespace();
    let size = fields
        .next()
        .ok_or("host memory value is missing")?
        .parse::<u64>()
        .map_err(|_| "invalid host memory value")?;
    if fields.next() != Some("kB") || fields.next().is_some() {
        return Err("unsupported host memory unit".into());
    }
    size.checked_mul(1024)
        .map(Some)
        .ok_or_else(|| "host memory size overflow".into())
}

struct FilesystemSizes {
    total_size: u64,
    free_size: u64,
    available_size: u64,
    used_size: u64,
}

fn filesystem_sizes(
    blocks: u64,
    free: u64,
    available: u64,
    fragment_size: u64,
) -> Result<FilesystemSizes, String> {
    if fragment_size == 0 || free > blocks || available > free {
        return Err("invalid data-volume block counts".into());
    }
    let size = |blocks: u64| {
        blocks
            .checked_mul(fragment_size)
            .ok_or("data-volume capacity overflow".to_owned())
    };
    Ok(FilesystemSizes {
        total_size: size(blocks)?,
        free_size: size(free)?,
        available_size: size(available)?,
        used_size: size(blocks - free)?,
    })
}

impl ResourceSampler {
    pub(crate) fn sample(&mut self, pid: u32, vm_id: &str, data_dir: &Path) -> VmResources {
        self.sample_sequence = self.sample_sequence.checked_add(1).unwrap_or(1);
        let mut sample = VmResources {
            vm_id: vm_id.into(),
            sample_sequence: self.sample_sequence,
            ..VmResources::default()
        };
        let mut issues = Vec::new();
        match read_small(Path::new("/proc/meminfo")) {
            Ok(text) => {
                match memory_total(&text) {
                    Ok(size) => sample.host_memory_total_size = Some(size),
                    Err(error) => issues.push(error),
                }
                match memory_field(&text, "MemAvailable") {
                    Ok(Some(size))
                        if sample
                            .host_memory_total_size
                            .is_some_and(|total| size <= total) =>
                    {
                        sample.host_memory_available_size = Some(size)
                    }
                    Ok(Some(_)) => issues
                        .push("host available memory exceeds total or total is unavailable".into()),
                    Ok(None) => issues.push("host MemAvailable is unavailable".into()),
                    Err(error) => issues.push(error),
                }
            }
            Err(error) => issues.push(error),
        }
        let ticks_per_second = rustix::param::clock_ticks_per_second();
        let now = Instant::now();
        match read_small(Path::new(&format!("/proc/{pid}/stat")))
            .and_then(|text| process_stat(&text))
        {
            Ok(stat) => {
                sample.qemu_resident_size = stat
                    .resident_pages
                    .checked_mul(rustix::param::page_size() as u64);
                if let Some((start, ticks, previous)) = self.previous
                    && start == stat.start_ticks
                    && let Some(delta) = stat.cpu_ticks.checked_sub(ticks)
                    && ticks_per_second > 0
                    && now > previous
                {
                    sample.qemu_cpu_percent = Some(
                        100.0 * delta as f64
                            / ticks_per_second as f64
                            / now.duration_since(previous).as_secs_f64(),
                    );
                }
                self.previous = Some((stat.start_ticks, stat.cpu_ticks, now));
                match read_small(Path::new("/proc/uptime")).and_then(|text| {
                    text.split_whitespace()
                        .next()
                        .ok_or("missing host uptime")?
                        .parse::<f64>()
                        .map_err(|_| "invalid host uptime".into())
                }) {
                    Ok(uptime) if uptime.is_finite() && uptime >= 0.0 && ticks_per_second > 0 => {
                        sample.uptime_ms = Some(
                            ((uptime - stat.start_ticks as f64 / ticks_per_second as f64).max(0.0)
                                * 1000.0) as u64,
                        );
                    }
                    Ok(_) => issues.push("host uptime unavailable".into()),
                    Err(error) => issues.push(error),
                }
            }
            Err(error) => {
                self.previous = None;
                issues.push(format!("QEMU resources: {error}"));
            }
        }
        match rustix::fs::statvfs(data_dir)
            .map_err(|error| format!("data-volume resources: {error}"))
            .and_then(|stat| {
                filesystem_sizes(stat.f_blocks, stat.f_bfree, stat.f_bavail, stat.f_frsize)
            }) {
            Ok(sizes) => {
                sample.data_disk_available_size = Some(sizes.available_size);
                sample.data_disk_total_size = Some(sizes.total_size);
                sample.data_disk_free_size = Some(sizes.free_size);
                sample.data_disk_used_size = Some(sizes.used_size);
            }
            Err(error) => issues.push(error),
        }
        if !issues.is_empty() {
            sample.sample_error = Some(issues.join("; "));
        }
        sample
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_comm_parentheses_do_not_shift_counters() {
        let mut fields = vec!["0"; 22];
        fields[0] = "S";
        fields[11] = "20";
        fields[12] = "5";
        fields[19] = "100";
        fields[21] = "3";
        let stat = process_stat(&format!("123 (worker (test)) {}", fields.join(" "))).unwrap();
        assert_eq!(
            (stat.cpu_ticks, stat.start_ticks, stat.resident_pages),
            (25, 100, 3)
        );
        assert!(process_stat("123 (worker) S 1").is_err());
        fields[21] = "-1";
        assert!(process_stat(&format!("123 (worker) {}", fields.join(" "))).is_err());
    }

    #[test]
    fn missing_process_does_not_report_zero_usage_or_reuse_old_cpu() {
        let mut sampler = ResourceSampler::default();
        let sample = sampler.sample(u32::MAX, "vm", Path::new("/tmp"));
        assert!(sample.qemu_cpu_percent.is_none());
        assert!(sample.qemu_resident_size.is_none());
        assert!(sample.uptime_ms.is_none());
        assert!(sample.sample_error.is_some());
        assert!(sample.data_disk_available_size.is_some());
        assert!(sample.data_disk_total_size.is_some());
        assert!(sample.host_memory_total_size.is_some());
        assert_eq!(sample.sample_sequence, 1);
        assert_eq!(
            sampler
                .sample(u32::MAX, "vm", Path::new("/tmp"))
                .sample_sequence,
            2
        );
        assert!(sampler.previous.is_none());
    }

    #[test]
    fn available_memory_is_checked_and_missing_values_are_unknown() {
        assert_eq!(
            memory_field("MemAvailable: 0 kB", "MemAvailable").unwrap(),
            Some(0)
        );
        assert_eq!(
            memory_field("MemAvailable: 1024 kB", "MemAvailable").unwrap(),
            Some(1024 * 1024)
        );
        assert_eq!(
            memory_field("MemFree: 1024 kB", "MemAvailable").unwrap(),
            None
        );
        for text in [
            "MemAvailable: -1 kB",
            "MemAvailable: 3 MB",
            "MemAvailable: 1 kB\nMemAvailable: 2 kB",
            "MemAvailable: 18446744073709551615 kB",
        ] {
            assert!(memory_field(text, "MemAvailable").is_err(), "{text}");
        }
    }

    #[test]
    fn filesystem_usage_does_not_count_reserved_free_blocks_as_used() {
        let sizes = filesystem_sizes(100, 40, 30, 4096).unwrap();
        assert_eq!(
            (
                sizes.total_size,
                sizes.free_size,
                sizes.available_size,
                sizes.used_size
            ),
            (409600, 163840, 122880, 245760)
        );
        assert_eq!(sizes.free_size + sizes.used_size, sizes.total_size);
        for (blocks, free, available, fragment_size) in [
            (1, 2, 0, 4096),
            (2, 1, 2, 4096),
            (1, 0, 0, 0),
            (u64::MAX, 0, 0, 4096),
        ] {
            assert!(filesystem_sizes(blocks, free, available, fragment_size).is_err());
        }
    }

    #[test]
    fn memory_total_requires_supported_units_and_a_bounded_extent() {
        assert_eq!(
            memory_total("MemTotal: 2048 kB\nMemFree: 1 kB\n").unwrap(),
            2 * 1024 * 1024
        );
        for invalid in [
            "MemFree: 2048 kB",
            "MemTotal: -1 kB",
            "MemTotal: 0 kB",
            "MemTotal: 2 MB",
            "MemTotal: 2 kB extra",
            "MemTotal: 18446744073709551615 kB",
        ] {
            assert!(memory_total(invalid).is_err(), "{invalid}");
        }
    }
}
