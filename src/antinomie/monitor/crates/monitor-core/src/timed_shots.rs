// SPDX-License-Identifier: GPL-3.0-only
//! Timed screenshots of the VM screen during a run (ANT-T0487): every N
//! seconds the run's own VNC client takes the frame and, if it changed since
//! the last shot, saves it as `screenshots/t+SSSSSS.s.png` in the run's folder
//! (the time is the run's, counted from its start). One worker thread takes,
//! hashes, encodes and writes; it never touches the recorder or the UI. A tick
//! that comes while the previous shot is still being written is dropped and
//! counted. The count and the bytes of a run are bounded; reaching a bound
//! ends the series with a notice. The numbers are kept in
//! `screenshots/series.json` next to the pictures.
use crate::vnc::{ScreenClient, encode_png};
use serde::{Deserialize, Serialize};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// The smallest and largest interval a run may ask for, in seconds.
pub const MIN_INTERVAL_S: u32 = 1;
pub const MAX_INTERVAL_S: u32 = 600;
/// The interval a switched-on setting starts with.
pub const DEFAULT_INTERVAL_S: u32 = 10;
/// At most this many pictures, and this many bytes of them, per run.
pub const MAX_SHOTS: u64 = 500;
pub const MAX_BYTES: u64 = 256 * 1024 * 1024;
/// The folder inside a run's folder.
pub const FOLDER: &str = "screenshots";
const SERIES_FILE: &str = "series.json";

/// Keep an interval in `1..=600`.
pub fn clamp_interval(seconds: u32) -> u32 {
    seconds.clamp(MIN_INTERVAL_S, MAX_INTERVAL_S)
}

/// What a run's series did, saved as `screenshots/series.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Series {
    pub every_s: u32,
    /// Pictures saved.
    pub taken: u64,
    /// Ticks skipped because the screen had not changed.
    pub unchanged: u64,
    /// Ticks dropped because the previous picture was still being written.
    pub dropped: u64,
    /// Ticks with no picture from the screen yet (not connected).
    #[serde(default)]
    pub no_screen: u64,
    pub bytes: u64,
    /// Why the series ended early (a bound, or a write that failed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped: Option<String>,
}

impl Series {
    /// One line for the run's notes.
    pub fn note(&self) -> String {
        let mut text = format!(
            "Timed screenshots every {} s: {} saved, {} skipped (screen unchanged)",
            self.every_s, self.taken, self.unchanged
        );
        if self.dropped > 0 {
            text.push_str(&format!(
                ", {} dropped (previous still writing)",
                self.dropped
            ));
        }
        if self.no_screen > 0 {
            text.push_str(&format!(", {} with no screen yet", self.no_screen));
        }
        if let Some(why) = &self.stopped {
            text.push_str(&format!(". Stopped early: {why}"));
        }
        text.push('.');
        text
    }
}

/// A saved picture of a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunShot {
    /// Milliseconds from the run's start.
    pub t_ms: u64,
    pub path: PathBuf,
    pub bytes: u64,
}

/// The file name of a picture taken `t_ms` after the run started.
pub fn file_name(t_ms: u64) -> String {
    format!("t+{:08.1}s.png", (t_ms / 100) as f64 / 10.0)
}

/// The run-relative time in a picture's file name.
pub fn parse_name(name: &str) -> Option<u64> {
    let seconds = name.strip_prefix("t+")?.strip_suffix("s.png")?;
    let (whole, tenth) = seconds.split_once('.')?;
    if tenth.len() != 1 {
        return None;
    }
    Some(whole.parse::<u64>().ok()? * 1000 + tenth.parse::<u64>().ok()? * 100)
}

/// "+1 min 23.4 s" style text for a run-relative time.
pub fn time_label(t_ms: u64) -> String {
    let tenths = t_ms / 100;
    let (minutes, seconds) = (tenths / 600, (tenths % 600) as f64 / 10.0);
    if minutes == 0 {
        format!("+{seconds:.1} s")
    } else {
        format!("+{minutes} min {seconds:.1} s")
    }
}

/// The pictures of the run in `run_dir`, oldest first.
pub fn list(run_dir: &Path) -> Vec<RunShot> {
    let mut shots: Vec<RunShot> = std::fs::read_dir(run_dir.join(FOLDER))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let t_ms = parse_name(entry.file_name().to_str()?)?;
            let meta = entry.metadata().ok()?;
            meta.is_file().then(|| RunShot {
                t_ms,
                path: entry.path(),
                bytes: meta.len(),
            })
        })
        .collect();
    shots.sort_by_key(|shot| shot.t_ms);
    shots
}

/// The saved numbers of a run's series, when it has any.
pub fn series(run_dir: &Path) -> Option<Series> {
    serde_json::from_slice(&std::fs::read(run_dir.join(FOLDER).join(SERIES_FILE)).ok()?).ok()
}

/// A frame: width, height, RGBA.
pub type Frame = (usize, usize, Vec<u8>);

/// The taking, without the thread or the clock: one call per tick.
pub struct Shooter<F: FnMut() -> Option<Frame>> {
    frame: F,
    dir: PathBuf,
    series: Series,
    last: Option<u64>,
    max_shots: u64,
    max_bytes: u64,
    done: bool,
}

impl<F: FnMut() -> Option<Frame>> Shooter<F> {
    pub fn new(frame: F, run_dir: &Path, every_s: u32) -> Self {
        Self {
            frame,
            dir: run_dir.join(FOLDER),
            series: Series {
                every_s,
                ..Series::default()
            },
            last: None,
            max_shots: MAX_SHOTS,
            max_bytes: MAX_BYTES,
            done: false,
        }
    }

    #[cfg(test)]
    fn with_bounds(mut self, shots: u64, bytes: u64) -> Self {
        self.max_shots = shots;
        self.max_bytes = bytes;
        self
    }

    /// Whether the series ended (a bound was reached or a write failed).
    pub fn done(&self) -> bool {
        self.done
    }

    pub fn series(&self) -> &Series {
        &self.series
    }

    pub fn dropped(&mut self, ticks: u64) {
        self.series.dropped = self.series.dropped.saturating_add(ticks);
    }

    /// Take the picture of the tick at `t_ms` after the run started.
    pub fn tick(&mut self, t_ms: u64) {
        if self.done {
            return;
        }
        let Some((w, h, rgba)) = (self.frame)() else {
            self.series.no_screen += 1;
            return;
        };
        let mut hasher = DefaultHasher::new();
        (w, h).hash(&mut hasher);
        rgba.hash(&mut hasher);
        let hash = hasher.finish();
        if self.last == Some(hash) {
            self.series.unchanged += 1;
            return;
        }
        if self.series.taken >= self.max_shots {
            return self.stop(format!(
                "the limit of {} pictures per run is reached",
                self.max_shots
            ));
        }
        let png = match encode_png(w, h, &rgba) {
            Ok(png) => png,
            Err(error) => return self.stop(format!("encoding failed: {error}")),
        };
        if self.series.bytes + png.len() as u64 > self.max_bytes {
            return self.stop(format!(
                "the limit of {} MiB of pictures per run is reached",
                self.max_bytes / (1024 * 1024)
            ));
        }
        let name = file_name(t_ms);
        let result = std::fs::create_dir_all(&self.dir).and_then(|()| {
            let part = self.dir.join(format!("{name}.part"));
            std::fs::write(&part, &png)?;
            std::fs::rename(&part, self.dir.join(&name))
        });
        match result {
            Ok(()) => {
                self.last = Some(hash);
                self.series.taken += 1;
                self.series.bytes += png.len() as u64;
                self.save_series();
            }
            Err(error) => self.stop(format!("writing failed: {error}")),
        }
    }

    fn stop(&mut self, why: String) {
        self.done = true;
        self.series.stopped = Some(why);
        self.save_series();
    }

    pub fn save_series(&self) {
        if std::fs::create_dir_all(&self.dir).is_ok()
            && let Ok(json) = serde_json::to_vec_pretty(&self.series)
        {
            let _ = std::fs::write(self.dir.join(SERIES_FILE), json);
        }
    }
}

/// The running series of one run: a worker thread with its own client of the
/// VM's screen socket.
pub struct TimedShots {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Series>>,
}

impl TimedShots {
    /// Start taking a picture of `socket` every `every_s` seconds into
    /// `run_dir`; `started_ms` is the run's start (host Unix milliseconds).
    pub fn start(socket: PathBuf, run_dir: PathBuf, every_s: u32, started_ms: u64) -> Self {
        let every_s = clamp_interval(every_s);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = thread::Builder::new()
            .name("antinomie-timed-shots".into())
            .spawn(move || {
                let client = ScreenClient::start(socket, Arc::new(|| {}));
                let mut shooter = Shooter::new(|| client.frame(), &run_dir, every_s);
                let offset = elapsed_before(started_ms);
                let begin = Instant::now();
                let since_start = |at: Instant| (at - begin).as_millis() as u64 + offset;
                let every = Duration::from_secs(u64::from(every_s));
                let mut next = begin + every;
                while !flag.load(Ordering::Relaxed) && !shooter.done() {
                    let now = Instant::now();
                    if now < next {
                        thread::sleep((next - now).min(Duration::from_millis(100)));
                        continue;
                    }
                    shooter.tick(since_start(Instant::now()));
                    // Ticks that came while the picture was being taken or
                    // written are dropped, not queued.
                    let now = Instant::now();
                    next += every;
                    while next <= now {
                        next += every;
                        shooter.dropped(1);
                    }
                }
                if !shooter.done() {
                    // A last picture at the end, when the screen changed.
                    shooter.tick(since_start(Instant::now()));
                }
                shooter.save_series();
                shooter.series().clone()
            })
            .ok();
        Self { stop, thread }
    }

    /// Ask the worker to end (it takes a last picture first) without waiting.
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Whether the worker has ended.
    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }

    /// End the series (taking a last picture) and return what it did.
    pub fn finish(&mut self) -> Option<Series> {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take()?.join().ok()
    }
}

/// How long the run has been going, in milliseconds.
fn elapsed_before(started_ms: u64) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    now.saturating_sub(started_ms)
}

impl Drop for TimedShots {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests;
