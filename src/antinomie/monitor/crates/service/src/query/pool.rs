// SPDX-License-Identifier: GPL-3.0-only
//! The two read pools and the deadline (design 5.12.6). Light reads (run list,
//! trace pages, custody, artifact, capture and core lists, terminal replay)
//! wait for a place up to their deadline; heavy reads (the process tree, the
//! packet filter, analysis listings) are refused at once when the pool is full
//! with `quota_exceeded` and `retry_after_s`. A watchdog sets the cancel flag
//! when the deadline passes and the read answers `unavailable/read_timeout`.
//! A client that goes away sets the same flag; the read answers `unavailable`.
//!
//! Also here: the retention lease, so `auto gc` and `run.delete
//! --with-recording` skip a run that has an open read (5.12.2).

use super::{context::ReadContext, key::RecordingKey, limits::QuerySettings};
use crate::api::error::{ApiError, ErrorCode};
use std::{
    collections::HashMap,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

/// Which pool a read runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadClass {
    Light,
    Heavy,
}

struct Gate {
    max: usize,
    used: Mutex<usize>,
    freed: Condvar,
}

impl Gate {
    fn new(max: u32) -> Self {
        Self {
            max: max.max(1) as usize,
            used: Mutex::new(0),
            freed: Condvar::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, usize> {
        self.used.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn try_take(&self) -> bool {
        let mut used = self.lock();
        if *used < self.max {
            *used += 1;
            true
        } else {
            false
        }
    }

    /// Wait for a place until `deadline` or until `cancel`.
    fn take_until(&self, deadline: Instant, cancel: &AtomicBool) -> Result<(), ApiError> {
        let mut used = self.lock();
        loop {
            if *used < self.max {
                *used += 1;
                return Ok(());
            }
            if cancel.load(Ordering::Relaxed) {
                return Err(cancelled());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(ApiError::read_timeout());
            }
            let wait = (deadline - now).min(Duration::from_millis(50));
            used = self
                .freed
                .wait_timeout(used, wait)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    fn release(&self) {
        *self.lock() -= 1;
        self.freed.notify_one();
    }

    fn in_flight(&self) -> usize {
        *self.lock()
    }
}

struct Place<'a>(&'a Gate);

impl Drop for Place<'_> {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// A read that the client or the deadline stopped.
pub fn cancelled() -> ApiError {
    ApiError::new(ErrorCode::Unavailable, "the read was cancelled")
        .with_detail("reason", serde_json::json!("cancelled"))
}

/// The two pools.
pub struct ReadPool {
    light: Gate,
    heavy: Gate,
    settings: QuerySettings,
}

impl ReadPool {
    pub fn new(settings: &QuerySettings) -> Self {
        Self {
            light: Gate::new(settings.limits.light_concurrency),
            heavy: Gate::new(settings.limits.heavy_concurrency),
            settings: settings.clone(),
        }
    }

    /// Reads in flight, `(light, heavy)`.
    pub fn in_flight(&self) -> (usize, usize) {
        (self.light.in_flight(), self.heavy.in_flight())
    }

    /// Run `read` in the pool of `class`, under the context's deadline (or the
    /// class default). `read` gets the cancel flag and must check it in long
    /// loops; the engine's reads do.
    pub fn run<T>(
        &self,
        class: ReadClass,
        ctx: &ReadContext,
        read: impl FnOnce(&AtomicBool) -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        if ctx.cancelled() {
            return Err(cancelled());
        }
        let default = match class {
            ReadClass::Light => self.settings.light_timeout,
            ReadClass::Heavy => self.settings.heavy_timeout,
        };
        let deadline = ctx.deadline.unwrap_or_else(|| Instant::now() + default);
        let gate = match class {
            ReadClass::Light => &self.light,
            ReadClass::Heavy => &self.heavy,
        };
        match class {
            ReadClass::Light => gate.take_until(deadline, &ctx.cancel)?,
            ReadClass::Heavy => {
                if !gate.try_take() {
                    return Err(ApiError::heavy_read_limit(
                        self.settings.heavy_retry_after_s,
                    ));
                }
            }
        }
        let _place = Place(gate);
        watched(deadline, &ctx.cancel, read)
    }
}

/// Run `read`; when `deadline` passes first, set `cancel` and report
/// `read_timeout` if the read then failed.
fn watched<T>(
    deadline: Instant,
    cancel: &Arc<AtomicBool>,
    read: impl FnOnce(&AtomicBool) -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    let timed_out = AtomicBool::new(false);
    let (done, wait) = mpsc::channel::<()>();
    let (timed_out_flag, cancel_flag) = (&timed_out, &**cancel);
    let result = std::thread::scope(|scope| {
        scope.spawn(move || {
            let left = deadline.saturating_duration_since(Instant::now());
            if wait.recv_timeout(left) == Err(mpsc::RecvTimeoutError::Timeout) {
                timed_out_flag.store(true, Ordering::Relaxed);
                cancel_flag.store(true, Ordering::Relaxed);
            }
        });
        let result = read(cancel);
        let _ = done.send(());
        result
    });
    match result {
        Err(_) if timed_out.load(Ordering::Relaxed) => Err(ApiError::read_timeout()),
        other => other,
    }
}

/// Open reads per run. A retention process asks [`Leases::held`] and skips the
/// run (design 5.12.2, "Not while deleting").
#[derive(Default)]
pub struct Leases {
    open: Mutex<HashMap<RecordingKey, usize>>,
}

impl Leases {
    pub fn take(self: &Arc<Self>, key: &RecordingKey) -> Lease {
        *self
            .open
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.clone())
            .or_insert(0) += 1;
        Lease {
            leases: Arc::clone(self),
            key: key.clone(),
        }
    }

    /// Whether a read of the run is open now.
    pub fn held(&self, key: &RecordingKey) -> bool {
        self.open
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .is_some_and(|count| *count > 0)
    }
}

/// An open read of one run; dropping it ends the lease.
pub struct Lease {
    leases: Arc<Leases>,
    key: RecordingKey,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut open = self.leases.open.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = open.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                open.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::error::ErrorReason;
    use std::sync::atomic::AtomicUsize;

    fn pool(light: u32, heavy: u32) -> ReadPool {
        let mut settings = QuerySettings::default();
        settings.limits.light_concurrency = light;
        settings.limits.heavy_concurrency = heavy;
        ReadPool::new(&settings)
    }

    fn ctx() -> ReadContext {
        ReadContext::local_owner("test")
    }

    #[test]
    fn a_full_heavy_pool_refuses_at_once_with_retry_after() {
        let pool = pool(2, 1);
        let entered = std::sync::Barrier::new(2);
        let leave = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                pool.run(ReadClass::Heavy, &ctx(), |_| {
                    entered.wait();
                    leave.wait();
                    Ok(())
                })
                .unwrap();
            });
            entered.wait();
            let error = pool.run(ReadClass::Heavy, &ctx(), |_| Ok(())).unwrap_err();
            assert_eq!(error.code, ErrorCode::QuotaExceeded);
            assert_eq!(error.reason(), Some(ErrorReason::HeavyReadLimit));
            assert!(error.details.contains_key("retry_after_s"));
            assert_eq!(pool.in_flight(), (0, 1));
            leave.wait();
        });
        assert_eq!(pool.in_flight(), (0, 0), "the place is given back");
        pool.run(ReadClass::Heavy, &ctx(), |_| Ok(())).unwrap();
    }

    #[test]
    fn a_light_read_waits_for_a_place_and_times_out_when_none_frees() {
        let pool = pool(1, 1);
        let entered = std::sync::Barrier::new(2);
        let leave = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                pool.run(ReadClass::Light, &ctx(), |_| {
                    entered.wait();
                    leave.wait();
                    Ok(())
                })
                .unwrap();
            });
            entered.wait();
            let short = ctx().with_timeout(Duration::from_millis(80));
            let error = pool.run(ReadClass::Light, &short, |_| Ok(())).unwrap_err();
            assert_eq!(error.code, ErrorCode::Unavailable);
            assert_eq!(error.reason(), Some(ErrorReason::ReadTimeout));
            leave.wait();
        });
    }

    #[test]
    fn the_deadline_sets_the_cancel_flag_and_the_read_answers_read_timeout() {
        let pool = pool(1, 1);
        let short = ctx().with_timeout(Duration::from_millis(60));
        let error = pool
            .run(ReadClass::Heavy, &short, |cancel| {
                // A long read that honours the flag, as the engine's do.
                while !cancel.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err::<(), _>(cancelled())
            })
            .unwrap_err();
        assert_eq!(error.reason(), Some(ErrorReason::ReadTimeout));
        assert_eq!(pool.in_flight(), (0, 0));
    }

    #[test]
    fn a_dropped_connection_cancels_without_a_timeout_reason() {
        let pool = pool(1, 1);
        let context = ctx();
        let flag = Arc::clone(&context.cancel);
        let error = pool
            .run(ReadClass::Heavy, &context, |cancel| {
                flag.store(true, Ordering::Relaxed);
                assert!(cancel.load(Ordering::Relaxed));
                Err::<(), _>(cancelled())
            })
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert_eq!(
            error.reason(),
            Some(crate::api::error::ErrorReason::Cancelled)
        );
        // The next read starts cancelled.
        let again = pool
            .run(ReadClass::Light, &context, |_| Ok(()))
            .unwrap_err();
        assert_eq!(again.code, ErrorCode::Unavailable);
    }

    #[test]
    fn a_finished_read_does_not_leave_the_watchdog_running() {
        let pool = pool(1, 1);
        let context = ctx().with_timeout(Duration::from_secs(30));
        let started = Instant::now();
        pool.run(ReadClass::Light, &context, |_| Ok(())).unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(!context.cancelled());
    }

    #[test]
    fn light_reads_run_side_by_side_up_to_the_limit() {
        let pool = pool(3, 1);
        let running = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..6 {
                scope.spawn(|| {
                    pool.run(ReadClass::Light, &ctx(), |_| {
                        let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(30));
                        running.fetch_sub(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .unwrap();
                });
            }
        });
        assert!(peak.load(Ordering::SeqCst) <= 3);
        assert!(peak.load(Ordering::SeqCst) >= 2);
    }

    #[test]
    fn a_lease_is_held_while_a_read_is_open() {
        let leases = Arc::new(Leases::default());
        let key = RecordingKey::new("vm", "b", "r").unwrap();
        assert!(!leases.held(&key));
        let first = leases.take(&key);
        let second = leases.take(&key);
        assert!(leases.held(&key));
        drop(first);
        assert!(leases.held(&key));
        drop(second);
        assert!(!leases.held(&key));
    }
}
