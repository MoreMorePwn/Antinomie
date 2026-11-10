// SPDX-License-Identifier: GPL-3.0-only
//! Follow copies of a run's program that run outside its recorded tree
//! ([`crate::persisted_copy`]): list the guest's processes every few seconds,
//! read the program of each new process outside the tree through ACQUIRE of
//! `/proc/<pid>/exe`, hash it, and hold the run open while a copy lives.
//! Only existing guest commands are used (PROCESS_LIST, ACQUIRE,
//! SPECIMEN_READ, SPECIMEN_RELEASE); nothing starts in the guest.
use super::*;
use crate::persisted_copy::{self, FinalLook, Looked, PersistedCopies, Reading};
use sha2::Digest;

/// Chunks of a program read per turn of the worker loop, so a large one
/// cannot hold the loop.
const READS_PER_TURN: usize = 32;

/// The longest the last look after the tree's end may take.
const FINAL_LOOK_MAX: Duration = Duration::from_secs(30);

impl ProgramRun {
    /// The watch goes on: the run is live, or held open (which includes the
    /// last look after its tree ended).
    fn watching(&self) -> bool {
        self.persisted.armed()
            && (self.summary.state.is_live()
                || self.summary.state == RunState::Unknown
                || self.held_open())
    }

    /// The run is held open: its tree ended and a copy outside it is alive,
    /// or the last look for one is still going on.
    pub(super) fn held_open(&self) -> bool {
        self.summary
            .persisted
            .as_ref()
            .is_some_and(|copies| copies.holding)
    }

    /// The guest says the tree ended: keep the run open for one last look
    /// for copies outside it (a copy started just before the end), so the
    /// run does not read as ended until it is decided. Set with the status
    /// that ends the tree, so no snapshot shows the run ended before.
    pub(super) fn begin_final_look(&mut self) {
        if !self.persisted.armed() || self.persisted.final_look != FinalLook::NotYet {
            return;
        }
        self.persisted.final_look = FinalLook::Pending(Instant::now());
        self.summary
            .persisted
            .get_or_insert_with(PersistedCopies::default)
            .holding = true;
    }

    /// The last look is over: hold the run open while a copy is alive, or
    /// let it end (and leave no `persisted` record when nothing was found).
    fn finish_final_look(&mut self, may_hold: bool) {
        self.persisted.final_look = FinalLook::Done;
        let stopped = self.summary.stopped_by_user || !may_hold;
        let Some(copies) = self.summary.persisted.as_mut() else {
            return;
        };
        if copies.alive().next().is_some() && !stopped {
            copies.hold_started_ms = Some(unix_ms());
            let note = persisted_copy::hold_note(copies);
            self.persisted.hold_since = Some(Instant::now());
            self.add_note(note);
        } else {
            copies.holding = false;
            if copies.copies.is_empty() && copies.more == 0 {
                self.summary.persisted = None;
            }
        }
        let _ = self.persist_summary();
    }

    /// End the hold, saying why; false when the run was not held.
    pub(super) fn end_hold(&mut self, why: &str) -> bool {
        if matches!(self.persisted.final_look, FinalLook::Pending(_)) {
            // Stopped during the last look: nothing was held yet.
            self.finish_final_look(false);
            return true;
        }
        let Some(copies) = self.summary.persisted.as_mut() else {
            return false;
        };
        if !copies.holding {
            return false;
        }
        copies.holding = false;
        copies.hold_ended = Some(why.to_owned());
        self.add_note(format!("The run is no longer held open: {why}."));
        let _ = self.persist_summary();
        true
    }
}

impl Session {
    /// The guest's specimen limit for a program outside the tree, or `None`
    /// when this guest cannot be asked.
    fn copy_read_limit(&self, revision: Option<u32>, watch_max: u64) -> Option<u32> {
        let bound = control::specimen_request(revision, self.vm.ram_mib)?;
        let wanted = u32::try_from(watch_max).ok()?;
        (wanted > 0).then(|| wanted.min(bound))
    }

    /// Read the next chunks of the program being hashed for run `cookie`.
    fn continue_reading(
        &mut self,
        cookie: u64,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) {
        let Some(mut reading) = self
            .runs
            .get_mut(&cookie)
            .and_then(|run| run.persisted.reading.take())
        else {
            return;
        };
        let timeout = self.reply_timeout();
        let mut failed = false;
        for _ in 0..READS_PER_TURN {
            if reading.offset >= reading.size {
                break;
            }
            let capacity = control::SPECIMEN_CHUNK_SIZE
                .min(u32::try_from(reading.size - reading.offset).unwrap_or(u32::MAX));
            let chunk = self
                .request(
                    control::SPECIMEN_READ,
                    &control::specimen_read(reading.id, reading.offset, capacity),
                    snapshot,
                    sender,
                    timeout,
                )
                .and_then(|reply| {
                    control::specimen_chunk(&reply, reading.offset, reading.size, capacity)
                        .map(<[u8]>::to_vec)
                });
            match chunk {
                Ok(bytes) => {
                    reading.hasher.update(&bytes);
                    reading.offset += bytes.len() as u64;
                }
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
        let done = failed || reading.offset >= reading.size;
        if !done {
            if let Some(run) = self.runs.get_mut(&cookie) {
                run.persisted.reading = Some(reading);
            }
            return;
        }
        let _ = self.request(
            control::SPECIMEN_RELEASE,
            &control::with_session(reading.id),
            snapshot,
            sender,
            timeout,
        );
        let Some(run) = self.runs.get_mut(&cookie) else {
            return;
        };
        if failed {
            run.persisted.note(&reading.process, Looked::Unreadable(0));
            return;
        }
        let digest: [u8; 32] = reading.hasher.finalize().into();
        let Some(of) = run.persisted.matches(&digest, reading.size) else {
            run.persisted.note(&reading.process, Looked::NotACopy);
            return;
        };
        run.persisted.note(&reading.process, Looked::Copy);
        let copies = run
            .summary
            .persisted
            .get_or_insert_with(PersistedCopies::default);
        let before = copies.copies.len();
        persisted_copy::found(
            copies,
            &reading.process,
            reading.parent_name,
            (of, &digest, reading.size),
            unix_ms(),
        );
        if let Some(copy) = copies.copies.get(before) {
            let note = persisted_copy::found_note(copy);
            run.add_note(note);
        }
        let _ = run.persist_summary();
    }

    /// Start reading the program of `process` for run `cookie`: false when
    /// it was settled at once (too large, another size, unreadable).
    fn start_reading(
        &mut self,
        cookie: u64,
        process: &crate::observation::GuestProcess,
        parent_name: Option<String>,
        limit: u32,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) -> bool {
        let timeout = self.reply_timeout();
        let path = format!("/proc/{}/exe", process.identity.tgid);
        let acquired = control::acquire(&path, 0, 0, limit).and_then(|args| {
            self.request(control::ACQUIRE, &args, snapshot, sender, timeout)
                .and_then(|reply| control::acquisition(&reply))
        });
        let Some(run) = self.runs.get_mut(&cookie) else {
            return false;
        };
        run.persisted.checks_left = run.persisted.checks_left.saturating_sub(1);
        let (id, size) = match acquired {
            Ok(pair) => pair,
            Err(error) => {
                // Larger than any image of the run: not a copy. Anything
                // else (busy, the process ended) may be tried again.
                let looked = if error.contains("File too large") {
                    Looked::NotACopy
                } else {
                    Looked::Unreadable(0)
                };
                run.persisted.note(process, looked);
                return false;
            }
        };
        if !run.persisted.size_known(size) {
            run.persisted.note(process, Looked::NotACopy);
            let _ = self.request(
                control::SPECIMEN_RELEASE,
                &control::with_session(id),
                snapshot,
                sender,
                timeout,
            );
            return false;
        }
        run.persisted.reading = Some(Reading {
            process: process.clone(),
            parent_name,
            id,
            size,
            offset: 0,
            hasher: sha2::Sha256::new(),
        });
        true
    }
}

impl Worker {
    /// One turn of the persisted-copy watch of every run that has one.
    pub(super) fn watch_persisted_copies(&mut self) {
        let revision = self.snapshot.guest_kernel.as_ref().and_then(|k| k.revision);
        let Some(session) = self.session.as_mut() else {
            return;
        };
        if self.snapshot.state != VmState::Running {
            return;
        }
        // A program being hashed is finished first.
        if let Some(cookie) = session
            .runs
            .iter()
            .find_map(|(cookie, run)| run.persisted.reading.is_some().then_some(*cookie))
        {
            session.continue_reading(cookie, &mut self.snapshot, &self.sender);
            return;
        }
        let due: Vec<u64> = session
            .runs
            .iter()
            .filter(|(_, run)| {
                run.watching()
                    && (matches!(run.persisted.final_look, FinalLook::Pending(_))
                        || run
                            .persisted
                            .last_poll
                            .is_none_or(|at| at.elapsed() >= persisted_copy::POLL))
            })
            .map(|(cookie, _)| *cookie)
            .collect();
        if due.is_empty() {
            return;
        }
        let timeout = session.reply_timeout();
        let listed = session.list_processes(0, &mut self.snapshot, &self.sender, timeout);
        let now_ms = unix_ms();
        for cookie in due {
            let Some(run) = session.runs.get_mut(&cookie) else {
                continue;
            };
            run.persisted.last_poll = Some(Instant::now());
            let final_look = match run.persisted.final_look {
                FinalLook::Pending(since) if since.elapsed() >= FINAL_LOOK_MAX => {
                    run.finish_final_look(true);
                    false
                }
                FinalLook::Pending(_) => true,
                _ => false,
            };
            let Ok(page) = listed.as_ref() else {
                continue;
            };
            if let Some(copies) = run.summary.persisted.as_mut() {
                persisted_copy::refresh(copies, &mut run.persisted, &page.processes, now_ms);
                let held_for = run
                    .persisted
                    .hold_since
                    .map_or(Duration::ZERO, |since| since.elapsed());
                if copies.holding
                    && run.persisted.final_look == FinalLook::Done
                    && let Some(why) = persisted_copy::hold_end(copies, held_for)
                {
                    run.end_hold(why);
                } else {
                    let _ = run.persist_summary();
                }
            }
            // New copies are looked for while the tree runs and in the last
            // look after it ended; a held run only follows the copies it has.
            if !final_look && !run.summary.state.is_live() && run.summary.state != RunState::Unknown
            {
                continue;
            }
            if run.persisted.reading.is_some() {
                continue;
            }
            if run.persisted.checks_left == 0 {
                if final_look {
                    run.finish_final_look(true);
                }
                continue;
            }
            let max = run.persisted.max_size();
            let Some(limit) = session.copy_read_limit(revision, max) else {
                if final_look && let Some(run) = session.runs.get_mut(&cookie) {
                    run.finish_final_look(true);
                }
                continue;
            };
            let Some(run) = session.runs.get(&cookie) else {
                continue;
            };
            let next = run
                .persisted
                .candidates(&page.processes, &run.tasks)
                .first()
                .map(|process| (*process).clone());
            let Some(process) = next else {
                if final_look && let Some(run) = session.runs.get_mut(&cookie) {
                    run.finish_final_look(true);
                }
                continue;
            };
            let parent_name = page
                .processes
                .iter()
                .find(|parent| parent.identity.tgid == process.parent_tgid)
                .map(|parent| parent.command.clone());
            session.start_reading(
                cookie,
                &process,
                parent_name,
                limit,
                &mut self.snapshot,
                &self.sender,
            );
            // One acquisition per turn across runs.
            break;
        }
    }
}
