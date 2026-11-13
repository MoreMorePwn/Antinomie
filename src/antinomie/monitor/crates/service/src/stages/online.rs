// SPDX-License-Identifier: GPL-3.0-only
//! Check online in an Auto run (ANT-T0548 F2, user decision 2026-11-14):
//! the `online` host work item of a run whose frozen preset has
//! `[detection] check_online = true` (off in every built-in preset; the
//! caller needs `lookup.online`, checked at submit and when the run starts).
//!
//! It is the desktop's Check online (Triage > IOC) over the whole run, with
//! the same code (`antinomie_monitor_core::ioc::online`):
//!
//! * **What is sent:** after `triage`, the public values the downloaded
//!   indicator datasets do not list ([`online::candidates`]: files first,
//!   then URLs, domains, endpoints; never a private address, a local name, a
//!   known false positive, a JA3 or certificate fingerprint, the base image's
//!   own traffic, or a file), each to ThreatFox and URLhaus, one request at a
//!   time from the host (never from the lab VM), through the system `curl`
//!   with the shared hardening and the process's proxy variables.
//! * **Bounds:** at most [`ONLINE_MAX_VALUES`] values per run (the desktop's
//!   per-press bound), at most [`ONLINE_WAIT`] for the whole step, one online
//!   step at a time on the node (the desktop's one check at a time), and a
//!   refused key or an HTTP 429 ends the step at once. A cancel of the run or
//!   the time limit stops the request in flight; the answers so far are kept.
//! * **Key:** the abuse.ch Auth-Key of the node's data directory
//!   (`<data>/api-keys.json`, mode 0600, `antinomie-cli config api-key set
//!   abusech`), handed to `curl` on its standard input. No key: the step is
//!   skipped with `no_key` and a warning; the run is not refused.
//! * **Results:** the answers go into the recording's `ioc-online.json`, the
//!   file the desktop keeps them in, before `assess` and `report`: the
//!   summary, the label and every report show an indicator abuse.ch knows as
//!   `Matched · online` with its dataset, family or tags and link, as the
//!   desktop does. The step's account ([`OnlineCheck`]) is on the item in
//!   `host_work`; a step that did not finish is a warning of the run. Neither
//!   changes the run's outcome: the evidence is complete without it.
use super::{
    LaneStages, StageStop,
    analyse::Bounded,
    items::{ItemEnd, ended},
    plan::ONLINE_WAIT,
};
use crate::{
    api::run::{
        HostItemState, ONLINE_MAX_VALUES, OnlineCheck, OnlineReason, OnlineStatus, Run, Stage,
    },
    engine::Engine,
    store::lock,
};
use antinomie_monitor_core::{
    api_keys::{self, ApiKey, Secret},
    ioc::{
        feeds,
        online::{self, Body, Transport},
    },
};
use antinomie_triage::{ArchiveScan, SavedRun, ioc_scan};
use std::{
    path::PathBuf,
    sync::{
        Mutex, MutexGuard, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// What the step needs from the node ([`super::host::HostTriage::online_access`]).
pub struct OnlineAccess {
    /// The abuse.ch Auth-Key; empty when none is stored.
    pub key: Secret,
    pub transport: Box<dyn Transport + Send + Sync>,
    /// Where the key's last use is noted (`api-key-use.json`, a time only).
    pub key_dir: Option<PathBuf>,
}

impl OnlineAccess {
    /// No key and nothing that sends: the step is skipped with `no_key`.
    pub fn none() -> Self {
        Self {
            key: Secret::default(),
            transport: Box::new(Refuse),
            key_dir: None,
        }
    }
}

/// Sends nothing.
struct Refuse;

impl Transport for Refuse {
    fn post(&self, _: &str, _: Body<'_>, _: &Secret, _: &AtomicBool) -> Result<String, String> {
        Err("this node sends no online lookups".into())
    }
}

/// One online step at a time on the node: the requests of all runs go to
/// abuse.ch one after another, as the desktop's one check at a time.
static GATE: Mutex<()> = Mutex::new(());

/// The gate, or `None` when `cancel` was set while waiting for it.
fn gate(cancel: &AtomicBool) -> Option<MutexGuard<'static, ()>> {
    loop {
        match GATE.try_lock() {
            Ok(guard) => return Some(guard),
            Err(TryLockError::Poisoned(poisoned)) => return Some(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => {}
        }
        if cancel.load(Ordering::Relaxed) {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// What the worker did.
struct Asked {
    checked: online::Checked,
    kept: Result<(), String>,
}

/// The account of a step that sent nothing.
fn skipped(reason: OnlineReason) -> OnlineCheck {
    OnlineCheck {
        status: OnlineStatus::Skipped,
        reason: Some(reason),
        asked: 0,
        found: 0,
        left_out: 0,
        error: None,
    }
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// The account of a step that had `total` values to send.
fn account(total: usize, asked: Option<Asked>, timed_out: bool, key: &Secret) -> OnlineCheck {
    let Some(Asked { checked, kept }) = asked else {
        // The worker ended before it reported: out of time waiting for the
        // node's other online step, or it failed.
        return OnlineCheck {
            status: OnlineStatus::Failed,
            reason: Some(if timed_out {
                OnlineReason::TimeLimit
            } else {
                OnlineReason::Error
            }),
            asked: 0,
            found: 0,
            left_out: count(total),
            error: (!timed_out).then(|| "the online check failed unexpectedly".into()),
        };
    };
    let some = checked.asked > 0;
    let partly = if some {
        OnlineStatus::Partial
    } else {
        OnlineStatus::Failed
    };
    let (status, reason, error) = if let Err(error) = kept {
        (
            OnlineStatus::Failed,
            Some(OnlineReason::Error),
            Some(format!("the answers were not kept: {error}")),
        )
    } else if timed_out {
        (partly, Some(OnlineReason::TimeLimit), None)
    } else if let Some(error) = checked.error {
        (partly, Some(OnlineReason::Error), Some(error))
    } else if checked.skipped > 0 {
        (OnlineStatus::Partial, Some(OnlineReason::Limit), None)
    } else {
        (OnlineStatus::Done, None, None)
    };
    OnlineCheck {
        status,
        reason,
        asked: count(checked.asked),
        found: count(checked.found),
        left_out: count(total.saturating_sub(checked.asked)),
        error: error.map(|text| api_keys::redact(&text, &[key])),
    }
}

/// The item's state and note for an account.
fn item_end(check: OnlineCheck) -> ItemEnd {
    let state = match (check.status, check.reason) {
        (OnlineStatus::Skipped, _) => HostItemState::Skipped,
        (_, Some(OnlineReason::TimeLimit)) => HostItemState::TimedOut,
        (OnlineStatus::Done, _) | (OnlineStatus::Partial, Some(OnlineReason::Limit)) => {
            HostItemState::Done
        }
        _ => HostItemState::Failed,
    };
    ItemEnd {
        online: Some(check.clone()),
        ..ended(state, note(&check))
    }
}

/// The account in words: the item's note and the run's warning.
fn note(check: &OnlineCheck) -> Option<String> {
    if check.status == OnlineStatus::Skipped {
        return Some(match check.reason {
            Some(OnlineReason::NoKey) => {
                "no_key: no abuse.ch Auth-Key is stored on this node, nothing was sent".into()
            }
            Some(OnlineReason::NoTriage) => {
                "no_triage: the Triage scan gave no indicators, nothing was sent".into()
            }
            Some(OnlineReason::NoDatasets) => "no_datasets: no indicator dataset is downloaded \
                 (Check online asks only about values the datasets do not list), nothing was sent"
                .into(),
            _ => "nothing was sent".into(),
        });
    }
    let mut text = format!(
        "{} value{} sent to abuse.ch, {} found",
        check.asked,
        if check.asked == 1 { "" } else { "s" },
        check.found
    );
    if check.left_out > 0 {
        text.push_str(&format!(", {} not sent", check.left_out));
    }
    match check.reason {
        Some(OnlineReason::Limit) => {
            text.push_str(&format!(" (at most {ONLINE_MAX_VALUES} per run)"));
        }
        Some(OnlineReason::TimeLimit) => text.push_str(&format!(
            " (the step's time limit of {} s ended it)",
            ONLINE_WAIT.as_secs()
        )),
        _ => {}
    }
    if let Some(error) = &check.error {
        text.push_str(&format!(": {error}"));
    }
    Some(text)
}

impl<E: Engine> LaneStages<'_, E> {
    /// The `online` item: ask abuse.ch about the run's indicators the
    /// datasets do not list. Never a problem of the analysis: what it could
    /// not do is a warning and its account on the item.
    pub(super) fn online_item(
        &mut self,
        job: &Run,
        scanned: Option<&(SavedRun, ArchiveScan)>,
        limit: Duration,
    ) -> Result<ItemEnd, StageStop> {
        let check = self.online_check(job, scanned, limit)?;
        if check.status != OnlineStatus::Done
            && let Some(text) = note(&check)
        {
            let code = if check.status == OnlineStatus::Skipped {
                "online_skipped"
            } else {
                "online_incomplete"
            };
            self.warn(job, code, &format!("Check online: {text}"));
        }
        Ok(item_end(check))
    }

    fn online_check(
        &mut self,
        job: &Run,
        scanned: Option<&(SavedRun, ArchiveScan)>,
        limit: Duration,
    ) -> Result<OnlineCheck, StageStop> {
        let access = self.env.triage.online_access();
        if access.key.is_empty() {
            return Ok(skipped(OnlineReason::NoKey));
        }
        let Some((saved, ioc)) =
            scanned.and_then(|(saved, scan)| scan.ioc.as_deref().map(|ioc| (saved, ioc)))
        else {
            return Ok(skipped(OnlineReason::NoTriage));
        };
        if ioc.scan.loaded.is_empty() {
            return Ok(skipped(OnlineReason::NoDatasets));
        }
        let run_dir = saved.run.directory.clone();
        let (fp, before) = ioc_scan::run_inputs(saved.settings.data_dir.as_deref(), &run_dir);
        let verdicts = ioc_scan::verdicts(ioc, &fp, &before);
        let lookups = online::candidates(&ioc.indicators, &verdicts);
        if lookups.is_empty() {
            return Ok(OnlineCheck {
                status: OnlineStatus::Done,
                reason: None,
                asked: 0,
                found: 0,
                left_out: 0,
                error: None,
            });
        }
        let sending = lookups.len().min(online::MAX_LOOKUPS);
        self.progress(
            job,
            Stage::Analyse,
            &format!("asking abuse.ch about {sending} values"),
        );
        let slot: Mutex<Option<Asked>> = Mutex::new(None);
        let worked = self.bounded(limit, |cancel| {
            let Some(_gate) = gate(cancel) else {
                return;
            };
            let mut results = before.clone();
            let checked = online::check(
                access.transport.as_ref(),
                &access.key,
                &lookups,
                feeds::now_unix(),
                &mut results,
                cancel,
            );
            let kept = if checked.asked > 0 {
                if let Some(dir) = &access.key_dir {
                    api_keys::record_use(dir, ApiKey::Abusech);
                }
                online::save(&run_dir, &results)
            } else {
                Ok(())
            };
            *lock(&slot) = Some(Asked { checked, kept });
        });
        let timed_out = match worked {
            Ok(()) => false,
            Err(Bounded::TimedOut) => true,
            Err(why) => match why.stop() {
                Some(stop) => return Err(stop),
                None => false,
            },
        };
        let asked = slot.into_inner().unwrap_or_else(|p| p.into_inner());
        Ok(account(lookups.len(), asked, timed_out, &access.key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checked(asked: usize, found: usize, skipped: usize, error: Option<&str>) -> Option<Asked> {
        Some(Asked {
            checked: online::Checked {
                asked,
                found,
                skipped,
                error: error.map(str::to_owned),
            },
            kept: Ok(()),
        })
    }

    #[test]
    fn the_account_says_done_partial_or_failed_and_never_holds_the_key() {
        let key = Secret::new("fake-online-key-0000");
        let done = account(3, checked(3, 1, 0, None), false, &key);
        assert_eq!((done.status, done.reason), (OnlineStatus::Done, None));
        assert_eq!(item_end(done).state, HostItemState::Done);

        let bound = account(60, checked(50, 0, 10, None), false, &key);
        assert_eq!(
            (bound.status, bound.reason, bound.left_out),
            (OnlineStatus::Partial, Some(OnlineReason::Limit), 10)
        );
        let end = item_end(bound);
        assert_eq!(end.state, HostItemState::Done);
        assert!(end.note.unwrap().contains("at most 50 per run"));

        let late = account(5, checked(2, 0, 0, Some("cancelled")), true, &key);
        assert_eq!(
            (late.status, late.reason, late.left_out),
            (OnlineStatus::Partial, Some(OnlineReason::TimeLimit), 3)
        );
        assert_eq!(item_end(late).state, HostItemState::TimedOut);

        let refused = account(
            5,
            checked(0, 0, 0, Some("abuse.ch echoed fake-online-key-0000")),
            false,
            &key,
        );
        assert_eq!(refused.status, OnlineStatus::Failed);
        let error = refused.error.clone().unwrap();
        assert!(!error.contains("fake-online-key-0000"), "{error}");
        let end = item_end(refused);
        assert_eq!(end.state, HostItemState::Failed);
        assert!(!end.note.unwrap().contains("fake-online-key"));

        let waited = account(5, None, true, &key);
        assert_eq!(
            (waited.status, waited.reason, waited.left_out),
            (OnlineStatus::Failed, Some(OnlineReason::TimeLimit), 5)
        );
        let no_key = item_end(skipped(OnlineReason::NoKey));
        assert_eq!(no_key.state, HostItemState::Skipped);
        assert!(no_key.note.unwrap().starts_with("no_key:"));
    }
}
