// SPDX-License-Identifier: GPL-3.0-only
//! Check online in an Auto run (ANT-T0548 F2): the `online` item over the
//! recording fixture with indicators put into its scan, a fake sender in
//! place of `curl` and a fake key in the scratch data directory. Nothing
//! here reaches the network or uses a real key.
use super::{
    Hosted,
    host_tests::{Hooked, collected, data_dir, finished, hook, host, run_dir, world_with},
    tests::W,
};
use crate::api::run::{Run, RunState};
use antinomie_monitor_core::{
    api_keys::{self, ApiKey, Secret},
    ioc::{
        feeds,
        indicator::{Collector, Seen, Source, Via},
        online::{self, Body, THREATFOX_API, Transport},
        verdict::{LoadedFeed, Scan},
    },
};
use antinomie_triage::ioc_scan::IocScan;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

/// A key of the right shape that no service knows.
pub(super) const FAKE_KEY: &str = "fake-auth-key-for-tests-0000";

pub(super) const HIT: &str = r#"{"query_status":"ok","data":[{"id":"1844011","ioc":"gate.kd-relay.example","threat_type":"botnet_cc","ioc_type":"domain","malware":"elf.gafgyt","malware_printable":"Gafgyt","confidence_level":75,"first_seen":"2026-10-20 10:00:00 UTC","reference":null}]}"#;

type PostHook = Box<dyn Fn(usize, &AtomicBool) -> Result<(), String> + Send + Sync>;

/// abuse.ch as the tests see it: ThreatFox knows `gate.kd-relay.example`,
/// nothing else is known. `before` runs first for each request (its number
/// from 0); an `Err` is the request's result.
#[derive(Default)]
pub(super) struct FakeAbuse {
    pub(super) sent: Mutex<Vec<(String, String)>>,
    pub(super) keys: Mutex<Vec<String>>,
    pub(super) before: Option<PostHook>,
}

impl Transport for FakeAbuse {
    fn post(
        &self,
        url: &str,
        body: Body<'_>,
        key: &Secret,
        cancel: &AtomicBool,
    ) -> Result<String, String> {
        let text = match body {
            Body::Json(text) => text.to_owned(),
            Body::Form(fields) => fields
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("&"),
        };
        let n = {
            let mut sent = self.sent.lock().unwrap();
            sent.push((url.to_owned(), text.clone()));
            sent.len() - 1
        };
        self.keys.lock().unwrap().push(key.expose().to_owned());
        if let Some(before) = &self.before {
            before(n, cancel)?;
        }
        Ok(
            if url == THREATFOX_API && text.contains("gate.kd-relay.example") {
                HIT.into()
            } else {
                r#"{"query_status":"no_result"}"#.into()
            },
        )
    }
}

/// The run's indicators: two domains and a public endpoint, with the four
/// abuse.ch feeds loaded (no record in them: every value is `No match`).
pub(super) fn indicators(extra_domains: usize) -> Arc<IocScan> {
    let mut c = Collector::default();
    c.domain(
        "gate.kd-relay.example",
        Via::Dns,
        &[],
        Source::Pcap,
        Seen::default(),
    );
    c.endpoint(
        "198.51.100.23".parse().unwrap(),
        8443,
        "tcp",
        Source::Pcap,
        Seen::default(),
    );
    for n in 0..extra_domains {
        c.domain(
            &format!("host{n}.example"),
            Via::Dns,
            &[],
            Source::Pcap,
            Seen::default(),
        );
    }
    let mut scan = Scan::default();
    scan.loaded = ["threatfox", "urlhaus", "sslbl-ja3", "feodo"]
        .iter()
        .map(|id| {
            let feed = feeds::feed(id).unwrap();
            LoadedFeed {
                id: feed.id,
                name: feed.name,
                date: "2026-11-01".into(),
                fetched_unix: 0,
            }
        })
        .collect();
    let mut ioc = IocScan::for_tests(c.finish());
    ioc.scan = Arc::new(scan);
    Arc::new(ioc)
}

/// A world whose preset has `check_online = on`, with the fake sender and
/// the run's indicators; `key` stores the fake key.
pub(super) fn online_world(name: &str, on: bool, key: bool, fake: &Arc<FakeAbuse>) -> W {
    online_world_with(name, on, key, fake, indicators(0))
}

fn online_world_with(
    name: &str,
    on: bool,
    key: bool,
    fake: &Arc<FakeAbuse>,
    ioc: Arc<IocScan>,
) -> W {
    let mut w = world_with(name, |p| p.detection.check_online = on);
    if key {
        api_keys::set(&data_dir(&w), ApiKey::Abusech, FAKE_KEY).unwrap();
    }
    let transport: Arc<dyn Transport + Send + Sync> = fake.clone();
    hook(&mut w, |h: &mut Hooked| {
        h.ioc = Some(ioc);
        h.transport = Some(transport);
    });
    w
}

fn warning<'a>(job: &'a Run, code: &str) -> Option<&'a str> {
    job.warnings
        .iter()
        .find(|x| x.code == code)
        .map(|x| x.text.as_str())
}

/// Every place the key could leak to: the run object, its events, its
/// artifacts, the recording's files.
pub(super) fn assert_no_key(w: &W, job: &Run) {
    let run = serde_json::to_string(&w.job(&job.id)).unwrap();
    assert!(!run.contains(FAKE_KEY), "the run object holds the key");
    let events = w.fx.store.events_list(&job.id, 0, 1000).unwrap().0;
    let events = serde_json::to_string(&events).unwrap();
    assert!(!events.contains(FAKE_KEY), "an event holds the key");
    for dir in [w.fx.store.job_dir(&job.id), run_dir(w)] {
        let mut stack = vec![dir];
        while let Some(next) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&next) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(bytes) = std::fs::read(&path) {
                    assert!(
                        !String::from_utf8_lossy(&bytes).contains(FAKE_KEY),
                        "{} holds the key",
                        path.display()
                    );
                }
            }
        }
    }
}

#[test]
fn check_online_off_sends_nothing_and_keeps_no_answers() {
    let fake = Arc::new(FakeAbuse::default());
    let w = online_world("online-off", false, true, &fake);
    let job = collected(&w, 1);
    let mut waiter = w.engine(|_| {});
    let done = finished(host(&w, &mut waiter, &job));
    assert_eq!(done.state, RunState::Succeeded, "{:?}", done.warnings);
    assert!(fake.sent.lock().unwrap().is_empty(), "no request was made");
    assert!(!run_dir(&w).join("ioc-online.json").exists());
    assert!(
        done.warnings.iter().all(|x| !x.code.starts_with("online")),
        "{:?}",
        done.warnings
    );
    // Off in every built-in preset.
    for (name, preset) in crate::config::validate::built_in_presets() {
        assert!(!preset.preset.detection.check_online, "{name}");
    }
}

#[test]
fn check_online_asks_abuse_ch_and_the_answers_reach_the_report() {
    let fake = Arc::new(FakeAbuse::default());
    let w = online_world("online-on", true, true, &fake);
    let job = collected(&w, 1);
    let mut waiter = w.engine(|_| {});
    let done = finished(host(&w, &mut waiter, &job));
    assert_eq!(done.state, RunState::Succeeded, "{:?}", done.warnings);
    // Two values, each to ThreatFox and to the URLhaus host lookup, with the
    // node's key handed to the sender.
    let sent = fake.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 4, "{sent:?}");
    assert!(sent[0].1.contains("gate.kd-relay.example"), "{sent:?}");
    assert!(sent[2].1.contains("198.51.100.23:8443"), "{sent:?}");
    assert!(fake.keys.lock().unwrap().iter().all(|k| k == FAKE_KEY));
    // The answers are kept with the recording, where the desktop reads them.
    let kept = online::load(&run_dir(&w));
    assert_eq!(kept.entries.len(), 2);
    let hit = kept
        .entry(
            antinomie_monitor_core::ioc::kind::Kind::Domain,
            "gate.kd-relay.example",
        )
        .expect("the domain's answer");
    assert_eq!(hit.records[0].family, "Gafgyt");
    // The JSON report shows the online match with its link.
    let report = done
        .artifacts
        .iter()
        .find(|a| a.kind == crate::api::artifact::ArtifactKind::ReportJson)
        .expect("a JSON report");
    let text = std::fs::read_to_string(
        w.fx.store
            .job_dir(&job.id)
            .join("artifacts")
            .join(&report.name),
    )
    .unwrap();
    assert!(text.contains("threatfox.abuse.ch/ioc/1844011/"), "{text}");
    assert!(text.contains("Gafgyt"));
    assert!(
        api_keys::last_used(&data_dir(&w), ApiKey::Abusech).is_some(),
        "the key's use is noted (a time only)"
    );
    assert_no_key(&w, &job);
}

#[test]
fn without_a_key_the_step_is_skipped_no_key_and_the_run_completes() {
    let fake = Arc::new(FakeAbuse::default());
    let w = online_world("online-nokey", true, false, &fake);
    let job = collected(&w, 1);
    let mut waiter = w.engine(|_| {});
    let done = finished(host(&w, &mut waiter, &job));
    assert_eq!(done.state, RunState::Succeeded, "{:?}", done.warnings);
    assert!(fake.sent.lock().unwrap().is_empty());
    let text = warning(&done, "online_skipped").expect("a warning");
    assert!(text.contains("no_key"), "{text}");
    assert!(!done.artifacts.is_empty(), "the reports are still written");
}

#[test]
fn a_cancel_during_the_lookups_stops_them_and_ends_the_run_cancelled() {
    use std::sync::mpsc;
    let (ask, asked) = mpsc::channel::<()>();
    let (ack, acked) = mpsc::channel::<()>();
    let acked = Mutex::new(acked);
    let ask = Mutex::new(ask);
    let fake = Arc::new(FakeAbuse {
        before: Some(Box::new(move |_, cancel| {
            ask.lock().unwrap().send(()).unwrap();
            acked.lock().unwrap().recv().unwrap();
            while !cancel.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err("cancelled".into())
        })),
        ..FakeAbuse::default()
    });
    let w = online_world("online-cancel", true, true, &fake);
    let job = collected(&w, 1);
    let store = &w.fx.store;
    let id = job.id.clone();
    let hosted = std::thread::scope(|scope| {
        scope.spawn(move || {
            if asked
                .recv_timeout(std::time::Duration::from_secs(60))
                .is_ok()
            {
                store
                    .cancel(&id, Some("test"), &crate::store::tests::manager())
                    .unwrap();
                let _ = ack.send(());
            }
        });
        let mut waiter = w.engine(|_| {});
        host(&w, &mut waiter, &job)
    });
    let Hosted::Cancelled(done) = hosted else {
        panic!("cancelled: {hosted:?}");
    };
    assert_eq!(done.state, RunState::Cancelled);
    assert_eq!(fake.sent.lock().unwrap().len(), 1, "no request after it");
    assert_no_key(&w, &job);
}

#[test]
fn the_time_limit_ends_the_step_and_keeps_the_answers_so_far() {
    let fake_slot: Arc<Mutex<Option<Arc<crate::clock::ManualClock>>>> = Arc::default();
    let clock_for_hook = Arc::clone(&fake_slot);
    let fake = Arc::new(FakeAbuse {
        before: Some(Box::new(move |n, cancel| {
            if n < 2 {
                return Ok(());
            }
            // The third request (the second value) hangs past the limit.
            if let Some(clock) = clock_for_hook.lock().unwrap().as_ref() {
                clock.advance(301_000);
            }
            while !cancel.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err("cancelled".into())
        })),
        ..FakeAbuse::default()
    });
    let w = online_world("online-late", true, true, &fake);
    *fake_slot.lock().unwrap() = Some(w.fx.clock.clone());
    let job = collected(&w, 1);
    let mut waiter = w.engine(|_| {});
    let done = finished(host(&w, &mut waiter, &job));
    assert_eq!(
        done.state,
        RunState::Succeeded,
        "the evidence is whole: {:?}",
        done.warnings
    );
    let text = warning(&done, "online_incomplete").expect("a warning");
    assert!(
        text.contains("1 value sent") && text.contains("time limit"),
        "{text}"
    );
    assert_eq!(online::load(&run_dir(&w)).entries.len(), 1, "kept");
}

#[test]
fn a_refused_request_never_shows_the_key() {
    let fake = Arc::new(FakeAbuse {
        before: Some(Box::new(|_, _| {
            Err(format!(
                "curl: (22) header 'Auth-Key: {FAKE_KEY}' refused by {THREATFOX_API}"
            ))
        })),
        ..FakeAbuse::default()
    });
    let w = online_world("online-refused", true, true, &fake);
    let job = collected(&w, 1);
    let mut waiter = w.engine(|_| {});
    let done = finished(host(&w, &mut waiter, &job));
    assert_eq!(done.state, RunState::Succeeded, "{:?}", done.warnings);
    assert_eq!(
        fake.sent.lock().unwrap().len(),
        1,
        "the first error ends it"
    );
    let text = warning(&done, "online_incomplete").expect("a warning");
    assert!(text.contains("[redacted]"), "{text}");
    assert!(!run_dir(&w).join("ioc-online.json").exists());
    assert_no_key(&w, &job);
}

#[test]
fn at_most_fifty_values_are_sent_per_run() {
    let fake = Arc::new(FakeAbuse::default());
    let w = online_world_with("online-bound", true, true, &fake, indicators(60));
    let job = collected(&w, 1);
    let mut waiter = w.engine(|_| {});
    let done = finished(host(&w, &mut waiter, &job));
    assert_eq!(done.state, RunState::Succeeded, "{:?}", done.warnings);
    assert_eq!(fake.sent.lock().unwrap().len(), 2 * online::MAX_LOOKUPS);
    let text = warning(&done, "online_incomplete").expect("a warning");
    assert!(
        text.contains("50 values sent") && text.contains("12 not sent"),
        "{text}"
    );
    assert_eq!(
        online::load(&run_dir(&w)).entries.len(),
        online::MAX_LOOKUPS
    );
}
