// SPDX-License-Identifier: GPL-3.0-only
//! `ioc datasets list|update|enable|disable` (ANT-T0548 F2b): the abuse.ch
//! IOC datasets of the data directory, the files the window's Tools >
//! Detection rules > IOC downloads and that Triage, the reports and an Auto
//! run's Check online read.
//!
//! The download is the window's own code (`ioc::download` in the core): the
//! same sources, the same folder (`<data>/ioc/feeds/<name>/`), the same
//! checks before a new copy replaces the old one, and the same switch
//! (`outbound_catalog`, the window's Allow outbound catalog and rule
//! downloads). The abuse.ch Auth-Key comes only from `api-keys.json`
//! (`config api-key set abusech`); it reaches curl on standard input and is
//! taken out of every message. No engine lock is taken, so a daemon may
//! serve meanwhile (it reads the datasets at each run); the datasets' own
//! lock keeps one update at a time.
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    exit::Exit,
    output::{Reply, table},
    signals,
};
use antinomie_monitor_core::{
    api_keys::{self, ApiKey, Secret},
    ioc::{
        self,
        download::UPDATE_BUSY,
        feeds::{self, Feed, FeedStatus},
    },
    lanes::{self, SharedWrite},
    ruleset::Curl,
    settings,
};
use clap::Subcommand;
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Subcommand, Debug)]
pub enum Ioc {
    /// The abuse.ch datasets the indicators of a run are matched against
    /// (ThreatFox, URLhaus, Feodo Tracker, SSLBL), kept in `<data>/ioc/`, the
    /// folder the window's Tools > Detection rules > IOC uses. An Auto run's
    /// Check online needs at least one of them.
    #[command(subcommand)]
    Datasets(Datasets),
}

#[derive(Subcommand, Debug)]
pub enum Datasets {
    /// Every dataset: switched on or off, the stored copy's records and date,
    /// whether it needs the abuse.ch Auth-Key. Reads only.
    List,
    /// Download NAME..., or every dataset that is switched on, from abuse.ch.
    /// Needs `config set outbound_catalog true` (the window's Allow outbound
    /// catalog and rule downloads; exit 5 otherwise) and, for ThreatFox and
    /// the URLhaus datasets, the abuse.ch Auth-Key stored with `config
    /// api-key set abusech` (without it nothing is downloaded, exit 5). A failed download
    /// keeps the previous copy (exit 21); Ctrl-C stops (exit 130). No engine
    /// lock: run it while a daemon serves, or from cron or a systemd timer.
    Update {
        /// Dataset names as `ioc datasets list` shows them (`threatfox`,
        /// `feodo`, ...).
        names: Vec<String>,
    },
    /// Switch a dataset on: `update` downloads it and matching uses it.
    Enable { name: String },
    /// Switch a dataset off: not downloaded, not used; its copy stays.
    Disable { name: String },
}

pub fn run(ioc: &Ioc, context: &Context) -> Result<Reply, CliError> {
    let Ioc::Datasets(datasets) = ioc;
    match datasets {
        Datasets::List => Ok(list(context)),
        Datasets::Update { names } => update(names, context),
        Datasets::Enable { name } => switch(name, true, context),
        Datasets::Disable { name } => switch(name, false, context),
    }
}

/// The window names its key dialog; a node has the command instead.
fn node_words(text: &str) -> String {
    text.replace(
        "in Tools > API keys",
        "with `antinomie-cli config api-key set abusech`",
    )
}

/// The state of a dataset in one word, as the window's chip says it.
fn state(status: &FeedStatus, now: u64) -> &'static str {
    match (&status.meta, status.last_error.is_some(), status.enabled) {
        (_, _, false) => "off",
        (None, true, _) => "failed",
        (None, false, _) => "not_downloaded",
        (Some(_), true, _) => "update_failed",
        (Some(meta), false, _) if meta.stale(now) => "old",
        (Some(_), false, _) => "loaded",
    }
}

fn item(data: &Path, status: &FeedStatus, now: u64) -> Value {
    let feed = status.feed;
    let meta = status.meta.as_ref();
    json!({
        "name": feed.id,
        "title": feed.name,
        "enabled": status.enabled,
        "state": state(status, now),
        "usable": status.usable(),
        "records": meta.map(|m| m.records),
        "fetched": meta.map(|m| m.date()),
        "age_days": meta.map(|m| m.age_days(now)),
        "needs_key": feed.needs_key,
        "used_for": feed.used_for,
        "license": feed.license(),
        "source": feed.url_display(),
        "file": feeds::data_path(data, feed),
        "last_error": status.last_error.as_deref().map(node_words),
    })
}

fn list(context: &Context) -> Reply {
    let data = context.data_dir();
    let now = feeds::now_unix();
    let statuses = feeds::status(data);
    let items: Vec<Value> = statuses
        .iter()
        .map(|status| item(data, status, now))
        .collect();
    let rows: Vec<Vec<String>> = statuses
        .iter()
        .map(|status| {
            let meta = status.meta.as_ref();
            vec![
                status.feed.id.to_owned(),
                state(status, now).replace('_', " "),
                meta.map_or("-".into(), |m| m.records.to_string()),
                meta.map_or("-".into(), |m| m.date()),
                if status.feed.needs_key { "yes" } else { "no" }.to_owned(),
                status.feed.name.to_owned(),
            ]
        })
        .collect();
    let mut human = table(
        &["name", "state", "records", "fetched", "key", "title"],
        &rows,
    );
    let key = api_keys::get(data, ApiKey::Abusech);
    human.push_str(&format!(
        "folder: {}\nabuse.ch Auth-Key: {}\n",
        feeds::root(data).join("feeds").display(),
        if key.is_empty() {
            "not stored (`antinomie-cli config api-key set abusech < key.txt`)".to_owned()
        } else {
            format!("stored ({})", api_keys::masked(&key))
        }
    ));
    let usable = statuses.iter().filter(|status| status.usable()).count();
    match feeds::age_line(&statuses, now) {
        Some(age) => human.push_str(&format!("{usable} in use; {age}\n")),
        None => human.push_str(
            "none downloaded: Check online is skipped (no_datasets) until `ioc datasets update`\n",
        ),
    }
    Reply::list(items, None).with_human(human)
}

/// The dataset `name` names; exit 3 when none does.
fn named(name: &str) -> Result<&'static Feed, CliError> {
    feeds::feed(name).ok_or_else(|| {
        let known: Vec<&str> = feeds::FEEDS.iter().map(|feed| feed.id).collect();
        CliError::not_found(format!(
            "no dataset named {name:?}; the datasets are {}",
            known.join(", ")
        ))
        .with_field("name")
    })
}

fn switch(name: &str, enabled: bool, context: &Context) -> Result<Reply, CliError> {
    let feed = named(name)?;
    feeds::set_enabled(context.data_dir(), feed.id, enabled).map_err(CliError::invalid)?;
    Ok(
        Reply::value(json!({"name": feed.id, "enabled": enabled})).with_human(format!(
            "{} is now {}.\n",
            feed.id,
            if enabled { "on" } else { "off" }
        )),
    )
}

/// The datasets an update asks for: the named ones (each known and switched
/// on), else every one that is switched on.
fn chosen(names: &[String], statuses: &[FeedStatus]) -> Result<Vec<&'static Feed>, CliError> {
    if names.is_empty() {
        let on: Vec<&'static Feed> = statuses
            .iter()
            .filter(|status| status.enabled)
            .map(|status| status.feed)
            .collect();
        if on.is_empty() {
            return Err(CliError::invalid(
                "every dataset is switched off; `ioc datasets enable NAME` switches one on",
            ));
        }
        return Ok(on);
    }
    let mut feeds_wanted: Vec<&'static Feed> = Vec::new();
    for name in names {
        let feed = named(name)?;
        let on = statuses
            .iter()
            .any(|status| status.feed.id == feed.id && status.enabled);
        if !on {
            return Err(CliError::invalid(format!(
                "{} is switched off; `ioc datasets enable {}` switches it on",
                feed.id, feed.id
            ))
            .with_field("name"));
        }
        if !feeds_wanted.contains(&feed) {
            feeds_wanted.push(feed);
        }
    }
    Ok(feeds_wanted)
}

/// The refusals that come before any request: downloads switched off, a
/// lane's folder, a needed key that is not stored.
fn preflight(data: &Path, wanted: &[&'static Feed], key: &Secret) -> Result<(), CliError> {
    lanes::refuse_in_lane(data, SharedWrite::FeedUpdate).map_err(CliError::invalid)?;
    let stored = settings::load(data)
        .map_err(|error| {
            CliError::new(
                ErrorCode::PreconditionFailed,
                format!("settings.json cannot be read: {error}"),
            )
        })?
        .unwrap_or_default();
    if !stored.outbound_catalog {
        return Err(CliError::new(
            ErrorCode::UnavailableOnNode,
            "downloads are off: run `antinomie-cli config set outbound_catalog true` (the window's Allow outbound catalog and rule downloads) to allow the dataset downloads",
        )
        .with_details(json!({"what": "outbound_catalog"})));
    }
    let need: Vec<&'static Feed> = wanted
        .iter()
        .copied()
        .filter(|feed| feed.needs_key)
        .collect();
    if key.is_empty() && !need.is_empty() {
        let free: Vec<&str> = wanted
            .iter()
            .filter(|feed| !feed.needs_key)
            .map(|feed| feed.id)
            .collect();
        let names: Vec<&str> = need.iter().map(|feed| feed.id).collect();
        let mut message = format!(
            "{} need{} the abuse.ch Auth-Key (free at auth.abuse.ch) and none is stored: store it with `antinomie-cli config api-key set abusech < key.txt`",
            names.join(", "),
            if names.len() == 1 { "s" } else { "" }
        );
        if !free.is_empty() {
            message.push_str(&format!(
                ", or name the datasets that need none (`ioc datasets update {}`)",
                free.join(" ")
            ));
        }
        message.push_str("; nothing was downloaded");
        return Err(CliError::new(ErrorCode::UnavailableOnNode, message)
            .with_details(json!({"what": "abusech_key", "needs_key": names})));
    }
    Ok(())
}

fn update(names: &[String], context: &Context) -> Result<Reply, CliError> {
    let data = context.data_dir();
    let wanted = chosen(names, &feeds::status(data))?;
    let key = api_keys::get(data, ApiKey::Abusech);
    preflight(data, &wanted, &key)?;
    signals::install();
    let cancel = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let watcher = {
        let (cancel, done) = (Arc::clone(&cancel), Arc::clone(&done));
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                if signals::interrupted() {
                    cancel.store(true, Ordering::Relaxed);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        })
    };
    let fetcher = Curl::new(context.options.curl.clone());
    let logger = context.logger;
    let mut show = |line: &str| logger.info(line);
    let outcomes = if names.is_empty() {
        ioc::update_all(data, &key, &fetcher, &cancel, &mut show)
    } else {
        let mut outcomes = Vec::new();
        for feed in wanted.iter().copied() {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            let result = ioc::update_feed(data, feed, &key, &fetcher, &cancel, &mut show);
            outcomes.push(ioc::Outcome { feed, result });
        }
        outcomes
    };
    done.store(true, Ordering::Relaxed);
    let _ = watcher.join();
    if outcomes
        .iter()
        .any(|outcome| outcome.feed.needs_key && outcome.result.is_ok())
    {
        api_keys::record_use(data, ApiKey::Abusech);
    }
    finish(data, &outcomes, &key, cancel.load(Ordering::Relaxed))
}

/// The result of an update: every dataset updated (exit 0), or what failed.
fn finish(
    data: &Path,
    outcomes: &[ioc::Outcome],
    key: &Secret,
    interrupted: bool,
) -> Result<Reply, CliError> {
    let words = |text: &str| node_words(&api_keys::redact(text, &[key]));
    let rows: Vec<Value> = outcomes
        .iter()
        .map(|outcome| match &outcome.result {
            Ok(meta) => json!({
                "name": outcome.feed.id, "title": outcome.feed.name, "ok": true,
                "records": meta.records, "fetched": meta.date(), "error": null,
            }),
            Err(error) => json!({
                "name": outcome.feed.id, "title": outcome.feed.name, "ok": false,
                "records": null, "fetched": null, "error": words(error),
            }),
        })
        .collect();
    let updated = outcomes.iter().filter(|o| o.result.is_ok()).count();
    let failed = outcomes.len() - updated;
    let lines: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            let text = |key: &str| row[key].as_str().unwrap_or("").to_owned();
            vec![
                text("name"),
                if row["ok"] == true {
                    format!("updated: {} records, {}", row["records"], text("fetched"))
                } else {
                    format!("failed: {}", text("error"))
                },
            ]
        })
        .collect();
    let human = table(&["name", "result"], &lines);
    let folder = feeds::root(data).join("feeds");
    let value = json!({
        "updated": updated,
        "failed": failed,
        "folder": folder,
        "datasets": rows,
    });
    let summary = words(&ioc::update_summary(outcomes));
    if interrupted {
        return Err(CliError::new(
            ErrorCode::Internal,
            format!("interrupted; a dataset not updated keeps its previous copy. {summary}"),
        )
        .with_details(value)
        .with_human_output(human)
        .with_exit(Exit::Interrupted));
    }
    if failed == 0 {
        return Ok(Reply::value(value).with_human(format!("{human}{summary}\n")));
    }
    let busy = updated == 0
        && outcomes.iter().all(|outcome| {
            outcome
                .result
                .as_ref()
                .is_err_and(|error| error.contains(UPDATE_BUSY))
        });
    let message = if busy {
        format!(
            "{UPDATE_BUSY} (the window's Tools > Detection rules > IOC or another antinomie-cli); try again when it ends"
        )
    } else {
        format!("{summary} The previous copies were kept.")
    };
    Err(CliError::new(ErrorCode::Unavailable, message)
        .with_details(value)
        .with_human_output(human))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_s_key_dialog_becomes_the_node_command() {
        let text = node_words(
            "ThreatFox: needs the abuse.ch Auth-Key (free at auth.abuse.ch); set it in Tools > API keys",
        );
        assert!(
            text.ends_with("set it with `antinomie-cli config api-key set abusech`"),
            "{text}"
        );
    }

    #[test]
    fn names_are_checked_before_anything_is_asked() {
        let dir = std::env::temp_dir().join(format!("ant-cli-ioc-{}", std::process::id()));
        let statuses = feeds::status(&dir);
        let all = chosen(&[], &statuses).unwrap();
        assert_eq!(
            all.len(),
            6,
            "every dataset on by default but the small URLhaus list"
        );
        let two = chosen(
            &["feodo".into(), "feodo".into(), "sslbl-ja3".into()],
            &statuses,
        )
        .unwrap();
        let ids: Vec<&str> = two.iter().map(|feed| feed.id).collect();
        assert_eq!(ids, ["feodo", "sslbl-ja3"]);
        assert_eq!(
            chosen(&["nope".into()], &statuses).unwrap_err().exit.code(),
            3
        );
        assert_eq!(
            chosen(&["urlhaus-recent".into()], &statuses)
                .unwrap_err()
                .exit
                .code(),
            4
        );
    }
}
