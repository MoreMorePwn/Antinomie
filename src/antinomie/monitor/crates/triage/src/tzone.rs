// SPDX-License-Identifier: GPL-3.0-only
//! The zone the app shows times in: the host's, found by itself, or one the
//! person chose in Settings > Appearance. Stored data stays UTC; this only
//! turns Unix seconds into an offset. Zones are read from the system's
//! TZif files (`/usr/share/zoneinfo`), with the POSIX rule of the file's
//! footer for the years after its last transition.
use antinomie_monitor_core::date::{civil_from_days, days_from_civil};
use std::sync::{Arc, RwLock};

/// The saved choice that means "follow the host".
pub const AUTOMATIC: &str = "";
pub const ZONEINFO: &str = "/usr/share/zoneinfo";

pub static ACTIVE: RwLock<Option<Arc<Zone>>> = RwLock::new(None);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Zone {
    pub name: String,
    pub rules: Rules,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rules {
    Fixed(i32),
    Table {
        /// `(UTC second, index into types)`, ascending.
        transitions: Vec<(i64, usize)>,
        /// Offsets in seconds.
        types: Vec<i32>,
        footer: Option<Posix>,
    },
    Posix(Posix),
}

/// `std offset dst [offset],start,end`: offsets in seconds east of UTC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Posix {
    pub std: i32,
    pub dst: Option<(i32, Rule, Rule)>,
}

/// A transition date: month, week (5 = last), weekday (0 = Sunday), or a day
/// of the year, and the local time of day in seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Day {
    Month(u32, u32, u32),
    Julian(u32),
    Zero(u32),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    pub day: Day,
    pub time: i32,
}

impl Zone {
    pub fn utc() -> Self {
        Self {
            name: "UTC".into(),
            rules: Rules::Fixed(0),
        }
    }

    /// The zone called `name` (`Asia/Jakarta`, `UTC`, or a POSIX string).
    pub fn named(name: &str) -> Option<Self> {
        let name = name.trim().trim_start_matches(':');
        if name.is_empty() {
            return None;
        }
        if matches!(name, "UTC" | "Etc/UTC" | "UTC0" | "Z" | "GMT") {
            return Some(Self::utc());
        }
        if !name.contains("..") && !name.starts_with('/') {
            if let Ok(bytes) = std::fs::read(format!("{ZONEINFO}/{name}")) {
                if let Some(rules) = parse_tzif(&bytes) {
                    return Some(Self {
                        name: name.into(),
                        rules,
                    });
                }
            }
        }
        parse_posix(name).map(|posix| Self {
            name: name.into(),
            rules: Rules::Posix(posix),
        })
    }

    /// The host's zone: `TZ`, else `/etc/localtime`, else UTC.
    pub fn detect() -> Self {
        if let Ok(value) = std::env::var("TZ") {
            if let Some(zone) = Self::named(&value) {
                return zone;
            }
            if value.trim().is_empty() {
                return Self::utc();
            }
        }
        if let Ok(target) = std::fs::read_link("/etc/localtime") {
            let text = target.to_string_lossy();
            if let Some((_, name)) = text.split_once("zoneinfo/") {
                if let Some(zone) = Self::named(name) {
                    return zone;
                }
            }
        }
        if let Ok(name) = std::fs::read_to_string("/etc/timezone") {
            if let Some(zone) = Self::named(name.trim()) {
                return zone;
            }
        }
        match std::fs::read("/etc/localtime")
            .ok()
            .and_then(|bytes| parse_tzif(&bytes))
        {
            Some(rules) => Self {
                name: "Local".into(),
                rules,
            },
            None => Self::utc(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Seconds east of UTC at the Unix second `seconds`.
    pub fn offset(&self, seconds: i64) -> i32 {
        match &self.rules {
            Rules::Fixed(offset) => *offset,
            Rules::Posix(posix) => posix.offset(seconds),
            Rules::Table {
                transitions,
                types,
                footer,
            } => {
                let past_last = transitions.last().is_none_or(|last| seconds >= last.0);
                if past_last {
                    if let Some(footer) = footer {
                        return footer.offset(seconds);
                    }
                }
                let at = transitions.partition_point(|entry| entry.0 <= seconds);
                match at.checked_sub(1) {
                    Some(index) => types[transitions[index].1],
                    None => types.first().copied().unwrap_or(0),
                }
            }
        }
    }
}

impl Posix {
    pub fn offset(&self, seconds: i64) -> i32 {
        let Some((dst, start, end)) = &self.dst else {
            return self.std;
        };
        let year = civil_from_days((seconds + i64::from(self.std)).div_euclid(86_400)).0;
        let begin = date_seconds(year, start.day) + i64::from(start.time) - i64::from(self.std);
        let finish = date_seconds(year, end.day) + i64::from(end.time) - i64::from(*dst);
        let summer = if begin < finish {
            seconds >= begin && seconds < finish
        } else {
            seconds >= begin || seconds < finish
        };
        if summer {
            *dst
        } else {
            self.std
        }
    }
}

/// Midnight UTC of the day a rule names in `year`, as Unix seconds.
pub fn date_seconds(year: i64, day: Day) -> i64 {
    let year = year as i32;
    let first_of = |month: u32| days_from_civil(year, month, 1).unwrap_or(0);
    let days = match day {
        Day::Month(month, week, weekday) => {
            let first = first_of(month);
            let (next_year, next) = if month == 12 {
                (year + 1, 1)
            } else {
                (year, month + 1)
            };
            let length = days_from_civil(next_year, next, 1).unwrap_or(0) - first;
            let first_weekday = (first + 4).rem_euclid(7);
            let mut offset = (i64::from(weekday) - first_weekday).rem_euclid(7)
                + i64::from(week.saturating_sub(1)) * 7;
            while offset >= length {
                offset -= 7;
            }
            first + offset
        }
        Day::Julian(n) => {
            // 1..=365, February 29th is never counted.
            let leap = days_from_civil(year, 3, 1).unwrap_or(0) - first_of(2) == 29;
            let n = i64::from(n);
            first_of(1) + n - 1 + i64::from(leap && n >= 60)
        }
        Day::Zero(n) => first_of(1) + i64::from(n),
    };
    days * 86_400
}

pub fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

/// The version 2+ block of a TZif file, which carries 64-bit transition times
/// and the POSIX footer.
pub fn parse_tzif(bytes: &[u8]) -> Option<Rules> {
    if bytes.get(..4)? != b"TZif" {
        return None;
    }
    let counts = |at: usize| -> Option<[usize; 6]> {
        let mut out = [0; 6];
        for (index, slot) in out.iter_mut().enumerate() {
            *slot = be32(bytes, at + 20 + index * 4)? as usize;
        }
        Some(out)
    };
    let first = counts(0)?;
    // isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt
    let (v1_utc, v1_std, v1_leap, v1_time, v1_type, v1_char) =
        (first[0], first[1], first[2], first[3], first[4], first[5]);
    let (start, wide, leap_size) = if bytes[4] >= b'2' {
        let v1_len = v1_time * 5 + v1_type * 6 + v1_char + v1_leap * 8 + v1_std + v1_utc;
        (44 + v1_len, true, 12)
    } else {
        (0, false, 8)
    };
    let [is_utc, is_std, leaps, times, kinds, chars] = counts(start)?;
    let stamp = if wide { 8 } else { 4 };
    let mut at = start + 44;
    let mut transitions = Vec::with_capacity(times);
    for index in 0..times {
        let raw = bytes.get(at + index * stamp..at + (index + 1) * stamp)?;
        let value = if wide {
            i64::from_be_bytes(raw.try_into().ok()?)
        } else {
            i64::from(i32::from_be_bytes(raw.try_into().ok()?))
        };
        transitions.push((value, 0usize));
    }
    at += times * stamp;
    for entry in &mut transitions {
        entry.1 = usize::from(*bytes.get(at)?);
        at += 1;
    }
    let mut types = Vec::with_capacity(kinds);
    for index in 0..kinds {
        types.push(be32(bytes, at + index * 6)? as i32);
    }
    at += kinds * 6 + chars + leaps * leap_size + is_std + is_utc;
    if transitions.iter().any(|entry| entry.1 >= types.len()) || types.is_empty() {
        return None;
    }
    let footer = if wide && bytes.get(at) == Some(&b'\n') {
        let rest = &bytes[at + 1..];
        let end = rest.iter().position(|byte| *byte == b'\n')?;
        std::str::from_utf8(&rest[..end]).ok().and_then(parse_posix)
    } else {
        None
    };
    Some(Rules::Table {
        transitions,
        types,
        footer,
    })
}

pub struct Cursor<'a>(&'a str);
impl Cursor<'_> {
    pub fn peek(&self) -> Option<char> {
        self.0.chars().next()
    }
    pub fn eat(&mut self, expected: char) -> bool {
        let found = self.peek() == Some(expected);
        if found {
            self.0 = &self.0[expected.len_utf8()..];
        }
        found
    }
    pub fn name(&mut self) -> Option<()> {
        if self.eat('<') {
            let end = self.0.find('>')?;
            self.0 = &self.0[end + 1..];
        } else {
            let end = self
                .0
                .find(|c: char| !c.is_ascii_alphabetic())
                .unwrap_or(self.0.len());
            if end < 3 {
                return None;
            }
            self.0 = &self.0[end..];
        }
        Some(())
    }
    pub fn number(&mut self) -> Option<u32> {
        let end = self
            .0
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(self.0.len());
        let value = self.0[..end].parse().ok()?;
        self.0 = &self.0[end..];
        Some(value)
    }
    /// `[+-]hh[:mm[:ss]]` as seconds.
    pub fn clock(&mut self) -> Option<i32> {
        let sign = if self.eat('-') {
            -1
        } else {
            self.eat('+');
            1
        };
        let mut seconds = self.number()? as i32 * 3600;
        if self.eat(':') {
            seconds += self.number()? as i32 * 60;
            if self.eat(':') {
                seconds += self.number()? as i32;
            }
        }
        Some(sign * seconds)
    }
    pub fn rule(&mut self) -> Option<Rule> {
        let day = if self.eat('M') {
            let month = self.number()?;
            self.eat('.').then_some(())?;
            let week = self.number()?;
            self.eat('.').then_some(())?;
            let weekday = self.number()?;
            if !(1..=12).contains(&month) || !(1..=5).contains(&week) || weekday > 6 {
                return None;
            }
            Day::Month(month, week, weekday)
        } else if self.eat('J') {
            Day::Julian(self.number()?)
        } else {
            Day::Zero(self.number()?)
        };
        let time = if self.eat('/') { self.clock()? } else { 7200 };
        Some(Rule { day, time })
    }
}

pub fn parse_posix(text: &str) -> Option<Posix> {
    let mut cursor = Cursor(text);
    cursor.name()?;
    let std = -cursor.clock()?;
    if cursor.0.is_empty() {
        return Some(Posix { std, dst: None });
    }
    cursor.name()?;
    let dst = if matches!(cursor.peek(), Some(',') | None) {
        std + 3600
    } else {
        -cursor.clock()?
    };
    if cursor.0.is_empty() {
        return None;
    }
    cursor.eat(',').then_some(())?;
    let start = cursor.rule()?;
    cursor.eat(',').then_some(())?;
    let end = cursor.rule()?;
    cursor.0.is_empty().then_some(Posix {
        std,
        dst: Some((dst, start, end)),
    })
}

/// Every zone Settings offers: the system's zone files.
pub fn choices() -> Vec<String> {
    let mut found = Vec::new();
    collect(std::path::Path::new(ZONEINFO), "", &mut found, 0);
    if found.is_empty() {
        found = antinomie_monitor_core::build::TIMEZONES
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
    }
    found.sort();
    found.dedup();
    found
}

pub fn collect(dir: &std::path::Path, prefix: &str, out: &mut Vec<String>, depth: u32) {
    const SKIP: [&str; 6] = [
        "posix",
        "right",
        "posixrules",
        "localtime",
        "Factory",
        "SECURITY",
    ];
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let known = name.chars().next().is_some_and(|c| c.is_ascii_uppercase());
        if !known || (depth == 0 && SKIP.contains(&name.as_str())) || name.contains('.') {
            continue;
        }
        let path = entry.path();
        let full = format!("{prefix}{name}");
        if path.is_dir() {
            if depth < 3 {
                collect(&path, &format!("{full}/"), out, depth + 1);
            }
        } else if depth > 0 {
            out.push(full);
        }
    }
}

/// The zone the app shows times in, from the saved choice: [`AUTOMATIC`], or
/// a zone's name (a name this host cannot read falls back to automatic).
pub fn choose(choice: &str) {
    let zone = Zone::named(choice)
        .filter(|_| choice != AUTOMATIC)
        .unwrap_or_else(Zone::detect);
    *ACTIVE.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(zone));
    antinomie_monitor_core::date::set_display_offset(offset_at);
}

pub fn active() -> Arc<Zone> {
    if let Some(zone) = ACTIVE.read().unwrap_or_else(|e| e.into_inner()).clone() {
        return zone;
    }
    choose(AUTOMATIC);
    active()
}

/// Seconds east of UTC in the active zone at a Unix second.
pub fn offset_at(seconds: i64) -> i32 {
    active().offset(seconds)
}
