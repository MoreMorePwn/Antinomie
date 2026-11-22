// SPDX-License-Identifier: GPL-3.0-only
//! Stable table order and disk-backed sorting before archive pagination.
use super::*;
use std::collections::BTreeMap;
use std::hash::Hash;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub column: usize,
    pub descending: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Atom {
    Number(i128),
    Text(String),
    Missing,
}

pub fn value(value: &RowValue) -> Atom {
    match value {
        RowValue::Number(number) => Atom::Number(*number),
        RowValue::Bool(value) => Atom::Number(i128::from(*value)),
        RowValue::Text(text) => Atom::Text(text.to_lowercase()),
        RowValue::List(values) => Atom::Text(values.join("\u{1f}").to_lowercase()),
        RowValue::Missing => Atom::Missing,
    }
}

pub fn atom(header: &str, column: usize, row: &[Cell]) -> Atom {
    let fields = row
        .first()
        .map(|cell| cell.values.as_slice())
        .unwrap_or_default();
    let names: &[&str] = match header {
        "Time" => &["event.time_ns", "frame.time_us"],
        "When" => &["finding.first_ns"],
        "Count" => &["finding.count"],
        "Frame" => &["frame.number"],
        "Diff count" => &["file.diff_count"],
        "Requests" | "Queries" => &["network.count"],
        "Frames" => &["network.frames"],
        "Bytes" => &["network.bytes"],
        "Sessions" => &["tls.sessions"],
        "Evidence" => &["event.id", "frame.number"],
        "TID" => &["process.tid"],
        "Path" => &["file.path"],
        "Started" => &["process.first_ns"],
        "Lifetime" => &["process.lifetime_ns"],
        "First seen" => &["process.first_ns", "network.first_us"],
        "Last seen" => &["process.last_ns", "network.last_us"],
        _ => &[],
    };
    if let Some((_, field)) = fields.iter().find(|(name, _)| names.contains(name)) {
        return value(field);
    }
    let Some(cell) = row.get(column) else {
        return Atom::Missing;
    };
    if header == "IP" {
        if let Ok(ip) = cell.text.parse::<std::net::IpAddr>() {
            return Atom::Text(match ip {
                std::net::IpAddr::V4(ip) => format!("4:{:08x}", u32::from(ip)),
                std::net::IpAddr::V6(ip) => format!("6:{:032x}", u128::from(ip)),
            });
        }
    }
    if matches!(
        cell.text.as_str(),
        "" | "—" | "Unavailable" | "?" | "Unknown"
    ) {
        return Atom::Missing;
    }
    if header == "Severity" || header == "Tier" {
        if let Some(rank) = match cell.text.as_str() {
            "info" | "informational" => Some(0),
            "low" => Some(1),
            "medium" => Some(2),
            "high" => Some(3),
            "critical" => Some(4),
            _ => None,
        } {
            return Atom::Number(rank);
        }
    }
    cell.text.trim_start_matches('#').parse().map_or_else(
        |_| Atom::Text(display_text(&cell.text).to_lowercase()),
        Atom::Number,
    )
}

pub fn compare(a: &Atom, b: &Atom, descending: bool) -> std::cmp::Ordering {
    match (a, b) {
        (Atom::Missing, Atom::Missing) => std::cmp::Ordering::Equal,
        (Atom::Missing, _) => std::cmp::Ordering::Greater,
        (_, Atom::Missing) => std::cmp::Ordering::Less,
        _ if descending => b.cmp(a),
        _ => a.cmp(b),
    }
}

pub trait Row: Sized {
    fn cells(&self) -> Vec<Cell>;
    fn from_cells(cells: Vec<Cell>) -> Result<Self, String>;
}

impl Row for Vec<Cell> {
    fn cells(&self) -> Vec<Cell> {
        self.clone()
    }
    fn from_cells(cells: Vec<Cell>) -> Result<Self, String> {
        Ok(cells)
    }
}
impl Row for Finding {
    fn cells(&self) -> Vec<Cell> {
        let mut cells = self.cells.clone();
        if let Some(first) = cells.first_mut() {
            first.values.clone_from(&self.values);
        }
        cells
    }
    fn from_cells(cells: Vec<Cell>) -> Result<Self, String> {
        let values = cells
            .first()
            .ok_or("sorted finding has no fields")?
            .values
            .clone();
        let field = |name| {
            files::number(&values, name).ok_or_else(|| format!("sorted finding lacks {name}"))
        };
        let key = (
            field("stream.id")?,
            field("process.cookie")?,
            field("event.id")?,
        );
        Ok(Self {
            call_id: key.2,
            key,
            cells,
            values,
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct StoredCell {
    pub text: String,
    pub tone: Tone,
    pub mono: bool,
    pub values: Vec<(usize, RowValue)>,
}

/// The stored form of a row: its cells with field names as small indexes.
#[derive(Default)]
pub struct Codec {
    pub names: Vec<&'static str>,
    pub lookup: BTreeMap<&'static str, usize>,
}

impl Codec {
    pub fn encode(&mut self, cells: &[Cell]) -> Result<Vec<u8>, String> {
        #[derive(serde::Serialize)]
        struct StoredCellRef<'a> {
            text: &'a str,
            tone: Tone,
            mono: bool,
            values: Vec<(usize, &'a RowValue)>,
        }
        let stored: Vec<_> = cells
            .iter()
            .map(|cell| {
                let values = cell
                    .values
                    .iter()
                    .map(|(name, value)| {
                        let next = self.names.len();
                        let index = *self.lookup.entry(name).or_insert_with(|| {
                            self.names.push(name);
                            next
                        });
                        (index, value)
                    })
                    .collect();
                StoredCellRef {
                    text: &cell.text,
                    tone: cell.tone,
                    mono: cell.mono,
                    values,
                }
            })
            .collect();
        if self.names.len() > 512 {
            return Err("sort field registry exceeds bound".into());
        }
        let payload = serde_json::to_vec(&stored).map_err(|error| error.to_string())?;
        if payload.len() > 512 * 1024 {
            return Err("sorted row exceeds 512 KiB".into());
        }
        Ok(payload)
    }

    /// The fields of a row's first cell alone, which every filter reads.
    pub fn encode_values(
        &mut self,
        values: &[(&'static str, RowValue)],
    ) -> Result<Vec<u8>, String> {
        let stored: Vec<(usize, &RowValue)> = values
            .iter()
            .map(|(name, value)| {
                let next = self.names.len();
                let index = *self.lookup.entry(name).or_insert_with(|| {
                    self.names.push(name);
                    next
                });
                (index, value)
            })
            .collect();
        if self.names.len() > 512 {
            return Err("sort field registry exceeds bound".into());
        }
        serde_json::to_vec(&stored).map_err(|error| error.to_string())
    }

    pub fn decode_values(&self, payload: &[u8]) -> Result<Vec<(&'static str, RowValue)>, String> {
        let stored: Vec<(usize, RowValue)> =
            serde_json::from_slice(payload).map_err(|error| error.to_string())?;
        stored
            .into_iter()
            .map(|(index, value)| {
                self.names
                    .get(index)
                    .copied()
                    .map(|name| (name, value))
                    .ok_or_else(|| "invalid stored field index".to_owned())
            })
            .collect()
    }

    pub fn decode(&self, payload: &[u8]) -> Result<Vec<Cell>, String> {
        let stored: Vec<StoredCell> =
            serde_json::from_slice(payload).map_err(|error| error.to_string())?;
        stored
            .into_iter()
            .map(|cell| {
                let values = cell
                    .values
                    .into_iter()
                    .map(|(index, value)| {
                        self.names
                            .get(index)
                            .copied()
                            .map(|name| (name, value))
                            .ok_or("invalid sorted field index")
                    })
                    .collect::<Result<_, &str>>()?;
                Ok(Cell {
                    text: cell.text,
                    tone: cell.tone,
                    mono: cell.mono,
                    values,
                    badges: Vec::new(),
                    note: None,
                })
            })
            .collect::<Result<_, &str>>()
            .map_err(str::to_owned)
    }
}

/// Bytes of rows a sort keeps in its own file at most. A sort whose rows are
/// already kept by the run's index ([`row_index`]) keeps none: it spools keys.
pub const SPOOL_PAYLOAD_MAX: u64 = 2 << 30;
/// Pages the key table may hold, 1 GiB (a key is a number or a lowercase text).
const SPOOL_KEY_PAGES: u64 = 262_144;

/// Where a spooled row's cells are: in the spool's own file, or in the run's
/// index under the row's sequence number (ANT-T0592).
enum Place {
    File { offset: u64, len: u64 },
    Kept(u64),
}

/// A disk-backed sort: the keys in a small SQLite table, ordered by SQLite
/// (its temporary files are not bounded by the table's page limit), and the
/// rows themselves in an append-only file the page reads back by offset.
pub struct Spool {
    pub connection: rusqlite::Connection,
    // Connection drops before this directory and its temporary files.
    pub _directory: PacketSpool,
    payload: std::fs::File,
    written: u64,
    pub codec: Codec,
}

impl Spool {
    pub fn new(cancel: Arc<AtomicBool>) -> Result<Self, String> {
        let directory = PacketSpool::new()?;
        let payload = directory
            .rows
            .try_clone()
            .map_err(|error| error.to_string())?;
        let mut connection = rusqlite::Connection::open(directory.directory.join("sort.sqlite"))
            .map_err(|error| error.to_string())?;
        connection.execute_batch(&format!("PRAGMA trusted_schema=OFF; PRAGMA page_size=4096; PRAGMA max_page_count={SPOOL_KEY_PAGES}; PRAGMA cache_size=-2048; PRAGMA temp_store=FILE; PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; CREATE TABLE rows(seq INTEGER PRIMARY KEY, missing INTEGER NOT NULL, k TEXT NOT NULL, offset INTEGER NOT NULL, len INTEGER NOT NULL); BEGIN;")).map_err(|error| error.to_string())?;
        connection
            .progress_handler(10_000, Some(move || cancel.load(Ordering::Relaxed)))
            .map_err(|error| error.to_string())?;
        Ok(Self {
            connection,
            _directory: directory,
            payload,
            written: 0,
            codec: Codec::default(),
        })
    }
    fn insert(&mut self, key: Atom, place: Place) -> Result<(), String> {
        let missing = key == Atom::Missing;
        let encoded = match key {
            Atom::Number(number) => format!("n{:039}", (number as u128) ^ (1u128 << 127)),
            Atom::Text(text) => format!("s{text}"),
            Atom::Missing => String::new(),
        };
        // A kept row has length 0 and its sequence number in the offset.
        let (offset, len) = match place {
            Place::File { offset, len } => (offset, len),
            Place::Kept(seq) => (seq, 0),
        };
        self.connection
            .prepare_cached("INSERT INTO rows(missing,k,offset,len) VALUES(?1,?2,?3,?4)")
            .and_then(|mut insert| {
                insert.execute(rusqlite::params![
                    missing,
                    encoded,
                    offset as i64,
                    len as i64
                ])
            })
            .map_err(|error| format!("triage sort spool (keys): {error}"))?;
        Ok(())
    }
    pub fn push(&mut self, key: Atom, cells: Vec<Cell>) -> Result<(), String> {
        use std::os::unix::fs::FileExt;
        let payload = self.codec.encode(&cells)?;
        let len = payload.len() as u64;
        if self.written.saturating_add(len) > SPOOL_PAYLOAD_MAX {
            return Err(format!(
                "triage sort spool: the sorted rows pass {} GiB; filter the table first",
                SPOOL_PAYLOAD_MAX >> 30
            ));
        }
        self.payload
            .write_all_at(&payload, self.written)
            .map_err(|error| format!("triage sort spool (rows): {error}"))?;
        let offset = self.written;
        self.written += len;
        self.insert(key, Place::File { offset, len })
    }
    /// A row the run's index keeps under `seq`: only its key is spooled.
    pub fn push_kept(&mut self, key: Atom, seq: u64) -> Result<(), String> {
        self.insert(key, Place::Kept(seq))
    }
    /// The rows of one page in sort order. `kept` reads a row the run's index
    /// keeps (a spool made with [`Self::push_kept`]).
    pub fn page<T: Row>(
        &self,
        offset: usize,
        limit: usize,
        descending: bool,
        kept: Option<&dyn Fn(u64) -> Result<Vec<Cell>, String>>,
    ) -> Result<Vec<T>, String> {
        use std::os::unix::fs::FileExt;
        self.connection
            .execute_batch("COMMIT")
            .map_err(|error| error.to_string())?;
        let order = if descending { "DESC" } else { "ASC" };
        let mut query = self.connection.prepare(&format!("SELECT offset, len FROM rows ORDER BY missing ASC, k {order}, seq ASC LIMIT ?1 OFFSET ?2")).map_err(|error| error.to_string())?;
        let offset = i64::try_from(offset).map_err(|_| "sorted page offset overflow")?;
        let places = query
            .query_map(rusqlite::params![limit as i64, offset], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|error| error.to_string())?;
        let mut result = Vec::new();
        let mut retained_size = 0usize;
        for place in places {
            let (at, len) = place.map_err(|error| error.to_string())?;
            let cells = if len == 0 {
                let kept = kept.ok_or("a sorted row is kept by the index, which is not given")?;
                kept(at as u64)?
            } else {
                let mut payload = vec![0u8; len as usize];
                self.payload
                    .read_exact_at(&mut payload, at as u64)
                    .map_err(|error| format!("triage sort spool (rows): {error}"))?;
                retained_size = retained_size.saturating_add(payload.len());
                self.codec.decode(&payload)?
            };
            if retained_size > 16 * 1024 * 1024 {
                return Err("sorted page exceeds 16 MiB preview bound".into());
            }
            result.push(T::from_cells(cells)?);
        }
        Ok(result)
    }
}

/// One query table; default order retains the original cheap bounded page.
pub struct Page<T> {
    pub rows: Vec<T>,
    pub spool: Option<Spool>,
    pub sort: Option<Spec>,
    pub index: usize,
    pub offset: usize,
    pub count: usize,
    /// Rows the page keeps.
    pub limit: usize,
    pub cancel: Arc<AtomicBool>,
}

impl<T: Row> Page<T> {
    pub fn new(request: &ScanRequest, index: usize, cancel: &Arc<AtomicBool>) -> Self {
        Self {
            rows: Vec::new(),
            spool: None,
            sort: request.sorts[index],
            index,
            offset: request.offsets[index],
            count: 0,
            limit: request.rows(),
            cancel: Arc::clone(cancel),
        }
    }
    pub fn push(&mut self, row: T) -> Result<(), String> {
        self.push_at(row, None)
    }
    /// Whether a row pushed now would be read: any row of a sorted table, and
    /// those inside the window of an unsorted one. A caller that holds its rows
    /// undecoded counts the others with [`Self::count_only`].
    pub fn needs_row(&self) -> bool {
        self.sort.is_some() || (self.count >= self.offset && self.rows.len() < self.limit)
    }
    pub fn count_only(&mut self) {
        self.count = self.count.saturating_add(1);
    }
    /// [`Self::push`] of a row the run's index keeps as number `seq` of its
    /// log: a sorted table spools its key alone and reads the row back from
    /// the log at the end ([`Self::finish_with`]).
    pub fn push_at(&mut self, row: T, kept: Option<u64>) -> Result<(), String> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        if let Some(sort) = self.sort {
            let cells = row.cells();
            let headers: &[&str] = match self.index {
                0 => rules::HEADERS,
                1 | 8..=15 => file_category::EVENT_HEADERS,
                SESSION_SLOT => SESSION_HEADERS,
                ENDPOINT_SLOT => net_tabs::ENDPOINT_STORED,
                DOMAIN_SLOT => net_tabs::DOMAIN_STORED,
                TLS_SLOT => net_tabs::TLS_STORED,
                2 => file_tabs::CHANGED_HEADERS,
                3 => HTTP_HEADERS,
                4 => DNS_HEADERS,
                5 => file_tabs::READ_HEADERS,
                6 => &["IP", "Country", "Organization"],
                _ => &[
                    "Hostname",
                    "Resolved / connected IPs",
                    "First seen",
                    "Last seen",
                    "Requests",
                    "Source",
                ],
            };
            let header = headers
                .get(sort.column)
                .ok_or("invalid triage sort column")?;
            if self.spool.is_none() {
                self.spool = Some(Spool::new(Arc::clone(&self.cancel))?);
            }
            let spool = self.spool.as_mut().ok_or("sort spool missing")?;
            let key = atom(header, sort.column, &cells);
            match kept {
                Some(seq) => spool.push_kept(key, seq)?,
                None => spool.push(key, cells)?,
            }
        } else if self.count >= self.offset && self.rows.len() < self.limit {
            self.rows.push(row);
        }
        self.count = self.count.saturating_add(1);
        Ok(())
    }
    pub fn finish(self) -> Result<(Vec<T>, u64, usize), String> {
        self.finish_with(None)
    }
    /// [`Self::finish`] for a table whose rows were pushed with
    /// [`Self::push_at`]: `kept` reads row number `seq` of the log.
    pub fn finish_with(
        mut self,
        kept: Option<&dyn Fn(u64) -> Result<Vec<Cell>, String>>,
    ) -> Result<(Vec<T>, u64, usize), String> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        if let Some(spool) = &self.spool {
            self.rows = spool.page(
                self.offset,
                self.limit,
                self.sort.is_some_and(|sort| sort.descending),
                kept,
            )?;
        }
        let omitted = self.count.saturating_sub(self.rows.len()) as u64;
        Ok((self.rows, omitted, self.count))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    #[test]
    fn sorts_before_pagination_and_retains_numeric_values_missing_last_and_identity() {
        let mut request = ScanRequest::default();
        request.sorts[6] = Some(Spec {
            column: 0,
            descending: true,
        });
        let mut page = Page::<Vec<Cell>>::new(&request, 6, &Arc::new(AtomicBool::new(false)));
        for number in 0..2051 {
            let mut row = vec![cell(number.to_string(), tone::text(), true)];
            row[0].values = vec![("frame.number", RowValue::Number(number))];
            page.push(row).unwrap();
        }
        page.push(vec![cell("Unavailable", tone::text(), false)])
            .unwrap();
        let (rows, omitted, total) = page.finish().unwrap();
        assert_eq!((rows.len(), omitted, total), (STORED_ROWS, 52, 2052));
        assert_eq!(rows[0][0].text, "2050");
        assert_eq!(
            files::number(&rows[0][0].values, "frame.number"),
            Some(2050)
        );
        assert_eq!(rows.last().unwrap()[0].text, "51");
        assert_eq!(
            compare(&Atom::Missing, &Atom::Number(9), true),
            std::cmp::Ordering::Greater
        );
        request.offsets[6] = STORED_ROWS;
        let mut next = Page::<Vec<Cell>>::new(&request, 6, &Arc::new(AtomicBool::new(false)));
        for number in 0..2051 {
            next.push(vec![cell(number.to_string(), tone::text(), true)])
                .unwrap();
        }
        next.push(vec![cell("Unavailable", tone::text(), false)])
            .unwrap();
        let (rows, omitted, total) = next.finish().unwrap();
        assert_eq!((rows.len(), omitted, total), (52, 2000, 2052));
        assert_eq!(rows[0][0].text, "50");
        assert_eq!(rows.last().unwrap()[0].text, "Unavailable");
    }

    #[test]
    fn a_sort_of_rows_the_index_keeps_spools_only_their_keys() {
        let mut request = ScanRequest::default();
        request.sorts[6] = Some(Spec {
            column: 0,
            descending: false,
        });
        let kept: Vec<Vec<Cell>> = (0..300u32)
            .map(|n| {
                let mut row = vec![cell((299 - n).to_string(), tone::text(), true)];
                row[0].values = vec![("frame.number", RowValue::Number(i128::from(299 - n)))];
                row
            })
            .collect();
        let mut page = Page::<Vec<Cell>>::new(&request, 6, &Arc::new(AtomicBool::new(false)));
        for (seq, row) in kept.iter().enumerate() {
            page.push_at(row.clone(), Some(seq as u64)).unwrap();
        }
        let fetch = |seq: u64| Ok(kept[seq as usize].clone());
        let (rows, omitted, total) = page.finish_with(Some(&fetch)).unwrap();
        assert_eq!((rows.len(), omitted, total), (300, 0, 300));
        assert_eq!(rows[0][0].text, "0");
        assert_eq!(rows[299][0].text, "299");
        // Without the log to read them back, a kept row is an error, not a gap.
        let mut page = Page::<Vec<Cell>>::new(&request, 6, &Arc::new(AtomicBool::new(false)));
        page.push_at(kept[0].clone(), Some(0)).unwrap();
        assert!(page.finish().is_err());
    }

    #[test]
    fn sorted_findings_keep_exact_unsigned_identity_and_cancellation_is_observable() {
        let mut request = ScanRequest::default();
        request.sorts[0] = Some(Spec {
            column: 9,
            descending: true,
        });
        let cancel = Arc::new(AtomicBool::new(false));
        let mut page = Page::<Finding>::new(&request, 0, &cancel);
        let mut call = crate::tests::call(7, 9, "mmap", 0);
        call.entry.as_mut().unwrap().args = Some([0, 4096, 7, 0, 0, 0]);
        call.call_id = u64::MAX;
        call.stream_id = 99;
        let finding = suspicious_rows(&[call]).remove(0);
        let expected = finding.key;
        page.push(finding).unwrap();
        let (rows, _, _) = page.finish().unwrap();
        assert_eq!(rows[0].key, expected);
        assert_eq!(rows[0].call_id, u64::MAX);
        let mut cancelled = Page::<Vec<Cell>>::new(&request, 0, &cancel);
        cancelled
            .push(vec![cell("row", tone::text(), false)])
            .unwrap();
        cancel.store(true, Ordering::Relaxed);
        assert!(matches!(cancelled.finish(), Err(error) if error.contains("cancelled")));
    }

    #[test]
    fn findings_sort_by_tier_rank_and_by_count_as_numbers() {
        use super::super::rules::tests::support::*;
        let mut calls = vec![
            open_write(1, "/etc/cron.d/a", 3),
            exec(2, "/bin/sh", &["sh"]),
        ];
        calls.extend((0..12).map(|_| open_read(3, "/etc/os-release", 4)));
        let out = run(calls);
        let rows = out.rows;
        let order = |column: usize, descending: bool| -> Vec<String> {
            let mut request = ScanRequest::default();
            request.sorts[0] = Some(Spec { column, descending });
            let mut page = Page::<Finding>::new(&request, 0, &Arc::new(AtomicBool::new(false)));
            for row in rows.iter().cloned() {
                page.push(row).unwrap();
            }
            page.finish()
                .unwrap()
                .0
                .iter()
                .map(|row| row.cells[0].text.clone())
                .collect()
        };
        // High, then low, then info; text order would put "info" before "low".
        let high_first = order(1, true);
        assert_eq!(high_first[..2], ["persistence.cron", "process.interpreter"]);
        assert_eq!(
            order(1, false)[..2],
            ["process.exec", "discovery.system_info"]
        );
        // 12 is more than 2 even though "12" sorts before "2" as text.
        assert_eq!(order(5, true)[0], "discovery.system_info");
    }
}
