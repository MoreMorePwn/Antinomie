// SPDX-License-Identifier: MIT
//! Stable table order and disk-backed sorting before archive pagination.
use super::*;
use std::collections::{hash_map::DefaultHasher, BTreeMap};
use std::hash::{Hash, Hasher};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Spec {
    pub column: usize,
    pub descending: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Atom {
    Number(i128),
    Text(String),
    Missing,
}

fn value(value: &RowValue) -> Atom {
    match value {
        RowValue::Number(number) => Atom::Number(*number),
        RowValue::Bool(value) => Atom::Number(i128::from(*value)),
        RowValue::Text(text) => Atom::Text(text.to_lowercase()),
        RowValue::List(values) => Atom::Text(values.join("\u{1f}").to_lowercase()),
        RowValue::Missing => Atom::Missing,
    }
}

fn atom(header: &str, column: usize, row: &[Cell]) -> Atom {
    let fields = row
        .first()
        .map(|cell| cell.values.as_slice())
        .unwrap_or_default();
    let names: &[&str] = match header {
        "Time" => &["event.time_ns", "frame.time_us"],
        "Frame" => &["frame.number"],
        "Diff count" => &["file.diff_count"],
        "Requests" => &["network.count"],
        "Evidence" => &["event.id", "frame.number"],
        "TID" => &["process.tid"],
        "Path" => &["file.path"],
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
    if header == "Severity" {
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

fn compare(a: &Atom, b: &Atom, descending: bool) -> std::cmp::Ordering {
    match (a, b) {
        (Atom::Missing, Atom::Missing) => std::cmp::Ordering::Equal,
        (Atom::Missing, _) => std::cmp::Ordering::Greater,
        (_, Atom::Missing) => std::cmp::Ordering::Less,
        _ if descending => b.cmp(a),
        _ => a.cmp(b),
    }
}

pub(crate) fn header(ui: &mut egui::Ui, table: &str, column: usize, title: &str) {
    crate::widgets::table::head_bg(ui);
    let id = egui::Id::new(("triage-sort", table));
    let current = ui.ctx().data(|data| data.get_temp::<Spec>(id));
    let arrow = current
        .filter(|sort| sort.column == column)
        .map_or("", |sort| if sort.descending { " ▼" } else { " ▲" });
    let response = ui.add(
        egui::Button::new(
            RichText::new(format!("{title}{arrow}"))
                .strong()
                .color(theme::muted()),
        )
        .frame(false),
    );
    if response.clicked() {
        let next = Spec {
            column,
            descending: current.is_some_and(|sort| sort.column == column && !sort.descending),
        };
        ui.ctx().data_mut(|data| {
            data.insert_temp(id, next);
            data.insert_temp(egui::Id::new(("triage-sort-request", table)), Some(next));
        });
    }
    response.context_menu(|ui| {
        if ui.button("Recorded order").clicked() {
            ui.ctx().data_mut(|data| {
                data.remove::<Spec>(id);
                data.insert_temp(egui::Id::new(("triage-sort-request", table)), None::<Spec>);
            });
            ui.close_menu();
        }
    });
}

/// The order a table's header clicks chose, if any.
pub(crate) fn current(ctx: &egui::Context, table: &str) -> Option<Spec> {
    ctx.data(|data| data.get_temp::<Spec>(egui::Id::new(("triage-sort", table))))
}

pub(super) fn take_request(ctx: &egui::Context, table: &str) -> Option<Option<Spec>> {
    ctx.data_mut(|data| data.remove_temp(egui::Id::new(("triage-sort-request", table))))
}

#[derive(Clone)]
struct Order {
    spec: Spec,
    hash: u64,
    indices: Arc<Vec<usize>>,
}

pub(super) fn order<'a>(
    ctx: &egui::Context,
    table: &str,
    headers: &[&str],
    rows: impl Iterator<Item = &'a [Cell]>,
) -> Option<Arc<Vec<usize>>> {
    let spec = ctx.data(|data| data.get_temp::<Spec>(egui::Id::new(("triage-sort", table))))?;
    let header = headers.get(spec.column)?;
    let keys: Vec<_> = rows.map(|row| atom(header, spec.column, row)).collect();
    let mut hash = DefaultHasher::new();
    keys.hash(&mut hash);
    let hash = hash.finish();
    let id = egui::Id::new(("triage-sort-order", table));
    if let Some(cached) = ctx
        .data(|data| data.get_temp::<Order>(id))
        .filter(|cached| cached.spec == spec && cached.hash == hash)
    {
        return Some(cached.indices);
    }
    let mut indices: Vec<_> = (0..keys.len()).collect();
    indices.sort_by(|a, b| compare(&keys[*a], &keys[*b], spec.descending));
    let indices = Arc::new(indices);
    ctx.data_mut(|data| {
        data.insert_temp(
            id,
            Order {
                spec,
                hash,
                indices: Arc::clone(&indices),
            },
        )
    });
    Some(indices)
}

pub(super) trait Row: Sized {
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
struct StoredCell {
    text: String,
    color: [u8; 4],
    /// The theme `color` was taken from.
    #[serde(default)]
    theme: crate::theme::Theme,
    mono: bool,
    values: Vec<(usize, RowValue)>,
}

struct Spool {
    connection: rusqlite::Connection,
    // Connection drops before this directory and its temporary database.
    _directory: PacketSpool,
    names: Vec<&'static str>,
    lookup: BTreeMap<&'static str, usize>,
}

impl Spool {
    fn new(cancel: Arc<AtomicBool>) -> Result<Self, String> {
        let directory = PacketSpool::new()?;
        let connection = rusqlite::Connection::open(directory.directory.join("sort.sqlite"))
            .map_err(|error| error.to_string())?;
        connection.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA page_size=4096; PRAGMA max_page_count=65536; PRAGMA cache_size=-2048; PRAGMA temp_store=FILE; PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; CREATE TABLE rows(seq INTEGER PRIMARY KEY, missing INTEGER NOT NULL, k TEXT NOT NULL, payload BLOB NOT NULL); BEGIN;").map_err(|error| error.to_string())?;
        connection
            .progress_handler(10_000, Some(move || cancel.load(Ordering::Relaxed)))
            .map_err(|error| error.to_string())?;
        Ok(Self {
            connection,
            _directory: directory,
            names: Vec::new(),
            lookup: BTreeMap::new(),
        })
    }
    fn push(&mut self, key: Atom, cells: Vec<Cell>) -> Result<(), String> {
        let stored: Vec<_> = cells
            .into_iter()
            .map(|cell| {
                let values = cell
                    .values
                    .into_iter()
                    .map(|(name, value)| {
                        let next = self.names.len();
                        let index = *self.lookup.entry(name).or_insert_with(|| {
                            self.names.push(name);
                            next
                        });
                        (index, value)
                    })
                    .collect();
                StoredCell {
                    text: cell.text,
                    color: cell.color.to_array(),
                    theme: cell.theme,
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
        let missing = key == Atom::Missing;
        let encoded = match key {
            Atom::Number(number) => format!("n{:039}", (number as u128) ^ (1u128 << 127)),
            Atom::Text(text) => format!("s{text}"),
            Atom::Missing => String::new(),
        };
        self.connection
            .execute(
                "INSERT INTO rows(missing,k,payload) VALUES(?1,?2,?3)",
                rusqlite::params![missing, encoded, payload],
            )
            .map_err(|error| format!("triage sort spool (256 MiB limit): {error}"))?;
        Ok(())
    }
    fn page<T: Row>(&self, offset: usize, descending: bool) -> Result<Vec<T>, String> {
        self.connection
            .execute_batch("COMMIT")
            .map_err(|error| error.to_string())?;
        let order = if descending { "DESC" } else { "ASC" };
        let mut query = self.connection.prepare(&format!("SELECT payload FROM rows ORDER BY missing ASC, k {order}, seq ASC LIMIT ?1 OFFSET ?2")).map_err(|error| error.to_string())?;
        let offset = i64::try_from(offset).map_err(|_| "sorted page offset overflow")?;
        let rows = query
            .query_map(rusqlite::params![STORED_ROWS as i64, offset], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(|error| error.to_string())?;
        let mut result = Vec::new();
        let mut retained_size = 0usize;
        for row in rows {
            let row = row.map_err(|error| error.to_string())?;
            retained_size = retained_size.saturating_add(row.len());
            if retained_size > 16 * 1024 * 1024 {
                return Err("sorted page exceeds 16 MiB preview bound".into());
            }
            let stored: Vec<StoredCell> =
                serde_json::from_slice(&row).map_err(|error| error.to_string())?;
            let cells = stored
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
                        .collect::<Result<_, _>>()?;
                    Ok(Cell {
                        text: cell.text,
                        color: egui::Color32::from_rgba_premultiplied(
                            cell.color[0],
                            cell.color[1],
                            cell.color[2],
                            cell.color[3],
                        ),
                        theme: cell.theme,
                        mono: cell.mono,
                        values,
                    })
                })
                .collect::<Result<_, &str>>()?;
            result.push(T::from_cells(cells)?);
        }
        Ok(result)
    }
}

/// One query table; default order retains the original cheap bounded page.
pub(super) struct Page<T> {
    rows: Vec<T>,
    spool: Option<Spool>,
    sort: Option<Spec>,
    index: usize,
    offset: usize,
    count: usize,
    cancel: Arc<AtomicBool>,
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
            cancel: Arc::clone(cancel),
        }
    }
    pub fn push(&mut self, row: T) -> Result<(), String> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        if let Some(sort) = self.sort {
            let cells = row.cells();
            let headers: &[&str] = match self.index {
                0 => &[
                    "Rule",
                    "Severity",
                    "Process",
                    "Summary",
                    "Source",
                    "Time",
                    "Confidence",
                    "Evidence",
                    "Version",
                    "Outcome",
                ],
                1 | 8..=15 => file_category::EVENT_HEADERS,
                SESSION_SLOT => SESSION_HEADERS,
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
            self.spool
                .as_mut()
                .ok_or("sort spool missing")?
                .push(atom(header, sort.column, &cells), cells)?;
        } else if self.count >= self.offset && self.rows.len() < STORED_ROWS {
            self.rows.push(row);
        }
        self.count = self.count.saturating_add(1);
        Ok(())
    }
    pub fn finish(mut self) -> Result<(Vec<T>, u64, usize), String> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        if let Some(spool) = &self.spool {
            self.rows = spool.page(self.offset, self.sort.is_some_and(|sort| sort.descending))?;
        }
        let omitted = self.count.saturating_sub(self.rows.len()) as u64;
        Ok((self.rows, omitted, self.count))
    }
}

#[cfg(test)]
mod tests {
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
            let mut row = vec![cell(number.to_string(), theme::text(), true)];
            row[0].values = vec![("frame.number", RowValue::Number(number))];
            page.push(row).unwrap();
        }
        page.push(vec![cell("Unavailable", theme::text(), false)])
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
            next.push(vec![cell(number.to_string(), theme::text(), true)])
                .unwrap();
        }
        next.push(vec![cell("Unavailable", theme::text(), false)])
            .unwrap();
        let (rows, omitted, total) = next.finish().unwrap();
        assert_eq!((rows.len(), omitted, total), (52, 2000, 2052));
        assert_eq!(rows[0][0].text, "50");
        assert_eq!(rows.last().unwrap()[0].text, "Unavailable");
    }

    #[test]
    fn sorted_findings_keep_exact_unsigned_identity_and_cancellation_is_observable() {
        let mut request = ScanRequest::default();
        request.sorts[0] = Some(Spec {
            column: 7,
            descending: true,
        });
        let cancel = Arc::new(AtomicBool::new(false));
        let mut page = Page::<Finding>::new(&request, 0, &cancel);
        let mut call = super::super::tests::call(7, 9, "mmap", 0);
        call.call_id = u64::MAX;
        call.stream_id = 99;
        let finding = hit(
            "memory.rwx",
            "high",
            "process".into(),
            "test evidence".into(),
            "fixture",
            trace::representative(&call).unwrap(),
            &call,
        );
        let expected = finding.key;
        page.push(finding).unwrap();
        let (rows, _, _) = page.finish().unwrap();
        assert_eq!(rows[0].key, expected);
        assert_eq!(rows[0].call_id, u64::MAX);
        let mut cancelled = Page::<Vec<Cell>>::new(&request, 0, &cancel);
        cancelled
            .push(vec![cell("row", theme::text(), false)])
            .unwrap();
        cancel.store(true, Ordering::Relaxed);
        assert!(matches!(cancelled.finish(), Err(error) if error.contains("cancelled")));
    }
}
