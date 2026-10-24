// SPDX-License-Identifier: GPL-3.0-only
//! The graph's index: one compact record per finding, and a pyramid of buckets
//! over time so any zoom level paints from a few thousand cells.
//!
//! Level 0 buckets are `2^shift` ns wide, chosen so the run fits in
//! [`L0_BUCKETS`]; each level above halves the resolution. A cell is one
//! `(lane, bucket)` with the findings in it, and only cells that hold something
//! are stored. The same buckets summed over lanes (`Bin`) give the severity
//! curve, the category heat strip and the phases.
use super::lanes::Lanes;
use super::phases::{self, Phase, Span};
use super::*;
use crate::triage::rules::{Category, Tier};

/// Buckets the run is cut into at level 0 (at most).
pub(in crate::triage) const L0_BUCKETS: u64 = 4096;
/// What a row adds to the severity curve, by [`Tier::index`]: HIGH, MEDIUM, LOW, INFO.
pub(in crate::triage) const WEIGHTS: [u32; 4] = [10, 4, 1, 0];
/// "No tier" in a cell that holds nothing.
pub(in crate::triage) const NO_TIER: u8 = 4;
/// A finding found in the capture and not tied to a call: drawn hollow.
pub(in crate::triage) const HOLLOW: u8 = 1;
/// "No phase" in a record.
pub(in crate::triage) const NO_PHASE: u8 = 255;

/// One finding as the graph keeps it: 32 bytes (the design allows 48).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::triage) struct Record {
    pub first_ns: u64,
    pub last_ns: u64,
    /// Occurrences folded into the row.
    pub count: u32,
    pub lane: u32,
    /// [`Tier::index`].
    pub tier: u8,
    /// [`Category::index`].
    pub category: u8,
    /// [`Phase::index`], or [`NO_PHASE`].
    pub phase: u8,
    pub flags: u8,
    /// The place among the distinct moments, for Events spacing.
    pub slot: u32,
}

impl Record {
    pub(in crate::triage) fn weight(&self) -> u32 {
        WEIGHTS[usize::from(self.tier).min(3)]
    }
}

/// The findings of one `(lane, bucket)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::triage) struct Cell {
    pub lane: u32,
    pub bucket: u32,
    /// Rows by [`Tier::index`].
    pub counts: [u32; 4],
    /// Index of the earliest record in the cell.
    pub first: u32,
    /// One bit per [`Category::index`].
    pub cats: u16,
    /// The worst tier in the cell, as the smallest [`Tier::index`].
    pub top: u8,
    /// The category of the first record of that tier.
    pub lead: u8,
}

impl Cell {
    pub(super) fn of(record: &Record, at: usize, bucket: u32) -> Self {
        let mut counts = [0; 4];
        counts[usize::from(record.tier).min(3)] = 1;
        Self {
            lane: record.lane,
            bucket,
            counts,
            first: at as u32,
            cats: 1 << record.category,
            top: record.tier,
            lead: record.category,
        }
    }

    pub(super) fn add(&mut self, record: &Record) {
        self.counts[usize::from(record.tier).min(3)] += 1;
        self.cats |= 1 << record.category;
        if record.tier < self.top {
            self.top = record.tier;
            self.lead = record.category;
        }
    }

    pub(super) fn merge(&mut self, other: &Cell) {
        for (mine, theirs) in self.counts.iter_mut().zip(other.counts) {
            *mine += theirs;
        }
        self.cats |= other.cats;
        self.first = self.first.min(other.first);
        if other.top < self.top {
            self.top = other.top;
            self.lead = other.lead;
        }
    }

    pub(in crate::triage) fn total(&self) -> u32 {
        self.counts.iter().sum()
    }
}

/// All lanes summed over one bucket: the severity curve, the heat strip and
/// what the phases are read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::triage) struct Bin {
    /// Rows by [`Tier::index`].
    pub tiers: [u32; 4],
    /// Rows by [`Category::index`], and the worst tier among them.
    pub cats: [u32; 13],
    pub top: [u8; 13],
    /// The weight of the bin by [`Phase::index`].
    pub phase_weight: [u32; 8],
    /// INFO matches of Discovery and anti-analysis rules, counted without rows.
    pub info_recon: u32,
}

impl Default for Bin {
    fn default() -> Self {
        Self {
            tiers: [0; 4],
            cats: [0; 13],
            top: [NO_TIER; 13],
            phase_weight: [0; 8],
            info_recon: 0,
        }
    }
}

impl Bin {
    pub(super) fn add(&mut self, record: &Record) {
        self.tiers[usize::from(record.tier).min(3)] += 1;
        let category = usize::from(record.category).min(12);
        self.cats[category] += 1;
        self.top[category] = self.top[category].min(record.tier);
        if let Some(weight) = self.phase_weight.get_mut(usize::from(record.phase)) {
            *weight += record.weight();
        }
    }

    fn merge(&mut self, other: &Bin) {
        for index in 0..4 {
            self.tiers[index] += other.tiers[index];
        }
        for index in 0..13 {
            self.cats[index] += other.cats[index];
            self.top[index] = self.top[index].min(other.top[index]);
        }
        for index in 0..8 {
            self.phase_weight[index] += other.phase_weight[index];
        }
        self.info_recon += other.info_recon;
    }

    /// The severity curve's height for one tier.
    pub(in crate::triage) fn weight_of(&self, tier: usize) -> u32 {
        self.tiers[tier] * WEIGHTS[tier]
    }

    pub(in crate::triage) fn weight(&self) -> u32 {
        (0..4).map(|tier| self.weight_of(tier)).sum()
    }
}

/// How the run is cut into buckets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::triage) struct Geometry {
    pub origin: u64,
    pub end: u64,
    pub shift: u32,
}

impl Geometry {
    pub(in crate::triage) fn new(origin: u64, end: u64) -> Self {
        let end = end.max(origin);
        let span = end - origin;
        let mut shift = 0;
        while (span >> shift) >= L0_BUCKETS {
            shift += 1;
        }
        Self { origin, end, shift }
    }

    pub(in crate::triage) fn buckets(&self) -> usize {
        ((self.end - self.origin) >> self.shift) as usize + 1
    }

    /// Levels from the base up to one bucket for the whole run.
    pub(in crate::triage) fn levels(&self) -> usize {
        let mut buckets = self.buckets();
        let mut levels = 1;
        while buckets > 1 {
            buckets = buckets.div_ceil(2);
            levels += 1;
        }
        levels
    }

    pub(in crate::triage) fn bucket(&self, ns: u64) -> usize {
        (((ns.saturating_sub(self.origin)) >> self.shift) as usize).min(self.buckets() - 1)
    }

    /// The width of a bucket of `level`, in ns.
    pub(in crate::triage) fn width(&self, level: usize) -> f64 {
        (1u64 << (self.shift + level as u32).min(62)) as f64
    }

    /// The first ns of `bucket` at `level`.
    pub(in crate::triage) fn start(&self, level: usize, bucket: usize) -> f64 {
        self.origin as f64 + bucket as f64 * self.width(level)
    }
}

/// An arrow from the injector's marker to the target lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::triage) struct Injection {
    pub record: u32,
    pub target: u32,
}

/// The whole index of one view of the findings.
#[derive(Default)]
pub(in crate::triage) struct GraphIndex {
    pub geometry: Option<Geometry>,
    pub lanes: Lanes,
    /// Sorted by `first_ns`.
    pub records: Vec<Record>,
    /// The rows behind `records`, in the same order; empty when only counts are kept.
    pub rows: Vec<Finding>,
    /// The kept levels of cells, finest first, each sorted by `(lane, bucket)`.
    pub cells: Vec<Vec<Cell>>,
    /// The pyramid level of each entry of `cells`.
    pub stored: Vec<usize>,
    /// Bins by level.
    pub bins: Vec<Vec<Bin>>,
    pub phases: Vec<Span>,
    pub injections: Vec<Injection>,
    /// Rows by [`Tier::index`].
    pub tiers: [u64; 4],
    /// Rows without a time, which the graph cannot place.
    pub unplaced: u64,
    /// One bit per [`Category::index`] present.
    pub categories: u16,
    /// Whether lane 0 (not tied to a process) holds a finding.
    pub lane0_used: bool,
    /// The whole run: the findings and every process's first and last sight.
    /// The buckets and `extent` cover the findings only, so a burst at the
    /// end of a long run still gets the full resolution.
    pub run: Option<(u64, u64)>,
    /// The distinct moments of the findings, for Events spacing.
    pub slots: super::axis::Slots,
    /// Told apart from every other index, so a cache can tell it changed.
    pub id: u64,
}

impl GraphIndex {
    pub(in crate::triage) fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub(in crate::triage) fn geometry(&self) -> Geometry {
        self.geometry.unwrap_or(Geometry::new(0, 0))
    }

    /// The first and last ns of the whole run, processes included.
    pub(in crate::triage) fn run_extent(&self) -> (u64, u64) {
        self.run.unwrap_or_else(|| self.extent())
    }

    /// The first and last ns of the findings.
    pub(in crate::triage) fn extent(&self) -> (u64, u64) {
        let geometry = self.geometry();
        (geometry.origin, geometry.end)
    }

    /// The records whose `first_ns` is in `[from, to]`.
    pub(in crate::triage) fn window(&self, from: f64, to: f64) -> std::ops::Range<usize> {
        let low = self
            .records
            .partition_point(|record| (record.first_ns as f64) < from);
        let high = self
            .records
            .partition_point(|record| (record.first_ns as f64) <= to);
        low..high.max(low)
    }

    /// The kept level to draw from for a bucket of `level`: the coarsest kept
    /// one that is not coarser than asked. Returns its place in `cells` and
    /// its pyramid level.
    pub(in crate::triage) fn kept_level(&self, level: usize) -> (usize, usize) {
        let slot = self
            .stored
            .partition_point(|kept| *kept <= level)
            .saturating_sub(1);
        (slot, self.stored.get(slot).copied().unwrap_or(0))
    }

    /// The cells of `lane` in kept level `slot` whose bucket is in `low..=high`.
    pub(in crate::triage) fn lane_cells(
        &self,
        slot: usize,
        lane: u32,
        low: u32,
        high: u32,
    ) -> &[Cell] {
        let Some(cells) = self.cells.get(slot) else {
            return &[];
        };
        let start = cells.partition_point(|cell| (cell.lane, cell.bucket) < (lane, low));
        let end = cells.partition_point(|cell| (cell.lane, cell.bucket) <= (lane, high));
        &cells[start..end.max(start)]
    }

    /// Bytes the index holds, for the memory budget.
    #[cfg(test)]
    pub(in crate::triage) fn bytes(&self) -> usize {
        let cells: usize = self.cells.iter().map(Vec::len).sum();
        let bins: usize = self.bins.iter().map(Vec::len).sum();
        self.records.len() * std::mem::size_of::<Record>()
            + self.slots.times.len() * 8
            + cells * std::mem::size_of::<Cell>()
            + bins * std::mem::size_of::<Bin>()
            + self.lanes.list.len() * std::mem::size_of::<super::lanes::Lane>()
    }

    /// The level whose buckets are at least `min_px` wide at `ns_per_px`.
    pub(in crate::triage) fn level_for(&self, ns_per_px: f64, min_px: f64) -> usize {
        let geometry = self.geometry();
        let top = geometry.levels() - 1;
        (0..=top)
            .find(|level| geometry.width(*level) / ns_per_px.max(1e-9) >= min_px)
            .unwrap_or(top)
    }

    /// The first record of the row, if any.
    pub(in crate::triage) fn first_with_key(&self, key: trace::InvocationKey) -> Option<usize> {
        self.rows.iter().position(|row| row.key == key)
    }
}

fn next_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// An INFO match counted at a time, with the phase it belongs to.
struct Counted {
    ns: u64,
    count: u32,
}

/// Collects findings, then settles them into an index.
pub(in crate::triage) struct Builder {
    lanes: Lanes,
    keep_lanes: bool,
    records: Vec<Record>,
    rows: Vec<Finding>,
    keep_rows: bool,
    /// For each record pushed from a row: the pid an injection reached.
    targets: Vec<(u32, u32)>,
    counted: Vec<Counted>,
    unplaced: u64,
    /// The time the lanes span, before any finding is added.
    extent: Option<(u64, u64)>,
}

impl Builder {
    /// An index with lanes, and the rows kept so a marker can open its Details.
    pub(in crate::triage) fn new(lanes: Lanes) -> Self {
        let extent = lanes.extent();
        Self {
            lanes,
            keep_lanes: true,
            records: Vec::new(),
            rows: Vec::new(),
            keep_rows: true,
            targets: Vec::new(),
            counted: Vec::new(),
            unplaced: 0,
            extent,
        }
    }

    /// Only the sums over time: the Summary strip has no lanes and no rows.
    pub(in crate::triage) fn overview() -> Self {
        let mut builder = Self::new(Lanes::default());
        builder.keep_lanes = false;
        builder.keep_rows = false;
        builder
    }

    /// Keep the compact records only, as a benchmark of 120,000 findings does.
    #[cfg(test)]
    pub(in crate::triage) fn without_rows(mut self) -> Self {
        self.keep_rows = false;
        self
    }

    pub(in crate::triage) fn push(&mut self, finding: &Finding) {
        let values = &finding.values;
        let text = |key: &str| {
            values.iter().find_map(|(name, value)| match value {
                RowValue::Text(text) if *name == key => Some(text.as_str()),
                _ => None,
            })
        };
        let number = |key: &str| files::number(values, key);
        let first = number("finding.first_ns").unwrap_or(0);
        let tier = Tier::ALL
            .iter()
            .find(|tier| Some(tier.tag()) == text("finding.tier"))
            .copied()
            .unwrap_or(Tier::Info);
        let category = Category::ALL
            .iter()
            .find(|category| Some(category.tag()) == text("finding.category"))
            .copied()
            .unwrap_or(Category::Execution);
        if first == 0 {
            self.unplaced += 1;
            return;
        }
        let rule = text("finding.rule").unwrap_or("");
        let hollow = values.iter().any(|(name, value)| {
            (*name == "capture.path")
                || (*name == "finding.flags"
                    && matches!(value, RowValue::List(flags) if flags.iter().any(|flag| flag == "vm-wide")))
        });
        let cookie = number("process.cookie").unwrap_or(0);
        let pid = number("process.pid").unwrap_or(0) as u32;
        let record = Record {
            first_ns: first,
            last_ns: number("finding.last_ns").unwrap_or(first).max(first),
            count: u32::try_from(number("finding.count").unwrap_or(1)).unwrap_or(u32::MAX),
            lane: if self.keep_lanes {
                self.lanes.lane_of(cookie, pid)
            } else {
                0
            },
            tier: tier.index() as u8,
            category: category.index() as u8,
            phase: phases::phase_of(rule, category).map_or(NO_PHASE, |phase| phase.index() as u8),
            flags: if hollow { HOLLOW } else { 0 },
            slot: 0,
        };
        if self.keep_lanes && rule.starts_with("injection.") {
            if let Some(target) = injected_pid(text("finding.object").unwrap_or("")) {
                self.targets.push((self.records.len() as u32, target));
            }
        }
        self.records.push(record);
        if self.keep_rows {
            self.rows.push(finding.clone());
        }
    }

    /// One INFO match of an anti-analysis or discovery rule, counted at its time.
    pub(in crate::triage) fn count_info(
        &mut self,
        ns: u64,
        count: u32,
        rule: &str,
        category: Category,
    ) {
        if phases::phase_of(rule, category) == Some(Phase::Recon) {
            self.counted.push(Counted { ns, count });
        }
    }

    /// Say that the record just pushed injected into `pid` (tests).
    #[cfg(test)]
    pub(in crate::triage) fn inject_into(&mut self, pid: u32) {
        self.targets.push((self.records.len() as u32 - 1, pid));
    }

    /// Push a record directly (benchmarks and tests).
    #[cfg(test)]
    pub(in crate::triage) fn push_record(&mut self, record: Record) {
        self.records.push(record);
    }

    pub(in crate::triage) fn finish(mut self) -> GraphIndex {
        let mut span: Option<(u64, u64)> = None;
        let mut widen = |from: u64, to: u64| {
            span = Some(span.map_or((from, to), |(lo, hi)| (lo.min(from), hi.max(to))));
        };
        let mut tiers = [0u64; 4];
        let mut categories = 0u16;
        let mut lane0 = false;
        // One pass over the records: the engine hands them over in time order,
        // so they are sorted only when this finds one that is not.
        let mut sorted = true;
        let mut previous = 0;
        let (mut lo, mut hi) = (u64::MAX, 0);
        for record in &self.records {
            sorted &= previous <= record.first_ns;
            previous = record.first_ns;
            lo = lo.min(record.first_ns);
            hi = hi.max(record.last_ns);
            tiers[usize::from(record.tier).min(3)] += 1;
            categories |= 1 << record.category;
            lane0 |= record.lane == 0;
        }
        if !self.records.is_empty() {
            widen(lo, hi);
        }
        if !sorted {
            self.sort();
        }
        // One slot for each distinct moment, in time order.
        let mut times: Vec<u64> = Vec::new();
        if self.keep_lanes {
            for record in &mut self.records {
                if times.last() != Some(&record.first_ns) {
                    times.push(record.first_ns);
                }
                record.slot = (times.len() - 1) as u32;
            }
        }
        let slots = super::axis::Slots::new(times);
        for mark in &self.counted {
            widen(mark.ns, mark.ns);
        }
        let Some((lo, hi)) = span else {
            return GraphIndex {
                unplaced: self.unplaced,
                run: self.extent,
                lanes: self.lanes,
                ..GraphIndex::default()
            };
        };
        let geometry = Geometry::new(lo, hi);
        let levels = geometry.levels();
        let mut bins = vec![vec![Bin::default(); geometry.buckets()]];
        for record in &self.records {
            bins[0][geometry.bucket(record.first_ns)].add(record);
        }
        for mark in &self.counted {
            bins[0][geometry.bucket(mark.ns)].info_recon += mark.count;
        }
        for level in 1..levels {
            let below = &bins[level - 1];
            let mut above = vec![Bin::default(); below.len().div_ceil(2)];
            for (at, bin) in below.iter().enumerate() {
                above[at / 2].merge(bin);
            }
            bins.push(above);
        }
        let phases = phases::detect(&bins[0]);
        let (cells, stored) = if self.keep_lanes {
            lane_cells(
                &self.records,
                &geometry,
                self.lanes.list.len().max(1),
                levels,
            )
        } else {
            (Vec::new(), Vec::new())
        };
        let injections = self
            .targets
            .iter()
            .filter_map(|(record, pid)| {
                let at = self.records[*record as usize].first_ns;
                let target = self.lanes.lane_for_pid(*pid, at)?;
                (target != self.records[*record as usize].lane).then_some(Injection {
                    record: *record,
                    target,
                })
            })
            .collect();
        GraphIndex {
            geometry: Some(geometry),
            lanes: self.lanes,
            records: if self.keep_lanes {
                self.records
            } else {
                Vec::new()
            },
            rows: self.rows,
            cells,
            stored,
            bins,
            phases,
            injections,
            tiers,
            unplaced: self.unplaced,
            categories,
            lane0_used: lane0,
            slots,
            id: next_id(),
            run: Some(
                self.extent
                    .map_or((lo, hi), |(a, b)| (a.min(lo), b.max(hi))),
            ),
        }
    }

    /// Put records (and the rows and injections tied to them) in time order.
    fn sort(&mut self) {
        let mut order: Vec<u32> = (0..self.records.len() as u32).collect();
        order.sort_by_key(|at| (self.records[*at as usize].first_ns, *at));
        let mut inverse = vec![0u32; order.len()];
        for (new, old) in order.iter().enumerate() {
            inverse[*old as usize] = new as u32;
        }
        self.records = order.iter().map(|at| self.records[*at as usize]).collect();
        if self.keep_rows && self.rows.len() == order.len() {
            let mut rows: Vec<Option<Finding>> = std::mem::take(&mut self.rows)
                .into_iter()
                .map(Some)
                .collect();
            self.rows = order
                .iter()
                .filter_map(|at| rows[*at as usize].take())
                .collect();
        }
        for (record, _) in &mut self.targets {
            *record = inverse[*record as usize];
        }
    }
}

/// The pid a rule of the Injection category acted on: its object reads `pid N ...`.
fn injected_pid(object: &str) -> Option<u32> {
    object
        .strip_prefix("pid ")?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

/// Cells of every level, from records sorted by time.
fn lane_cells(
    records: &[Record],
    geometry: &Geometry,
    lanes: usize,
    levels: usize,
) -> (Vec<Vec<Cell>>, Vec<usize>) {
    // Records are in time order, so each lane's cells come out in bucket order;
    // laying the lanes end to end gives the (lane, bucket) order.
    // Each lane gets room for as many cells as it has records, in one array,
    // then the filled parts are laid end to end.
    let mut start = vec![0usize; lanes + 1];
    for record in records {
        start[(record.lane as usize).min(lanes - 1) + 1] += 1;
    }
    for lane in 0..lanes {
        start[lane + 1] += start[lane];
    }
    let mut slots = vec![Cell::default(); records.len()];
    let mut filled = start.clone();
    for (at, record) in records.iter().enumerate() {
        let bucket = geometry.bucket(record.first_ns) as u32;
        let lane = (record.lane as usize).min(lanes - 1);
        match filled[lane]
            .checked_sub(1)
            .filter(|last| *last >= start[lane])
        {
            Some(last) if slots[last].bucket == bucket => slots[last].add(record),
            _ => {
                slots[filled[lane]] = Cell::of(record, at, bucket);
                filled[lane] += 1;
            }
        }
    }
    let mut sorted = Vec::with_capacity(
        filled
            .iter()
            .zip(&start)
            .map(|(end, begin)| end - begin)
            .sum(),
    );
    for lane in 0..lanes {
        sorted.extend_from_slice(&slots[start[lane]..filled[lane]]);
    }
    drop(slots);
    // Keep a level only when it holds at most half the cells of the one kept
    // below it: the kept levels then add up to at most twice the base. Drawing
    // from a finer kept level than asked merges cells that fall within a few
    // pixels of each other as it goes.
    let counts = level_counts(&sorted, levels);
    let mut kept = vec![sorted];
    let mut stored = vec![0usize];
    for (level, count) in counts.iter().enumerate().skip(1) {
        // The cells a level holds are the same whichever kept level they are made from.
        if count * 2 <= kept.last().map_or(0, Vec::len) {
            let below = kept.last().expect("the base level");
            let shift = (level - stored.last().copied().unwrap_or(0)) as u32;
            let merged = merge_up(below, shift);
            kept.push(merged);
            stored.push(level);
        }
    }
    (kept, stored)
}

/// How many cells each level holds, from the base level in one pass. A cell
/// starts a new cell at every level up to the highest bit its bucket differs
/// from the one before in, and at every level when its lane differs.
fn level_counts(cells: &[Cell], levels: usize) -> Vec<usize> {
    let mut starts_to = vec![0usize; 33];
    let mut new_lanes = 0usize;
    let mut previous: Option<&Cell> = None;
    for cell in cells {
        match previous {
            Some(before) if before.lane == cell.lane => {
                let differing = 32 - (before.bucket ^ cell.bucket).leading_zeros() as usize;
                starts_to[differing] += 1;
            }
            _ => new_lanes += 1,
        }
        previous = Some(cell);
    }
    (0..levels)
        .map(|level| new_lanes + starts_to[(level + 1).min(32)..].iter().sum::<usize>())
        .collect()
}

/// `cells` with their buckets halved `shift` times, equal ones merged.
fn merge_up(cells: &[Cell], shift: u32) -> Vec<Cell> {
    let mut above: Vec<Cell> = Vec::with_capacity(cells.len() / 2 + 1);
    for cell in cells {
        let mut cell = *cell;
        cell.bucket >>= shift;
        match above.last_mut() {
            Some(last) if last.lane == cell.lane && last.bucket == cell.bucket => last.merge(&cell),
            _ => above.push(cell),
        }
    }
    above
}
