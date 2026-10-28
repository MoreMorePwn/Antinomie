// SPDX-License-Identifier: GPL-3.0-only
//! What the run knows of each byte of a file, after each call that touched it.
//!
//! The File Reconstruction window replays a file's calls in the order the file
//! system applied them over what the file held at the start of the run, and
//! asks this module, for any point in that story, what each byte is and how it
//! became known.
//!
//! | Name | Role |
//! | --- | --- |
//! | [`State`] | How a byte is known: unknown, read, before-image, written, not captured, mapping |
//! | [`Step`], [`Action`] | One call's effect on the bytes, in write order ([`Timeline`]) |
//! | [`Start`] | What the file held when the run started |
//! | [`Reconstruction`] | The byte map after the chosen step, with each byte's history |
//!
//! Nothing is invented. A byte nobody has seen stays unknown (`??`); a byte
//! written without a captured payload is `##`; a byte a shared mapping may
//! have changed is `~~` until a later write or read shows it. A saved
//! reconstruction fills such bytes with 00 and says which ones in a mask.
//!
//! How a call changes the map:
//!
//! * a **read** of bytes that are unknown, not captured or under a mapping
//!   makes them *read* (the file's content at that moment); bytes already
//!   known keep their state and the time they were first learned;
//! * a **write** with its payload makes the range *written*, a write without
//!   one makes it *not captured*;
//! * a **resize** cuts the bytes past the new end and, past the old end, adds
//!   zeros (written), when the old size is known;
//! * a **zero** range (punch hole, zero range) is written zeros;
//! * a **change** whose bytes are not known (an in-kernel copy from another
//!   file, a collapsed range) makes the range *not captured*;
//! * a **mapping** (a shared writable mapping, which can change bytes with no
//!   call) makes the range *mapping*.
use crate::file_before::{Before as EarlierBytes, DiskFile};
use crate::file_writes::{Extent, Gap, Piece, ReadError, Source};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{self, Write};

/// Steps kept per file; further calls are counted.
pub const STEPS_PER_FILE: usize = 65_536;
/// The "step" that stands for the start of the run.
pub const START: usize = usize::MAX;
/// Bytes read from a source at a time.
const CHUNK: u64 = 65_536;

/// How a byte is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Nobody has seen it.
    Unknown,
    /// Seen in a read: the file's content at that moment.
    Read,
    /// From what the file held when the run started.
    Before,
    /// Put there by a write (or zeros the run made) whose bytes are known.
    Written,
    /// Changed, and the new value was not captured.
    NotCaptured(Gap),
    /// A shared writable mapping may have changed it.
    Mapping,
}

impl State {
    /// The two characters the byte map shows for a byte with no value.
    pub fn glyph(self) -> Option<&'static str> {
        match self {
            State::Unknown => Some("??"),
            State::NotCaptured(_) => Some("##"),
            State::Mapping => Some("~~"),
            State::Read | State::Before | State::Written => None,
        }
    }

    /// Whether the byte has a value.
    pub fn has_value(self) -> bool {
        self.glyph().is_none()
    }

    pub fn label(self) -> &'static str {
        match self {
            State::Unknown => "never seen",
            State::Read => "seen in a read",
            State::Before => "from the starting disk",
            State::Written => "written by the run",
            State::NotCaptured(_) => "changed, new value not captured",
            State::Mapping => "may have changed through a shared mapping",
        }
    }

    /// The byte of a saved `.mask` file: 0 known, 1 unknown, 2 not captured,
    /// 3 mapping.
    pub fn mask(self) -> u8 {
        match self {
            State::Unknown => 1,
            State::NotCaptured(_) => 2,
            State::Mapping => 3,
            State::Read | State::Before | State::Written => 0,
        }
    }
}

/// What a call did to the file's bytes.
#[derive(Clone, Debug)]
pub enum Action {
    /// Bytes the call returned: [`Piece::Kept`] extents.
    Read(Vec<Extent>),
    /// Bytes the call wrote: kept or not captured.
    Write(Vec<Extent>),
    /// The file was cut or extended to this size.
    Resize(u64),
    /// A range now reads back as zeros (punch hole, zero range).
    Zero { offset: u64, len: u64 },
    /// A range changed to bytes the run did not see.
    Changed { offset: u64, len: u64 },
    /// A shared writable mapping covers the range.
    Mapping { offset: u64, len: u64 },
}

/// One call's effect, in the order the file system applied it.
#[derive(Clone, Debug)]
pub struct Step {
    pub time_ns: u64,
    /// The call's index in the file's event list, when it has one.
    pub event: Option<u32>,
    /// The guest's write order, which settles two racing writers.
    pub order: Option<u64>,
    pub action: Action,
}

impl Step {
    /// The ranges the step touches, with the state each gets (`None` for a
    /// read, which changes only what was not known).
    pub fn ranges(&self) -> Vec<(u64, u64, Option<State>)> {
        match &self.action {
            Action::Read(extents) => extents
                .iter()
                .map(|extent| (extent.offset, extent.len, None))
                .collect(),
            Action::Write(extents) => extents
                .iter()
                .map(|extent| {
                    let state = match extent.piece {
                        Piece::NotCaptured(gap) => State::NotCaptured(gap),
                        _ => State::Written,
                    };
                    (extent.offset, extent.len, Some(state))
                })
                .collect(),
            Action::Resize(_) => Vec::new(),
            Action::Zero { offset, len } => vec![(*offset, *len, Some(State::Written))],
            Action::Changed { offset, len } => {
                vec![(*offset, *len, Some(State::NotCaptured(Gap::NotRecorded)))]
            }
            Action::Mapping { offset, len } => vec![(*offset, *len, Some(State::Mapping))],
        }
    }
}

/// A file's steps in write order.
#[derive(Clone, Debug, Default)]
pub struct Timeline {
    steps: Vec<Step>,
    /// Calls that changed bytes after the list was full.
    pub unlisted: u64,
}

impl Timeline {
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Add a step: after the calls before it, but before a numbered write
    /// with a higher write order (two writers raced and this one reached the
    /// host late). Returns false, and counts the call, when the list is full.
    pub fn push(&mut self, step: Step) -> bool {
        if self.steps.len() >= STEPS_PER_FILE {
            self.unlisted += 1;
            return false;
        }
        let mut at = self.steps.len();
        if let Some(order) = step.order {
            while at > 0 && self.steps[at - 1].order.is_some_and(|later| later > order) {
                at -= 1;
            }
        }
        self.steps.insert(at, step);
        true
    }
}

/// What the file held when the run started.
#[derive(Clone, Debug, Default)]
pub struct Start {
    /// Its size, when known.
    pub size: Option<u64>,
    /// Where its bytes can be read, when they can.
    pub source: Option<Source>,
}

impl Start {
    /// A file the run created: it started empty.
    pub fn empty() -> Self {
        Self {
            size: Some(0),
            source: None,
        }
    }

    /// From what the starting disk (or the recording) says of the file.
    pub fn from_earlier(before: Option<&EarlierBytes>, file: Option<&DiskFile>) -> Self {
        let source = |size: u64| {
            file.filter(|_| size > 0).map(|file| Source::Disk {
                file: file.clone(),
                at: 0,
            })
        };
        match before {
            Some(EarlierBytes::Created) => Self::empty(),
            Some(EarlierBytes::OnDisk { size, .. } | EarlierBytes::Recorded { size, .. }) => Self {
                size: Some(*size),
                source: source(*size),
            },
            Some(EarlierBytes::NotCopied { size, .. } | EarlierBytes::TooLarge(size)) => Self {
                size: Some(*size),
                source: None,
            },
            _ => Self::default(),
        }
    }
}

/// How a span of bytes is filled.
#[derive(Clone, Debug)]
enum Fill {
    None,
    Zero,
    Bytes(Source),
}

#[derive(Clone, Debug)]
struct Span {
    len: u64,
    state: State,
    fill: Fill,
    /// The step that gave the span its state ([`START`] for the start).
    learned: usize,
}

impl Span {
    /// The part of this span `skip` bytes in, `len` long.
    fn part(&self, skip: u64, len: u64) -> Span {
        let fill = match &self.fill {
            Fill::Bytes(source) => Fill::Bytes(source.tail(skip).head(len)),
            Fill::Zero => Fill::Zero,
            Fill::None => Fill::None,
        };
        Span {
            len,
            state: self.state,
            fill,
            learned: self.learned,
        }
    }
}

/// One byte for the byte map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    pub state: State,
    /// Its value, when it has one and could be read.
    pub byte: Option<u8>,
    /// The step that gave it this state.
    pub learned: usize,
}

/// What a step did to one byte, for its history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// The file held it when the run started.
    Start,
    Read,
    Written,
    /// Written through a shared mapping: the page as the guest copied it at
    /// writeback or unmap.
    WrittenMapped,
    NotCaptured(Gap),
    Zeroed,
    Mapping,
    /// Cut off by a resize.
    Cut,
    /// Changed by a call whose bytes the run did not see.
    Changed,
}

impl Event {
    pub fn label(self) -> &'static str {
        match self {
            Event::Start => "held at the start of the run",
            Event::Read => "read",
            Event::Written => "written",
            Event::WrittenMapped => "written through a shared mapping (as at writeback or unmap)",
            Event::NotCaptured(_) => "written, value not captured",
            Event::Zeroed => "zeroed",
            Event::Mapping => "under a shared writable mapping",
            Event::Cut => "cut off by a resize",
            Event::Changed => "changed, bytes not seen",
        }
    }
}

/// One line of a byte's history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct History {
    /// The step, or [`START`].
    pub step: usize,
    pub event: Event,
    pub byte: Option<u8>,
}

/// Bytes by state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub unknown: u64,
    pub read: u64,
    pub before: u64,
    pub written: u64,
    pub not_captured: u64,
    pub mapping: u64,
}

impl Counts {
    pub fn total(&self) -> u64 {
        self.unknown + self.read + self.before + self.written + self.not_captured + self.mapping
    }

    /// Bytes with no value.
    pub fn missing(&self) -> u64 {
        self.unknown + self.not_captured + self.mapping
    }
}

/// What a save produced.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Saved {
    pub bytes: u64,
    /// Bytes saved as 00 because they have no value (or could not be read).
    pub filled: u64,
    /// Of those, bytes that have a value but could not be read from their
    /// source (the starting disk is gone).
    pub unreadable: u64,
}

/// Why no hash could be taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Incomplete {
    /// The file's size is not known.
    SizeUnknown,
    /// Bytes with no value remain.
    Missing(u64),
    /// A source could not be read (the starting disk is gone).
    Unreadable,
}

/// The byte map of one file at a point in its story.
#[derive(Clone, Debug)]
pub struct Reconstruction {
    start: Start,
    steps: Vec<Step>,
    spans: BTreeMap<u64, Span>,
    /// The file's size when known (from the start or from a resize).
    size: Option<u64>,
    /// The highest offset any span reaches.
    reach: u64,
    /// Steps applied.
    at: usize,
}

impl Reconstruction {
    /// The map at the start of the run: before any step.
    pub fn new(start: Start, timeline: &Timeline) -> Self {
        let mut map = Self {
            size: start.size,
            reach: 0,
            spans: BTreeMap::new(),
            steps: timeline.steps.clone(),
            at: 0,
            start,
        };
        map.reset();
        map
    }

    fn reset(&mut self) {
        self.spans.clear();
        self.size = self.start.size;
        self.reach = 0;
        self.at = 0;
        if let Some(size) = self.start.size.filter(|size| *size > 0) {
            // With a size and no source the bytes are not known: nothing to show.
            if let Some(source) = self.start.source.clone() {
                self.put(0, size, State::Before, Fill::Bytes(source), START);
            }
        }
    }

    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// What the file held when the run started.
    pub fn start(&self) -> &Start {
        &self.start
    }

    /// Steps applied: the map shows the file after this many calls.
    pub fn position(&self) -> usize {
        self.at
    }

    /// Show the file after `count` steps (clamped).
    pub fn goto(&mut self, count: usize) {
        let count = count.min(self.steps.len());
        if count < self.at {
            self.reset();
        }
        while self.at < count {
            self.apply(self.at);
            self.at += 1;
        }
    }

    /// The size the map spans: the file's size where known, else the highest
    /// offset any step reached.
    pub fn size(&self) -> u64 {
        self.size.unwrap_or(self.reach).max(self.reach)
    }

    /// Whether the size is known (not only the highest offset reached).
    pub fn size_known(&self) -> bool {
        self.size.is_some()
    }

    fn put(&mut self, offset: u64, len: u64, state: State, fill: Fill, learned: usize) {
        if len == 0 {
            return;
        }
        let end = offset.saturating_add(len);
        self.clear(offset, end);
        self.spans.insert(
            offset,
            Span {
                len: end - offset,
                state,
                fill,
                learned,
            },
        );
        self.reach = self.reach.max(end);
    }

    /// Remove what lies in `[from, to)`, keeping the parts around it.
    fn clear(&mut self, from: u64, to: u64) {
        let touching: Vec<u64> = self
            .spans
            .range(..to)
            .rev()
            .take_while(|(start, old)| start.saturating_add(old.len) > from)
            .map(|(start, _)| *start)
            .collect();
        for start in touching {
            let old = self.spans.remove(&start).expect("listed");
            let end = start + old.len;
            if start < from {
                self.spans.insert(start, old.part(0, from - start));
            }
            if end > to {
                self.spans.insert(to, old.part(to - start, end - to));
            }
        }
    }

    /// The end of the last span.
    fn last_end(&self) -> u64 {
        self.spans
            .iter()
            .next_back()
            .map_or(0, |(start, span)| start + span.len)
    }

    /// Where `[from, to)` is not known to have a value: the sub-ranges that
    /// are unknown, not captured or under a mapping.
    fn missing_in(&self, from: u64, to: u64) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut at = from;
        let first = self
            .spans
            .range(..=from)
            .next_back()
            .filter(|(start, span)| start.saturating_add(span.len) > from)
            .map_or(from, |(start, _)| *start);
        for (start, span) in self.spans.range(first..to) {
            let end = start + span.len;
            if *start > at {
                out.push((at, *start));
            }
            if !span.state.has_value() {
                out.push(((*start).max(from), end.min(to)));
            }
            at = at.max(end);
        }
        if at < to {
            out.push((at, to));
        }
        out
    }

    fn apply(&mut self, index: usize) {
        let action = self.steps[index].action.clone();
        match action {
            Action::Read(extents) => {
                for extent in extents {
                    let Piece::Kept(source) = &extent.piece else {
                        continue;
                    };
                    let end = extent.end();
                    for (from, to) in self.missing_in(extent.offset, end) {
                        let part = source.tail(from - extent.offset).head(to - from);
                        self.put(from, to - from, State::Read, Fill::Bytes(part), index);
                    }
                    self.grow(end);
                }
            }
            Action::Write(extents) => {
                for extent in extents {
                    match &extent.piece {
                        Piece::Kept(source) | Piece::Mapped(source) | Piece::Before(source) => self
                            .put(
                                extent.offset,
                                extent.len,
                                State::Written,
                                Fill::Bytes(source.clone()),
                                index,
                            ),
                        Piece::NotCaptured(gap) => self.put(
                            extent.offset,
                            extent.len,
                            State::NotCaptured(*gap),
                            Fill::None,
                            index,
                        ),
                    }
                    self.grow(extent.end());
                }
            }
            Action::Resize(to) => {
                let old = self.size.unwrap_or(self.reach);
                if to < old.max(self.reach) {
                    self.clear(to, u64::MAX);
                    self.reach = self.last_end();
                } else if self.size.is_some() && to > old {
                    self.put(old, to - old, State::Written, Fill::Zero, index);
                }
                self.size = Some(to);
            }
            Action::Zero { offset, len } => {
                self.put(offset, len, State::Written, Fill::Zero, index);
                self.grow(offset.saturating_add(len));
            }
            Action::Changed { offset, len } => {
                let end = self.clip(offset, len);
                self.put(
                    offset,
                    end.saturating_sub(offset),
                    State::NotCaptured(Gap::NotRecorded),
                    Fill::None,
                    index,
                );
            }
            Action::Mapping { offset, len } => {
                let end = self.clip(offset, len);
                self.put(
                    offset,
                    end.saturating_sub(offset),
                    State::Mapping,
                    Fill::None,
                    index,
                );
            }
        }
    }

    /// The end of `[offset, offset + len)`, cut at the file's size when that
    /// is known (a range of "everything from here").
    fn clip(&self, offset: u64, len: u64) -> u64 {
        let end = offset.saturating_add(len);
        if len == u64::MAX || end == u64::MAX {
            self.size.unwrap_or(self.reach).max(self.reach)
        } else {
            end
        }
    }

    /// A call reached `end`: the file is at least that long.
    fn grow(&mut self, end: u64) {
        if self.size.is_some_and(|size| size < end) {
            self.size = Some(end);
        }
        self.reach = self.reach.max(end);
    }

    /// The bytes in `[offset, offset + count)` for the byte map, clipped to
    /// the size.
    pub fn row(&self, offset: u64, count: usize) -> Vec<Cell> {
        let end = offset.saturating_add(count as u64).min(self.size());
        let mut cells = Vec::with_capacity(count);
        let mut at = offset;
        while at < end {
            let found = self
                .spans
                .range(..=at)
                .next_back()
                .filter(|(start, span)| start.saturating_add(span.len) > at);
            match found {
                None => {
                    // Unknown until the next span.
                    let next = self
                        .spans
                        .range(at..)
                        .next()
                        .map_or(end, |(start, _)| (*start).min(end));
                    for _ in at..next {
                        cells.push(Cell {
                            state: State::Unknown,
                            byte: None,
                            learned: START,
                        });
                    }
                    at = next;
                }
                Some((start, span)) => {
                    let stop = (start + span.len).min(end);
                    let len = stop - at;
                    let bytes = match &span.fill {
                        Fill::Bytes(source) => source.read(at - start, len).ok(),
                        Fill::Zero => Some(vec![0; len as usize]),
                        Fill::None => None,
                    };
                    for index in 0..len as usize {
                        cells.push(Cell {
                            state: span.state,
                            byte: bytes.as_ref().and_then(|bytes| bytes.get(index).copied()),
                            learned: span.learned,
                        });
                    }
                    at = stop;
                }
            }
        }
        cells
    }

    /// The spans in order, unknown stretches included, from 0 to the size.
    pub fn spans(&self) -> Vec<(u64, u64, State)> {
        let size = self.size();
        let mut out = Vec::new();
        let mut at = 0;
        for (start, span) in &self.spans {
            if *start >= size {
                break;
            }
            if *start > at {
                out.push((at, *start - at, State::Unknown));
            }
            let len = span.len.min(size - start);
            out.push((*start, len, span.state));
            at = start + len;
        }
        if at < size {
            out.push((at, size - at, State::Unknown));
        }
        out
    }

    /// Bytes by state over the file's size.
    pub fn counts(&self) -> Counts {
        let mut counts = Counts::default();
        for (_, len, state) in self.spans() {
            match state {
                State::Unknown => counts.unknown += len,
                State::Read => counts.read += len,
                State::Before => counts.before += len,
                State::Written => counts.written += len,
                State::NotCaptured(_) => counts.not_captured += len,
                State::Mapping => counts.mapping += len,
            }
        }
        counts
    }

    /// Every byte of the file has a value.
    pub fn complete(&self) -> bool {
        self.size.is_some() && self.counts().missing() == 0
    }

    /// The history of the byte at `offset` up to the current step, oldest
    /// first. The last entry is the one that gave the byte its present state,
    /// except that a read of a known byte is not listed (it changes nothing).
    pub fn history(&self, offset: u64) -> Vec<History> {
        let mut out = Vec::new();
        if let (Some(size), Some(source)) = (self.start.size, &self.start.source)
            && offset < size
        {
            out.push(History {
                step: START,
                event: Event::Start,
                byte: source.read(offset, 1).ok().and_then(|b| b.first().copied()),
            });
        }
        let value = |extent: &Extent| match &extent.piece {
            Piece::Kept(source) | Piece::Mapped(source) | Piece::Before(source) => source
                .read(offset - extent.offset, 1)
                .ok()
                .and_then(|bytes| bytes.first().copied()),
            Piece::NotCaptured(_) => None,
        };
        for (index, step) in self.steps[..self.at].iter().enumerate() {
            let inside = |extent: &&Extent| extent.offset <= offset && offset < extent.end();
            match &step.action {
                Action::Read(extents) => {
                    for extent in extents.iter().filter(inside) {
                        out.push(History {
                            step: index,
                            event: Event::Read,
                            byte: value(extent),
                        });
                    }
                }
                Action::Write(extents) => {
                    for extent in extents.iter().filter(inside) {
                        out.push(History {
                            step: index,
                            event: match extent.piece {
                                Piece::NotCaptured(gap) => Event::NotCaptured(gap),
                                Piece::Mapped(_) => Event::WrittenMapped,
                                _ => Event::Written,
                            },
                            byte: value(extent),
                        });
                    }
                }
                Action::Resize(to) => {
                    if offset >= *to && out.last().is_some_and(|last| last.event != Event::Cut) {
                        out.push(History {
                            step: index,
                            event: Event::Cut,
                            byte: None,
                        });
                    }
                }
                Action::Zero { offset: from, len } => {
                    if *from <= offset && offset - from < *len {
                        out.push(History {
                            step: index,
                            event: Event::Zeroed,
                            byte: Some(0),
                        });
                    }
                }
                Action::Changed { offset: from, len } => {
                    if *from <= offset && offset - from < *len {
                        out.push(History {
                            step: index,
                            event: Event::Changed,
                            byte: None,
                        });
                    }
                }
                Action::Mapping { offset: from, len } => {
                    if *from <= offset && offset - from < *len {
                        out.push(History {
                            step: index,
                            event: Event::Mapping,
                            byte: None,
                        });
                    }
                }
            }
        }
        out
    }

    /// The exact bytes `[offset, offset + len)`, or why not.
    pub fn bytes(&self, offset: u64, len: u64) -> Result<Vec<u8>, ReadError> {
        let end = offset.checked_add(len).ok_or(ReadError::Unknown(offset))?;
        let mut out = Vec::with_capacity(usize::try_from(len).unwrap_or(0).min(1 << 26));
        let mut at = offset;
        while at < end {
            let step = (end - at).min(CHUNK);
            let cells = self.row(at, step as usize);
            if (cells.len() as u64) < step {
                return Err(ReadError::Unknown(at + cells.len() as u64));
            }
            for (index, cell) in cells.iter().enumerate() {
                match (cell.state, cell.byte) {
                    (State::Unknown | State::Mapping, _) => {
                        return Err(ReadError::Unknown(at + index as u64));
                    }
                    (State::NotCaptured(_), _) => {
                        return Err(ReadError::NotCaptured(at + index as u64));
                    }
                    (_, Some(byte)) => out.push(byte),
                    (_, None) => return Err(ReadError::Unreadable),
                }
            }
            at += step;
        }
        Ok(out)
    }

    /// Write the file, bytes with no value as 00, to `out`; with `mask`, one
    /// byte per file byte says which ones those are ([`State::mask`]).
    pub fn save(&self, out: &mut dyn Write, mut mask: Option<&mut dyn Write>) -> io::Result<Saved> {
        let size = self.size();
        let mut saved = Saved::default();
        let mut at = 0;
        while at < size {
            let step = (size - at).min(CHUNK);
            let cells = self.row(at, step as usize);
            let mut data = Vec::with_capacity(cells.len());
            let mut marks = Vec::with_capacity(cells.len());
            for cell in &cells {
                match cell.byte.filter(|_| cell.state.has_value()) {
                    Some(byte) => {
                        data.push(byte);
                        marks.push(0);
                    }
                    None => {
                        saved.filled += 1;
                        saved.unreadable += u64::from(cell.state.has_value());
                        data.push(0);
                        // A byte that should have a value but could not be
                        // read is unknown here.
                        marks.push(match cell.state.mask() {
                            0 => 1,
                            mask => mask,
                        });
                    }
                }
            }
            out.write_all(&data)?;
            if let Some(mask) = mask.as_deref_mut() {
                mask.write_all(&marks)?;
            }
            saved.bytes += data.len() as u64;
            at += step;
        }
        Ok(saved)
    }

    /// The SHA-256 of the file as reconstructed, when every byte has a value.
    pub fn sha256(&self) -> Result<String, Incomplete> {
        if self.size.is_none() {
            return Err(Incomplete::SizeUnknown);
        }
        let counts = self.counts();
        if counts.missing() > 0 {
            return Err(Incomplete::Missing(counts.missing()));
        }
        struct Digester(Sha256);
        impl Write for Digester {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.update(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut digest = Digester(Sha256::new());
        let saved = self
            .save(&mut digest, None)
            .map_err(|_| Incomplete::Unreadable)?;
        if saved.unreadable > 0 {
            return Err(Incomplete::Unreadable);
        }
        Ok(digest
            .0
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }

    /// The number of steps at or before `time_ns`: the story as it stood at
    /// that moment.
    pub fn steps_until(&self, time_ns: u64) -> usize {
        self.steps
            .iter()
            .rposition(|step| step.time_ns <= time_ns)
            .map_or(0, |last| last + 1)
    }

    /// The text of the file when every byte is known, it is valid UTF-8 and
    /// not larger than `limit`.
    pub fn text(&self, limit: u64) -> Result<String, TextError> {
        if self.size.is_none() {
            return Err(TextError::Incomplete(0));
        }
        let size = self.size();
        if size > limit {
            return Err(TextError::TooLarge(size));
        }
        let counts = self.counts();
        if counts.missing() > 0 {
            return Err(TextError::Incomplete(counts.missing()));
        }
        let bytes = self.bytes(0, size).map_err(|_| TextError::Incomplete(0))?;
        String::from_utf8(bytes).map_err(|_| TextError::NotText)
    }
}

/// The SHA-256 of `bytes` as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Why a file has no text view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextError {
    TooLarge(u64),
    /// Bytes with no value remain.
    Incomplete(u64),
    /// Not valid UTF-8, or it holds control bytes.
    NotText,
}

impl TextError {
    pub fn label(self) -> String {
        match self {
            TextError::TooLarge(size) => {
                format!("the file is {size} bytes, too large for a line diff")
            }
            TextError::Incomplete(0) => "the file's size is not known".into(),
            TextError::Incomplete(count) => format!("{count} bytes have no value yet"),
            TextError::NotText => "the file is not text".into(),
        }
    }
}

/// One line of a line diff.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffLine {
    pub change: Change,
    pub text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Same,
    Added,
    Removed,
}

/// The lines that differ between `old` and `new`, in order, with common lines
/// between. Common lines at the head and tail are kept short by the caller.
/// Files with more than [`DIFF_LINES`] differing lines on a side give the
/// whole old side removed and the new side added.
pub fn line_diff(old: &str, new: &str) -> Vec<DiffLine> {
    let a: Vec<&str> = old.split_inclusive('\n').collect();
    let b: Vec<&str> = new.split_inclusive('\n').collect();
    let head = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let tail = a[head..]
        .iter()
        .rev()
        .zip(b[head..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (ma, mb) = (&a[head..a.len() - tail], &b[head..b.len() - tail]);
    let line = |change, text: &str| DiffLine {
        change,
        text: text.trim_end_matches('\n').to_owned(),
    };
    let mut out: Vec<DiffLine> = a[..head].iter().map(|t| line(Change::Same, t)).collect();
    if ma.len() > DIFF_LINES || mb.len() > DIFF_LINES {
        out.extend(ma.iter().map(|t| line(Change::Removed, t)));
        out.extend(mb.iter().map(|t| line(Change::Added, t)));
    } else {
        // Longest common subsequence of the middle.
        let width = mb.len() + 1;
        let mut table = vec![0u32; (ma.len() + 1) * width];
        for i in (0..ma.len()).rev() {
            for j in (0..mb.len()).rev() {
                table[i * width + j] = if ma[i] == mb[j] {
                    table[(i + 1) * width + j + 1] + 1
                } else {
                    table[(i + 1) * width + j].max(table[i * width + j + 1])
                };
            }
        }
        let (mut i, mut j) = (0, 0);
        while i < ma.len() && j < mb.len() {
            if ma[i] == mb[j] {
                out.push(line(Change::Same, ma[i]));
                i += 1;
                j += 1;
            } else if table[(i + 1) * width + j] >= table[i * width + j + 1] {
                out.push(line(Change::Removed, ma[i]));
                i += 1;
            } else {
                out.push(line(Change::Added, mb[j]));
                j += 1;
            }
        }
        out.extend(ma[i..].iter().map(|t| line(Change::Removed, t)));
        out.extend(mb[j..].iter().map(|t| line(Change::Added, t)));
    }
    out.extend(a[a.len() - tail..].iter().map(|t| line(Change::Same, t)));
    out
}

/// Differing lines per side the line diff will align.
pub const DIFF_LINES: usize = 2000;

#[cfg(test)]
mod tests;
