// SPDX-License-Identifier: GPL-3.0-only
//! Notes on a sample, with typed references to the things they are about.
//!
//! A note is free text the analyst wrote. Its references are links to a run,
//! a process, a call, an indicator, an artefact, a custody entry or a node of
//! the lineage graph. A reference keeps the label it had when the note was
//! saved, so it still reads well after the thing it names is gone.
//!
//! Adding, editing and deleting a note each add an entry to the sample's
//! custody log with the SHA-256 of the text and the labels of the references.
//! The text itself is not in the log: the log can be exported and shared.
use super::{
    custody::CustodyEvent,
    library::{Library, now_ms},
};
use rusqlite::params;

/// Tables of the notes; created with the rest of the library (layout 2).
pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS note(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL REFERENCES sample(sha256) ON DELETE CASCADE,
    body TEXT NOT NULL,
    by TEXT NOT NULL DEFAULT '',
    created_ms INTEGER NOT NULL,
    edited_ms INTEGER
);
CREATE INDEX IF NOT EXISTS note_sample ON note(sha256);
CREATE TABLE IF NOT EXISTS note_ref(
    note_id INTEGER NOT NULL REFERENCES note(id) ON DELETE CASCADE,
    ord INTEGER NOT NULL,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(note_id, ord)
);
";

/// The longest note, in characters.
pub const MAX_NOTE: usize = 8000;
/// Most references one note names.
pub const MAX_REFS: usize = 32;

/// What a reference points at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RefKind {
    /// A run of the sample; the target is `<vm id>/<run id>`.
    Run,
    /// A process of a run; `<vm id>/<run id>/<pid>`.
    Process,
    /// A call in the run's Syscall Trace; `<vm id>/<run id>/<call number>`.
    Call,
    /// An indicator; `<type>:<value>`.
    Indicator,
    /// An artefact; `<kind>/<vm id>/<run id>/<name>`, see [`artifact_target`].
    Artifact,
    /// An entry of the sample's custody log; its number.
    Custody,
    /// A node of the lineage graph; the node's SHA-256 or path key.
    Lineage,
}

impl RefKind {
    pub const ALL: [RefKind; 7] = [
        Self::Run,
        Self::Process,
        Self::Call,
        Self::Indicator,
        Self::Artifact,
        Self::Custody,
        Self::Lineage,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Process => "process",
            Self::Call => "call",
            Self::Indicator => "indicator",
            Self::Artifact => "artifact",
            Self::Custody => "custody",
            Self::Lineage => "lineage",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == text)
    }

    /// The word a picker or chip uses for the kind.
    pub fn label(self) -> &'static str {
        match self {
            Self::Run => "Run",
            Self::Process => "Process",
            Self::Call => "Call",
            Self::Indicator => "IoC",
            Self::Artifact => "Artifact",
            Self::Custody => "Custody entry",
            Self::Lineage => "Lineage node",
        }
    }
}

/// One reference of a note.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NoteRef {
    pub kind: RefKind,
    pub target: String,
    /// What the reference read like when the note was saved.
    pub label: String,
}

impl NoteRef {
    pub fn new(kind: RefKind, target: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            kind,
            target: target.into(),
            label: label.into(),
        }
    }

    /// The run a run, process or call reference names: `(vm id, run id)`.
    pub fn run(&self) -> Option<(&str, &str)> {
        if !matches!(self.kind, RefKind::Run | RefKind::Process | RefKind::Call) {
            return None;
        }
        let mut parts = self.target.splitn(3, '/');
        Some((parts.next()?, parts.next()?))
    }

    /// The process id of a process reference, or the call number of a call.
    pub fn number(&self) -> Option<u64> {
        if !matches!(self.kind, RefKind::Process | RefKind::Call) {
            return None;
        }
        self.target.splitn(3, '/').nth(2)?.parse().ok()
    }
}

/// The target of an artefact reference.
pub fn artifact_target(kind: &str, vm_id: &str, run_id: &str, name: &str) -> String {
    format!("{kind}/{vm_id}/{run_id}/{name}")
}

/// A note as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    pub id: i64,
    pub sha256: String,
    pub text: String,
    pub by: String,
    pub created_ms: u64,
    pub edited_ms: Option<u64>,
    pub refs: Vec<NoteRef>,
}

/// SHA-256 of a note's text, as the custody log records it.
pub fn text_hash(text: &str) -> String {
    crate::storage::sha256_hex(text.as_bytes())
}

/// The references once each: the same target twice is one reference.
fn once(refs: &[NoteRef]) -> Vec<NoteRef> {
    let mut seen = std::collections::HashSet::new();
    refs.iter()
        .filter(|reference| seen.insert((reference.kind, reference.target.clone())))
        .cloned()
        .collect()
}

fn check(text: &str, refs: &[NoteRef]) -> Result<String, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("the note is empty".into());
    }
    if text.chars().count() > MAX_NOTE {
        return Err(format!("a note holds at most {MAX_NOTE} characters"));
    }
    if text
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err("the note has control characters".into());
    }
    if refs.len() > MAX_REFS {
        return Err(format!("a note names at most {MAX_REFS} references"));
    }
    for reference in refs {
        if reference.target.is_empty()
            || reference.target.len() > 600
            || reference.label.len() > 400
            || reference.target.chars().any(char::is_control)
            || reference.label.chars().any(char::is_control)
        {
            return Err("a reference is empty, too long or has control characters".into());
        }
    }
    Ok(text.to_owned())
}

fn labels(refs: &[NoteRef]) -> String {
    refs.iter()
        .map(|reference| reference.label.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

impl Library {
    /// The notes of a sample, newest first.
    pub fn notes(&self, sha256: &str) -> Result<Vec<Note>, String> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, sha256, body, by, created_ms, edited_ms FROM note
                 WHERE sha256=?1 ORDER BY created_ms DESC, id DESC",
            )
            .map_err(|e| e.to_string())?;
        let mut notes: Vec<Note> = statement
            .query_map([sha256.to_ascii_lowercase()], |row| {
                Ok(Note {
                    id: row.get(0)?,
                    sha256: row.get(1)?,
                    text: row.get(2)?,
                    by: row.get(3)?,
                    created_ms: row.get::<_, i64>(4)? as u64,
                    edited_ms: row.get::<_, Option<i64>>(5)?.map(|ms| ms as u64),
                    refs: Vec::new(),
                })
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?;
        for note in &mut notes {
            note.refs = self.note_refs(note.id)?;
        }
        Ok(notes)
    }

    fn note_refs(&self, id: i64) -> Result<Vec<NoteRef>, String> {
        let mut statement = self
            .connection
            .prepare("SELECT kind, target, label FROM note_ref WHERE note_id=?1 ORDER BY ord")
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        // A kind this build does not know (a newer one) is left out.
        Ok(rows
            .into_iter()
            .filter_map(|(kind, target, label)| {
                Some(NoteRef::new(RefKind::parse(&kind)?, target, label))
            })
            .collect())
    }

    fn write_refs(
        transaction: &rusqlite::Transaction<'_>,
        id: i64,
        refs: &[NoteRef],
    ) -> Result<(), String> {
        transaction
            .execute("DELETE FROM note_ref WHERE note_id=?1", [id])
            .map_err(|e| e.to_string())?;
        for (order, reference) in refs.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO note_ref(note_id, ord, kind, target, label) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        id,
                        order as i64,
                        reference.kind.as_str(),
                        reference.target,
                        reference.label
                    ],
                )
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Add a note to a sample; returns its number. The custody log gets an
    /// entry with the text's hash and the references' labels.
    pub fn add_note(&mut self, sha256: &str, text: &str, refs: &[NoteRef]) -> Result<i64, String> {
        let sha256 = sha256.to_ascii_lowercase();
        let text = check(text, refs)?;
        let refs = &once(refs)[..];
        if !self.contains(&sha256)? {
            return Err("no such sample".into());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        transaction
            .execute(
                "INSERT INTO note(sha256, body, by, created_ms) VALUES (?1, ?2, 'analyst', ?3)",
                params![sha256, text, now_ms() as i64],
            )
            .map_err(|e| e.to_string())?;
        let id = transaction.last_insert_rowid();
        Self::write_refs(&transaction, id, refs)?;
        transaction.commit().map_err(|e| e.to_string())?;
        self.note(
            &sha256,
            "analyst",
            CustodyEvent::NoteAdded {
                note: id as u64,
                hash: text_hash(&text),
                refs: labels(refs),
            },
        )?;
        Ok(id)
    }

    /// Replace a note's text and references.
    pub fn edit_note(&mut self, id: i64, text: &str, refs: &[NoteRef]) -> Result<(), String> {
        let text = check(text, refs)?;
        let refs = &once(refs)[..];
        let sha256: String = self
            .connection
            .query_row("SELECT sha256 FROM note WHERE id=?1", [id], |row| {
                row.get(0)
            })
            .map_err(|_| "no such note".to_owned())?;
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        transaction
            .execute(
                "UPDATE note SET body=?2, edited_ms=?3 WHERE id=?1",
                params![id, text, now_ms() as i64],
            )
            .map_err(|e| e.to_string())?;
        Self::write_refs(&transaction, id, refs)?;
        transaction.commit().map_err(|e| e.to_string())?;
        self.note(
            &sha256,
            "analyst",
            CustodyEvent::NoteEdited {
                note: id as u64,
                hash: text_hash(&text),
                refs: labels(refs),
            },
        )
    }

    /// Delete a note. The custody log keeps the entries about it.
    pub fn delete_note(&mut self, id: i64) -> Result<(), String> {
        let (sha256, text): (String, String) = self
            .connection
            .query_row("SELECT sha256, body FROM note WHERE id=?1", [id], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .map_err(|_| "no such note".to_owned())?;
        let refs = labels(&self.note_refs(id)?);
        self.connection
            .execute("DELETE FROM note WHERE id=?1", [id])
            .map_err(|e| e.to_string())?;
        self.note(
            &sha256,
            "analyst",
            CustodyEvent::NoteDeleted {
                note: id as u64,
                hash: text_hash(&text),
                refs,
            },
        )
    }
}
