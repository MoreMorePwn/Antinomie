//! Inputs the guest read again after a call's Entry (contract section 22).
//!
//! A guest from series 0053 on reads an input its Entry recorded NOT_RESIDENT
//! again when the call returns and publishes it in the Exit, marked
//! [`Recapture`]. Pairing moves such a field into the Entry, in place of the
//! NOT_RESIDENT one, so everything that reads a call's inputs (the trace,
//! Triage, filters, rules) sees the value, and the mark says where it came
//! from. The Entry is no longer incomplete for that field.
use crate::api::{FieldSummary, InvocationSummary};

/// Field status of memory that was mapped but not resident (contract 15.1).
const NOT_RESIDENT: u32 = 12;

/// Move the complete recaptured fields of `row`'s Exit into its Entry.
///
/// | Entry field with the same key | Result |
/// | --- | --- |
/// | NOT_RESIDENT | Replaced; it keeps its object id, and its "capture incomplete" issue goes |
/// | None (exec strings after the one the Entry stopped at) | Appended with a new object id |
/// | Any other status | Left alone; the recaptured field stays in the Exit |
///
/// A recaptured field that is not complete stays in the Exit as it was sent.
pub(crate) fn promote(row: &mut InvocationSummary) {
    let (Some(entry), Some(exit)) = (row.entry.as_mut(), row.exit.as_mut()) else {
        return;
    };
    if !exit
        .fields
        .iter()
        .any(|field| field.recapture.is_some() && field.complete)
    {
        return;
    }
    let mut next_id = entry
        .fields
        .iter()
        .map(|field| field.object_id)
        .max()
        .unwrap_or(0);
    let mut kept = Vec::with_capacity(exit.fields.len());
    for field in std::mem::take(&mut exit.fields) {
        if field.recapture.is_none() || !field.complete {
            kept.push(field);
            continue;
        }
        match entry.fields.iter_mut().find(|slot| slot.key == field.key) {
            Some(slot) if slot.status == Some(NOT_RESIDENT) => {
                let issue = format!(
                    "object {} capture incomplete, status NOT_RESIDENT",
                    slot.object_id
                );
                entry.issues.retain(|existing| *existing != issue);
                *slot = FieldSummary {
                    object_id: slot.object_id,
                    arg: slot.arg.or(field.arg),
                    ..field
                };
            }
            Some(_) => kept.push(field),
            None => {
                next_id = next_id.saturating_add(1);
                entry.fields.push(FieldSummary {
                    object_id: next_id,
                    ..field
                });
            }
        }
    }
    exit.fields = kept;
    entry.complete = entry.issues.is_empty();
}

#[cfg(test)]
mod tests;
