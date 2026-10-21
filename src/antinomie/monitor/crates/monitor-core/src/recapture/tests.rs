// SPDX-License-Identifier: MIT
use crate::api::{Recapture, pair_events};
use crate::parser::Assembler;

/// Packets of one event, numbered from `seq`, as the guest recorder sends them.
struct Event {
    phase: u8,
    seq: u64,
    packets: Vec<Vec<u8>>,
    objects: u32,
}

impl Event {
    fn new(phase: u8, seq: u64, result: Option<i64>) -> Self {
        let mut begin = vec![0; 120];
        begin[48] = 3;
        if let Some(result) = result {
            begin[49] = 1;
            begin[56..64].copy_from_slice(&result.to_le_bytes());
        }
        let mut event = Self {
            phase,
            seq,
            packets: Vec::new(),
            objects: 0,
        };
        event.push(1, 0, 0, &begin);
        event
    }
    fn push(&mut self, fragment: u8, id: u32, offset: u64, body: &[u8]) {
        let mut p = vec![0; 128];
        p[..4].copy_from_slice(b"ANTT");
        p[4..6].copy_from_slice(&1u16.to_le_bytes());
        p[8..10].copy_from_slice(&128u16.to_le_bytes());
        p[10..12].copy_from_slice(&1u16.to_le_bytes());
        p[12..16].copy_from_slice(&(128u32 + body.len() as u32).to_le_bytes());
        p[20..24].copy_from_slice(&1u32.to_le_bytes());
        p[24..32].copy_from_slice(&7u64.to_le_bytes());
        p[32..40].copy_from_slice(&9u64.to_le_bytes());
        p[40..48].copy_from_slice(&3u64.to_le_bytes());
        p[48..56].copy_from_slice(&u64::from(self.phase).to_le_bytes());
        let seq = self.seq + self.packets.len() as u64;
        p[56..64].copy_from_slice(&seq.to_le_bytes());
        p[72..76].copy_from_slice(&40u32.to_le_bytes());
        p[76..80].copy_from_slice(&40u32.to_le_bytes());
        p[88..96].copy_from_slice(&59u64.to_le_bytes());
        p[96..98].copy_from_slice(&1u16.to_le_bytes());
        p[98] = self.phase;
        p[99] = fragment;
        p[100..104].copy_from_slice(&id.to_le_bytes());
        p[104..112].copy_from_slice(&offset.to_le_bytes());
        p[112..120].copy_from_slice(&u64::MAX.to_le_bytes());
        p[120..124].copy_from_slice(&(body.len() as u32).to_le_bytes());
        p.extend(body);
        self.packets.push(p);
    }
    /// A string field: its bytes, or none with `status`.
    fn field(&mut self, key: &str, flags: u32, data: Option<&[u8]>, status: u32) {
        self.objects += 1;
        let id = self.objects;
        let mut begin = vec![0; 40];
        begin[0] = 0;
        begin[1] = 1;
        begin[2..4].copy_from_slice(&2u16.to_le_bytes());
        begin[4..6].copy_from_slice(&u16::from(self.phase).to_le_bytes());
        begin[32..34].copy_from_slice(&(key.len() as u16).to_le_bytes());
        begin[36..40].copy_from_slice(&(flags | 2).to_le_bytes());
        begin.extend(key.as_bytes());
        self.push(2, id, 0, &begin);
        let mut end = vec![0; 32];
        if let Some(data) = data {
            self.push(3, id, 0, data);
            end[0..8].copy_from_slice(&(data.len() as u64).to_le_bytes());
            end[8..16].copy_from_slice(&(data.len() as u64).to_le_bytes());
            end[24..32].copy_from_slice(&1u64.to_le_bytes());
        } else {
            end[0..8].copy_from_slice(&u64::MAX.to_le_bytes());
        }
        end[16..20].copy_from_slice(&status.to_le_bytes());
        self.push(4, id, 0, &end);
    }
    fn end(mut self, flags_incomplete: bool) -> Vec<Vec<u8>> {
        let mut end = vec![0; 32];
        end[0..8].copy_from_slice(&u64::from(self.objects).to_le_bytes());
        end[8..16].copy_from_slice(&(self.packets.len() as u64 + 1).to_le_bytes());
        if flags_incomplete {
            end[24..32].copy_from_slice(&1u64.to_le_bytes());
        }
        self.push(5, 0, 0, &end);
        if flags_incomplete {
            for packet in &mut self.packets {
                packet[16] |= 1;
            }
        }
        self.packets
    }
}

fn pair(packets: impl IntoIterator<Item = Vec<u8>>) -> crate::api::InvocationSummary {
    let directory =
        std::env::temp_dir().join(format!("ant-recapture-{}", crate::storage::unique_id()));
    let mut assembler = Assembler::new(directory.clone(), 1 << 20).unwrap();
    for packet in packets {
        assembler.ingest(&packet).unwrap();
    }
    let mut rows = pair_events(&assembler.history());
    std::fs::remove_dir_all(directory).ok();
    assert_eq!(rows.len(), 1);
    rows.remove(0)
}

#[test]
fn a_field_recaptured_at_exit_replaces_the_not_resident_entry_field() {
    let mut entry = Event::new(1, 1, None);
    entry.field("arg0.path", 0, None, 12);
    let mut exit = Event::new(2, 100, Some(-2));
    exit.field("arg0.path", Recapture::FLAG, Some(b"/tmp/.x\0"), 0);
    let row = pair(entry.end(true).into_iter().chain(exit.end(false)));
    let entry = row.entry.unwrap();
    assert!(entry.complete, "{:?}", entry.issues);
    assert_eq!(entry.fields.len(), 1);
    let field = &entry.fields[0];
    assert_eq!(field.object_id, 1);
    assert_eq!(field.status, Some(0));
    assert!(field.complete);
    assert_eq!(field.recapture, Some(Recapture::AtExit));
    assert_eq!(field.preview, b"/tmp/.x\0");
    let exit = row.exit.unwrap();
    assert!(exit.fields.is_empty() && exit.complete);
}

#[test]
fn kernel_copies_and_strings_the_entry_never_reached_are_added() {
    let mut entry = Event::new(1, 1, None);
    entry.field("arg0.path", 0, None, 12);
    entry.field("arg1.string[0]", 0, Some(b"sh\0"), 0);
    entry.field("arg1.string[1]", 0, None, 12);
    let mut exit = Event::new(2, 100, Some(0));
    let copy = Recapture::FLAG | Recapture::KERNEL_COPY_FLAG;
    exit.field("arg0.path", copy, Some(b"/bin/sh\0"), 0);
    exit.field("arg1.string[1]", copy, Some(b"-c\0"), 0);
    exit.field("arg1.string[2]", copy, Some(b"id\0"), 0);
    let row = pair(entry.end(true).into_iter().chain(exit.end(false)));
    let entry = row.entry.unwrap();
    assert!(entry.complete, "{:?}", entry.issues);
    let keys: Vec<_> = entry
        .fields
        .iter()
        .map(|field| (field.object_id, field.key.as_str(), field.recapture))
        .collect();
    assert_eq!(
        keys,
        [
            (1, "arg0.path", Some(Recapture::KernelCopy)),
            (2, "arg1.string[0]", None),
            (3, "arg1.string[1]", Some(Recapture::KernelCopy)),
            (4, "arg1.string[2]", Some(Recapture::KernelCopy)),
        ]
    );
}

#[test]
fn other_entry_gaps_keep_the_call_incomplete_and_unmarked_exit_fields_stay() {
    let mut entry = Event::new(1, 1, None);
    entry.field("arg0.path", 0, None, 12);
    entry.field("arg1.ptr[0]", 0, None, 12);
    entry.field("arg2.data", 0, Some(b"ok"), 0);
    let mut exit = Event::new(2, 100, Some(0));
    exit.field("arg2.data", 0, Some(b"out"), 0);
    exit.field("arg0.path", Recapture::FLAG, Some(b"/x\0"), 0);
    // The Entry captured this key itself; the recapture is not moved.
    exit.field("arg2.data", Recapture::FLAG, Some(b"again"), 0);
    let row = pair(entry.end(true).into_iter().chain(exit.end(false)));
    let entry = row.entry.unwrap();
    assert!(!entry.complete);
    assert_eq!(
        entry.issues,
        ["object 2 capture incomplete, status NOT_RESIDENT"]
    );
    assert_eq!(entry.fields[0].recapture, Some(Recapture::AtExit));
    let exit = row.exit.unwrap();
    let left: Vec<_> = exit
        .fields
        .iter()
        .map(|field| (field.key.as_str(), field.recapture))
        .collect();
    assert_eq!(
        left,
        [("arg2.data", None), ("arg2.data", Some(Recapture::AtExit))]
    );
}

#[test]
fn an_old_guest_without_marks_pairs_as_before() {
    let mut entry = Event::new(1, 1, None);
    entry.field("arg0.path", 0, None, 12);
    let exit = Event::new(2, 100, Some(0));
    let row = pair(entry.end(true).into_iter().chain(exit.end(false)));
    let entry = row.entry.unwrap();
    assert!(!entry.complete);
    assert_eq!(entry.fields[0].status, Some(12));
    assert_eq!(entry.fields[0].recapture, None);
}

#[test]
fn flags_name_the_mark() {
    assert_eq!(Recapture::from_flags(2), None);
    assert_eq!(Recapture::from_flags(2 | 8), Some(Recapture::AtExit));
    assert_eq!(Recapture::from_flags(8 | 16), Some(Recapture::KernelCopy));
    // A kernel-copy bit without the recapture bit is not a mark.
    assert_eq!(Recapture::from_flags(16), None);
}
