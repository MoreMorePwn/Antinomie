//! Large exec-style events use the aggregate field budget without rejecting
//! valid object identities or losing bytes from the derived object store.
use super::{tests::packet, *};

fn fields(count: u32) -> Vec<Vec<u8>> {
    let mut packets = vec![packet(1, 0, 0, &[0; 120], 1)];
    for object in 1..=count {
        let mut begin = [0; 40];
        begin[..3].copy_from_slice(&[1, 1, 1]);
        begin[4] = 1;
        let mut end = [0; 32];
        end[..8].copy_from_slice(&4u64.to_le_bytes());
        end[8..16].copy_from_slice(&4u64.to_le_bytes());
        end[24..32].copy_from_slice(&1u64.to_le_bytes());
        let sequence = u64::from(object) * 3 - 1;
        packets.push(packet(2, object, 0, &begin, sequence));
        packets.push(packet(3, object, 0, &object.to_le_bytes(), sequence + 1));
        packets.push(packet(4, object, 0, &end, sequence + 2));
    }
    let mut end = [0; 32];
    let packet_count = u64::from(count) * 3 + 2;
    end[..8].copy_from_slice(&u64::from(count).to_le_bytes());
    end[8..16].copy_from_slice(&packet_count.to_le_bytes());
    packets.push(packet(5, 0, 0, &end, packet_count));
    packets
}

#[test]
fn large_exec_event_is_complete_and_replays_all_stored_objects() {
    let directory =
        std::env::temp_dir().join(format!("ant-large-fields-{}", crate::storage::unique_id()));
    let packets = fields(1025);
    let objects = directory.join("objects");
    let mut live = Assembler::new(objects.clone(), 2 * 1024 * 1024).unwrap();
    for packet in &packets {
        live.ingest(packet).unwrap();
    }
    live.pack.as_mut().unwrap().sync().unwrap();
    let live_event = &live.history()[0];
    assert!(live_event.complete, "{:?}", live_event.issues);
    assert_eq!(live_event.fields.len(), 1025);
    assert_eq!(live.field_count, 1025);
    assert_eq!(live.evicted_count, 0);

    let mut replay = Assembler::open_archive(objects).unwrap();
    for packet in &packets {
        replay.ingest(packet).unwrap();
    }
    let event = &replay.history()[0];
    assert!(event.complete, "{:?}", event.issues);
    assert_eq!(event.fields.len(), 1025);
    for field in &event.fields {
        assert!(field.complete);
        assert_eq!(field.arg, Some(1));
        assert_eq!(field.preview, field.object_id.to_le_bytes());
        assert_eq!(
            crate::recording::read_captured_range(&directory, field, 0, 4).unwrap(),
            field.object_id.to_le_bytes()
        );
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn a_large_event_still_obeys_the_aggregate_state_budget() {
    let directory =
        std::env::temp_dir().join(format!("ant-field-budget-{}", crate::storage::unique_id()));
    let mut assembler = Assembler::new(directory.clone(), 1024 * 1024).unwrap();
    assembler.capacity = 16;
    for packet in fields(40) {
        assembler.ingest(&packet).unwrap();
        assert!(assembler.field_count <= assembler.capacity * 2);
    }
    assert!(assembler.evicted_count > 0);
    assert!(assembler.history().iter().all(|event| !event.complete));
    assert!(assembler.history().iter().any(|event| {
        event
            .issues
            .iter()
            .any(|issue| issue.contains("retention eviction"))
    }));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn field_descriptors_name_their_argument_or_none() {
    let directory =
        std::env::temp_dir().join(format!("ant-field-arg-{}", crate::storage::unique_id()));
    let mut assembler = Assembler::new(directory.clone(), 1024 * 1024).unwrap();
    for (object, arg) in [(1u32, 3u8), (2, 255)] {
        let mut begin = [0; 40];
        begin[..3].copy_from_slice(&[arg, 1, 1]);
        begin[4] = 1;
        assembler
            .ingest(&packet(2, object, 0, &begin, u64::from(object)))
            .unwrap();
    }
    let event = &assembler.recent(1)[0];
    let args: Vec<_> = event.fields.iter().map(|field| field.arg).collect();
    assert_eq!(args, [Some(3), None]);
    std::fs::remove_dir_all(directory).unwrap();
}
