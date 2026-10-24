// SPDX-License-Identifier: GPL-3.0-only
use super::*;

const SPECIMEN: &[u8] = b"the packed file";
const LAYER: &[u8] = b"\x7fELF the unpacked layer, a different file";

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn layer_row(index: u32, content: &[u8]) -> AnalysisEntry {
    AnalysisEntry {
        label: format!("Layer {index}"),
        value: "UPX".into(),
        offset: None,
        record: Some(AnalysisRecord {
            revision: 1,
            id: u64::from(index) + 1,
            location: None,
            data: AnalysisData::Layer {
                index,
                method: if index == 0 { "original" } else { "UPX" }.into(),
                sha256: hash(content),
                size: content.len() as u64,
                parent: (index > 0).then(|| index - 1),
                packer: (index == 0).then(|| "UPX".into()),
                file: (index > 0).then(|| format!("layer-{index}.bin")),
                report_id: Some("forged".into()),
                note: String::new(),
            },
        }),
    }
}

/// A finished job whose report has an Unpacking section with one layer, and
/// the folder it ran in.
fn finished(name: &str) -> (Job, PathBuf) {
    let root = std::env::temp_dir().join(format!("ant-layers-{name}-{}", storage::unique_id()));
    let directory = root.join("analysis");
    let folder = directory.join("output/artifacts/unpack");
    fs::create_dir_all(&folder).unwrap();
    fs::write(folder.join("layer-1.bin"), LAYER).unwrap();
    let mut unpacking = AnalysisSection::new(AnalysisKind::Unpacking);
    unpacking.state = AnalysisSectionState::Complete;
    unpacking.entries = vec![layer_row(0, SPECIMEN), layer_row(1, LAYER)];
    let mut strings = AnalysisSection::new(AnalysisKind::Strings);
    strings.state = AnalysisSectionState::Complete;
    let report = AnalysisReport {
        id: "main".into(),
        state: AnalysisState::Complete,
        source_path: "/home/user/sample".into(),
        specimen_sha256: Some(hash(SPECIMEN)),
        specimen_len: Some(SPECIMEN.len() as u64),
        reason: None,
        sections: vec![strings, unpacking],
        layer: None,
        specimen_source: None,
    };
    let job = Job {
        run_id: Some("run-1".into()),
        report,
        directory,
        handle: None,
        total_len: SPECIMEN.len() as u64,
        received_len: SPECIMEN.len() as u64,
        file: None,
        deadline: Instant::now(),
        child: None,
        cleanup_reason: None,
        reserved_len: 0,
        digest: Sha256::new(),
        disk_len: 0,
        worker_len: 0,
        report_len: 0,
        specimen_publication: None,
        progress: Default::default(),
        host_copy: None,
        supplement: None,
    };
    (job, root)
}

fn row_of(job: &Job, index: u32) -> (Option<String>, String) {
    let section = job
        .report
        .sections
        .iter()
        .find(|s| s.kind == AnalysisKind::Unpacking)
        .unwrap();
    match &section.entries[index as usize]
        .record
        .as_ref()
        .unwrap()
        .data
    {
        AnalysisData::Layer {
            report_id, note, ..
        } => (report_id.clone(), note.clone()),
        _ => unreachable!(),
    }
}

#[test]
fn a_layer_is_queued_for_its_own_analysis_beside_the_packed_files_report() {
    let (mut job, root) = finished("queue");
    let mut jobs = Jobs::default();
    jobs.available = u64::MAX;
    jobs.queue_layers(&mut job);
    assert_eq!(jobs.pending_count(), 1);
    let updates = jobs.updates();
    let (run, layer) = &updates[0];
    // Not the run's report: the run keeps the packed file's analysis.
    assert_eq!(*run, None);
    assert_eq!(layer.id, "main-L1");
    assert_eq!(
        layer.layer,
        Some(AnalysisLayer {
            parent_id: "main".into(),
            index: 1,
            method: "UPX".into(),
            parent_sha256: hash(SPECIMEN),
        })
    );
    // The same checks, without unpacking again.
    let kinds: Vec<_> = layer.sections.iter().map(|s| s.kind).collect();
    assert_eq!(kinds, [AnalysisKind::Strings]);
    assert_eq!(layer.source_path, "/home/user/sample");
    let copy = job.directory.join("layers/1/specimen.partial");
    assert_eq!(fs::read(copy).unwrap(), LAYER);
    // Only the host names a layer's report: the worker's value is gone.
    assert_eq!(row_of(&job, 1).0.as_deref(), Some("main-L1"));
    assert_eq!(row_of(&job, 0).0, None);
    // The original stays where it was, and the layer file is untouched.
    let kept = job.directory.join("output/artifacts/unpack/layer-1.bin");
    assert_eq!(fs::read(kept).unwrap(), LAYER);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_layer_file_that_was_swapped_or_linked_is_not_analysed() {
    for case in ["hash", "size", "link", "missing"] {
        let (mut job, root) = finished(case);
        let file = job.directory.join("output/artifacts/unpack/layer-1.bin");
        let outside = root.join("outside-secret");
        fs::write(&outside, LAYER).unwrap();
        match case {
            "hash" => fs::write(&file, b"\x7fELF the unpacked layer, a different fail").unwrap(),
            "size" => fs::write(&file, b"short").unwrap(),
            "link" => {
                fs::remove_file(&file).unwrap();
                std::os::unix::fs::symlink(&outside, &file).unwrap();
            }
            _ => fs::remove_file(&file).unwrap(),
        }
        let mut jobs = Jobs::default();
        jobs.available = u64::MAX;
        jobs.queue_layers(&mut job);
        assert_eq!(jobs.pending_count(), 0, "{case}");
        let (report_id, note) = row_of(&job, 1);
        assert_eq!(report_id, None, "{case}");
        assert!(
            note.starts_with("Not analysed on its own:"),
            "{case}: {note}"
        );
        assert!(!job.directory.join("layers").exists(), "{case}");
        let _ = fs::remove_dir_all(root);
    }
}

#[test]
fn nothing_is_queued_for_a_layer_itself_or_an_unfinished_job_or_without_other_checks() {
    let (mut job, root) = finished("skip");
    let mut jobs = Jobs::default();
    jobs.available = u64::MAX;
    job.report.state = AnalysisState::Cancelled;
    jobs.queue_layers(&mut job);
    job.report.state = AnalysisState::Complete;
    job.report.layer = Some(AnalysisLayer {
        parent_id: "x".into(),
        index: 1,
        method: "UPX".into(),
        parent_sha256: hash(SPECIMEN),
    });
    jobs.queue_layers(&mut job);
    job.report.layer = None;
    job.report.sections.remove(0);
    jobs.queue_layers(&mut job);
    assert_eq!(jobs.pending_count(), 0);
    assert!(row_of(&job, 1).1.contains("no other check was selected"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn analyses_reserve_room_for_the_layers_an_unpacker_may_leave() {
    let (job, root) = finished("reserve");
    assert_eq!(
        extra_reserve(&job.report),
        super::super::super::unpack::TOTAL_MAX_SIZE
    );
    let mut plain = job.report.clone();
    plain.sections.retain(|s| s.kind == AnalysisKind::Strings);
    assert_eq!(extra_reserve(&plain), 0);
    let _ = fs::remove_dir_all(root);
}
