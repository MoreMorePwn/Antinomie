// SPDX-License-Identifier: GPL-3.0-only
use super::upx::detect;
use super::*;
use std::os::unix::fs::PermissionsExt;

const L_INFO: usize = 0xe8;

/// A file shaped like a UPX-packed x86-64 ELF: three program headers, UPX's
/// loader header right after them, filler for the compressed data, and the
/// pack header and overlay offset at the end.
fn packed(seed: u8, filler: usize) -> Vec<u8> {
    let mut file = vec![0u8; L_INFO];
    file[..4].copy_from_slice(b"\x7fELF");
    file[4] = 2;
    file[5] = 1;
    file[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
    file[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
    file[0x38..0x3a].copy_from_slice(&3u16.to_le_bytes());
    // l_info: checksum, magic, size, version, format.
    file.extend_from_slice(&[seed, 1, 2, 3]);
    file.extend_from_slice(b"UPX!");
    file.extend_from_slice(&[0x14, 0x0b, 14, 22]);
    file.extend((0..filler).map(|n| (n as u8).wrapping_mul(7).wrapping_add(seed)));
    let header = file.len() + 8;
    file.extend_from_slice(b"\0\0\0\0UPX!");
    file.extend_from_slice(&[0; 4]);
    // The pack header: magic, version, format, method, level, adlers, sizes.
    file.extend_from_slice(b"UPX!");
    file.extend_from_slice(&[14, 22, 8, 9]);
    file.extend_from_slice(&[1; 8]);
    file.extend_from_slice(&(1_000_000u32).to_le_bytes());
    file.extend_from_slice(&(header as u32).to_le_bytes());
    file.extend_from_slice(&(1_000_000u32).to_le_bytes());
    file.extend_from_slice(&[0x49, 0x13, 0, 0xb0]);
    file.extend_from_slice(&[0; 4]);
    file
}

fn header_of(file: &[u8]) -> usize {
    file.len() - TRAILER_SIZE
}
const TRAILER_SIZE: usize = 36;

/// A program that is not packed: an ELF with program headers and nothing else.
fn plain(seed: u8) -> Vec<u8> {
    let mut file = packed(seed, 64);
    file.truncate(L_INFO + 12 + 64);
    file[L_INFO + 4..L_INFO + 8].copy_from_slice(b"ELF.");
    file
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("ant-unpack-{name}-{}", crate::storage::unique_id()));
    std::fs::create_dir_all(dir.join("artifacts")).unwrap();
    dir
}

/// A stand-in for `upx -d -q -o OUT IN`: it refuses a file with fewer than
/// three `UPX!` markers (as UPX refuses a file whose magic was overwritten)
/// and otherwise writes the next of the files `payload-1.bin`, `payload-2.bin`.
fn fake_upx(dir: &Path) -> String {
    let path = dir.join("upx");
    std::fs::write(
        &path,
        r#"#!/bin/sh
case "$1" in --version) echo "upx 9.9.9-fake"; exit 0;; esac
D=$(dirname "$0")
OUT="$4"; IN="$5"
n=$(grep -a -o 'UPX!' "$IN" | wc -l)
if [ "$n" -lt 3 ]; then echo "upx: $IN: NotPackedException: not packed by UPX" >&2; exit 2; fi
step=$(cat "$D/step" 2>/dev/null || echo 0); step=$((step+1)); echo $step > "$D/step"
[ -f "$D/payload-$step.bin" ] || cp "$D/payload-last.bin" "$D/payload-$step.bin"
cat "$D/payload-$step.bin" > "$OUT"
"#,
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path.display().to_string()
}

fn run(specimen: &[u8], payloads: &[&[u8]], tool: bool) -> (AnalysisSection, std::path::PathBuf) {
    let dir = scratch("run");
    let upx = fake_upx(&dir);
    for (number, payload) in payloads.iter().enumerate() {
        std::fs::write(dir.join(format!("payload-{}.bin", number + 1)), payload).unwrap();
    }
    if let Some(last) = payloads.last() {
        std::fs::write(dir.join("payload-last.bin"), last).unwrap();
    }
    let mut section = AnalysisSection::new(AnalysisKind::Unpacking);
    unpack_with(
        &mut section,
        specimen,
        &dir.join("artifacts"),
        tool.then_some(upx.as_str()),
    );
    (section, dir)
}

fn report_of(section: AnalysisSection) -> AnalysisReport {
    AnalysisReport {
        id: "r".into(),
        state: AnalysisState::Complete,
        source_path: "/bin/sample".into(),
        specimen_sha256: None,
        specimen_len: None,
        reason: None,
        sections: vec![section],
        layer: None,
        specimen_source: None,
    }
}

#[test]
fn a_file_upx_wrote_is_found_a_changed_one_says_what_changed() {
    let file = packed(1, 500);
    let found = detect(&file).unwrap();
    assert!(found.changes.is_empty());
    assert_eq!(found.label(), "UPX");
    assert_eq!(
        found.layout,
        Some(upx::Layout {
            l_info: L_INFO,
            header: header_of(&file)
        })
    );
    // Magic overwritten in the loader header, in the pack header, and data appended.
    let mut changed = file.clone();
    changed[L_INFO + 4..L_INFO + 8].copy_from_slice(b"XXXX");
    let header = header_of(&file);
    changed[header..header + 4].copy_from_slice(b"\0\0\0\0");
    changed.extend_from_slice(b"appended payload bytes");
    let found = detect(&changed).unwrap();
    assert_eq!(found.label(), "UPX (header modified)");
    assert_eq!(found.changes.len(), 3, "{:?}", found.changes);
    assert!(found.changes[2].starts_with("22 octets follow"));
    // Mending gives back the file UPX wrote.
    assert_eq!(upx::repaired(&changed, found.layout.unwrap()), file);
    // Files that are not packed.
    assert!(detect(&plain(1)).is_none());
    assert!(detect(b"UPX! in a text file, and UPX! again, UPX!").is_none());
    assert!(detect(b"").is_none());
    let mut pe = b"MZ".to_vec();
    pe.extend_from_slice(&[0; 300]);
    pe.extend_from_slice(b"UPX0\0\0\0\0UPX1");
    assert!(detect(&pe).is_some_and(|found| found.layout.is_none()));
}

#[test]
fn a_packed_file_becomes_two_phases_with_hashes_and_a_layer_file_that_is_not_a_program() {
    let original = packed(1, 400);
    let inner = plain(9);
    let (section, dir) = run(&original, &[&inner], true);
    assert_eq!(section.state, AnalysisSectionState::Complete);
    assert_eq!(section.tools, ["upx 9.9.9-fake"]);
    assert_eq!(
        section.summary,
        "Packed with UPX: 1 layer recovered, each one analysed on its own"
    );
    let report = report_of(section);
    let layers = unpack_layers(&report);
    assert_eq!(layers.len(), 2);
    assert_eq!(layers[0].method, "original");
    assert_eq!(layers[0].packer.as_deref(), Some("UPX"));
    assert_eq!(layers[0].sha256, sha256(&original));
    assert_eq!(
        (layers[1].method.as_str(), layers[1].parent),
        ("UPX", Some(0))
    );
    assert_eq!(layers[1].sha256, sha256(&inner));
    assert_eq!(layers[1].size, inner.len() as u64);
    assert_eq!(layers[1].packer, None);
    assert_eq!(layers[1].file.as_deref(), Some("layer-1.bin"));
    let kept = dir.join("artifacts/unpack/layer-1.bin");
    assert_eq!(std::fs::read(&kept).unwrap(), inner);
    let mode = std::fs::metadata(&kept).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "a layer is data, never executable");
    // The copies made for UPX are gone; the manifest repeats the report.
    let names: Vec<_> = std::fs::read_dir(dir.join("artifacts/unpack"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        {
            let mut names = names;
            names.sort();
            names
        },
        ["layer-1.bin", "layers.json"]
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("artifacts/unpack/layers.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["layers"][1]["sha256"], sha256(&inner));
    assert_eq!(
        packer_verdict(&report),
        Some(PackerVerdict {
            packer: "UPX".into(),
            modified: false,
            layers: 1,
            sha256: sha256(&original),
        })
    );
    for entry in &report.sections[0].entries {
        crate::analysis::validation::validate_record(
            AnalysisKind::Unpacking,
            entry,
            entry.record.as_ref().unwrap(),
            Some(original.len() as u64),
        )
        .unwrap();
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_file_with_its_magic_overwritten_is_mended_and_the_layer_says_so() {
    let mut damaged = packed(2, 300);
    damaged[L_INFO + 4..L_INFO + 8].copy_from_slice(b"XXXX");
    let header = header_of(&damaged);
    damaged[header..header + 4].copy_from_slice(b"XXXX");
    damaged[header - 4..header].copy_from_slice(b"XXXX");
    damaged.extend_from_slice(&[0xAA; 100]);
    let inner = plain(3);
    let (section, dir) = run(&damaged, &[&inner], true);
    assert_eq!(section.state, AnalysisSectionState::Complete);
    let report = report_of(section);
    let layers = unpack_layers(&report);
    assert_eq!(layers[0].packer.as_deref(), Some("UPX (header modified)"));
    assert_eq!(layers[1].method, "UPX (header repaired)");
    assert!(
        layers[1]
            .note
            .starts_with("Repaired before unpacking: the magic in the loader header")
    );
    assert!(layers[0].note.contains("100 octets follow the pack header"));
    let verdict = packer_verdict(&report).unwrap();
    assert!(verdict.modified);
    // The specimen the caller holds is untouched: only copies were mended.
    assert_eq!(damaged[L_INFO + 4..L_INFO + 8], *b"XXXX");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_file_packed_twice_is_unpacked_twice_and_a_deeper_chain_is_cut() {
    let outer = packed(1, 200);
    let middle = packed(2, 100);
    let inner = plain(4);
    let (section, dir) = run(&outer, &[&middle, &inner], true);
    let layers = unpack_layers(&report_of(section));
    let chain: Vec<_> = layers
        .iter()
        .map(|l| (l.index, l.parent, l.packer.is_some()))
        .collect();
    assert_eq!(
        chain,
        [(0, None, true), (1, Some(0), true), (2, Some(1), false)]
    );
    let _ = std::fs::remove_dir_all(dir);

    // Layers that are always packed again stop at the limit.
    let deeper: Vec<Vec<u8>> = (5..9)
        .map(|seed| packed(seed, 90 + usize::from(seed)))
        .collect();
    let payloads: Vec<&[u8]> = deeper.iter().map(Vec::as_slice).collect();
    let (section, dir) = run(&outer, &payloads, true);
    assert_eq!(section.state, AnalysisSectionState::Partial);
    assert!(
        section.summary.contains("layers recovered"),
        "{}",
        section.summary
    );
    assert!(section.summary.contains("deep"), "{}", section.summary);
    assert_eq!(
        unpack_layers(&report_of(section)).len(),
        LAYER_MAX_COUNT + 1
    );
    let _ = std::fs::remove_dir_all(dir);

    // An unpacker that gives the same file back would loop for ever.
    let (section, dir) = run(&outer, &[&outer], true);
    assert_eq!(section.state, AnalysisSectionState::Partial);
    assert!(
        section.summary.contains("already seen"),
        "{}",
        section.summary
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn without_the_unpacker_a_packed_file_is_reported_and_a_plain_one_is_not() {
    let (section, dir) = run(&packed(1, 100), &[], false);
    assert_eq!(section.state, AnalysisSectionState::Partial);
    assert!(
        section.summary.contains("install UPX"),
        "{}",
        section.summary
    );
    let layers = unpack_layers(&report_of(section));
    assert_eq!(layers.len(), 1);
    assert_eq!(layers[0].packer.as_deref(), Some("UPX"));
    // Only the manifest: no layer, no copy of the packed file.
    let names: Vec<_> = std::fs::read_dir(dir.join("artifacts/unpack"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["layers.json"]);
    let _ = std::fs::remove_dir_all(dir);

    let (section, dir) = run(&plain(1), &[], true);
    assert_eq!(section.state, AnalysisSectionState::Complete);
    assert!(section.summary.starts_with("No UPX packing found"));
    assert_eq!(packer_verdict(&report_of(section)), None);
    assert!(!dir.join("artifacts/unpack").exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn an_unpacker_that_refuses_or_overflows_leaves_the_file_packed_with_the_reason() {
    let dir = scratch("refuse");
    let upx = fake_upx(&dir);
    let file = packed(1, 100);
    // UPX exits with an error, whatever mending was tried.
    std::fs::write(
        &upx,
        "#!/bin/sh\ncase \"$1\" in --version) echo upx; exit 0;; esac\necho 'upx: CantUnpackException: file corrupted' >&2\nexit 1\n",
    )
    .unwrap();
    let mut section = AnalysisSection::new(AnalysisKind::Unpacking);
    unpack_with(&mut section, &file, &dir.join("artifacts"), Some(&upx));
    assert_eq!(section.state, AnalysisSectionState::Partial);
    assert!(
        section.summary.contains("UPX exited with code 1")
            && section.summary.contains("file corrupted"),
        "{}",
        section.summary
    );
    let layers = unpack_layers(&report_of(section));
    assert_eq!(layers.len(), 1);
    assert!(layers[0].note.contains("file corrupted"));
    let _ = std::fs::remove_dir_all(dir);

    // Output over the size given is refused, and no copy is left behind.
    let dir = scratch("limit");
    let upx = fake_upx(&dir);
    std::fs::write(dir.join("payload-1.bin"), vec![7u8; 4096]).unwrap();
    std::fs::write(dir.join("payload-last.bin"), vec![7u8; 4096]).unwrap();
    let found = detect(&file).unwrap();
    std::fs::create_dir_all(dir.join("work")).unwrap();
    let error = upx::unpack(
        &upx,
        &file,
        &found,
        &dir.join("work"),
        1,
        Duration::from_secs(20),
        1000,
    )
    .err()
    .unwrap();
    assert!(error.contains("4096 octets"), "{error}");
    assert_eq!(std::fs::read_dir(dir.join("work")).unwrap().count(), 0);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn layer_rows_with_another_file_name_or_a_bad_hash_are_rejected() {
    let (section, dir) = run(&packed(1, 100), &[&plain(2)], true);
    let report = report_of(section);
    let entry = report.sections[0].entries[1].clone();
    let check = |change: &dyn Fn(&mut AnalysisData)| {
        let mut entry = entry.clone();
        change(&mut entry.record.as_mut().unwrap().data);
        crate::analysis::validation::validate_record(
            AnalysisKind::Unpacking,
            &entry,
            entry.record.as_ref().unwrap(),
            Some(10_000),
        )
    };
    assert!(check(&|_| {}).is_ok());
    assert!(
        check(&|data| if let AnalysisData::Layer { file, .. } = data {
            *file = Some("../../etc/passwd".into())
        })
        .is_err()
    );
    assert!(
        check(&|data| if let AnalysisData::Layer { file, .. } = data {
            *file = Some("layer-2.bin".into())
        })
        .is_err()
    );
    assert!(
        check(&|data| if let AnalysisData::Layer { sha256, .. } = data {
            *sha256 = "zz".into()
        })
        .is_err()
    );
    assert!(
        check(&|data| if let AnalysisData::Layer { index, .. } = data {
            *index = 9
        })
        .is_err()
    );
    assert!(
        check(&|data| if let AnalysisData::Layer { parent, .. } = data {
            *parent = None
        })
        .is_err()
    );
    assert!(
        check(
            &|data| if let AnalysisData::Layer { report_id, .. } = data {
                *report_id = Some("a/b".into())
            }
        )
        .is_err()
    );
    // Only an Unpacking section may hold them.
    assert!(
        crate::analysis::validation::validate_record(
            AnalysisKind::Strings,
            &entry,
            entry.record.as_ref().unwrap(),
            Some(10_000)
        )
        .is_err()
    );
    let _ = std::fs::remove_dir_all(dir);
}
