// SPDX-License-Identifier: GPL-3.0-only
//! BH-23: the plain copies an earlier Samples > Analyze left are removed.
use super::*;

fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "ant-analysis-input-{name}-{}",
        crate::storage::unique_id()
    ));
    fs::create_dir_all(samples_dir(&root)).unwrap();
    root
}

#[test]
fn bh_23_the_plain_copies_of_analyze_are_removed_and_the_library_kept() {
    let root = scratch("folder");
    let samples = samples_dir(&root);
    let inputs = samples.join("analysis-input");
    fs::create_dir_all(&inputs).unwrap();
    fs::write(inputs.join("0123abcd-sample.elf"), b"\x7fELF plain").unwrap();
    fs::write(samples.join("kept.zip"), b"archive").unwrap();
    assert_eq!(remove_analysis_inputs(&root), Ok(true));
    assert!(!inputs.exists());
    assert!(
        samples.join("kept.zip").is_file(),
        "the library is untouched"
    );
    // Nothing there: nothing to do.
    assert_eq!(remove_analysis_inputs(&root), Ok(false));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn bh_23_a_link_in_place_of_the_folder_is_removed_not_followed() {
    let root = scratch("link");
    let elsewhere = root.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    fs::write(elsewhere.join("keep"), b"x").unwrap();
    std::os::unix::fs::symlink(&elsewhere, samples_dir(&root).join("analysis-input")).unwrap();
    assert_eq!(remove_analysis_inputs(&root), Ok(true));
    assert!(elsewhere.join("keep").is_file());
    assert!(!samples_dir(&root).join("analysis-input").exists());
    let _ = fs::remove_dir_all(root);
}
