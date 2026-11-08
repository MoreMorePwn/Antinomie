// SPDX-License-Identifier: GPL-3.0-only
//! A data folder that moved keeps its bases and VMs (ANT-T0416).
use super::*;
use crate::api::VmConfig;
use crate::storage::{create_overlay, private_dir, unique_id};

fn qemu_img(args: &[&str], file: &Path) -> std::process::Output {
    Command::new("qemu-img")
        .args(args)
        .arg(file)
        .output()
        .unwrap()
}

/// A data folder with one installed base and one VM on it.
fn data_folder(root: &Path) -> (BackendOptions, Bundle) {
    let options = BackendOptions {
        data_dir: root.join("data"),
        bundle_dir: root.join("missing-build"),
        ..BackendOptions::default()
    };
    private_dir(&options.data_dir).unwrap();
    let source = root.join("source");
    private_dir(&source).unwrap();
    fs::write(source.join("kernel"), b"kernel fixture").unwrap();
    let status = Command::new("qemu-img")
        .args(["create", "-f", "qcow2"])
        .arg(source.join("base.qcow2"))
        .arg("1M")
        .output()
        .unwrap()
        .status;
    assert!(status.success());
    let bundle = Bundle {
        arch: Default::default(),
        kernel: source.join("kernel"),
        base_disk: source.join("base.qcow2"),
        initrd: None,
        kernel_append: String::new(),
        kernel_version: "6.12.94".into(),
        schema_id: 1,
        base_identity: None,
        guest: None,
        fixed_display: true,
        build_provenance: None,
        antinomie_revision: None,
        antinomie_source: None,
        built_with: None,
        min_app_version: None,
        name: None,
        symbols: None,
        stealth_support: Vec::new(),
        uefi: Default::default(),
    }
    .install(&options)
    .unwrap();
    fs::remove_dir_all(source).unwrap();
    let dir = options.data_dir.join("vm1");
    private_dir(&dir).unwrap();
    let vm = VmConfig {
        id: "vm1".into(),
        base_identity: bundle.base_identity.clone(),
        ..VmConfig::default()
    };
    storage::atomic_json(&dir.join("config.json"), &vm).unwrap();
    create_overlay(&options, &dir, 1, &bundle).unwrap();
    let location = crate::locations::locations(&options, "vm1").unwrap();
    crate::locations::publish(&options, &location).unwrap();
    (options, bundle)
}

fn backing_of(disk: &Path) -> PathBuf {
    crate::disk_start::backing_file(disk).unwrap().unwrap()
}

#[test]
fn a_moved_data_folder_keeps_its_base_and_its_vm() {
    let root = std::env::temp_dir().join(format!("ant-moved-{}", unique_id()));
    fs::create_dir_all(&root).unwrap();
    let (old, bundle) = data_folder(&root);
    let id = bundle.base_identity.clone().unwrap();
    // The new bundle.json holds relative names; the VM's copy and its disk
    // still name the old folder.
    let recorded =
        fs::read_to_string(old.data_dir.join("bases").join(&id).join("bundle.json")).unwrap();
    assert!(!recorded.contains(root.to_str().unwrap()), "{recorded}");
    let vm_copy = fs::read_to_string(old.data_dir.join("vm1/bundle.json")).unwrap();
    assert!(vm_copy.contains(root.to_str().unwrap()));
    let moved_root = std::env::temp_dir().join(format!("ant-moved-to-{}", unique_id()));
    fs::rename(&root, &moved_root).unwrap();
    let options = BackendOptions {
        data_dir: moved_root.join("data"),
        ..old.clone()
    };
    // The base lists from its new place with no repair.
    let (bases, problems) = crate::locations::installed_bases_checked(&options).unwrap();
    assert_eq!((bases.len(), problems.len()), (1, 0));
    // The VM does not work yet: its disk names a base that is gone.
    assert!(
        !qemu_img(
            &["info", "--backing-chain"],
            &options.data_dir.join("vm1/disk.qcow2")
        )
        .status
        .success()
    );
    let problems = repair(&options);
    assert!(problems.is_empty(), "{problems:?}");
    let base_disk = options.data_dir.join("bases").join(&id).join("base.qcow2");
    assert_eq!(
        backing_of(&options.data_dir.join("vm1/disk.qcow2")),
        base_disk
    );
    assert!(
        qemu_img(
            &["info", "--backing-chain"],
            &options.data_dir.join("vm1/disk.qcow2")
        )
        .status
        .success()
    );
    let copy: Bundle = storage::read_json(&options.data_dir.join("vm1/bundle.json")).unwrap();
    assert_eq!(
        copy.kernel,
        options.data_dir.join("bases").join(&id).join("kernel")
    );
    assert_eq!(copy.base_disk, base_disk);
    copy.verify_installed().unwrap();
    storage::validate_disk_chain(
        &options,
        &options.data_dir.join("vm1/disk.qcow2"),
        Some(&copy.base_disk),
    )
    .unwrap();
    // The registry names this folder now, on disk too.
    let location = crate::locations::locations(&options, "vm1").unwrap();
    assert_eq!(location.disk_directory, options.data_dir.join("vm1"));
    assert_eq!(
        location.recording_directories,
        vec![options.data_dir.join("vm1")]
    );
    let registry = fs::read_to_string(options.data_dir.join("vm-locations.json")).unwrap();
    assert!(
        registry.contains(moved_root.to_str().unwrap()),
        "{registry}"
    );
    assert!(!registry.contains(root.to_str().unwrap()), "{registry}");
    // A second run finds nothing to do.
    assert!(repair(&options).is_empty());
    let _ = fs::remove_dir_all(&moved_root);
}

#[test]
fn a_vm_whose_base_file_is_gone_is_reported_not_guessed() {
    let root = std::env::temp_dir().join(format!("ant-moved-gone-{}", unique_id()));
    fs::create_dir_all(&root).unwrap();
    let (old, bundle) = data_folder(&root);
    let id = bundle.base_identity.clone().unwrap();
    let moved_root = std::env::temp_dir().join(format!("ant-moved-gone-to-{}", unique_id()));
    fs::rename(&root, &moved_root).unwrap();
    let options = BackendOptions {
        data_dir: moved_root.join("data"),
        ..old
    };
    fs::remove_file(options.data_dir.join("bases").join(&id).join("base.qcow2")).unwrap();
    let problems = repair(&options);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("does not exist"), "{problems:?}");
    let _ = fs::remove_dir_all(&moved_root);
}

#[test]
fn a_base_that_cannot_load_is_listed_with_its_reason_and_hides_no_other() {
    let root = std::env::temp_dir().join(format!("ant-base-problem-{}", unique_id()));
    fs::create_dir_all(&root).unwrap();
    let (options, bundle) = data_folder(&root);
    let id = bundle.base_identity.clone().unwrap();
    let good = options.data_dir.join("bases").join(&id);
    let broken = options.data_dir.join("bases").join("broken");
    fs::create_dir_all(&broken).unwrap();
    fs::copy(good.join("bundle.json"), broken.join("bundle.json")).unwrap();
    let (bases, problems) = crate::locations::installed_bases_checked(&options).unwrap();
    assert_eq!(bases.len(), 1);
    assert_eq!(bases[0].id, id);
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].directory, broken);
    assert!(
        problems[0].reason.contains("not found in the bundle"),
        "{problems:?}"
    );
    // The plain listing the boot path uses still gives the usable base.
    assert_eq!(
        crate::locations::installed_bases(&options).unwrap().len(),
        1
    );
    let _ = fs::remove_dir_all(&root);
}
