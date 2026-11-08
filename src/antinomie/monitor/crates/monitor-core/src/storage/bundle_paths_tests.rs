// SPDX-License-Identifier: GPL-3.0-only
//! How `Bundle::load` reads the paths a bundle records (ANT-T0416).
use super::*;

fn folder(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("ant-bundle-paths-{tag}-{}", unique_id()));
    private_dir(&root).unwrap();
    fs::write(root.join("kernel"), b"kernel").unwrap();
    fs::write(root.join("base.qcow2"), b"disk").unwrap();
    fs::canonicalize(root).unwrap()
}

fn write(root: &Path, kernel: &str, disk: &str) {
    let manifest = serde_json::json!({
        "kernel": kernel, "base_disk": disk, "kernel_version": "6.12.94",
        "kernel_append": "", "schema_id": 1,
    });
    fs::write(root.join("bundle.json"), manifest.to_string()).unwrap();
}

#[test]
fn a_relative_bundle_loads_from_its_folder() {
    let root = folder("relative");
    write(&root, "kernel", "base.qcow2");
    let bundle = Bundle::load(&root).unwrap();
    assert_eq!(bundle.kernel, root.join("kernel"));
    assert_eq!(bundle.base_disk, root.join("base.qcow2"));
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn an_old_absolute_bundle_moved_to_a_new_root_loads_from_the_new_folder() {
    let root = folder("moved");
    // Recorded by an older build in a folder that no longer exists.
    write(
        &root,
        "/srv/old-data/data/bases/abc/kernel",
        "/srv/old-data/data/bases/abc/base.qcow2",
    );
    let bundle = Bundle::load(&root).unwrap();
    assert_eq!(bundle.kernel, root.join("kernel"));
    assert_eq!(bundle.base_disk, root.join("base.qcow2"));
    // Absolute paths that still point into the folder keep working.
    write(
        &root,
        root.join("kernel").to_str().unwrap(),
        root.join("base.qcow2").to_str().unwrap(),
    );
    assert_eq!(Bundle::load(&root).unwrap().kernel, root.join("kernel"));
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_copy_with_the_old_folder_still_present_uses_its_own_files() {
    let old = folder("old-copy");
    let new = folder("new-copy");
    write(
        &new,
        old.join("kernel").to_str().unwrap(),
        old.join("base.qcow2").to_str().unwrap(),
    );
    let bundle = Bundle::load(&new).unwrap();
    assert_eq!(bundle.kernel, new.join("kernel"));
    assert_eq!(bundle.base_disk, new.join("base.qcow2"));
    fs::remove_dir_all(&old).unwrap();
    fs::remove_dir_all(&new).unwrap();
}

#[test]
fn a_path_that_escapes_the_bundle_folder_is_still_refused() {
    let root = folder("escape");
    let outside = folder("outside");
    fs::write(outside.join("secret"), b"x").unwrap();
    // An existing file elsewhere that the folder does not hold.
    write(
        &root,
        outside.join("secret").to_str().unwrap(),
        "base.qcow2",
    );
    let error = Bundle::load(&root).unwrap_err();
    assert!(error.contains("escapes bundle directory"), "{error}");
    // Parent components, relative or absolute.
    write(&root, "../kernel", "base.qcow2");
    let error = Bundle::load(&root).unwrap_err();
    assert!(error.contains("escapes bundle directory"), "{error}");
    write(&root, "/srv/old-data/../../etc/passwd", "base.qcow2");
    let error = Bundle::load(&root).unwrap_err();
    assert!(error.contains("escapes bundle directory"), "{error}");
    // A link inside the folder that leaves it.
    fs::remove_file(root.join("kernel")).unwrap();
    std::os::unix::fs::symlink(outside.join("secret"), root.join("kernel")).unwrap();
    write(&root, "kernel", "base.qcow2");
    let error = Bundle::load(&root).unwrap_err();
    assert!(error.contains("escapes bundle directory"), "{error}");
    // A name that is not in the folder at all says so.
    write(&root, "/srv/old-data/bases/abc/missing", "base.qcow2");
    let error = Bundle::load(&root).unwrap_err();
    assert!(error.contains("not found in the bundle folder"), "{error}");
    fs::remove_dir_all(&root).unwrap();
    fs::remove_dir_all(&outside).unwrap();
}

#[test]
fn an_install_records_paths_relative_to_the_base_folder() {
    let root = folder("install");
    let source = root.join("source");
    private_dir(&source).unwrap();
    fs::write(source.join("kernel"), b"kernel").unwrap();
    assert!(
        Command::new("qemu-img")
            .args(["create", "-f", "qcow2"])
            .arg(source.join("base.qcow2"))
            .arg("1M")
            .output()
            .unwrap()
            .status
            .success()
    );
    write(&source, "kernel", "base.qcow2");
    let options = BackendOptions {
        data_dir: root.join("data"),
        ..BackendOptions::default()
    };
    private_dir(&options.data_dir).unwrap();
    let installed = Bundle::load(&source).unwrap().install(&options).unwrap();
    let folder = installed.kernel.parent().unwrap().to_path_buf();
    let text = fs::read_to_string(folder.join("bundle.json")).unwrap();
    let recorded: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(recorded["kernel"], "kernel");
    assert_eq!(recorded["base_disk"], "base.qcow2");
    // Loading it resolves them back to the folder.
    assert_eq!(Bundle::load(&folder).unwrap().kernel, installed.kernel);
    fs::remove_dir_all(&root).unwrap();
}
