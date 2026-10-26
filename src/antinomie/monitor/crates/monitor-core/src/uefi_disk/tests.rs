use super::*;

fn layout_json(removed: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "format": 1,
        "label": "gpt",
        "esp": {"first_sector": 2048, "sectors": 1329152, "fstab_placeholder": "0000-0000"},
        "root": {"first_sector": 1331200, "sectors": 6291456},
        "removed": removed,
        "times": {"usr/lib/grub/x86_64-efi": [[10, 1], [20, 2], [20, 2], [5, 3]]},
    })
}

fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("ant-uefi-{name}-{}", storage::unique_id()));
    storage::private_dir(&root).unwrap();
    root
}

#[test]
fn layout_records_are_checked_before_use() {
    let root = scratch("layout");
    let path = root.join(LAYOUT_FILE);
    fs::write(&path, layout_json(&["usr/lib/grub/i386-pc"]).to_string()).unwrap();
    let layout = read_layout(&path).unwrap();
    assert_eq!(
        layout.esp,
        Extent {
            first_sector: 2048,
            sectors: 1329152
        }
    );
    for bad in [
        "../etc/shadow",
        "/etc/passwd",
        "usr//lib",
        "a\"b",
        "a\nb",
        "",
    ] {
        fs::write(&path, layout_json(&[bad]).to_string()).unwrap();
        assert!(read_layout(&path).is_err(), "{bad:?}");
    }
    let mut overlapping = layout_json(&[]);
    overlapping["root"]["first_sector"] = 4096.into();
    fs::write(&path, overlapping.to_string()).unwrap();
    assert!(read_layout(&path).is_err());
    let mut mbr = layout_json(&[]);
    mbr["label"] = "dos".into();
    fs::write(&path, mbr.to_string()).unwrap();
    assert!(read_layout(&path).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn the_script_lays_out_partman_s_disk_and_applies_the_delta() {
    let root = scratch("script");
    let path = root.join(LAYOUT_FILE);
    fs::write(
        &path,
        layout_json(&["usr/lib/grub/i386-pc/boot.img", "usr/lib/grub/i386-pc"]).to_string(),
    )
    .unwrap();
    let layout = read_layout(&path).unwrap();
    let script = script_text(
        Path::new("/b/base.qcow2"),
        Path::new("/b/.base-uefi.qcow2.partial"),
        Path::new("/b/uefi-root.tar.xz"),
        Path::new("/t/times"),
        &layout,
    )
    .unwrap();
    let position = |text: &str| {
        script
            .find(text)
            .unwrap_or_else(|| panic!("{text}\n{script}"))
    };
    assert!(script.starts_with("add \"/b/base.qcow2\" readonly:true format:qcow2\n"));
    assert!(position("part-init /dev/sdb gpt\n") < position("part-add /dev/sdb p 2048 1331199\n"));
    assert!(
        position("part-add /dev/sdb p 2048 1331199\n")
            < position("part-add /dev/sdb p 1331200 7622655\n")
    );
    assert!(script.contains("part-set-gpt-type /dev/sdb 1 C12A7328-F81F-11D2-BA4B-00A0C93EC93B\n"));
    assert!(
        position("copy-device-to-device /dev/sda1 /dev/sdb2 sparse:true\n")
            < position("mount /dev/sdb2 /\n")
    );
    // Removals (deepest first, as recorded) before the delta.
    assert!(
        position("rm-rf \"/usr/lib/grub/i386-pc/boot.img\"\n")
            < position("rm-rf \"/usr/lib/grub/i386-pc\"\n")
    );
    assert!(
        position("rm-rf \"/usr/lib/grub/i386-pc\"\n")
            < position("tar-in \"/b/uefi-root.tar.xz\" / compress:xz")
    );
    // The times are set with debugfs on the unmounted filesystem.
    assert!(position("umount-all\n") < position("debugfs -w -f /tmp/.times /dev/sdb2"));
    let times = timeline_commands(&layout).unwrap();
    assert!(times.contains("set_inode_field \"/usr/lib/grub/x86_64-efi\" ctime @20\n"));
    assert!(times.contains("set_inode_field \"/usr/lib/grub/x86_64-efi\" mtime_extra 12\n"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn only_a_uefi_profile_on_a_base_with_the_layout_gets_the_disk() {
    let mut bundle: Bundle = serde_json::from_value(serde_json::json!({
        "kernel": "kernel", "base_disk": "/b/base.qcow2", "initrd": null,
        "stealth_support": ["uefi", "sata"],
        "uefi_root": "/b/uefi-root.tar.xz", "uefi_layout": "/b/uefi-layout.json",
    }))
    .unwrap();
    let mut profile = crate::stealth::StealthProfile {
        firmware: crate::stealth::Firmware::Uefi,
        ..Default::default()
    };
    assert!(wanted(&bundle, &profile));
    profile.firmware = crate::stealth::Firmware::UefiSecureBoot;
    assert!(wanted(&bundle, &profile));
    profile.firmware = crate::stealth::Firmware::Bios;
    assert!(!wanted(&bundle, &profile));
    profile.firmware = crate::stealth::Firmware::Uefi;
    bundle.stealth_support.retain(|item| item != "uefi");
    assert!(!wanted(&bundle, &profile));
    bundle.stealth_support.push("uefi".into());
    bundle.uefi.uefi_root = None;
    assert!(!wanted(&bundle, &profile));
    // A VM's record names its derived disk; the backing follows it.
    assert_eq!(bundle.vm_disk(), Path::new("/b/base.qcow2"));
    bundle.uefi.uefi_disk = Some("/b/base-uefi.qcow2".into());
    assert_eq!(bundle.vm_disk(), Path::new("/b/base-uefi.qcow2"));
    assert!(installed_for(&bundle).starts_with("UEFI"));
    let text = serde_json::to_string(&bundle).unwrap();
    assert!(text.contains("\"uefi_disk\":\"/b/base-uefi.qcow2\""));
}

#[test]
fn a_derived_disk_is_reused_only_for_its_base_and_while_unchanged() {
    let root = scratch("record");
    let base = root.join("base.qcow2");
    fs::write(&base, b"base").unwrap();
    let mut bundle: Bundle = serde_json::from_value(serde_json::json!({
        "kernel": "kernel", "base_disk": base, "initrd": null, "base_identity": "a".repeat(64),
    }))
    .unwrap();
    assert_eq!(existing(&bundle).unwrap(), None);
    let disk = root.join(DISK_FILE);
    fs::write(&disk, b"uefi disk").unwrap();
    let (size, mtime_ns, inode) = stamp(&disk).unwrap();
    let record = |identity: &str, sha256: String| Record {
        format: 1,
        recipe: RECIPE,
        base_identity: identity.into(),
        sha256,
        size,
        mtime_ns,
        inode,
    };
    let sha = sha256_hex(&disk).unwrap();
    storage::atomic_json(
        &root.join(RECORD_FILE),
        &record(&"a".repeat(64), sha.clone()),
    )
    .unwrap();
    assert_eq!(existing(&bundle).unwrap(), Some(disk.clone()));
    // Another base's record: laid out again.
    bundle.base_identity = Some("b".repeat(64));
    assert_eq!(existing(&bundle).unwrap(), None);
    bundle.base_identity = Some("a".repeat(64));
    // A changed file is refused rather than used.
    fs::write(&disk, b"other disk").unwrap();
    assert!(existing(&bundle).unwrap_err().contains("differs"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn too_little_room_is_refused_before_anything_is_written() {
    let root = scratch("space");
    let error = require_space(&root, u64::MAX / 2).unwrap_err();
    assert!(
        error.contains("needs about") && error.contains("available"),
        "{error}"
    );
    assert!(require_space(&root, 1).is_ok());
    fs::remove_dir_all(root).unwrap();
}
