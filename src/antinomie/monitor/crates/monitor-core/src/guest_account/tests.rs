// SPDX-License-Identifier: GPL-3.0-only
use super::*;
#[test]
fn tool_deadline_reaps_owned_child_and_preserves_unrelated_process() {
    let root = std::env::temp_dir().join(format!("ant-account-timeout-{}", storage::unique_id()));
    storage::private_dir(&root).unwrap();
    let tool = root.join("hung-tool");
    fs::write(
        &tool,
        "#!/bin/sh\nroot=$(dirname \"$0\")\nprintf '%s\\n' \"$$\" > \"$root/tool-pid\"\ncat >/dev/null\nsleep 60 &\nprintf '%s\\n' \"$!\" > \"$root/descendant-pid\"\nif test \"$1\" = exit-parent; then exit 0; fi\nwait\n",
    )
    .unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
    let mut unrelated = Command::new("sleep").arg("60").spawn().unwrap();
    let secret = "private-timeout-password";
    // The pid of a process the tool started, once it wrote one whole.
    let written = |name: &str| {
        fs::read_to_string(root.join(name))
            .ok()
            .filter(|text| text.ends_with('\n'))
    };
    for (capture_hash, exit_parent) in [(false, false), (true, false), (true, true)] {
        // The deadline is what the tool is made to miss, so it has to be
        // long enough for a loaded host to start the tool and let it
        // start its descendant first. A deadline that fired before then
        // proves nothing about the descendant: the run is repeated with
        // twice the time, up to ten seconds.
        let mut timeout = Duration::from_millis(500);
        let (pid, descendant) = loop {
            for name in ["tool-pid", "descendant-pid"] {
                let _ = fs::remove_file(root.join(name));
            }
            let started = Instant::now();
            let mut command = Command::new(&tool);
            if exit_parent {
                command.arg("exit-parent");
            }
            let error =
                run_private_with_timeout(&mut command, secret.as_bytes(), capture_hash, timeout)
                    .unwrap_err();
            assert!(error.contains("timed out"));
            assert!(!error.contains(secret));
            // Killing the group is prompt: far from the tool's 60 s sleep.
            assert!(started.elapsed() < timeout + Duration::from_secs(20));
            if let (Some(pid), Some(descendant)) = (written("tool-pid"), written("descendant-pid"))
            {
                break (pid, descendant);
            }
            assert!(
                timeout < Duration::from_secs(10),
                "the tool never started its descendant within {timeout:?}"
            );
            timeout *= 2;
        };
        assert!(!Path::new("/proc").join(pid.trim()).exists());
        let stopped_deadline = Instant::now() + Duration::from_secs(60);
        while let Ok(stat) =
            fs::read_to_string(Path::new("/proc").join(descendant.trim()).join("stat"))
        {
            if stat.split_once(") ").unwrap().1.starts_with('Z') {
                break;
            }
            assert!(Instant::now() < stopped_deadline);
            thread::sleep(Duration::from_millis(10));
        }
        assert!(unrelated.try_wait().unwrap().is_none());
    }
    unrelated.kill().unwrap();
    unrelated.wait().unwrap();
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn oversized_tool_input_and_output_are_rejected_without_exposing_content() {
    let error = run_private_with_timeout(
        &mut Command::new("missing-tool"),
        &[0; 4097],
        true,
        Duration::from_millis(100),
    )
    .unwrap_err();
    assert!(error.contains("input exceeds limit"));
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "cat >/dev/null; head -c 8192 /dev/zero"]);
    let error = run_private_with_timeout(
        &mut command,
        b"private-output-password",
        true,
        Duration::from_secs(1),
    )
    .unwrap_err();
    assert!(error.contains("output exceeded limit"));
    assert!(!error.contains("private-output-password"));
}
/// The probe's answer for a whole-disk root (a desktop base) of 6 GiB.
const WHOLE_DISK: &str = "/dev/sda: ext4\\n6442450944\\n";
/// The console base's disk on a 6 GiB VM disk, before provisioning.
const PARTITIONED: &str = "/dev/sda1: ext4\\n6442450944\\n[0] = {\\n  part_num: 1\\n  part_start: 1048576\\n  part_end: 3222274047\\n  part_size: 3221225472\\n}\\n";
fn input_of(root: &Path) -> String {
    fs::read_to_string(root.join("input")).unwrap()
}
/// The hash the fake guest reports, as Debian 13's chpasswd makes one.
fn guest_hash() -> String {
    format!("$y$j9T${}${}", "s".repeat(22), "h".repeat(43))
}
fn account() -> GuestAccount {
    GuestAccount {
        username: "analyst".into(),
        password_hash: guest_hash(),
        root_uuid: None,
        interface: None,
        boot_disk: None,
    }
}
/// A guestfish stand-in: the read-only probe lists `filesystems`, the
/// writable run records its argv and commands and prints the hash the
/// guest stored, as the provisioning script's last `sh` does.
fn fake_tool(directory: &Path, fail: bool, filesystems: &str) -> std::path::PathBuf {
    let path = directory.join("fake-tool");
    fs::write(&path, format!("#!/bin/sh\nroot=$(dirname \"$0\")\nif [ \"$1\" = --ro ]; then cat > \"$root/probe\"; printf '{filesystems}'; exit 0; fi\nprintf '%s\\n' \"$@\" > \"$root/argv\"\ncat > \"$root/input\"\ncat \"$root/input\" >&2\nprintf 'hash:%s\\n' '{}'\nexit {}\n", guest_hash(), if fail { 1 } else { 0 })).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}
#[test]
fn offline_tool_uses_stdin_and_never_exposes_sensitive_output() {
    let root = std::env::temp_dir().join(format!("ant-account-{}", storage::unique_id()));
    storage::private_dir(&root).unwrap();
    let disk = root.join("disk.qcow2");
    fs::write(&disk, b"unchanged disk fixture").unwrap();
    // A new account: the guest hashes the password itself.
    let secret = "private-provision-password";
    let mut account = GuestAccount::unprovisioned("analyst".into()).unwrap();
    account
        .provision_with(
            &disk,
            &fake_tool(&root, false, WHOLE_DISK),
            1024,
            &Password::Plain(secret),
            None,
        )
        .unwrap();
    assert_eq!(account.password_hash, guest_hash());
    let uuid = account.root_uuid().unwrap().to_owned();
    assert!(valid_uuid(&uuid), "{uuid}");
    assert_eq!(
        fs::read_to_string(root.join("probe")).unwrap().as_bytes(),
        PROBE
    );
    // A whole-disk root keeps its disk as it is (it grows at boot).
    assert!(!input_of(&root).contains("part-"));
    let argv = fs::read_to_string(root.join("argv")).unwrap();
    assert!(argv.starts_with("--rw\n--no-progress-bars\n--format=qcow2\n-a\n"));
    assert!(!argv.contains(secret));
    assert!(!argv.contains(&account.username));
    let input = input_of(&root);
    // The password reaches only the guest's chpasswd, on its standard
    // input: never in a file written to the disk.
    let carrying: Vec<_> = input.lines().filter(|line| line.contains(secret)).collect();
    assert_eq!(carrying.len(), 1, "{input}");
    assert!(
        carrying[0].starts_with(
            "sh \"set -eu\\nchpasswd <<'ACCOUNT'\\nanalyst:private-provision-password\\nACCOUNT\\n"
        ),
        "{}",
        carrying[0]
    );
    assert!(!input.contains("/password"));
    assert!(!input.contains("chpasswd -e"));
    // A new identity before the root is mounted, then the account.
    let position = |text: &str| input.find(text).unwrap_or_else(|| panic!("{text}"));
    assert!(position("e2fsck-f /dev/sda\n") < position(&format!("set-uuid /dev/sda {uuid}")));
    assert!(
        position("-debug sh \"echo ssv hash_seed random | debugfs -w -f - /dev/sda")
            < position("mount /dev/sda /")
    );
    assert!(position("provision.sh\"\n") < position("chpasswd"));
    assert!(input.contains(&format!("UUID={uuid}\\\\1|' /etc/fstab")));
    // The installer's adduser: the full name, its groups (where they
    // exist), a private home; the installation's own machine ID.
    assert!(input.contains("addgroup --quiet --gid 1000 'analyst'"));
    assert!(input.contains(
        "adduser --quiet --uid 1000 --gid 1000 --comment 'Analyst,,,' --disabled-password 'analyst'"
    ));
    assert!(input.contains(&format!("for group in {INSTALLER_GROUPS}; do")));
    assert!(input.contains("chmod 0700 '/home/analyst'"));
    // No interface asked for: the network configuration stays.
    assert!(!input.contains("/etc/network/interfaces"));
    assert_eq!(account.interface, None);
    let machine_id = input
        .lines()
        .find_map(|line| line.strip_prefix("write /etc/machine-id \""))
        .unwrap();
    assert!(
        machine_id.len() == 32 + 3 && machine_id.ends_with("\\n\""),
        "{machine_id}"
    );
    assert!(!input.contains("NOPASSWD"));
    assert!(!input.contains("sudoers"));
    assert!(!input.to_lowercase().contains("antinomie"));
    // A reset sets the recorded hash again, and gets a new identity.
    let mut again = account.clone();
    again
        .provision_with(
            &disk,
            &fake_tool(&root, false, WHOLE_DISK),
            1024,
            &Password::Hashed(&guest_hash()),
            None,
        )
        .unwrap();
    assert_ne!(again.root_uuid(), Some(uuid.as_str()));
    let input = input_of(&root);
    assert!(input.contains(&format!(
        "chpasswd -e <<'ACCOUNT'\\nanalyst:{}\\nACCOUNT",
        guest_hash()
    )));
    assert!(!input.contains(secret));
    // The guest keeping another hash than the recorded one is an error.
    let other = format!("$6$fixturesalt${}", "a".repeat(86));
    assert!(
        account
            .provision_with(
                &disk,
                &fake_tool(&root, false, WHOLE_DISK),
                1024,
                &Password::Hashed(&other),
                None,
            )
            .unwrap_err()
            .contains("did not keep")
    );
    let error = account
        .provision_with(
            &disk,
            &fake_tool(&root, true, WHOLE_DISK),
            1024,
            &Password::Plain(secret),
            None,
        )
        .unwrap_err();
    assert!(!error.contains(secret));
    assert!(!error.contains(&account.password_hash));
    assert!(!format!("{account:?}").contains(&account.password_hash));
    assert!(
        account
            .provision_with(
                &disk,
                &root.join("missing"),
                1024,
                &Password::Plain(secret),
                None
            )
            .is_err()
    );
    // No single ext4 root: nothing is written.
    fs::remove_file(root.join("input")).unwrap();
    for listing in [
        "/dev/sda: xfs\\n",
        "/dev/sda1: ext4\\n/dev/sda2: ext4\\n",
        "/dev/sdb1: ext4\\n",
    ] {
        assert!(
            account
                .provision_with(
                    &disk,
                    &fake_tool(&root, false, listing),
                    1024,
                    &Password::Plain(secret),
                    None
                )
                .is_err()
        );
        assert!(!root.join("input").exists());
    }
    assert_eq!(fs::read(&disk).unwrap(), b"unchanged disk fixture");
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn the_nic_stanza_names_the_interface_provisioning_was_given() {
    let root = std::env::temp_dir().join(format!("ant-account-nic-{}", storage::unique_id()));
    storage::private_dir(&root).unwrap();
    let disk = root.join("disk.qcow2");
    fs::write(&disk, b"disk").unwrap();
    let mut account = account();
    // A disk provisioned before 0.7.1 configures the base's enp0s25.
    assert_eq!(account.interface(), "enp0s25");
    account
        .provision_with(
            &disk,
            &fake_tool(&root, false, PARTITIONED),
            1024,
            &Password::Hashed(&guest_hash()),
            Some("enp0s31f6"),
        )
        .unwrap();
    assert_eq!(account.interface(), "enp0s31f6");
    let input = input_of(&root);
    assert!(
        input.contains("allow-hotplug %s\\\\niface %s inet dhcp"),
        "{input}"
    );
    assert!(input.contains("' enp0s31f6 enp0s31f6 enp0s31f6 >> /root/.provision-"));
    assert!(input.contains("> /etc/network/interfaces\\n"));
    // The record keeps it; a name that is not an interface is refused.
    account.save(&root).unwrap();
    assert_eq!(GuestAccount::load(&root).unwrap().interface(), "enp0s31f6");
    for bad in ["", "enp0s31f6; reboot", "Enp0s25", "averyveryverylongname"] {
        let mut record = self::account();
        record.interface = Some(bad.into());
        assert!(record.validate().is_err(), "{bad}");
        assert!(
            record
                .set_interface_with(&disk, &fake_tool(&root, false, PARTITIONED), bad)
                .is_err()
        );
    }
    // Moving the NIC later rewrites only the stanza, on the root.
    account
        .set_interface_with(&disk, &fake_tool(&root, false, PARTITIONED), "enp0s25")
        .unwrap();
    assert_eq!(account.interface(), "enp0s25");
    let input = input_of(&root);
    assert!(input.starts_with("run\nmount /dev/sda1 /\nmkdir /root/.provision-"));
    assert!(input.contains("' enp0s25 enp0s25 enp0s25 >> /root/.provision-"));
    for absent in ["chpasswd", "set-uuid", "part-", "machine-id"] {
        assert!(!input.contains(absent), "{absent}");
    }
    fs::remove_dir_all(root).unwrap();
}
/// The guest's stanza, run by sh over a copy of the installer's file:
/// the base's (loopback only) and one an earlier provisioning wrote.
#[test]
fn the_nic_stanza_replaces_the_one_before_it() {
    let root = std::env::temp_dir().join(format!("ant-account-ifaces-{}", storage::unique_id()));
    storage::private_dir(&root).unwrap();
    let file = root.join("interfaces");
    let base = "# This file describes the network interfaces available on your system\n# and how to activate them. For more information, see interfaces(5).\n\nsource /etc/network/interfaces.d/*\n\n# The loopback network interface\nauto lo\niface lo inet loopback\n";
    let stanza = |name: &str| {
        format!(
            "{base}\n# The primary network interface\nallow-hotplug {name}\niface {name} inet dhcp\n# This is an autoconfigured IPv6 interface\niface {name} inet6 auto\n"
        )
    };
    for (before, name) in [
        (base.to_owned(), "enp0s25"),
        (stanza("enp0s25"), "enp0s31f6"),
        (stanza("enp0s31f6"), "enp0s31f6"),
    ] {
        fs::write(&file, &before).unwrap();
        let stage = root.join("stage");
        fs::create_dir_all(&stage).unwrap();
        let script = interface_commands(name, &stage.display().to_string())
            .replace("/etc/network/interfaces", &file.display().to_string());
        let status = Command::new("/bin/sh")
            .args(["-eu", "-c", &script])
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(fs::read_to_string(&file).unwrap(), stanza(name));
    }
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn partitions_follow_the_installer_and_the_vm() {
    // A 6 GiB disk (12582912 sectors), a 3 GiB root, 1 GiB of RAM: the
    // swap partition ends a MiB before the disk, the root a MiB before it.
    let plan = partition_plan(12_582_912, 6_293_503, 1024, None, false);
    assert_eq!(plan.swap, Some((10_483_712, 12_580_863)));
    assert_eq!(plan.root_last, 10_481_663);
    // A quarter of the disk at most; the root never shrinks.
    assert_eq!(
        partition_plan(12_582_912, 6_293_503, 8192, None, false).swap,
        Some((9_435_136, 12_580_863))
    );
    let tight = partition_plan(8_388_608, 8_380_000, 1024, None, false);
    assert_eq!((tight.root_last, tight.swap), (8_386_559, None));
    let layout = parse_probe(
        "/dev/sda1: ext4\n/dev/sda2: unknown\n/dev/sda5: swap\n6442450944\n[0] = {\n  part_num: 1\n  part_end: 5366611967\n}\n[1] = {\n  part_num: 5\n  part_end: 6441402367\n  part_size: 1073741824\n}\n0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d\n",
    )
    .unwrap();
    assert_eq!(layout.root_last, Some(10_481_663));
    assert_eq!(
        layout.swap,
        Some(("0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d".into(), 2_097_152))
    );
    let root = std::env::temp_dir().join(format!("ant-account-parts-{}", storage::unique_id()));
    storage::private_dir(&root).unwrap();
    let disk = root.join("disk.qcow2");
    fs::write(&disk, b"disk").unwrap();
    let mut account = account();
    account.boot_disk = Some("/dev/vda".into());
    account
        .provision_with(
            &disk,
            &fake_tool(&root, false, PARTITIONED),
            1024,
            &Password::Hashed(&guest_hash()),
            None,
        )
        .unwrap();
    let input = input_of(&root);
    let position = |text: &str| input.find(text).unwrap_or_else(|| panic!("{text}"));
    assert!(
        position("part-resize /dev/sda 1 10481663\n")
            < position("part-add /dev/sda e 10483710 12580863\n")
    );
    assert!(
        position("part-add /dev/sda l 10483712 12580863\n") < position("mkswap /dev/sda5 uuid:")
    );
    assert!(position("resize2fs /dev/sda1\n") < position("mount /dev/sda1 /\n"));
    assert!(input.contains("set-uuid /dev/sda1 "));
    // The disk identifier changes last, after everything that opens a
    // partition.
    assert!(position("umount-all\n") < position("sfdisk --disk-id /dev/sda 0x"));
    assert!(input.contains("# swap was on /dev/sda5 during installation"));
    assert!(BOOT_LOADER.contains("update-grub"));
    // GRUB's boot code goes into this disk's MBR (its core.img names this
    // disk's root UUID) before grub.cfg is written, as grub-installer does:
    // the helper runs for the BIOS disk.
    assert!(BOOT_LOADER.find("grub-install --force /dev/sda") < BOOT_LOADER.find("update-grub"));
    // The appliance installs to its /dev/sda; debconf names the VM's own disk
    // (virtio's vda here), which grub-pc's upgrades in the VM install to.
    assert!(BOOT_LOADER.contains("grub-pc grub-pc/install_devices multiselect %s"));
    assert!(BOOT_LOADER.contains("' \"$2\" | debconf-set-selections"));
    assert!(!BOOT_LOADER.contains("multiselect /dev/sda"));
    assert!(input.contains(".grub.sh bios /dev/vda\\n"), "{input}");
    // The whole provisioning still fits the tool's standard input.
    assert!(input.len() < 4096, "{}", input.len());
    // The initramfs helper reaches the appliance as a file, runs after the
    // account's files and before the disk is unmounted, names the swap
    // partition's UUID and the installer's root partition, and is gone
    // from the host afterwards.
    let uploads: Vec<_> = input
        .lines()
        .filter(|line| line.starts_with("upload "))
        .map(|line| line.split('"').nth(1).unwrap().to_owned())
        .collect();
    assert!(uploads[0].ends_with("/initrd.py") && uploads[1].ends_with("/boot-loader.sh"));
    assert!(uploads.iter().all(|path| !Path::new(path).exists()));
    let swap_uuid = input
        .split("mkswap /dev/sda5 uuid:")
        .nth(1)
        .unwrap()
        .split('\n')
        .next()
        .unwrap();
    assert!(
        input.contains(&format!(" RESUME=UUID={swap_uuid} 8:1\\n")),
        "{input}"
    );
    assert!(position("provision.sh\"\n") < position("upload "));
    assert!(position("python3 -I /root/.provision-") < position("umount-all\n"));
    // Growing it later keeps the swap partition's UUID and size.
    let grown = "/dev/sda1: ext4\n/dev/sda5: swap\n10737418240\n[0] = {\n  part_num: 1\n  part_end: 5366611967\n}\n[1] = {\n  part_num: 5\n  part_end: 6441402367\n  part_size: 1073741824\n}\n0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d\n";
    grow_disk_with(&disk, &fake_tool(&root, false, &grown.replace('\n', "\\n"))).unwrap();
    let input = input_of(&root);
    assert!(
        input.starts_with(
            "run\npart-del /dev/sda 5\npart-del /dev/sda 2\npart-resize /dev/sda 1 18870271\n"
        ),
        "{input}"
    );
    assert!(input.contains("mkswap /dev/sda5 uuid:0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d\n"));
    assert!(!input.contains("chpasswd"));
    // A whole-disk root is left to the initrd.
    fs::remove_file(root.join("input")).unwrap();
    grow_disk_with(&disk, &fake_tool(&root, false, WHOLE_DISK)).unwrap();
    assert!(!root.join("input").exists());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn the_guest_reports_the_hash_it_stored() {
    // The guest's chpasswd hashes (yescrypt on Debian 13); the record
    // also takes the SHA-512 hashes of disks provisioned before 0.7.1.
    validate_hash(&guest_hash()).unwrap();
    validate_hash(&format!("$6$fixturesalt${}", "a".repeat(86))).unwrap();
    for bad in [
        format!("$y$j9T${}${}", "a".repeat(22), "b".repeat(42)),
        format!("$y$jFT${}${}", "a".repeat(22), "b".repeat(43)),
        format!("$y$j9T${}${}", "a:".repeat(11), "b".repeat(43)),
        format!("$5$salt${}", "a".repeat(43)),
        "!".into(),
        String::new(),
    ] {
        assert!(validate_hash(&bad).is_err(), "{bad}");
    }
    assert_eq!(
        printed_hash(format!("noise\nhash:{}\n", guest_hash()).as_bytes()),
        Some(guest_hash())
    );
    assert_eq!(printed_hash(b"no marker\n"), None);
    // A password with shell and here-document characters stays one
    // line of chpasswd's input; the hash goes in with -e.
    let commands = password_commands("analyst", &Password::Plain("a'b\"$(x)`ACCOUNT"));
    assert!(commands.contains("chpasswd <<'ACCOUNT'\nanalyst:a'b\"$(x)`ACCOUNT\nACCOUNT\n"));
    let commands = password_commands("analyst", &Password::Hashed(&guest_hash()));
    assert!(commands.contains(&format!(
        "chpasswd -e <<'ACCOUNT'\nanalyst:{}\n",
        guest_hash()
    )));
    assert!(GuestAccount::unprovisioned("root".into()).is_err());
}
#[test]
fn probe_finds_the_root_on_a_whole_disk_or_a_partition() {
    let whole = parse_probe("/dev/sda: ext4\n6442450944\n").unwrap();
    assert_eq!(
        (whole.root.as_str(), whole.size),
        ("/dev/sda", 6_442_450_944)
    );
    assert_eq!((whole.root_last, whole.swap), (None, None));
    assert_eq!(
        parse_probe("/dev/sda1: ext4\n/dev/sda2: unknown\n6442450944\n[0] = {\n  part_num: 1\n  part_end: 3222274047\n}\n")
            .unwrap()
            .root_last,
        Some(6_293_503)
    );
    // No size, or a root partition the probe did not list.
    assert!(parse_probe("/dev/sda: ext4\n").is_err());
    assert!(parse_probe("/dev/sda1: ext4\n6442450944\n").is_err());
    assert!(parse_probe("").is_err());
    assert!(parse_probe("/dev/sda1; rm -rf /: ext4\n").is_err());
    assert_eq!(fish_quote("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
    assert!(valid_uuid("0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"));
    for bad in [
        "0B1C2D3E-4F50-4A6B-8C7D-9E0F1A2B3C4D",
        "0b1c2d3e4f504a6b8c7d9e0f1a2b3c4d",
        "",
    ] {
        assert!(!valid_uuid(bad));
    }
    let mut record = account();
    record.root_uuid = Some("not-a-uuid".into());
    assert!(record.validate().is_err());
}
#[test]
fn account_record_is_private_and_malformed_hashes_are_redacted() {
    let root = std::env::temp_dir().join(format!("ant-account-record-{}", storage::unique_id()));
    storage::private_dir(&root).unwrap();
    let account = account();
    account.save(&root).unwrap();
    assert_eq!(
        fs::metadata(root.join("guest-account.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        GuestAccount::load(&root).unwrap().password_hash,
        account.password_hash
    );
    fs::set_permissions(
        root.join("guest-account.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(GuestAccount::load(&root).is_err());
    fs::set_permissions(
        root.join("guest-account.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(
        root.join("guest-account.json"),
        br#"{"username":"analyst","password_hash":123456789}"#,
    )
    .unwrap();
    assert!(!GuestAccount::load(&root).unwrap_err().contains("123456789"));
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn the_initramfs_takes_the_resume_answer_the_installer_gives() {
    let layout = DiskLayout {
        root: "/dev/sda1".into(),
        size: 4 << 30,
        root_last: Some(8_386_559),
        swap: None,
        gpt: false,
    };
    let guids = gpt_guids();
    let identity = Identity {
        uuid: "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d",
        swap_uuid: "1c2d3e4f-5061-4b7c-8d9e-0f1a2b3c4d5e",
        machine_id: "00112233445566778899aabbccddeeff",
        gpt_guids: &guids,
    };
    let hash = guest_hash();
    let helper = Path::new("/host");
    // No room for a swap partition: the installer answers "none".
    let tight = PartitionPlan {
        root_last: 8_386_559,
        swap: None,
    };
    let script = account().script(
        &layout,
        Some(&tight),
        &identity,
        &Password::Hashed(&hash),
        None,
        Some(helper),
    );
    assert!(script.contains("upload \"/host/initrd.py\" /root/.provision-"));
    assert!(script.contains("upload \"/host/boot-loader.sh\" /root/.provision-"));
    assert!(script.contains(" RESUME=none 8:1\\n"), "{script}");
    assert!(!script.contains("RESUME=UUID="));
    // The helper's own text is never in the script on standard input.
    assert!(!script.contains("TRAILER"));
    // A whole-disk root (BusyBox, the desktops) has no swap and no helper.
    let whole = DiskLayout {
        root: "/dev/sda".into(),
        root_last: None,
        ..layout
    };
    let script = account().script(
        &whole,
        None,
        &identity,
        &Password::Hashed(&hash),
        None,
        None,
    );
    assert!(!script.contains("upload ") && !script.contains("RESUME="));
}

fn gpt_guids() -> [String; 4] {
    [
        "11111111-2222-4333-8444-555555555551".into(),
        "11111111-2222-4333-8444-555555555552".into(),
        "11111111-2222-4333-8444-555555555553".into(),
        "11111111-2222-4333-8444-555555555554".into(),
    ]
}

#[test]
fn a_uefi_disk_is_laid_out_and_set_up_as_the_installer_does() {
    // The derived UEFI disk on an 8 GiB VM disk: ESP sda1, root sda2.
    let layout = parse_probe(
        "/dev/sda1: vfat\n/dev/sda2: ext4\n8589934592\n[0] = {\n  part_num: 1\n  part_end: 681574399\n}\n[1] = {\n  part_num: 2\n  part_end: 3902799871\n}\ngpt\n",
    )
    .unwrap();
    assert!(layout.gpt);
    assert_eq!(layout.root, "/dev/sda2");
    assert_eq!(layout.root_last, Some(7_622_655));
    // The swap partition follows the root directly (no extended partition).
    let plan = partition_plan(16_777_216, 7_622_655, 1024, None, true);
    assert_eq!(plan.swap, Some((14_678_016, 16_775_167)));
    assert_eq!(plan.root_last, 14_678_015);
    let guids = gpt_guids();
    let identity = Identity {
        uuid: "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d",
        swap_uuid: "1c2d3e4f-5061-4b7c-8d9e-0f1a2b3c4d5e",
        machine_id: "00112233445566778899aabbccddeeff",
        gpt_guids: &guids,
    };
    let hash = guest_hash();
    let script = account().script(
        &layout,
        Some(&plan),
        &identity,
        &Password::Hashed(&hash),
        Some("enp0s31f6"),
        Some(Path::new("/host")),
    );
    let position = |text: &str| {
        script
            .find(text)
            .unwrap_or_else(|| panic!("{text}\n{script}"))
    };
    assert!(position("part-expand-gpt /dev/sda\n") < position("part-resize /dev/sda 2 14678015\n"));
    assert!(
        position("part-add /dev/sda p 14678016 16775167\n") < position("mkswap /dev/sda3 uuid:")
    );
    assert!(script.contains("part-set-gpt-type /dev/sda 3 0657FD6D-A4AB-43C4-84E5-0933C84B4F4F\n"));
    assert!(!script.contains("part-add /dev/sda e") && !script.contains("sfdisk"));
    assert!(position("resize2fs /dev/sda2\n") < position("mount /dev/sda2 /\n"));
    // The ESP is formatted for this VM and mounted for grub-install.
    assert!(position("mkfs vfat /dev/sda1\n") < position("mount /dev/sda2 /\n"));
    assert!(position("mount /dev/sda2 /\n") < position("mount /dev/sda1 /boot/efi\n"));
    assert!(position("mount /dev/sda1 /boot/efi\n") < position(".grub.sh uefi /dev/sda\\n"));
    assert!(script.contains("# swap was on /dev/sda3 during installation"));
    assert!(script.contains(" RESUME=UUID=1c2d3e4f-5061-4b7c-8d9e-0f1a2b3c4d5e 8:2\\n"));
    // The disk's and its partitions' GUIDs of its own, after unmounting.
    assert!(
        position("umount-all\n")
            < position("part-set-disk-guid /dev/sda 11111111-2222-4333-8444-555555555551\n")
    );
    for number in 1..=3 {
        assert!(script.contains(&format!(
            "part-set-gpt-guid /dev/sda {number} 11111111-2222-4333-8444-55555555555{}\n",
            number + 1
        )));
    }
    assert!(script.len() < 4096, "{}", script.len());
    // The guest side: fstab's ESP line, grub-install for UEFI with the
    // removable-media copy and without touching the firmware's variables.
    assert!(BOOT_LOADER.contains("--target=x86_64-efi --efi-directory=/boot/efi"));
    assert!(BOOT_LOADER.contains("--force-extra-removable --no-nvram"));
    assert!(BOOT_LOADER.contains("[[:space:]]+/boot/efi[[:space:]]"));
    // Growing a GPT disk moves the backup table and keeps sda3.
    let grown = parse_probe(
        "/dev/sda1: vfat\n/dev/sda2: ext4\n/dev/sda3: swap\n12884901888\n[0] = {\n  part_num: 2\n  part_end: 7514095615\n}\n[1] = {\n  part_num: 3\n  part_end: 8588886015\n  part_size: 1073741824\n}\ngpt\n2b3c4d5e-6f70-4a8b-9c0d-1e2f3a4b5c6d\n",
    )
    .unwrap();
    assert_eq!(
        grown.swap,
        Some(("2b3c4d5e-6f70-4a8b-9c0d-1e2f3a4b5c6d".into(), 2_097_152))
    );
    let commands = layout_commands(
        &grown,
        &partition_plan(25_165_824, 14_675_967, 0, Some(2_097_152), true),
        "u",
    );
    assert_eq!(
        commands[..2],
        ["part-expand-gpt /dev/sda", "part-del /dev/sda 3"]
    );
}

/// grub-pc's debconf answer names the VM's disk on its bus, at provisioning
/// and when the profile moves the disk; the record keeps it, and a disk
/// provisioned before keeps the appliance's /dev/sda until then.
#[test]
fn the_boot_disk_answer_follows_the_vm_disk_bus() {
    use crate::stealth::{DiskBus, StealthProfile};
    let on = |bus| {
        boot_disk(&StealthProfile {
            disk_bus: bus,
            ..StealthProfile::default()
        })
    };
    assert_eq!(on(DiskBus::Virtio), "/dev/vda");
    assert_eq!(on(DiskBus::Sata), "/dev/sda");
    assert_eq!(on(DiskBus::Nvme), "/dev/nvme0n1");
    let root = std::env::temp_dir().join(format!("ant-account-boot-{}", storage::unique_id()));
    storage::private_dir(&root).unwrap();
    let disk = root.join("disk.qcow2");
    fs::write(&disk, b"disk").unwrap();
    // One stand-in for every run: writing an executable while another test
    // thread forks can leave it busy for an exec.
    let tool = fake_tool(&root, false, PARTITIONED);
    let mut account = account();
    assert_eq!(account.boot_disk(), "/dev/sda");
    // The script the guest runs over a scratch debconf stand-in: the answer
    // names the device, only where GRUB for BIOS is installed.
    let commands = boot_disk_commands("/dev/vda");
    assert!(commands.starts_with("if [ -d /usr/lib/grub/i386-pc ]; then"));
    assert!(commands.contains("multiselect /dev/vda\\n' | debconf-set-selections"));
    for device in ["/dev/vda", "/dev/sda", "/dev/nvme0n1"] {
        account.set_boot_disk_with(&disk, &tool, device).unwrap();
        assert_eq!(account.boot_disk(), device);
        let input = input_of(&root);
        assert!(input.starts_with("run\nmount /dev/sda1 /\nmkdir /root/.provision-"));
        assert!(
            input.contains(&format!("install_devices multiselect {device}\\\\n")),
            "{input}"
        );
        for absent in ["chpasswd", "set-uuid", "part-", "machine-id", "interfaces"] {
            assert!(!input.contains(absent), "{absent}");
        }
        account.save(&root).unwrap();
        assert_eq!(GuestAccount::load(&root).unwrap().boot_disk(), device);
    }
    for bad in ["", "/dev/vdb", "/dev/sda; reboot", "vda"] {
        let mut record = self::account();
        record.boot_disk = Some(bad.into());
        assert!(record.validate().is_err(), "{bad}");
        assert!(
            record
                .provision_with(&disk, &tool, 1024, &Password::Hashed(&guest_hash()), None,)
                .is_err()
        );
        assert!(
            self::account()
                .set_boot_disk_with(&disk, &tool, bad)
                .is_err()
        );
    }
    fs::remove_dir_all(root).unwrap();
}
