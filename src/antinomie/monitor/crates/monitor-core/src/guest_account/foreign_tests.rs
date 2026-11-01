// SPDX-License-Identifier: GPL-3.0-only
use super::*;

fn guest_hash() -> String {
    format!("$y$j9T${}${}", "s".repeat(22), "h".repeat(43))
}

fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("ant-foreign-{name}-{}", storage::unique_id()));
    storage::private_dir(&root).unwrap();
    root
}

const BASE_FSTAB: &str = "# /etc/fstab: static file system information.\n#\n# <file system> <mount point>   <type>  <options>       <dump>  <pass>\n# / was on /dev/sda1 during installation\nUUID=2da308b0-4365-44b4-9efd-3d5777536aaa /               ext4    errors=remount-ro 0       1\n/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0\n";
const UEFI_FSTAB: &str = "# / was on /dev/sda2 during installation\nUUID=2da308b0-4365-44b4-9efd-3d5777536aaa /               ext4    errors=remount-ro 0       1\n# /boot/efi was on /dev/sda1 during installation\nUUID=0000-0000  /boot/efi       vfat    umask=0077      0       1\n/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0\n";

/// The fw_cfg item names the private file, its commas doubled for QEMU.
#[test]
fn the_secret_reaches_the_guest_over_fw_cfg_from_a_file() {
    assert_eq!(
        fw_cfg_option(Path::new("/tmp/a,b/secret")),
        "name=opt/antinomie/provision,file=/tmp/a,,b/secret"
    );
    let boot = ProvisionBoot {
        arch: crate::api::GuestArch::AARCH64,
        qemu: "qemu-system-aarch64".into(),
        kernel: "/bases/k".into(),
        initrd: Some("/bases/i".into()),
        append: "BOOT_IMAGE=/boot/vmlinuz-6.12.94+deb13-arm64 root=UUID=2da308b0-4365-44b4-9efd-3d5777536aaa ro quiet".into(),
    };
    let args = boot.args(
        Path::new("/vm/disk.qcow2"),
        "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d",
        "provision-x.target",
        Path::new("/private/secret"),
    );
    let value = |name: &str| {
        let at = args.iter().position(|arg| arg == name).unwrap();
        args[at + 1].as_str()
    };
    assert_eq!(
        value("-fw_cfg"),
        "name=opt/antinomie/provision,file=/private/secret"
    );
    assert_eq!(value("-machine"), "virt,gic-version=3");
    assert_eq!(value("-accel"), "tcg");
    assert_eq!(value("-cpu"), "cortex-a72");
    assert_eq!(value("-m"), "1024");
    assert_eq!(value("-kernel"), "/bases/k");
    assert_eq!(value("-initrd"), "/bases/i");
    assert_eq!(value("-nic"), "none");
    assert_eq!(value("-serial"), "stdio");
    assert_eq!(value("-display"), "none");
    assert_eq!(
        value("-drive"),
        "file=/vm/disk.qcow2,format=qcow2,if=none,id=root"
    );
    assert_eq!(value("-device"), "virtio-blk-pci,drive=root");
    assert!(args.contains(&"-no-reboot".to_owned()));
    // The disk's own root UUID, the serial console, the provisioning target;
    // no bootstrap page (nothing records this boot).
    assert_eq!(
        value("-append"),
        "BOOT_IMAGE=/boot/vmlinuz-6.12.94+deb13-arm64 root=UUID=0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d ro quiet console=ttyAMA0 panic=-1 antinomie_kpti=off systemd.unit=provision-x.target"
    );
    assert!(!args.iter().any(|arg| arg.contains("antinomie_boot_gpa")));
}

/// The unit runs the staging script once, before anything else of the
/// boot, prints to the serial console and powers off either way.
#[test]
fn the_unit_runs_the_script_alone_and_powers_off() {
    let (service, target) = unit_files("/root/.provision-x", "provision-x");
    for line in [
        "DefaultDependencies=no",
        "ConditionPathExists=/root/.provision-x/provision.sh",
        "SuccessAction=poweroff-force",
        "FailureAction=poweroff-force",
        "Type=oneshot",
        "ExecStart=/bin/sh /root/.provision-x/provision.sh",
        "TimeoutStartSec=infinity",
        "StandardInput=null",
        "StandardOutput=tty",
        "StandardError=tty",
        "TTYPath=/dev/ttyAMA0",
    ] {
        assert!(
            service.lines().any(|text| text == line),
            "{line}\n{service}"
        );
    }
    assert!(!service.contains("WantedBy"));
    assert_eq!(
        target,
        "[Unit]\nDescription=Provisioning\nAllowIsolate=yes\nWants=provision-x.service\n"
    );
}

/// The hash comes only from between the markers (the last pair, with the
/// serial console's carriage returns); a failed step is named; anything
/// else is no report.
#[test]
fn the_console_report_is_read_between_the_markers() {
    let hash = guest_hash();
    let console = format!(
        "[    0.000000] Booting Linux\r\nprovision-hash-begin\r\nnot-this\r\nnoise\r\n\r\nprovision-hash-begin\r\n{hash}\r\nprovision-hash-end\r\n[  OK  ] reboot\r\n"
    );
    assert_eq!(
        console_report(console.as_bytes()),
        Report::Hash(hash.clone())
    );
    assert_eq!(
        console_report(format!("provision-hash-begin\n{hash}\n").as_bytes()),
        Report::Nothing
    );
    assert_eq!(
        console_report(
            format!("provision-hash-begin\n{hash}\nextra\nprovision-hash-end\n").as_bytes()
        ),
        Report::Nothing
    );
    assert_eq!(
        console_report(b"boot\r\n\r\nprovision-failed boot-loader\r\n"),
        Report::Failed("boot-loader".into())
    );
    assert_eq!(
        console_report(b"provision-failed $(reboot)\n"),
        Report::Nothing
    );
    assert_eq!(console_report(b""), Report::Nothing);
}

/// After the boot the appliance removes the staging folder, the unit, its
/// target and link and this machine's journal, and the boot traces the disk
/// did not have before.
#[test]
fn the_boot_traces_are_removed_unless_the_base_had_them() {
    let mut existed = vec![false; BOOT_TRACES.len()];
    existed[0] = true;
    let commands = trace_commands(
        "/dev/sda2",
        "/root/.provision-x",
        "provision-x",
        "00112233445566778899aabbccddeeff",
        &existed,
    );
    let mut expected = vec![
        "run".to_owned(),
        "mount /dev/sda2 /".into(),
        "rm-rf /root/.provision-x".into(),
        "rm-f /etc/systemd/system/provision-x.service".into(),
        "rm-f /etc/systemd/system/provision-x.target".into(),
        "rm-rf /etc/systemd/system/provision-x.target.wants".into(),
        "rm-rf /var/log/journal/00112233445566778899aabbccddeeff".into(),
    ];
    expected.extend(BOOT_TRACES[1..].iter().map(|path| format!("rm-rf {path}")));
    expected.extend(["umount-all".into(), String::new()]);
    assert_eq!(commands, expected);
    for path in [
        "/var/lib/systemd/random-seed",
        "/var/lib/systemd/timers",
        "/var/log/wtmp",
        "/var/log/btmp",
        "/var/log/lastlog",
        "/var/lib/wtmpdb/wtmp.db",
    ] {
        assert!(BOOT_TRACES.contains(&path), "{path}");
    }
    assert!(
        BOOT_TRACES
            .iter()
            .all(|path| path.starts_with('/') && !path.contains(' '))
    );
    let answers = "false\n".repeat(BOOT_TRACES.len());
    assert_eq!(
        parse_existing(answers.as_bytes()).unwrap(),
        vec![false; BOOT_TRACES.len()]
    );
    assert!(parse_existing(b"true\n").is_err());
}

/// The host's fstab and interfaces edits give what the x86-64 script's sed
/// and awk give in the guest, run here by sh over the same files.
#[test]
fn the_host_edits_match_the_x86_guest_edits() {
    let root = scratch("edits");
    let file = root.join("fstab");
    let uuid = "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d";
    let swap_uuid = "1c2d3e4f-5061-4b7c-8d9e-0f1a2b3c4d5e";
    for (fstab, swap) in [
        (BASE_FSTAB, None),
        (BASE_FSTAB, Some(5)),
        (UEFI_FSTAB, Some(3)),
        (UEFI_FSTAB, None),
        ("/dev/vda / ext4 defaults 0 1\n", None),
    ] {
        fs::write(&file, fstab).unwrap();
        let path = file.display().to_string();
        let mut script = format!(
            "sed -i -E 's|^UUID=[0-9A-Fa-f-]+([[:space:]]+/[[:space:]])|UUID={uuid}\\1|' {path}\n"
        );
        if let Some(number) = swap {
            script.push_str(&format!(
                "awk -v u={swap_uuid} '/^\\/dev\\/sr0/ {{print \"# swap was on /dev/sda{number} during installation\"; printf \"UUID=%s none            swap    sw              0       0\\n\", u}} {{print}}' {path} > {path}.new\ncat {path}.new > {path}\n"
            ));
        }
        assert!(
            Command::new("/bin/sh")
                .args(["-eu", "-c", &script])
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(
            fstab_text(fstab, uuid, swap.map(|number| (swap_uuid, number))),
            fs::read_to_string(&file).unwrap(),
            "{fstab}"
        );
    }
    let text = fstab_text(UEFI_FSTAB, uuid, None);
    assert!(text.contains(&format!("UUID={uuid} /               ext4")));
    assert!(text.contains("UUID=0000-0000  /boot/efi"));
    let file = root.join("interfaces");
    let base = "# This file describes the network interfaces available on your system\n\nsource /etc/network/interfaces.d/*\n\n# The loopback network interface\nauto lo\niface lo inet loopback\n";
    let provisioned = interfaces_text(base, "enp0s25");
    for (before, name) in [
        (base, "enp0s25"),
        (provisioned.as_str(), "enp0s31f6"),
        ("", "eno1"),
        ("auto lo\n\n\n", "ens3"),
    ] {
        fs::write(&file, before).unwrap();
        let stage = root.join("stage");
        fs::create_dir_all(&stage).unwrap();
        let script = interface_commands(name, &stage.display().to_string())
            .replace("/etc/network/interfaces", &file.display().to_string());
        assert!(
            Command::new("/bin/sh")
                .args(["-eu", "-c", &script])
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(
            interfaces_text(before, name),
            fs::read_to_string(&file).unwrap(),
            "{before}"
        );
    }
    fs::remove_dir_all(root).unwrap();
}

/// The guest's part: the x86-64 script's account steps, GRUB for arm64 UEFI
/// on a GPT disk, the initramfs on a partitioned one, then the password
/// straight from fw_cfg into chpasswd and the stored hash between markers.
#[test]
fn the_guest_part_runs_the_guest_programs_and_reads_the_secret_once() {
    let script = guest_script(&GuestPart {
        username: "analyst",
        staging: "/root/.provision-x",
        hashed: false,
        gpt: true,
        initrd: Some(("RESUME=UUID=1c2d3e4f-5061-4b7c-8d9e-0f1a2b3c4d5e", "8:2")),
    });
    let position = |text: &str| {
        script
            .find(text)
            .unwrap_or_else(|| panic!("{text}\n{script}"))
    };
    assert!(script.starts_with("set -eu\n"));
    assert!(
        position("mount -o remount,rw /\n") < position("addgroup --quiet --gid 1000 'analyst'\n")
    );
    assert!(script.contains(
        "adduser --quiet --uid 1000 --gid 1000 --comment 'Analyst,,,' --disabled-password 'analyst'\n"
    ));
    assert!(script.contains(&format!("for group in {INSTALLER_GROUPS}; do\n")));
    assert!(script.contains("chmod 0700 '/home/analyst'\n"));
    assert!(position("passwd -l root") < position("step=boot-loader"));
    assert!(script.contains("esp=$(blkid -s UUID -o value /dev/vda1)\n"));
    assert!(script.contains("[[:space:]]+/boot/efi[[:space:]])|UUID=$esp\\1|\" /etc/fstab\n"));
    assert!(script.contains(
        "grub-install --force --target=arm64-efi --efi-directory=/boot/efi --bootloader-id=debian --force-extra-removable --no-nvram"
    ));
    assert!(position("step=boot-loader") < position("step=initramfs"));
    assert!(script.contains(
        "python3 -I /root/.provision-x/initrd.py RESUME=UUID=1c2d3e4f-5061-4b7c-8d9e-0f1a2b3c4d5e 8:2\n"
    ));
    assert!(position("step=initramfs") < position("step=password"));
    assert!(script.contains("modprobe qemu_fw_cfg\n"));
    let reads: Vec<_> = script
        .lines()
        .filter(|line| line.contains("qemu_fw_cfg/by_name/opt/antinomie/provision/raw"))
        .collect();
    assert_eq!(
        reads,
        [
            "{ printf '%s:' 'analyst'; cat /sys/firmware/qemu_fw_cfg/by_name/opt/antinomie/provision/raw; printf '\\n'; } | chpasswd"
        ]
    );
    assert!(position("| chpasswd\n") < position("rm -rf /root/.provision-x\n"));
    assert!(script.ends_with(
        "sync\nprintf '\\nprovision-hash-begin\\n%s\\nprovision-hash-end\\n' \"$hash\"\n"
    ));
    // A reset sets the recorded hash; a BIOS disk has no boot loader on
    // arm64; a whole disk no initramfs step.
    let reset = guest_script(&GuestPart {
        username: "analyst",
        staging: "/root/.provision-x",
        hashed: true,
        gpt: false,
        initrd: None,
    });
    assert!(reset.contains("| chpasswd -e\n"));
    assert!(
        !reset.contains("grub") && !reset.contains("initrd.py") && !reset.contains("/boot/efi")
    );
    // The script parses, and a failing step prints its name.
    for text in [&script, &reset] {
        assert!(
            Command::new("/bin/sh")
                .args(["-n", "-c", text])
                .status()
                .unwrap()
                .success()
        );
    }
    let failing = format!(
        "{}step=account\nfalse\n",
        &reset[..reset.find("mount -o").unwrap()]
    );
    let output = Command::new("/bin/sh")
        .args(["-c", &failing])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        console_report(&output.stdout),
        Report::Failed("account".into())
    );
}

/// A guestfish stand-in for the foreign path: the probe lists a partitioned
/// disk, the read pass "downloads" fixtures and answers `exists`, each
/// writable pass is recorded.
fn fake_guestfish(root: &Path) -> PathBuf {
    fs::write(root.join("fstab.fixture"), BASE_FSTAB).unwrap();
    fs::write(
        root.join("interfaces.fixture"),
        "source /etc/network/interfaces.d/*\n\n# The loopback network interface\nauto lo\niface lo inet loopback\n",
    )
    .unwrap();
    let path = root.join("fake-guestfish");
    fs::write(
        &path,
        "#!/bin/sh\nroot=$(dirname \"$0\")\ninput=$(cat)\nn=$(ls \"$root\" | grep -c '^pass-')\nprintf '%s\\n' \"$input\" > \"$root/pass-$n\"\nprintf '%s\\n' \"$@\" > \"$root/argv-$n\"\n\
         if [ \"$1\" = --ro ]; then\n\
         case \"$input\" in\n\
         *'download /etc/'*)\n\
         for f in fstab interfaces; do\n\
         to=$(printf '%s\\n' \"$input\" | sed -n \"s|^download /etc[a-z/]*/$f \\\"\\\\(.*\\\\)\\\"\\$|\\\\1|p\")\n\
         [ -z \"$to\" ] || cp \"$root/$f.fixture\" \"$to\"\n\
         done\n\
         printf '%s\\n' \"$input\" | grep '^exists ' | sed '1s/.*/true/;1!s/.*/false/'\n\
         ;;\n\
         *) printf '/dev/sda1: ext4\\n6442450944\\n[0] = {\\n  part_num: 1\\n  part_end: 3222274047\\n  part_size: 3221225472\\n}\\n' ;;\n\
         esac\n\
         fi\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

/// A QEMU stand-in: it reads the fw_cfg file (keeping a copy for the test),
/// keeps its arguments and prints `console`.
fn fake_qemu(root: &Path, console: &str) -> PathBuf {
    let path = root.join("fake-qemu");
    fs::write(
        &path,
        format!(
            "#!/bin/sh\nroot=$(dirname \"$0\")\nprintf '%s\\n' \"$@\" > \"$root/qemu-argv\"\n\
             for arg; do case \"$arg\" in name=opt/antinomie/provision,file=*) cat \"${{arg#*,file=}}\" > \"$root/fw-cfg-seen\"; ls -l \"${{arg#*,file=}}\" > \"$root/fw-cfg-mode\";; esac; done\n\
             printf '{console}'\nexit 0\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn boot_with(qemu: PathBuf) -> ProvisionBoot {
    ProvisionBoot {
        arch: crate::api::GuestArch::AARCH64,
        qemu,
        kernel: "/bases/kernel".into(),
        initrd: None,
        append: "root=UUID=2da308b0-4365-44b4-9efd-3d5777536aaa ro quiet".into(),
    }
}

/// The whole path with stand-ins: the appliance's offline part (no guest
/// `sh`, the secret nowhere in it), the boot (the secret only in its private
/// fw_cfg file, gone afterwards), the hash from the console and the traces'
/// removal; a failed or silent boot is a plain error.
#[test]
fn a_foreign_disk_is_provisioned_in_its_own_boot() {
    let root = scratch("boot");
    let disk = root.join("disk.qcow2");
    fs::write(&disk, b"disk").unwrap();
    let guestfish = fake_guestfish(&root);
    let hash = guest_hash();
    let qemu = fake_qemu(
        &root,
        &format!("boot\\r\\nprovision-hash-begin\\r\\n{hash}\\r\\nprovision-hash-end\\r\\n"),
    );
    let secret = "private-provision-password";
    let mut account = GuestAccount::unprovisioned("analyst".into()).unwrap();
    account.boot_disk = Some("/dev/vda".into());
    account
        .provision_foreign(
            &disk,
            &guestfish,
            1024,
            &Password::Plain(secret),
            Some("enp0s25"),
            &boot_with(qemu.clone()),
        )
        .unwrap();
    assert_eq!(account.password_hash, hash);
    assert_eq!(account.interface(), "enp0s25");
    let uuid = account.root_uuid().unwrap().to_owned();
    let pass = |n: u32| fs::read_to_string(root.join(format!("pass-{n}"))).unwrap();
    // Probe, read pass, offline write pass, trace removal.
    assert_eq!(pass(0).as_bytes(), PROBE);
    let read = pass(1);
    assert!(read.starts_with("run\nmount-ro /dev/sda1 /\ndownload /etc/fstab \""));
    assert_eq!(read.matches("\nexists ").count(), BOOT_TRACES.len());
    let write = pass(2);
    assert!(
        fs::read_to_string(root.join("argv-2"))
            .unwrap()
            .starts_with("--rw\n")
    );
    for line in [
        "part-resize /dev/sda 1 ",
        "e2fsck-f /dev/sda1\n",
        &format!("set-uuid /dev/sda1 {uuid}\n"),
        "mount /dev/sda1 /\n",
        " /etc/fstab\n",
        " /etc/network/interfaces\n",
        "write /etc/machine-id \"",
        "/provision.sh\n",
        "/initrd.py\n",
        "ln-s ../provision-",
        "umount-all\n",
        "-debug sh \"sfdisk --disk-id /dev/sda 0x",
    ] {
        assert!(write.contains(line), "{line}\n{write}");
    }
    // Only appliance operations: no command runs a guest program.
    assert!(
        !write.lines().any(|line| line.starts_with("sh ")),
        "{write}"
    );
    for text in [&read, &write] {
        assert!(!text.contains(secret) && !text.contains("chpasswd"));
    }
    let staging = write
        .lines()
        .find_map(|line| line.strip_prefix("mkdir /root/.provision-"))
        .map(|id| format!("/root/.provision-{id}"))
        .unwrap();
    // The boot: the secret went in over fw_cfg from a private file only.
    let argv = fs::read_to_string(root.join("qemu-argv")).unwrap();
    assert!(!argv.contains(secret));
    assert!(argv.contains(&format!("root=UUID={uuid} ro quiet console=ttyAMA0")));
    assert_eq!(
        fs::read_to_string(root.join("fw-cfg-seen")).unwrap(),
        secret
    );
    assert!(
        fs::read_to_string(root.join("fw-cfg-mode"))
            .unwrap()
            .starts_with("-rw-------")
    );
    let file = argv
        .lines()
        .find_map(|line| line.strip_prefix("name=opt/antinomie/provision,file="))
        .unwrap();
    assert!(!Path::new(file).exists());
    assert!(!Path::new(file).parent().unwrap().exists());
    // The traces' removal, last.
    let traces = pass(3);
    assert!(traces.starts_with(&format!("run\nmount /dev/sda1 /\nrm-rf {staging}\n")));
    assert!(!traces.contains(&format!("rm-rf {}\n", BOOT_TRACES[0])));
    assert!(traces.contains(&format!("rm-rf {}\n", BOOT_TRACES[1])));
    assert!(!root.join("pass-4").exists());
    // A reset with the recorded hash: chpasswd -e, and the guest must keep it.
    let mut again = account.clone();
    again
        .provision_foreign(
            &disk,
            &guestfish,
            1024,
            &Password::Hashed(&hash),
            None,
            &boot_with(qemu),
        )
        .unwrap();
    assert_eq!(fs::read_to_string(root.join("fw-cfg-seen")).unwrap(), hash);
    assert!(!pass(6).contains("/etc/network/interfaces"));
    let other = format!("$6$fixturesalt${}", "a".repeat(86));
    let error = account
        .provision_foreign(
            &disk,
            &guestfish,
            1024,
            &Password::Hashed(&other),
            None,
            &boot_with(fake_qemu(
                &root,
                &format!("provision-hash-begin\\n{hash}\\nprovision-hash-end\\n"),
            )),
        )
        .unwrap_err();
    assert!(error.contains("did not keep"), "{error}");
    // A failed step, a silent boot, a missing QEMU: plain errors.
    for (console, expected) in [
        (
            "provision-failed boot-loader\\n",
            "failed at its boot-loader step",
        ),
        ("kernel panic\\n", "ended without reporting"),
    ] {
        let error = account
            .provision_foreign(
                &disk,
                &guestfish,
                1024,
                &Password::Plain(secret),
                None,
                &boot_with(fake_qemu(&root, console)),
            )
            .unwrap_err();
        assert!(
            error.starts_with("the arm64 VM's provisioning boot "),
            "{error}"
        );
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains(secret));
    }
    assert!(
        account
            .provision_foreign(
                &disk,
                &guestfish,
                1024,
                &Password::Plain(secret),
                None,
                &boot_with(root.join("missing-qemu")),
            )
            .is_err()
    );
    // Moving the NIC rewrites the stanza on the host.
    let before = fs::read_dir(&root).unwrap().count();
    account
        .set_interface_foreign(&disk, &guestfish, "enp0s31f6")
        .unwrap();
    assert_eq!(account.interface(), "enp0s31f6");
    let passes = fs::read_dir(&root).unwrap().count() - before;
    assert_eq!(passes, 6, "probe, read and write, with their argv");
    assert!(
        account
            .set_interface_foreign(&disk, &guestfish, "bad name")
            .is_err()
    );
    fs::remove_dir_all(root).unwrap();
}

/// Only a base of another architecture than x86-64 boots for its account,
/// with the QEMU of its machine; arm64's disk edits after creation follow.
#[test]
fn only_a_foreign_base_gets_a_provisioning_boot() {
    let options = crate::api::BackendOptions {
        qemu: "/opt/qemu/bin/qemu-system-x86_64".into(),
        ..crate::api::BackendOptions::default()
    };
    let mut bundle: storage::Bundle = serde_json::from_value(serde_json::json!({
        "kernel": "/b/kernel",
        "base_disk": "/b/base.qcow2",
        "initrd": "/b/initrd.gz",
        "kernel_append": "root=UUID=2da308b0-4365-44b4-9efd-3d5777536aaa ro quiet",
    }))
    .unwrap();
    assert!(
        ProvisionBoot::for_bundle(&options, &bundle)
            .unwrap()
            .is_none()
    );
    bundle.arch = crate::api::GuestArch::AARCH64;
    let boot = ProvisionBoot::for_bundle(&options, &bundle)
        .unwrap()
        .unwrap();
    assert_eq!(boot.qemu, Path::new("/opt/qemu/bin/qemu-system-aarch64"));
    assert_eq!(boot.initrd.as_deref(), Some(Path::new("/b/initrd.gz")));
    // No GRUB for BIOS on arm64: a new disk bus changes only the record.
    let mut account = GuestAccount::unprovisioned("analyst".into()).unwrap();
    account
        .set_boot_disk(Path::new("/nonexistent"), "/dev/nvme0n1", bundle.arch)
        .unwrap();
    assert_eq!(account.boot_disk(), "/dev/nvme0n1");
    assert!(
        account
            .set_boot_disk(Path::new("/nonexistent"), "/dev/vdb", bundle.arch)
            .is_err()
    );
}
