// SPDX-License-Identifier: GPL-3.0-only
use super::support::*;

#[test]
fn many_files_renamed_to_one_new_extension_is_a_ransomware_rewrite() {
    let renames: Calls = (0..25)
        .map(|n| {
            rename(
                1,
                &format!("/home/user/doc{n}.txt"),
                &format!("/home/user/doc{n}.txt.locked"),
            )
        })
        .collect();
    let out = run(renames);
    assert_eq!(tier(&out, "impact.ransom_rewrite").as_deref(), Some("high"));
    assert_eq!(
        list(rows(&out, "impact.ransom_rewrite")[0], "finding.technique"),
        ["T1486", "DET0215"]
    );
    let few: Calls = (0..5)
        .map(|n| {
            rename(
                1,
                &format!("/home/user/d{n}.txt"),
                &format!("/home/user/d{n}.locked"),
            )
        })
        .collect();
    assert!(!has(&run(few), "impact.ransom_rewrite"));
    let same: Calls = (0..25)
        .map(|n| {
            rename(
                1,
                &format!("/home/user/a{n}.txt"),
                &format!("/home/user/b{n}.txt"),
            )
        })
        .collect();
    assert!(
        !has(&run(same), "impact.ransom_rewrite"),
        "the same extension is an ordinary rename"
    );
}

#[test]
fn the_same_note_in_three_directories_is_a_ransom_note() {
    let note = |dir: &str| open_write(1, &format!("{dir}/README_DECRYPT.txt"), 3);
    let out = run(vec![
        note("/home/user/a"),
        note("/home/user/b"),
        note("/home/user/c"),
    ]);
    assert_eq!(tier(&out, "impact.ransom_note").as_deref(), Some("medium"));
    assert!(!has(
        &run(vec![note("/home/user/a"), note("/home/user/b")]),
        "impact.ransom_note"
    ));
    let makefile = |dir: &str| open_write(1, &format!("{dir}/Makefile"), 3);
    assert!(!has(
        &run(vec![
            makefile("/a"),
            makefile("/b"),
            makefile("/c"),
            makefile("/d")
        ]),
        "impact.ransom_note"
    ));
}

#[test]
fn deleting_a_hundred_files_it_did_not_create_is_a_mass_delete() {
    let deletes: Calls = (0..120)
        .map(|n| unlink(1, &format!("/home/user/dir{}/file{n}", n % 4)))
        .collect();
    assert_eq!(
        tier(&run(deletes), "impact.mass_delete").as_deref(),
        Some("high")
    );
    // Files the run made itself are its own cleanup.
    let mut own: Calls = (0..120)
        .map(|n| open_write(1, &format!("/tmp/w{}/f{n}", n % 4), 3))
        .collect();
    own.extend((0..120).map(|n| unlink(1, &format!("/tmp/w{}/f{n}", n % 4))));
    assert!(!has(&run(own), "impact.mass_delete"));
    let few: Calls = (0..20)
        .map(|n| unlink(1, &format!("/home/user/f{n}")))
        .collect();
    assert!(!has(&run(few), "impact.mass_delete"));
}

#[test]
fn writing_a_disk_or_erasing_a_block_device_is_high() {
    for path in [
        "/dev/sda",
        "/dev/vda1",
        "/dev/nvme0n1",
        "/dev/mmcblk0",
        "/dev/mtd0",
        "/dev/loop0",
        "/dev/dm-0",
    ] {
        let out = run(vec![open(1, path, 1, 3), write(1, 3, b"\0\0\0\0")]);
        assert_eq!(
            tier(&out, "impact.block_device_write").as_deref(),
            Some("high"),
            "{path}"
        );
    }
    assert!(
        !has(
            &run(vec![open_read(1, "/dev/sda", 3)]),
            "impact.block_device_write"
        ),
        "reading a disk is not wiping it"
    );
    let wipe = run(vec![
        open(1, "/dev/sdb", 1, 3),
        sys(1, 16, "ioctl", [3, 0x127f, 0, 0, 0, 0], 0),
    ]);
    assert!(has(&wipe, "impact.block_device_write"));
    assert!(!has(
        &run(vec![open(1, "/dev/null", 1, 3)]),
        "impact.block_device_write"
    ));
}

#[test]
fn rebooting_or_replacing_the_kernel_is_high() {
    let reboot = |command: u64| {
        run(vec![sys(
            1,
            169,
            "reboot",
            [0xfee1_dead, 672274793, command, 0, 0, 0],
            0,
        )])
    };
    for command in [
        0x0123_4567u64,
        0xCDEF_0123,
        0x4321_FEDC,
        0xA1B2_C3D4,
        0x4558_4543,
    ] {
        assert_eq!(
            tier(&reboot(command), "impact.reboot").as_deref(),
            Some("high"),
            "{command:#x}"
        );
    }
    assert!(
        !has(&reboot(0x89AB_CDEF), "impact.reboot"),
        "Ctrl-Alt-Del handling is not a reboot"
    );
    assert!(has(
        &run(vec![sys(1, 246, "kexec_load", [0; 6], 0)]),
        "impact.reboot"
    ));
    assert!(has(
        &run(vec![sys(1, 320, "kexec_file_load", [0; 6], 0)]),
        "impact.reboot"
    ));
    for argv in [
        vec!["reboot"],
        vec!["shutdown", "-h", "now"],
        vec!["poweroff"],
        vec!["init", "6"],
        vec!["systemctl", "reboot"],
    ] {
        let path = format!("/sbin/{}", argv[0]);
        assert!(
            has(&run(vec![exec(1, &path, &argv)]), "impact.reboot"),
            "{argv:?}"
        );
    }
    assert!(!has(
        &run(vec![exec(1, "/sbin/init", &["init", "2"])]),
        "impact.reboot"
    ));
}

#[test]
fn mining_is_found_in_arguments_names_and_stratum_traffic() {
    for argv in [
        vec![
            "xmrig",
            "-o",
            "stratum+tcp://pool.example:3333",
            "-u",
            "wallet",
        ],
        vec![
            "./kworker",
            "--donate-level=1",
            "-o",
            "pool.minexmr.com:4444",
        ],
        vec!["minerd", "-a", "cryptonight"],
    ] {
        let path = format!("/tmp/{}", argv[0].trim_start_matches("./"));
        assert_eq!(
            tier(&run(vec![exec(1, &path, &argv)]), "impact.miner").as_deref(),
            Some("high"),
            "{argv:?}"
        );
    }
    let login = br#"{"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"w","pass":"x","agent":"xmrig/6"}}"#;
    let wire = run(vec![
        socket(1, 2, 1, 3),
        connect(1, 3, [203, 0, 113, 9], 3333),
        with_entry(
            sys(
                1,
                1,
                "write",
                [3, 0, login.len() as u64, 0, 0, 0],
                login.len() as i64,
            ),
            "arg1.data",
            login,
        ),
    ]);
    assert!(has(&wire, "impact.miner"));
    let subscribe = br#"{"id":1,"method":"mining.subscribe","params":[]}"#;
    let eth = run(vec![
        socket(1, 2, 1, 3),
        connect(1, 3, [203, 0, 113, 9], 3333),
        with_entry(
            sys(
                1,
                1,
                "write",
                [3, 0, subscribe.len() as u64, 0, 0, 0],
                subscribe.len() as i64,
            ),
            "arg1.data",
            subscribe,
        ),
    ]);
    assert!(has(&eth, "impact.miner"));
    assert!(!has(
        &run(vec![exec(
            1,
            "/usr/bin/curl",
            &["curl", "-o", "x.html", "http://example.test"]
        )]),
        "impact.miner"
    ));
}

#[test]
fn tuning_the_machine_for_mining_is_medium() {
    for path in [
        "/proc/sys/vm/nr_hugepages",
        "/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages",
        "/dev/cpu/0/msr",
    ] {
        let out = run(vec![open_write(1, path, 3), write(1, 3, b"1280")]);
        assert_eq!(
            tier(&out, "impact.miner_tuning").as_deref(),
            Some("medium"),
            "{path}"
        );
    }
    assert!(has(
        &run(vec![exec(1, "/sbin/modprobe", &["modprobe", "msr"])]),
        "impact.miner_tuning"
    ));
    assert!(!has(
        &run(vec![open_read(1, "/proc/sys/vm/nr_hugepages", 3)]),
        "impact.miner_tuning"
    ));
}

#[test]
fn a_runaway_fork_loop_is_medium_with_or_without_failures() {
    let forks: Calls = (0..300u64)
        .map(|n| at(fork(1, 100 + n as i64), n * MS))
        .collect();
    assert_eq!(
        tier(&run(forks), "impact.fork_bomb").as_deref(),
        Some("medium")
    );
    let refused: Calls = (0..30u64).map(|n| at(fork(1, -11), n * 100 * MS)).collect();
    assert!(has(&run(refused), "impact.fork_bomb"));
    let busy: Calls = (0..50u64)
        .map(|n| at(fork(1, 100 + n as i64), n * 100 * MS))
        .collect();
    assert!(!has(&run(busy), "impact.fork_bomb"));
    let threads: Calls = (0..300u64)
        .map(|n| {
            at(
                sys(1, 56, "clone", [0x0001_0000, 0, 0, 0, 0, 0], 100 + n as i64),
                n * MS,
            )
        })
        .collect();
    assert!(
        !has(&run(threads), "impact.fork_bomb"),
        "threads are not processes"
    );
}

#[test]
fn stopping_services_and_removing_recovery_are_medium() {
    for script in [
        "systemctl stop mysql",
        "systemctl disable postgresql",
        "service nginx stop",
        "esxcli vm process kill --type=force --world-id=1",
        "vim-cmd vmsvc/power.off 1",
    ] {
        assert!(
            has(&run(vec![shell(1, script)]), "impact.service_stop"),
            "{script}"
        );
    }
    assert!(!has(
        &run(vec![shell(1, "systemctl status mysql")]),
        "impact.service_stop"
    ));
    for script in [
        "lvremove -f vg/snap",
        "btrfs subvolume delete /snap",
        "vim-cmd vmsvc/snapshot.removeall 1",
        "zfs destroy pool@snap",
    ] {
        assert!(
            has(&run(vec![shell(1, script)]), "impact.inhibit_recovery"),
            "{script}"
        );
    }
    for path in [
        "/var/backups/dpkg.status.0",
        "/backup1/db.tar",
        "/home/user/file.bak",
    ] {
        assert!(
            has(&run(vec![unlink(1, path)]), "impact.inhibit_recovery"),
            "{path}"
        );
    }
    assert!(!has(
        &run(vec![unlink(1, "/tmp/x")]),
        "impact.inhibit_recovery"
    ));
}

#[test]
fn input_devices_the_screen_the_microphone_and_the_clipboard_are_collection() {
    for (path, rule, expected) in [
        ("/dev/input/event3", "collection.keylog", "medium"),
        ("/dev/uinput", "collection.keylog", "medium"),
        ("/dev/fb0", "collection.screen_capture", "low"),
        ("/dev/video0", "collection.av_capture", "low"),
        ("/dev/snd/pcmC0D0c", "collection.av_capture", "low"),
    ] {
        let out = run(vec![open_read(1, path, 3)]);
        assert_eq!(tier(&out, rule).as_deref(), Some(expected), "{path}");
    }
    assert!(
        !has(
            &run(vec![open_read(1, "/dev/snd/pcmC0D0p", 3)]),
            "collection.av_capture"
        ),
        "playback is not capture"
    );
    for (argv, rule) in [
        (vec!["scrot", "/tmp/s.png"], "collection.screen_capture"),
        (
            vec!["import", "-window", "root", "x.png"],
            "collection.screen_capture",
        ),
        (vec!["arecord", "-d", "5", "x.wav"], "collection.av_capture"),
        (
            vec!["ffmpeg", "-f", "v4l2", "-i", "/dev/video0", "x.mp4"],
            "collection.av_capture",
        ),
        (vec!["xclip", "-o"], "collection.clipboard"),
        (vec!["xsel", "-o"], "collection.clipboard"),
        (vec!["wl-paste"], "collection.clipboard"),
    ] {
        let path = format!("/usr/bin/{}", argv[0]);
        assert!(has(&run(vec![exec(1, &path, &argv)]), rule), "{argv:?}");
    }
    assert!(
        !has(
            &run(vec![exec(1, "/usr/bin/xclip", &["xclip", "-i", "x"])]),
            "collection.clipboard"
        ),
        "filling the clipboard is not reading it"
    );
    let tty = run(vec![sys(1, 16, "ioctl", [0, 0x5412, 0x1000, 0, 0, 0], 0)]);
    assert_eq!(
        tier(&tty, "collection.tty_inject").as_deref(),
        Some("medium")
    );
    assert!(list(rows(&tty, "collection.tty_inject")[0], "finding.technique").is_empty());
}

#[test]
fn archiving_home_data_into_a_staging_directory_is_medium() {
    for argv in [
        vec!["tar", "czf", "/tmp/.a.tgz", "/home/user/Documents"],
        vec!["zip", "-r", "/dev/shm/x.zip", "/root/.ssh"],
        vec!["7z", "a", "/tmp/x.7z", "/home/user"],
    ] {
        let path = format!("/usr/bin/{}", argv[0]);
        assert_eq!(
            tier(
                &run(vec![exec(1, &path, &argv)]),
                "collection.archive_staging"
            )
            .as_deref(),
            Some("medium"),
            "{argv:?}"
        );
    }
    assert!(!has(
        &run(vec![exec(
            1,
            "/usr/bin/tar",
            &["tar", "czf", "/var/backups/a.tgz", "/etc"]
        )]),
        "collection.archive_staging"
    ));
    assert!(!has(
        &run(vec![exec(1, "/usr/bin/tar", &["tar", "xf", "/tmp/x.tar"])]),
        "collection.archive_staging"
    ));
}
