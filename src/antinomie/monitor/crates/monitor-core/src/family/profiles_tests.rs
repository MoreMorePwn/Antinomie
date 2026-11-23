// SPDX-License-Identifier: GPL-3.0-only
//! The family profile format, the shipped profiles and their thresholds.
//! Every run here is made up, in the shape of what a real run records.
use super::*;

fn seen(findings: &[&str], paths: &[&str], network: &[&str], commands: &[&str]) -> Seen {
    let own = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect();
    Seen {
        findings: own(findings),
        paths: own(paths),
        network: own(network),
        commands: own(commands),
    }
    .tidy()
}

/// One made-up run per shipped profile.
fn runs() -> Vec<(&'static str, Seen)> {
    let long_uri = format!("http://203.0.113.7:8080/{}", "aB3_-x9Zq".repeat(6));
    vec![
        (
            "Prometei",
            seen(
                &[],
                &["/usr/sbin/uplugplay"],
                &["http://203.0.113.5/cgi-bin/p.cgi?r=12&i=AB12CD34"],
                &[],
            ),
        ),
        (
            "Kaiji",
            seen(
                &["evasion.proc_hide_mount"],
                &[
                    "/etc/32676",
                    "/etc/init.d/linux_kill",
                    "/etc/id.services.conf",
                ],
                &[],
                &["renice -20 77"],
            ),
        ),
        (
            "Chaos",
            seen(
                &["evasion.proc_hide_mount"],
                &["/boot/system.pub", "/etc/init.d/dns-udp4", "/.mod"],
                &[],
                &[],
            ),
        ),
        (
            "XorDDoS",
            seen(
                &["persistence.cron", "persistence.rc_init"],
                &["/etc/cron.hourly/gcc.sh", "/usr/bin/qwertyuiop"],
                &[],
                &[],
            ),
        ),
        (
            "BillGates",
            seen(
                &[],
                &[
                    "/etc/init.d/DbSecuritySpt",
                    "/usr/bin/bsd-port/getty",
                    "/tmp/moni.lod",
                ],
                &[],
                &[],
            ),
        ),
        (
            "Dofloo",
            seen(
                &["persistence.rc_init"],
                &[],
                &[],
                &["sed -i -e '2 i/tmp/sample reboot' /etc/rc.local"],
            ),
        ),
        (
            "BPFDoor",
            seen(&["c2.bpf_backdoor"], &["/var/run/haldrund.pid"], &[], &[]),
        ),
        (
            "RotaJakiro",
            seen(
                &[],
                &[
                    "/home/user/.gvfsd/.profile/gvfsd-helper",
                    "/home/user/.dbus/sessions/session-dbus",
                ],
                &[],
                &[],
            ),
        ),
        (
            "Mirai",
            seen(
                &[
                    "evasion.watchdog_disable",
                    "network.raw_socket",
                    "discovery.network_scan",
                ],
                &["/dev/FTWDT101_watchdog"],
                &[],
                &[],
            ),
        ),
        (
            "Sliver",
            seen(
                &["network.c2_ip_literal"],
                &[],
                &["http://203.0.113.9/assets/bundles/main.js?k=123456"],
                &[],
            ),
        ),
        (
            "Mettle",
            seen(
                &[],
                &["/etc/xensource-inventory", "/etc/mandrake-release"],
                &[long_uri.as_str()],
                &[],
            ),
        ),
        ("XMRig", seen(&[], &["/root/.xmrig.json"], &[], &[])),
        ("Kinsing", seen(&[], &["/tmp/kdevtmpfsi"], &[], &[])),
        (
            "Tsunami",
            seen(
                &["network.irc_c2"],
                &["/usr/dict/words", "/etc/rc.conf"],
                &[],
                &[],
            ),
        ),
        (
            "VPNFilter",
            seen(
                &[],
                &["/etc/config/crontab"],
                &["toknowall.com", "GET photobucket.com/user/someone/library"],
                &[],
            ),
        ),
    ]
}

#[test]
fn every_shipped_file_parses_and_names_one_family() {
    let mut names = Vec::new();
    for (file, text) in SHIPPED {
        let list = parse(text, file).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(list.len(), 1, "{file}");
        assert!(!list[0].references.is_empty(), "{file}: cite the sources");
        names.push(list[0].name.clone());
    }
    let count = names.len();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), count, "one profile per family");
    assert_eq!(shipped().len(), SHIPPED.len());
}

#[test]
fn each_profile_names_its_family_and_no_other() {
    let profiles = shipped();
    let made_up = runs();
    assert_eq!(made_up.len(), profiles.len(), "a run for every profile");
    for (family, run) in &made_up {
        let found = matching(&profiles, run, &Rules::default());
        let names: Vec<&str> = found.iter().map(|m| m.family.as_str()).collect();
        assert_eq!(names, [*family], "{family}: {found:?}");
        assert!(
            found[0]
                .source
                .starts_with(&format!("behaviour profile {family} \u{b7} ")),
            "{}",
            found[0].source
        );
        assert!(found[0].points > BASE_POINTS && found[0].points <= MAX_POINTS);
    }
}

#[test]
fn generic_markers_alone_name_no_family() {
    let profiles = shipped();
    // Watchdog, raw socket, scan and telnet login without a distinctive
    // marker: Kaiji and other bots do all of this too.
    let bot = seen(
        &[
            "evasion.watchdog_disable",
            "network.raw_socket",
            "discovery.network_scan",
            "network.inetsim_telnet_login",
            "persistence.cron",
            "persistence.rc_init",
            "evasion.proc_hide_mount",
        ],
        &["/dev/watchdog", "/dev/misc/watchdog", "/.mod"],
        &[],
        &[],
    );
    assert!(matching(&profiles, &bot, &Rules::default()).is_empty());
    // One distinctive Kaiji path is not enough (two are needed).
    let one = seen(
        &["evasion.proc_hide_mount"],
        &["/etc/32676"],
        &[],
        &["renice -20 1"],
    );
    assert!(matching(&profiles, &one, &Rules::default()).is_empty());
    // Prometei's single marker is enough, as its behaviour signature was.
    let prometei = seen(&[], &["/lib/systemd/system/uplugplay.service"], &[], &[]);
    let found = matching(&profiles, &prometei, &Rules::default());
    assert_eq!(found[0].family, "Prometei");
    assert_eq!(found[0].points, 200);
}

#[test]
fn texts_of_unknown_kind_count_as_paths_urls_and_commands() {
    let texts = Seen::of_texts(&["GET 198.51.100.2/cgi-bin/p.cgi?r=1&i=X", ""]).tidy();
    assert_eq!(texts.paths.len(), 1);
    let found = matching(&shipped(), &texts, &Rules::default());
    assert_eq!(found[0].family, "Prometei");
}

#[test]
fn sigma_ids_yara_rules_and_tags_are_markers() {
    let text = r#"
[[profile]]
name = "Testbot"
min_markers = 2
min_distinctive = 1
[[profile.marker]]
sigma = "9e1bef8d-0fff-46f6-8465-9aa54e128c1e"
distinctive = true
[[profile.marker]]
yara_tag = "mirai-like"
[[profile.marker]]
yara_rule = "^ELF_Test_"
"#;
    let profiles = parse(text, "test").unwrap();
    let rules = Rules {
        sigma: vec!["9E1BEF8D-0FFF-46F6-8465-9AA54E128C1E"],
        yara: vec!["ELF_Test_Bot"],
        tags: vec!["Mirai-like".into()],
    };
    let found = matching(&profiles, &Seen::default(), &rules);
    assert_eq!(found.len(), 1);
    assert!(
        found[0].source.contains("3 of 3 markers"),
        "{}",
        found[0].source
    );
    assert!(
        found[0].source.contains("Sigma 9e1bef8d"),
        "{}",
        found[0].source
    );
    let without_sigma = Rules {
        sigma: Vec::new(),
        ..rules
    };
    assert!(matching(&profiles, &Seen::default(), &without_sigma).is_empty());
}

#[test]
fn a_profile_for_another_platform_is_skipped() {
    let text = r#"
[[profile]]
name = "Winbot"
platforms = ["windows"]
[[profile.marker]]
path = "/tmp/x"
distinctive = true
"#;
    let profiles = parse(text, "test").unwrap();
    let run = seen(&[], &["/tmp/x"], &[], &[]);
    assert!(matching(&profiles, &run, &Rules::default()).is_empty());
    let any = parse(&text.replace("\"windows\"", "\"any\""), "test").unwrap();
    assert_eq!(matching(&any, &run, &Rules::default()).len(), 1);
}

#[test]
fn bad_profiles_are_refused_with_the_reason() {
    let cases = [
        (
            "name = \"\"\n[[profile.marker]]\npath = \"/x\"\ndistinctive = true",
            "no name",
        ),
        ("name = \"A\"", "no marker"),
        (
            "name = \"A\"\n[[profile.marker]]\npath = \"/x\"\nurl = \"y\"\ndistinctive = true",
            "exactly one of",
        ),
        (
            "name = \"A\"\n[[profile.marker]]\npath = \"/x\"",
            "only 0 marker(s) are distinctive",
        ),
        (
            "name = \"A\"\nmin_distinctive = 0\n[[profile.marker]]\npath = \"/x\"\ndistinctive = true",
            "at least 1",
        ),
        (
            "name = \"A\"\nmin_markers = 3\n[[profile.marker]]\npath = \"/x\"\ndistinctive = true",
            "min_markers",
        ),
        (
            "name = \"A\"\n[[profile.marker]]\npath_regex = \"(\"\ndistinctive = true",
            "marker 1",
        ),
        (
            "name = \"A\"\n[[profile.marker]]\npath = \"/x\"\nweight = 0\ndistinctive = true",
            "weight",
        ),
        (
            "name = \"A\"\n[[profile.marker]]\npath = \"  \"\ndistinctive = true",
            "empty",
        ),
        (
            "name = \"A\"\ncolour = 1\n[[profile.marker]]\npath = \"/x\"\ndistinctive = true",
            "unknown field",
        ),
    ];
    for (body, reason) in cases {
        let text = format!("[[profile]]\n{body}\n");
        let error = parse(&text, "user.toml").unwrap_err();
        assert!(error.contains(reason), "{body}: {error}");
        assert!(error.starts_with("user.toml"), "{error}");
    }
}

#[test]
fn user_profiles_add_to_and_replace_the_shipped_ones() {
    let dir = std::env::temp_dir().join(format!("antinomie-profiles-{}", std::process::id()));
    let families = dir.join(USER_DIR);
    std::fs::create_dir_all(&families).unwrap();
    std::fs::write(
        families.join("a.toml"),
        "[[profile]]\nname = \"prometei\"\n[[profile.marker]]\npath = \"/opt/own\"\ndistinctive = true\n",
    )
    .unwrap();
    std::fs::write(
        families.join("b.toml"),
        "[[profile]]\nname = \"Newbot\"\n[[profile.marker]]\ncommand = \"newbot --run\"\ndistinctive = true\n",
    )
    .unwrap();
    std::fs::write(families.join("c.toml"), "[[profile]]\nname = 3\n").unwrap();
    std::fs::write(families.join("notes.txt"), "not a profile").unwrap();
    let (profiles, problems) = load(Some(&dir));
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("c.toml"), "{problems:?}");
    assert_eq!(profiles.len(), shipped().len() + 1);
    let own = seen(&[], &["/opt/own"], &[], &["newbot --run"]);
    let mut names: Vec<String> = matching(&profiles, &own, &Rules::default())
        .into_iter()
        .map(|m| m.family)
        .collect();
    names.sort();
    assert_eq!(names, ["Newbot", "prometei"]);
    // The shipped Prometei profile was replaced, not kept beside it.
    let shipped_marker = seen(&[], &["/usr/sbin/uplugplay"], &[], &[]);
    assert!(matching(&profiles, &shipped_marker, &Rules::default()).is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
    // No data directory, or none with profiles: the shipped ones.
    assert_eq!(load(None).0.len(), shipped().len());
    assert!(load(Some(&dir)).1.is_empty());
}
