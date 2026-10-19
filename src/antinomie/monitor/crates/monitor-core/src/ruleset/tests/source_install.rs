// SPDX-License-Identifier: MIT
use super::source_fixture::*;
use super::*;
use std::sync::atomic::AtomicBool;

fn install(
    dir: &Path,
    pack: &SourcePack,
    options: &[&str],
    fixture: &Fixture,
) -> Result<SourceInstall, String> {
    let options = options.iter().map(|id| (*id).to_owned()).collect();
    install_source(dir, pack, &options, fixture, &no_cancel(), &mut |_| {})
}

fn names(dir: &Path, pack: &str) -> Vec<String> {
    let mut found: Vec<String> = pack_index(dir, "yara", pack)
        .unwrap()
        .into_iter()
        .map(|rule| rule.name)
        .collect();
    found.sort();
    found
}

#[test]
fn the_license_fallback_keeps_rules_from_openly_licensed_repositories() {
    let dir = temp_dir("fallback");
    let (pack, fixture) = forge_pack();
    let installed = install(&dir, &pack, &[], &fixture).unwrap();
    // Own license allowed, or none and the repository's license allowed.
    // Dropped: an own license that is not allowed, a repository without a
    // license or missing from the table, rules that do not compile and the
    // rule that needs one of them.
    assert_eq!(
        names(&dir, "forge-core"),
        [
            "Broken_Fine",
            "Closed_Own",
            "Open_Own",
            "Open_Plain",
            "Open_Pointer",
            "Stray_Plain"
        ]
    );
    assert_eq!(installed.rules, 6);
    let report = installed.provenance.summary.join("\n");
    assert!(report.contains("2 by its own license"), "{report}");
    assert!(report.contains("4 by the repository's license"), "{report}");
    assert!(
        report.contains("because its own license is not an allowed one"),
        "{report}"
    );
    assert!(
        report.contains("because its repository has no license"),
        "{report}"
    );
    assert!(
        report.contains("because it does not compile with YARA-X"),
        "{report}"
    );
    assert_eq!(installed.provenance.dropped_rules, 2 + 2 + 2);

    // The pack carries the repository license where findings can show it.
    let open = fs::read_to_string(
        rules_root(&dir)
            .join("packs/yara/forge-core")
            .join(&installed.version)
            .join("open.yar"),
    )
    .unwrap();
    let plain = open.split("rule Open_Plain").nth(1).unwrap();
    assert!(
        plain
            .split("rule ")
            .next()
            .unwrap()
            .contains("antinomie_repo_license = \"BSD-2-Clause (repository https://github.com/example/open-rules)\""),
        "{open}"
    );
    let own = open.split("rule Open_Own").nth(1).unwrap();
    assert!(
        !own.split("rule ")
            .next()
            .unwrap()
            .contains("antinomie_repo_license")
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn rules_without_a_repository_license_install_only_on_explicit_opt_in() {
    let dir = temp_dir("optin");
    let (pack, fixture) = forge_pack();
    assert!(pack.default_options().is_empty());
    install(&dir, &pack, &[], &fixture).unwrap();
    let off = names(&dir, "forge-core");
    assert!(
        !off.iter()
            .any(|name| name == "Closed_Plain" || name == "Unlisted_Plain")
    );

    let on = install(&dir, &pack, &["include-unlicensed"], &fixture).unwrap();
    let with = names(&dir, "forge-core");
    assert!(with.iter().any(|name| name == "Closed_Plain"));
    assert!(with.iter().any(|name| name == "Unlisted_Plain"));
    // A rule with an explicit license that is not allowed stays out.
    assert!(
        !with
            .iter()
            .any(|name| name == "Closed_Bad" || name == "Open_Bad")
    );
    assert_eq!(on.provenance.options, ["include-unlicensed"]);
    let closed = fs::read_to_string(
        rules_root(&dir)
            .join("packs/yara/forge-core")
            .join(&on.version)
            .join("closed.yar"),
    )
    .unwrap();
    assert!(
        closed.contains("none: all rights reserved, local use only"),
        "{closed}"
    );

    // The two installs are different versions; the registry records the option.
    let registry = load_registry(&dir).unwrap();
    let installed = &registry.packs[0];
    assert_eq!(installed.versions.len(), 2);
    assert_eq!(
        installed.source.as_ref().unwrap().options,
        ["include-unlicensed"]
    );
    // Turning it off again selects the retained default version without a download.
    let before = fixture.requested();
    let back = install(&dir, &pack, &[], &fixture).unwrap();
    assert!(back.already_installed);
    assert_eq!(fixture.requested(), before);
    assert!(
        load_registry(&dir).unwrap().packs[0]
            .source
            .as_ref()
            .unwrap()
            .options
            .is_empty()
    );

    let error = install(&dir, &pack, &["accept-anything"], &fixture).unwrap_err();
    assert!(error.contains("unknown option"), "{error}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_changed_download_is_rejected_and_installs_nothing() {
    let dir = temp_dir("tamper");
    let (pack, _) = forge_pack();
    // The whole download differs from the pinned checksum.
    let other = zip_bytes(&[(FORGE_PATH, "rule Evil { condition: true }")]);
    let swapped = Fixture::default().with(FORGE_URL, other.clone());
    let error = install(&dir, &pack, &[], &swapped).unwrap_err();
    assert!(
        error.contains("does not match the catalog checksum"),
        "{error}"
    );

    // A catalog that pins files only: one file is replaced inside a valid archive.
    let mut by_file = pack.clone();
    by_file.sources[0].sha256.clear();
    by_file.sources[0].size = other.len() as u64;
    let error = install(&dir, &by_file, &[], &swapped).unwrap_err();
    assert!(
        error.contains("does not match the catalog (expected"),
        "{error}"
    );
    assert!(error.contains(FORGE_PATH), "{error}");

    // The pinned file is missing from the archive.
    let empty = zip_bytes(&[("other.txt", "x")]);
    let mut missing = by_file.clone();
    missing.sources[0].size = empty.len() as u64;
    let error = install(
        &dir,
        &missing,
        &[],
        &Fixture::default().with(FORGE_URL, empty),
    )
    .unwrap_err();
    assert!(error.contains("no longer holds"), "{error}");

    assert!(load_registry(&dir).unwrap().packs.is_empty());
    assert!(!rules_root(&dir).join("packs/yara/forge-core").exists());
    let staging = rules_root(&dir).join("staging");
    assert!(!staging.exists() || fs::read_dir(staging).unwrap().next().is_none());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_failed_install_keeps_the_previous_selection() {
    let dir = temp_dir("keep");
    let (pack, fixture) = forge_pack();
    let first = install(&dir, &pack, &[], &fixture).unwrap();
    let mut newer = pack.clone();
    newer.revision = "2".into();
    // The new pin points at a download that is gone.
    let error = install(&dir, &newer, &[], &Fixture::default()).unwrap_err();
    assert!(error.contains("404"), "{error}");
    let registry = load_registry(&dir).unwrap();
    assert_eq!(registry.packs[0].version, first.version);
    assert_eq!(registry.packs[0].versions.len(), 1);

    // A write failure while registering also leaves the old version selected.
    fail_once("source-install");
    let error = install(&dir, &newer, &[], &fixture).unwrap_err();
    assert!(error.contains("No space left"), "{error}");
    assert_eq!(load_registry(&dir).unwrap().packs[0].version, first.version);
    assert!(
        !rules_root(&dir)
            .join("packs/yara/forge-core")
            .join(newer.version(&BTreeSet::new()))
            .exists()
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn cancelling_stops_before_anything_is_registered() {
    let dir = temp_dir("cancel");
    let (pack, fixture) = forge_pack();
    let cancel = AtomicBool::new(true);
    let error = install_source(
        &dir,
        &pack,
        &BTreeSet::new(),
        &fixture,
        &cancel,
        &mut |_| {},
    )
    .unwrap_err();
    assert_eq!(error, "cancelled");
    assert!(load_registry(&dir).unwrap().packs.is_empty());
    // Cancelling after the download, from the progress callback.
    let flag = AtomicBool::new(false);
    let error = install_source(
        &dir,
        &pack,
        &BTreeSet::new(),
        &fixture,
        &flag,
        &mut |line| {
            if line.starts_with("Verifying") {
                flag.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        },
    )
    .unwrap_err();
    assert_eq!(error, "cancelled");
    assert!(load_registry(&dir).unwrap().packs.is_empty());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn provenance_reaches_the_registry_the_rule_set_list_and_scan_manifests() {
    let dir = temp_dir("prov");
    let (pack, fixture) = forge_pack();
    let installed = install(&dir, &pack, &[], &fixture).unwrap();
    let registry = load_registry(&dir).unwrap();
    let source = registry.packs[0].source.clone().unwrap();
    assert_eq!(source.revision, "1");
    assert_eq!(source.homepage, "https://github.com/example/forge");
    assert_eq!(source.sources[0].url, FORGE_URL);
    assert_eq!(source.sources[0].host, "github.com");
    assert!(source.sources[0].verified);
    assert_eq!(source.sources[0].download_sha256, pack.sources[0].sha256);
    assert!(source.line().contains("github.com/example/forge"));
    assert_eq!(source, installed.provenance);

    let manifest: Value = serde_json::from_slice(
        &fs::read(
            rules_root(&dir)
                .join("packs/yara/forge-core")
                .join(&installed.version)
                .join("manifest.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["source"]["revision"], "1");
    assert_eq!(manifest["source_files"][0]["path"], FORGE_PATH);

    let facts = installed_engines();
    let snap = snapshot_from(&dir, "yara", &registry, &facts, None).unwrap();
    assert_eq!(snap.enabled_rules, 6, "{:?}", snap.warnings);
    let selection: Value =
        serde_json::from_slice(&fs::read(snap.directory.unwrap().join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(selection["packs"][0]["source"]["revision"], "1");
    assert_eq!(
        selection["packs"][0]["source"]["sources"][0]["url"],
        FORGE_URL
    );
    let sets = engine_sets(&dir, &registry, "yara");
    assert_eq!(sets[0].rules, 6);
    assert!(sets[0].source.contains("github.com/example/forge"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn the_catalog_reports_an_update_only_for_a_new_pin() {
    let dir = temp_dir("update");
    let (pack, fixture) = forge_pack();
    install(&dir, &pack, &[], &fixture).unwrap();
    let installed = load_registry(&dir).unwrap().packs[0].clone();
    let catalog = Catalog {
        schema: 2,
        packs: Vec::new(),
        sources: vec![pack.clone()],
    };
    assert!(source_update(&catalog, &installed).is_none());
    let mut newer = pack.clone();
    newer.revision = "2".into();
    let catalog = Catalog {
        sources: vec![newer],
        ..catalog
    };
    assert_eq!(source_update(&catalog, &installed).unwrap().revision, "2");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn rolling_downloads_record_a_difference_instead_of_failing() {
    let dir = temp_dir("rolling");
    let rules = "alert tcp any any -> any any (msg:\"one\"; sid:1; rev:1;)\n";
    let newer = "alert tcp any any -> any any (msg:\"one\"; sid:1; rev:2;)\nalert tcp any any -> any any (msg:\"two\"; sid:2; rev:1;)\n";
    let url = "https://rules.example.org/open/all.rules";
    let pack = SourcePack {
        id: "rolling-ids".into(),
        engine: "ids".into(),
        name: "Rolling IDS".into(),
        homepage: "https://rules.example.org/".into(),
        license: "BSD".into(),
        license_url: String::new(),
        revision: "2026-10-17".into(),
        revision_kind: "rolling".into(),
        app: ">=0.6.2".into(),
        engine_requirement: "Suricata 7".into(),
        rules: 1,
        helpers: 0,
        evidence: vec!["pcap".into()],
        limits: Vec::new(),
        sources: vec![SourceFetch {
            url: url.into(),
            format: "file".into(),
            size: rules.len() as u64,
            sha256: sha(rules.as_bytes()),
            rolling: true,
            strip: 0,
            paths: Vec::new(),
            files: vec![SourceFile {
                path: "all.rules".into(),
                sha256: sha(rules.as_bytes()),
            }],
        }],
        filter: SourceFilter::Copy {
            extensions: vec![".rules".into()],
            support: Vec::new(),
        },
        options: Vec::new(),
        notices: Vec::new(),
    };
    // Unchanged: verified.
    let same = Fixture::default().with(url, rules.as_bytes().to_vec());
    let first = install(&dir, &pack, &[], &same).unwrap();
    assert!(first.provenance.sources[0].verified);
    // The publisher moved on: installed, recorded as different.
    let dir2 = temp_dir("rolling2");
    let moved = Fixture::default().with(url, newer.as_bytes().to_vec());
    let second = install(&dir2, &pack, &[], &moved).unwrap();
    assert!(!second.provenance.sources[0].verified);
    assert_eq!(second.provenance.sources[0].changed_files, 1);
    assert!(second.provenance.notes[0].contains("differs from the catalog"));
    assert_eq!(second.rules, 2);
    assert_eq!(
        second.provenance.sources[0].download_sha256,
        sha(newer.as_bytes())
    );
    // A pinned source with the same change would have been refused.
    let mut pinned = pack.clone();
    pinned.sources[0].rolling = false;
    pinned.revision_kind = "release".into();
    let error = install(&temp_dir("rolling3"), &pinned, &[], &moved).unwrap_err();
    assert!(
        error.contains("more than") || error.contains("does not match"),
        "{error}"
    );
    let _ = fs::remove_dir_all(dir);
    let _ = fs::remove_dir_all(dir2);
}

#[test]
fn rollback_restores_the_source_of_the_older_version() {
    let dir = temp_dir("rollback");
    let (pack, fixture) = forge_pack();
    let first = install(&dir, &pack, &[], &fixture).unwrap();
    let with = install(&dir, &pack, &["include-unlicensed"], &fixture).unwrap();
    assert_ne!(first.version, with.version);
    assert_eq!(
        load_registry(&dir).unwrap().packs[0]
            .source
            .as_ref()
            .unwrap()
            .options
            .len(),
        1
    );
    rollback(&dir, "forge-core", &first.version).unwrap();
    let registry = load_registry(&dir).unwrap();
    assert_eq!(registry.packs[0].version, first.version);
    assert!(
        registry.packs[0]
            .source
            .as_ref()
            .unwrap()
            .options
            .is_empty()
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_hosted_archive_install_still_works_and_clears_source_provenance() {
    let dir = temp_dir("v1");
    let bytes = archive(&[("one.yar", "rule Real { condition: true }\n")]);
    let listed = entry(&sha(&bytes), bytes.len() as u64);
    install_archive(&dir, &listed, &bytes).unwrap();
    let registry = load_registry(&dir).unwrap();
    assert!(registry.packs[0].source.is_none());
    let raw = fs::read_to_string(rules_root(&dir).join("registry.json")).unwrap();
    // A registry written before sources existed has no `source` key and still loads.
    let mut value: Value = serde_json::from_str(&raw).unwrap();
    value["packs"][0].as_object_mut().unwrap().remove("source");
    fs::write(rules_root(&dir).join("registry.json"), value.to_string()).unwrap();
    assert!(load_registry(&dir).unwrap().packs[0].source.is_none());
    let _ = fs::remove_dir_all(dir);
}

fn sigma_doc(title: &str, id: &str, logsource: &str) -> String {
    format!(
        "title: {title}\nid: {id}\nstatus: test\nlogsource:\n{logsource}\ndetection:\n    selection:\n        Image|endswith: '/bin/sh'\n    condition: selection\nlevel: low\n"
    )
}

#[test]
fn sigma_keeps_the_listed_log_sources_and_marks_unevaluated_ones_with_a_reason() {
    let dir = temp_dir("sigma");
    let ids = [
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333",
        "44444444-4444-4444-8444-444444444444",
        "55555555-5555-4555-8555-555555555555",
        "66666666-6666-4666-8666-666666666666",
    ];
    let docs = [
        (
            "rules/linux/process_creation/a.yml",
            sigma_doc(
                "Proc",
                ids[0],
                "    product: linux\n    category: process_creation",
            ),
        ),
        (
            "rules/windows/process_creation/b.yml",
            sigma_doc(
                "Win",
                ids[1],
                "    product: windows\n    category: process_creation",
            ),
        ),
        (
            "rules/linux/network_connection/c.yml",
            sigma_doc(
                "Net",
                ids[2],
                "    product: linux\n    category: network_connection",
            ),
        ),
        (
            "rules/linux/network_connection/f.yml",
            sigma_doc(
                "NetHost",
                ids[5],
                "    product: linux\n    category: network_connection",
            )
            .replace("Image|endswith: '/bin/sh'", "User|endswith: 'root'"),
        ),
        (
            "rules/linux/auditd/d.yml",
            sigma_doc("Audit", ids[3], "    product: linux\n    service: auditd"),
        ),
        (
            "rules/linux/builtin/e.yml",
            sigma_doc("Syslog", ids[4], "    product: linux\n    service: syslog"),
        ),
    ];
    let mut members: Vec<(String, &str)> =
        vec![("sigma-abc/LICENSE".into(), "Detection Rule License 1.1\n")];
    for (path, text) in &docs {
        members.push((format!("sigma-abc/{path}"), text.as_str()));
    }
    let archive_bytes = archive(
        &members
            .iter()
            .map(|(p, t)| (p.as_str(), *t))
            .collect::<Vec<_>>(),
    );
    let url = "https://codeload.github.com/example/sigma/tar.gz/abc";
    let files: Vec<SourceFile> = std::iter::once(("LICENSE", "Detection Rule License 1.1\n"))
        .chain(docs.iter().map(|(p, t)| (*p, t.as_str())))
        .map(|(path, text)| SourceFile {
            path: path.into(),
            sha256: sha(text.as_bytes()),
        })
        .collect();
    let keep = |category: &str, service: &str| SigmaLogsource {
        product: "linux".into(),
        category: category.into(),
        service: service.into(),
    };
    let pack = SourcePack {
        id: "sigma-linux".into(),
        engine: "sigma".into(),
        name: "Sigma Linux".into(),
        homepage: "https://github.com/example/sigma".into(),
        license: "DRL 1.1".into(),
        license_url: String::new(),
        revision: "abc".into(),
        revision_kind: "commit".into(),
        app: ">=0.6.2".into(),
        engine_requirement: "pySigma 2.x SQLite backend".into(),
        rules: 3,
        helpers: 0,
        evidence: vec!["process".into()],
        limits: Vec::new(),
        sources: vec![SourceFetch {
            url: url.into(),
            format: "tar.gz".into(),
            size: archive_bytes.len() as u64,
            sha256: String::new(),
            rolling: false,
            strip: 1,
            paths: vec!["rules/linux/".into()],
            files,
        }],
        filter: SourceFilter::Sigma(SigmaFilter {
            keep: vec![
                keep("process_creation", ""),
                keep("network_connection", ""),
                keep("", "auditd"),
            ],
        }),
        options: Vec::new(),
        notices: Vec::new(),
    };
    let fixture = Fixture::default().with(url, archive_bytes);
    let installed = install(&dir, &pack, &[], &fixture).unwrap();
    let rules = pack_index(&dir, "sigma", "sigma-linux").unwrap();
    let mut titles: Vec<_> = rules.iter().map(|rule| rule.name.as_str()).collect();
    titles.sort_unstable();
    assert_eq!(
        titles,
        ["Audit", "Net", "NetHost", "Proc"],
        "Windows and syslog rules are not kept"
    );
    let by_name = |name: &str| rules.iter().find(|rule| rule.name == name).unwrap();
    assert!(by_name("Proc").compatible);
    // Connections are recorded with an address and port, so these are evaluated;
    // a rule that needs a user is not, and says which field is missing.
    assert!(by_name("Net").compatible, "{}", by_name("Net").reason);
    assert!(!by_name("NetHost").compatible);
    assert!(
        by_name("NetHost").reason.contains("User"),
        "{}",
        by_name("NetHost").reason
    );
    // auditd rules are evaluated against auditd-style records built from the trace.
    assert!(by_name("Audit").compatible, "{}", by_name("Audit").reason);
    assert!(
        installed
            .provenance
            .summary
            .iter()
            .any(|line| line.contains("Removed 2 because its log source"))
    );
    assert!(
        rules_root(&dir)
            .join("packs/sigma/sigma-linux")
            .join(&installed.version)
            .join("LICENSE")
            .is_file()
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn the_copy_filter_keeps_rule_and_license_files_from_several_downloads() {
    let dir = temp_dir("copy");
    let events = "alert tcp any any -> any any (msg:\"event\"; sid:2200001; rev:1;)\n";
    let stream =
        "alert tcp any any -> any any (msg:\"stream\"; sid:2210001; rev:1;)\n# a comment\n";
    let copying = "GNU GENERAL PUBLIC LICENSE\n";
    let mut sources = Vec::new();
    let mut fixture = Fixture::default();
    for (name, body) in [
        ("decoder-events.rules", events),
        ("stream-events.rules", stream),
        ("COPYING", copying),
    ] {
        let url = format!("https://raw.githubusercontent.com/example/suri/abc/rules/{name}");
        sources.push(SourceFetch {
            url: url.clone(),
            format: "file".into(),
            size: body.len() as u64,
            sha256: sha(body.as_bytes()),
            rolling: false,
            strip: 0,
            paths: Vec::new(),
            files: vec![SourceFile {
                path: name.into(),
                sha256: sha(body.as_bytes()),
            }],
        });
        fixture = fixture.with(&url, body.as_bytes().to_vec());
    }
    let pack = SourcePack {
        id: "suri-builtin".into(),
        engine: "ids".into(),
        name: "Suricata built-in".into(),
        homepage: "https://github.com/example/suri".into(),
        license: "GPL-2.0".into(),
        license_url: String::new(),
        revision: "abc".into(),
        revision_kind: "commit".into(),
        app: ">=0.6.2".into(),
        engine_requirement: "Suricata 7".into(),
        rules: 2,
        helpers: 0,
        evidence: vec!["pcap".into()],
        limits: Vec::new(),
        sources,
        filter: SourceFilter::Copy {
            extensions: vec![".rules".into()],
            support: vec!["COPYING".into()],
        },
        options: Vec::new(),
        notices: Vec::new(),
    };
    let installed = install(&dir, &pack, &[], &fixture).unwrap();
    assert_eq!(installed.rules, 2);
    assert!(
        pack.hosts()
            .contains(&"raw.githubusercontent.com".to_owned())
    );
    let root = rules_root(&dir)
        .join("packs/ids/suri-builtin")
        .join(&installed.version);
    assert!(root.join("COPYING").is_file());
    assert!(root.join("SOURCE.txt").is_file());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn removing_a_pack_deletes_its_files_and_toggles() {
    let dir = temp_dir("remove");
    let (pack, fixture) = forge_pack();
    install(&dir, &pack, &[], &fixture).unwrap();
    install(&dir, &pack, &["include-unlicensed"], &fixture).unwrap();
    set_rule_enabled(&dir, "pack:forge-core", "Open_Plain", false).unwrap();
    assert!(rules_root(&dir).join("packs/yara/forge-core").is_dir());
    remove_pack(&dir, "forge-core").unwrap();
    let registry = load_registry(&dir).unwrap();
    assert!(registry.packs.is_empty());
    assert!(registry.disabled.is_empty());
    assert!(!rules_root(&dir).join("packs/yara/forge-core").exists());
    assert!(
        remove_pack(&dir, "forge-core")
            .unwrap_err()
            .contains("not installed")
    );
    assert!(remove_pack(&dir, "../etc").is_err());
    // It installs again from nothing.
    install(&dir, &pack, &[], &fixture).unwrap();
    assert_eq!(load_registry(&dir).unwrap().packs.len(), 1);
    let _ = fs::remove_dir_all(dir);
}
