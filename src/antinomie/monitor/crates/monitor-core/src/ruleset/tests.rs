// SPDX-License-Identifier: MIT
use super::*;
use std::io::Write;

fn entry(sha: &str, size: u64) -> PackEntry {
    PackEntry {
        id: "sample".into(),
        engine: "yara".into(),
        name: "Sample".into(),
        version: "1".into(),
        upstream_revision: "abc".into(),
        upstream_url: "https://example.invalid/rules".into(),
        download_url: "https://example.invalid/sample.tar.gz".into(),
        sha256: sha.into(),
        size,
        app: ">=0.6.2".into(),
        engine_requirement: "YARA-X 1.21".into(),
        rules: 1,
        helpers: 0,
        license: "example".into(),
        evidence: vec!["sample".into()],
        limits: Vec::new(),
    }
}

/// Facts for a host with every engine installed, for tests whose subject
/// is not the requirement check.
fn installed_engines() -> ToolFacts {
    ToolFacts {
        app: crate::api::APP_VERSION.into(),
        yara: yara_x::VERSION.into(),
        suricata: ToolProbe::Found {
            identity: "This is Suricata version 7.0.10 RELEASE".into(),
            version: "7.0.10".into(),
        },
        sigma: ToolProbe::Found {
            identity: "pysigma 2.0.1 / sqlite 2.1.0".into(),
            version: "2.0.1".into(),
        },
        sigma_python: DEFAULT_SIGMA_PYTHON.into(),
    }
}

fn archive(files: &[(&str, &str)]) -> Vec<u8> {
    let mut raw = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut raw);
        for (name, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, *name, data.as_bytes())
                .unwrap();
        }
        builder.finish().unwrap();
    }
    let mut encoded = Vec::new();
    {
        let mut gzip = flate2::write::GzEncoder::new(&mut encoded, flate2::Compression::fast());
        gzip.write_all(&raw).unwrap();
        gzip.finish().unwrap();
    }
    encoded
}

#[test]
fn catalog_rejects_missing_malformed_and_accepts_null_lists() {
    let missing = serde_json::json!({"schema": 1, "packs": [{}]});
    assert!(validate_catalog(&missing).unwrap_err().contains("missing"));
    let bad = serde_json::json!({"schema": 1, "packs": "nope"});
    assert!(validate_catalog(&bad).is_err());
    let unknown = serde_json::json!({"schema": 3, "packs": []});
    assert!(validate_catalog(&unknown).unwrap_err().contains("schema"));
    let ok = serde_json::json!({
        "schema": 1,
        "packs": [{
            "id": "core",
            "engine": "sigma",
            "name": "Sigma",
            "version": "1",
            "upstream_revision": "c0ffee",
            "upstream_url": "https://example.invalid",
            "download_url": "https://example.invalid/a.tar.gz",
            "sha256": "ab".repeat(32),
            "size": 1,
            "app": ">=0.6.2",
            "engine_requirement": "pySigma",
            "rules": 1,
            "helpers": 0,
            "license": "see NOTICE",
            "evidence": null,
            "limits": null
        }]
    });
    let catalog = validate_catalog(&ok).unwrap();
    assert!(catalog.packs[0].limits.is_empty());
    assert!(catalog.packs[0].evidence.is_empty());
}

#[test]
fn bad_checksum_and_path_escape_keep_the_previous_pack() {
    let dir = std::env::temp_dir().join(format!("ant-rules-{}", crate::storage::unique_id()));
    let rule = "rule Keep { condition: true }\n";
    let good = archive(&[("keep.yar", rule)]);
    let sha = format!("{:x}", Sha256::digest(&good));
    let mut listed = entry(&sha, good.len() as u64);
    install_archive(&dir, &listed, &good).unwrap();
    listed.version = "2".into();
    let broken = b"not-the-archive".to_vec();
    listed.size = broken.len() as u64;
    listed.sha256 = format!("{:x}", Sha256::digest(&broken));
    // Checksum matches the bytes but they are not a gzip archive.
    let error = install_archive(&dir, &listed, &broken).unwrap_err();
    assert!(!error.is_empty());
    let registry = load_registry(&dir).unwrap();
    assert_eq!(registry.packs[0].version, "1");
    assert!(dir.join("rules/packs/yara/sample/1/keep.yar").is_file());
    assert!(!dir.join("rules/packs/yara/sample/2").exists());

    let payload = b"owned";
    let mut header = [0u8; 512];
    header[..13].copy_from_slice(b"../escape.yar");
    {
        let mut put = |offset: usize, value: u64, width: usize| {
            let text = format!("{:0width$o} ", value, width = width - 1);
            header[offset..offset + width].copy_from_slice(&text.as_bytes()[..width]);
        };
        put(100, 0o644, 8);
        put(108, 0, 8);
        put(116, 0, 8);
        put(124, payload.len() as u64, 12);
        put(136, 0, 12);
    }
    header[156] = b'0';
    header[148..156].copy_from_slice(b"        ");
    let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    let checksum = format!("{sum:06o}\0 ");
    header[148..156].copy_from_slice(checksum.as_bytes());
    let mut raw = header.to_vec();
    raw.extend_from_slice(payload);
    raw.resize(512 + 512, 0);
    raw.extend_from_slice(&[0u8; 1024]);
    let mut escaped = Vec::new();
    {
        let mut gzip = flate2::write::GzEncoder::new(&mut escaped, flate2::Compression::fast());
        gzip.write_all(&raw).unwrap();
        gzip.finish().unwrap();
    }
    listed.version = "3".into();
    listed.size = escaped.len() as u64;
    listed.sha256 = format!("{:x}", Sha256::digest(&escaped));
    assert!(
        install_archive(&dir, &listed, &escaped)
            .unwrap_err()
            .contains("escapes")
    );
    assert_eq!(load_registry(&dir).unwrap().packs[0].version, "1");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn disabled_helper_is_not_reported_as_a_successful_compile() {
    let dir = std::env::temp_dir().join(format!("ant-rules-{}", crate::storage::unique_id()));
    let source = "private rule Helper { condition: true }\nrule Uses { condition: Helper }\nrule Other { condition: true }\n";
    let bytes = archive(&[("pack.yar", source)]);
    let sha = format!("{:x}", Sha256::digest(&bytes));
    let listed = entry(&sha, bytes.len() as u64);
    install_archive(&dir, &listed, &bytes).unwrap();
    set_rule_enabled(&dir, "pack:sample", "Helper", false).unwrap();
    let snap = snapshot(&dir, "yara", &ToolConfig::default()).unwrap();
    assert_eq!(snap.enabled_rules, 1);
    let emitted = fs::read_to_string(snap.directory.unwrap().join("pack/sample/pack.yar")).unwrap();
    assert!(emitted.contains("rule Other"));
    assert!(!emitted.contains("rule Uses"));
    assert!(
        snap.warnings
            .iter()
            .any(|warning| warning.contains("Helper"))
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn engine_sets_count_enabled_rules_and_keep_a_disabled_group() {
    let dir = std::env::temp_dir().join(format!("ant-rules-{}", crate::storage::unique_id()));
    let source = dir.join("incoming");
    fs::create_dir_all(&source).unwrap();
    fs::write(
        source.join("local.yar"),
        "rule Local { condition: true }\nprivate rule Helper { condition: true }\n",
    )
    .unwrap();
    let id = import_group(&dir, "Local group", "yara", &source).unwrap();
    let registry = load_registry(&dir).unwrap();
    let sets = engine_sets(&dir, &registry, "yara");
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].name, "Local group");
    assert_eq!(sets[0].revision, "r1");
    assert!(sets[0].enabled);
    assert_eq!(sets[0].rules, 1, "private helpers are not rule counts");
    set_group_enabled(&dir, &id, false).unwrap();
    let registry = load_registry(&dir).unwrap();
    let sets = engine_sets(&dir, &registry, "yara");
    assert!(!sets[0].enabled);
    assert_eq!(sets[0].rules, 1);
    assert!(engine_sets(&dir, &registry, "ids").is_empty());
    let body = yara_rule_source(
        "rule Other { condition: false }\nrule Local { condition: true }\n",
        "Local",
    )
    .unwrap();
    assert!(body.contains("rule Local"));
    assert!(!body.contains("rule Other"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn import_is_a_copy_and_rejects_a_link() {
    let dir = std::env::temp_dir().join(format!("ant-rules-{}", crate::storage::unique_id()));
    let source = dir.join("incoming");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("local.yar"), "rule Local { condition: true }\n").unwrap();
    let id = import_group(&dir, "Local group", "yara", &source).unwrap();
    fs::write(
        source.join("local.yar"),
        "rule Changed { condition: false }\n",
    )
    .unwrap();
    let stored = fs::read_to_string(dir.join(format!("rules/custom/{id}/1/local.yar"))).unwrap();
    assert!(stored.contains("rule Local"));
    let link = dir.join("linked");
    std::os::unix::fs::symlink(&source, &link).unwrap();
    assert!(
        import_group(&dir, "Linked", "yara", &link)
            .unwrap_err()
            .contains("link")
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn duplicate_ids_rules_are_marked_and_not_both_selected() {
    let dir = std::env::temp_dir().join(format!("ant-rules-{}", crate::storage::unique_id()));
    let first = "alert tcp any any -> any any (msg:\"one\"; sid:10; rev:1;)\n";
    let second = "alert tcp any any -> any any (msg:\"two\"; sid:10; rev:2;)\n";
    let bytes = archive(&[("a.rules", first), ("b.rules", second)]);
    let mut listed = entry(&format!("{:x}", Sha256::digest(&bytes)), bytes.len() as u64);
    listed.engine = "ids".into();
    listed.id = "et".into();
    listed.engine_requirement = "Suricata 7".into();
    install_archive(&dir, &listed, &bytes).unwrap();
    let index = pack_index(&dir, "ids", "et").unwrap();
    assert!(
        index
            .iter()
            .any(|rule| !rule.compatible && rule.reason.contains("duplicate"))
    );
    let snap = snapshot_from(
        &dir,
        "ids",
        &load_registry(&dir).unwrap(),
        &installed_engines(),
        None,
    )
    .unwrap();
    assert_eq!(snap.enabled_rules, 1);
    assert!(
        snap.warnings
            .iter()
            .any(|warning| warning.contains("duplicate"))
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn prepared_community_packs_install_and_select() {
    let Some(catalog_path) = std::env::var_os("ANTINOMIE_RULES_CATALOG") else {
        return;
    };
    let catalog_path = PathBuf::from(catalog_path);
    let value: Value = serde_json::from_slice(&fs::read(&catalog_path).unwrap()).unwrap();
    let catalog = validate_catalog(&value).unwrap();
    let dir = std::env::temp_dir().join(format!("ant-rules-{}", crate::storage::unique_id()));
    for entry in &catalog.packs {
        let packs_dir = catalog_path.parent().unwrap().join("packs");
        let bytes = fs::read_dir(&packs_dir)
            .unwrap()
            .find_map(|item| {
                let path = item.ok()?.path();
                if !path.is_file() {
                    return None;
                }
                let bytes = fs::read(&path).ok()?;
                (format!("{:x}", Sha256::digest(&bytes)) == entry.sha256).then_some(bytes)
            })
            .expect("pack archive");
        install_archive(&dir, entry, &bytes).unwrap();
        let snap = snapshot(&dir, &entry.engine, &ToolConfig::default()).unwrap();
        assert!(snap.enabled_rules > 0, "{}", entry.id);
        if entry.engine == "ids" {
            let root = snap.directory.as_ref().unwrap();
            let malware = root.join("pack/emerging-threats-open/rules/emerging-malware.rules");
            let text = fs::read_to_string(&malware).expect("malware rules were not emitted");
            assert!(
                text.len() > 1_000_000,
                "emerging-malware.rules was truncated to {} bytes",
                text.len()
            );
            assert!(ids_blocks(&text).len() > 10_000);
            assert!(
                root.join("pack/emerging-threats-open/rules/classification.config")
                    .is_file()
                    || root.join("rules/classification.config").is_file()
                    || root
                        .join("pack/emerging-threats-open/classification.config")
                        .is_file(),
                "classification.config was not copied"
            );
        }
        if entry.engine == "sigma" {
            assert!(
                snap.warnings
                    .iter()
                    .any(|warning| warning.contains("not a captured")),
                "sigma exclusions were not reported"
            );
        }
    }
    let yara = snapshot(&dir, "yara", &ToolConfig::default()).unwrap();
    assert!(yara.enabled_rules > 1_000);
    set_pack_enabled(&dir, "yara-forge-core", false).unwrap();
    let after = snapshot(&dir, "yara", &ToolConfig::default()).unwrap();
    assert_eq!(after.enabled_rules, 0);
    assert!(after.directory.is_none());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn version_path_rollback_and_ids_message_keep_their_bytes() {
    let absolute = serde_json::json!({
        "schema": 1,
        "packs": [{
            "id": "core",
            "engine": "yara",
            "name": "Core",
            "version": "/tmp/outside",
            "upstream_revision": "1",
            "upstream_url": "https://example.invalid",
            "download_url": "https://example.invalid/a.tar.gz",
            "sha256": "ab".repeat(32),
            "size": 1,
            "app": ">=0.6.2",
            "engine_requirement": "YARA-X",
            "rules": 1,
            "helpers": 0,
            "license": "example"
        }]
    });
    assert!(validate_catalog(&absolute).unwrap_err().contains("version"));

    let dir = std::env::temp_dir().join(format!("ant-rules-{}", crate::storage::unique_id()));
    let first = archive(&[("keep.yar", "rule First { condition: true }\n")]);
    let second = archive(&[("keep.yar", "rule Second { condition: false }\n")]);
    let mut listed = entry(&format!("{:x}", Sha256::digest(&first)), first.len() as u64);
    install_archive(&dir, &listed, &first).unwrap();
    listed.version = "2".into();
    listed.upstream_revision = "rev-2".into();
    listed.sha256 = format!("{:x}", Sha256::digest(&second));
    listed.size = second.len() as u64;
    install_archive(&dir, &listed, &second).unwrap();
    rollback(&dir, "sample", "1").unwrap();
    let restored = &load_registry(&dir).unwrap().packs[0];
    assert_eq!(restored.version, "1");
    assert_eq!(restored.sha256, format!("{:x}", Sha256::digest(&first)));
    assert_ne!(restored.upstream_revision, "rev-2");

    let indented = dir.join("indented.yar");
    fs::write(
        &indented,
        "rule ValidIndented {\n    condition: true\n    }\n",
    )
    .unwrap();
    let id = import_group(&dir, "indented", "yara", &indented).unwrap();
    let indexed = group_index(&dir, &id).unwrap();
    assert_eq!(indexed.len(), 1);
    assert_eq!(indexed[0].id, "ValidIndented");

    let ids = dir.join("custom.rules");
    fs::write(
        &ids,
        "alert tcp any any -> any any (msg:\"this rule matches\"; sid:1; rev:1;)\nalert tcp any any -> any any (msg:\"second\"; sid:2; rev:1;)\n",
    )
    .unwrap();
    let group = import_group(&dir, "custom", "ids", &ids).unwrap();
    set_rule_enabled(&dir, &format!("group:{group}"), "2", false).unwrap();
    let snap = snapshot(&dir, "ids", &ToolConfig::default()).unwrap();
    let body = fs::read_to_string(
        snap.directory
            .unwrap()
            .join("group")
            .join(&group)
            .join("custom.rules"),
    )
    .unwrap();
    assert!(body.contains("sid:1"));
    assert!(!body.contains("sid:2"));
    assert_eq!(snap.enabled_rules, 1);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn group_revisions_keep_the_previous_directory() {
    let dir = std::env::temp_dir().join(format!("ant-rules-{}", crate::storage::unique_id()));
    let source = dir.join("src");
    fs::create_dir_all(&source).unwrap();
    fs::write(
        source.join("a.yar"),
        "rule One { condition: true }\nrule Two { condition: true }\n",
    )
    .unwrap();
    let id = import_group(&dir, "custom", "yara", &source).unwrap();
    let root = rules_root(&dir).join("custom").join(&id);
    let original = fs::read_to_string(root.join("1/a.yar")).unwrap();
    let replacement = dir.join("next");
    fs::create_dir_all(&replacement).unwrap();
    fs::write(
        replacement.join("b.yar"),
        "rule Three { condition: true }\n",
    )
    .unwrap();
    assert_eq!(replace_group_revision(&dir, &id, &replacement).unwrap(), 2);
    assert_eq!(fs::read_to_string(root.join("1/a.yar")).unwrap(), original);
    assert!(root.join("2/b.yar").is_file());
    assert_eq!(
        revise_group(&dir, &id, None, &["Three".to_string()]).unwrap(),
        3
    );
    assert!(
        fs::read_to_string(root.join("2/b.yar"))
            .unwrap()
            .contains("Three")
    );
    let removed = fs::read_to_string(root.join("3/b.yar")).unwrap_or_default();
    assert!(!removed.contains("rule Three"));
    let registry = load_registry(&dir).unwrap();
    assert!(registry.generation >= 3);
    assert_eq!(
        registry
            .groups
            .iter()
            .find(|group| group.id == id)
            .unwrap()
            .revision,
        3
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn yara_lexer_ignores_false_headers_and_keeps_indented_rules() {
    let text = "/*\nEach rule keeps its author\n*/\nrule \"not a name\"\n// rule Commented\nrule Real {\n    strings:\n        $a = \"rule Hidden\"\n        $b = { 90 90 }\n    condition:\n        $a\n    }\n";
    let names: Vec<_> = yara_blocks(text)
        .into_iter()
        .map(|(name, _, _)| name)
        .collect();
    assert_eq!(names, vec!["Real".to_string()]);
    let indented = yara_blocks("rule ValidIndented {\n    condition: true\n    }\n");
    assert_eq!(indented.len(), 1);
    assert_eq!(indented[0].0, "ValidIndented");
}

#[test]
fn helper_dependencies_are_transitive_and_namespaces_stay_distinct() {
    let dir = std::env::temp_dir().join(format!("ant-rules-{}", crate::storage::unique_id()));
    let source = "\
private rule Helper { condition: true }\n\
private rule Middle { condition: Helper }\n\
rule Uses { condition: Middle }\n\
rule Other { condition: true }\n";
    let bytes = archive(&[("pack.yar", source)]);
    let sha = format!("{:x}", Sha256::digest(&bytes));
    install_archive(&dir, &entry(&sha, bytes.len() as u64), &bytes).unwrap();
    set_rule_enabled(&dir, "pack:sample", "Helper", false).unwrap();
    let snap = snapshot(&dir, "yara", &ToolConfig::default()).unwrap();
    let emitted = fs::read_to_string(snap.directory.unwrap().join("pack/sample/pack.yar")).unwrap();
    assert!(emitted.contains("rule Other"));
    assert!(!emitted.contains("rule Uses"));
    assert!(!emitted.contains("rule Middle"));
    assert!(!emitted.contains("rule Helper"));
    assert_eq!(snap.enabled_rules, 1);
    assert!(
        snap.warnings
            .iter()
            .any(|warning| warning.contains("Helper"))
    );

    let first = dir.join("a.yar");
    let second = dir.join("b.yar");
    fs::write(&first, "rule Same { condition: true }\n").unwrap();
    fs::write(&second, "rule Same { condition: false }\n").unwrap();
    fs::create_dir_all(dir.join("pair")).unwrap();
    fs::copy(&first, dir.join("pair/a.yar")).unwrap();
    fs::copy(&second, dir.join("pair/b.yar")).unwrap();
    let id = import_group(&dir, "pair", "yara", &dir.join("pair")).unwrap();
    let indexed = group_index(&dir, &id).unwrap();
    let ids: BTreeSet<_> = indexed.iter().map(|rule| rule.id.clone()).collect();
    assert_eq!(
        ids,
        BTreeSet::from(["a.yar/Same".to_string(), "b.yar/Same".to_string()])
    );
    assert!(indexed.iter().all(|rule| rule.compatible));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_relative_include_compiles_and_an_escaping_include_does_not() {
    let dir = std::env::temp_dir().join(format!("ant-rules-{}", crate::storage::unique_id()));
    let bytes = archive(&[
        ("included.yar", "rule Included { condition: true }\n"),
        (
            "main.yar",
            "include \"included.yar\"\nrule Main { condition: Included and not \"rule Fake\" }\n",
        ),
    ]);
    let sha = format!("{:x}", Sha256::digest(&bytes));
    install_archive(&dir, &entry(&sha, bytes.len() as u64), &bytes).unwrap();
    let indexed = read_index(&dir.join("rules/packs/yara/sample/1")).unwrap();
    let names: BTreeSet<_> = indexed.iter().map(|rule| rule.name.clone()).collect();
    assert_eq!(
        names,
        BTreeSet::from(["Included".to_string(), "Main".to_string()])
    );
    assert_eq!(
        indexed
            .iter()
            .find(|rule| rule.name == "Main")
            .unwrap()
            .depends_on,
        vec!["Included".to_string()]
    );
    let escaped = archive(&[(
        "bad.yar",
        "include \"../outside.yar\"\nrule Bad { condition: true }\n",
    )]);
    let sha = format!("{:x}", Sha256::digest(&escaped));
    let mut escaped_entry = entry(&sha, escaped.len() as u64);
    escaped_entry.id = "escaped".into();
    escaped_entry.version = "2".into();
    let error = install_archive(&dir, &escaped_entry, &escaped).unwrap_err();
    assert!(error.contains("include") || error.contains("YARA-X") || error.contains("escapes"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn yara_forge_index_matches_yara_x_identities() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/rules/yara-forge-core.yar");
    let text = fs::read_to_string(&path).unwrap();
    let blocks = yara_blocks(&text);
    let indexed: BTreeSet<_> = blocks.iter().map(|(name, _, _)| name.clone()).collect();
    assert!(
        !indexed.contains("keeps"),
        "comment text was indexed as a rule"
    );
    for name in [
        "ESET_Invisimole_Blob_PRIVATE",
        "BLACKBERRY_Mal_Infostealer_Win32_Blackguard",
        "SIGNATURE_BASE_WEBSHELL_PHP_Generic_Eval",
        "SIGNATURE_BASE_WEBSHELL_JSP_Generic_Encoded_Shell",
    ] {
        assert!(indexed.contains(name), "{name} was not indexed");
    }
    let helpers = blocks.iter().filter(|(_, _, helper)| *helper).count();
    assert_eq!(helpers, 2);
    assert_eq!(blocks.len() - helpers, 2094);
    let mut compiler = yara_x::Compiler::new();
    compiler.relaxed_re_syntax(true);
    let code = yara_x::SourceCode::from(text.as_str()).with_origin("yara-forge-core.yar");
    compiler
        .add_source(code)
        .expect("YARA-X rejected the forge collection");
    let rules = compiler.build();
    let compiled: BTreeSet<_> = rules
        .iter()
        .map(|rule| rule.identifier().to_owned())
        .collect();
    assert_eq!(indexed, compiled);
    let namespaces: BTreeSet<_> = rules
        .iter()
        .map(|rule| rule.namespace().to_owned())
        .collect();
    assert_eq!(namespaces, BTreeSet::from(["default".to_string()]));
}

#[test]
fn same_version_with_a_different_checksum_keeps_the_installed_bytes() {
    let dir = std::env::temp_dir().join(format!("ant-rules-{}", crate::storage::unique_id()));
    let good = archive(&[("keep.yar", "rule Keep { condition: true }\n")]);
    let sha = format!("{:x}", Sha256::digest(&good));
    install_archive(&dir, &entry(&sha, good.len() as u64), &good).unwrap();
    let other = archive(&[("keep.yar", "rule Other { condition: false }\n")]);
    let mut collision = entry(&format!("{:x}", Sha256::digest(&other)), other.len() as u64);
    collision.version = "1".into();
    let error = install_archive(&dir, &collision, &other).unwrap_err();
    assert!(error.contains("immutable"));
    let text = fs::read_to_string(dir.join("rules/packs/yara/sample/1/keep.yar")).unwrap();
    assert!(text.contains("rule Keep"));
    assert!(!text.contains("rule Other"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn too_many_archive_members_are_rejected() {
    let mut raw = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut raw);
        for index in 0..=MAX_MEMBERS {
            let name = format!("f{index}.yar");
            let data = b"rule R { condition: true }\n";
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, &name, &data[..]).unwrap();
        }
        builder.finish().unwrap();
    }
    let mut encoded = Vec::new();
    {
        let mut gzip = flate2::write::GzEncoder::new(&mut encoded, flate2::Compression::fast());
        gzip.write_all(&raw).unwrap();
        gzip.finish().unwrap();
    }
    let dir = std::env::temp_dir().join(format!("ant-rules-{}", crate::storage::unique_id()));
    fs::create_dir_all(&dir).unwrap();
    let error = unpack_archive(&encoded, &dir).unwrap_err();
    assert!(error.contains("too many members"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_failed_registry_write_keeps_the_previous_selection() {
    let dir = std::env::temp_dir().join(format!("ant-rules-{}", crate::storage::unique_id()));
    let good = archive(&[("keep.yar", "rule Keep { condition: true }\n")]);
    let sha = format!("{:x}", Sha256::digest(&good));
    install_archive(&dir, &entry(&sha, good.len() as u64), &good).unwrap();
    let registry_path = rules_root(&dir).join("registry.json");
    let before = fs::read(&registry_path).unwrap();
    fail_once("registry-write");
    let error = set_pack_enabled(&dir, "sample", false).unwrap_err();
    assert!(error.contains("No space"));
    assert_eq!(fs::read(&registry_path).unwrap(), before);
    assert!(load_registry(&dir).unwrap().packs[0].enabled);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_full_disk_during_install_keeps_the_previous_version() {
    let dir = std::env::temp_dir().join(format!("ant-rules-{}", crate::storage::unique_id()));
    let good = archive(&[("keep.yar", "rule Keep { condition: true }\n")]);
    let sha = format!("{:x}", Sha256::digest(&good));
    install_archive(&dir, &entry(&sha, good.len() as u64), &good).unwrap();
    let next = archive(&[("next.yar", "rule Next { condition: true }\n")]);
    let mut listed = entry(&format!("{:x}", Sha256::digest(&next)), next.len() as u64);
    listed.version = "2".into();
    fail_once("unpack-write");
    let error = install_archive(&dir, &listed, &next).unwrap_err();
    assert!(error.contains("No space") || error.contains("space"));
    let registry = load_registry(&dir).unwrap();
    assert_eq!(registry.packs[0].version, "1");
    assert!(dir.join("rules/packs/yara/sample/1/keep.yar").is_file());
    assert!(
        !dir.join("rules/packs/yara/sample/2/manifest.json")
            .is_file()
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_disk_failure_on_one_thread_does_not_fail_another_install() {
    let parent = std::env::temp_dir().join(format!("ant-iso-p-{}", crate::storage::unique_id()));
    let child_dir = std::env::temp_dir().join(format!("ant-iso-c-{}", crate::storage::unique_id()));
    let bytes = archive(&[("keep.yar", "rule Keep { condition: true }\n")]);
    let sha = format!("{:x}", Sha256::digest(&bytes));
    let child_bytes = bytes.clone();
    let child_sha = sha.clone();
    let child = std::thread::spawn(move || {
        fail_once("unpack-write");
        let listed = entry(&child_sha, child_bytes.len() as u64);
        install_archive(&child_dir, &listed, &child_bytes).unwrap_err()
    });
    install_archive(&parent, &entry(&sha, bytes.len() as u64), &bytes).unwrap();
    let error = child.join().unwrap();
    assert!(
        error.contains("No space") || error.contains("space"),
        "{error}"
    );
    assert!(parent.join("rules/packs/yara/sample/1/keep.yar").is_file());
    let _ = fs::remove_dir_all(&parent);
    let _ = fs::remove_dir_all(std::env::temp_dir().join("unused"));
}

#[test]
fn requirements_reject_unknown_and_older_versions_without_string_order() {
    let facts = ToolFacts {
        app: "0.6.2".into(),
        yara: "1.21.0".into(),
        suricata: ToolProbe::Found {
            identity: "This is Suricata version 7.0.10 RELEASE".into(),
            version: "This is Suricata version 7.0.10 RELEASE".into(),
        },
        sigma: ToolProbe::Found {
            identity: "pysigma 2.0.1 / sqlite 2.1.0".into(),
            version: "2.0.1".into(),
        },
        sigma_python: DEFAULT_SIGMA_PYTHON.into(),
    };
    assert_eq!(
        classify_requirement(">=0.6.2", "YARA-X 1.21", "yara", &facts),
        RequirementStatus::Satisfied
    );
    assert!(matches!(
        classify_requirement(">=0.6.10", "YARA-X 1.21", "yara", &facts),
        RequirementStatus::Incompatible(_)
    ));
    assert!(matches!(
        classify_requirement("", "Mystery 1", "yara", &facts),
        RequirementStatus::Unknown(_)
    ));
    assert!(matches!(
        classify_requirement("", "YARA-X later", "yara", &facts),
        RequirementStatus::Malformed(_)
    ));
    let pending = ToolFacts {
        suricata: ToolProbe::Absent("Suricata is not installed".into()),
        ..facts.clone()
    };
    assert!(matches!(
        classify_requirement("", "Suricata 7", "ids", &pending),
        RequirementStatus::Pending(_)
    ));
    assert_eq!(
        classify_requirement("", "Suricata 7", "ids", &facts),
        RequirementStatus::Satisfied
    );
    assert_eq!(
        classify_requirement("", "pySigma 2.x SQLite backend", "sigma", &facts),
        RequirementStatus::Satisfied
    );
}

#[test]
fn an_old_parser_index_keeps_real_toggles_and_a_failed_rewrite() {
    let dir = std::env::temp_dir().join(format!("ant-mig-{}", crate::storage::unique_id()));
    let root = dir.join("rules/packs/yara/sample/1");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("one.yar"), "rule Real { condition: true }\n").unwrap();
    fs::write(
        root.join("index.json"),
        serde_json::json!({"rules": [
            {"id": "keeps", "name": "keeps", "file": "one.yar", "helper": false, "tags": [], "severity": "", "license": "", "source_url": "", "condition": "", "references": [], "evidence": [], "compatible": true, "reason": "", "content_sha256": "", "depends_on": []},
            {"id": "Real", "name": "Real", "file": "one.yar", "helper": false, "tags": [], "severity": "", "license": "", "source_url": "", "condition": "", "references": [], "evidence": [], "compatible": true, "reason": "", "content_sha256": "", "depends_on": []}
        ]})
        .to_string(),
    )
    .unwrap();
    let registry = serde_json::json!({
        "schema": 1,
        "packs": [{
            "id": "sample", "engine": "yara", "name": "Sample", "version": "1",
            "enabled": true, "sha256": "ab".repeat(32), "upstream_revision": "1",
            "upstream_url": "https://example.invalid", "license": "test",
            "evidence": [], "limits": [], "versions": ["1"]
        }],
        "groups": [],
        "disabled": {"pack:sample": ["keeps", "Real"]}
    });
    fs::write(dir.join("rules/registry.json"), registry.to_string()).unwrap();
    let before = fs::read(root.join("index.json")).unwrap();
    fail_once("index-write");
    let error = migrate_indexes(&dir).unwrap_err();
    assert!(error.contains("No space"));
    assert_eq!(fs::read(root.join("index.json")).unwrap(), before);
    let report = migrate_indexes(&dir).unwrap();
    assert_eq!(report.rebuilt.len(), 1);
    assert!(report.obsolete.iter().any(|item| item.contains("keeps")));
    let index: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("index.json")).unwrap()).unwrap();
    assert_eq!(index["parser"], 2);
    let names: Vec<_> = index["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| rule["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(names, vec!["Real".to_owned()]);
    let saved = load_registry(&dir).unwrap();
    assert!(saved.disabled["pack:sample"].contains("Real"));
    assert!(!saved.disabled["pack:sample"].contains("keeps"));
    assert!(
        saved.obsolete_disabled["pack:sample"]
            .iter()
            .any(|id| id == "keeps")
    );
    let again = migrate_indexes(&dir).unwrap();
    assert!(again.rebuilt.is_empty());
    assert_eq!(again.current.len(), 1);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn the_saved_r2_index_migrates_to_the_yara_x_identity_set() {
    let source = Path::new("/tmp/antinomie-4d2e369-review/upgrade");
    if !source
        .join("rules/packs/yara/yara-forge-core/20261004-r2/index.json")
        .is_file()
    {
        eprintln!("pre-fix r2 index is absent; migration was not executed");
        return;
    }
    let dir = std::env::temp_dir().join(format!("ant-r2-{}", crate::storage::unique_id()));
    copy_fixture(source, &dir);
    let index_path = dir.join("rules/packs/yara/yara-forge-core/20261004-r2/index.json");
    let old: serde_json::Value = serde_json::from_slice(&fs::read(&index_path).unwrap()).unwrap();
    let old_ids: BTreeSet<_> = old["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| rule["id"].as_str().unwrap().to_owned())
        .collect();
    assert!(old_ids.contains("keeps"));
    assert_eq!(old_ids.len(), 2093);
    let mut registry = load_registry(&dir).unwrap();
    registry.disabled.insert(
        "pack:yara-forge-core".into(),
        BTreeSet::from(["keeps".into()]),
    );
    let real = old_ids
        .iter()
        .find(|id| id.as_str() != "keeps")
        .unwrap()
        .clone();
    registry
        .disabled
        .get_mut("pack:yara-forge-core")
        .unwrap()
        .insert(real.clone());
    fs::write(
        dir.join("rules/registry.json"),
        serde_json::to_vec_pretty(&registry).unwrap(),
    )
    .unwrap();
    let report = migrate_indexes(&dir).unwrap();
    assert_eq!(report.rebuilt.len(), 1);
    assert!(report.obsolete.iter().any(|item| item.contains("keeps")));
    let index: serde_json::Value = serde_json::from_slice(&fs::read(&index_path).unwrap()).unwrap();
    let names: BTreeSet<_> = index["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| rule["name"].as_str().unwrap().to_owned())
        .collect();
    assert!(!names.contains("keeps"));
    for name in [
        "ESET_Invisimole_Blob_PRIVATE",
        "BLACKBERRY_Mal_Infostealer_Win32_Blackguard",
        "SIGNATURE_BASE_WEBSHELL_PHP_Generic_Eval",
        "SIGNATURE_BASE_WEBSHELL_JSP_Generic_Encoded_Shell",
    ] {
        assert!(names.contains(name), "{name} missing after migration");
    }
    let text = fs::read_to_string(
        dir.join("rules/packs/yara/yara-forge-core/20261004-r2/yara-forge-core.yar"),
    )
    .unwrap();
    let mut compiler = yara_x::Compiler::new();
    compiler.relaxed_re_syntax(true);
    compiler
        .add_source(yara_x::SourceCode::from(text.as_str()).with_origin("yara-forge-core.yar"))
        .unwrap();
    let compiled: BTreeSet<_> = compiler
        .build()
        .iter()
        .map(|rule| rule.identifier().to_owned())
        .collect();
    assert_eq!(names, compiled);
    let saved = load_registry(&dir).unwrap();
    assert!(saved.disabled["pack:yara-forge-core"].contains(&real));
    assert!(!saved.disabled["pack:yara-forge-core"].contains("keeps"));
    let bytes = fs::read(&index_path).unwrap();
    let second = migrate_indexes(&dir).unwrap();
    assert!(second.rebuilt.is_empty());
    assert_eq!(fs::read(&index_path).unwrap(), bytes);
    let _ = fs::remove_dir_all(&dir);
}

fn copy_fixture(source: &Path, dest: &Path) {
    for entry in walkdir_files(source) {
        let rel = entry.strip_prefix(source).unwrap();
        let target = dest.join(rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        if entry.is_file() {
            fs::copy(&entry, target).unwrap();
        }
    }
}

fn walkdir_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            if entry.path().is_dir() {
                pending.push(entry.path());
            } else {
                out.push(entry.path());
            }
        }
    }
    out
}

#[test]
fn an_unmet_engine_requirement_is_not_evaluated_and_notice_is_hashed() {
    let dir = std::env::temp_dir().join(format!("ant-req-{}", crate::storage::unique_id()));
    let bytes = archive(&[("one.yar", "rule Real { condition: true }\n")]);
    let sha = format!("{:x}", Sha256::digest(&bytes));
    let mut listed = entry(&sha, bytes.len() as u64);
    listed.engine_requirement = "YARA-X 99".into();
    install_archive(&dir, &listed, &bytes).unwrap();
    let pack = dir.join("rules/packs/yara/sample/1");
    fs::write(pack.join("NOTICE"), "upstream notice\n").unwrap();
    let mut catalog = Catalog {
        schema: 1,
        packs: vec![listed.clone()],
        sources: Vec::new(),
    };
    catalog.packs[0].version = "1".into();
    store_catalog(&dir, &catalog).unwrap();
    let snap = snapshot(&dir, "yara", &ToolConfig::default()).unwrap();
    assert_eq!(snap.enabled_rules, 0);
    assert!(
        snap.warnings
            .iter()
            .any(|warning| warning.contains("incompatible")),
        "{:?}",
        snap.warnings
    );
    // A catalog that later advertises a compatible requirement for the
    // same version does not change what was installed.
    catalog.packs[0].engine_requirement = "YARA-X 1.21".into();
    store_catalog(&dir, &catalog).unwrap();
    let still = snapshot(&dir, "yara", &ToolConfig::default()).unwrap();
    assert_eq!(still.enabled_rules, 0, "{:?}", still.warnings);
    let bytes = archive(&[("one.yar", "rule Real { condition: true }\n")]);
    let mut newer = entry(&format!("{:x}", Sha256::digest(&bytes)), bytes.len() as u64);
    newer.version = "2".into();
    install_archive(&dir, &newer, &bytes).unwrap();
    fs::write(
        dir.join("rules/packs/yara/sample/2/NOTICE"),
        "upstream notice\n",
    )
    .unwrap();
    let snap = snapshot(&dir, "yara", &ToolConfig::default()).unwrap();
    assert_eq!(snap.enabled_rules, 1);
    let manifest =
        fs::read_to_string(dir.join(format!("rules/profiles/yara/{}/manifest.json", snap.digest)))
            .unwrap();
    assert!(manifest.contains("NOTICE"), "{manifest}");
    let _ = fs::remove_dir_all(&dir);
}

/// The published SigmaHQ pack against a real pySigma venv. Set
/// `ANTINOMIE_RULES_PUBLISHED` to a directory holding the public
/// `catalog.json` and `packs/<sha256>.tar.gz`, and
/// `ANTINOMIE_TEST_SIGMA_PYTHON` to an interpreter with pySigma 2.
#[test]
#[ignore = "needs the published packs and a pySigma venv"]
fn the_published_sigma_pack_qualifies_with_the_configured_interpreter() {
    let published = PathBuf::from(
        std::env::var("ANTINOMIE_RULES_PUBLISHED")
            .unwrap_or_else(|_| "/tmp/antinomie-rules-r4".into()),
    );
    let python = std::env::var("ANTINOMIE_TEST_SIGMA_PYTHON")
        .unwrap_or_else(|_| "/tmp/antinomie-sigma-venv/bin/python".into());
    let catalog: Value =
        serde_json::from_slice(&fs::read(published.join("catalog.json")).unwrap()).unwrap();
    let catalog = validate_catalog(&catalog).unwrap();
    let entry = catalog
        .packs
        .iter()
        .find(|pack| pack.engine == "sigma")
        .unwrap()
        .clone();
    let bytes = fs::read(
        published
            .join("packs")
            .join(format!("{}.tar.gz", entry.sha256)),
    )
    .unwrap();
    let dir = std::env::temp_dir().join(format!("ant-sigma-real-{}", crate::storage::unique_id()));
    store_catalog(&dir, &catalog).unwrap();
    install_archive(&dir, &entry, &bytes).unwrap();
    let tools = ToolConfig::from_sigma_setting(&python);
    let facts = tool_facts(&tools);
    assert!(
        matches!(&facts.sigma, ToolProbe::Found { version, .. } if version.starts_with("2.")),
        "{facts:?}"
    );
    assert_eq!(
        classify_requirement(&entry.app, &entry.engine_requirement, "sigma", &facts),
        RequirementStatus::Satisfied
    );
    let snap = snapshot(&dir, "sigma", &tools).unwrap();
    assert_eq!(
        (snap.enabled_rules, snap.excluded_rules),
        (117, 93),
        "{:?}",
        snap.warnings
    );
    let manifest: Value = serde_json::from_slice(
        &fs::read(dir.join(format!(
            "rules/profiles/sigma/{}/manifest.json",
            snap.digest
        )))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["sigma_python"], Value::String(python.clone()));
    assert!(
        manifest["engine_identity"]
            .as_str()
            .unwrap()
            .contains("pysigma 2.")
    );
    // A Python without pySigma leaves the pack pending, not satisfied.
    let missing = ToolConfig::from_sigma_setting(dir.join("no-python").to_str().unwrap());
    let other = snapshot(&dir, "sigma", &missing).unwrap();
    assert_ne!(other.digest, snap.digest);
    assert_eq!(other.enabled_rules, 0);
    assert!(
        other
            .warnings
            .iter()
            .any(|warning| warning.contains("validation pending")),
        "{:?}",
        other.warnings
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn installed_requirements_survive_catalog_loss_corruption_and_replacement() {
    let dir = std::env::temp_dir().join(format!("ant-retained-{}", crate::storage::unique_id()));
    let tools = ToolConfig::default();
    let bytes = archive(&[("one.yar", "rule Real { condition: true }\n")]);
    let sha = format!("{:x}", Sha256::digest(&bytes));
    let mut old = entry(&sha, bytes.len() as u64);
    old.engine_requirement = "YARA-X 99".into();
    install_archive(&dir, &old, &bytes).unwrap();
    let mut good = entry(&sha, bytes.len() as u64);
    good.version = "2".into();
    install_archive(&dir, &good, &bytes).unwrap();
    let catalog = Catalog {
        schema: 1,
        packs: vec![good.clone()],
        sources: Vec::new(),
    };
    store_catalog(&dir, &catalog).unwrap();
    let enabled = |dir: &Path| snapshot(dir, "yara", &tools).unwrap();
    let compatible = enabled(&dir);
    assert_eq!(compatible.enabled_rules, 1);
    let catalog_path = dir.join("rules/catalog.json");
    // Missing, corrupt and replaced catalogs leave the compatible version usable.
    fs::remove_file(&catalog_path).unwrap();
    assert_eq!(enabled(&dir).digest, compatible.digest);
    fs::write(&catalog_path, b"{not json").unwrap();
    assert_eq!(enabled(&dir).digest, compatible.digest);
    let mut replaced = catalog.clone();
    replaced.packs[0].engine_requirement = "YARA-X 99".into();
    store_catalog(&dir, &replaced).unwrap();
    assert_eq!(enabled(&dir).enabled_rules, 1);
    // The older version keeps its own incompatible requirement offline.
    fs::remove_file(&catalog_path).unwrap();
    rollback(&dir, "sample", "1").unwrap();
    let older = enabled(&dir);
    assert_eq!(older.enabled_rules, 0);
    assert!(
        older.warnings.iter().any(|w| w.contains("incompatible")),
        "{:?}",
        older.warnings
    );
    // A registry from before requirements were retained reads the version's
    // own manifest, not a catalog row for another version.
    let mut registry = load_registry(&dir).unwrap();
    registry.packs[0].app.clear();
    registry.packs[0].engine_requirement.clear();
    store_catalog(&dir, &catalog).unwrap();
    save_registry(&dir, &registry).unwrap();
    assert_eq!(enabled(&dir).enabled_rules, 0);
    migrate_indexes(&dir).unwrap();
    assert_eq!(
        load_registry(&dir).unwrap().packs[0].engine_requirement,
        "YARA-X 99"
    );
    // With neither, the requirement is unknown and the pack is not evaluated.
    let mut registry = load_registry(&dir).unwrap();
    registry.packs[0].engine_requirement.clear();
    save_registry(&dir, &registry).unwrap();
    fs::remove_file(dir.join("rules/packs/yara/sample/1/manifest.json")).unwrap();
    let unknown = enabled(&dir);
    assert_eq!(unknown.enabled_rules, 0);
    assert!(
        unknown
            .warnings
            .iter()
            .any(|w| w.contains("unknown requirement")),
        "{:?}",
        unknown.warnings
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn an_admitted_registry_is_not_changed_by_a_later_catalog_or_rollback() {
    let dir = std::env::temp_dir().join(format!("ant-admitted-{}", crate::storage::unique_id()));
    let facts = tool_facts(&ToolConfig::default());
    let bytes = archive(&[("one.yar", "rule Real { condition: true }\n")]);
    let sha = format!("{:x}", Sha256::digest(&bytes));
    let mut old = entry(&sha, bytes.len() as u64);
    old.engine_requirement = "YARA-X 99".into();
    install_archive(&dir, &old, &bytes).unwrap();
    let mut good = entry(&sha, bytes.len() as u64);
    good.version = "2".into();
    install_archive(&dir, &good, &bytes).unwrap();
    let admitted = load_registry(&dir).unwrap();
    let digest = selection_digest_of(&dir, &admitted, "yara", &facts);
    store_catalog(
        &dir,
        &Catalog {
            schema: 1,
            packs: vec![old.clone()],
            sources: Vec::new(),
        },
    )
    .unwrap();
    rollback(&dir, "sample", "1").unwrap();
    let snap = snapshot_from(&dir, "yara", &admitted, &facts, None).unwrap();
    assert_eq!(
        (snap.digest.as_str(), snap.enabled_rules),
        (digest.as_str(), 1)
    );
    let next = snapshot(&dir, "yara", &ToolConfig::default()).unwrap();
    assert_ne!(next.digest, digest);
    assert_eq!(next.enabled_rules, 0);
    let _ = fs::remove_dir_all(&dir);
}

/// Mark an installed index as written by the parser before `INDEX_PARSER`.
fn make_legacy(root: &Path) {
    let path = root.join("index.json");
    let mut index: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    index["parser"] = Value::from(0);
    fs::write(&path, index.to_string()).unwrap();
}

fn parser_of(root: &Path) -> u64 {
    let index: Value = serde_json::from_slice(&fs::read(root.join("index.json")).unwrap()).unwrap();
    index["parser"].as_u64().unwrap_or(0)
}

fn install_version(dir: &Path, version: &str, files: &[(&str, &str)]) {
    let bytes = archive(files);
    let mut listed = entry(&format!("{:x}", Sha256::digest(&bytes)), bytes.len() as u64);
    listed.version = version.into();
    install_archive(dir, &listed, &bytes).unwrap();
}

#[test]
fn migrating_an_older_version_keeps_a_toggle_of_the_selected_one() {
    let dir = std::env::temp_dir().join(format!("ant-mig2-{}", crate::storage::unique_id()));
    install_version(
        &dir,
        "1",
        &[("old.yar", "rule OldOnly { condition: true }\n")],
    );
    install_version(
        &dir,
        "2",
        &[(
            "new.yar",
            "rule NewOnly { condition: true }\nrule Kept { condition: true }\n",
        )],
    );
    set_rule_enabled(&dir, "pack:sample", "NewOnly", false).unwrap();
    let packs = dir.join("rules/packs/yara/sample");
    make_legacy(&packs.join("1"));
    make_legacy(&packs.join("2"));
    let report = migrate_indexes(&dir).unwrap();
    assert_eq!(report.rebuilt.len(), 2, "{report:?}");
    assert!(report.obsolete.is_empty(), "{report:?}");
    let registry = load_registry(&dir).unwrap();
    assert!(registry.disabled["pack:sample"].contains("NewOnly"));
    assert!(registry.obsolete_disabled.is_empty());
    assert_eq!(
        snapshot_from(&dir, "yara", &registry, &installed_engines(), None)
            .unwrap()
            .enabled_rules,
        1
    );
    // Rolling back neither drops nor applies the toggle; reopening and
    // returning to version 2 still has NewOnly disabled.
    rollback(&dir, "sample", "1").unwrap();
    assert!(migrate_indexes(&dir).unwrap().rebuilt.is_empty());
    let reopened = load_registry(&dir).unwrap();
    assert!(reopened.disabled["pack:sample"].contains("NewOnly"));
    assert_eq!(
        snapshot_from(&dir, "yara", &reopened, &installed_engines(), None)
            .unwrap()
            .enabled_rules,
        1
    );
    rollback(&dir, "sample", "2").unwrap();
    assert!(load_registry(&dir).unwrap().disabled["pack:sample"].contains("NewOnly"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_failed_registry_write_or_promotion_is_finished_by_the_next_migration() {
    let dir = std::env::temp_dir().join(format!("ant-mig3-{}", crate::storage::unique_id()));
    // Two files define `Twin`, so its id is namespaced; `Solo` is a bare name.
    install_version(
        &dir,
        "1",
        &[
            (
                "a.yar",
                "rule Twin { condition: true }\nrule Solo { condition: true }\n",
            ),
            ("b.yar", "rule Twin { condition: true }\n"),
        ],
    );
    let root = dir.join("rules/packs/yara/sample/1");
    for id in ["Solo", "Twin", "Gone"] {
        set_rule_enabled(&dir, "pack:sample", id, false).unwrap();
    }
    make_legacy(&root);
    let legacy = fs::read(root.join("index.json")).unwrap();
    let toggles = load_registry(&dir).unwrap().disabled;
    fail_once("registry-write");
    assert!(migrate_indexes(&dir).unwrap_err().contains("No space"));
    assert_eq!(fs::read(root.join("index.json")).unwrap(), legacy);
    assert!(root.join(STAGED_INDEX).is_file());
    assert_eq!(load_registry(&dir).unwrap().disabled, toggles);
    // The registry commits, then promotion is interrupted.
    fail_once("index-promote");
    assert_eq!(migrate_indexes(&dir).unwrap_err(), "interrupted");
    assert_eq!(parser_of(&root), 0);
    let saved = load_registry(&dir).unwrap();
    assert_eq!(
        saved.disabled["pack:sample"]
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["Solo".to_owned()]
    );
    // A restart finishes the staged index without rebuilding or repeating.
    let report = migrate_indexes(&dir).unwrap();
    assert_eq!(report.rebuilt.len(), 1);
    assert!(report.obsolete.is_empty(), "{report:?}");
    assert_eq!(parser_of(&root), u64::from(INDEX_PARSER));
    assert!(!root.join(STAGED_INDEX).exists());
    let finished = load_registry(&dir).unwrap();
    assert_eq!(
        finished.obsolete_disabled["pack:sample"],
        vec!["Gone".to_owned(), "Twin".to_owned()]
    );
    let reasons = &finished.obsolete_reasons["pack:sample"];
    assert!(reasons["Twin"].contains("matches 2 rules"), "{reasons:?}");
    assert!(reasons["Gone"].contains("no rule"), "{reasons:?}");
    // The ambiguous name was not applied to either namespaced rule.
    assert_eq!(
        snapshot_from(&dir, "yara", &finished, &installed_engines(), None)
            .unwrap()
            .enabled_rules,
        2
    );
    let again = migrate_indexes(&dir).unwrap();
    assert!(again.rebuilt.is_empty() && again.current.len() == 1);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn group_migration_reconciles_only_the_selected_revision() {
    let dir = std::env::temp_dir().join(format!("ant-mig4-{}", crate::storage::unique_id()));
    let source = dir.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("one.yar"), "rule First { condition: true }\n").unwrap();
    let id = import_group(&dir, "Local", "yara", &source).unwrap();
    fs::write(
        source.join("one.yar"),
        "rule First { condition: true }\nrule Second { condition: true }\n",
    )
    .unwrap();
    let revision = replace_group_revision(&dir, &id, &source).unwrap();
    let key = format!("group:{id}");
    set_rule_enabled(&dir, &key, "Second", false).unwrap();
    let base = dir.join("rules/custom").join(&id);
    for entry in fs::read_dir(&base).unwrap().flatten() {
        make_legacy(&entry.path());
    }
    let report = migrate_indexes(&dir).unwrap();
    assert!(report.rebuilt.len() >= 2, "{report:?}");
    assert!(report.obsolete.is_empty(), "{report:?}");
    let registry = load_registry(&dir).unwrap();
    assert!(registry.disabled[&key].contains("Second"));
    assert_eq!(registry.groups[0].revision, revision);
    let _ = fs::remove_dir_all(&dir);
}

mod source_catalog;
mod source_fixture;
mod source_install;
mod source_policy;

#[test]
fn the_registry_lock_is_per_data_directory() {
    let first = source_fixture_dir("lock-a");
    let second = source_fixture_dir("lock-b");
    let held = registry::registry_lock(&first);
    // Another data directory is not blocked by the first one's lock.
    let (sender, receiver) = std::sync::mpsc::channel();
    let other = second.clone();
    let thread = std::thread::spawn(move || {
        let _lock = registry::registry_lock(&other);
        sender.send(()).unwrap();
    });
    receiver
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("an unrelated data directory waited for the lock");
    thread.join().unwrap();
    // The same directory behind a symbolic link is the same lock.
    let spelled = second.join("alias");
    std::os::unix::fs::symlink(&first, &spelled).unwrap();
    assert_eq!(
        registry::lock_key(&rules_root(&spelled)),
        registry::lock_key(&rules_root(&first))
    );
    drop(held);
    let _ = fs::remove_dir_all(first);
    let _ = fs::remove_dir_all(second);
}

fn source_fixture_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ant-{label}-{}", crate::storage::unique_id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}
