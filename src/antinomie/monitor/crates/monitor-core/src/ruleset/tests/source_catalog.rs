// SPDX-License-Identifier: MIT
use super::source_fixture::*;
use super::*;

fn catalog_json(pack: &SourcePack) -> Value {
    serde_json::json!({"schema": 2, "packs": [pack]})
}

#[test]
fn schema_two_lists_sources_and_schema_one_still_reads() {
    let (pack, _) = forge_pack();
    let parsed = validate_catalog(&catalog_json(&pack)).unwrap();
    assert_eq!(parsed.schema, CATALOG_SCHEMA_SOURCES);
    assert!(parsed.packs.is_empty());
    assert_eq!(parsed.sources, vec![pack.clone()]);

    let v1 = serde_json::json!({"schema": 1, "packs": [{
        "id": "core", "engine": "sigma", "name": "Core", "version": "1",
        "upstream_revision": "abc", "upstream_url": "https://example.invalid/",
        "download_url": "https://example.invalid/core.tar.gz",
        "sha256": "a".repeat(64), "size": 10, "app": ">=0.6.2",
        "engine_requirement": "pySigma 2.x", "rules": 1, "helpers": 0,
        "license": "x", "evidence": [], "limits": null
    }]});
    let old = validate_catalog(&v1).unwrap();
    assert_eq!(old.schema, CATALOG_SCHEMA);
    assert_eq!(old.packs.len(), 1);
    assert!(old.sources.is_empty());
    assert!(
        validate_catalog(&serde_json::json!({"schema": 3, "packs": []}))
            .unwrap_err()
            .contains("schema")
    );
}

#[test]
fn schema_two_example_entry_round_trips_through_the_local_copy() {
    let (pack, _) = forge_pack();
    let dir = temp_dir("cat-store");
    let catalog = validate_catalog(&catalog_json(&pack)).unwrap();
    store_catalog(&dir, &catalog).unwrap();
    let stored: Value =
        serde_json::from_slice(&fs::read(dir.join("rules/catalog.json")).unwrap()).unwrap();
    assert_eq!(stored["schema"], 2);
    assert_eq!(stored["packs"][0]["id"], "forge-core");
    assert_eq!(stored["packs"][0]["filter"]["kind"], "yara-forge");
    assert_eq!(load_catalog(&dir).unwrap().unwrap(), catalog);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn schema_two_rejects_unsafe_or_incomplete_entries() {
    let (good, _) = forge_pack();
    let reject = |edit: &dyn Fn(&mut SourcePack), needle: &str| {
        let mut pack = good.clone();
        edit(&mut pack);
        let error = validate_catalog(&catalog_json(&pack)).unwrap_err();
        assert!(error.contains(needle), "{error} should mention {needle}");
    };
    reject(
        &|p| p.sources[0].url = "http://github.com/a/b.zip".into(),
        "https",
    );
    reject(
        &|p| p.sources[0].url = "https://user@github.com/a/b.zip".into(),
        "host",
    );
    reject(
        &|p| p.sources[0].url = "https://github.com:444/a/b.zip".into(),
        "host",
    );
    reject(&|p| p.sources[0].format = "rar".into(), "format");
    reject(&|p| p.sources[0].sha256 = "xyz".into(), "SHA-256");
    reject(
        &|p| p.sources[0].files[0].sha256 = "A".repeat(64),
        "SHA-256",
    );
    reject(
        &|p| p.sources[0].files[0].path = "../escape.yar".into(),
        "relative",
    );
    reject(
        &|p| p.sources[0].files[0].path = "/abs.yar".into(),
        "relative",
    );
    reject(&|p| p.sources[0].files.clear(), "no files");
    reject(&|p| p.sources[0].size = 0, "size");
    reject(&|p| p.sources[0].size = MAX_SOURCE_BYTES + 1, "size");
    reject(
        &|p| {
            p.sources[0].rolling = true;
            p.sources[0].paths.clear();
        },
        "rolling",
    );
    reject(&|p| p.revision = "a/b".into(), "revision");
    reject(&|p| p.revision_kind = "latest".into(), "revision kind");
    reject(&|p| p.engine = "ids".into(), "belongs to a YARA pack");
    reject(&|p| p.engine = "nope".into(), "engine");
    reject(&|p| p.homepage = "ftp://x".into(), "https");
    reject(&|p| p.id = "Not Valid".into(), "identifier");
    reject(&|p| p.options.push(p.options[0].clone()), "twice");
    reject(
        &|p| {
            let again = p.sources[0].clone();
            p.sources.push(again);
        },
        "twice",
    );
    let duplicate = serde_json::json!({"schema": 2, "packs": [good, good]});
    assert!(
        validate_catalog(&duplicate)
            .unwrap_err()
            .contains("duplicate")
    );
    let mut missing = catalog_json(&good);
    missing["packs"][0]
        .as_object_mut()
        .unwrap()
        .remove("revision");
    assert!(validate_catalog(&missing).unwrap_err().contains("revision"));
}

#[test]
fn a_pack_names_every_host_it_contacts() {
    let (mut pack, _) = forge_pack();
    assert_eq!(pack.primary_hosts(), ["github.com"]);
    let hosts = pack.hosts();
    for host in [
        "github.com",
        "codeload.github.com",
        "release-assets.githubusercontent.com",
        "objects.githubusercontent.com",
    ] {
        assert!(
            hosts.iter().any(|found| found == host),
            "{host} in {hosts:?}"
        );
    }
    let mut other = pack.sources[0].clone();
    other.url = "https://rules.example.org/open.rules".into();
    pack.sources.push(other);
    assert!(
        pack.primary_hosts()
            .contains(&"rules.example.org".to_owned())
    );
    assert!(pack.hosts().contains(&"rules.example.org".to_owned()));
    assert!(redirect_hosts("rules.example.org").is_empty());
}

#[test]
fn the_version_follows_the_pin_the_filter_and_the_options() {
    let (pack, _) = forge_pack();
    let none = BTreeSet::new();
    let unlicensed = BTreeSet::from(["include-unlicensed".to_owned()]);
    let default = pack.version(&none);
    assert!(default.starts_with("1-"));
    assert_eq!(default, pack.version(&none));
    assert_ne!(default, pack.version(&unlicensed));
    assert!(
        pack.default_options().is_empty(),
        "no-license rules are off by default"
    );
    assert_eq!(
        pack.unknown_options(&BTreeSet::from(["x".to_owned()])),
        ["x"]
    );
    let mut repinned = pack.clone();
    repinned.revision = "2".into();
    assert_ne!(default, repinned.version(&none));
    let mut refiltered = pack.clone();
    if let SourceFilter::YaraForge(filter) = &mut refiltered.filter {
        filter.allowed_repository_licenses.push("GPL-3.0".into());
    }
    assert_ne!(
        pack.plan_digest(&none),
        refiltered.plan_digest(&none),
        "a filter change is a different plan"
    );
    path_component(&default, "version").unwrap();
}
