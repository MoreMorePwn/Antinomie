// SPDX-License-Identifier: MIT
//! The text of one rule is cut from its installed file for every engine.
use super::*;

fn pack_of(dir: &Path, engine: &str, file: &str, text: &str) -> (String, Vec<IndexedRule>) {
    let mut entry = entry("unused", 0);
    entry.engine = engine.into();
    let bytes = archive(&[(file, text)]);
    entry.sha256 = crate::storage::sha256_hex(&bytes);
    entry.size = bytes.len() as u64;
    install_archive(dir, &entry, &bytes).unwrap();
    (
        entry.id.clone(),
        pack_index(dir, engine, &entry.id).unwrap(),
    )
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ant-rule-text-{name}-{}",
        crate::storage::unique_id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_yara_rule_is_cut_from_its_file_without_its_neighbours() {
    let dir = temp("yara");
    let text = "rule First { condition: true }\n\nrule Second\n{\n  meta:\n    description = \"two\"\n  condition: false\n}\n";
    let (id, rules) = pack_of(&dir, "yara", "a.yar", text);
    let second = rules.iter().find(|rule| rule.name == "Second").unwrap();
    let source = pack_rule_source(&dir, "yara", &id, second).unwrap();
    assert!(source.starts_with("rule Second") && source.contains("description = \"two\""));
    assert!(!source.contains("First"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn an_ids_rule_is_found_by_its_sid() {
    let dir = temp("ids");
    let text = "alert tcp any any -> any 80 (msg:\"one\"; sid:1001; rev:1;)\nalert tcp any any -> any 81 (msg:\"two\"; sid:1002; rev:1;)\n";
    let (id, rules) = pack_of(&dir, "ids", "a.rules", text);
    let two = rules.iter().find(|rule| rule.id == "1002").unwrap();
    let source = pack_rule_source(&dir, "ids", &id, two).unwrap();
    assert!(source.contains("sid:1002") && !source.contains("sid:1001"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_sigma_rule_is_found_among_the_documents_of_one_file() {
    let dir = temp("sigma");
    let doc = |id: &str| {
        format!(
            "title: Rule {id}\nid: {id}\nlogsource:\n  product: linux\n  category: process_creation\ndetection:\n  selection:\n    Image: /bin/x\n  condition: selection\nlevel: low\n"
        )
    };
    let text = format!("{}\n---\n{}", doc("aaaa"), doc("bbbb"));
    let (id, rules) = pack_of(&dir, "sigma", "a.yml", &text);
    let second = rules.iter().find(|rule| rule.id == "bbbb").unwrap();
    let source = pack_rule_source(&dir, "sigma", &id, second).unwrap();
    assert!(source.contains("title: Rule bbbb") && !source.contains("aaaa"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_rule_file_outside_the_pack_is_refused() {
    let dir = temp("escape");
    let (id, rules) = pack_of(&dir, "yara", "a.yar", "rule A { condition: true }\n");
    let mut rule = rules[0].clone();
    rule.file = "../../registry.json".into();
    assert!(pack_rule_source(&dir, "yara", &id, &rule).is_err());
    rule.file = "/etc/passwd".into();
    assert!(pack_rule_source(&dir, "yara", &id, &rule).is_err());
    let _ = fs::remove_dir_all(&dir);
}
