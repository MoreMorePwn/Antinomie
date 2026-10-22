// SPDX-License-Identifier: GPL-3.0-only
//! The original text of one indexed rule, read from the installed file it was
//! parsed from. Nothing is stored beside the index: the text is cut out of the
//! pack or group file again with the same block splitters the index uses.
use super::*;

/// Largest rule file read for one rule, bytes. Packs hold files of a few MiB.
const RULE_FILE_LIMIT: u64 = 64 * 1024 * 1024;

/// The text of `rule` in the installed pack `id`.
pub fn pack_rule_source(
    data_dir: &Path,
    engine: &str,
    id: &str,
    rule: &IndexedRule,
) -> Result<String, String> {
    let registry = load_registry(data_dir)?;
    let pack = registry
        .packs
        .iter()
        .find(|pack| pack.id == id && pack.engine == engine)
        .ok_or_else(|| format!("pack {id} is not installed"))?;
    let root = rules_root(data_dir)
        .join("packs")
        .join(engine)
        .join(id)
        .join(&pack.version);
    rule_text(&root, engine, rule)
}

/// The text of `rule` in the custom group `id`.
pub fn group_rule_source(data_dir: &Path, id: &str, rule: &IndexedRule) -> Result<String, String> {
    let registry = load_registry(data_dir)?;
    let group = registry
        .groups
        .iter()
        .find(|group| group.id == id)
        .ok_or_else(|| format!("group {id} is not installed"))?;
    let root = rules_root(data_dir)
        .join("custom")
        .join(id)
        .join(group.revision.to_string());
    rule_text(&root, &group.engine, rule)
}

fn rule_text(root: &Path, engine: &str, rule: &IndexedRule) -> Result<String, String> {
    let file = Path::new(&rule.file);
    if rule.file.is_empty()
        || file.is_absolute()
        || file
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("the rule's file is not inside its pack".into());
    }
    let path = root.join(file);
    let length = fs::metadata(&path)
        .map_err(|error| format!("{}: {error}", rule.file))?
        .len();
    if length > RULE_FILE_LIMIT {
        return Err(format!("{} is too large to show", rule.file));
    }
    let text = fs::read_to_string(&path).map_err(|error| format!("{}: {error}", rule.file))?;
    rule_in_text(&text, engine, rule)
        .ok_or_else(|| format!("the rule was not found in {}", rule.file))
}

/// The block of `text` the index parsed `rule` from: the one whose body hash
/// matches, else the one with the same name (YARA) or id.
fn rule_in_text(text: &str, engine: &str, rule: &IndexedRule) -> Option<String> {
    let hash = |body: &str| format!("{:x}", Sha256::digest(body.as_bytes()));
    let blocks: Vec<(String, String)> = match engine {
        "yara" => yara_blocks(text)
            .into_iter()
            .map(|(name, body, _)| (name, body))
            .collect(),
        "ids" => ids_blocks(text),
        "sigma" => text
            .split("\n---\n")
            .filter(|doc| doc.contains("title:"))
            .map(|doc| (meta_line(doc, "id").unwrap_or_default(), doc.to_owned()))
            .collect(),
        _ => return None,
    };
    let key = if engine == "yara" {
        &rule.name
    } else {
        &rule.id
    };
    blocks
        .iter()
        .find(|(_, body)| !rule.content_sha256.is_empty() && hash(body) == rule.content_sha256)
        .or_else(|| blocks.iter().find(|(name, _)| name == key))
        .map(|(_, body)| body.trim_end().to_owned())
}
