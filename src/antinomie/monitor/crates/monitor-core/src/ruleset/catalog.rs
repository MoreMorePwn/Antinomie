// SPDX-License-Identifier: GPL-3.0-only
//! The rules catalog: validation, loading and storing.
use super::*;

pub fn validate_catalog(value: &Value) -> Result<Catalog, String> {
    let object = value.as_object().ok_or("catalog must be a JSON object")?;
    let schema = required_u64(object, "schema")?;
    let packs = object
        .get("packs")
        .and_then(Value::as_array)
        .ok_or("catalog packs must be an array")?;
    if schema == u64::from(CATALOG_SCHEMA_SOURCES) {
        return validate_source_catalog(packs);
    }
    if schema != u64::from(CATALOG_SCHEMA) {
        return Err(format!("unsupported rules catalog schema {schema}"));
    }
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    for pack in packs {
        let entry = pack_entry(pack)?;
        if !seen.insert(entry.id.clone()) {
            return Err(format!("duplicate pack id {}", entry.id));
        }
        entries.push(entry);
    }
    Ok(Catalog {
        schema: CATALOG_SCHEMA,
        packs: entries,
        sources: Vec::new(),
    })
}

fn validate_source_catalog(packs: &[Value]) -> Result<Catalog, String> {
    let mut sources = Vec::new();
    let mut seen = BTreeSet::new();
    for pack in packs {
        let pack = validate_source_pack(pack)?;
        if !seen.insert(pack.id.clone()) {
            return Err(format!("duplicate pack id {}", pack.id));
        }
        sources.push(pack);
    }
    Ok(Catalog {
        schema: CATALOG_SCHEMA_SOURCES,
        packs: Vec::new(),
        sources,
    })
}

fn pack_entry(value: &Value) -> Result<PackEntry, String> {
    let object = value.as_object().ok_or("pack entry must be an object")?;
    let engine = required_string(object, "engine")?;
    if !ENGINES.contains(&engine.as_str()) {
        return Err(format!("unknown rules engine {engine}"));
    }
    let id = required_string(object, "id")?;
    if !valid_id(&id) {
        return Err(format!("pack id {id} is not a stable identifier"));
    }
    let version = required_string(object, "version")?;
    path_component(&version, "version")?;
    let sha256 = required_string(object, "sha256")?;
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("pack {id} checksum is not SHA-256"));
    }
    Ok(PackEntry {
        id,
        engine,
        name: required_string(object, "name")?,
        version,
        upstream_revision: required_string(object, "upstream_revision")?,
        upstream_url: required_string(object, "upstream_url")?,
        download_url: required_string(object, "download_url")?,
        sha256: sha256.to_ascii_lowercase(),
        size: required_u64(object, "size")?,
        app: required_string(object, "app")?,
        engine_requirement: required_string(object, "engine_requirement")?,
        rules: required_u64(object, "rules")?,
        helpers: required_u64(object, "helpers")?,
        license: required_string(object, "license")?,
        evidence: string_list(object, "evidence")?,
        limits: string_list(object, "limits")?,
    })
}

fn required_string(object: &Map<String, Value>, key: &str) -> Result<String, String> {
    match object.get(key) {
        Some(Value::String(text)) if !text.is_empty() => Ok(text.clone()),
        Some(Value::Null) => Err(format!("{key} is null")),
        Some(_) => Err(format!("{key} must be a string")),
        None => Err(format!("missing {key}")),
    }
}

fn required_u64(object: &Map<String, Value>, key: &str) -> Result<u64, String> {
    match object.get(key) {
        Some(Value::Number(number)) => number
            .as_u64()
            .ok_or_else(|| format!("{key} must be a non-negative integer")),
        Some(Value::Null) => Err(format!("{key} is null")),
        Some(_) => Err(format!("{key} must be an integer")),
        None => Err(format!("missing {key}")),
    }
}

/// Missing and JSON null both mean an empty list. Any other type is an error.
fn string_list(object: &Map<String, Value>, key: &str) -> Result<Vec<String>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{key} entries must be strings"))
            })
            .collect(),
        Some(_) => Err(format!("{key} must be an array or null")),
    }
}

pub fn load_catalog(data_dir: &Path) -> Result<Option<Catalog>, String> {
    let path = rules_root(data_dir).join("catalog.json");
    if !path.is_file() {
        return Ok(None);
    }
    let data = fs::read(&path).map_err(|error| error.to_string())?;
    let value: Value = serde_json::from_slice(&data).map_err(|error| error.to_string())?;
    validate_catalog(&value).map(Some)
}

pub fn store_catalog(data_dir: &Path, catalog: &Catalog) -> Result<(), String> {
    let root = rules_root(data_dir);
    crate::storage::private_dir(&root).map_err(|error| error.to_string())?;
    if catalog.schema == CATALOG_SCHEMA_SOURCES {
        let stored = serde_json::json!({"schema": catalog.schema, "packs": catalog.sources});
        return crate::storage::atomic_json(&root.join("catalog.json"), &stored);
    }
    let stored = serde_json::json!({"schema": catalog.schema, "packs": catalog.packs});
    crate::storage::atomic_json(&root.join("catalog.json"), &stored)
}
