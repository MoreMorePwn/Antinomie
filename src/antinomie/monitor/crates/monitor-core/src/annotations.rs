// SPDX-License-Identifier: MIT
//! User labels separate from recorder-owned evidence and identities.
use serde::{Deserialize, Serialize};
use std::{fs, io::Read, path::Path};
const FILE: &str = "annotation.json";
const MAX_SIZE: u64 = 16 * 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Annotation {
    pub name: String,
    pub tags: Vec<String>,
}
impl Annotation {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.len() > 256 || self.name.chars().any(char::is_control) {
            return Err("name must be at most 256 UTF-8 bytes without control characters".into());
        }
        if self.tags.len() > 32
            || self
                .tags
                .iter()
                .any(|tag| tag.is_empty() || tag.len() > 64 || tag.chars().any(char::is_control))
        {
            return Err(
                "use at most 32 tags, each 1..64 UTF-8 bytes without control characters".into(),
            );
        }
        Ok(())
    }
}
/// Read a bounded sidecar. Missing labels preserve the original title.
pub fn load(directory: &Path) -> Result<Annotation, String> {
    let path = directory.join(FILE);
    if !path.exists() {
        return Ok(Annotation::default());
    }
    let file = crate::archive_io::open_regular(directory, &path).map_err(|e| e.to_string())?;
    let mut data = Vec::new();
    file.take(MAX_SIZE + 1)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() as u64 > MAX_SIZE {
        return Err("annotation exceeds 16 KiB".into());
    }
    let annotation: Annotation = serde_json::from_slice(&data).map_err(|e| e.to_string())?;
    annotation.validate()?;
    Ok(annotation)
}
/// Atomically replace the label sidecar without changing original evidence.
pub fn save(directory: &Path, annotation: &Annotation) -> Result<(), String> {
    annotation.validate()?;
    if !directory.is_dir() {
        if directory.parent().is_none_or(|parent| !parent.is_dir()) {
            return Err("evidence directory is unavailable".into());
        }
        crate::storage::private_dir(directory).map_err(|e| e.to_string())?;
    }
    let path = directory.join(FILE);
    if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("annotation path is a symbolic link".into());
    }
    crate::storage::atomic_json(&path, annotation)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn labels_roundtrip_preserving_evidence_and_reject_bad_values() {
        let dir = std::env::temp_dir().join(format!("ant-label-{}", crate::storage::unique_id()));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("run.json"), b"original").unwrap();
        assert_eq!(load(&dir).unwrap(), Annotation::default());
        let value = Annotation {
            name: "Suspicious child".into(),
            tags: vec!["triage".into()],
        };
        save(&dir, &value).unwrap();
        assert_eq!(load(&dir).unwrap(), value);
        assert_eq!(fs::read(dir.join("run.json")).unwrap(), b"original");
        assert!(
            save(
                &dir,
                &Annotation {
                    name: "x\n".into(),
                    tags: vec![]
                }
            )
            .is_err()
        );
        fs::write(dir.join(FILE), vec![0; MAX_SIZE as usize + 1]).unwrap();
        assert!(load(&dir).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
