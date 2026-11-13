// SPDX-License-Identifier: GPL-3.0-only
//! `RecordingKey` (design 5.12.1): the opaque address of one recorded run. A run id
//! alone is not unique across boots, so the key carries `{vm_id, boot_id,
//! run_id}`. Clients never build or parse it; `recording.list` and
//! `Run.recording.recording_key` produce it, and the CLI's `vm:boot:run` triple is
//! turned into one with [`RecordingKey::from_triple`].

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt};

const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64url without padding.
pub(crate) fn base64url_encode(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        let digits = chunk.len() + 1;
        for i in 0..digits {
            text.push(URL_ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    text
}

/// The inverse of [`base64url_encode`]; `None` for any other input, including
/// padding and a length that no encoder makes.
pub(crate) fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 2);
    let bytes = text.as_bytes();
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, b) in chunk.iter().enumerate() {
            let value = URL_ALPHABET.iter().position(|a| a == b)? as u32;
            n |= value << (18 - 6 * i);
        }
        let produced = chunk.len() - 1;
        for i in 0..produced {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    // One encoding per byte string: spare bits must be zero.
    if base64url_encode(&out) != text {
        return None;
    }
    Some(out)
}

/// A key part is a path component of the data directory (the VM folder, the
/// boot folder, the run folder), so it may not contain a separator or be a
/// dot name.
fn safe_part(part: &str) -> bool {
    !part.is_empty()
        && part.len() <= 128
        && part != "."
        && part != ".."
        && part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Why a string is not a run key.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("not a run key: {0}")]
pub struct RunKeyError(pub &'static str);

/// The opaque run address: base64url (no padding) of the JSON array
/// `[vm_id, boot_id, run_id]`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RecordingKey(String);

impl RecordingKey {
    /// The key of a run, from the engine's own ids.
    pub fn new(vm_id: &str, boot_id: &str, run_id: &str) -> Result<Self, RunKeyError> {
        if ![vm_id, boot_id, run_id].into_iter().all(safe_part) {
            return Err(RunKeyError("an id is empty or not a plain file name"));
        }
        let json = serde_json::to_vec(&[vm_id, boot_id, run_id]).unwrap_or_default();
        Ok(Self(base64url_encode(&json)))
    }

    /// The CLI's `vm:boot:run` spelling.
    pub fn from_triple(triple: &str) -> Result<Self, RunKeyError> {
        let mut parts = triple.split(':');
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(vm), Some(boot), Some(run), None) => Self::new(vm, boot, run),
            _ => Err(RunKeyError("expected vm:boot:run")),
        }
    }

    /// The ids the key addresses: `(vm_id, boot_id, run_id)`.
    pub fn parts(&self) -> (String, String, String) {
        // The constructor and `TryFrom` check the shape, so this cannot fail.
        let bytes = base64url_decode(&self.0).unwrap_or_default();
        let parts: Vec<String> = serde_json::from_slice(&bytes).unwrap_or_default();
        let mut parts = parts.into_iter();
        (
            parts.next().unwrap_or_default(),
            parts.next().unwrap_or_default(),
            parts.next().unwrap_or_default(),
        )
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RecordingKey {
    type Error = RunKeyError;
    fn try_from(text: String) -> Result<Self, RunKeyError> {
        if text.len() > 512 {
            return Err(RunKeyError("too long"));
        }
        let bytes = base64url_decode(&text).ok_or(RunKeyError("not base64url"))?;
        let parts: Vec<String> =
            serde_json::from_slice(&bytes).map_err(|_| RunKeyError("not a run address"))?;
        let [vm, boot, run] = parts.as_slice() else {
            return Err(RunKeyError("expected three ids"));
        };
        let key = Self::new(vm, boot, run)?;
        // One key, one spelling.
        if key.0 == text {
            Ok(key)
        } else {
            Err(RunKeyError("not the canonical spelling"))
        }
    }
}

impl From<RecordingKey> for String {
    fn from(key: RecordingKey) -> String {
        key.0
    }
}

impl fmt::Display for RecordingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl JsonSchema for RecordingKey {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("RecordingKey")
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({"type": "string", "pattern": "^[A-Za-z0-9_-]+$", "maxLength": 512,
            "description": "Opaque run address. Produced by recording.list and Run.recording.recording_key; clients never build or parse it."})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_the_rfc_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64url_encode(plain.as_bytes()), encoded);
            assert_eq!(base64url_decode(encoded).unwrap(), plain.as_bytes());
        }
        assert_eq!(base64url_encode(&[0xfb, 0xff]), "-_8");
        assert!(
            base64url_decode("Zg==").is_none(),
            "padding is not part of the spelling"
        );
        assert!(base64url_decode("Z").is_none());
        assert!(base64url_decode("Zh").is_none(), "non-zero spare bits");
    }

    #[test]
    fn a_key_round_trips_its_three_ids() {
        let key = RecordingKey::new("vm_1", "b2", "r3.x").unwrap();
        assert_eq!(key.parts(), ("vm_1".into(), "b2".into(), "r3.x".into()));
        assert_eq!(RecordingKey::try_from(key.to_string()).unwrap(), key);
        assert_eq!(RecordingKey::from_triple("vm_1:b2:r3.x").unwrap(), key);
        let value = serde_json::to_value(&key).unwrap();
        assert_eq!(serde_json::from_value::<RecordingKey>(value).unwrap(), key);
    }

    #[test]
    fn a_key_cannot_name_a_path() {
        for bad in ["..", ".", "a/b", "", "a b", "é"] {
            assert!(RecordingKey::new(bad, "b", "r").is_err(), "{bad:?}");
            assert!(RecordingKey::new("v", bad, "r").is_err());
            assert!(RecordingKey::new("v", "b", bad).is_err());
        }
        assert!(RecordingKey::from_triple("a:b").is_err());
        assert!(RecordingKey::from_triple("a:b:c:d").is_err());
        let hand_made = base64url_encode(br#"["../x","b","r"]"#);
        assert!(RecordingKey::try_from(hand_made).is_err());
        let loose = base64url_encode(br#"[ "v","b","r"]"#);
        assert!(
            RecordingKey::try_from(loose).is_err(),
            "only the canonical spelling is a key"
        );
        assert!(RecordingKey::try_from("!!".to_owned()).is_err());
    }
}
