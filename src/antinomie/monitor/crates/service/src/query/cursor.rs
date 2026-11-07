// SPDX-License-Identifier: GPL-3.0-only
//! Paging cursors (design 5.12.5). A cursor is opaque and encodes
//! `{offset, generation, filter_hash, sort_hash}`. The trace cursor's offset is
//! a raw-file byte offset, not a row number. A cursor from another generation,
//! filter or sort fails `conflict` with `details.reason = "cursor_stale"`.

use super::key::{base64url_decode, base64url_encode};
use crate::api::error::ApiError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Cursors are 33 bytes: a version byte and four little-endian u64.
const VERSION: u8 = 1;
const LEN: usize = 1 + 4 * 8;

/// A monotonic token for a recording's content: a hash of the manifest and
/// journal file sizes and modification times. Sent as a decimal string
/// (identifiers that can pass 2^53 are strings).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Generation(pub u64);

impl Serialize for Generation {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Generation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map(Self).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for Generation {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Generation".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({"type": "string", "pattern": "^[0-9]{1,20}$",
            "description": "Monotonic token for the recording's content, a decimal string. The ETag of a complete recording."})
    }
}

/// FNV-1a over the canonical JSON of a value: stable across runs and builds,
/// which a cursor needs (a `DefaultHasher` is not).
pub fn stable_hash<T: Serialize>(value: &T) -> u64 {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// What a cursor binds a walk to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorBinding {
    pub generation: Generation,
    pub filter_hash: u64,
    pub sort_hash: u64,
}

/// The decoded cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    /// Where the next page starts: a row index, or a byte offset for the trace
    /// and the terminal journal.
    pub offset: u64,
    pub binding: CursorBinding,
}

impl Cursor {
    pub fn encode(&self) -> String {
        let mut bytes = Vec::with_capacity(LEN);
        bytes.push(VERSION);
        for value in [
            self.offset,
            self.binding.generation.0,
            self.binding.filter_hash,
            self.binding.sort_hash,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        base64url_encode(&bytes)
    }

    /// A cursor that is not one this build made is `invalid_argument`.
    pub fn decode(text: &str) -> Result<Self, ApiError> {
        let bad = || ApiError::invalid_argument("cursor", "not a cursor this service made");
        if text.len() > 64 {
            return Err(bad());
        }
        let bytes = base64url_decode(text).ok_or_else(bad)?;
        if bytes.len() != LEN || bytes[0] != VERSION {
            return Err(bad());
        }
        let word = |index: usize| {
            let start = 1 + index * 8;
            let mut word = [0u8; 8];
            word.copy_from_slice(&bytes[start..start + 8]);
            u64::from_le_bytes(word)
        };
        Ok(Self {
            offset: word(0),
            binding: CursorBinding {
                generation: Generation(word(1)),
                filter_hash: word(2),
                sort_hash: word(3),
            },
        })
    }

    /// The offset to continue from, or `cursor_stale` when the generation, the
    /// filter or the sort is not the one the cursor was made for.
    pub fn resume(text: &str, now: CursorBinding) -> Result<u64, ApiError> {
        let cursor = Self::decode(text)?;
        if cursor.binding == now {
            Ok(cursor.offset)
        } else {
            Err(ApiError::cursor_stale())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::error::ErrorReason;

    fn binding() -> CursorBinding {
        CursorBinding {
            generation: Generation(7),
            filter_hash: stable_hash(&serde_json::json!({"tier": "high"})),
            sort_hash: stable_hash(&serde_json::json!(null)),
        }
    }

    #[test]
    fn a_cursor_round_trips_and_resumes() {
        let cursor = Cursor {
            offset: u64::MAX - 5,
            binding: binding(),
        };
        let text = cursor.encode();
        assert!(text.len() <= 64);
        assert_eq!(Cursor::decode(&text).unwrap(), cursor);
        assert_eq!(Cursor::resume(&text, binding()).unwrap(), u64::MAX - 5);
    }

    #[test]
    fn another_generation_filter_or_sort_is_stale() {
        let text = Cursor {
            offset: 3,
            binding: binding(),
        }
        .encode();
        for changed in [
            CursorBinding {
                generation: Generation(8),
                ..binding()
            },
            CursorBinding {
                filter_hash: 1,
                ..binding()
            },
            CursorBinding {
                sort_hash: 1,
                ..binding()
            },
        ] {
            let error = Cursor::resume(&text, changed).unwrap_err();
            assert_eq!(error.code, crate::api::error::ErrorCode::Conflict);
            assert_eq!(error.reason(), Some(ErrorReason::CursorStale));
        }
    }

    #[test]
    fn garbage_is_invalid_argument_naming_the_cursor() {
        for text in ["", "AAAA", "!!!", &"A".repeat(200)] {
            let error = Cursor::decode(text).unwrap_err();
            assert_eq!(error.code, crate::api::error::ErrorCode::InvalidArgument);
            assert_eq!(error.field.as_deref(), Some("cursor"));
        }
        let mut wrong_version = Cursor {
            offset: 0,
            binding: binding(),
        }
        .encode()
        .into_bytes();
        wrong_version[0] = b'B';
        assert!(Cursor::decode(&String::from_utf8(wrong_version).unwrap()).is_err());
    }

    #[test]
    fn the_hash_is_stable_and_sensitive() {
        assert_eq!(
            stable_hash(&serde_json::json!({"a": 1})),
            stable_hash(&serde_json::json!({"a": 1}))
        );
        assert_ne!(
            stable_hash(&serde_json::json!({"a": 1})),
            stable_hash(&serde_json::json!({"a": 2}))
        );
        // FNV-1a of "null" is a fixed value: a regression guard for the
        // hash being part of a cursor.
        assert_eq!(stable_hash(&serde_json::json!(null)), 0x5b9b_c4ba_5281_08e4);
    }
}
