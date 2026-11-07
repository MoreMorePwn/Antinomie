// SPDX-License-Identifier: GPL-3.0-only
//! Identifiers of the job API (design 5.2): an opaque string that is safe as a
//! path component, a prefix and 26 Crockford base32 characters in the shape of
//! a ULID (time-ordered, built locally; no new crate).
//!
//! `j_` job, `a_` artifact, `u_` upload, `ra_` recording artifact. Lane ids
//! are `lane-<n>` ([`LaneId`]). Sample identity is the lowercase SHA-256
//! ([`Sha256Hex`]).

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Why a string is not an identifier of the expected kind.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct IdError(pub String);

/// The 26 characters of a ULID: 48 bits of Unix milliseconds, then 80 random
/// bits. Ids made later sort after ids made earlier.
pub fn encode_ulid(time_ms: u64, random: [u8; 10]) -> String {
    let mut value: u128 = u128::from(time_ms & 0xFFFF_FFFF_FFFF) << 80;
    let mut low: u128 = 0;
    for byte in random {
        low = (low << 8) | u128::from(byte);
    }
    value |= low;
    let mut text = String::with_capacity(26);
    for index in (0..26).rev() {
        let digit = ((value >> (index * 5)) & 0x1F) as usize;
        text.push(ALPHABET[digit] as char);
    }
    text
}

fn valid_ulid(text: &str) -> bool {
    text.len() == 26
        && text.bytes().all(|b| ALPHABET.contains(&b))
        // 128 bits in 26 characters: the first holds only 3 bits.
        && text.as_bytes()[0] <= b'7'
}

macro_rules! prefixed_id {
    ($name:ident, $prefix:literal, $what:literal) => {
        #[doc = concat!("The identifier of ", $what, ": `", $prefix, "_` and 26 base32 characters.")]
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// The prefix of this kind of identifier, with its underscore.
            pub const PREFIX: &'static str = concat!($prefix, "_");

            /// A new identifier from the clock and 80 random bits.
            pub fn from_parts(time_ms: u64, random: [u8; 10]) -> Self {
                Self(format!("{}{}", Self::PREFIX, encode_ulid(time_ms, random)))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdError;
            fn try_from(text: String) -> Result<Self, IdError> {
                match text.strip_prefix(Self::PREFIX) {
                    Some(rest) if valid_ulid(rest) => Ok(Self(text)),
                    _ => Err(IdError(format!(
                        "not {}: expected `{}` and 26 base32 characters",
                        $what,
                        Self::PREFIX
                    ))),
                }
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> String {
                id.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> Cow<'static, str> {
                Cow::Borrowed(stringify!($name))
            }
            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!({
                    "type": "string",
                    "pattern": concat!("^", $prefix, "_[0-7][0-9A-HJKMNP-TV-Z]{25}$"),
                    "description": concat!("The identifier of ", $what, ".")
                })
            }
        }
    };
}

prefixed_id!(JobId, "j", "a job");
prefixed_id!(ArtifactId, "a", "a job artifact");
prefixed_id!(UploadId, "u", "a staged upload");
prefixed_id!(RecordingArtifactId, "ra", "a file of a recording");

/// A lane: `lane-<n>`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LaneId(String);

impl LaneId {
    pub fn new(number: u32) -> Self {
        Self(format!("lane-{number}"))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LaneId {
    type Error = IdError;
    fn try_from(text: String) -> Result<Self, IdError> {
        let ok = text.strip_prefix("lane-").is_some_and(|n| {
            !n.is_empty() && n.len() <= 9 && n.bytes().all(|b| b.is_ascii_digit())
        });
        if ok {
            Ok(Self(text))
        } else {
            Err(IdError("not a lane id: expected `lane-<n>`".into()))
        }
    }
}

impl From<LaneId> for String {
    fn from(id: LaneId) -> String {
        id.0
    }
}

impl fmt::Display for LaneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl JsonSchema for LaneId {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("LaneId")
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({"type": "string", "pattern": "^lane-[0-9]{1,9}$",
            "description": "A lane: `lane-<n>`."})
    }
}

/// A sample's identity: 64 lowercase hex characters.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256Hex(String);

impl Sha256Hex {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Sha256Hex {
    type Error = IdError;
    fn try_from(text: String) -> Result<Self, IdError> {
        if text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(Self(text))
        } else {
            Err(IdError(
                "not a SHA-256: expected 64 lowercase hex characters".into(),
            ))
        }
    }
}

impl From<Sha256Hex> for String {
    fn from(id: Sha256Hex) -> String {
        id.0
    }
}

impl fmt::Display for Sha256Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl JsonSchema for Sha256Hex {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("Sha256Hex")
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({"type": "string", "pattern": "^[0-9a-f]{64}$",
            "description": "A sample's identity: the lowercase SHA-256."})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_have_a_prefix_and_26_base32_characters() {
        let id = JobId::from_parts(1_794_000_000_000, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert!(id.as_str().starts_with("j_"));
        assert_eq!(id.as_str().len(), 28);
        assert_eq!(JobId::try_from(id.to_string()).unwrap(), id);
        assert!(ArtifactId::try_from(id.to_string()).is_err());
        assert!(JobId::try_from("j_short".to_owned()).is_err());
        assert!(JobId::try_from(format!("j_{}", "I".repeat(26))).is_err());
        assert!(JobId::try_from(format!("j_8{}", "0".repeat(25))).is_err());
    }

    #[test]
    fn later_ids_sort_after_earlier_ones() {
        let a = JobId::from_parts(1_000, [255; 10]);
        let b = JobId::from_parts(1_001, [0; 10]);
        assert!(a < b);
        let max = JobId::from_parts(0xFFFF_FFFF_FFFF, [255; 10]);
        assert_eq!(max.as_str(), "j_7ZZZZZZZZZZZZZZZZZZZZZZZZZ");
    }

    #[test]
    fn lane_and_sha256_are_checked() {
        assert!(LaneId::try_from("lane-1".to_owned()).is_ok());
        assert!(LaneId::try_from("lane-".to_owned()).is_err());
        assert!(LaneId::try_from("lane-x".to_owned()).is_err());
        assert!(Sha256Hex::try_from("a".repeat(64)).is_ok());
        assert!(Sha256Hex::try_from("A".repeat(64)).is_err());
        assert!(Sha256Hex::try_from("a".repeat(63)).is_err());
    }
}
