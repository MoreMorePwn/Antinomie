// SPDX-License-Identifier: GPL-3.0-only
//! The canonical form of a submitted spec (design 5.2): keys sorted, no
//! whitespace, the spec as sent (before policy defaults are filled in). The
//! JSON map keeps insertion order when another crate of the workspace asks for
//! it, so the sorting is done here.

use serde_json::Value;

fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for key in keys {
                out.insert(key.clone(), sorted(&map[key]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

/// The canonical text of any serialisable value.
pub fn canonical(value: &impl serde::Serialize) -> String {
    let value = serde_json::to_value(value).unwrap_or(Value::Null);
    sorted(&value).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_order_does_not_matter() {
        let a: Value = serde_json::from_str(r#"{"b":1,"a":{"y":[2,1],"x":null}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":{"x":null,"y":[2,1]},"b":1}"#).unwrap();
        assert_eq!(canonical(&a), canonical(&b));
        assert_eq!(canonical(&a), r#"{"a":{"x":null,"y":[2,1]},"b":1}"#);
        let c: Value = serde_json::from_str(r#"{"a":{"x":null,"y":[1,2]},"b":1}"#).unwrap();
        assert_ne!(canonical(&a), canonical(&c));
    }
}
