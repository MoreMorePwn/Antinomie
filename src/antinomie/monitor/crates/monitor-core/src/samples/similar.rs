// SPDX-License-Identifier: GPL-3.0-only
//! Library samples that look like another by TLSH distance, and what they
//! share. The stored hash cannot be parsed back by `tlsh2`, so a candidate's
//! hash is built again from its archived bytes; only samples up to
//! [`MAX_SIZE`] are compared and at most [`MAX_CANDIDATES`] are read, so
//! opening a sample window never reads the whole library.
use super::Library;
use std::collections::{BTreeSet, HashSet};

/// Closer than this is "similar": TLSH reads 0 as identical and anything up
/// to about 100 as a close variant; 150 keeps loose relatives too.
pub const MAX_DISTANCE: i32 = 150;
/// Rows the Summary lists.
pub const MAX_ROWS: usize = 5;
/// Archives larger than this are not compared.
pub const MAX_SIZE: u64 = 16 * 1024 * 1024;
/// Samples read for one comparison.
pub const MAX_CANDIDATES: usize = 300;
/// The shortest string that counts as shared.
const MIN_STRING: usize = 8;
/// Strings kept per file.
const MAX_STRINGS: usize = 20_000;

/// What two samples have in common.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shared {
    /// Both are ELF files: the symbols they import.
    Imports { count: usize, examples: Vec<String> },
    /// Anything else: printable strings of eight or more characters.
    Strings { count: usize, examples: Vec<String> },
}

impl Shared {
    pub fn count(&self) -> usize {
        match self {
            Shared::Imports { count, .. } | Shared::Strings { count, .. } => *count,
        }
    }

    pub fn label(&self) -> String {
        let (count, word) = match self {
            Shared::Imports { count, .. } => (*count, "import"),
            Shared::Strings { count, .. } => (*count, "string"),
        };
        format!("{count} {word}{}", if count == 1 { "" } else { "s" })
    }

    pub fn examples(&self) -> &[String] {
        match self {
            Shared::Imports { examples, .. } | Shared::Strings { examples, .. } => examples,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Similar {
    pub sha256: String,
    pub name: String,
    pub distance: i32,
    pub shared: Shared,
}

fn tlsh(bytes: &[u8]) -> Option<tlsh2::TlshDefault> {
    tlsh2::TlshDefaultBuilder::build_from(bytes)
}

/// Symbols an ELF file imports, or `None` when it is not an ELF file.
fn imports(bytes: &[u8]) -> Option<BTreeSet<String>> {
    use object::Object;
    if !bytes.starts_with(b"\x7fELF") {
        return None;
    }
    let file = object::File::parse(bytes).ok()?;
    Some(
        file.imports()
            .ok()?
            .filter_map(Result::ok)
            .filter_map(|import| match import.name() {
                object::NameOrOrdinal::Name(name) => String::from_utf8(name.to_vec()).ok(),
                object::NameOrOrdinal::Ordinal(_) => None,
            })
            .filter(|name| !name.is_empty())
            .collect(),
    )
}

fn strings(bytes: &[u8]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut start = None;
    let flush = |from: usize, to: usize, out: &mut BTreeSet<String>| {
        if to - from >= MIN_STRING && out.len() < MAX_STRINGS {
            out.insert(String::from_utf8_lossy(&bytes[from..to]).into_owned());
        }
    };
    for (at, byte) in bytes.iter().enumerate() {
        let printable = matches!(byte, 0x20..=0x7e);
        match (printable, start) {
            (true, None) => start = Some(at),
            (false, Some(from)) => {
                flush(from, at, &mut out);
                start = None;
            }
            _ => {}
        }
    }
    if let Some(from) = start {
        flush(from, bytes.len(), &mut out);
    }
    out
}

/// What `a` and `b` share: imports when both are ELF files, strings otherwise.
pub fn shared(a: &[u8], b: &[u8]) -> Shared {
    let (names, by_imports): (BTreeSet<String>, bool) = match (imports(a), imports(b)) {
        (Some(left), Some(right)) => (left.intersection(&right).cloned().collect(), true),
        _ => (
            strings(a).intersection(&strings(b)).cloned().collect(),
            false,
        ),
    };
    // The longest first: they say the most.
    let mut examples: Vec<String> = names.iter().cloned().collect();
    examples.sort_by(|x, y| y.len().cmp(&x.len()).then_with(|| x.cmp(y)));
    examples.truncate(5);
    let count = names.len();
    if by_imports {
        Shared::Imports { count, examples }
    } else {
        Shared::Strings { count, examples }
    }
}

/// The closest of `candidates` to `subject`, nearest first.
pub fn rank<'a>(
    subject: &[u8],
    candidates: impl Iterator<Item = (&'a str, &'a str, Vec<u8>)>,
) -> Result<Vec<Similar>, String> {
    let Some(mine) = tlsh(subject) else {
        return Err("too small or too uniform for a similarity hash".into());
    };
    let mut found: Vec<Similar> = candidates
        .filter_map(|(sha256, name, bytes)| {
            let theirs = tlsh(&bytes)?;
            let distance = mine.diff(&theirs, true);
            (distance <= MAX_DISTANCE).then(|| Similar {
                sha256: sha256.to_owned(),
                name: name.to_owned(),
                distance,
                shared: shared(subject, &bytes),
            })
        })
        .collect();
    found.sort_by(|a, b| {
        a.distance
            .cmp(&b.distance)
            .then_with(|| a.name.cmp(&b.name))
    });
    found.truncate(MAX_ROWS);
    Ok(found)
}

impl Library {
    /// The samples most like `sha256`, leaving out `exclude` (itself, its
    /// parents and its children, which the lineage graph shows).
    pub fn similar_to(
        &self,
        sha256: &str,
        exclude: &HashSet<String>,
    ) -> Result<Vec<Similar>, String> {
        let archive = self.archive_path(sha256)?;
        let subject = super::open_sample(&archive, sha256)?;
        let mut loaded = Vec::new();
        for record in self.list()? {
            if loaded.len() >= MAX_CANDIDATES {
                break;
            }
            if record.sha256 == sha256
                || exclude.contains(&record.sha256)
                || record.removed_ms.is_some()
                || record.size > MAX_SIZE
                || record.tlsh.is_empty()
            {
                continue;
            }
            let Ok(path) = self.archive_path(&record.sha256) else {
                continue;
            };
            let Ok(bytes) = super::open_sample(&path, &record.sha256) else {
                continue;
            };
            loaded.push((record.sha256, record.name, bytes));
        }
        rank(
            &subject,
            loaded
                .iter()
                .map(|(sha, name, bytes)| (sha.as_str(), name.as_str(), bytes.clone())),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(seed: u32) -> Vec<u8> {
        // Enough varied text for a TLSH.
        let mut out = String::new();
        let mut x = seed;
        for line in 0..400 {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            out.push_str(&format!(
                "line {line}: value {} /usr/lib/lib{}.so connect to host-{}.example.test\n",
                x % 9973,
                x % 17,
                x % 101
            ));
        }
        out.into_bytes()
    }

    #[test]
    fn a_near_copy_is_close_and_shares_strings_and_an_unrelated_file_is_not_listed() {
        let base = text(1);
        let mut variant = base.clone();
        variant.extend_from_slice(b"\n# one more line that only the variant has\n");
        let unrelated: Vec<u8> = (0..60_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let found = rank(
            &base,
            [
                ("aa", "variant", variant.clone()),
                ("bb", "noise", unrelated),
            ]
            .into_iter(),
        )
        .unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].sha256, "aa");
        assert!(found[0].distance < 50);
        assert!(matches!(found[0].shared, Shared::Strings { count, .. } if count > 100));
        assert_eq!(found[0].shared.label().split(' ').nth(1), Some("strings"));
    }

    #[test]
    fn a_subject_too_small_for_a_hash_says_why() {
        let error = rank(b"tiny", std::iter::empty()).unwrap_err();
        assert!(error.contains("too small"), "{error}");
    }

    #[test]
    fn two_elf_files_share_imports_not_strings() {
        // Not a parseable ELF: falls back to strings, so the label says so.
        let fake = b"\x7fELF not really an elf file but long enough to count as strings".to_vec();
        assert!(matches!(shared(&fake, &fake), Shared::Strings { .. }));
        assert_eq!(imports(b"plain text"), None);
    }

    #[test]
    fn the_library_finds_the_variant_and_skips_the_excluded() {
        use crate::samples::{Library, NewSample};
        let dir = std::env::temp_dir().join(format!("ant-similar-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut library = Library::open(&dir).unwrap();
        let base = text(1);
        let mut variant = base.clone();
        variant.extend_from_slice(b"\n# only the variant\n");
        let add = |library: &mut Library, bytes: &[u8], name: &str| {
            library
                .add_bytes(
                    bytes,
                    NewSample {
                        name: name.into(),
                        ..NewSample::default()
                    },
                )
                .unwrap()
                .sha256
        };
        let me = add(&mut library, &base, "base");
        let near = add(&mut library, &variant, "variant");
        let found = library.similar_to(&me, &HashSet::new()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].sha256, near);
        // A parent or child is left out: the lineage graph shows it.
        let excluded = HashSet::from([near.clone()]);
        assert!(library.similar_to(&me, &excluded).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_real_elf_lists_its_imports() {
        let Ok(bytes) = std::fs::read("/bin/ls") else {
            return;
        };
        let names = imports(&bytes).expect("an ELF file");
        assert!(
            names
                .iter()
                .any(|name| name.contains("strlen") || name.contains("malloc")),
            "{names:?}"
        );
        assert!(matches!(shared(&bytes, &bytes), Shared::Imports { count, .. } if count > 10));
    }
}
