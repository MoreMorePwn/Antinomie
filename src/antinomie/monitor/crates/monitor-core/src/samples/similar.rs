// SPDX-License-Identifier: GPL-3.0-only
//! Library samples that look like another by TLSH distance, and what they
//! share. The distance is computed on the TLSH each sample stored when it
//! was added (`tlsh2` parses the `T1` text back), against every sample of
//! the library, with no file read; only the few listed are read from their
//! archives, for what they share.
use super::Library;
use std::collections::{BTreeSet, HashSet};

/// Closer than this is "similar": TLSH reads 0 as identical and anything up
/// to about 100 as a close variant. The sample window lists nothing looser.
pub const MAX_DISTANCE: i32 = 100;
/// Rows the Summary lists.
pub const MAX_ROWS: usize = 5;
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
    /// One of the two archives could not be read (removed, moved or
    /// damaged): the distance stands, what they share is not known.
    Unread,
}

impl Shared {
    pub fn count(&self) -> usize {
        match self {
            Shared::Imports { count, .. } | Shared::Strings { count, .. } => *count,
            Shared::Unread => 0,
        }
    }

    pub fn label(&self) -> String {
        let (count, word) = match self {
            Shared::Imports { count, .. } => (*count, "import"),
            Shared::Strings { count, .. } => (*count, "string"),
            Shared::Unread => return "archive not readable".into(),
        };
        format!("{count} {word}{}", if count == 1 { "" } else { "s" })
    }

    pub fn examples(&self) -> &[String] {
        match self {
            Shared::Imports { examples, .. } | Shared::Strings { examples, .. } => examples,
            Shared::Unread => &[],
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

/// A TLSH as the library stores it (`T1` and 70 hex digits, see
/// `intake::tlsh_of`), or `None` when it is empty or not one.
fn parse(hash: &str) -> Option<tlsh2::TlshDefault> {
    hash.parse().ok()
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

/// The closest of `candidates` (sha256, name, stored TLSH) to the stored
/// TLSH `subject`, nearest first (then by name): at most [`MAX_ROWS`] within
/// [`MAX_DISTANCE`], as (sha256, name, distance). A candidate without a
/// readable hash is left out.
pub fn closest(
    subject: &str,
    candidates: impl IntoIterator<Item = (String, String, String)>,
) -> Result<Vec<(String, String, i32)>, String> {
    if subject.is_empty() {
        return Err("too small or too uniform for a similarity hash".into());
    }
    let Some(mine) = parse(subject) else {
        return Err("its similarity hash is not readable".into());
    };
    let mut found: Vec<(String, String, i32)> = candidates
        .into_iter()
        .filter_map(|(sha256, name, hash)| {
            let distance = mine.diff(&parse(&hash)?, true);
            (distance <= MAX_DISTANCE).then_some((sha256, name, distance))
        })
        .collect();
    found.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.1.cmp(&b.1)));
    found.truncate(MAX_ROWS);
    Ok(found)
}

impl Library {
    /// The samples most like `sha256`, leaving out `exclude` (itself, its
    /// parents and its children, which the lineage graph shows) and removed
    /// samples. Every sample's stored TLSH is compared; only the samples
    /// listed (and `sha256`) are read, for what they share.
    pub fn similar_to(
        &self,
        sha256: &str,
        exclude: &HashSet<String>,
    ) -> Result<Vec<Similar>, String> {
        let sha256 = sha256.to_ascii_lowercase();
        let subject = self
            .get(&sha256)?
            .ok_or_else(|| format!("{sha256} is not in the library"))?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT sha256, name, tlsh FROM sample WHERE tlsh != '' AND removed_ms IS NULL",
            )
            .map_err(|e| e.to_string())?;
        let candidates: Vec<(String, String, String)> = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|e| e.to_string())?
            .filter_map(Result::ok)
            .filter(|(candidate, _, _)| *candidate != sha256 && !exclude.contains(candidate))
            .collect();
        let found = closest(&subject.tlsh, candidates)?;
        if found.is_empty() {
            return Ok(Vec::new());
        }
        let read = |sha: &str| {
            self.archive_path(sha)
                .and_then(|path| super::open_sample(&path, sha))
                .ok()
        };
        let mine = read(&sha256);
        Ok(found
            .into_iter()
            .map(|(sha256, name, distance)| {
                let shared = match (&mine, read(&sha256)) {
                    (Some(mine), Some(theirs)) => shared(mine, &theirs),
                    _ => Shared::Unread,
                };
                Similar {
                    sha256,
                    name,
                    distance,
                    shared,
                }
            })
            .collect())
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

    fn row(sha256: &str, name: &str, bytes: &[u8]) -> (String, String, String) {
        (
            sha256.into(),
            name.into(),
            super::super::intake::tlsh_of(bytes),
        )
    }

    #[test]
    fn a_near_copy_is_close_and_shares_strings_and_an_unrelated_file_is_not_listed() {
        let base = text(1);
        let mut variant = base.clone();
        variant.extend_from_slice(b"\n# one more line that only the variant has\n");
        let unrelated: Vec<u8> = (0..60_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let found = closest(
            &super::super::intake::tlsh_of(&base),
            [
                row("aa", "variant", &variant),
                row("bb", "noise", &unrelated),
                ("cc".into(), "no hash".into(), String::new()),
                ("dd".into(), "damaged".into(), "T1zz".into()),
            ],
        )
        .unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].0, "aa");
        assert!(found[0].2 < 50);
        let shared = shared(&base, &variant);
        assert!(matches!(shared, Shared::Strings { count, .. } if count > 100));
        assert_eq!(shared.label().split(' ').nth(1), Some("strings"));
        assert_eq!(Shared::Unread.label(), "archive not readable");
    }

    #[test]
    fn a_subject_too_small_for_a_hash_says_why() {
        let error = closest("", Vec::new()).unwrap_err();
        assert!(error.contains("too small"), "{error}");
        let error = closest("T1nothex", Vec::new()).unwrap_err();
        assert!(error.contains("not readable"), "{error}");
    }

    #[test]
    fn a_stored_hash_gives_the_distance_tlsh2_gives_on_the_files() {
        // The stored text parses back to the same hash, and the distance on
        // two parsed hashes is tlsh2's own `diff` on the two files.
        let files: Vec<Vec<u8>> = (1..=12u32)
            .map(|seed| {
                let mut bytes = text(seed % 4 + 1);
                // Near copies and far files alike.
                bytes.extend(text(seed).iter().take(seed as usize * 700));
                bytes
            })
            .collect();
        for a in &files {
            let stored = super::super::intake::tlsh_of(a);
            let parsed = parse(&stored).expect("a stored TLSH parses");
            assert_eq!(String::from_utf8_lossy(&parsed.hash()), stored);
            for b in &files {
                let built = tlsh2::TlshDefaultBuilder::build_from(a)
                    .unwrap()
                    .diff(&tlsh2::TlshDefaultBuilder::build_from(b).unwrap(), true);
                let theirs = parse(&super::super::intake::tlsh_of(b)).unwrap();
                assert_eq!(parsed.diff(&theirs, true), built);
            }
        }
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

    #[test]
    fn every_library_sample_is_compared_by_its_stored_hash() {
        // The variant is the oldest sample, behind thousands of newer ones:
        // well past the 300 the old comparison read, in list order.
        use crate::samples::{Library, NewSample};
        let dir =
            std::env::temp_dir().join(format!("ant-similar-many-{}", crate::storage::unique_id()));
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
        let near = add(&mut library, &variant, "variant");
        let me = add(&mut library, &base, "base");
        const ROWS: u64 = 4_000;
        let newer = super::super::library::now_ms() + 1_000;
        {
            let tx = library.connection.unchecked_transaction().unwrap();
            let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
            for n in 0..ROWS {
                // A well-formed hash of random buckets: far from anything.
                let mut hash = String::from("T1");
                for _ in 0..35 {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    hash.push_str(&format!("{:02X}", x & 0xff));
                }
                tx.execute(
                    "INSERT INTO sample(sha256, tlsh, name, size, added_ms) VALUES (?1, ?2, ?3, 1, ?4)",
                    rusqlite::params![format!("{n:064x}"), hash, format!("synthetic {n}"), (newer + n) as i64],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        let position = library
            .list()
            .unwrap()
            .iter()
            .position(|record| record.sha256 == near)
            .unwrap();
        assert!(position > 300, "{position}");
        let started = std::time::Instant::now();
        let found = library.similar_to(&me, &HashSet::new()).unwrap();
        let took = started.elapsed();
        eprintln!("similar_to over {} samples: {took:?}", ROWS + 2);
        assert_eq!(
            found.first().map(|row| row.sha256.as_str()),
            Some(near.as_str())
        );
        assert!(matches!(found[0].shared, Shared::Strings { count, .. } if count > 100));
        // No archive read per candidate: thousands compare well within a
        // second even on a loaded machine.
        assert!(took < std::time::Duration::from_secs(3), "{took:?}");
        // A listed sample whose archive is gone keeps its distance.
        std::fs::remove_file(library.archive_path(&near).unwrap()).unwrap();
        let found = library.similar_to(&me, &HashSet::new()).unwrap();
        assert_eq!(found[0].sha256, near);
        assert_eq!(found[0].shared, Shared::Unread);
        let _ = std::fs::remove_dir_all(dir);
    }
}
