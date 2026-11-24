// SPDX-License-Identifier: GPL-3.0-only
//! Compiled YARA rules kept with their rule profile (ANT-T0618, audit AN-06).
//!
//! YARA-X takes 13 to 27 s to compile a 1,700-file profile and about 4.5 s to
//! load the serialised form, and the static Rules check and the detection
//! engine each compiled it afresh. The host compiles a profile once, in the
//! background, and writes `compiled/<key>.bin` into the profile folder; both
//! read it from there (the static check mounts the folder read-only, detection
//! copies it with the profile).
//!
//! The key covers everything the compile depends on: the YARA-X version, the
//! relaxed regular-expression syntax, every file of the profile besides its
//! own bookkeeping (the include folder) and the text of each compiled source in
//! order. A file is a magic, the SHA-256 of what follows, the list of sources
//! that did not compile (by position) and the serialised rules. One that is
//! missing, partial, damaged or from another YARA-X is not trusted: the rules
//! are compiled from source as before. The cache only ever holds what the host
//! compiled from the same bytes, so a hit finds what a compile would.
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{Duration, SystemTime},
};

const MAGIC: &[u8; 8] = b"ANTYRC01";
const FOLDER: &str = "compiled";
/// A build that left its lock this long ago is not running.
const LOCK_LIFE: Duration = Duration::from_secs(15 * 60);
/// Files of a profile folder that say nothing about the rules.
const BOOKKEEPING: [&str; 4] = ["manifest.json", "counts.txt", "warnings.txt", ".complete"];

/// What the rules were compiled from: `(position, error)` for each source that
/// did not compile, so a hit names the files by the caller's own names.
type Skipped = Vec<(usize, String)>;

/// The key of compiling `sources` in `directory`.
pub(super) fn key(directory: &Path, sources: &[(String, String)]) -> Option<String> {
    let mut hash = Sha256::new();
    hash.update(yara_x::VERSION.as_bytes());
    hash.update(b"\0relaxed\0");
    let mut files = Vec::new();
    collect(directory, directory, &mut files).ok()?;
    files.sort();
    for (name, digest) in files {
        hash.update(name.as_bytes());
        hash.update(digest);
    }
    hash.update(b"\0sources\0");
    for (_, text) in sources {
        hash.update(Sha256::digest(text.as_bytes()));
    }
    Some(format!("{:x}", hash.finalize())[..32].to_owned())
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, [u8; 32])>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let kind = entry.file_type()?;
        let relative = path.strip_prefix(root).unwrap_or(&path);
        if kind.is_dir() {
            if relative != Path::new(FOLDER) {
                collect(root, &path, out)?;
            }
        } else if kind.is_file() {
            let name = entry.file_name();
            if dir == root && BOOKKEEPING.iter().any(|b| name == *b) {
                continue;
            }
            out.push((
                relative.to_string_lossy().into_owned(),
                Sha256::digest(fs::read(&path)?).into(),
            ));
        }
    }
    Ok(())
}

fn file(directory: &Path, key: &str) -> PathBuf {
    directory.join(FOLDER).join(format!("{key}.bin"))
}

/// The rules compiled earlier for `sources` in `directory`, with the names of
/// the sources that did not compile; `None` for anything but a whole, intact
/// file of this key and this YARA-X.
pub(super) fn load(
    directory: &Path,
    sources: &[(String, String)],
) -> Option<(yara_x::Rules, Vec<String>)> {
    let key = key(directory, sources)?;
    let bytes = fs::read(file(directory, &key)).ok()?;
    let (magic, rest) = bytes.split_at_checked(MAGIC.len())?;
    let (digest, body) = rest.split_at_checked(32)?;
    if magic != MAGIC || Sha256::digest(body).as_slice() != digest {
        return None;
    }
    let (len, rest) = body.split_at_checked(8)?;
    let len = usize::try_from(u64::from_le_bytes(len.try_into().ok()?)).ok()?;
    let (header, payload) = rest.split_at_checked(len)?;
    let skipped: Skipped = serde_json::from_slice(header).ok()?;
    let names = skipped
        .into_iter()
        .map(|(index, error)| Some(format!("{}: {error}", sources.get(index)?.0)))
        .collect::<Option<Vec<_>>>()?;
    let rules = yara_x::Rules::deserialize(payload).ok()?;
    Some((rules, names))
}

/// Compile `sources` as the Rules check and detection do, remembering which
/// did not compile by position.
fn compile(
    sources: &[(String, String)],
    include: &Path,
) -> Result<(yara_x::Rules, Skipped), String> {
    let (rules, texts) = super::rules::compile_sources(sources, Some(include))?;
    let skipped = sources
        .iter()
        .enumerate()
        .filter_map(|(index, (name, _))| {
            let prefix = format!("{name}: ");
            texts
                .iter()
                .find_map(|text| text.strip_prefix(&prefix))
                .map(|error| (index, error.to_owned()))
        })
        .collect();
    Ok((rules, skipped))
}

/// Compile and store the rules of `directory` unless a file for them exists.
/// Returns whether a file is there afterwards.
pub(super) fn build(directory: &Path, sources: &[(String, String)]) -> bool {
    let Some(key) = key(directory, sources) else {
        return false;
    };
    let target = file(directory, &key);
    if target.is_file() {
        if load(directory, sources).is_some() {
            return true;
        }
        let _ = fs::remove_file(&target); // not trusted: made again
    }
    let folder = directory.join(FOLDER);
    if crate::storage::private_dir(&folder).is_err() {
        return false;
    }
    let lock = folder.join(format!("{key}.lock"));
    let stale = fs::metadata(&lock)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|time| SystemTime::now().duration_since(time).ok())
        .is_some_and(|age| age > LOCK_LIFE);
    if stale {
        let _ = fs::remove_file(&lock);
    }
    if fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock)
        .is_err()
    {
        return false; // another process is building it
    }
    let built = (|| -> Option<()> {
        let (rules, skipped) = compile(sources, directory).ok()?;
        let payload = rules.serialize().ok()?;
        let header = serde_json::to_vec(&skipped).ok()?;
        let mut body = Vec::with_capacity(8 + header.len() + payload.len());
        body.extend((header.len() as u64).to_le_bytes());
        body.extend(&header);
        body.extend(&payload);
        let temporary = folder.join(format!("{key}.{}.tmp", crate::storage::unique_id()));
        let mut out = fs::File::create(&temporary).ok()?;
        let written = out
            .write_all(MAGIC)
            .and_then(|()| out.write_all(&Sha256::digest(&body)))
            .and_then(|()| out.write_all(&body))
            .and_then(|()| out.sync_all());
        drop(out);
        if written.is_err() || fs::rename(&temporary, &target).is_err() {
            let _ = fs::remove_file(&temporary);
            return None;
        }
        Some(())
    })();
    let _ = fs::remove_file(&lock);
    built.is_some()
}

/// Build the compiled rules of the profile `directory` in the background, once
/// at a time per folder. `keep` is held until the build ends, so pruning
/// leaves the profile alone.
pub(crate) fn warm(directory: PathBuf, keep: crate::ruleset::ProfileUse) {
    static BUILDING: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    let building = BUILDING.get_or_init(Default::default);
    if !building
        .lock()
        .is_ok_and(|mut active| active.insert(directory.clone()))
    {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("compile-rules".into())
        .spawn({
            let directory = directory.clone();
            move || {
                let sources = super::rules::selected_sources(&directory);
                if !sources.is_empty() {
                    build(&directory, &sources);
                }
                drop(keep);
                if let Some(building) = BUILDING.get()
                    && let Ok(mut active) = building.lock()
                {
                    active.remove(&directory);
                }
            }
        });
    if spawned.is_err()
        && let Some(building) = BUILDING.get()
        && let Ok(mut active) = building.lock()
    {
        active.remove(&directory);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str) -> (PathBuf, Vec<(String, String)>) {
        let dir = std::env::temp_dir().join(format!(
            "ant-compiled-{name}-{}",
            crate::storage::unique_id()
        ));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("manifest.json"), "{}").unwrap();
        let a = "rule A { strings: $a = \"alpha\" condition: $a }\n";
        let b = "rule B { condition: undefined_identifier }\n";
        let c = "rule C { strings: $c = \"gamma\" condition: $c }\n";
        let mut sources = Vec::new();
        for (name, text) in [("a.yar", a), ("b.yar", b), ("c.yar", c)] {
            fs::write(dir.join(name), text).unwrap();
            sources.push((dir.join(name).display().to_string(), text.to_owned()));
        }
        (dir, sources)
    }

    fn matches(rules: &yara_x::Rules, data: &[u8]) -> Vec<String> {
        let mut scanner = yara_x::Scanner::new(rules);
        let results = scanner.scan(data).unwrap();
        results
            .matching_rules()
            .map(|r| r.identifier().to_owned())
            .collect()
    }

    #[test]
    fn a_stored_compile_loads_with_the_same_matches_and_the_same_skipped_files() {
        let (dir, sources) = profile("hit");
        assert!(load(&dir, &sources).is_none(), "nothing yet");
        assert!(build(&dir, &sources));
        let (rules, skipped) = load(&dir, &sources).expect("a hit");
        let (fresh, fresh_skipped) =
            super::super::rules::compile_sources(&sources, Some(&dir)).unwrap();
        assert_eq!(skipped, fresh_skipped);
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].starts_with(&sources[1].0));
        let data = b"..alpha..gamma..";
        assert_eq!(matches(&rules, data), matches(&fresh, data));
        assert_eq!(matches(&rules, data), vec!["A", "C"]);
        // The names come from the caller: the same text under other names hits too.
        let renamed: Vec<_> = sources
            .iter()
            .map(|(name, text)| (name.replace("a.yar", "z.yar"), text.clone()))
            .collect();
        assert!(load(&dir, &renamed).is_some());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_changed_source_or_profile_file_is_a_different_key() {
        let (dir, mut sources) = profile("key");
        let before = key(&dir, &sources).unwrap();
        assert_eq!(before, key(&dir, &sources).unwrap());
        sources[0].1.push(' ');
        assert_ne!(before, key(&dir, &sources).unwrap());
        sources[0].1.pop();
        fs::write(dir.join("included.yar"), "rule I { condition: true }").unwrap();
        assert_ne!(before, key(&dir, &sources).unwrap());
        // The bookkeeping and the cache folder are not part of it.
        let with_file = key(&dir, &sources).unwrap();
        fs::write(dir.join("manifest.json"), "{\"x\":1}").unwrap();
        fs::create_dir_all(dir.join(FOLDER)).unwrap();
        fs::write(dir.join(FOLDER).join("x.bin"), "x").unwrap();
        assert_eq!(with_file, key(&dir, &sources).unwrap());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_partial_damaged_or_foreign_file_is_never_trusted() {
        let (dir, sources) = profile("bad");
        assert!(build(&dir, &sources));
        let path = file(&dir, &key(&dir, &sources).unwrap());
        let good = fs::read(&path).unwrap();
        for bad in [
            good[..good.len() / 2].to_vec(),
            good[..10].to_vec(),
            Vec::new(),
            {
                let mut flipped = good.clone();
                let last = flipped.len() - 5;
                flipped[last] ^= 0x40;
                flipped
            },
            {
                let mut foreign = good.clone();
                foreign[0] = b'X';
                foreign
            },
        ] {
            fs::write(&path, &bad).unwrap();
            assert!(load(&dir, &sources).is_none());
        }
        // The next build replaces a file that is not trusted.
        assert!(build(&dir, &sources));
        assert!(load(&dir, &sources).is_some());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_build_in_progress_is_left_alone_and_a_dead_lock_is_cleared() {
        let (dir, sources) = profile("lock");
        let key = key(&dir, &sources).unwrap();
        fs::create_dir_all(dir.join(FOLDER)).unwrap();
        let lock = dir.join(FOLDER).join(format!("{key}.lock"));
        fs::write(&lock, b"").unwrap();
        assert!(!build(&dir, &sources), "another process is on it");
        fs::OpenOptions::new()
            .write(true)
            .open(&lock)
            .unwrap()
            .set_modified(SystemTime::now() - LOCK_LIFE - Duration::from_secs(60))
            .unwrap();
        assert!(build(&dir, &sources));
        assert!(!lock.exists());
        let _ = fs::remove_dir_all(dir);
    }

    /// By hand, on a copy of a real profile (ANT-T0618 measurement):
    /// `ANT_PROFILE_DIR=<copy of rules/profiles/yara/<digest>> cargo test --release -p
    /// antinomie-monitor-core compiled_rules::tests::time_a_real_profile -- --ignored --nocapture`.
    #[test]
    #[ignore = "needs ANT_PROFILE_DIR"]
    fn time_a_real_profile() {
        let Some(dir) = std::env::var_os("ANT_PROFILE_DIR") else {
            return;
        };
        let dir = PathBuf::from(dir);
        let t = std::time::Instant::now();
        let sources = super::super::rules::selected_sources(&dir);
        eprintln!(
            "TIMING read {} sources: {:.2} s",
            sources.len(),
            t.elapsed().as_secs_f64()
        );
        let t = std::time::Instant::now();
        let key = key(&dir, &sources).unwrap();
        eprintln!("TIMING key {key}: {:.2} s", t.elapsed().as_secs_f64());
        let t = std::time::Instant::now();
        let (_, skipped) = super::super::rules::compile_sources(&sources, Some(&dir)).unwrap();
        eprintln!(
            "TIMING compile ({} skipped): {:.2} s",
            skipped.len(),
            t.elapsed().as_secs_f64()
        );
        if let Some(first) = skipped.first() {
            eprintln!(
                "TIMING first skipped: {}",
                first.chars().take(400).collect::<String>()
            );
        }
        let t = std::time::Instant::now();
        assert!(build(&dir, &sources));
        eprintln!(
            "TIMING build (compile + serialise + write): {:.2} s",
            t.elapsed().as_secs_f64()
        );
        let bytes = fs::metadata(file(&dir, &key)).unwrap().len();
        let t = std::time::Instant::now();
        let (_, skipped2) = load(&dir, &sources).expect("a hit");
        eprintln!(
            "TIMING load ({bytes} bytes, {} skipped): {:.2} s",
            skipped2.len(),
            t.elapsed().as_secs_f64()
        );
        assert_eq!(skipped, skipped2);
    }
}
