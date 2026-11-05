// SPDX-License-Identifier: GPL-3.0-only
//! The git files whose change means the commit checked out in a repository
//! moved, for the build script's `cargo:rerun-if-changed` lines. Shared with
//! the library's tests (`build_git_head`), which run it on fake `.git` layouts.
use std::{
    fs,
    path::{Path, PathBuf},
};

/// The files of `repo`'s git checkout that change when its HEAD moves, the
/// existing ones only (cargo reruns a build script on every build while a
/// watched file is missing):
///
/// * the gitdir's `HEAD` and `logs/HEAD` (the reflog, appended on every move,
///   also when the branch's ref is only in packed-refs);
/// * the loose ref HEAD names (`ref: refs/heads/x`), in the gitdir for a
///   per-worktree ref, else in the common dir;
/// * the common dir's `packed-refs`.
///
/// The gitdir is `repo/.git` in a normal clone. In a worktree `.git` is a
/// file (`gitdir: <path>`, relative to `repo` or absolute) and the gitdir's
/// `commondir` file names the main repository's `.git`, relative to the
/// gitdir: branches and packed-refs live there. A detached HEAD has no ref.
pub(crate) fn head_files(repo: &Path) -> Vec<PathBuf> {
    let dotgit = repo.join(".git");
    let gitdir = if dotgit.is_dir() {
        dotgit
    } else {
        let Some(path) = fs::read_to_string(&dotgit).ok().and_then(|text| {
            text.lines()
                .next()
                .and_then(|line| line.strip_prefix("gitdir:"))
                .map(|path| path.trim().to_owned())
        }) else {
            return Vec::new();
        };
        repo.join(path)
    };
    let gitdir = fs::canonicalize(&gitdir).unwrap_or(gitdir);
    let common = fs::read_to_string(gitdir.join("commondir"))
        .ok()
        .map(|text| gitdir.join(text.trim()))
        .map(|dir| fs::canonicalize(&dir).unwrap_or(dir))
        .unwrap_or_else(|| gitdir.clone());
    let mut files = vec![gitdir.join("HEAD"), gitdir.join("logs/HEAD")];
    if let Some(name) = fs::read_to_string(gitdir.join("HEAD"))
        .ok()
        .and_then(|head| {
            head.trim()
                .strip_prefix("ref:")
                .map(|r| r.trim().to_owned())
        })
        .filter(|name| name.starts_with("refs/") && !name.split('/').any(|part| part == ".."))
    {
        let own = gitdir.join(&name);
        files.push(if own.is_file() {
            own
        } else {
            common.join(&name)
        });
    }
    files.push(common.join("packed-refs"));
    files.retain(|path| path.is_file());
    files.dedup();
    files
}

#[cfg(test)]
mod tests {
    use super::head_files;
    use std::{fs, path::Path};

    fn write(path: &Path, text: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567\n";

    /// A new folder, removed with the guard.
    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn scratch() -> Scratch {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "antinomie-git-head-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Scratch(path)
    }

    #[test]
    fn normal_clone_watches_head_reflog_branch_and_packed_refs() {
        let dir = scratch();
        let root = fs::canonicalize(dir.path()).unwrap();
        let git = root.join(".git");
        write(&git.join("HEAD"), "ref: refs/heads/main\n");
        write(&git.join("logs/HEAD"), "");
        write(&git.join("refs/heads/main"), COMMIT);
        write(&git.join("packed-refs"), "");
        assert_eq!(
            head_files(&root),
            [
                git.join("HEAD"),
                git.join("logs/HEAD"),
                git.join("refs/heads/main"),
                git.join("packed-refs")
            ]
        );
    }

    #[test]
    fn worktree_reads_its_gitdir_and_the_branch_in_the_common_dir() {
        let dir = scratch();
        let root = fs::canonicalize(dir.path()).unwrap();
        let common = root.join("main/.git");
        let gitdir = common.join("worktrees/wt");
        let tree = root.join("wt");
        write(
            &tree.join(".git"),
            &format!("gitdir: {}\n", gitdir.display()),
        );
        write(&gitdir.join("HEAD"), "ref: refs/heads/wip/x\n");
        write(&gitdir.join("commondir"), "../..\n");
        write(&gitdir.join("logs/HEAD"), "");
        write(&common.join("refs/heads/wip/x"), COMMIT);
        write(&common.join("packed-refs"), "");
        // The main checkout's own HEAD is not this worktree's.
        write(&common.join("HEAD"), "ref: refs/heads/main\n");
        assert_eq!(
            head_files(&tree),
            [
                gitdir.join("HEAD"),
                gitdir.join("logs/HEAD"),
                common.join("refs/heads/wip/x"),
                common.join("packed-refs")
            ]
        );
    }

    #[test]
    fn relative_gitdir_packed_branch_and_detached_head() {
        let dir = scratch();
        let root = fs::canonicalize(dir.path()).unwrap();
        let common = root.join("main/.git");
        let gitdir = common.join("worktrees/wt");
        let tree = root.join("wt");
        write(&tree.join(".git"), "gitdir: ../main/.git/worktrees/wt\n");
        write(&gitdir.join("commondir"), "../..\n");
        // The branch is only in packed-refs: its loose file would be missing.
        write(&gitdir.join("HEAD"), "ref: refs/heads/packed\n");
        write(
            &common.join("packed-refs"),
            &format!("{} refs/heads/packed\n", COMMIT.trim()),
        );
        assert_eq!(
            head_files(&tree),
            [gitdir.join("HEAD"), common.join("packed-refs")]
        );
        write(&gitdir.join("HEAD"), COMMIT);
        assert_eq!(
            head_files(&tree),
            [gitdir.join("HEAD"), common.join("packed-refs")]
        );
    }

    #[test]
    fn a_per_worktree_ref_stays_in_the_gitdir_and_no_git_watches_nothing() {
        let dir = scratch();
        let root = fs::canonicalize(dir.path()).unwrap();
        let common = root.join("main/.git");
        let gitdir = common.join("worktrees/wt");
        let tree = root.join("wt");
        write(
            &tree.join(".git"),
            &format!("gitdir: {}\n", gitdir.display()),
        );
        write(&gitdir.join("commondir"), "../..\n");
        write(&gitdir.join("HEAD"), "ref: refs/bisect/bad\n");
        write(&gitdir.join("refs/bisect/bad"), COMMIT);
        assert_eq!(
            head_files(&tree),
            [gitdir.join("HEAD"), gitdir.join("refs/bisect/bad")]
        );
        let plain = root.join("plain");
        fs::create_dir_all(&plain).unwrap();
        assert!(head_files(&plain).is_empty());
        write(&plain.join(".git"), "not a gitdir line\n");
        assert!(head_files(&plain).is_empty());
    }
}
