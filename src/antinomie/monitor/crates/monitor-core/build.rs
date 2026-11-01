// SPDX-License-Identifier: GPL-3.0-only
use std::{env, fs, path::Path};

/// Repository files the app writes out as its base build kit, in
/// their repository layout.
const KIT_FILES: &[&str] = &[
    "LICENSE",
    "LICENSING.md",
    "THIRD-PARTY-NOTICES.md",
    "LICENSES/Antinomie-MIT.txt",
    "LICENSES/GPL-2.0-only.txt",
    "scripts/build-base.py",
    "scripts/toolchain_chroot.py",
    "scripts/build-monitor-kernel.sh",
    "scripts/build-monitor-image.py",
    "scripts/build-debian-image.py",
    "scripts/debian-uefi-delta.py",
    "scripts/make-kernel-symbols.py",
    "scripts/check-kernel-btf.py",
    "scripts/check-kernel-abi.py",
    "src/antinomie/packaging/debian-6.12.94-1-trixie/adapter.conf",
    "src/antinomie/packaging/debian-6.12.94-1-trixie/module-signing.pem",
    "src/antinomie/packaging/debian-6.12.94-1-trixie/module-signing-arm64.pem",
    "src/antinomie/packaging/kconfig/x86_64/minimal.cfg",
    "src/antinomie/packaging/kconfig/arm64/minimal.cfg",
    "src/antinomie/packaging/container/Dockerfile",
    "src/antinomie/monitor/protocol/revisions.json",
    "src/debian/linux_6.12.94-1.dsc",
    "src/debian/linux_6.12.94-1.debian.tar.xz",
];
const KIT_SERIES: &str = "src/antinomie/core/6.12";

/// The first 8 hex digits of a commit id, if `text` starts with one.
fn short_commit(text: &str) -> Option<String> {
    let text = text.trim();
    let hex: String = text.chars().take_while(char::is_ascii_hexdigit).collect();
    (hex.len() >= 7 && hex.len() == text.len().min(hex.len()))
        .then(|| hex[..8.min(hex.len())].to_owned())
}

/// The commit this build is made from. In order: `ANTINOMIE_BUILD_COMMIT`;
/// `git rev-parse HEAD` in a git checkout (with `-dirty` after tracked
/// changes); `source_commit` of a `BUILD-INFO.json` at the repository root (a
/// source archive without .git); else `unknown`. Nothing is fetched, and the
/// same source without .git always gives the same text.
fn build_commit(repo: &Path) -> String {
    println!("cargo:rerun-if-env-changed=ANTINOMIE_BUILD_COMMIT");
    if let Some(commit) = env::var("ANTINOMIE_BUILD_COMMIT")
        .ok()
        .as_deref()
        .and_then(short_commit)
    {
        return commit;
    }
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
    };
    if repo.join(".git").exists()
        && let Some(commit) = git(&["rev-parse", "HEAD"])
            .as_deref()
            .and_then(short_commit)
    {
        {
            if let Some(dir) = git(&["rev-parse", "--absolute-git-dir"]) {
                // Only files that exist: cargo reruns every build for a missing one.
                let mut watch = vec![format!("{dir}/HEAD"), format!("{dir}/packed-refs")];
                if let Some(reference) = git(&["symbolic-ref", "-q", "HEAD"]) {
                    watch.push(format!("{dir}/{reference}"));
                }
                for path in watch.into_iter().filter(|path| Path::new(path).exists()) {
                    println!("cargo:rerun-if-changed={path}");
                }
            }
            let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
                .is_some_and(|out| !out.is_empty());
            return if dirty {
                format!("{commit}-dirty")
            } else {
                commit
            };
        }
    }
    let info = repo.join("BUILD-INFO.json");
    println!("cargo:rerun-if-changed={}", info.display());
    fs::read_to_string(info)
        .ok()
        .and_then(|text| {
            let rest = text.split("\"source_commit\"").nth(1)?;
            let value = rest.split('"').nth(1)?;
            short_commit(value)
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

fn main() {
    {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../..");
        let repo = repo.canonicalize().unwrap_or(repo);
        println!(
            "cargo:rustc-env=ANTINOMIE_BUILD_COMMIT_STAMP={}",
            build_commit(&repo)
        );
    }
    let transport = "../../../transport";
    cc::Build::new()
        .file(format!("{transport}/host.c"))
        .file("src/ffi_layout.c")
        .include(transport)
        .flag("-std=gnu11")
        .compile("ant_host");
    println!("cargo:rerun-if-changed={transport}");
    println!("cargo:rerun-if-changed=src/ffi_layout.c");
    build_guest_resources();
    build_kit();
}

fn build_kit() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../..")
        .canonicalize()
        .expect("repository root");
    let mut files: Vec<String> = KIT_FILES.iter().map(|path| path.to_string()).collect();
    let series = repo.join(KIT_SERIES);
    println!("cargo:rerun-if-changed={}", series.display());
    let mut patches: Vec<String> = fs::read_dir(&series)
        .expect("core patch series")
        .map(|entry| {
            entry
                .expect("series entry")
                .file_name()
                .into_string()
                .expect("UTF-8 name")
        })
        .filter(|name| name.ends_with(".patch"))
        .collect();
    patches.sort();
    assert!(!patches.is_empty(), "no core patches in {KIT_SERIES}");
    files.extend(
        patches
            .into_iter()
            .map(|name| format!("{KIT_SERIES}/{name}")),
    );
    let mut source = String::from("pub(crate) static KIT_FILES: &[(&str, &[u8])] = &[\n");
    for file in &files {
        let path = repo.join(file);
        assert!(path.is_file(), "kit file {} missing", path.display());
        println!("cargo:rerun-if-changed={}", path.display());
        source.push_str(&format!(
            "    ({file:?}, include_bytes!({:?})),\n",
            path.display().to_string()
        ));
    }
    source.push_str("];\n");
    let out = Path::new(&env::var("OUT_DIR").expect("OUT_DIR")).join("kit_files.rs");
    fs::write(out, source).expect("write kit file list");
}

/// A static x86-64 guest probe also works in the libc-free BusyBox base.
fn build_guest_resources() {
    println!("cargo:rerun-if-changed=src/guest_resources.c");
    println!("cargo:rerun-if-env-changed=ANTINOMIE_GUEST_CC");
    let compiler = env::var_os("ANTINOMIE_GUEST_CC").unwrap_or_else(|| "musl-gcc".into());
    let output = Path::new(&env::var_os("OUT_DIR").expect("OUT_DIR")).join("guest-resources");
    let status = std::process::Command::new(compiler)
        .args([
            "-static",
            "-Os",
            "-s",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fno-ident",
            "-o",
        ])
        .arg(output)
        .arg("src/guest_resources.c")
        .status()
        .expect("guest resource collector compiler; install musl-tools");
    assert!(
        status.success(),
        "guest resource collector compilation failed"
    );
}
