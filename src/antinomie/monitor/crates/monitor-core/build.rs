use std::{env, fs, path::Path};

/// Repository files the app writes out as its base build kit (ANT-T0028), in
/// their repository layout.
const KIT_FILES: &[&str] = &[
    "LICENSE",
    "scripts/build-base.py",
    "scripts/build-monitor-kernel.sh",
    "scripts/build-monitor-image.py",
    "scripts/build-debian-image.py",
    "src/antinomie/packaging/debian-6.12.94-1-trixie/adapter.conf",
    "src/antinomie/monitor/protocol/revisions.json",
    "src/debian/linux_6.12.94-1.dsc",
    "src/debian/linux_6.12.94-1.debian.tar.xz",
];
const KIT_SERIES: &str = "src/antinomie/core/6.12";

fn main() {
    let transport = "../../../transport";
    cc::Build::new()
        .file(format!("{transport}/host.c"))
        .file("src/ffi_layout.c")
        .include(transport)
        .flag("-std=gnu11")
        .compile("ant_host");
    println!("cargo:rerun-if-changed={transport}");
    println!("cargo:rerun-if-changed=src/ffi_layout.c");
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
