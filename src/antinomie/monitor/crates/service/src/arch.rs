// SPDX-License-Identifier: GPL-3.0-only
//! One spelling of an architecture across `service.toml`, the presets, the
//! CLI and the API: `x86_64`, `x86`, `arm64`, `arm`, `mips`, `powerpc`,
//! `sparc`, `riscv`, `superh`, `m68k` and `other` (ANT-T0556). A lane group
//! named after an architecture uses the same word.
//!
//! The other spellings stay readable: `samples::detect_type`'s (`AArch64`,
//! `ARM`, `MIPS`, `RISC-V`, ...), Debian's (`amd64`, `aarch64`, `i386`), the
//! labels of the window (`x86-64`) and MalwareBazaar's (`X86_64`, `PPC`). A
//! preset file, a run's overrides and a job stored before this all read as
//! the one spelling.
use antinomie_monitor_core::GuestArch;

/// Every architecture word, in the order the messages list them.
pub const ARCHES: [&str; 11] = [
    "x86_64", "x86", "arm64", "arm", "mips", "powerpc", "sparc", "riscv", "superh", "m68k", "other",
];

/// The one spelling of `name`, in any spelling this module reads; `None` for
/// a word that names no architecture.
pub fn canonical(name: &str) -> Option<&'static str> {
    let lower = name.trim().to_ascii_lowercase();
    Some(match lower.as_str() {
        "x86_64" | "x86-64" | "amd64" | "x64" => "x86_64",
        "x86" | "i386" | "i486" | "i586" | "i686" | "80386" | "ia32" => "x86",
        "arm64" | "aarch64" => "arm64",
        "arm" | "armhf" | "armel" | "arm32" => "arm",
        "mips" | "mipsel" | "mips64" | "mips64el" => "mips",
        "powerpc" | "ppc" | "ppc64" | "ppc64el" | "ppc64le" => "powerpc",
        "sparc" | "sparc64" => "sparc",
        "risc-v" | "riscv" | "riscv64" | "riscv32" => "riscv",
        "superh" | "sh4" => "superh",
        "m68k" => "m68k",
        "other" => "other",
        _ => return None,
    })
}

/// `name` in the one spelling, or unchanged when it names no architecture
/// (so a check can still say which word it did not know).
pub fn normalize(name: &str) -> String {
    canonical(name).map_or_else(|| name.to_owned(), str::to_owned)
}

/// The word of a guest (a lane VM's base).
pub fn of_guest(arch: GuestArch) -> &'static str {
    match arch {
        GuestArch::X86_64 => "x86_64",
        GuestArch::AARCH64 => "arm64",
        GuestArch::ARM => "arm",
        GuestArch::MIPS | GuestArch::MIPSEL => "mips",
        GuestArch::RISCV64 => "riscv",
        _ => "other",
    }
}

/// Whether a guest of `guest` runs an ELF whose architecture is `sample`
/// (any spelling): x86-64 also runs i386 programs, arm64 32-bit ARM ones.
pub fn guest_runs(guest: GuestArch, sample: &str) -> bool {
    match canonical(sample) {
        Some("x86_64" | "x86") => guest == GuestArch::X86_64,
        Some("arm64") => guest == GuestArch::AARCH64,
        Some("arm") => guest == GuestArch::AARCH64 || guest == GuestArch::ARM,
        Some("riscv") => guest == GuestArch::RISCV64,
        Some("mips") => guest == GuestArch::MIPS || guest == GuestArch::MIPSEL,
        _ => false,
    }
}

/// serde: a list of architectures read in any spelling, kept in the one
/// spelling (a word that names none stays as written for the check).
pub fn deserialize_list<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    let words: Vec<String> = serde::Deserialize::deserialize(deserializer)?;
    let mut out: Vec<String> = Vec::with_capacity(words.len());
    for word in words {
        let word = if word == "any" {
            word
        } else {
            normalize(&word)
        };
        if !out.contains(&word) {
            out.push(word);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_old_spelling_reads_as_the_one_spelling() {
        for (old, new) in [
            ("AArch64", "arm64"),
            ("aarch64", "arm64"),
            ("arm64", "arm64"),
            ("x86_64", "x86_64"),
            ("x86-64", "x86_64"),
            ("X86_64", "x86_64"),
            ("amd64", "x86_64"),
            ("i386", "x86"),
            ("x86", "x86"),
            ("ARM", "arm"),
            ("MIPS", "mips"),
            ("PowerPC", "powerpc"),
            ("PPC", "powerpc"),
            ("SPARC", "sparc"),
            ("RISC-V", "riscv"),
            ("SuperH", "superh"),
            ("m68k", "m68k"),
            ("other", "other"),
        ] {
            assert_eq!(canonical(old), Some(new), "{old}");
        }
        assert_eq!(canonical("vax"), None);
        assert_eq!(normalize("vax"), "vax");
        for word in ARCHES {
            assert_eq!(canonical(word), Some(word), "{word} is its own spelling");
        }
    }

    #[test]
    fn a_guest_has_one_word_and_runs_what_the_window_runs() {
        assert_eq!(of_guest(GuestArch::X86_64), "x86_64");
        assert_eq!(of_guest(GuestArch::AARCH64), "arm64");
        assert!(guest_runs(GuestArch::AARCH64, "AArch64"));
        assert!(guest_runs(GuestArch::AARCH64, "arm64"));
        assert!(guest_runs(GuestArch::AARCH64, "ARM"));
        assert!(!guest_runs(GuestArch::AARCH64, "x86_64"));
        assert!(guest_runs(GuestArch::X86_64, "x86"));
        assert!(guest_runs(GuestArch::X86_64, "i386"));
        assert!(!guest_runs(GuestArch::X86_64, "arm64"));
        assert!(!guest_runs(GuestArch::X86_64, "vax"));
    }

    #[test]
    fn a_list_reads_old_spellings_once_and_keeps_unknown_words() {
        let list: Vec<String> =
            deserialize_list(serde_json::json!(["AArch64", "arm64", "any", "vax"])).unwrap();
        assert_eq!(list, ["arm64", "any", "vax"]);
    }
}
