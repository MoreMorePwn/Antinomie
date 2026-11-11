// SPDX-License-Identifier: GPL-3.0-only
//! Two and three engines in one process, one per lane, on one shared lane 0
//! (ANT-T0455 card B). No VM starts: the engines list the shared base, a lane
//! creates a VM on it (a qcow2 overlay), the lanes refuse the shared writers,
//! lane 0 refuses to delete a base a lane's VM uses, and every lane writes the
//! one sample library at once without losing a custody entry.
use super::tests::Tree;
use super::*;
use crate::{
    Backend, Command, Notification,
    api::VmConfig,
    samples::{CustodyEvent, Library, NewOrigin, NewSample, OriginKind, Tag, TagKind},
    storage::Bundle,
};
use std::time::{Duration, Instant};

/// Install a 1 MiB base into lane 0, as `base install` does.
fn install_base(tree: &Tree) -> String {
    let source = tree.root.join("source");
    crate::storage::private_dir(&source).unwrap();
    fs::write(source.join("kernel"), b"kernel fixture").unwrap();
    let created = std::process::Command::new("qemu-img")
        .args(["create", "-f", "qcow2"])
        .arg(source.join("base.qcow2"))
        .arg("1M")
        .output()
        .unwrap();
    assert!(created.status.success());
    let bundle = Bundle {
        arch: Default::default(),
        kernel: source.join("kernel"),
        base_disk: source.join("base.qcow2"),
        initrd: None,
        kernel_append: String::new(),
        kernel_version: "6.12.94".into(),
        schema_id: 1,
        base_identity: None,
        guest: None,
        fixed_display: true,
        build_provenance: None,
        antinomie_revision: None,
        antinomie_source: None,
        built_with: None,
        min_app_version: None,
        name: None,
        symbols: None,
        stealth_support: Vec::new(),
        uefi: Default::default(),
    }
    .install(&tree.options(None))
    .unwrap();
    fs::remove_dir_all(source).unwrap();
    bundle.base_identity.unwrap()
}

/// No KVM on a CI or VPS host.
fn tcg() -> crate::VmLaunchOptions {
    crate::VmLaunchOptions {
        acceleration: crate::VmAcceleration::Tcg,
        ..Default::default()
    }
}

/// Send `command` and wait for its result.
fn command(backend: &Backend, command: Command) -> Result<String, String> {
    let id = backend.send(command).unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        match backend.recv_timeout(Duration::from_millis(50)).unwrap() {
            Some(Notification::CommandResult {
                id: result,
                success,
                message,
            }) if result == id => return if success { Ok(message) } else { Err(message) },
            _ => {}
        }
    }
    panic!("command timed out");
}

/// Wait until the engine has checked its bases; returns how many it lists.
fn bases_listed(backend: &Backend) -> usize {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        if let Some(Notification::Snapshot(snapshot)) =
            backend.recv_timeout(Duration::from_millis(50)).unwrap()
            && !snapshot.bases_checking
        {
            assert!(
                snapshot.base_problems.is_empty(),
                "{:?}",
                snapshot.base_problems
            );
            return snapshot.bases.len();
        }
    }
    panic!("base check never completed");
}

fn engines(lanes: u32) {
    let tree = Tree::new(&format!("engines-{lanes}"));
    let identity = install_base(&tree);
    // Lane 0 first, as the daemon starts them, then every other lane.
    let mut backends: Vec<Backend> = (0..lanes)
        .map(|lane| Backend::new(tree.options((lane > 0).then_some(lane))).unwrap())
        .collect();
    for (lane, backend) in backends.iter().enumerate() {
        assert_eq!(bases_listed(backend), 1, "lane {lane}");
    }
    for lane in 1..lanes {
        assert_eq!(
            lane_of(&lane_dir(&tree.shared, lane))
                .unwrap()
                .unwrap()
                .lane,
            lane
        );
    }
    // The owner records name the lanes.
    let record = crate::data_owner::read_record(&lane_dir(&tree.shared, 1)).unwrap();
    assert_eq!(record.lane, Some(1));
    // Each lane but 0 has a VM on the shared base, in its own folder.
    for lane in 1..lanes {
        let vm = VmConfig {
            id: format!("lane{lane}-vm"),
            name: format!("Lane {lane}"),
            base_identity: Some(identity.clone()),
            launch: tcg(),
            ..VmConfig::default()
        };
        command(&backends[lane as usize], Command::Create(vm)).unwrap();
        let folder = lane_dir(&tree.shared, lane).join(format!("lane{lane}-vm"));
        assert!(folder.join("disk.qcow2").is_file(), "{}", folder.display());
    }
    assert!(!tree.shared.join("lane1-vm").exists());
    // The lanes refuse every shared writer, whatever its arguments.
    let lane1 = &backends[1];
    let writers = [
        Command::ImportBase {
            directory: tree.root.join("nowhere"),
        },
        Command::DeleteBase {
            identity: identity.clone(),
            confirmed: true,
        },
        Command::DownloadBase {
            identity: identity.clone(),
        },
        Command::BuildBase {
            request: crate::build::BuildRequest {
                profile: "busybox".into(),
                mode: Default::default(),
                options: crate::build::BuildOptions::defaults(crate::build::Kind::BusyBox),
                arch: Default::default(),
            },
        },
        Command::InstallTool { id: "capa".into() },
        Command::RemoveTool { id: "capa".into() },
    ];
    for writer in writers {
        let error = command(lane1, writer).unwrap_err();
        assert!(is_refusal(&error) && error.contains("lane 1"), "{error}");
    }
    // Lane 0 keeps the base while lane 1's VM is built on it.
    let delete = || Command::DeleteBase {
        identity: identity.clone(),
        confirmed: true,
    };
    let error = command(&backends[0], delete()).unwrap_err();
    assert!(error.contains("Lane 1 (lane 1)"), "{error}");
    assert!(bases_dir(&tree.shared).join(&identity).is_dir());
    // Every lane writes the shared library at once, through its own folder,
    // as each lane's intake and custody log do.
    let hashes = write_library_from_every_lane(&tree, lanes);
    let library = Library::open(&tree.shared).unwrap();
    for sha in &hashes {
        let events = library.events(sha).unwrap();
        let activity = events
            .iter()
            .filter(|row| matches!(row.event, CustodyEvent::Activity { .. }))
            .count();
        assert_eq!(activity, ROUNDS, "{sha}");
    }
    assert_eq!(library.list().unwrap().len(), lanes as usize);
    assert!(library.custody_check_all().unwrap().broken().is_empty());
    assert!(!lane_dir(&tree.shared, 1).join("samples").exists());
    // Once the lanes' VMs are gone, lane 0 deletes the base.
    for lane in 1..lanes {
        let id = format!("lane{lane}-vm");
        command(
            &backends[lane as usize],
            Command::Delete {
                vm_id: id,
                confirmed: true,
            },
        )
        .unwrap();
    }
    command(&backends[0], delete()).unwrap();
    for backend in &mut backends {
        backend.shutdown().unwrap();
    }
}

const ROUNDS: usize = 8;

fn write_library_from_every_lane(tree: &Tree, lanes: u32) -> Vec<String> {
    let workers: Vec<_> = (0..lanes)
        .map(|lane| {
            let folder = if lane == 0 {
                tree.shared.clone()
            } else {
                lane_dir(&tree.shared, lane)
            };
            std::thread::spawn(move || -> Result<String, String> {
                let mut library = Library::open_patient(&folder)?;
                let bytes = format!("#!/bin/sh\necho lane {lane}\n").into_bytes();
                let mut sha = String::new();
                for round in 0..ROUNDS {
                    let new = NewSample {
                        origin: NewOrigin {
                            kind: OriginKind::Added,
                            path: format!("/in/{lane}/{round}"),
                            ..NewOrigin::default()
                        },
                        ..NewSample::default()
                    };
                    sha = library.add_bytes(&bytes, new)?.sha256;
                    library.add_tag(&sha, Tag::new(TagKind::Custom, format!("l{lane}r{round}")))?;
                    library.record_event(
                        &sha,
                        "analyst",
                        CustodyEvent::Activity {
                            run: format!("lane{lane}"),
                            detail: format!("{round}"),
                        },
                    )?;
                }
                Ok(sha)
            })
        })
        .collect();
    workers
        .into_iter()
        .map(|worker| worker.join().unwrap().unwrap())
        .collect()
}

#[test]
fn two_lane_engines_share_lane_0s_folders() {
    engines(2);
}

#[test]
fn three_lane_engines_share_lane_0s_folders() {
    engines(3);
}

#[test]
fn a_moved_tree_repairs_a_lane_vm_against_the_shared_base() {
    let tree = Tree::new("moved-vm");
    let identity = install_base(&tree);
    let mut lane0 = Backend::new(tree.options(None)).unwrap();
    let mut lane1 = Backend::new(tree.options(Some(1))).unwrap();
    bases_listed(&lane1);
    let vm = VmConfig {
        id: "moved-vm".into(),
        base_identity: Some(identity.clone()),
        launch: tcg(),
        ..VmConfig::default()
    };
    command(&lane1, Command::Create(vm)).unwrap();
    lane1.shutdown().unwrap();
    lane0.shutdown().unwrap();
    let moved = tree.root.join("moved");
    fs::rename(&tree.shared, &moved).unwrap();
    let moved = fs::canonicalize(moved).unwrap();
    let options = BackendOptions {
        data_dir: lane_dir(&moved, 1),
        shared_root: Some(moved.clone()),
        ..tree.options(Some(1))
    };
    let problems = crate::data_move::repair(&options);
    assert!(problems.is_empty(), "{problems:?}");
    let disk = lane_dir(&moved, 1).join("moved-vm/disk.qcow2");
    assert_eq!(
        crate::disk_start::backing_file(&disk).unwrap().unwrap(),
        moved.join("bases").join(&identity).join("base.qcow2")
    );
    // The lane's engine starts on the moved tree.
    let mut lane1 = Backend::new(options).unwrap();
    assert_eq!(bases_listed(&lane1), 1);
    lane1.shutdown().unwrap();
}

#[test]
fn a_lane_engine_refuses_a_folder_that_is_not_its_own() {
    let tree = Tree::new("engine-start");
    let mut lane1 = Backend::new(tree.options(Some(1))).unwrap();
    lane1.shutdown().unwrap();
    // The window opening lane 1's folder is sent to lane 0.
    let mut window = tree.options(Some(1));
    window.owner = Default::default();
    window.shared_root = None;
    let error = Backend::new(window).err().unwrap();
    assert!(
        error.contains("lane 1") && error.contains("open"),
        "{error}"
    );
    // Lane 2 on lane 1's folder.
    let mut other = tree.options(Some(1));
    other.owner.lane = Some(2);
    assert!(Backend::new(other).is_err());
}
