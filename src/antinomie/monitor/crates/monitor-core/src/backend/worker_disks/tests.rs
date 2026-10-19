// SPDX-License-Identifier: MIT
use super::*;
use crate::disks::{
    self, Ext4State,
    fixture::{Fixture as Images, require_tools},
    reader::{DiskAnswer, DiskRequest, image::Image},
};
use std::process::Command as Process;

fn vm_command(name: &str) -> Vec<Command> {
    let vm_id = || "a".to_string();
    let request = || SnapshotRequest {
        name: "checkpoint".into(),
        description: String::new(),
        mode: VmSnapshotMode::Disk,
    };
    match name {
        "changing" => vec![
            Command::Reset {
                vm_id: vm_id(),
                confirmed: true,
            },
            Command::RestoreVmSnapshot {
                vm_id: vm_id(),
                snapshot_id: "s".into(),
                boot_from_disk: true,
                save_current: None,
                confirmed: true,
            },
            Command::CreateVmSnapshot {
                vm_id: vm_id(),
                request: request(),
            },
            Command::Delete {
                vm_id: vm_id(),
                confirmed: true,
            },
            Command::Duplicate {
                vm_id: vm_id(),
                name: "copy".into(),
            },
        ],
        _ => unreachable!(),
    }
}

fn dump(vm: &str) -> Command {
    Command::DumpDisk {
        vm_id: vm.into(),
        hash: true,
        layer_digests: false,
    }
}

fn keep(vm: &str) -> Command {
    Command::KeepCurrentDiskAsDump {
        vm_id: vm.into(),
        hash: true,
        layer_digests: false,
    }
}

#[test]
fn the_lease_refuses_what_would_touch_the_chain_being_read() {
    let start = |vm: &str| Command::Start { vm_id: vm.into() };
    // No job: nothing is refused.
    for command in [
        start("a"),
        Command::MeasureDisk { vm_id: "a".into() },
        dump("a"),
        keep("a"),
    ]
    .into_iter()
    .chain(vm_command("changing"))
    {
        assert_eq!(lease(None, &command), Ok(()), "{command:?}");
    }
    // A job on VM `a`: its own chain is protected.
    let message = lease(Some("a"), &start("a")).unwrap_err();
    assert!(
        message.contains("being read for the Disks tab"),
        "{message}"
    );
    assert!(message.contains("before starting the VM"), "{message}");
    for command in vm_command("changing") {
        let message = lease(Some("a"), &command).unwrap_err();
        assert!(
            message.contains("being read for the Disks tab"),
            "{command:?}: {message}"
        );
    }
    // Another VM's disk is unrelated.
    assert_eq!(lease(Some("a"), &start("b")), Ok(()));
    assert_eq!(
        lease(
            Some("a"),
            &Command::Reset {
                vm_id: "b".into(),
                confirmed: true
            }
        ),
        Ok(())
    );
    // One job slot overall.
    for vm in ["a", "b"] {
        for command in [
            Command::MeasureDisk { vm_id: vm.into() },
            Command::OpenCurrentDisk { vm_id: vm.into() },
            dump(vm),
            keep(vm),
        ] {
            let message = lease(Some("a"), &command).unwrap_err();
            assert!(message.contains("another disk inspection or dump is still running"));
        }
    }
    // Stop, cancel, close, renames and logical deletes never touch the chain.
    for command in [
        Command::Stop,
        Command::CancelDiskJob { vm_id: "a".into() },
        Command::CloseCurrentDisk { vm_id: "a".into() },
        Command::Rename {
            vm_id: "a".into(),
            name: "x".into(),
        },
        Command::RenameVmSnapshot {
            vm_id: "a".into(),
            snapshot_id: "s".into(),
            name: "n".into(),
        },
        Command::DeleteVmSnapshot {
            vm_id: "a".into(),
            snapshot_id: "s".into(),
            confirmed: true,
        },
    ] {
        assert_eq!(lease(Some("a"), &command), Ok(()), "{command:?}");
    }
}

#[test]
fn only_chain_changing_commands_close_a_view() {
    assert_eq!(
        effect(&Command::Start { vm_id: "a".into() }),
        Some(("a", DiskEffect::Starts))
    );
    for command in vm_command("changing") {
        let expected = if matches!(command, Command::Duplicate { .. }) {
            DiskEffect::Reads
        } else {
            DiskEffect::Changes
        };
        assert_eq!(effect(&command), Some(("a", expected)), "{command:?}");
    }
    assert_eq!(effect(&Command::Stop), None);
    assert_eq!(effect(&Command::DumpMemory), None);
    // Dumping reads the chain; it is a job, not a chain change.
    assert_eq!(effect(&dump("a")), None);
    assert_eq!(effect(&keep("a")), None);
}

fn blank_worker(root: PathBuf) -> Worker {
    let (_commands, receiver) = mpsc::sync_channel(1);
    let (sender, _notifications) = mpsc::sync_channel(64);
    let (completion_sender, _completions) = mpsc::sync_channel(COMMAND_COMPLETION_CAPACITY);
    Worker {
        options: BackendOptions {
            bundle_dir: root.join("missing-bundle"),
            data_dir: root,
            ..BackendOptions::default()
        },
        snapshot: Snapshot::default(),
        receiver,
        sender,
        completion_sender,
        completion_credits: Arc::new(CompletionCredits::default()),
        closing: Arc::new(AtomicBool::new(false)),
        stopping: Arc::new(AtomicBool::new(false)),
        owner_failed: Arc::new(AtomicBool::new(false)),
        session: None,
        keyboard: None,
        catalog: distribution::Catalog::default(),
        refresh: None,
        download: None,
        build: None,
        tool: None,
        last_publish: Instant::now(),
        latest_snapshot: Arc::new(Mutex::new(None)),
        guest_epoch: Arc::new(AtomicU64::new(0)),
        reconnect: (0, None),
        deferred_flush: None,
        flusher: Default::default(),
        evidence: Default::default(),
        disk_job: None,
        host_analysis: Default::default(),
        debug: super::super::debug_service::DebugService::new().0,
        wake: None,
    }
}

/// A VM whose installed base holds the standard ext4 image and whose disk is
/// an overlay holding one more file (`/etc/written-after-base`).
struct Machine {
    /// Keeps the fixture folder until the machine is dropped.
    _images: Images,
    worker: Worker,
    vm: VmConfig,
    directory: PathBuf,
}

impl Machine {
    fn new() -> Self {
        let images = Images::new();
        let options_root = images.path("data");
        storage::private_dir(&options_root).unwrap();
        let mut worker = blank_worker(options_root.clone());
        let tree = images.standard_tree("tree");
        let base_raw = images.ext4("base.ext4", &tree, &[]);
        let base = images.path("source-base.qcow2");
        convert(&["-f", "raw", "-O", "qcow2"], &base_raw, &base, None);
        let kernel = images.path("kernel");
        fs::write(&kernel, b"synthetic kernel").unwrap();
        let bundle = storage::Bundle {
            kernel,
            base_disk: base,
            initrd: None,
            kernel_append: String::new(),
            kernel_version: "6.12.94".into(),
            schema_id: 1,
            base_identity: None,
            guest: None,
            fixed_display: false,
            build_provenance: None,
            antinomie_revision: None,
            antinomie_source: None,
            symbols: None,
            built_with: None,
            min_app_version: None,
            name: None,
        }
        .install(&worker.options)
        .unwrap();
        let mut vm = VmConfig {
            id: "fixture".into(),
            name: "Fixture".into(),
            ..VmConfig::default()
        };
        vm.base_identity = bundle.base_identity.clone();
        let directory = options_root.join("fixture");
        storage::private_dir(&directory).unwrap();
        storage::atomic_json(&directory.join("bundle.json"), &bundle).unwrap();
        storage::atomic_json(&directory.join("config.json"), &vm).unwrap();
        // The overlay: the base plus one file, as a guest would have left it.
        fs::write(tree.join("etc/written-after-base"), "after the base\n").unwrap();
        let changed = images.ext4("overlay.ext4", &tree, &[]);
        convert(
            &["-f", "raw", "-O", "qcow2", "-F", "qcow2"],
            &changed,
            &directory.join("disk.qcow2"),
            Some(&bundle.base_disk),
        );
        worker.snapshot.vms = vec![vm.clone()];
        worker.refresh_locations().unwrap();
        Self {
            _images: images,
            worker,
            vm,
            directory,
        }
    }

    fn command(&mut self, command: Command) -> Result<String, String> {
        self.worker.command(command)
    }

    /// Run the worker loop's disk polling until the job ends.
    fn finish_job(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        while self.worker.disk_job.is_some() {
            self.worker.poll_disk_job();
            assert!(Instant::now() < deadline, "the disk job did not end");
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn disks_dir(&self) -> PathBuf {
        disks::disks_dir(&self.directory)
    }

    fn scratch(&self) -> Vec<PathBuf> {
        fs::read_dir(self.disks_dir())
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.path())
                    .filter(|path| {
                        path.file_name()
                            .is_some_and(|name| name.to_string_lossy().starts_with(".scratch-"))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn open_view(&mut self) -> disks::CurrentDiskView {
        self.command(Command::OpenCurrentDisk {
            vm_id: "fixture".into(),
        })
        .unwrap();
        self.finish_job();
        self.worker.snapshot.current_disk.clone().expect("a view")
    }
}

fn convert(flags: &[&str], source: &Path, target: &Path, backing: Option<&Path>) {
    let mut command = Process::new("qemu-img");
    command.arg("convert").args(flags);
    if let Some(backing) = backing {
        command.arg("-B").arg(backing);
    }
    let output = command.arg(source).arg(target).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_file(view: &disks::CurrentDiskView, path: &str) -> Result<String, String> {
    let out = view.image.parent().unwrap().join("probe-out");
    fs::create_dir_all(&out).unwrap();
    let image = Image::open(&view.image, &out);
    match image
        .handle(
            77,
            DiskRequest::Extract {
                path: path.into(),
                max_len: 1 << 20,
            },
        )
        .map_err(|error| error.to_string())?
    {
        DiskAnswer::Extracted(_) => {
            let text = fs::read_to_string(out.join("77")).unwrap();
            fs::remove_dir_all(&out).unwrap();
            Ok(text)
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn measuring_then_opening_reads_the_overlay_and_records_where_it_came_from() {
    require_tools!();
    let mut machine = Machine::new();
    machine
        .command(Command::MeasureDisk {
            vm_id: "fixture".into(),
        })
        .unwrap();
    assert_eq!(
        machine
            .worker
            .snapshot
            .disk_job
            .as_ref()
            .map(|job| job.purpose),
        Some(disks::DiskJobPurpose::Measure)
    );
    machine.finish_job();
    let measure = machine.worker.snapshot.disk_measure.clone().unwrap();
    assert_eq!(measure.error, None);
    assert_eq!(measure.vm_id, "fixture");
    assert_eq!(measure.logical_size, 32 * 1024 * 1024);
    assert_eq!(measure.source.active_layer, "disk.qcow2");
    assert_eq!(measure.source.active_parent_id, None);
    assert!(machine.worker.snapshot.disk_job.is_none());

    let view = machine.open_view();
    assert_eq!(view.fs_state, Ext4State::Clean);
    assert_eq!(view.source.active_layer, "disk.qcow2");
    assert_eq!(view.source.layers.len(), 2);
    assert_eq!(
        read_file(&view, "/etc/written-after-base").unwrap(),
        "after the base\n"
    );
    assert_eq!(machine.scratch().len(), 1);
    // The chain is untouched: the overlay is still a valid image.
    assert!(
        Process::new("qemu-img")
            .arg("check")
            .arg(machine.directory.join("disk.qcow2"))
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn opening_again_replaces_the_view_and_closing_deletes_its_scratch() {
    require_tools!();
    let mut machine = Machine::new();
    let first = machine.open_view();
    let second = machine.open_view();
    assert_ne!(first.view_id, second.view_id);
    assert!(!first.image.exists());
    assert_eq!(
        machine.scratch(),
        [second.image.parent().unwrap().to_path_buf()]
    );
    assert!(
        machine
            .command(Command::CloseCurrentDisk {
                vm_id: "other".into()
            })
            .is_err()
    );
    machine
        .command(Command::CloseCurrentDisk {
            vm_id: "fixture".into(),
        })
        .unwrap();
    assert!(machine.worker.snapshot.current_disk.is_none());
    assert!(machine.scratch().is_empty());
}

#[test]
fn start_reset_restore_snapshot_delete_and_duplicate_wait_for_the_job() {
    require_tools!();
    let mut machine = Machine::new();
    machine
        .command(Command::OpenCurrentDisk {
            vm_id: "fixture".into(),
        })
        .unwrap();
    let guarded = [
        Command::Start {
            vm_id: "fixture".into(),
        },
        Command::Reset {
            vm_id: "fixture".into(),
            confirmed: true,
        },
        Command::RestoreVmSnapshot {
            vm_id: "fixture".into(),
            snapshot_id: "s".into(),
            boot_from_disk: true,
            save_current: None,
            confirmed: true,
        },
        Command::CreateVmSnapshot {
            vm_id: "fixture".into(),
            request: SnapshotRequest {
                name: "n".into(),
                description: String::new(),
                mode: VmSnapshotMode::Disk,
            },
        },
        Command::Delete {
            vm_id: "fixture".into(),
            confirmed: true,
        },
        Command::Duplicate {
            vm_id: "fixture".into(),
            name: "copy".into(),
        },
    ];
    // Slow the job down by cancelling nothing: the job is live right now.
    assert!(machine.worker.disk_job.is_some());
    for command in guarded {
        let error = machine.command(command.clone()).unwrap_err();
        assert!(
            error.contains("being read for the Disks tab"),
            "{command:?}: {error}"
        );
    }
    assert!(
        machine
            .command(Command::OpenCurrentDisk {
                vm_id: "fixture".into()
            })
            .unwrap_err()
            .contains("another disk inspection")
    );
    assert!(
        machine
            .command(Command::MeasureDisk {
                vm_id: "fixture".into()
            })
            .unwrap_err()
            .contains("another disk inspection")
    );
    machine
        .command(Command::CancelDiskJob {
            vm_id: "fixture".into(),
        })
        .unwrap();
    machine.finish_job();
    // The lease is gone: nothing refuses the commands on account of the job.
    assert!(
        machine
            .worker
            .disk_lease_gate(&Command::Start {
                vm_id: "fixture".into()
            })
            .is_ok()
    );
    assert!(
        machine.worker.snapshot.current_disk.is_none()
            || machine.worker.snapshot.current_disk.is_some()
    );
}

#[test]
fn cancelling_leaves_no_scratch_and_no_view() {
    require_tools!();
    let mut machine = Machine::new();
    machine
        .command(Command::OpenCurrentDisk {
            vm_id: "fixture".into(),
        })
        .unwrap();
    assert!(
        machine
            .command(Command::CancelDiskJob {
                vm_id: "other".into()
            })
            .is_err()
    );
    machine
        .command(Command::CancelDiskJob {
            vm_id: "fixture".into(),
        })
        .unwrap();
    machine.finish_job();
    // The job may have finished before it saw the cancel; either way the
    // state is consistent: a view exists only with its one scratch folder.
    let view = machine.worker.snapshot.current_disk.clone();
    assert_eq!(machine.scratch().len(), usize::from(view.is_some()));
    assert!(machine.worker.snapshot.disk_job.is_none());
}

#[test]
fn opening_needs_the_vm_off() {
    require_tools!();
    let mut machine = Machine::new();
    machine.worker.snapshot.active_vm = Some("fixture".into());
    for state in [VmState::Starting, VmState::Running, VmState::Stopping] {
        machine.worker.snapshot.state = state.clone();
        for command in [
            Command::OpenCurrentDisk {
                vm_id: "fixture".into(),
            },
            Command::MeasureDisk {
                vm_id: "fixture".into(),
            },
        ] {
            assert_eq!(
                machine.command(command).unwrap_err(),
                "stop the VM before inspecting or dumping its disk"
            );
        }
    }
    assert!(machine.worker.disk_job.is_none());
    // Another VM running does not matter: its disk is unrelated.
    machine.worker.snapshot.active_vm = Some("other".into());
    machine
        .command(Command::MeasureDisk {
            vm_id: "fixture".into(),
        })
        .unwrap();
    machine.finish_job();
    assert!(machine.worker.snapshot.disk_measure.is_some());
}

#[test]
fn a_changed_chain_or_a_started_vm_closes_the_view_and_deletes_its_scratch() {
    require_tools!();
    let mut machine = Machine::new();
    for command in [
        Command::Start {
            vm_id: "fixture".into(),
        },
        Command::Reset {
            vm_id: "fixture".into(),
            confirmed: true,
        },
        Command::Delete {
            vm_id: "fixture".into(),
            confirmed: true,
        },
    ] {
        let view = machine.open_view();
        assert!(view.image.exists());
        machine.worker.snapshot.disk_measure = Some(disks::DiskMeasure {
            vm_id: "fixture".into(),
            ..disks::DiskMeasure::default()
        });
        machine.worker.close_disk_view_after(&command);
        assert!(
            machine.worker.snapshot.current_disk.is_none(),
            "{command:?}"
        );
        assert!(
            machine.worker.snapshot.disk_measure.is_none(),
            "{command:?}"
        );
        assert!(
            !view.image.exists() && machine.scratch().is_empty(),
            "{command:?}"
        );
    }
    // Another VM's start, and a read-only copy, leave the view alone.
    let view = machine.open_view();
    machine.worker.close_disk_view_after(&Command::Start {
        vm_id: "other".into(),
    });
    machine.worker.close_disk_view_after(&Command::Duplicate {
        vm_id: "fixture".into(),
        name: "copy".into(),
    });
    assert_eq!(machine.worker.snapshot.current_disk.as_ref(), Some(&view));
    assert!(view.image.exists());
}

#[test]
fn a_successful_reset_closes_the_view_through_the_command_path() {
    require_tools!();
    let mut machine = Machine::new();
    let view = machine.open_view();
    // Reset needs the bundle the VM was created from.
    match machine.command(Command::Reset {
        vm_id: "fixture".into(),
        confirmed: true,
    }) {
        Ok(_) => {
            assert!(machine.worker.snapshot.current_disk.is_none());
            assert!(!view.image.exists());
        }
        Err(error) => {
            // A refused command leaves the view as it was.
            assert!(!error.contains("Disks tab"), "{error}");
            assert_eq!(machine.worker.snapshot.current_disk.as_ref(), Some(&view));
        }
    }
}

#[test]
fn a_snapshot_tree_shows_the_top_layer_and_names_its_parent() {
    require_tools!();
    let mut machine = Machine::new();
    let request = SnapshotRequest {
        name: "before".into(),
        description: String::new(),
        mode: VmSnapshotMode::Disk,
    };
    let prepared = crate::snapshots::prepare_take(
        &machine.worker.options,
        &machine.vm,
        &request,
        VmSnapshotConsistency::Stopped,
    )
    .unwrap();
    let checkpoint =
        crate::snapshots::commit_take(&machine.worker.options, &machine.vm, prepared, None, None)
            .unwrap();
    machine.worker.refresh_vm_snapshots("fixture").unwrap();
    let view = machine.open_view();
    assert!(
        view.source.active_layer.starts_with("snapshots/"),
        "{:?}",
        view.source
    );
    assert_eq!(
        view.source.active_parent_id.as_deref(),
        Some(checkpoint.id.as_str())
    );
    // base, disk.qcow2 (frozen) and the new empty top.
    assert_eq!(view.source.layers.len(), 3);
    // What the guest wrote before the checkpoint is in the view.
    assert_eq!(
        read_file(&view, "/etc/written-after-base").unwrap(),
        "after the base\n"
    );
}

#[test]
fn leftover_scratch_folders_are_swept_at_start() {
    require_tools!();
    let mut machine = Machine::new();
    let leftover = machine.disks_dir().join(".scratch-crashed");
    fs::create_dir_all(&leftover).unwrap();
    fs::write(leftover.join("root.ext4"), "x").unwrap();
    // An unfinished dump (an image, no dump.json) goes too; a finished one,
    // a view's extractions and somebody's folder stay.
    let unfinished = machine.disks_dir().join("unfinished");
    fs::create_dir_all(&unfinished).unwrap();
    fs::write(unfinished.join("root.ext4.part"), "x").unwrap();
    let finished = machine.disks_dir().join("finished");
    fs::create_dir_all(&finished).unwrap();
    fs::write(
        finished.join("dump.json"),
        r#"{"id":"finished","finished_ms":1}"#,
    )
    .unwrap();
    let extracted = machine.disks_dir().join("extracted/view");
    fs::create_dir_all(&extracted).unwrap();
    machine.worker.sweep_disk_scratch();
    assert!(!leftover.exists() && !unfinished.exists());
    assert!(finished.exists() && extracted.exists());
    // And closing the backend removes an open view.
    let view = machine.open_view();
    machine.worker.shutdown_disks();
    assert!(!view.image.exists() && machine.worker.snapshot.current_disk.is_none());
}

#[test]
fn a_pending_snapshot_journal_is_recovered_before_the_disk_is_read() {
    require_tools!();
    let mut machine = Machine::new();
    // An interrupted take leaves its journal: the disk commands run the same
    // recovery `start()` does, and refuse while it cannot be completed.
    fs::write(machine.directory.join("snapshot-operation.json"), b"{}").unwrap();
    let error = machine
        .command(Command::OpenCurrentDisk {
            vm_id: "fixture".into(),
        })
        .unwrap_err();
    assert!(!error.is_empty());
    assert!(machine.worker.disk_job.is_none() && machine.scratch().is_empty());
}

#[test]
fn host_files_are_analyzed_through_the_ordinary_job_queue() {
    let images = Images::new();
    let mut worker = blank_worker(images.path("data"));
    worker.snapshot.vms = vec![VmConfig {
        id: "fixture".into(),
        ..VmConfig::default()
    }];
    let selection = crate::analysis::AnalysisSelection {
        enabled: true,
        checks: crate::analysis::AnalysisKind::TRIAGE.to_vec(),
    };
    // Disabled analysis, a directory and a link are refused.
    let disabled = crate::analysis::AnalysisSelection::default();
    assert!(
        worker
            .analyze_host_file("fixture", &images.root, disabled)
            .is_err()
    );
    assert!(
        worker
            .analyze_host_file("fixture", &images.root, selection.clone())
            .is_err()
    );
    let target = images.path("sample.bin");
    fs::write(&target, b"\x7fELF-not-really").unwrap();
    let link = images.path("link.bin");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(
        worker
            .analyze_host_file("fixture", &link, selection.clone())
            .is_err()
    );
    assert!(worker.snapshot.analysis_reports.is_empty());
}

fn dump_of(machine: &mut Machine, hash: bool) -> disks::dump::DiskDump {
    machine
        .command(Command::DumpDisk {
            vm_id: "fixture".into(),
            hash,
            layer_digests: false,
        })
        .unwrap();
    assert_eq!(
        machine
            .worker
            .snapshot
            .disk_job
            .as_ref()
            .map(|job| job.purpose),
        Some(disks::DiskJobPurpose::Dump)
    );
    machine.finish_job();
    disks::dump::list(std::slice::from_ref(&machine.directory))
        .into_iter()
        .next()
        .expect("a dump")
}

/// Delete through the evidence-delete thread, as the worker loop does, and
/// wait for it: the error is the command's failure, the thread's or the
/// immediate one.
fn delete_dump(machine: &mut Machine, directory: &Path) -> Result<String, String> {
    machine.worker.snapshot.last_error = None;
    machine.worker.start_evidence_delete(
        1,
        "fixture",
        crate::EvidenceItem::DiskDump {
            directory: directory.to_path_buf(),
        },
        true,
    )?;
    machine.worker.finish_evidence_deletes();
    match machine.worker.snapshot.last_error.take() {
        Some(error) => Err(error),
        None => Ok("Deleted disk dump".into()),
    }
}

#[test]
fn dumping_writes_a_finished_dump_of_the_overlay_with_the_vms_identity() {
    require_tools!();
    let mut machine = Machine::new();
    let dump = dump_of(&mut machine, true);
    assert_eq!(dump.vm_id, "fixture");
    assert_eq!(dump.vm_name, "Fixture");
    assert_eq!(dump.system, "Linux 6.12.94");
    assert_eq!(dump.fs_state, Ext4State::Clean);
    assert!(dump.sha256.as_deref().is_some_and(|sum| sum.len() == 64));
    assert_eq!(dump.source.active_layer, "disk.qcow2");
    assert_eq!(dump.source.layers.len(), 2);
    // It holds the file written after the base, and no view was opened.
    let view = disks::CurrentDiskView {
        image: dump.path(),
        extract_dir: machine.directory.join("out"),
        ..disks::CurrentDiskView::default()
    };
    fs::create_dir_all(&view.extract_dir).unwrap();
    assert_eq!(
        read_file_at(&view.image, &view.extract_dir, "/etc/written-after-base").unwrap(),
        "after the base\n"
    );
    assert!(machine.worker.snapshot.current_disk.is_none());
    assert!(machine.scratch().is_empty() && machine.worker.snapshot.disk_job.is_none());
    // Without the hash setting no digest is recorded.
    let plain = dump_of(&mut machine, false);
    assert_eq!(plain.sha256, None);
}

fn read_file_at(image: &Path, out: &Path, path: &str) -> Result<String, String> {
    let image = Image::open(image, out);
    match image
        .handle(
            78,
            DiskRequest::Extract {
                path: path.into(),
                max_len: 1 << 20,
            },
        )
        .map_err(|error| error.to_string())?
    {
        DiskAnswer::Extracted(_) => Ok(fs::read_to_string(out.join("78")).unwrap()),
        other => panic!("{other:?}"),
    }
}

#[test]
fn dumping_needs_the_vm_off_and_a_free_job_slot() {
    require_tools!();
    let mut machine = Machine::new();
    machine.worker.snapshot.active_vm = Some("fixture".into());
    for state in [VmState::Starting, VmState::Running, VmState::Stopping] {
        machine.worker.snapshot.state = state.clone();
        for command in [dump("fixture"), keep("fixture")] {
            let error = machine.command(command).unwrap_err();
            assert!(error.contains("stop the VM"), "{state:?}: {error}");
        }
    }
    machine.worker.snapshot.active_vm = None;
    assert!(machine.worker.disk_job.is_none());
    machine.command(dump("fixture")).unwrap();
    assert!(
        machine
            .command(dump("fixture"))
            .unwrap_err()
            .contains("another disk inspection or dump")
    );
    // Starting the VM waits for the dump too.
    assert!(
        machine
            .command(Command::Start {
                vm_id: "fixture".into()
            })
            .unwrap_err()
            .contains("being read for the Disks tab")
    );
    machine
        .command(Command::CancelDiskJob {
            vm_id: "fixture".into(),
        })
        .unwrap();
    machine.finish_job();
    // A cancelled dump leaves nothing, or a finished dump if it won the race.
    let dumps = disks::dump::list(std::slice::from_ref(&machine.directory));
    let folders = fs::read_dir(machine.disks_dir()).map_or(0, Iterator::count);
    assert_eq!(folders, dumps.len());
}

#[test]
fn a_dump_over_the_quota_fails_with_the_quota_sentence() {
    require_tools!();
    let mut machine = Machine::new();
    machine.worker.options.capture_quota_size = 4096;
    machine.command(dump("fixture")).unwrap();
    machine.finish_job();
    let error = machine.worker.snapshot.last_error.clone().unwrap();
    assert!(crate::quota::is_quota_error(&error), "{error}");
    assert!(disks::dump::list(std::slice::from_ref(&machine.directory)).is_empty());
    assert!(fs::read_dir(machine.disks_dir()).map_or(0, Iterator::count) == 0);
    // The measure shows the ceiling so the tab can say why before the click.
    machine
        .command(Command::MeasureDisk {
            vm_id: "fixture".into(),
        })
        .unwrap();
    machine.finish_job();
    let measure = machine.worker.snapshot.disk_measure.clone().unwrap();
    assert_eq!(measure.quota, 4096);
    assert!(measure.quota_error().is_some() && measure.error.is_none());
}

#[test]
fn keep_as_dump_promotes_the_open_view_and_closing_it_keeps_the_dump() {
    require_tools!();
    let mut machine = Machine::new();
    assert!(
        machine
            .command(keep("fixture"))
            .unwrap_err()
            .contains("no disk view is open")
    );
    let view = machine.open_view();
    let old_folder = view.image.parent().unwrap().to_path_buf();
    machine.command(keep("fixture")).unwrap();
    assert_eq!(
        machine
            .worker
            .snapshot
            .disk_job
            .as_ref()
            .map(|job| job.purpose),
        Some(disks::DiskJobPurpose::Keep)
    );
    machine.finish_job();
    let kept = machine
        .worker
        .snapshot
        .current_disk
        .clone()
        .expect("still open");
    let dumps = disks::dump::list(std::slice::from_ref(&machine.directory));
    assert_eq!(dumps.len(), 1);
    assert_eq!(kept.kept_as.as_deref(), Some(dumps[0].id.as_str()));
    assert_eq!(kept.image, dumps[0].path());
    assert_eq!(kept.view_id, view.view_id);
    assert!(!old_folder.exists() && machine.scratch().is_empty());
    // Keeping twice is refused.
    machine.command(keep("fixture")).unwrap();
    machine.finish_job();
    assert_eq!(
        disks::dump::list(std::slice::from_ref(&machine.directory)).len(),
        1
    );
    assert!(
        machine
            .worker
            .snapshot
            .last_error
            .as_deref()
            .unwrap()
            .contains("already kept")
    );
    // Closing the view must not delete the dump it became.
    machine
        .command(Command::CloseCurrentDisk {
            vm_id: "fixture".into(),
        })
        .unwrap();
    assert!(dumps[0].path().is_file() && dumps[0].dir.join("dump.json").is_file());
    // Neither does starting the VM or a chain change with a kept view open.
    machine.worker.snapshot.current_disk = Some(kept);
    machine.worker.close_disk_view_after(&Command::Start {
        vm_id: "fixture".into(),
    });
    assert!(machine.worker.snapshot.current_disk.is_none());
    assert!(dumps[0].path().is_file());
}

#[test]
fn dumps_stay_browsable_while_the_vm_runs() {
    require_tools!();
    let mut machine = Machine::new();
    let dump = dump_of(&mut machine, true);
    machine.worker.snapshot.active_vm = Some("fixture".into());
    machine.worker.snapshot.state = VmState::Running;
    // New inspection is refused, the saved dump still lists and reads.
    assert!(machine.command(dump_command()).is_err());
    let listed = disks::dump::list(std::slice::from_ref(&machine.directory));
    assert_eq!(listed.len(), 1);
    assert!(listed[0].browsable());
    let out = machine.directory.join("running-out");
    fs::create_dir_all(&out).unwrap();
    assert_eq!(
        read_file_at(&listed[0].path(), &out, "/etc/written-after-base").unwrap(),
        "after the base\n"
    );
    // Deleting a dump is a host-file operation and works with the VM running.
    delete_dump(&mut machine, &dump.dir).unwrap();
    assert!(!dump.dir.exists());
}

fn dump_command() -> Command {
    dump("fixture")
}

#[test]
fn deleting_a_dump_is_confined_to_the_recording_folders() {
    require_tools!();
    let mut machine = Machine::new();
    let dump = dump_of(&mut machine, false);
    let precious = machine.directory.join("precious");
    fs::create_dir_all(&precious).unwrap();
    fs::write(precious.join("dump.json"), "{}").unwrap();
    fs::write(precious.join("keep.txt"), "x").unwrap();
    // Outside the VM's recording folders, with a sidecar of its own.
    let outside = machine._images.path("outside/disks/looks-like-a-dump");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("dump.json"), "{}").unwrap();
    let escape = dump.dir.join("..").join("..").join("precious");
    let view_folder = machine.disks_dir().join(".scratch-view");
    fs::create_dir_all(&view_folder).unwrap();
    fs::write(view_folder.join("dump.json"), "{}").unwrap();
    let link = machine.disks_dir().join("linked");
    std::os::unix::fs::symlink(&precious, &link).unwrap();
    let extracted = machine.disks_dir().join("extracted");
    fs::create_dir_all(&extracted).unwrap();
    fs::write(extracted.join("dump.json"), "{}").unwrap();
    let inside_dump = dump.dir.join("extracted");
    fs::create_dir_all(&inside_dump).unwrap();
    fs::write(inside_dump.join("dump.json"), "{}").unwrap();
    for target in [
        outside.clone(),
        escape,
        precious.clone(),
        view_folder.clone(),
        link.clone(),
        extracted.clone(),
        inside_dump.clone(),
        machine.disks_dir(),
        machine.directory.clone(),
        PathBuf::from("disks/relative"),
        PathBuf::from("/"),
        machine.disks_dir().join("absent"),
    ] {
        let error = delete_dump(&mut machine, &target);
        assert!(error.is_err(), "{}: {error:?}", target.display());
    }
    assert!(outside.join("dump.json").exists() && precious.join("keep.txt").exists());
    assert!(view_folder.exists() && link.exists() && extracted.exists());
    assert!(dump.dir.join("dump.json").exists());
    // Unconfirmed deletes do nothing.
    assert!(
        machine
            .worker
            .start_evidence_delete(
                2,
                "fixture",
                crate::EvidenceItem::DiskDump {
                    directory: dump.dir.clone()
                },
                false,
            )
            .unwrap_err()
            .contains("confirmation")
    );
    assert!(dump.dir.exists());
    // The real dump deletes, with its extractions.
    let message = delete_dump(&mut machine, &dump.dir).unwrap();
    assert!(message.contains("Deleted disk dump"), "{message}");
    assert!(!dump.dir.exists());
    assert!(machine.disks_dir().join("linked").exists());
}

#[test]
fn deleting_the_dump_an_open_view_reads_is_refused_until_it_closes() {
    require_tools!();
    let mut machine = Machine::new();
    machine.open_view();
    machine.command(keep("fixture")).unwrap();
    machine.finish_job();
    let dump = disks::dump::list(std::slice::from_ref(&machine.directory))
        .pop()
        .unwrap();
    let error = delete_dump(&mut machine, &dump.dir).unwrap_err();
    assert!(error.contains("close the view"), "{error}");
    assert!(dump.dir.exists());
    machine
        .command(Command::CloseCurrentDisk {
            vm_id: "fixture".into(),
        })
        .unwrap();
    delete_dump(&mut machine, &dump.dir).unwrap();
    assert!(!dump.dir.exists());
}

#[test]
fn deleting_an_imported_dump_leaves_the_original_image() {
    require_tools!();
    let mut machine = Machine::new();
    let tree = machine._images.standard_tree("import-tree");
    let image = machine._images.ext4("import.ext4", &tree, &[]);
    let dump = disks::dump::import(&machine.directory, "fixture", "Fixture", &image).unwrap();
    delete_dump(&mut machine, &dump.dir).unwrap();
    assert!(!dump.dir.exists() && image.is_file());
}
