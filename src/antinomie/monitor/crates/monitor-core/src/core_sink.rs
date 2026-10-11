// SPDX-License-Identifier: MIT
//! Four disk workers isolate bounded process-core writes and durability from
//! the transport owner. A sink submits at most one job and polls its receipt.
use crate::{api::RunArtifactState, storage};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    },
    thread,
};

const WORKERS: usize = 4;
const QUEUED_JOBS: usize = 4;
pub(super) const CHUNK_SIZE: usize = 16328;

pub(super) enum Action {
    Init {
        metadata: serde_json::Value,
    },
    Write {
        offset: u64,
        data: Vec<u8>,
        metadata: serde_json::Value,
    },
    Finish {
        state: RunArtifactState,
        generation: u64,
        metadata: serde_json::Value,
    },
    #[cfg(test)]
    Hold(Receiver<()>),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Init,
    Write,
    Finish,
    #[cfg(test)]
    Hold,
}
pub(super) struct Receipt {
    pub kind: Kind,
    pub size: u64,
    pub sha256: String,
    pub has_file: bool,
    pub final_state: Option<RunArtifactState>,
    pub generation: u64,
    pub result: Result<(), String>,
}
#[cfg(test)]
#[derive(Clone, Copy)]
enum Failure {
    WriteAfter(u64),
    Sync,
    Publication,
}
struct State {
    directory: PathBuf,
    file: Option<File>,
    size: u64,
    digest: Sha256,
    has_file: bool,
    sealed: Arc<AtomicBool>,
    #[cfg(test)]
    failure: Option<Failure>,
    #[cfg(test)]
    gate: Option<Receiver<()>>,
}
struct Job {
    state: State,
    action: Action,
    reply: SyncSender<(State, Receipt)>,
}
struct Pool {
    sender: SyncSender<Job>,
}
fn pool() -> Result<&'static Pool, String> {
    static POOL: OnceLock<Result<Pool, String>> = OnceLock::new();
    match POOL.get_or_init(|| {
        let (sender, receiver) = mpsc::sync_channel::<Job>(QUEUED_JOBS);
        let receiver = Arc::new(Mutex::new(receiver));
        for index in 0..WORKERS {
            let receiver = receiver.clone();
            thread::Builder::new()
                .name(format!("antinomie-core-io-{index}"))
                .spawn(move || {
                    loop {
                        let job = {
                            receiver
                                .lock()
                                .unwrap_or_else(|error| error.into_inner())
                                .recv()
                        };
                        let Ok(mut job) = job else {
                            return;
                        };
                        let receipt = execute(&mut job.state, job.action);
                        // One in-flight job guarantees an empty mailbox. A
                        // disconnected receiver belongs to a sealed old owner;
                        // a full mailbox would violate the controller contract.
                        if let Err(TrySendError::Full(_)) = job.reply.try_send((job.state, receipt))
                        {
                            eprintln!("core disk receipt mailbox unexpectedly full");
                        }
                    }
                })
                .map_err(|error| format!("core disk worker: {error}"))?;
        }
        Ok(Pool { sender })
    }) {
        Ok(pool) => Ok(pool),
        Err(error) => Err(error.clone()),
    }
}
pub(super) struct Sink {
    state: Option<State>,
    receiver: Receiver<(State, Receipt)>,
    pending: bool,
    sealed: Arc<AtomicBool>,
}
impl Sink {
    pub fn new(directory: PathBuf) -> Self {
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(sender);
        let sealed = Arc::new(AtomicBool::new(false));
        Self {
            state: Some(State {
                directory,
                file: None,
                size: 0,
                digest: Sha256::new(),
                has_file: false,
                sealed: sealed.clone(),
                #[cfg(test)]
                failure: None,
                #[cfg(test)]
                gate: None,
            }),
            receiver,
            pending: false,
            sealed,
        }
    }
    pub fn pending(&self) -> bool {
        self.pending
    }
    pub fn seal(&self) {
        self.sealed.store(true, Ordering::Release);
    }
    pub fn submit(&mut self, action: Action) -> Result<bool, String> {
        if self.pending {
            return Ok(false);
        }
        if let Action::Write { data, .. } = &action
            && (data.is_empty() || data.len() > CHUNK_SIZE)
        {
            return Err("core disk chunk exceeds its bound".into());
        }
        let pool = pool()?;
        let state = self.state.take().ok_or("core sink state is missing")?;
        // Only the job owns the reply sender: a stopped worker must become an
        // observable disconnection rather than an eternally pending receipt.
        let (reply, receiver) = mpsc::sync_channel(1);
        match pool.sender.try_send(Job {
            state,
            action,
            reply,
        }) {
            Ok(()) => {
                self.receiver = receiver;
                self.pending = true;
                Ok(true)
            }
            Err(TrySendError::Full(job)) => {
                self.state = Some(job.state);
                Ok(false)
            }
            Err(TrySendError::Disconnected(job)) => {
                self.state = Some(job.state);
                Err("core disk workers disconnected".into())
            }
        }
    }
    pub fn poll(&mut self) -> Result<Option<Receipt>, String> {
        if !self.pending {
            return Ok(None);
        }
        match self.receiver.try_recv() {
            Ok((state, receipt)) => {
                self.state = Some(state);
                self.pending = false;
                Ok(Some(receipt))
            }
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => {
                self.pending = false;
                Err("core disk receipt channel disconnected".into())
            }
        }
    }
}
impl Drop for Sink {
    fn drop(&mut self) {
        self.seal();
    }
}
fn publish(state: &State, mut metadata: serde_json::Value) -> Result<(), String> {
    #[cfg(test)]
    if matches!(state.failure, Some(Failure::Publication)) {
        return Err("injected core metadata publication failure".into());
    }
    metadata["stored_size"] = state.size.into();
    metadata["sha256"] = format!("{:x}", state.digest.clone().finalize()).into();
    storage::private_dir(&state.directory).map_err(|error| format!("core directory: {error}"))?;
    storage::atomic_json(&state.directory.join("core.json"), &metadata)
}
fn write_chunk(state: &mut State, offset: u64, data: &[u8]) -> Result<(), String> {
    if offset != state.size {
        return Err("core disk write offset is not contiguous".into());
    }
    if state.file.is_none() {
        storage::private_dir(&state.directory)
            .map_err(|error| format!("core directory: {error}"))?;
        state.file = Some(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(state.directory.join("process.elf"))
                .map_err(|error| format!("core file: {error}"))?,
        );
        state.has_file = true;
    }
    let file = state.file.as_mut().ok_or("core disk file missing")?;
    let mut remaining = data;
    while !remaining.is_empty() {
        let writable = remaining;
        #[cfg(test)]
        let writable = if let Some(Failure::WriteAfter(limit)) = state.failure {
            let left = limit.saturating_sub(state.size) as usize;
            if left == 0 {
                return Err("core file write: injected ENOSPC".into());
            }
            &writable[..left.min(writable.len())]
        } else {
            writable
        };
        match file.write(writable) {
            Ok(0) => return Err("core file write made no progress".into()),
            Ok(count) => {
                state.digest.update(&remaining[..count]);
                state.size += count as u64;
                remaining = &remaining[count..];
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("core file write: {error}")),
        }
    }
    Ok(())
}
fn execute(state: &mut State, action: Action) -> Receipt {
    #[cfg(test)]
    if let Some(gate) = state.gate.take() {
        let _ = gate.recv();
    }
    let mut final_state = None;
    let mut generation = 0;
    let (kind, result) = match action {
        Action::Init { metadata } => (Kind::Init, publish(state, metadata)),
        Action::Write {
            offset,
            data,
            metadata,
        } => {
            let first = state.size == 0;
            let result = write_chunk(state, offset, &data).and_then(|()| {
                if first {
                    publish(state, metadata)
                } else {
                    Ok(())
                }
            });
            (Kind::Write, result)
        }
        Action::Finish {
            state: requested,
            generation: version,
            mut metadata,
        } => {
            generation = version;
            let sync = state
                .file
                .take()
                .map_or(Ok(()), |file| {
                    file.sync_all()
                        .map_err(|error| format!("core durability: {error}"))
                })
                .and_then(|()| storage::sync_directory_parent(&state.directory));
            #[cfg(test)]
            let sync = if matches!(state.failure, Some(Failure::Sync)) {
                Err("injected core fsync failure".into())
            } else {
                sync
            };
            let mut actual = if sync.is_err() {
                RunArtifactState::Failed
            } else if requested == RunArtifactState::Complete
                && state.sealed.load(Ordering::Acquire)
            {
                if state.size > 0 {
                    RunArtifactState::Partial
                } else {
                    RunArtifactState::Interrupted
                }
            } else {
                requested
            };
            final_state = Some(actual);
            metadata["state"] = serde_json::to_value(actual).unwrap_or(serde_json::Value::Null);
            metadata["incomplete"] = (actual != RunArtifactState::Complete).into();
            if let Err(error) = &sync {
                metadata["durability_error"] = error.clone().into();
            }
            let mut publication = publish(state, metadata.clone());
            if actual == RunArtifactState::Complete && state.sealed.load(Ordering::Acquire) {
                actual = if state.size > 0 {
                    RunArtifactState::Partial
                } else {
                    RunArtifactState::Interrupted
                };
                final_state = Some(actual);
                metadata["state"] = serde_json::to_value(actual).unwrap_or(serde_json::Value::Null);
                metadata["incomplete"] = true.into();
                publication = publication.and(publish(state, metadata));
            }
            let result = sync.and(publication);
            if result.is_err() {
                final_state = Some(RunArtifactState::Failed);
            }
            (Kind::Finish, result)
        }
        #[cfg(test)]
        Action::Hold(receiver) => (
            Kind::Hold,
            receiver.recv().map_err(|error| error.to_string()),
        ),
    };
    Receipt {
        kind,
        size: state.size,
        sha256: format!("{:x}", state.digest.clone().finalize()),
        has_file: state.has_file,
        final_state,
        generation,
        result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    fn wait(sink: &mut Sink) -> Receipt {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(receipt) = sink.poll().unwrap() {
                return receipt;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
    }
    #[test]
    fn held_disk_job_does_not_block_owner_polling_or_accept_another_chunk() {
        let mut sink = Sink::new(std::env::temp_dir().join("unused-core-poll"));
        let (release, held) = mpsc::channel();
        assert!(sink.submit(Action::Hold(held)).unwrap());
        let start = Instant::now();
        for _ in 0..1000 {
            assert!(sink.poll().unwrap().is_none());
        }
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(
            !sink
                .submit(Action::Init {
                    metadata: serde_json::json!({})
                })
                .unwrap()
        );
        release.send(()).unwrap();
        assert_eq!(wait(&mut sink).kind, Kind::Hold);
    }
    #[test]
    fn lost_worker_reply_is_failed_instead_of_pending_forever() {
        let mut sink = Sink::new(std::env::temp_dir().join("unused-core-disconnected"));
        // New sinks have no retained sender. A lost job leaves precisely this
        // disconnected mailbox instead of requiring a timeout or disk join.
        sink.pending = true;
        assert!(matches!(sink.poll(), Err(error) if error.contains("disconnected")));
        assert!(!sink.pending());
    }
    #[test]
    fn worker_reports_actual_prefix_hash_and_terminal_durability_errors() {
        let root = std::env::temp_dir().join(format!("ant-core-sink-{}", storage::unique_id()));
        let mut sink = Sink::new(root.clone());
        assert!(
            sink.submit(Action::Write {
                offset: 0,
                data: b"retained prefix".to_vec(),
                metadata: serde_json::json!({"state":"in_progress"})
            })
            .unwrap()
        );
        let written = wait(&mut sink);
        assert!(written.result.is_ok());
        assert_eq!(written.size, 15);
        assert_eq!(
            written.sha256,
            format!("{:x}", Sha256::digest(b"retained prefix"))
        );
        assert!(
            sink.submit(Action::Finish {
                state: RunArtifactState::Partial,
                generation: 3,
                metadata: serde_json::json!({})
            })
            .unwrap()
        );
        let finished = wait(&mut sink);
        assert!(finished.result.is_ok());
        assert_eq!(finished.final_state, Some(RunArtifactState::Partial));
        assert_eq!(finished.generation, 3);
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("core.json")).unwrap()).unwrap();
        assert_eq!(value["stored_size"], 15);
        assert_eq!(value["incomplete"], true);
        std::fs::remove_dir_all(&root).unwrap();
        let blocked = root.with_extension("blocked");
        std::fs::write(&blocked, b"file").unwrap();
        let mut sink = Sink::new(blocked.clone());
        assert!(
            sink.submit(Action::Init {
                metadata: serde_json::json!({})
            })
            .unwrap()
        );
        assert!(wait(&mut sink).result.is_err());
        std::fs::remove_file(blocked).unwrap();
    }
    #[test]
    fn partial_enospc_acknowledges_only_written_prefix_and_can_seal_it() {
        let root = std::env::temp_dir().join(format!("ant-core-enospc-{}", storage::unique_id()));
        let mut sink = Sink::new(root.clone());
        sink.state.as_mut().unwrap().failure = Some(Failure::WriteAfter(5));
        assert!(
            sink.submit(Action::Write {
                offset: 0,
                data: b"retained suffix".to_vec(),
                metadata: serde_json::json!({})
            })
            .unwrap()
        );
        let receipt = wait(&mut sink);
        assert!(receipt.result.unwrap_err().contains("ENOSPC"));
        assert_eq!(receipt.size, 5);
        assert_eq!(receipt.sha256, format!("{:x}", Sha256::digest(b"retai")));
        assert_eq!(std::fs::read(root.join("process.elf")).unwrap(), b"retai");
        assert!(
            sink.submit(Action::Finish {
                state: RunArtifactState::Partial,
                generation: 1,
                metadata: serde_json::json!({})
            })
            .unwrap()
        );
        let final_receipt = wait(&mut sink);
        assert!(final_receipt.result.is_ok());
        assert_eq!(final_receipt.final_state, Some(RunArtifactState::Partial));
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("core.json")).unwrap()).unwrap();
        assert_eq!(value["stored_size"], 5);
        assert_eq!(value["incomplete"], true);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn fsync_and_publication_errors_never_report_complete() {
        for failure in [Failure::Sync, Failure::Publication] {
            let root =
                std::env::temp_dir().join(format!("ant-core-durability-{}", storage::unique_id()));
            let mut sink = Sink::new(root.clone());
            assert!(
                sink.submit(Action::Write {
                    offset: 0,
                    data: b"prefix".to_vec(),
                    metadata: serde_json::json!({})
                })
                .unwrap()
            );
            assert!(wait(&mut sink).result.is_ok());
            sink.state.as_mut().unwrap().failure = Some(failure);
            assert!(
                sink.submit(Action::Finish {
                    state: RunArtifactState::Complete,
                    generation: 1,
                    metadata: serde_json::json!({})
                })
                .unwrap()
            );
            let receipt = wait(&mut sink);
            assert!(receipt.result.is_err());
            assert_eq!(receipt.size, 6);
            assert_eq!(receipt.final_state, Some(RunArtifactState::Failed));
            if matches!(failure, Failure::Sync) {
                let value: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(root.join("core.json")).unwrap())
                        .unwrap();
                assert_eq!(value["state"], "failed");
                assert_eq!(value["incomplete"], true);
            }
            std::fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn cancellation_while_write_pending_seals_prefix_without_promoting_to_complete() {
        let root = std::env::temp_dir().join(format!("ant-core-cancel-{}", storage::unique_id()));
        let mut sink = Sink::new(root.clone());
        let (release, gate) = mpsc::channel();
        sink.state.as_mut().unwrap().gate = Some(gate);
        assert!(
            sink.submit(Action::Write {
                offset: 0,
                data: b"prefix".to_vec(),
                metadata: serde_json::json!({})
            })
            .unwrap()
        );
        for _ in 0..1000 {
            assert!(sink.poll().unwrap().is_none());
        }
        sink.seal();
        release.send(()).unwrap();
        assert_eq!(wait(&mut sink).size, 6);
        assert!(
            sink.submit(Action::Finish {
                state: RunArtifactState::Complete,
                generation: 1,
                metadata: serde_json::json!({})
            })
            .unwrap()
        );
        let receipt = wait(&mut sink);
        assert!(receipt.result.is_ok());
        assert_eq!(receipt.final_state, Some(RunArtifactState::Partial));
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("core.json")).unwrap()).unwrap();
        assert_eq!(value["state"], "partial");
        assert_eq!(value["incomplete"], true);
        std::fs::remove_dir_all(root).unwrap();
    }
}
