// SPDX-License-Identifier: GPL-3.0-only
//! `recording.run.list` and `recording.run.get` (design 5.12.3, `RunInfo`,
//! `RunDetail`): the recorded runs of every VM of the data directory, newest
//! first, read without the lock and without writing into a run folder.

use super::{
    cursor::{Cursor, CursorBinding, Generation, stable_hash},
    key::RunKey,
    page::{Page, Single},
    phase::detect,
    request::{RunFilter, RunParams},
    service::{Opened, QueryService, state_name},
    types::*,
};
use crate::api::{error::ApiError, ids::Sha256Hex, job::RecordingPhase, spec::Route};
use antinomie_monitor_core::{
    RunState, RunSummary, WaitStatus,
    recording::{list_runs_read_only, run_filter_facts},
    route::RouteKind,
};

/// One run of the listing, before its page is cut.
struct Row {
    key: RunKey,
    run: RunSummary,
    phase: RecordingPhase,
    state: RunStateName,
}

pub(super) fn route_of(kind: RouteKind) -> Route {
    match kind {
        RouteKind::Drop => Route::Drop,
        RouteKind::Internet => Route::Internet,
        RouteKind::InetSim => Route::InetSim,
        RouteKind::Tor => Route::Tor,
        RouteKind::Vpn => Route::Vpn,
        RouteKind::Socks5 => Route::Socks5,
    }
}

fn exit_of(status: &WaitStatus) -> RunExit {
    match status {
        WaitStatus::Exited { code } => RunExit {
            kind: RunExitKind::Exited,
            code: i32::from(*code),
        },
        WaitStatus::Signaled { signal, .. } => RunExit {
            kind: RunExitKind::Signaled,
            code: i32::from(*signal),
        },
    }
}

impl QueryService {
    /// The `RunInfo` of a run in `phase`. `ended_ms` is read from the run's
    /// manifest, which costs a file read, so the list does it per page item.
    fn run_info(
        &self,
        key: &RunKey,
        run: &RunSummary,
        phase: RecordingPhase,
        state: RunStateName,
    ) -> RunInfo {
        let facts = run_filter_facts(&run.directory, &run.id, &run.vm_id, &run.boot_id).ok();
        RunInfo {
            run_key: key.clone(),
            vm_id: run.vm_id.clone(),
            boot_id: run.boot_id.clone(),
            run_id: run.id.clone(),
            state,
            phase,
            started_ms: run.started_ms,
            ended_ms: facts.and_then(|facts| facts.ended_ms),
            sample_sha256: run
                .request
                .sample
                .as_ref()
                .and_then(|sample| Sha256Hex::try_from(sample.sha256.clone()).ok()),
            program: self.scrub.text(&run.request.path),
            job_id: self
                .jobs
                .as_ref()
                .and_then(|jobs| jobs.job_of_run(&run.vm_id, &run.boot_id, &run.id)),
            route: run.route.as_ref().map(|route| route_of(route.kind)),
            exit: run
                .execution
                .as_ref()
                .and_then(|execution| execution.root_exit.as_ref())
                .map(exit_of),
            end_reason: run
                .recording_error
                .as_deref()
                .map(|text| self.scrub.text(text)),
            held: antinomie_triage::run_state::held(run),
        }
    }

    /// Every run of every VM that passes the filter, newest first.
    fn listed_runs(&self, filter: &RunFilter) -> Result<Vec<Row>, ApiError> {
        let snapshot = self.snapshot();
        let mut rows = Vec::new();
        for location in self.locations()? {
            if filter
                .vm_id
                .as_ref()
                .is_some_and(|vm| *vm != location.vm_id)
            {
                continue;
            }
            // One VM that cannot be read must not hide the others.
            let Ok(runs) = list_runs_read_only(&location) else {
                continue;
            };
            for run in runs {
                let Ok(key) = RunKey::new(&run.vm_id, &run.boot_id, &run.id) else {
                    continue;
                };
                let phase = detect(
                    &location.disk_directory,
                    &run.vm_id,
                    &run.boot_id,
                    run.state == RunState::Interrupted,
                    snapshot.as_deref(),
                )
                .phase;
                let mut state = state_name(&run.state);
                if state == RunStateName::Interrupted && phase == RecordingPhase::Live {
                    state = RunStateName::Running;
                }
                rows.push(Row {
                    key,
                    run,
                    phase,
                    state,
                });
            }
        }
        rows.retain(|row| self.passes(filter, row));
        rows.sort_by(|a, b| {
            b.run
                .started_ms
                .cmp(&a.run.started_ms)
                .then_with(|| a.key.cmp(&b.key))
        });
        Ok(rows)
    }

    fn passes(&self, filter: &RunFilter, row: &Row) -> bool {
        if filter.state.is_some_and(|state| state != row.state) {
            return false;
        }
        if filter
            .since_ms
            .is_some_and(|since| row.run.started_ms.is_none_or(|started| started < since))
        {
            return false;
        }
        if let Some(sha) = &filter.sample_sha256
            && row.run.request.sample.as_ref().map(|s| s.sha256.as_str()) != Some(sha.as_str())
        {
            return false;
        }
        if let Some(job) = &filter.job_id {
            let found = self
                .jobs
                .as_ref()
                .and_then(|jobs| jobs.job_of_run(&row.run.vm_id, &row.run.boot_id, &row.run.id));
            if found.as_ref() != Some(job) {
                return false;
            }
        }
        true
    }

    /// `recording.run.list`.
    pub(super) fn run_list_page(&self, filter: &RunFilter) -> Result<Page<RunInfo>, ApiError> {
        let (default, max) = self.settings.rows();
        let request = super::page::PageRequest {
            limit: filter.limit,
            cursor: filter.cursor.clone(),
        };
        let limit = request.effective_limit(default, max)? as usize;
        let rows = self.listed_runs(filter)?;
        // The list's generation is its content: a new run in front shifts
        // every offset, so a cursor from before is stale.
        let listing: Vec<(&str, RunStateName, RecordingPhase)> = rows
            .iter()
            .map(|row| (row.key.as_str(), row.state, row.phase))
            .collect();
        let generation = Generation(stable_hash(&listing));
        let mut filter_only = filter.clone();
        filter_only.limit = None;
        filter_only.cursor = None;
        let binding = CursorBinding {
            generation,
            filter_hash: stable_hash(&filter_only),
            sort_hash: stable_hash(&serde_json::Value::Null),
        };
        let start = match &request.cursor {
            Some(text) => Cursor::resume(text, binding)? as usize,
            None => 0,
        };
        let total = rows.len();
        let end = (start + limit).min(total);
        let items: Vec<RunInfo> = rows
            .get(start..end)
            .unwrap_or_default()
            .iter()
            .map(|row| self.run_info(&row.key, &row.run, row.phase, row.state))
            .collect();
        // A list has no one phase: it is `live` while any run on it is.
        let phase = if rows.iter().any(|row| row.phase == RecordingPhase::Live) {
            RecordingPhase::Live
        } else {
            RecordingPhase::Complete
        };
        let mut page = Page::new(items, generation, phase);
        page.next_cursor = (end < total).then(|| {
            Cursor {
                offset: end as u64,
                binding,
            }
            .encode()
        });
        page.total = Some(total as u64);
        page.total_exact = Some(phase != RecordingPhase::Live);
        page.untrusted = Some(true);
        Ok(page)
    }

    /// `recording.run.get`.
    pub(super) fn run_detail(&self, params: &RunParams) -> Result<Single<RunDetail>, ApiError> {
        let opened = self.open_run(&params.run_key)?;
        let detail = self.detail_of(&opened);
        Ok(opened.single(detail, true))
    }

    fn detail_of(&self, opened: &Opened) -> RunDetail {
        let run = &opened.run;
        let info = self.run_info(&opened.key, run, opened.phase.phase, opened.state());
        let scrubbed = |value: Option<serde_json::Value>| {
            value.map(|mut value| {
                self.scrub.value(&mut value);
                value
            })
        };
        let artifacts = artifact_states(&opened.dir);
        RunDetail {
            info,
            execution: run.execution.as_ref().map(|execution| Execution {
                live_task_count: execution.live_task_count,
                pending_async_count: execution.pending_async_count,
                total_task_count: execution.total_task_count,
                async_loss_count: execution.async_loss_count,
                root_wait_status: execution.root_wait_status,
                root_exit: execution.root_exit.as_ref().map(exit_of),
            }),
            notes: run
                .notes
                .iter()
                .map(|note| self.scrub.text(antinomie_monitor_core::run_note_text(note)))
                .collect(),
            route_record: scrubbed(
                run.route
                    .as_ref()
                    .and_then(|v| serde_json::to_value(v).ok()),
            ),
            machine: scrubbed(
                run.machine
                    .as_ref()
                    .and_then(|v| serde_json::to_value(v).ok()),
            ),
            environment: scrubbed(
                run.environment
                    .as_ref()
                    .and_then(|v| serde_json::to_value(v).ok()),
            ),
            artifacts,
            generation: opened.generation,
            owner_state: opened.phase.owner,
            layer: opened.phase.layer,
            recording_error: run
                .recording_error
                .as_deref()
                .map(|text| self.scrub.text(text)),
            // L: the folder is never sent by the service; a local CLI that
            // owns the directory knows it already.
            directory: None,
        }
    }
}

fn state_of(state: antinomie_monitor_core::RunArtifactState) -> ArtifactState {
    use antinomie_monitor_core::RunArtifactState as S;
    match state {
        S::Disabled => ArtifactState::Disabled,
        S::WaitingForTreeExit => ArtifactState::WaitingForTreeExit,
        S::WaitingForRootExit => ArtifactState::WaitingForRootExit,
        S::Recording => ArtifactState::Recording,
        S::Queued => ArtifactState::Queued,
        S::InProgress => ArtifactState::InProgress,
        S::Complete => ArtifactState::Complete,
        S::Partial => ArtifactState::Partial,
        S::Interrupted => ArtifactState::Interrupted,
        S::Failed => ArtifactState::Failed,
    }
}

pub(super) fn artifact_status(
    state: antinomie_monitor_core::RunArtifactState,
    present: bool,
) -> ArtifactStatus {
    ArtifactStatus {
        state: state_of(state),
        present,
    }
}

/// `{network, memory, core}` from `artifacts.json`; a run that kept none reads
/// as three disabled kinds.
fn artifact_states(dir: &std::path::Path) -> RunArtifactStates {
    use antinomie_monitor_core::RunArtifactState::Disabled;
    let artifacts = antinomie_monitor_core::RunArtifacts::load(dir)
        .ok()
        .flatten();
    match artifacts {
        Some(a) => RunArtifactStates {
            network: artifact_status(
                a.network_state,
                !a.network_captures.is_empty() && !a.network_deleted,
            ),
            memory: artifact_status(a.memory_state, a.memory_dump.is_some()),
            core: artifact_status(a.core_state, a.core_dump.is_some() && !a.core_deleted),
        },
        None => RunArtifactStates {
            network: artifact_status(Disabled, false),
            memory: artifact_status(Disabled, false),
            core: artifact_status(Disabled, false),
        },
    }
}
