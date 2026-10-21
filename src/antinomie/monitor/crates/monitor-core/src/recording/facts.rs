// SPDX-License-Identifier: MIT
//! The small facts a run's saved sidecars state, read without its telemetry.
use super::*;

/// Small saved-run metadata; missing values retain legacy/unfinished meaning.
#[derive(Clone, Debug, Default)]
pub struct RunFilterFacts {
    pub started_ms: Option<u64>,
    pub ended_ms: Option<u64>,
    pub saved_size: Option<u64>,
    pub has_core: Option<bool>,
    pub has_memory: Option<bool>,
    pub has_network: Option<bool>,
    pub transport_loss: Option<u64>,
    pub ui_loss: Option<u64>,
    pub storage_loss: Option<u64>,
    pub complete: Option<bool>,
    /// Working directory the root process was launched in, from the run's
    /// saved request. Absent in a manifest that does not carry the request.
    pub launch_cwd: Option<String>,
    /// The guest was asked to hash the files the run writes (and, with it,
    /// the program's own image): `tracer_hashing` in the manifest.
    pub hashed_writes: bool,
}

/// Read bounded sidecars on an archive worker; all three run identities must match.
///
/// | Argument | Meaning |
/// |---|---|
/// | `directory` | Run evidence directory, never modified. |
/// | `run_id`, `vm_id`, `boot_id` | Expected persistent identities. |
pub fn run_filter_facts(
    directory: &Path,
    run_id: &str,
    vm_id: &str,
    boot_id: &str,
) -> Result<RunFilterFacts, String> {
    let mut facts = RunFilterFacts::default();
    match archive_io::open_regular(directory, &directory.join("manifest.json")) {
        Ok(file) => {
            let mut encoded = Vec::new();
            file.take(2 * 1024 * 1024 + 1)
                .read_to_end(&mut encoded)
                .map_err(|error| error.to_string())?;
            if encoded.len() > 2 * 1024 * 1024 {
                return Err("run manifest exceeds metadata bound".into());
            }
            let manifest: serde_json::Value =
                serde_json::from_slice(&encoded).map_err(|error| error.to_string())?;
            let run = manifest
                .get("run")
                .ok_or("run manifest identity unavailable")?;
            for (key, expected) in [("id", run_id), ("vm_id", vm_id), ("boot_id", boot_id)] {
                if run.get(key).and_then(serde_json::Value::as_str) != Some(expected) {
                    return Err("run manifest identity mismatch".into());
                }
            }
            facts.started_ms = manifest
                .get("started_ms")
                .and_then(serde_json::Value::as_u64);
            facts.ended_ms = manifest.get("ended_ms").and_then(serde_json::Value::as_u64);
            facts.launch_cwd = run
                .get("request")
                .and_then(|request| request.get("cwd"))
                .and_then(serde_json::Value::as_str)
                .filter(|cwd| cwd.starts_with('/'))
                .map(str::to_owned);
            facts.saved_size = manifest.get("bytes").and_then(serde_json::Value::as_u64);
            facts.hashed_writes = manifest
                .get("tracer_hashing")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|flags| flags & u64::from(crate::control::EXEC_HASH_WRITES) != 0);
            if facts
                .started_ms
                .zip(facts.ended_ms)
                .is_some_and(|(start, end)| end < start)
            {
                return Err("run completion timestamp precedes start".into());
            }
            let health = manifest.get("health");
            facts.transport_loss = health
                .and_then(|health| health.get("dropped"))
                .and_then(serde_json::Value::as_u64);
            facts.ui_loss = health
                .and_then(|health| health.get("ui_dropped"))
                .and_then(serde_json::Value::as_u64);
            facts.storage_loss = health
                .and_then(|health| health.get("storage_dropped_packets"))
                .and_then(serde_json::Value::as_u64);
            facts.complete = run
                .get("execution")
                .and_then(|execution| execution.get("flags"))
                .and_then(serde_json::Value::as_u64)
                .zip(
                    manifest
                        .get("terminal_complete")
                        .and_then(serde_json::Value::as_bool),
                )
                .map(|(flags, terminal_complete)| {
                    // Dropped on-screen previews (`ui_loss`) lose nothing from the
                    // recording, so they never make a run incomplete.
                    flags & 2 != 0
                        && terminal_complete
                        && manifest
                            .get("persistence_error")
                            .is_none_or(serde_json::Value::is_null)
                        && run
                            .get("recording_error")
                            .is_none_or(serde_json::Value::is_null)
                        && facts.transport_loss == Some(0)
                        && facts.storage_loss == Some(0)
                });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    if let Some(artifacts) = crate::RunArtifacts::load(directory)? {
        if artifacts.run_id != run_id || artifacts.vm_id != vm_id || artifacts.boot_id != boot_id {
            return Err("run artifact identity mismatch".into());
        }
        facts.has_core = Some(artifacts.core_dump.is_some());
        facts.has_memory = Some(artifacts.memory_dump.is_some());
        facts.has_network = Some(!artifacts.network_captures.is_empty());
    }
    Ok(facts)
}
