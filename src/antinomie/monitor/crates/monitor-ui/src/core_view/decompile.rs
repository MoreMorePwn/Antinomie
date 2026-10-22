// SPDX-License-Identifier: GPL-3.0-only
//! Ghidra decompilation of a core and its saved results.
use super::*;

impl CoreView {
    pub(super) fn ghidra_button(&mut self, ui: &mut egui::Ui, record: &CoreRecord) {
        if self.decompile_active {
            if ui.button("Cancel").clicked() {
                self.cancel_decompile();
            }
            return;
        }
        if ui
            .add_enabled(
                self.job.is_none(),
                egui::Button::new("Decompile with Ghidra"),
            )
            .clicked()
        {
            self.decompile_core(record);
        }
    }

    fn cancel_decompile(&mut self) {
        self.ghidra_cancel.store(true, Ordering::SeqCst);
        let pid = self.ghidra_pid.swap(0, Ordering::SeqCst);
        if pid > 0 {
            signal_process_group(pid);
            reap_child(pid);
        }
        self.decompile_active = false;
        self.status = DECOMPILE_CANCELLED.into();
    }

    fn decompile_core(&mut self, record: &CoreRecord) {
        if self.job.is_some() {
            return;
        }
        if let Err(error) = write_ghidra_mappings(&record.dir, &record.core.mappings) {
            self.fail(error);
            return;
        }
        self.ghidra_cancel.store(false, Ordering::SeqCst);
        let source = record.core.source.clone();
        let dir = record.dir.clone();
        let tools_dir = self.tools_dir.clone();
        let pid = Arc::clone(&self.ghidra_pid);
        let cancel = Arc::clone(&self.ghidra_cancel);
        self.decompile_active = true;
        self.start(move || {
            ghidra_decompile(&source, &dir, &tools_dir, &pid, &cancel).map(Reply::Decompiled)
        });
        if self.job.is_none() {
            self.decompile_active = false;
        }
    }
}

/// Load `decompiled.txt` from this record's directory only when a function marker is present.
pub(super) fn saved_decompilation(dir: &Path) -> Option<String> {
    let path = dir.join("decompiled.txt");
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() => {}
        _ => return None,
    }
    let text = fs::read_to_string(&path).ok()?;
    text.lines()
        .any(|line| line.starts_with("@@ANTINOMIE-FUNCTION"))
        .then_some(text)
}

pub(super) fn export_saved_functions(dir: &Path) -> Result<PathBuf, String> {
    let source = dir.join("decompiled.txt");
    let text = fs::read_to_string(&source).map_err(|error| error.to_string())?;
    if crate::analysis::index_ghidra_markers(&text).is_empty() {
        return Err("this result has no saved Ghidra function markers".into());
    }
    let exported = crate::analysis::export_ghidra_text(&text);
    let destination = dir.join("function-export.txt");
    fs::write(&destination, exported).map_err(|error| error.to_string())?;
    Ok(destination)
}

pub(super) fn parse_ghidra(text: &str) -> (Vec<CoreFunction>, Vec<String>) {
    let mut functions = Vec::new();
    let mut bodies = Vec::new();
    let mut current = String::new();
    let mut open = false;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("@@ANTINOMIE-FUNCTION\t") {
            if open {
                bodies.push(std::mem::take(&mut current));
            }
            open = true;
            let mut parts = rest.split('\t');
            let address = parts
                .next()
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let size = parts
                .next()
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let name = parts.next().unwrap_or("FUN").to_string();
            functions.push(CoreFunction {
                address,
                size,
                name,
            });
        } else if open && !line.starts_with("@@ANTINOMIE-") {
            current.push_str(line);
            current.push('\n');
        }
    }
    if open {
        bodies.push(current);
    }
    (functions, bodies)
}

/// Record each mapping's declared and captured extents. Holes stay absent;
/// this file is not a zero-padded image of `memory_size`.
pub(super) fn write_ghidra_mappings(dir: &Path, mappings: &[CoreMapping]) -> Result<(), String> {
    let mut text = String::new();
    for mapping in mappings {
        text.push_str(&format!(
            "{:x} {} {} {} {}\n",
            mapping.start,
            mapping.memory_size,
            mapping.captured_size,
            mapping.available_size,
            mapping.permissions()
        ));
    }
    fs::write(dir.join("ghidra-mappings.txt"), text).map_err(|error| error.to_string())
}

fn ghidra_decompile(
    core: &Path,
    dir: &Path,
    tools_dir: &Path,
    _pid_slot: &AtomicI32,
    cancel: &AtomicBool,
) -> Result<String, String> {
    // The analysis job owns analyzeHeadless. This thread only starts that job
    // and watches cancel. A mappings file is not passed and is not a result.
    match antinomie_monitor_core::decompile_captured_core(core, dir, tools_dir, cancel) {
        Err(error) if error == "cancelled" || cancel.load(Ordering::SeqCst) => {
            Err(DECOMPILE_CANCELLED.into())
        }
        other => other,
    }
}

#[cfg(test)]
pub(super) fn accept_ghidra_export(
    success: bool,
    export: &Path,
    previous_modified: Option<std::time::SystemTime>,
) -> Result<String, String> {
    if !success {
        return Err("Ghidra decompilation failed; an existing export is not a result.".to_string());
    }
    let metadata =
        fs::metadata(export).map_err(|_| "Ghidra produced no decompilation.".to_string())?;
    if let Some(previous) = previous_modified {
        let modified = metadata
            .modified()
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        if modified <= previous {
            return Err(
                "Ghidra produced no decompilation for this run; refusing an older export."
                    .to_string(),
            );
        }
    }
    fs::read_to_string(export).map_err(|error| format!("Ghidra produced no decompilation. {error}"))
}

const DECOMPILE_CANCELLED: &str = "The decompile was cancelled.";

pub(super) fn signal_process_group(pid: i32) {
    if pid > 0 {
        unsafe {
            kill(-pid, 9);
        }
    }
}

pub(super) fn reap_child(pid: i32) {
    if pid <= 0 {
        return;
    }
    let mut status = 0;
    loop {
        let result = unsafe { waitpid(pid, &mut status, 0) };
        if result >= 0 {
            return;
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(4) {
            return;
        }
    }
}
