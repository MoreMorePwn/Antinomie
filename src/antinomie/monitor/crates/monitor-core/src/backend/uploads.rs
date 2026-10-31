// SPDX-License-Identifier: GPL-3.0-only
//! Streaming uploads into the guest and guest-scoped command checks.
use super::*;

/// The note an executable upload's result carries when the program is for
/// another architecture than the running guest's (empty otherwise).
pub(super) fn arch_note(snapshot: &Snapshot, program: &[u8], executable: bool) -> String {
    let arch = snapshot
        .guest_kernel
        .as_ref()
        .map(|kernel| kernel.arch)
        .unwrap_or_default();
    match executable.then(|| arch.elf_mismatch(program)).flatten() {
        Some(note) => format!(" (note: {note})"),
        None => String::new(),
    }
}

/// Send `total` bytes from `source` to a new guest file through the upload
/// protocol; `target` is the guest path, overwrite and executable.
#[allow(clippy::too_many_arguments)]
pub(super) fn upload_stream(
    session: &mut Session,
    snapshot: &mut Snapshot,
    sender: &SyncSender<Notification>,
    stopping: &AtomicBool,
    timeout: Duration,
    source: &mut dyn Read,
    total: u64,
    (destination, overwrite, executable): (&str, bool, bool),
) -> Result<String, String> {
    let reply = session.request(
        control::UPLOAD_BEGIN,
        &control::upload_begin(destination, total, overwrite, executable)?,
        snapshot,
        sender,
        timeout,
    )?;
    if reply.len() != 8 {
        return Err("invalid upload begin reply".into());
    }
    let upload = u64_at(&reply, 0).map_err(|e| e.to_string())?;
    upload_contents(
        session,
        snapshot,
        sender,
        stopping,
        timeout,
        source,
        total,
        destination,
        upload,
    )
}

/// An executable upload is a program the guest may run and analyse, and the
/// guest keeps one copy of an analysed program in its memory: one larger
/// than a quarter of the VM's RAM is refused before anything is sent.
pub(super) fn check_program_size(total: u64, executable: bool, ram_mib: u32) -> Result<(), String> {
    let bound = control::specimen_ram_bound(ram_mib);
    if executable && total > bound {
        return Err(format!(
            "The program is {} and this VM has {ram_mib} MiB of RAM: a program to run and \
             analyse may be at most a quarter of the VM's RAM ({}), because the guest keeps a \
             copy of it in memory. Give the VM at least {} MiB of RAM in its settings (stop it \
             first), then upload it again.",
            crate::byte_size::short_size(total),
            crate::byte_size::short_size(bound),
            total.div_ceil(1 << 18).div_ceil(256) * 256,
        ));
    }
    Ok(())
}

/// Continue only an acknowledged Upload Begin; failures abort the owned transfer.
#[allow(clippy::too_many_arguments)]
pub(super) fn upload_contents(
    session: &mut Session,
    snapshot: &mut Snapshot,
    sender: &SyncSender<Notification>,
    stopping: &AtomicBool,
    timeout: Duration,
    source: &mut dyn Read,
    total: u64,
    destination: &str,
    upload: u64,
) -> Result<String, String> {
    let result = (|| -> Result<(), String> {
        let chunk_size = session
            .transport
            .command_limit
            .saturating_sub(24)
            .min(64 * 1024);
        if chunk_size == 0 {
            return Err("transport has no upload payload capacity".into());
        }
        let mut chunk = vec![0; chunk_size];
        let mut offset = 0u64;
        while offset < total {
            if stopping.load(Ordering::Relaxed) {
                return Err("upload aborted for VM shutdown; partial destination remains".into());
            }
            let used = usize::try_from((total - offset).min(chunk_size as u64))
                .map_err(|_| "upload size overflow")?;
            source
                .read_exact(&mut chunk[..used])
                .map_err(|e| e.to_string())?;
            let mut args = control::with_session(upload);
            args.extend(offset.to_le_bytes());
            args.extend(&chunk[..used]);
            let reply = session.request(control::UPLOAD_CHUNK, &args, snapshot, sender, timeout)?;
            if reply.len() != 8 || u64_at(&reply, 0).map_err(|e| e.to_string())? != used as u64 {
                return Err("guest reported a partial upload write".into());
            }
            offset += used as u64;
        }
        session.request(
            control::UPLOAD_COMMIT,
            &control::with_session(upload),
            snapshot,
            sender,
            timeout,
        )?;
        Ok(())
    })();
    if let Err(e) = result {
        let abort = session.request(
            control::UPLOAD_ABORT,
            &control::with_session(upload),
            snapshot,
            sender,
            Duration::from_secs(2),
        );
        return Err(match abort {
            Ok(_) => e,
            Err(a) => format!("{e}; abort failed: {a}"),
        });
    }
    Ok(format!("uploaded {total} bytes to {destination}"))
}

pub(super) fn guest_scoped_command(command: &Command) -> bool {
    matches!(
        command,
        Command::Upload { .. }
            | Command::TypeClipboard { .. }
            | Command::UploadSample { .. }
            | Command::Execute(_)
            | Command::CancelProcessCore { .. }
            | Command::DumpProcessCore { .. }
            | Command::CancelCoreCapture { .. }
            | Command::AnalyzeOnly { .. }
            | Command::TerminalInput { .. }
            | Command::TerminalRead { .. }
            | Command::TerminalResize { .. }
            | Command::TerminalSnapshot { .. }
            | Command::Signal { .. }
            | Command::StopRun { .. }
            | Command::RecorderStats
            | Command::ListProcesses { .. }
            | Command::AttachProcess { .. }
            | Command::CaptureAll
            | Command::StopCapture { .. }
            | Command::DebugAttach { .. }
            | Command::DebugDetach { .. }
            | Command::DebugUi(_)
            | Command::StartNetworkCapture
            | Command::StopNetworkCapture
    )
}

pub(super) fn validate_snapshot_command(command: &Command) -> Result<(), String> {
    let request = match command {
        Command::CreateVmSnapshot { request, .. } => Some(request),
        Command::RestoreVmSnapshot { save_current, .. } => save_current.as_ref(),
        _ => None,
    };
    if let Some(request) = request
        && (request.name.trim().is_empty()
            || request.name.len() > 128
            || request.name.chars().any(char::is_control)
            || request.description.len() > 4096)
    {
        return Err("snapshot name/description exceeds supported bounds".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::check_program_size;

    #[test]
    fn a_program_over_a_quarter_of_the_vms_ram_is_refused_before_it_is_sent() {
        let mib = 1u64 << 20;
        // 2 GiB of RAM: programs up to 512 MiB; any plain file passes.
        assert!(check_program_size(512 * mib, true, 2048).is_ok());
        assert!(check_program_size(600 * mib, false, 2048).is_ok());
        let error = check_program_size(96 * mib, true, 256).unwrap_err();
        assert!(error.contains("256 MiB of RAM"), "{error}");
        assert!(error.contains("quarter of the VM's RAM"), "{error}");
        // 96 MiB needs 384 MiB, offered in 256 MiB steps.
        assert!(error.contains("at least 512 MiB"), "{error}");
        assert!(check_program_size(64 * mib, true, 256).is_ok());
        assert!(check_program_size(64 * mib + 1, true, 256).is_err());
    }
}
