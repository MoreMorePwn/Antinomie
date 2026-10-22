// SPDX-License-Identifier: GPL-3.0-only
//! Streaming uploads into the guest and guest-scoped command checks.
use super::*;

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
