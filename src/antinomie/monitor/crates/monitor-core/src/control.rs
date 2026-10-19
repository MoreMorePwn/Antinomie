use crate::api::ExecRequest;
pub(crate) const UPLOAD_BEGIN: u32 = 0x1001;
pub(crate) const UPLOAD_CHUNK: u32 = 0x1002;
pub(crate) const UPLOAD_COMMIT: u32 = 0x1003;
pub(crate) const UPLOAD_ABORT: u32 = 0x1004;
pub(crate) const EXEC: u32 = 0x1010;
pub(crate) const INPUT: u32 = 0x1011;
pub(crate) const READ: u32 = 0x1012;
pub(crate) const RESIZE: u32 = 0x1013;
pub(crate) const SIGNAL: u32 = 0x1014;
pub(crate) const RUN_STATUS: u32 = 0x1016;
pub(crate) const STATS: u32 = 0x1020;
pub(crate) const INFO: u32 = 0x1021;
pub(crate) const INFO_SIZE: usize = 160;
pub(crate) const SHUTDOWN: u32 = 0x1030;
pub(crate) const RESOURCES: u32 = 0x1070;
pub(crate) const RESOURCES_SIZE: usize = 96;
/// Guest contract revision this host implements (`ANTC_REVISION`).
pub const REVISION: u32 = 17;
pub(crate) const PROCESS_LIST: u32 = 0x1050;
pub(crate) const CAPTURE_ATTACH: u32 = 0x1051;
pub(crate) const CAPTURE_ALL: u32 = 0x1052;
pub(crate) const CAPTURE_STOP: u32 = 0x1053;
pub(crate) const CAPTURE_STATUS: u32 = 0x1054;
pub(crate) const CORE_CAPTURE: u32 = 0x1063;
pub(crate) const CORE_LOOKUP: u32 = 0x1064;
pub(crate) const CORE_CANCEL: u32 = 0x1065;
pub(crate) fn core_capture(
    request: &crate::api::ProcessCoreRequest,
    nonce: [u64; 2],
) -> Result<Vec<u8>, String> {
    crate::core_capture::validate_request(request)?;
    let mut args = header(0);
    args.extend(request.target.task_cookie.to_le_bytes());
    args.extend(request.target.start_boot_ns.to_le_bytes());
    args.extend(request.target.tgid.to_le_bytes());
    args.extend(request.max_size.to_le_bytes());
    args.extend(request.timeout_ms.to_le_bytes());
    args.extend(1u32.to_le_bytes());
    args.extend(nonce[0].to_le_bytes());
    args.extend(nonce[1].to_le_bytes());
    Ok(args)
}
pub(crate) fn core_lookup(
    identity: &crate::observation::GuestProcessIdentity,
    nonce: [u64; 2],
) -> Vec<u8> {
    let mut args = header(0);
    args.extend(identity.task_cookie.to_le_bytes());
    args.extend(identity.start_boot_ns.to_le_bytes());
    args.extend(identity.tgid.to_le_bytes());
    args.extend(0u32.to_le_bytes());
    args.extend(nonce[0].to_le_bytes());
    args.extend(nonce[1].to_le_bytes());
    args
}
pub(crate) const ACQUIRE: u32 = 0x1040;
pub(crate) const SPECIMEN_READ: u32 = 0x1041;
pub(crate) const SPECIMEN_RELEASE: u32 = 0x1042;
pub(crate) const SPECIMEN_MAX_SIZE: u32 = 64 * 1024 * 1024;
pub(crate) const SPECIMEN_CHUNK_SIZE: u32 = 16328;
pub(crate) fn header(flags: u32) -> Vec<u8> {
    let mut v = vec![1, 0, 8, 0];
    v.extend(flags.to_le_bytes());
    v
}
pub(crate) fn string(s: &str, absolute: bool) -> Result<(), String> {
    if s.contains('\0') || (absolute && !s.starts_with('/')) {
        Err("guest paths must be absolute and strings cannot contain NUL".into())
    } else {
        Ok(())
    }
}
pub(crate) fn upload_begin(
    path: &str,
    total: u64,
    overwrite: bool,
    executable: bool,
) -> Result<Vec<u8>, String> {
    string(path, true)?;
    let len = u32::try_from(path.len()).map_err(|_| "upload path too long")?;
    let mut v = header(u32::from(overwrite) | (u32::from(executable) * 2));
    v.extend(total.to_le_bytes());
    v.extend(len.to_le_bytes());
    v.extend(0u32.to_le_bytes());
    v.extend(path.as_bytes());
    Ok(v)
}
pub(crate) fn with_session(session: u64) -> Vec<u8> {
    let mut v = header(0);
    v.extend(session.to_le_bytes());
    v
}
pub(crate) fn process_list(after_pid: u32) -> Vec<u8> {
    let mut args = header(0);
    args.extend(after_pid.to_le_bytes());
    args.extend(crate::observation::PROCESS_PAGE_MAX_COUNT.to_le_bytes());
    args
}
pub(crate) fn attach_process(
    identity: &crate::observation::GuestProcessIdentity,
) -> Result<Vec<u8>, String> {
    if identity.task_cookie == 0 || identity.tgid == 0 {
        return Err("process identity must contain a nonzero task cookie and PID".into());
    }
    let mut args = header(0);
    args.extend(identity.task_cookie.to_le_bytes());
    args.extend(identity.start_boot_ns.to_le_bytes());
    args.extend(identity.tgid.to_le_bytes());
    args.extend(0u32.to_le_bytes());
    Ok(args)
}
pub(crate) fn process_page(
    reply: &[u8],
    boot_id: &str,
    after_pid: u32,
) -> Result<crate::observation::GuestProcessPage, String> {
    use crate::{
        observation::*,
        parser::{u32_at, u64_at},
    };
    if reply.len() < 16 {
        return Err("truncated process list reply".into());
    }
    let stream = u64_at(reply, 0).map_err(|error| error.to_string())?;
    let count = u32_at(reply, 8).map_err(|error| error.to_string())?;
    let next_pid = u32_at(reply, 12).map_err(|error| error.to_string())?;
    if stream == 0 || count > PROCESS_PAGE_MAX_COUNT || reply.len() != 16 + count as usize * 64 {
        return Err("invalid process list stream, count or length".into());
    }
    let mut processes = Vec::with_capacity(count as usize);
    let mut prior_pid = after_pid;
    for entry in reply[16..].as_chunks::<64>().0 {
        let cookie = u64_at(entry, 0).map_err(|error| error.to_string())?;
        let tgid = u32_at(entry, 16).map_err(|error| error.to_string())?;
        let thread_count = u32_at(entry, 32).map_err(|error| error.to_string())?;
        let end = entry[40..56]
            .iter()
            .position(|&byte| byte == 0)
            .ok_or("process command is not terminated")?;
        if cookie == 0
            || tgid <= prior_pid
            || thread_count == 0
            || entry[36..40]
                .iter()
                .chain(entry[56..].iter())
                .any(|&byte| byte != 0)
        {
            return Err("invalid process entry identity, ordering or padding".into());
        }
        processes.push(GuestProcess {
            identity: GuestProcessIdentity {
                boot_id: boot_id.into(),
                task_cookie: cookie,
                tgid,
                start_boot_ns: u64_at(entry, 8).map_err(|error| error.to_string())?,
            },
            parent_tgid: u32_at(entry, 20).map_err(|error| error.to_string())?,
            uid: u32_at(entry, 24).map_err(|error| error.to_string())?,
            gid: u32_at(entry, 28).map_err(|error| error.to_string())?,
            thread_count,
            command: String::from_utf8_lossy(&entry[40..40 + end]).into_owned(),
        });
        prior_pid = tgid;
    }
    if next_pid != 0 && (count == 0 || next_pid != prior_pid) {
        return Err("invalid process page continuation".into());
    }
    Ok(GuestProcessPage {
        boot_id: boot_id.into(),
        after_pid,
        next_pid,
        processes,
    })
}
pub(crate) fn capture_started(reply: &[u8]) -> Result<(u64, u64), String> {
    use crate::parser::u64_at;
    if reply.len() != 16 {
        return Err("invalid capture start reply length".into());
    }
    let cookie = u64_at(reply, 0).map_err(|error| error.to_string())?;
    let stream = u64_at(reply, 8).map_err(|error| error.to_string())?;
    if cookie == 0 || stream == 0 {
        return Err("invalid capture start identity".into());
    }
    Ok((cookie, stream))
}
pub(crate) struct CaptureStatus {
    pub cookie: u64,
    pub active: bool,
    pub mode: u32,
    pub start_ns: u64,
    pub stop_ns: u64,
}
pub(crate) fn capture_status(reply: &[u8], expected: u64) -> Result<CaptureStatus, String> {
    use crate::parser::{u32_at, u64_at};
    if reply.len() != 32 {
        return Err("invalid capture status reply length".into());
    }
    let cookie = u64_at(reply, 0).map_err(|error| error.to_string())?;
    if cookie == 0 {
        if expected != 0 || reply.iter().any(|&byte| byte != 0) {
            return Err("invalid empty capture status".into());
        }
        return Ok(CaptureStatus {
            cookie,
            active: false,
            mode: 0,
            start_ns: 0,
            stop_ns: 0,
        });
    }
    let flags = u32_at(reply, 8).map_err(|error| error.to_string())?;
    let mode = u32_at(reply, 12).map_err(|error| error.to_string())?;
    let start_ns = u64_at(reply, 16).map_err(|error| error.to_string())?;
    let stop_ns = u64_at(reply, 24).map_err(|error| error.to_string())?;
    if (expected != 0 && cookie != expected)
        || flags & !7 != 0
        || !matches!(flags & 3, 1 | 2)
        || !matches!(mode, 1 | 2)
        || (flags & 1 != 0 && stop_ns != 0)
        || (flags & 2 != 0 && stop_ns < start_ns)
    {
        return Err("invalid capture status identity, flags, mode or timestamps".into());
    }
    Ok(CaptureStatus {
        cookie,
        active: flags & 1 != 0,
        mode,
        start_ns,
        stop_ns,
    })
}
pub(crate) fn execute(r: &ExecRequest) -> Result<Vec<u8>, String> {
    string(&r.path, true)?;
    string(&r.cwd, true)?;
    if r.args.len() > 4095 || r.env.len() > 4096 {
        return Err("too many launch arguments or environment entries".into());
    }
    let mut v = header(0);
    v.extend(r.uid.to_le_bytes());
    v.extend(r.gid.to_le_bytes());
    v.extend((r.args.len() as u32 + 1).to_le_bytes());
    v.extend((r.env.len() as u32).to_le_bytes());
    v.extend(
        u32::try_from(r.path.len())
            .map_err(|_| "executable path too long")?
            .to_le_bytes(),
    );
    v.extend(
        u32::try_from(r.cwd.len())
            .map_err(|_| "cwd too long")?
            .to_le_bytes(),
    );
    v.extend(r.path.as_bytes());
    v.extend(r.cwd.as_bytes());
    for entry in std::iter::once(&r.path)
        .chain(r.args.iter())
        .chain(r.env.iter())
    {
        string(entry, false)?;
        v.extend(
            u32::try_from(entry.len())
                .map_err(|_| "launch string too long")?
                .to_le_bytes(),
        );
        v.extend(entry.as_bytes());
    }
    Ok(v)
}
pub(crate) fn execute_analysis(r: &ExecRequest, supported: bool) -> Result<Vec<u8>, String> {
    r.analysis.validate()?;
    let mut encoded = execute(r)?;
    if supported && r.analysis.enabled {
        encoded[4..8].copy_from_slice(&1u32.to_le_bytes());
        encoded.extend(SPECIMEN_MAX_SIZE.to_le_bytes());
        encoded.extend(5000u32.to_le_bytes());
    }
    if r.core_dump_on_exit {
        let flags = u32::from(supported && r.analysis.enabled) | 2;
        encoded[4..8].copy_from_slice(&flags.to_le_bytes());
        encoded.extend(SPECIMEN_MAX_SIZE.to_le_bytes());
        encoded.extend(5000u32.to_le_bytes());
    }
    Ok(encoded)
}
pub(crate) fn acquire(path: &str, uid: u32, gid: u32) -> Result<Vec<u8>, String> {
    string(path, true)?;
    let mut encoded = header(0);
    encoded.extend(uid.to_le_bytes());
    encoded.extend(gid.to_le_bytes());
    encoded.extend(
        u32::try_from(path.len())
            .map_err(|_| "path too long")?
            .to_le_bytes(),
    );
    encoded.extend(0u32.to_le_bytes());
    encoded.extend(path.as_bytes());
    encoded.extend(SPECIMEN_MAX_SIZE.to_le_bytes());
    encoded.extend(5000u32.to_le_bytes());
    Ok(encoded)
}
pub(crate) fn acquisition(reply: &[u8]) -> Result<(u64, u64), String> {
    use crate::parser::{u32_at, u64_at};
    if reply.len() != 24 || u32_at(reply, 20).map_err(|e| e.to_string())? != 0 {
        return Err("invalid acquisition reply length or padding".into());
    }
    let id = u64_at(reply, 0).map_err(|e| e.to_string())?;
    let size = u64_at(reply, 8).map_err(|e| e.to_string())?;
    let status = u32_at(reply, 16).map_err(|e| e.to_string())? as i32;
    if status < 0 && id == 0 && size == 0 {
        let errno = status
            .checked_neg()
            .filter(|&n| n <= 4095)
            .ok_or("invalid acquisition errno")?;
        return Err(format!(
            "guest acquisition unavailable: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }
    if status != 0 || id == 0 || size > u64::from(SPECIMEN_MAX_SIZE) {
        return Err("invalid acquisition identity, size or status".into());
    }
    Ok((id, size))
}
pub(crate) fn specimen_read(id: u64, offset: u64, capacity: u32) -> Vec<u8> {
    let mut encoded = with_session(id);
    encoded.extend(offset.to_le_bytes());
    encoded.extend(capacity.to_le_bytes());
    encoded.extend(0u32.to_le_bytes());
    encoded
}
pub(crate) fn specimen_chunk(
    reply: &[u8],
    offset: u64,
    total: u64,
    capacity: u32,
) -> Result<&[u8], String> {
    use crate::parser::{u32_at, u64_at};
    if reply.len() < 24 {
        return Err("truncated specimen reply".into());
    }
    let count = u32_at(reply, 16).map_err(|e| e.to_string())?;
    if u64_at(reply, 0).map_err(|e| e.to_string())? != offset
        || u64_at(reply, 8).map_err(|e| e.to_string())? != total
        || u32_at(reply, 20).map_err(|e| e.to_string())? != 0
        || count > capacity
        || count == 0
        || reply.len() != 24 + count as usize
        || offset
            .checked_add(u64::from(count))
            .is_none_or(|end| end > total)
    {
        return Err("invalid or noncontiguous specimen reply".into());
    }
    Ok(&reply[24..])
}
/// Decode an INFO reply: the kernel's revision, source id and release.
pub(crate) fn info(reply: &[u8]) -> Result<crate::api::GuestKernel, String> {
    if reply.len() != INFO_SIZE {
        return Err("invalid guest info reply length".into());
    }
    let text = |field: &[u8]| -> Result<String, String> {
        let end = field
            .iter()
            .position(|&byte| byte == 0)
            .ok_or("guest info string is not terminated")?;
        if field[end..].iter().any(|&byte| byte != 0) {
            return Err("guest info string padding is not zero".into());
        }
        String::from_utf8(field[..end].to_vec())
            .map_err(|_| "guest info string is not UTF-8".into())
    };
    let revision = u32::from_le_bytes(reply[0..4].try_into().expect("four bytes"));
    if revision == 0
        || reply[4..8].iter().any(|&byte| byte != 0)
        || reply[152..].iter().any(|&byte| byte != 0)
    {
        return Err("invalid guest info reply".into());
    }
    let source = text(&reply[8..88])?;
    let release = text(&reply[88..152])?;
    let source = if source.is_empty() {
        None
    } else {
        let (claimed, series) = crate::api::parse_source_id(&source)
            .ok_or_else(|| format!("invalid guest source id {source:?}"))?;
        if claimed != revision {
            return Err(format!(
                "guest source id names revision {claimed} but the kernel reports {revision}"
            ));
        }
        Some(series)
    };
    Ok(crate::api::GuestKernel {
        revision: Some(revision),
        source,
        release: Some(release),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn core_exec_trailer_follows_optional_specimen_without_changing_legacy_wire() {
        let mut request = ExecRequest::default();
        let legacy = execute(&request).unwrap();
        request.core_dump_on_exit = true;
        let core = execute_analysis(&request, true).unwrap();
        assert_eq!(core.len(), legacy.len() + 8);
        assert_eq!(&core[4..8], &2u32.to_le_bytes());
        assert_eq!(
            &core[legacy.len()..legacy.len() + 4],
            &SPECIMEN_MAX_SIZE.to_le_bytes()
        );
        request.analysis.enabled = true;
        let combined = execute_analysis(&request, true).unwrap();
        assert_eq!(combined.len(), legacy.len() + 16);
        assert_eq!(&combined[4..8], &3u32.to_le_bytes());
        assert_eq!(
            &combined[legacy.len()..legacy.len() + 8],
            &combined[legacy.len() + 8..]
        );
    }
    #[test]
    fn analysis_wire_preserves_off_and_legacy_execution_and_rejects_bad_replies() {
        let mut request = ExecRequest::default();
        assert_eq!(
            execute_analysis(&request, true).unwrap(),
            execute(&request).unwrap()
        );
        request.analysis.enabled = true;
        assert_eq!(
            execute_analysis(&request, false).unwrap(),
            execute(&request).unwrap()
        );
        let extended = execute_analysis(&request, true).unwrap();
        assert_eq!(&extended[4..8], &1u32.to_le_bytes());
        assert_eq!(extended.len(), execute(&request).unwrap().len() + 8);
        let mut ready = Vec::new();
        ready.extend(4u64.to_le_bytes());
        ready.extend(3u64.to_le_bytes());
        ready.extend(0i32.to_le_bytes());
        ready.extend(0u32.to_le_bytes());
        assert_eq!(acquisition(&ready).unwrap(), (4, 3));
        for len in 0..24 {
            assert!(acquisition(&ready[..len]).is_err());
        }
        ready[0..8].fill(0);
        assert!(acquisition(&ready).is_err());
        ready[8..16].fill(0);
        ready[16..20].copy_from_slice(&i32::MIN.to_le_bytes());
        assert!(acquisition(&ready).is_err());
        let mut chunk = Vec::new();
        chunk.extend(0u64.to_le_bytes());
        chunk.extend(3u64.to_le_bytes());
        chunk.extend(3u32.to_le_bytes());
        chunk.extend(0u32.to_le_bytes());
        chunk.extend(b"abc");
        assert_eq!(specimen_chunk(&chunk, 0, 3, 3).unwrap(), b"abc");
        assert!(specimen_chunk(&chunk, 1, 3, 3).is_err());
        assert!(specimen_chunk(&chunk, 0, 3, 2).is_err());
        assert!(specimen_chunk(&chunk[..26], 0, 3, 3).is_err());
        assert_eq!(specimen_read(4, 0, 3).len(), 32);
        assert_eq!(acquire("/tmp/a", 1000, 1000).unwrap().len(), 38);
    }
    #[test]
    fn constants_match_the_shared_control_header() {
        let header = include_str!("../../../protocol/control.h");
        let define = |name: &str| -> u32 {
            let line = header
                .lines()
                .find(|line| line.split_whitespace().nth(1) == Some(name))
                .unwrap_or_else(|| panic!("{name} missing"));
            let value = line.split_whitespace().nth(2).unwrap();
            match value.strip_prefix("0x") {
                Some(hex) => u32::from_str_radix(hex, 16).unwrap(),
                None => value.parse().unwrap(),
            }
        };
        for (name, value) in [
            ("ANTC_UPLOAD_BEGIN", UPLOAD_BEGIN),
            ("ANTC_UPLOAD_CHUNK", UPLOAD_CHUNK),
            ("ANTC_UPLOAD_COMMIT", UPLOAD_COMMIT),
            ("ANTC_UPLOAD_ABORT", UPLOAD_ABORT),
            ("ANTC_EXEC", EXEC),
            ("ANTC_ACQUIRE", ACQUIRE),
            ("ANTC_SPECIMEN_READ", SPECIMEN_READ),
            ("ANTC_SPECIMEN_RELEASE", SPECIMEN_RELEASE),
            ("ANTC_TERMINAL_INPUT", INPUT),
            ("ANTC_TERMINAL_READ", READ),
            ("ANTC_TERMINAL_RESIZE", RESIZE),
            ("ANTC_SIGNAL", SIGNAL),
            ("ANTC_RUN_STATUS", RUN_STATUS),
            ("ANTC_STATS", STATS),
            ("ANTC_INFO", INFO),
            ("ANTC_INFO_SIZE", INFO_SIZE as u32),
            ("ANTC_SHUTDOWN", SHUTDOWN),
            ("ANTC_RESOURCES", RESOURCES),
            ("ANTC_RESOURCES_SIZE", RESOURCES_SIZE as u32),
            ("ANTC_REVISION", REVISION),
            ("ANTC_PROCESS_LIST", PROCESS_LIST),
            ("ANTC_CAPTURE_ATTACH", CAPTURE_ATTACH),
            ("ANTC_CAPTURE_ALL", CAPTURE_ALL),
            ("ANTC_CAPTURE_STOP", CAPTURE_STOP),
            ("ANTC_CAPTURE_STATUS", CAPTURE_STATUS),
            (
                "ANTC_CAPTURE_RETAINED",
                crate::observation::OBSERVATION_RETAINED as u32,
            ),
            (
                "ANTC_PROCESS_PAGE_MAX",
                crate::observation::PROCESS_PAGE_MAX_COUNT,
            ),
        ] {
            assert_eq!(define(name), value, "{name}");
        }
    }
    #[test]
    fn process_pages_validate_bounds_order_and_stable_identity() {
        let mut reply = vec![0; 80];
        reply[..8].copy_from_slice(&9u64.to_le_bytes());
        reply[8..12].copy_from_slice(&1u32.to_le_bytes());
        reply[16..24].copy_from_slice(&91u64.to_le_bytes());
        reply[24..32].copy_from_slice(&33u64.to_le_bytes());
        reply[32..36].copy_from_slice(&42u32.to_le_bytes());
        reply[48..52].copy_from_slice(&3u32.to_le_bytes());
        reply[56..60].copy_from_slice(b"test");
        let page = process_page(&reply, "boot", 0).unwrap();
        assert_eq!(page.processes[0].identity.start_boot_ns, 33);
        assert_eq!(page.processes[0].identity.boot_id, "boot");
        assert_eq!(
            attach_process(&page.processes[0].identity).unwrap().len(),
            32
        );
        for len in 0..reply.len() {
            assert!(process_page(&reply[..len], "boot", 0).is_err());
        }
        assert!(process_page(&reply, "boot", 42).is_err());
        reply[12..16].copy_from_slice(&41u32.to_le_bytes());
        assert!(process_page(&reply, "boot", 0).is_err());
        reply[12..16].copy_from_slice(&42u32.to_le_bytes());
        assert_eq!(process_page(&reply, "boot", 0).unwrap().next_pid, 42);
        reply[72] = 1;
        assert!(process_page(&reply, "boot", 0).is_err());
        let mut oversized = vec![0; 16];
        oversized[..8].copy_from_slice(&9u64.to_le_bytes());
        oversized[8..12].copy_from_slice(&65u32.to_le_bytes());
        assert!(process_page(&oversized, "boot", 0).is_err());
    }
    #[test]
    fn capture_reply_rejects_aliases_bad_flags_and_false_stop() {
        let mut started = [0; 16];
        started[..8].copy_from_slice(&4u64.to_le_bytes());
        started[8..].copy_from_slice(&9u64.to_le_bytes());
        assert_eq!(capture_started(&started).unwrap(), (4, 9));
        for len in 0..16 {
            assert!(capture_started(&started[..len]).is_err());
        }
        let mut status = [0; 32];
        assert_eq!(capture_status(&status, 0).unwrap().cookie, 0);
        assert!(capture_status(&status, 4).is_err());
        status[..8].copy_from_slice(&4u64.to_le_bytes());
        status[8..12].copy_from_slice(&6u32.to_le_bytes());
        status[12..16].copy_from_slice(&2u32.to_le_bytes());
        status[16..24].copy_from_slice(&10u64.to_le_bytes());
        status[24..].copy_from_slice(&20u64.to_le_bytes());
        assert!(!capture_status(&status, 4).unwrap().active);
        assert!(capture_status(&status, 5).is_err());
        status[8..12].copy_from_slice(&7u32.to_le_bytes());
        assert!(capture_status(&status, 4).is_err());
        status[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert!(capture_status(&status, 4).is_err());
        status[24..].fill(0);
        assert!(capture_status(&status, 4).unwrap().active);
    }
    fn info_reply(revision: u32, source: &str, release: &str) -> Vec<u8> {
        let mut reply = vec![0; INFO_SIZE];
        reply[0..4].copy_from_slice(&revision.to_le_bytes());
        reply[8..8 + source.len()].copy_from_slice(source.as_bytes());
        reply[88..88 + release.len()].copy_from_slice(release.as_bytes());
        reply
    }
    #[test]
    fn info_reply_reports_revision_source_and_release() {
        let series = "ab".repeat(32);
        let info = info(&info_reply(9, &format!("9:{series}"), "6.12.94-g1")).unwrap();
        assert_eq!(info.revision, Some(9));
        assert_eq!(info.source.as_deref(), Some(series.as_str()));
        assert_eq!(info.release.as_deref(), Some("6.12.94-g1"));
        let unversioned = super::info(&info_reply(9, "", "6.12.94")).unwrap();
        assert_eq!(unversioned.source, None);
        for bad in [
            info_reply(0, "", "6.12.94"),
            info_reply(9, &format!("8:{series}"), "6.12.94"),
            info_reply(9, "9:xyz", "6.12.94"),
            vec![0; INFO_SIZE - 1],
        ] {
            assert!(super::info(&bad).is_err());
        }
        let mut unterminated = info_reply(9, "", "");
        unterminated[88..152].fill(b'a');
        assert!(super::info(&unterminated).is_err());
        let mut dirty = info_reply(9, "", "6.12.94");
        dirty[100] = b'x';
        assert!(super::info(&dirty).is_err());
    }
    #[test]
    fn rejects_embedded_nul_and_relative_execution() {
        let mut r = ExecRequest {
            path: "sh".into(),
            ..ExecRequest::default()
        };
        assert!(execute(&r).is_err());
        r.path = "/bin/sh".into();
        r.args.push("bad\0value".into());
        assert!(execute(&r).is_err());
    }
    #[test]
    fn upload_flags_are_independent_of_execution() {
        let v = upload_begin("/tmp/a", 3, true, false).unwrap();
        assert_eq!(v[4], 1);
        assert_eq!(&v[24..], b"/tmp/a");
    }
}
