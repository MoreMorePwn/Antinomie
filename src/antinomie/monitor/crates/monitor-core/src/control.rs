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
/// Guest contract revision this host implements (`ANTC_REVISION`).
pub const REVISION: u32 = 9;
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
            ("ANTC_TERMINAL_INPUT", INPUT),
            ("ANTC_TERMINAL_READ", READ),
            ("ANTC_TERMINAL_RESIZE", RESIZE),
            ("ANTC_SIGNAL", SIGNAL),
            ("ANTC_RUN_STATUS", RUN_STATUS),
            ("ANTC_STATS", STATS),
            ("ANTC_INFO", INFO),
            ("ANTC_INFO_SIZE", INFO_SIZE as u32),
            ("ANTC_SHUTDOWN", SHUTDOWN),
            ("ANTC_REVISION", REVISION),
        ] {
            assert_eq!(define(name), value, "{name}");
        }
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
