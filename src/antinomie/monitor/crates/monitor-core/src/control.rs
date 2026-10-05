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
pub(crate) const SHUTDOWN: u32 = 0x1030;
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
#[cfg(test)]
mod tests {
    use super::*;
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
