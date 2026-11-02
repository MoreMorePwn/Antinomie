// SPDX-License-Identifier: GPL-3.0-only
//! The QMP control connection (moved out of `vm`).
use super::*;

pub(super) struct Qmp {
    writer: UnixStream,
    reader: std::io::BufReader<UnixStream>,
}
impl Qmp {
    pub(super) fn send_fd(&mut self, stream: &UnixStream) -> Result<(), String> {
        use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
        let command = b"{\"execute\":\"getfd\",\"arguments\":{\"fdname\":\"antinomie-state\"}}\n";
        let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        let descriptors = [stream.as_fd()];
        if !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)) {
            return Err("QMP descriptor control buffer is too small".into());
        }
        let sent = sendmsg(
            &self.writer,
            &[std::io::IoSlice::new(command)],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .map_err(|e| format!("QMP descriptor transfer: {e}"))?;
        if sent < command.len() {
            self.writer
                .write_all(&command[sent..])
                .map_err(|e| e.to_string())?;
        }
        self.reply("")?;
        Ok(())
    }
    /// Connects, retrying for `wait` while QEMU is still creating the socket
    /// or has not reached the main loop that sends the greeting.
    ///
    /// `server=on,wait=off` listens before QEMU can write that greeting.
    /// A read against the accepted connection then returns EAGAIN when its
    /// receive timeout expires, which is the same code as a nonblocking read.
    pub(super) fn connect(path: &Path, wait: Duration) -> Result<Self, String> {
        Self::connect_with(path, wait, Duration::from_secs(5))
    }
    /// [`Qmp::connect`] with the time each later reply may take (`reply`: 5 s
    /// at KVM speed, longer under TCG, where QEMU's main loop stalls).
    pub(super) fn connect_with(
        path: &Path,
        wait: Duration,
        reply: Duration,
    ) -> Result<Self, String> {
        let deadline = std::time::Instant::now() + wait;
        let socket = loop {
            match UnixStream::connect(path) {
                Ok(socket) => break socket,
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Err(error) => return Err(error.to_string()),
            }
        };
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err("QMP read: timed out waiting for a reply".into());
        }
        socket
            .set_read_timeout(Some(remaining))
            .and_then(|_| socket.set_write_timeout(Some(reply)))
            .map_err(|e| e.to_string())?;
        let mut qmp = Qmp {
            writer: socket.try_clone().map_err(|e| e.to_string())?,
            reader: std::io::BufReader::new(socket),
        };
        qmp.reply("")?;
        qmp.reader
            .get_mut()
            .set_read_timeout(Some(reply))
            .map_err(|e| e.to_string())?;
        qmp.reply("{\"execute\":\"qmp_capabilities\"}\n")?;
        Ok(qmp)
    }
    /// Sends `command` (unless empty) and returns the next greeting or
    /// return value, skipping events.
    pub(super) fn reply(&mut self, command: &str) -> Result<serde_json::Value, String> {
        if !command.is_empty() {
            self.writer
                .write_all(command.as_bytes())
                .map_err(|e| format!("QMP write: {e}"))?;
        }
        loop {
            let mut line = String::new();
            if std::io::BufRead::read_line(&mut self.reader, &mut line).map_err(|error| {
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut
                {
                    "QMP read: timed out waiting for a reply".to_string()
                } else {
                    format!("QMP read: {error}")
                }
            })? == 0
            {
                return Err("QMP closed".into());
            }
            let value: serde_json::Value =
                serde_json::from_str(&line).map_err(|e| format!("QMP reply: {e}"))?;
            if value.get("QMP").is_some() || value.get("return").is_some() {
                return Ok(value);
            }
            if let Some(error) = value.get("error") {
                return Err(format!("QMP error: {error}"));
            }
        }
    }
}
/// Times a read-only QMP question is asked before QEMU is taken for dead.
pub(super) const QMP_ATTEMPTS: u32 = 3;

/// A QMP error that is only a missing reply, not a closed or refused socket.
pub(super) fn is_timeout(error: &str) -> bool {
    error.contains("timed out waiting for a reply")
}
