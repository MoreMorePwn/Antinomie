// SPDX-License-Identifier: GPL-3.0-only
//! Raw packet capture file of a VM run (moved out of `storage`).
use super::*;

#[derive(Serialize)]
struct CaptureManifest<'a> {
    format: &'static str,
    vm: &'a VmConfig,
    bundle: &'a Bundle,
    disk_bundle: &'a Bundle,
    packets: u64,
    bytes: u64,
    persistence_error: &'a Option<String>,
    final_state: &'a str,
    health: &'a Option<Health>,
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_kernel: &'a Option<crate::api::GuestKernel>,
}
/// Packets are buffered in memory and handed to the recording writer thread
/// in large blocks: the transport thread calls [`RawCapture::flush`] after
/// every drain pass, and `sync`, `manifest` and drop flush too. `sync` and
/// `manifest` also wait until the writer has written everything. A block the
/// full writer queue cannot take yet stays buffered for the next flush (the
/// transport owner stops taking telemetry meanwhile, see `writer`).
pub struct RawCapture {
    pub directory: PathBuf,
    file: std::sync::Arc<File>,
    buffer: Vec<u8>,
    /// File length and packet count handed to the writer thread.
    written: (u64, u64),
    /// Ticket of the last block handed to the writer thread.
    ticket: u64,
    /// The writer thread's first error for this file, reported once.
    write_error: crate::writer::ErrorSlot,
    write_error_seen: bool,
    quota: u64,
    pub packets: u64,
    pub bytes: u64,
    pub error: Option<String>,
    pub final_health: Option<Health>,
    /// The guest kernel's INFO answer, recorded in the manifest.
    pub guest_kernel: Option<crate::api::GuestKernel>,
}
/// Buffered raw packet bytes that trigger a write before the next flush.
const RAW_BUFFER: usize = 1024 * 1024;
impl Drop for RawCapture {
    fn drop(&mut self) {
        self.flush_blocking();
    }
}
impl RawCapture {
    pub(crate) fn sync(&mut self) -> Result<(), String> {
        self.flush_blocking();
        crate::writer::wait_for(self.ticket);
        self.flush_blocking();
        if let Some(error) = &self.error
            && error.starts_with("capture write failed")
        {
            return Err(error.clone());
        }
        self.file.sync_all().map_err(|error| {
            let message = format!("raw capture sync failed: {error}");
            self.error.get_or_insert(message.clone());
            message
        })
    }
    /// Every packet appended so far is in the file: nothing is buffered and
    /// the writer has finished the last block. Hands the buffer over first;
    /// never waits.
    pub(crate) fn drained(&mut self) -> bool {
        self.flush();
        self.error.is_none() && self.buffer.is_empty() && crate::writer::is_done(self.ticket)
    }
    pub(crate) fn quota(&self) -> u64 {
        self.quota
    }
    /// A stand-in for a capture whose recording moved to a flush job: it
    /// refuses packets and holds no file of the recording.
    pub(crate) fn sealed(quota: u64) -> Self {
        Self {
            directory: PathBuf::new(),
            file: std::sync::Arc::new(File::open("/dev/null").expect("open /dev/null")),
            buffer: Vec::new(),
            written: (0, 0),
            ticket: 0,
            write_error: crate::writer::error_slot(),
            write_error_seen: false,
            quota,
            packets: 0,
            bytes: 0,
            error: Some("recording sealed".into()),
            final_health: None,
            guest_kernel: None,
        }
    }
    pub fn new(directory: PathBuf, quota: u64) -> Result<Self, String> {
        private_dir(&directory).map_err(|e| e.to_string())?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("telemetry.raw"))
            .map_err(|e| e.to_string())?;
        Ok(Self {
            directory,
            file: std::sync::Arc::new(file),
            buffer: Vec::new(),
            written: (0, 0),
            ticket: 0,
            write_error: crate::writer::error_slot(),
            write_error_seen: false,
            quota,
            packets: 0,
            bytes: 0,
            error: None,
            final_health: None,
            guest_kernel: None,
        })
    }
    pub fn append(&mut self, packet: &[u8]) -> bool {
        self.append_with_reserved(packet, 0)
    }
    pub fn append_with_reserved(&mut self, packet: &[u8], reserved_len: u64) -> bool {
        if self.error.is_some() {
            return false;
        }
        let Some(total) = self
            .bytes
            .checked_add(4)
            .and_then(|n| n.checked_add(packet.len() as u64))
        else {
            self.error = Some("capture size overflow".into());
            return false;
        };
        if total.saturating_add(reserved_len) > self.quota {
            self.error = Some(crate::quota::message(self.quota));
            return false;
        }
        let length = match u32::try_from(packet.len()) {
            Ok(n) => n,
            Err(_) => {
                self.error = Some("packet length overflow".into());
                return false;
            }
        };
        self.buffer.extend_from_slice(&length.to_le_bytes());
        self.buffer.extend_from_slice(packet);
        self.bytes = total;
        self.packets += 1;
        self.buffer.len() < RAW_BUFFER || self.flush()
    }
    /// Hand buffered packets to the writer thread. False once, when an
    /// earlier write of this file has failed: the writer then cut the file
    /// back to the last complete block, so it stays whole packets, and
    /// nothing more is written.
    pub fn flush(&mut self) -> bool {
        self.flush_with(false)
    }
    fn flush_blocking(&mut self) -> bool {
        self.flush_with(true)
    }
    fn flush_with(&mut self, blocking: bool) -> bool {
        if !self.write_error_seen
            && let Some(error) = crate::writer::error_of(&self.write_error)
        {
            self.write_error_seen = true;
            self.error.get_or_insert(error);
            self.buffer.clear();
            if let Ok(metadata) = self.file.metadata() {
                self.bytes = metadata.len();
            }
            return false;
        }
        if !self.buffer.is_empty() && !self.write_error_seen {
            let op = crate::writer::Op::Append {
                file: self.file.clone(),
                data: std::mem::take(&mut self.buffer),
                rollback: self.written.0,
                error: self.write_error.clone(),
            };
            let submitted = if blocking {
                Ok(crate::writer::submit(op))
            } else {
                crate::writer::try_submit(op)
            };
            match submitted {
                Ok(ticket) => {
                    self.ticket = ticket;
                    self.written = (self.bytes, self.packets);
                }
                // No room yet: kept for the next flush.
                Err(crate::writer::Op::Append { data, .. }) => self.buffer = data,
                Err(crate::writer::Op::WriteAt { .. }) => unreachable!("raw append operation"),
            }
        }
        true
    }
    /// Writes the manifest durably: waits for this file's data, syncs it and
    /// publishes the manifest with `fsync`. For the end of a recording, off
    /// the transport thread; use [`Self::queue_manifest`] while it runs.
    pub(crate) fn manifest(
        &mut self,
        vm: &VmConfig,
        bundle: &Bundle,
        disk_bundle: &Bundle,
        state: &str,
    ) -> Result<(), String> {
        self.flush_blocking();
        crate::writer::wait_for(self.ticket);
        if self.flush_blocking()
            && let Err(e) = self.file.sync_all()
        {
            self.error
                .get_or_insert_with(|| format!("capture sync failed: {e}"));
        }
        atomic_json(
            &self.directory.join("manifest.json"),
            &self.manifest_body(vm, bundle, disk_bundle, state),
        )
    }

    /// Queues the manifest for the persistence thread and returns at once.
    pub(crate) fn queue_manifest(
        &mut self,
        vm: &VmConfig,
        bundle: &Bundle,
        disk_bundle: &Bundle,
        state: &str,
    ) -> Result<(), String> {
        queue_json(
            &self.directory.join("manifest.json"),
            &self.manifest_body(vm, bundle, disk_bundle, state),
        )
    }

    fn manifest_body<'a>(
        &'a mut self,
        vm: &'a VmConfig,
        bundle: &'a Bundle,
        disk_bundle: &'a Bundle,
        state: &'a str,
    ) -> CaptureManifest<'a> {
        if let Some(health) = &mut self.final_health {
            health.persistence_error = self
                .error
                .clone()
                .or_else(|| health.persistence_error.clone());
        }
        CaptureManifest {
            format: "ANTT1 length-prefixed raw LE32",
            vm,
            bundle,
            disk_bundle,
            packets: self.packets,
            bytes: self.bytes,
            persistence_error: &self.error,
            final_state: state,
            health: &self.final_health,
            guest_kernel: &self.guest_kernel,
        }
    }
}
