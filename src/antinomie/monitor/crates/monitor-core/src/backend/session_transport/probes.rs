// SPDX-License-Identifier: GPL-3.0-only
//! Kernel INFO and tracer capability probes (moved out of `session_transport`).
use super::*;

impl Session {
    /// Advance the kernel probe: send INFO when due and apply waiting replies.
    pub(in crate::backend) fn probe_kernel(
        &mut self,
        snapshot: &mut Snapshot,
        sender: &SyncSender<Notification>,
    ) -> Result<(), String> {
        match self.kernel_probe {
            KernelProbe::Done => Ok(()),
            KernelProbe::Due(when) => {
                if Instant::now() >= when {
                    // A full request ring only delays identification.
                    self.kernel_probe =
                        match self.transport.send(control::INFO, &control::header(0)) {
                            Ok(id) => KernelProbe::Info(id),
                            Err(_) => KernelProbe::Due(Instant::now() + KERNEL_PROBE_RETRY),
                        };
                }
                Ok(())
            }
            KernelProbe::CoreDue(when, attempts) => {
                if Instant::now() >= when {
                    self.kernel_probe =
                        match self.transport.send(control::CORE_CAPS, &control::header(0)) {
                            Ok(id) => KernelProbe::Core(id, attempts + 1),
                            Err(_) => {
                                KernelProbe::CoreDue(Instant::now() + KERNEL_PROBE_RETRY, attempts)
                            }
                        };
                }
                Ok(())
            }
            KernelProbe::TracerDue(when, attempts) => {
                if Instant::now() >= when {
                    self.kernel_probe = match self
                        .transport
                        .send(control::TRACER_CAPS, &control::header(0))
                    {
                        Ok(id) => KernelProbe::Tracer(id, attempts + 1),
                        Err(_) => {
                            KernelProbe::TracerDue(Instant::now() + KERNEL_PROBE_RETRY, attempts)
                        }
                    };
                }
                Ok(())
            }
            KernelProbe::Info(_)
            | KernelProbe::ArchInfo(_)
            | KernelProbe::Arch(_)
            | KernelProbe::Stats(_)
            | KernelProbe::Core(..)
            | KernelProbe::Tracer(..) => self.drain_replies(snapshot, sender),
        }
    }
    /// Consume a reply that belongs to the kernel probe; false for any other reply.
    pub(super) fn kernel_probe_reply(
        &mut self,
        reply_id: u64,
        status: i32,
        payload: &[u8],
        snapshot: &mut Snapshot,
    ) -> bool {
        const EOPNOTSUPP: i32 = 95;
        let retry = KernelProbe::Due(Instant::now() + KERNEL_PROBE_RETRY);
        match self.kernel_probe {
            KernelProbe::Info(id) if id == reply_id => {
                self.kernel_probe = if status == 0 {
                    match control::info(payload) {
                        Ok(kernel) => {
                            let revision = kernel.revision;
                            self.kernel_identified(kernel, snapshot);
                            self.arch_probe_start(revision, snapshot)
                        }
                        Err(error) => {
                            snapshot.last_error = Some(format!("guest info: {error}"));
                            self.core_probe_start(snapshot)
                        }
                    }
                } else if status == -EOPNOTSUPP {
                    match self.transport.send(control::STATS, &control::header(0)) {
                        Ok(id) => KernelProbe::Stats(id),
                        Err(_) => retry,
                    }
                } else {
                    retry
                };
                true
            }
            KernelProbe::Stats(id) if id == reply_id => {
                // INFO is registered before every other opcode: a kernel that
                // answers STATS but not INFO predates revision 9.
                self.kernel_probe = if status == 0 {
                    self.kernel_identified(GuestKernel::default(), snapshot);
                    self.core_probe_start(snapshot)
                } else {
                    retry
                };
                true
            }
            KernelProbe::ArchInfo(id) if id == reply_id => {
                // A guest that answers but cannot be read is taken as its debug
                // engine says, as a revision-17 guest is.
                self.kernel_probe = match (status == 0).then(|| control::arch_info(payload)) {
                    Some(Ok((arch, info))) => {
                        if let Some(note) = control::arch_table_mismatch(arch, &info) {
                            snapshot.last_error = Some(note);
                        }
                        self.arch_identified(arch, Some(info), snapshot);
                        self.core_probe_start(snapshot)
                    }
                    Some(Err(error)) => {
                        snapshot.last_error = Some(format!("guest architecture: {error}"));
                        self.caps_probe_start(snapshot)
                    }
                    None => self.caps_probe_start(snapshot),
                };
                true
            }
            KernelProbe::Arch(id) if id == reply_id => {
                // A guest that cannot say (a development kernel without the
                // debug engine) is taken as x86-64, as every older guest is.
                if status == 0 {
                    match control::arch_caps(payload) {
                        Ok(arch) => self.arch_identified(arch, None, snapshot),
                        Err(error) => {
                            snapshot.last_error = Some(format!("guest architecture: {error}"))
                        }
                    }
                }
                self.kernel_probe = self.core_probe_start(snapshot);
                true
            }
            KernelProbe::Core(id, attempts) if id == reply_id => {
                self.kernel_probe = self.core_caps_reply(status, payload, attempts, snapshot);
                true
            }
            KernelProbe::Tracer(id, attempts) if id == reply_id => {
                self.kernel_probe = self.tracer_caps_reply(status, payload, attempts, snapshot);
                true
            }
            _ => false,
        }
    }
    /// Ask a revision-15 or newer guest for its process-core limits; an older
    /// one has none, and runs under the contract every kernel had.
    pub(super) fn core_probe_start(&mut self, snapshot: &mut Snapshot) -> KernelProbe {
        let revision = snapshot
            .guest_kernel
            .as_ref()
            .and_then(|kernel| kernel.revision);
        if revision.is_some_and(|revision| revision >= 15) {
            KernelProbe::CoreDue(Instant::now(), 0)
        } else {
            self.core_limits_known(crate::core_limits::CoreLimits::LEGACY, snapshot);
            snapshot.guest_tracer = Some(crate::api::GuestTracerCaps::default());
            KernelProbe::Done
        }
    }
    /// After the core limits: what a revision-17 guest's tracer offers. An
    /// older guest offers nothing.
    pub(super) fn tracer_probe_start(snapshot: &mut Snapshot) -> KernelProbe {
        let revision = snapshot
            .guest_kernel
            .as_ref()
            .and_then(|kernel| kernel.revision);
        if revision.is_some_and(|revision| revision >= 17) {
            KernelProbe::TracerDue(Instant::now(), 0)
        } else {
            snapshot.guest_tracer = Some(crate::api::GuestTracerCaps::default());
            KernelProbe::Done
        }
    }
    /// TRACER_CAPS answers: the offer, nothing for an unsupported opcode, or a
    /// retry (three tries) for anything else, after which nothing is asked.
    pub(super) fn tracer_caps_reply(
        &mut self,
        status: i32,
        payload: &[u8],
        attempts: u8,
        snapshot: &mut Snapshot,
    ) -> KernelProbe {
        const EOPNOTSUPP: i32 = 95;
        let caps = if status == 0 {
            control::tracer_caps(payload)
        } else if status == -EOPNOTSUPP {
            Ok(crate::api::GuestTracerCaps::default())
        } else {
            Err(format!("guest status {status}"))
        };
        match caps {
            Ok(caps) => {
                snapshot.guest_tracer = Some(caps);
                KernelProbe::Done
            }
            Err(_) if attempts < 3 => {
                KernelProbe::TracerDue(Instant::now() + KERNEL_PROBE_RETRY, attempts)
            }
            Err(error) => {
                snapshot.last_error = Some(format!(
                    "guest tracer capabilities unavailable; written files and the program's own image are not hashed: {error}"
                ));
                snapshot.guest_tracer = Some(crate::api::GuestTracerCaps::default());
                KernelProbe::Done
            }
        }
    }
    pub(super) fn core_limits_known(
        &mut self,
        limits: crate::core_limits::CoreLimits,
        snapshot: &mut Snapshot,
    ) {
        self.core_limits = Some(limits);
        snapshot.guest_core_limits = Some(limits);
    }
    /// CORE_CAPS answers: limits, the legacy contract for an unsupported
    /// opcode, or a retry (three tries) for anything else.
    pub(super) fn core_caps_reply(
        &mut self,
        status: i32,
        payload: &[u8],
        attempts: u8,
        snapshot: &mut Snapshot,
    ) -> KernelProbe {
        const EOPNOTSUPP: i32 = 95;
        let limits = if status == 0 {
            crate::core_limits::CoreLimits::parse(payload)
        } else if status == -EOPNOTSUPP {
            Ok(crate::core_limits::CoreLimits::LEGACY)
        } else {
            Err(format!("guest status {status}"))
        };
        match limits {
            Ok(limits) => {
                self.core_limits_known(limits, snapshot);
                Self::tracer_probe_start(snapshot)
            }
            Err(_) if attempts < 3 => {
                KernelProbe::CoreDue(Instant::now() + KERNEL_PROBE_RETRY, attempts)
            }
            Err(error) => {
                snapshot.last_error = Some(format!(
                    "guest process-core limits unavailable; using 64 MiB and 5 s: {error}"
                ));
                self.core_limits_known(crate::core_limits::CoreLimits::LEGACY, snapshot);
                Self::tracer_probe_start(snapshot)
            }
        }
    }
    pub(super) fn kernel_identified(&mut self, kernel: GuestKernel, snapshot: &mut Snapshot) {
        let claimed = (
            self.bundle.antinomie_revision,
            self.bundle.antinomie_source.as_deref(),
        );
        let running = (kernel.revision, kernel.source.as_deref());
        if claimed.0.is_some() && claimed != running {
            snapshot.last_error = Some(format!(
                "the running kernel does not match its base: the base was built {}, the kernel is {}",
                describe_source(claimed),
                describe_source(running)
            ));
        } else if kernel
            .revision
            .is_some_and(|revision| revision > APP_REVISION)
        {
            snapshot.last_error = Some(format!(
                "the guest kernel is {}, newer than this app; update Antinomie",
                describe_source(running)
            ));
        }
        self.capture.guest_kernel = Some(kernel.clone());
        snapshot.guest_kernel = Some(kernel);
    }
}
