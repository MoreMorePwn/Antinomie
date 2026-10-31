// SPDX-License-Identifier: GPL-3.0-only
//! Which architecture the guest is: ARCH_INFO, the debug engine's CAPS, or
//! x86-64 for a guest too old to say.
use super::*;

impl Session {
    /// Ask the guest for its architecture: the guest's own account of whose
    /// system call numbers, layouts and registers its records use. ARCH_INFO
    /// for a revision-20 guest, the debug engine's CAPS for a revision-17 to 19
    /// one; an older guest is x86-64 and is not asked.
    pub(super) fn arch_probe_start(
        &mut self,
        revision: Option<u32>,
        snapshot: &mut Snapshot,
    ) -> KernelProbe {
        if revision.is_some_and(|revision| revision >= control::ARCH_INFO_REVISION) {
            match self.transport.send(control::ARCH_INFO, &control::header(0)) {
                Ok(id) => return KernelProbe::ArchInfo(id),
                Err(error) => snapshot.last_error = Some(format!("guest architecture: {error}")),
            }
        }
        if revision.is_some_and(|revision| revision >= 17) {
            return self.caps_probe_start(snapshot);
        }
        self.core_probe_start(snapshot)
    }
    pub(super) fn caps_probe_start(&mut self, snapshot: &mut Snapshot) -> KernelProbe {
        match self.transport.send(
            crate::debug::wire::CAPS,
            &crate::debug::wire::caps_request(),
        ) {
            Ok(id) => return KernelProbe::Arch(id),
            Err(error) => snapshot.last_error = Some(format!("guest architecture: {error}")),
        }
        self.core_probe_start(snapshot)
    }
    pub(super) fn arch_identified(
        &mut self,
        arch: crate::api::GuestArch,
        info: Option<crate::api::GuestArchInfo>,
        snapshot: &mut Snapshot,
    ) {
        if !arch.supported() {
            snapshot.last_error = Some(unsupported_arch(arch));
        }
        for kernel in [
            self.capture.guest_kernel.as_mut(),
            snapshot.guest_kernel.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            kernel.arch = arch;
            kernel.arch_info.clone_from(&info);
        }
    }
}
