// SPDX-License-Identifier: MIT
//! Debugger support: a host RSP (GDB Remote Serial Protocol) server in front of
//! a `DebugBackend`. The shipped backend is the Antinomie guest kernel's
//! ptrace-free debug engine over the V7 control channel; the trait is the seam
//! a QEMU-gdbstub backend would implement. Nothing runs inside the guest.
//!
//! Multi-architecture by construction: wire messages carry an architecture tag
//! (the ELF `e_machine`), registers travel as regset blobs tagged with their ELF
//! note type, the guest reports a capability set at attach, and every register
//! view (the GDB target description and the UI) is built from one
//! [`TargetDescription`] per architecture. x86-64 is the first and only entry.
pub mod amd64;
pub(crate) mod debugger;
mod inferior;
mod kernel_backend;
mod regs;
mod rsp_client;
mod rsp_packet;
mod rsp_requests;
mod rsp_server;
pub mod signal_policy;
pub mod signals;
mod target;
#[cfg(test)]
mod tests;
mod ui_control;
mod ui_follow;
pub mod view;
pub mod wire;

pub use debugger::AdoptedChild;
pub use kernel_backend::{AttachedSession, KernelDebugBackend};
pub use regs::{RegKind, RegSource, RegSpec, RegisterFile, TargetDescription};
pub use rsp_server::{DebugEndpoints, DebugServer};
pub use target::{
    ArchTag, ChildRef, DebugBackend, DebugCaps, DebugError, DetachMode, EventBatch,
    GuestBreakpoint, GuestLink, LinkError, RegsetBlob, RegsetInfo, ResumeAction, SessionInfo,
    SessionOptions, StopEvent, StopKind, TargetState, ThreadAction, ThreadInfo,
};
pub use ui_control::PanelHandle;
pub use view::{BreakpointKind, WatchAccess};
