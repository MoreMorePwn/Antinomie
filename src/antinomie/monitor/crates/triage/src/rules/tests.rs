// SPDX-License-Identifier: GPL-3.0-only
//! Rule tests: synthetic calls through the whole engine, one module per family.
#[cfg(test)]
pub mod bpf_attach;
#[cfg(test)]
pub mod columns;
#[cfg(test)]
pub mod credential;
#[cfg(test)]
pub mod discovery;
#[cfg(test)]
pub mod evasion;
#[cfg(test)]
pub mod execution;
#[cfg(test)]
pub mod frames;
#[cfg(test)]
pub mod impact;
#[cfg(test)]
pub mod injection;
#[cfg(test)]
pub mod network;
#[cfg(test)]
pub mod persistence;
#[cfg(test)]
pub mod pipeline;
#[cfg(test)]
pub mod privilege;
#[cfg(test)]
pub mod probes;
pub mod support;
