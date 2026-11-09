// SPDX-License-Identifier: GPL-3.0-only
//! Argument positions are read from the event's own ABI table (ANT-T0440).
use super::*;
use antinomie_monitor_core::syscalls::{self, Abi};

const ABIS: [Abi; 4] = [Abi::X86_64, Abi::Aarch64, Abi::Arm, Abi::I386];

fn clone_on(abi: Abi) -> InvocationSummary {
    let nr = syscalls::id(abi, syscalls::table(abi).number("clone").unwrap());
    let mut call = tests::call(7, nr, "clone", 8);
    call.entry.as_mut().unwrap().args = Some([0x11, 0x22, 0x33, 0x44, 0x55, 0]);
    call
}

#[test]
fn a_rule_reads_clone_roles_at_the_event_abis_positions() {
    let files = FdState::default();
    // x86-64 puts child_tid before tls; arm64, AArch32 and ia32 swap them.
    let expected = [(Abi::X86_64, 0x55, 0x44), (Abi::Aarch64, 0x44, 0x55)]
        .into_iter()
        .chain([(Abi::Arm, 0x44, 0x55), (Abi::I386, 0x44, 0x55)]);
    for (abi, tls, child_tid) in expected {
        let call = clone_on(abi);
        let event = call.entry.as_ref().unwrap();
        let cx = rules::ctx::Ctx::new(&call, event, &files, None, false);
        assert_eq!(cx.arg("tls"), tls, "{abi:?}");
        assert_eq!(cx.arg("child_tidptr"), child_tid, "{abi:?}");
        assert_eq!(cx.arg("clone_flags"), 0x11, "{abi:?}");
        assert_eq!(clone_flags(event.syscall_nr, &event.args.unwrap()), 0x11);
    }
}

#[test]
fn the_calls_triage_reads_are_at_the_same_place_on_every_abi_that_has_them() {
    // The roles the sites read: where the four tables differ for them is
    // listed in the task record; the others must agree, so a wrong table can
    // not change today's answers.
    let roles = [
        ("execve", "filename"),
        ("execve", "argv"),
        ("execve", "envp"),
        ("execveat", "argv"),
        ("execveat", "envp"),
        ("clone", "clone_flags"),
        ("connect", "uservaddr"),
        ("bind", "umyaddr"),
        ("sendto", "addr"),
    ];
    for (call, role) in roles {
        let positions: Vec<_> = ABIS
            .iter()
            .filter_map(|abi| syscalls::table(*abi).argument(call, role))
            .collect();
        assert!(positions.len() >= 3, "{call}.{role}: {positions:?}");
        assert!(positions.windows(2).all(|pair| pair[0] == pair[1]));
    }
    assert_eq!(
        syscalls::table(Abi::X86_64).argument("clone", "tls"),
        Some(4)
    );
}

#[test]
fn an_unknown_abi_id_falls_back_to_the_x86_64_table() {
    let unknown = syscalls::untabled_id(56);
    assert_eq!(syscalls::argument_of(unknown, "clone", "tls"), Some(4));
    assert_eq!(syscalls::argument_of(56, "clone", "tls"), Some(4));
}

#[test]
fn x86_64_address_and_spawn_decisions_are_unchanged() {
    let connect = syscalls::number("connect").unwrap();
    assert_eq!(sigma_events::address_argument(connect, "connect"), Some(1));
    assert_eq!(sigma_events::address_argument(connect, "read"), None);
    let nr = syscalls::number("clone").unwrap();
    let call = tests::call(7, nr, "clone", 8);
    let spawn = |flags| process_tree::spawn_kind(&call, nr, "clone", Some([flags, 0, 0, 0, 0, 0]));
    assert!(matches!(spawn(CLONE_THREAD), Some(Spawn::Skip)));
    assert!(matches!(spawn(0), Some(Spawn::Process)));
    // The same decision on an arm64 id.
    let arm = syscalls::id(
        Abi::Aarch64,
        syscalls::table(Abi::Aarch64).number("clone").unwrap(),
    );
    assert!(matches!(
        process_tree::spawn_kind(&call, arm, "clone", Some([CLONE_THREAD, 0, 0, 0, 0, 0])),
        Some(Spawn::Skip)
    ));
}
