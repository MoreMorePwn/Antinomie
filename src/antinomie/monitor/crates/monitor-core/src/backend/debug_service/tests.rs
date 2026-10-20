// SPDX-License-Identifier: MIT
use super::*;
use crate::observation::GuestProcessIdentity;

#[test]
fn only_debug_opcodes_pass_the_link() {
    for (opcode, ok) in [
        (0x107f, false),
        (wire::CAPS, true),
        (wire::BP_CLEAR, true),
        (wire::AUXV, true),
        (wire::AUXV + 1, false),
        (crate::control::EXEC, false),
        (crate::control::SHUTDOWN, false),
        (crate::control::UPLOAD_BEGIN, false),
        (0, false),
    ] {
        assert_eq!(allowed(opcode), ok, "{opcode:#x}");
    }
}

#[test]
fn the_link_forwards_a_request_and_its_answer() {
    let (service, link) = DebugService::new();
    let transport = thread::spawn(move || {
        let request = service
            .requests
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        assert_eq!(
            (request.opcode, request.args.as_slice()),
            (wire::STATUS, &[1, 2][..])
        );
        request.reply.send(Ok(vec![9])).unwrap();
        let request = service
            .requests
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        request
            .reply
            .send(Err(LinkError {
                errno: Some(16),
                message: "busy".into(),
                outcome_unknown: false,
            }))
            .unwrap();
        service
    });
    let mut link = link;
    assert_eq!(link.request(wire::STATUS, &[1, 2]).unwrap(), vec![9]);
    let error = link.request(wire::STOP, &[]).unwrap_err();
    assert_eq!((error.errno, error.message.as_str()), (Some(16), "busy"));
    let service = transport.join().unwrap();
    drop(service);
    // With the transport thread gone, a request fails instead of hanging.
    let error = link.request(wire::STATUS, &[]).unwrap_err();
    assert!(error.message.contains("closing"), "{}", error.message);
}

#[test]
fn nonces_differ_and_are_never_zero() {
    let target = GuestProcessIdentity {
        boot_id: "boot".into(),
        task_cookie: 1,
        tgid: 2,
        start_boot_ns: 3,
    };
    let (first, second) = (nonce(&target), nonce(&target));
    assert_ne!(first, second);
    assert!(first[0] != 0 && second[0] != 0);
}

#[test]
fn attaching_needs_a_running_vm_and_a_snapshot_waits_for_detach() {
    let mut worker = super::super::tests::download_worker(std::env::temp_dir());
    let target = GuestProcessIdentity {
        boot_id: "boot".into(),
        task_cookie: 1,
        tgid: 2,
        start_boot_ns: 3,
    };
    assert_eq!(worker.debug_attach(target).unwrap_err(), "VM is stopped");
    assert_eq!(
        worker.debug_detach(false).unwrap_err(),
        "no debugger is attached"
    );
    assert!(worker.debug_snapshot_guard().is_ok());
    // Requests that arrive with no VM are answered, not left waiting.
    let mut link = worker.debug.link.clone();
    let asker = thread::spawn(move || link.request(wire::STATUS, &[]));
    let until = Instant::now() + Duration::from_secs(5);
    while !asker.is_finished() {
        worker.serve_debug_requests();
        assert!(Instant::now() < until);
        thread::sleep(Duration::from_millis(1));
    }
    let error = asker.join().unwrap().unwrap_err();
    assert!(error.message.contains("stopped"));
}
