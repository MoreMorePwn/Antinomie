// SPDX-License-Identifier: GPL-3.0-only
#![no_main]
use libfuzzer_sys::fuzz_target;

// The RunRequest JSON a socket client or the CLI sends (crates/service/src/api/spec.rs).
fuzz_target!(|data: &[u8]| {
    antinomie_service::fuzz_entry::job_spec(data);
});
