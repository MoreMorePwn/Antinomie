// SPDX-License-Identifier: GPL-3.0-only
#![no_main]
use libfuzzer_sys::fuzz_target;

// The daemon's socket framing: lines with a size limit, the strict request
// parser, and the Base64 of uploads (crates/service/src/server/frame.rs).
fuzz_target!(|data: &[u8]| {
    antinomie_service::server::frame::fuzz_entry(data);
});
