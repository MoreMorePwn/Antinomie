// SPDX-License-Identifier: GPL-3.0-only
#![no_main]
use libfuzzer_sys::fuzz_target;

// The label expression grammar of a policy's verdict rules (crates/service/src/verdict/expr.rs).
fuzz_target!(|data: &[u8]| {
    antinomie_service::fuzz_entry::label_expr(data);
});
