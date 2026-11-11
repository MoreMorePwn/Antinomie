// SPDX-License-Identifier: GPL-3.0-only
#![no_main]
use libfuzzer_sys::fuzz_target;

// Names from watch folders, uploads and policy folders (crates/service/src/watch/, intake/).
fuzz_target!(|data: &[u8]| {
    antinomie_service::fuzz_entry::watch_names(data);
});
