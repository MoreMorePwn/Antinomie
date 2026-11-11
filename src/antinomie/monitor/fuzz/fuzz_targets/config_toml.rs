// SPDX-License-Identifier: GPL-3.0-only
#![no_main]
use libfuzzer_sys::fuzz_target;

// Policy and service TOML, including the verdict rules' expressions (crates/service/src/config/).
fuzz_target!(|data: &[u8]| {
    antinomie_service::fuzz_entry::config_toml(data);
});
