// SPDX-License-Identifier: GPL-3.0-only
#![no_main]
use libfuzzer_sys::fuzz_target;

// The recording read API's client inputs: the Triage filter language of `q`
// (crates/triage/src/query.rs), paging cursors, field ids, run keys and the
// operation parameters (crates/service/src/query/{cursor,convert,request}.rs).
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let compiled = antinomie_triage::query::compile_note(text);
    let _ = compiled.error.is_some();
    let _ = antinomie_triage::query::structured(text);
    let _ = antinomie_service::query::cursor::Cursor::decode(text);
    let _ = antinomie_service::query::convert::parse_field_id(text);
    if let Some((op, params)) = text.split_once('\n') {
        if let Ok(value) = serde_json::from_str(params) {
            let _ = antinomie_service::query::request::RecordingRead::parse(op, value);
        }
    }
});
