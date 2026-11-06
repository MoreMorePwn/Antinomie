// SPDX-License-Identifier: GPL-3.0-only
use super::*;

/// A real `get_info` reply for a Mirai/Prometei ELF, trimmed, with every null.
const REAL: &[u8] = include_bytes!("../../tests/fixtures/mb_get_info_mirai.json");

#[test]
fn the_real_reply_parses_and_keeps_what_the_window_shows() {
    let found = parse_reply(REAL).unwrap();
    assert_eq!(found.len(), 1);
    let sample = &found[0];
    assert_eq!(
        sample.sha256_hash,
        "dcafcf1e34c55497ff3f71f2bdfc25107613762aab2a228708885035b65fc3b2"
    );
    assert_eq!(sample.signature.as_deref(), Some("Mirai"));
    assert_eq!(sample.tags, ["elf", "Mirai", "Prometei"]);
    assert_eq!(sample.file_size, 1_288_875);
    assert!(sample.may_run());
    let intel = sample.intel.as_ref().unwrap();
    assert_eq!(
        intel.clamav,
        [
            "Unix.Trojan.Prometei-10045451-0",
            "Unix.Trojan.Prometei-10045459-0"
        ]
    );
    assert_eq!(intel.triage_family.as_deref(), Some("prometei_elf"));
    assert_eq!(intel.last_seen, None);
    assert_eq!(intel.comment, None);
    // The rule with no author, description or reference is kept by name.
    let bare = intel
        .yara
        .iter()
        .find(|rule| rule.rule_name == "malwareelf55503")
        .unwrap();
    assert!(bare.author.is_none() && bare.description.is_none() && bare.reference.is_none());
    // Vendors of every shape are listed: objects, a list, a null inside.
    for vendor in ["Triage", "Spamhaus_HBL", "Intezer", "CERT-PL_MWDB"] {
        assert!(intel.vendors.iter().any(|name| name == vendor), "{vendor}");
    }
    let text = sample.partner_text().unwrap();
    for part in [
        "Mirai",
        "elf, Mirai, Prometei",
        "Unix.Trojan.Prometei-10045451-0",
        "Triage family: prometei_elf",
    ] {
        assert!(text.contains(part), "{text}");
    }
}

#[test]
fn a_reply_with_every_optional_field_null_still_parses() {
    let body = br#"{"query_status":"ok","data":[{
        "sha256_hash":"ab","sha1_hash":null,"md5_hash":null,"first_seen":null,
        "last_seen":null,"file_name":null,"file_size":null,"file_type_mime":null,
        "file_type":null,"file_arch":null,"reporter":null,"signature":null,
        "imphash":null,"gimphash":null,"dhash_icon":null,"comment":null,
        "archive_pw":null,"tags":null,"code_sign":null,"delivery_method":null,
        "intelligence":{"clamav":null,"downloads":null,"uploads":null,"mail":null},
        "file_information":null,"ole_information":null,"yara_rules":null,
        "vendor_intel":null,"comments":null,"trid":null}]}"#;
    let found = parse_reply(body).unwrap();
    assert_eq!(found.len(), 1);
    let sample = &found[0];
    assert_eq!(sample.sha256_hash, "ab");
    assert!(sample.signature.is_none() && sample.tags.is_empty());
    assert!(sample.file_name.is_empty() && sample.file_size == 0);
    assert!(sample.intel.is_none() && sample.partner_text().is_none());
}

#[test]
fn unknown_vendors_and_shapes_do_not_fail_the_lookup() {
    let body = br#"{"query_status":"ok","data":[{"sha256_hash":"cd","signature":"Gafgyt",
        "vendor_intel":{
            "Triage":{"malware_family":7,"score":null},
            "NewVendor":{"a":{"b":[1,2,{"c":null}]}},
            "Listy":[1,"two",null],
            "Plain":"text","Gone":null,"Flag":true},
        "yara_rules":[{"rule_name":"r1","author":3},"junk",{"author":"x"}],
        "intelligence":{"clamav":["A",null,5]}}]}"#;
    let found = parse_reply(body).unwrap();
    let intel = found[0].intel.as_ref().unwrap();
    assert_eq!(intel.triage_family.as_deref(), Some("7"));
    assert!(intel.triage_score.is_none());
    assert_eq!(intel.clamav, ["A", "5"]);
    assert_eq!(intel.yara.len(), 1);
    assert_eq!(intel.yara[0].author.as_deref(), Some("3"));
    assert!(intel.vendors.iter().any(|name| name == "NewVendor"));
    assert!(!intel.vendors.iter().any(|name| name == "Gone"));
    assert_eq!(found[0].signature.as_deref(), Some("Gafgyt"));
}

#[test]
fn a_record_of_the_wrong_type_is_dropped_not_fatal() {
    let body = br#"{"query_status":"ok","data":[1,null,{"sha256_hash":"ef","file_size":"42"}]}"#;
    let found = parse_reply(body).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].file_size, 42);
    assert!(
        parse_reply(br#"{"query_status":"ok","data":"odd"}"#)
            .unwrap()
            .is_empty()
    );
}
