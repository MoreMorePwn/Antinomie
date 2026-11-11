// SPDX-License-Identifier: GPL-3.0-only
//! The Test button of Tools > API keys against a fake MalwareBazaar on
//! 127.0.0.1. No real key and no network beyond loopback.
use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

const KEY: &str = "fakekey0123456789";

/// Serves one canned HTTP answer per connection and records each request.
fn server(status: &str, body: &str) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/api/v1/", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let answer = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = stream.read(&mut chunk).unwrap_or(0);
                request.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&request).to_string();
                if let Some((head, rest)) = text.split_once("\r\n\r\n") {
                    let want = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if rest.len() >= want {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            log.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&request).to_string());
            let _ = stream.write_all(answer.as_bytes());
        }
    });
    (url, seen)
}

fn check(status: &str, body: &str) -> (Result<(), String>, Vec<String>) {
    let (url, seen) = server(status, body);
    let result = check_key_at(&url, Path::new("curl"), KEY, &AtomicBool::new(false));
    let seen = seen.lock().unwrap().clone();
    (result, seen)
}

#[test]
fn a_valid_key_passes_whatever_the_probe_hash_answers() {
    for body in [
        r#"{"query_status":"hash_not_found"}"#,
        r#"{"query_status":"no_results"}"#,
        r#"{"query_status":"ok","data":[]}"#,
    ] {
        let (result, _) = check("200 OK", body);
        assert_eq!(result, Ok(()), "{body}");
    }
}

#[test]
fn the_test_sends_the_same_hash_lookup_as_an_import_with_the_key_in_a_header() {
    let (result, seen) = check("200 OK", r#"{"query_status":"hash_not_found"}"#);
    assert!(result.is_ok());
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    assert!(request.starts_with("POST /api/v1/ "), "{request}");
    assert!(request.contains(&format!("Auth-Key: {KEY}")));
    assert!(request.contains("query=get_info"));
    assert!(request.contains(&format!("hash={PROBE_HASH}")));
    assert!(!request.contains("get_taginfo"));
}

#[test]
fn a_refused_key_fails_in_words_without_the_key() {
    for status in ["wrong_auth_key", "unknown_auth_key", "user_blacklisted"] {
        let (result, _) = check("200 OK", &format!(r#"{{"query_status":"{status}"}}"#));
        let error = result.unwrap_err();
        assert_eq!(error, "MalwareBazaar refused the API key", "{status}");
        assert!(!error.contains(KEY));
    }
}

#[test]
fn http_errors_and_html_pages_are_failures() {
    let (result, _) = check("503 Service Unavailable", "<html>busy</html>");
    assert!(result.unwrap_err().contains("not JSON"));
    let (result, _) = check(
        "200 OK",
        r#"{"query_status":"unknown_error","data":"Query execution time exceeded threshold."}"#,
    );
    assert!(result.unwrap_err().contains("exceeded"));
}

#[test]
fn the_api_keys_test_goes_through_the_hash_probe_not_a_tag_listing() {
    // The old probe asked for the busiest tag; it is gone from the Test path.
    let source = include_str!("../api_keys.rs");
    let body = source.split("pub fn test(").nth(1).unwrap();
    assert!(body.contains("samples::check_key"));
    assert!(!body.contains("Query::Tag"));
}
