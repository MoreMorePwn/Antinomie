// SPDX-License-Identifier: GPL-3.0-only
//! `ioc datasets` through the built binary (ANT-T0548 F2b). abuse.ch is a
//! stand-in `curl` first and alone on PATH: it serves small files in the
//! datasets' real formats from the scratch folder, records its arguments and
//! the URL it was handed on standard input, and never reaches a network. The
//! key is a fake of the right shape that no service knows.
use antinomie_monitor_core::ioc::{
    feeds, indicator::Collector, indicator::Seen, indicator::Source,
};
use serde_json::Value;
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const KEY: &str = "fake-ioc-key-for-tests-7c2e";

const THREATFOX: &str = "# \"first_seen_utc\", \"ioc_id\", \"ioc_value\", \"ioc_type\", \"threat_type\", \"fk_malware\", \"malware_alias\", \"malware_printable\", \"last_seen_utc\", \"confidence_level\", \"reference\", \"tags\", \"anonymous\", \"reporter\"\n\
\"2026-09-02 10:11:13\", \"1831207\", \"c2.update-cdn.example\", \"domain\", \"botnet_cc\", \"elf.mirai\", \"\", \"Mirai\", \"\", \"75\", \"None\", \"mirai\", \"0\", \"reporter1\"\n\
\"2026-09-02 10:11:12\", \"1831204\", \"203.0.113.45:443\", \"ip:port\", \"botnet_cc\", \"elf.mirai\", \"\", \"Mirai\", \"\", \"75\", \"None\", \"mirai\", \"0\", \"reporter1\"\n";
const URLHAUS: &str = "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n\
\"3350918\",\"2026-10-11 08:00:00\",\"http://198.51.100.77/x\",\"online\",\"2026-10-12 08:00:00\",\"malware_download\",\"mirai,elf\",\"https://urlhaus.abuse.ch/url/3350918/\",\"r\"\n";
const PAYLOADS: &str = "# firstseen,url,filetype,md5,sha256,signature\n\
\"2026-10-11 08:00:02\",\"http://cdn.fastmirror.example/bin/x86_64/.kd\",\"elf\",\"87221652a79fc3c9b04cde0b335fdd5b\",\"f66025c51e65b02ffdaf55ea9460656a0b79598cb7db1514dc7a23a81b4cf1aa\",\"Mirai\"\n";
const FEODO: &str = "[{\"ip_address\":\"203.0.113.45\",\"port\":443,\"status\":\"online\",\"first_seen\":\"2026-08-01 00:00:00\",\"malware\":\"Dridex\"}]";
const JA3: &str = "# ja3_md5,Firstseen,Lastseen,Listingreason\n\
f6d64cbcb6dead5e8e864400f056fa32,2026-08-19 10:00:00,2026-10-01 10:00:00,Gafgyt C&C\n";
const CERT: &str = "# Listingdate,SHA1,Listingreason\n\
2026-08-19 10:00:00,2f22765d04931a078909145ca628d2264c852d7d,Gafgyt C&C\n";

/// The stand-in abuse.ch: what each URL serves, by `<host>_<file name>`.
const SERVED: [(&str, &str); 6] = [
    ("threatfox-api.abuse.ch_full.csv.zip", THREATFOX),
    ("urlhaus-api.abuse.ch_full.csv.zip", URLHAUS),
    ("urlhaus-api.abuse.ch_payload.csv.zip", PAYLOADS),
    ("feodotracker.abuse.ch_ipblocklist.json", FEODO),
    ("sslbl.abuse.ch_ja3_fingerprints.csv", JA3),
    ("sslbl.abuse.ch_sslblacklist.csv", CERT),
];

struct Node {
    root: PathBuf,
    data: PathBuf,
    bin: PathBuf,
    served: PathBuf,
}

impl Node {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("ant-cli-ioc-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (data, bin, served) = (root.join("data"), root.join("bin"), root.join("served"));
        for dir in [&data, &bin, &served] {
            std::fs::create_dir_all(dir).unwrap();
        }
        for (name, text) in SERVED {
            std::fs::write(served.join(name), text).unwrap();
        }
        let node = Self {
            root,
            data,
            bin,
            served,
        };
        node.fake_curl();
        node
    }

    /// A `curl` that answers a HEAD with the file's length and a download
    /// with the file, or 404 for a file it does not serve (its HEAD says 7
    /// bytes, so the free-space check is not what fails). Only shell
    /// built-ins and absolute paths: PATH holds nothing else.
    fn fake_curl(&self) {
        let tool = |name: &str| {
            ["/usr/bin", "/bin"]
                .iter()
                .map(|dir| Path::new(dir).join(name))
                .find(|path| path.exists())
                .unwrap()
                .display()
                .to_string()
        };
        let script = self.bin.join("curl");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n\
                 out=; prev=; head=no\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$prev\" = --output ]; then out=$arg; fi\n\
                   if [ \"$arg\" = --head ]; then head=yes; fi\n\
                   prev=$arg\n\
                 done\n\
                 printf '%s\\n' \"$@\" >> '{log}/args.txt'\n\
                 IFS= read -r line\n\
                 printf '%s\\n' \"$line\" >> '{log}/stdin.txt'\n\
                 url=${{line#url = \\\"}}; url=${{url%\\\"}}\n\
                 host=${{url#https://}}; host=${{host%%/*}}\n\
                 body='{served}'/\"${{host}}_${{url##*/}}\"\n\
                 if [ $head = yes ]; then\n\
                   if [ -f \"$body\" ]; then\n\
                     printf 'HTTP/1.1 200 OK\\r\\nContent-Length: %s\\r\\n\\r\\n' $({wc} -c < \"$body\")\n\
                   else\n\
                     printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 7\\r\\n\\r\\n'\n\
                   fi\n\
                   exit 0\n\
                 fi\n\
                 if [ -f \"$body\" ]; then {cp} \"$body\" \"$out\"; printf '200 '; else printf 'nothing' > \"$out\"; printf '404 '; fi\n",
                log = self.root.display(),
                served = self.served.display(),
                wc = tool("wc"),
                cp = tool("cp"),
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Run the CLI with the stand-in alone on PATH; returns the exit code, the
    /// JSON document and both streams. No output may hold the key.
    fn cli(&self, format: &str, tail: &[&str], input: &str) -> (i32, Value, String) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_antinomie-cli"))
            .env("PATH", &self.bin)
            .env_remove("http_proxy")
            .env_remove("https_proxy")
            .env_remove("HTTPS_PROXY")
            .args(["-o", format, "--data-dir", self.data.to_str().unwrap()])
            .args(tail)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("antinomie-cli runs");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!text.contains(KEY), "the key was printed: {text}");
        let value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
        (output.status.code().unwrap_or(-1), value, text)
    }

    fn json(&self, tail: &[&str]) -> (i32, Value) {
        let (code, value, _) = self.cli("json", tail, "");
        (code, value)
    }

    fn requests(&self) -> String {
        std::fs::read_to_string(self.root.join("stdin.txt")).unwrap_or_default()
    }

    fn allow_downloads(&self) {
        let (code, set) = self.json(&["config", "set", "outbound_catalog", "true"]);
        assert_eq!(code, 0, "{set}");
    }

    fn store_key(&self) {
        let (code, _, _) = self.cli(
            "json",
            &["config", "api-key", "set", "abusech"],
            &format!("{KEY}\n"),
        );
        assert_eq!(code, 0);
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn update_refuses_before_any_request_while_downloads_are_off_or_a_needed_key_is_missing() {
    let node = Node::new("refuse");
    // Downloads are off until the person allows them, as in the window.
    let (code, off) = node.json(&["ioc", "datasets", "update"]);
    assert_eq!(code, 5, "{off}");
    assert_eq!(off["error"]["code"], "unavailable_on_node");
    assert_eq!(off["error"]["details"]["what"], "outbound_catalog");
    node.allow_downloads();
    // No key: the three datasets that need it are named, nothing is asked.
    let (code, nokey) = node.json(&["ioc", "datasets", "update"]);
    assert_eq!(code, 5, "{nokey}");
    assert_eq!(nokey["error"]["details"]["what"], "abusech_key");
    assert_eq!(
        nokey["error"]["details"]["needs_key"],
        serde_json::json!(["threatfox", "urlhaus", "urlhaus-payloads"])
    );
    let message = nokey["error"]["message"].as_str().unwrap();
    assert!(message.contains("config api-key set abusech"), "{message}");
    assert!(
        message.contains("ioc datasets update feodo sslbl-ja3 sslbl-cert"),
        "{message}"
    );
    assert_eq!(node.requests(), "", "no request without the key");
    // Unknown and switched-off names are refused before anything is asked.
    assert_eq!(node.json(&["ioc", "datasets", "update", "nope"]).0, 3);
    assert_eq!(
        node.json(&["ioc", "datasets", "update", "urlhaus-recent"])
            .0,
        4
    );
    assert_eq!(node.requests(), "");
    // The datasets that need no key can be fetched without one.
    let (code, free) = node.json(&["ioc", "datasets", "update", "feodo", "sslbl-ja3"]);
    assert_eq!(code, 0, "{free}");
    assert_eq!(free["result"]["updated"], 2);
    // Nothing was written for the datasets that were not asked for.
    let (_, list) = node.json(&["ioc", "datasets", "list"]);
    let states: Vec<(&str, &str)> = list["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| (i["name"].as_str().unwrap(), i["state"].as_str().unwrap()))
        .collect();
    assert_eq!(
        states,
        [
            ("threatfox", "not_downloaded"),
            ("urlhaus", "not_downloaded"),
            ("urlhaus-payloads", "not_downloaded"),
            ("feodo", "loaded"),
            ("sslbl-ja3", "loaded"),
            ("sslbl-cert", "not_downloaded"),
            ("urlhaus-recent", "off"),
        ]
    );
}

#[test]
fn update_downloads_into_the_folder_the_window_reads_with_the_key_on_stdin_only() {
    let node = Node::new("download");
    node.allow_downloads();
    node.store_key();
    let (code, value, text) = node.cli("json", &["-v", "ioc", "datasets", "update"], "");
    assert_eq!(code, 0, "{text}");
    assert_eq!(value["result"]["updated"], 6, "{value}");
    assert_eq!(value["result"]["failed"], 0);
    assert!(
        text.contains("Downloading ThreatFox"),
        "progress on stderr: {text}"
    );
    // The window's folder and files: `<data>/ioc/feeds/<name>/meta.json` and
    // the data file it names; the core reads them as the window does.
    let statuses = feeds::status(&node.data);
    assert!(
        statuses
            .iter()
            .filter(|s| s.feed.default_on)
            .all(|s| s.usable()),
        "{statuses:?}"
    );
    assert!(node.data.join("ioc/feeds/threatfox/meta.json").is_file());
    let meta = std::fs::read_to_string(node.data.join("ioc/feeds/threatfox/meta.json")).unwrap();
    assert!(
        meta.contains("/exports/****/") && !meta.contains(KEY),
        "{meta}"
    );
    // A run's indicator is matched against them (what Triage and the daemon do).
    let mut c = Collector::default();
    c.domain(
        "c2.update-cdn.example",
        antinomie_monitor_core::ioc::indicator::Via::Dns,
        &[],
        Source::Pcap,
        Seen::default(),
    );
    let scan = antinomie_monitor_core::ioc::verdict::scan_datasets(
        &node.data,
        &c.finish(),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(scan.loaded.len(), 6);
    assert!(!scan.hits.is_empty(), "the ThreatFox record matches");
    // The key went to curl on standard input, never as an argument.
    let args = std::fs::read_to_string(node.root.join("args.txt")).unwrap();
    assert!(!args.contains(KEY) && !args.contains("https://"), "{args}");
    assert!(
        node.requests()
            .contains(&format!("/exports/{KEY}/full.csv.zip"))
    );
    assert!(
        antinomie_monitor_core::api_keys::last_used(
            &node.data,
            antinomie_monitor_core::api_keys::ApiKey::Abusech
        )
        .is_some()
    );
    // The list in both formats.
    let (code, list) = node.json(&["ioc", "datasets", "list"]);
    assert_eq!(code, 0);
    let first = &list["result"]["items"][0];
    assert_eq!(first["name"], "threatfox");
    assert_eq!(first["state"], "loaded");
    assert_eq!(first["records"], 2);
    assert_eq!(first["needs_key"], true);
    let (code, _, human) = node.cli("human", &["ioc", "datasets", "list"], "");
    assert_eq!(code, 0);
    assert!(
        human.contains("abuse.ch Auth-Key: stored (…7c2e)"),
        "{human}"
    );
    assert!(human.contains("6 in use"), "{human}");
}

#[test]
fn a_failed_download_keeps_the_previous_copy_and_says_so_without_the_key() {
    let node = Node::new("failed");
    node.allow_downloads();
    node.store_key();
    assert_eq!(node.json(&["ioc", "datasets", "update"]).0, 0);
    let before = std::fs::read_to_string(node.data.join("ioc/feeds/urlhaus/meta.json")).unwrap();
    // URLhaus now answers 404 and SSLBL sends a page instead of its list.
    std::fs::remove_file(node.served.join("urlhaus-api.abuse.ch_full.csv.zip")).unwrap();
    std::fs::write(
        node.served.join("sslbl.abuse.ch_sslblacklist.csv"),
        "<html>429 Too Many Requests</html>",
    )
    .unwrap();
    let (code, value, text) = node.cli("json", &["ioc", "datasets", "update"], "");
    assert_eq!(code, 21, "{text}");
    let error = &value["error"];
    assert_eq!(error["code"], "unavailable");
    assert_eq!(error["retryable"], true);
    assert_eq!(error["details"]["updated"], 4);
    assert_eq!(error["details"]["failed"], 2);
    let message = error["message"].as_str().unwrap();
    assert!(message.contains("URLhaus dump"), "{message}");
    assert!(message.contains("/exports/****/"), "{message}");
    assert!(message.contains("previous copies were kept"), "{message}");
    let after = std::fs::read_to_string(node.data.join("ioc/feeds/urlhaus/meta.json")).unwrap();
    assert_eq!(before, after, "the previous copy is untouched");
    // The window's failure note is kept with the dataset, without the key.
    let (_, list) = node.json(&["ioc", "datasets", "list"]);
    let urlhaus = &list["result"]["items"][1];
    assert_eq!(urlhaus["state"], "update_failed");
    assert!(
        !std::fs::read_to_string(node.data.join("ioc/feeds/urlhaus/last-error.json"))
            .unwrap()
            .contains(KEY)
    );
    // A dataset switched off is left out of the next update, and back on.
    let (code, off) = node.json(&["ioc", "datasets", "disable", "urlhaus"]);
    assert_eq!(code, 0, "{off}");
    let (code, _, text) = node.cli("json", &["ioc", "datasets", "update"], "");
    assert_eq!(code, 21, "SSLBL still fails: {text}");
    assert!(!text.contains("URLhaus dump"), "{text}");
    assert_eq!(node.json(&["ioc", "datasets", "enable", "urlhaus"]).0, 0);
    assert_eq!(node.json(&["ioc", "datasets", "enable", "nope"]).0, 3);
}
