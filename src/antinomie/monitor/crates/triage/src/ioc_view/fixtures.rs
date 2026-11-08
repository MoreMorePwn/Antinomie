// SPDX-License-Identifier: GPL-3.0-only
//! A run with a fixture capture and small fixture datasets served by a mock
//! (no network), for the IOC tests here and in the GUI crate.
use super::*;
use crate::archive_scan::scan_archive_query;
use crate::tests::{http_pcap, write_rwx_calls};
use antinomie_monitor_core::{
    api_keys::Secret,
    ioc::{feeds, update_all},
    ruleset::Fetcher,
};

// The fixture capture is a GET of http://example.com/ to 93.184.216.34:80.
pub const THREATFOX: &str = "# \"first_seen_utc\", \"ioc_id\", \"ioc_value\", \"ioc_type\", \"threat_type\", \"fk_malware\", \"malware_alias\", \"malware_printable\", \"last_seen_utc\", \"confidence_level\"\n\"2026-09-02 10:11:12\", \"1831204\", \"93.184.216.34:80\", \"ip:port\", \"botnet_cc\", \"elf.mirai\", \"\", \"Mirai\", \"\", \"75\"\n";
pub const URLHAUS: &str = "# id,dateadded,url,url_status,last_online,threat,tags\n\"3350918\",\"2026-10-11 08:00:00\",\"http://example.com/\",\"online\",\"\",\"malware_download\",\"mirai,elf\"\n";
pub const PAYLOADS: &str = "# firstseen,url,filetype,md5,sha256,signature\n\"2026-10-11 08:00:02\",\"http://x.example/a\",\"elf\",\"87221652a79fc3c9b04cde0b335fdd5b\",\"f66025c51e65b02ffdaf55ea9460656a0b79598cb7db1514dc7a23a81b4cf1aa\",\"Mirai\"\n";
pub const FEODO: &str = "[{\"ip_address\":\"203.0.113.45\",\"port\":443,\"status\":\"online\",\"first_seen\":\"2026-08-01 00:00:00\",\"malware\":\"Dridex\"}]";
pub const SSLBL_JA3: &str = "# ja3_md5,Firstseen,Lastseen,Listingreason\nf6d64cbcb6dead5e8e864400f056fa32,2026-08-19 10:00:00,2026-10-01 10:00:00,Gafgyt C&C\n";
pub const SSLBL_CERT: &str = "# Listingdate,SHA1,Listingreason\n2026-08-19 10:00:00,2f22765d04931a078909145ca628d2264c852d7d,Gafgyt C&C\n";

pub struct Served;

impl Fetcher for Served {
    fn fetch(
        &self,
        url: &str,
        dest: &Path,
        _max: u64,
        _cancel: &AtomicBool,
        _progress: &mut dyn FnMut(u64),
    ) -> Result<(), String> {
        let feed = feeds::FEEDS.iter().find(|feed| feed.owns(url)).unwrap();
        let text = match feed.id {
            "threatfox" => THREATFOX,
            "urlhaus" => URLHAUS,
            "urlhaus-payloads" => PAYLOADS,
            "feodo" => FEODO,
            "sslbl-ja3" => SSLBL_JA3,
            _ => SSLBL_CERT,
        };
        std::fs::write(dest, text).map_err(|error| error.to_string())
    }
}

pub fn tshark() -> bool {
    std::process::Command::new("tshark")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

pub struct Fixture {
    pub run: PacketSpool,
    pub data: std::path::PathBuf,
}

impl Fixture {
    pub fn new(datasets: bool) -> Self {
        let run = PacketSpool::new().unwrap();
        let mut raw = Vec::new();
        write_rwx_calls(&mut raw, 0..1);
        std::fs::write(run.directory.join("telemetry.raw"), raw).unwrap();
        std::fs::write(run.directory.join("fixture.pcap"), http_pcap()).unwrap();
        let data = std::env::temp_dir().join(format!(
            "ant-ioc-triage-{}-{}",
            std::process::id(),
            antinomie_monitor_core::storage::sha256_hex(run.directory.to_string_lossy().as_bytes())
                [..8]
                .to_owned()
        ));
        let _ = std::fs::remove_dir_all(&data);
        std::fs::create_dir_all(&data).unwrap();
        if datasets {
            let outcomes = update_all(
                &data,
                &Secret::new("fixture-key"),
                &Served,
                &AtomicBool::new(false),
                &mut |_| {},
            );
            assert!(outcomes.iter().all(|outcome| outcome.result.is_ok()));
        }
        Self { run, data }
    }

    pub fn scan(&self, cache: Option<ioc_scan::Cache>) -> ArchiveScan {
        let request = ScanRequest {
            root_cookie: 55,
            data_dir: Some(self.data.clone()),
            ioc_cache: cache,
            ..ScanRequest::default()
        };
        scan_archive_query(
            &self.run.directory,
            Some(&self.run.directory.join("fixture.pcap")),
            false,
            &Arc::new(AtomicBool::new(false)),
            &request,
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.data);
    }
}

pub fn find<'a>(scan: &'a ioc_scan::IocScan, ty: Type, key: &str) -> (usize, &'a Indicator) {
    scan.indicators
        .iter()
        .enumerate()
        .find(|(_, i)| i.ty == ty && i.key.contains(key))
        .unwrap_or_else(|| {
            panic!(
                "no {ty:?} {key} in {:?}",
                scan.indicators.iter().map(|i| &i.key).collect::<Vec<_>>()
            )
        })
}
