// SPDX-License-Identifier: GPL-3.0-only
//! The fake cloud metadata service of a cloud VPS profile. A real instance
//! asks its provider's link-local metadata address (169.254.169.254,
//! Tencent's 169.254.0.23, Alibaba's 100.100.100.200) for its identity and
//! credentials; an instance with no answer there is a sandbox. The gateway
//! answers that address itself, on every route, from a thread per connection
//! over an in-process socket pair: nothing listens on the host and nothing
//! leaves it.
//!
//! The answers are the provider's layout with the instance id, region and
//! host name of the profile, and credentials that are canaries: fake values,
//! new for each run, that no cloud accepts. The service logs every request
//! and looks for the run's canary values in what the guest sends out by TCP
//! afterwards (a plain-text request, not TLS); both end up in
//! `cloud-metadata.json` in the run's folder, which Triage reads as findings
//! (T1552.005, unsecured credentials: cloud instance metadata API).
use crate::stealth::{CloudProvider, MetadataStyle, random_text};
use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::Ipv4Addr,
    os::unix::net::UnixStream,
    path::Path,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// The report's file name in a run's folder.
pub const REPORT: &str = "cloud-metadata.json";
const IDLE: Duration = Duration::from_secs(20);
const MAX_LINE: u64 = 8 * 1024;
const MAX_REQUESTS: usize = 64;
const MAX_EVENTS: usize = 2_000;
const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// Temporary credentials last six hours, as the providers' role credentials do.
const LIFETIME_S: u64 = 21_600;

/// The fake credentials of one run.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Canary {
    pub id: String,
    pub secret: String,
    pub token: String,
}

impl Canary {
    fn of(style: MetadataStyle) -> Self {
        let text = |len| random_text(ALPHABET, len);
        // The provider's own form, length and alphabet, and nothing else: a
        // marker in the value would tell a sample it is in a sandbox. The
        // run's report keeps the values, which is how Triage knows them.
        match style {
            MetadataStyle::Tencent => Self {
                id: format!("AKID{}", text(32)),
                secret: text(32),
                token: text(160),
            },
            MetadataStyle::Alibaba => Self {
                id: format!("STS.N{}", text(24)),
                secret: text(44),
                token: format!("CAIS{}", random_text(BASE64, 476)),
            },
            MetadataStyle::DigitalOcean => Self {
                id: format!("dop_v1_{}", random_text(b"0123456789abcdef", 64)),
                secret: String::new(),
                token: String::new(),
            },
            MetadataStyle::Vultr => Self {
                id: random_text(b"ABCDEFGHJKLMNPQRSTUVWXYZ234567", 36),
                secret: String::new(),
                token: String::new(),
            },
        }
    }

    fn values(&self) -> Vec<&str> {
        [&self.id, &self.secret, &self.token]
            .into_iter()
            .filter(|value| !value.is_empty())
            .map(String::as_str)
            .collect()
    }
}

/// One thing the service saw.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Event {
    /// Host Unix time, ms.
    pub ms: u64,
    /// `request`: a metadata request; `credentials`: the canary values were
    /// handed out; `canary-use`: they were sent to an address.
    pub kind: String,
    /// The request line, or the destination and the line holding the value.
    pub detail: String,
    /// What was asked of or sent to, `ip:port`.
    pub endpoint: String,
}

/// Everything a run's report holds.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Report {
    pub version: u32,
    pub provider: String,
    pub address: String,
    pub run: String,
    pub instance_id: String,
    pub canary: Canary,
    pub events: Vec<Event>,
}

struct State {
    run: String,
    canary: Canary,
    events: Vec<Event>,
}

/// The service of one VM: its provider's layout and the current run's state.
pub struct Service {
    provider: &'static CloudProvider,
    instance_id: String,
    hostname: String,
    ip: Ipv4Addr,
    state: Mutex<State>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// `YYYY-MM-DDTHH:MM:SSZ` for Unix seconds.
fn utc(unix: u64) -> String {
    let day = unix % 86_400;
    format!(
        "{}T{:02}:{:02}:{:02}Z",
        crate::ioc::feeds::date_text(unix),
        day / 3600,
        day % 3600 / 60,
        day % 60
    )
}

impl Service {
    /// The service for `provider`. The instance id and host name belong to the
    /// VM and stay the same for every run.
    pub fn new(provider: &'static CloudProvider, instance_id: &str, hostname: &str) -> Arc<Self> {
        Arc::new(Self {
            provider,
            instance_id: instance_id.into(),
            hostname: hostname.into(),
            ip: provider
                .metadata_ip
                .parse()
                .unwrap_or(Ipv4Addr::new(169, 254, 169, 254)),
            state: Mutex::new(State {
                run: String::new(),
                canary: Canary::of(provider.metadata),
                events: Vec::new(),
            }),
        })
    }

    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    /// The provider's metadata host name, if it has one.
    pub fn name(&self) -> &'static str {
        self.provider.metadata_name
    }

    /// A new run: new canary credentials and an empty log.
    pub fn begin_run(&self, run: &str) {
        let mut state = self.lock();
        state.run = run.into();
        state.canary = Canary::of(self.provider.metadata);
        state.events.clear();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn note(&self, kind: &str, detail: String, endpoint: String) {
        let mut state = self.lock();
        if state.events.len() < MAX_EVENTS {
            state.events.push(Event {
                ms: now_ms(),
                kind: kind.into(),
                detail,
                endpoint,
            });
        }
    }

    /// The guest's end of a connection to the service, which a thread serves.
    pub fn connect(self: &Arc<Self>) -> Result<UnixStream, String> {
        let (guest, service) =
            UnixStream::pair().map_err(|error| format!("metadata service: {error}"))?;
        service
            .set_read_timeout(Some(IDLE))
            .and_then(|()| service.set_write_timeout(Some(IDLE)))
            .map_err(|error| format!("metadata service: {error}"))?;
        let this = self.clone();
        thread::Builder::new()
            .name("route-metadata".into())
            .spawn(move || {
                let _ = this.serve(service);
            })
            .map_err(|error| format!("metadata service: {error}"))?;
        Ok(guest)
    }

    fn serve(&self, stream: UnixStream) -> std::io::Result<()> {
        let mut writer = stream.try_clone()?;
        let mut reader = BufReader::new(stream);
        for _ in 0..MAX_REQUESTS {
            let Some(request) = read_line(&mut reader)? else {
                return Ok(());
            };
            if request.is_empty() {
                continue;
            }
            let mut parts = request.split_whitespace();
            let method = parts.next().unwrap_or("").to_ascii_uppercase();
            let target = parts.next().unwrap_or("/").to_owned();
            let mut close = parts.next() == Some("HTTP/1.0");
            let mut length = 0u64;
            let mut host = String::new();
            loop {
                let Some(header) = read_line(&mut reader)? else {
                    return Ok(());
                };
                if header.is_empty() {
                    break;
                }
                if let Some((name, value)) = header.split_once(':') {
                    match name.trim().to_ascii_lowercase().as_str() {
                        "content-length" => length = value.trim().parse().unwrap_or(0),
                        "connection" => close = value.trim().eq_ignore_ascii_case("close"),
                        "host" => host = value.trim().to_owned(),
                        _ => {}
                    }
                }
            }
            if length > 64 * 1024 {
                return Ok(());
            }
            std::io::copy(&mut (&mut reader).take(length), &mut std::io::sink())?;
            let path = target.split(['?', '#']).next().unwrap_or("/");
            let endpoint = format!("{}:80", self.ip);
            self.note(
                "request",
                format!(
                    "{method} {target}{}",
                    if host.is_empty() {
                        String::new()
                    } else {
                        format!(" (Host: {host})")
                    }
                ),
                endpoint.clone(),
            );
            let (status, kind, body, handed) = self.answer(&method, path);
            if handed {
                self.note("credentials", format!("{method} {path}"), endpoint);
            }
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
                body.len(),
                if close { "close" } else { "keep-alive" }
            );
            writer.write_all(head.as_bytes())?;
            if method != "HEAD" {
                writer.write_all(body.as_bytes())?;
            }
            if close {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Status, content type, body and whether the canary values were in it.
    fn answer(&self, method: &str, path: &str) -> (&'static str, &'static str, String, bool) {
        if !matches!(method, "GET" | "HEAD") {
            return ("405 Method Not Allowed", "text/plain", String::new(), false);
        }
        let state = self.lock();
        let found = match self.provider.metadata {
            MetadataStyle::Tencent => self.tencent(path, &state.canary),
            MetadataStyle::Alibaba => self.alibaba(path, &state.canary),
            MetadataStyle::DigitalOcean => self.digitalocean(path, &state.canary),
            MetadataStyle::Vultr => self.vultr(path, &state.canary),
        };
        match found {
            Some((kind, body)) => {
                let handed = state
                    .canary
                    .values()
                    .iter()
                    .any(|value| body.contains(value));
                ("200 OK", kind, body, handed)
            }
            None => (
                "404 Not Found",
                "text/plain",
                "404 - Not Found\n".into(),
                false,
            ),
        }
    }

    fn region(&self) -> &'static str {
        self.provider.state.region
    }

    fn private_ip(&self) -> String {
        // The guest's DHCP address, which the provider's network names.
        self.provider.nat.3.to_owned()
    }

    fn tencent(&self, path: &str, canary: &Canary) -> Option<(&'static str, String)> {
        let text = |body: String| Some(("text/plain", body));
        let path = path.trim_end_matches('/');
        let (version, rest) = match path.strip_prefix("/latest") {
            Some(rest) => ("latest", rest),
            None => match path.strip_prefix("/meta-data") {
                Some(_) => ("latest", path),
                None => ("", path),
            },
        };
        match (version, rest) {
            ("", "") => text("1.0\n2017-03-12\nlatest\n".into()),
            ("latest", "") => text("meta-data\nuser-data\n".into()),
            ("latest", "/meta-data") => text(
                "app-id\ninstance-id\ninstance-name\nlocal-ipv4\nmac\nplacement/\nuuid\ncam/\n"
                    .into(),
            ),
            ("latest", "/meta-data/instance-id") => text(self.instance_id.clone()),
            ("latest", "/meta-data/instance-name") => text(self.hostname.clone()),
            ("latest", "/meta-data/local-ipv4") => text(self.private_ip()),
            ("latest", "/meta-data/uuid") => text(self.instance_id.clone()),
            ("latest", "/meta-data/placement/region") => text(self.region().into()),
            ("latest", "/meta-data/placement/zone") => text(format!("{}-3", self.region())),
            ("latest", "/meta-data/cam/security-credentials") => text("CVMRole".into()),
            ("latest", "/meta-data/cam/security-credentials/CVMRole") => Some((
                "application/json",
                format!(
                    "{{\n  \"TmpSecretId\": \"{}\",\n  \"TmpSecretKey\": \"{}\",\n  \"ExpiredTime\": {},\n  \"Expiration\": \"{}\",\n  \"Token\": \"{}\",\n  \"Code\": \"Success\"\n}}",
                    canary.id,
                    canary.secret,
                    now_ms() / 1000 + LIFETIME_S,
                    utc(now_ms() / 1000 + LIFETIME_S),
                    canary.token
                ),
            )),
            ("latest", "/user-data") => text("#!/bin/sh\n# first boot\napt-get update\n".into()),
            _ => None,
        }
    }

    fn alibaba(&self, path: &str, canary: &Canary) -> Option<(&'static str, String)> {
        let text = |body: String| Some(("text/plain", body));
        let path = path.trim_end_matches('/');
        let rest = path.strip_prefix("/latest").unwrap_or(path);
        match rest {
            "" => text("meta-data\nuser-data\ndynamic\n".into()),
            "/meta-data" => text(
                "hostname\ninstance-id\nimage-id\nmac\nnetwork/\nprivate-ipv4\nregion-id\nzone-id\nram/\ninstance/\n"
                    .into(),
            ),
            "/meta-data/instance-id" => text(self.instance_id.clone()),
            "/meta-data/hostname" => text(self.hostname.clone()),
            "/meta-data/region-id" => text(self.region().into()),
            "/meta-data/zone-id" => text(format!("{}-h", self.region())),
            "/meta-data/private-ipv4" => text(self.private_ip()),
            "/meta-data/image-id" => text("ubuntu_22_04_x64_20G_alibase_20240101.vhd".into()),
            "/meta-data/ram/security-credentials" => text("EcsRamRole".into()),
            "/meta-data/ram/security-credentials/EcsRamRole" => Some((
                "application/json",
                format!(
                    "{{\n  \"AccessKeyId\" : \"{}\",\n  \"AccessKeySecret\" : \"{}\",\n  \"Expiration\" : \"{}\",\n  \"SecurityToken\" : \"{}\",\n  \"LastUpdated\" : \"{}\",\n  \"Code\" : \"Success\"\n}}",
                    canary.id,
                    canary.secret,
                    utc(now_ms() / 1000 + LIFETIME_S),
                    canary.token,
                    utc(now_ms() / 1000)
                ),
            )),
            "/user-data" => text("#!/bin/sh\n# first boot\n".into()),
            _ => None,
        }
    }

    fn digitalocean(&self, path: &str, canary: &Canary) -> Option<(&'static str, String)> {
        let user_data = format!(
            "#cloud-config\npackage_update: true\nwrite_files:\n  - path: /root/.env\n    content: |\n      DIGITALOCEAN_ACCESS_TOKEN={}\n",
            canary.id
        );
        let text = |body: String| Some(("text/plain", body));
        let path = path.trim_end_matches('/');
        match path {
            "" | "/metadata" => text("v1.json\nv1/\n".into()),
            "/metadata/v1.json" => Some((
                "application/json",
                format!(
                    "{{\"droplet_id\":{},\"hostname\":\"{}\",\"user_data\":{},\"region\":\"{}\",\"public_keys\":[],\"tags\":[],\"features\":{{\"dhcp_enabled\":false}},\"interfaces\":{{\"private\":[{{\"ipv4\":{{\"ip_address\":\"{}\",\"netmask\":\"255.255.240.0\",\"gateway\":\"{}\"}}}}]}}}}",
                    self.instance_id,
                    self.hostname,
                    serde_json::Value::String(user_data),
                    self.region(),
                    self.private_ip(),
                    self.provider.nat.1
                ),
            )),
            "/metadata/v1" => {
                text("id\nhostname\nuser-data\nvendor-data\nregion\ninterfaces/\ntags/\n".into())
            }
            "/metadata/v1/id" => text(self.instance_id.clone()),
            "/metadata/v1/hostname" => text(self.hostname.clone()),
            "/metadata/v1/region" => text(self.region().into()),
            "/metadata/v1/user-data" => text(user_data),
            "/metadata/v1/vendor-data" => text("#cloud-config\n".into()),
            "/metadata/v1/interfaces/private/0/ipv4/address" => text(self.private_ip()),
            _ => None,
        }
    }

    fn vultr(&self, path: &str, canary: &Canary) -> Option<(&'static str, String)> {
        let text = |body: String| Some(("text/plain", body));
        let path = path.trim_end_matches('/');
        match path {
            "/v1.json" => Some((
                "application/json",
                format!(
                    "{{\"hostname\":\"{}\",\"instanceid\":\"{}\",\"instance-v2-id\":\"{}\",\"region\":{{\"regioncode\":\"{}\"}},\"public-keys\":[]}}",
                    self.hostname,
                    self.instance_id,
                    self.instance_id,
                    self.region()
                ),
            )),
            "/v1" | "" => text("hostname\ninstanceid\ninstance-v2-id\nregion/\n".into()),
            "/v1/hostname" => text(self.hostname.clone()),
            "/v1/instanceid" | "/v1/instance-v2-id" => text(self.instance_id.clone()),
            "/v1/region/regioncode" => text(self.region().into()),
            "/latest/user-data" | "/user-data" => text(format!(
                "#cloud-config\nwrite_files:\n  - path: /root/.vultr\n    content: VULTR_API_KEY={}\n",
                canary.id
            )),
            _ => None,
        }
    }

    /// Looks for the run's canary values in bytes the guest sent to `endpoint`
    /// (not the metadata service itself) and logs the first line holding one.
    pub fn scan_outbound(&self, endpoint: &str, payload: &[u8]) {
        let values: Vec<String> = {
            let state = self.lock();
            if state.canary.id.is_empty() {
                return;
            }
            state
                .canary
                .values()
                .into_iter()
                .map(str::to_owned)
                .collect()
        };
        let text = String::from_utf8_lossy(payload);
        for value in &values {
            if !text.contains(value.as_str()) {
                continue;
            }
            let line = text
                .lines()
                .find(|line| line.contains(value.as_str()))
                .unwrap_or("");
            // The value itself is fake, but the line is cut short anyway.
            let line: String = line.chars().take(200).collect();
            self.note("canary-use", line, endpoint.to_owned());
            return;
        }
    }

    /// Whether the log holds anything for the run.
    pub fn has_events(&self) -> bool {
        !self.lock().events.is_empty()
    }

    /// The run's report, as it is now.
    pub fn report(&self) -> Report {
        let state = self.lock();
        Report {
            version: 1,
            provider: self.provider.id.into(),
            address: self.ip.to_string(),
            run: state.run.clone(),
            instance_id: self.instance_id.clone(),
            canary: state.canary.clone(),
            events: state.events.clone(),
        }
    }

    /// Writes the report into `directory` when there is anything to report.
    pub fn write_report(&self, directory: &Path) -> Result<bool, String> {
        if !self.has_events() {
            return Ok(false);
        }
        crate::storage::atomic_json(&directory.join(REPORT), &self.report())?;
        Ok(true)
    }
}

/// The report of a run, if its folder holds a readable one.
pub fn read_report(directory: &Path) -> Option<Report> {
    let path = directory.join(REPORT);
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if !meta.file_type().is_file() || meta.len() > 4 * 1024 * 1024 {
        return None;
    }
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn read_line(reader: &mut impl BufRead) -> std::io::Result<Option<String>> {
    let mut bytes = Vec::new();
    if reader.take(MAX_LINE).read_until(b'\n', &mut bytes)? == 0 {
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&bytes)
            .trim_end_matches(['\r', '\n'])
            .to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stealth::CLOUDS;

    fn ask(service: &Arc<Service>, request: &str) -> String {
        let mut guest = service.connect().unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        guest.write_all(request.as_bytes()).unwrap();
        guest.shutdown(std::net::Shutdown::Write).unwrap();
        let mut out = String::new();
        guest.read_to_string(&mut out).unwrap();
        out
    }

    fn get(service: &Arc<Service>, path: &str) -> String {
        ask(
            service,
            &format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
        )
    }

    fn service(id: &str) -> Arc<Service> {
        let provider = CloudProvider::find(id).unwrap();
        let service = Service::new(
            provider,
            &provider.instance_id("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"),
            "web-01",
        );
        service.begin_run("run-1");
        service
    }

    #[test]
    fn tencent_hands_out_a_role_with_canary_credentials() {
        let service = service("cloud-tencent-cvm");
        assert_eq!(service.ip(), Ipv4Addr::new(169, 254, 0, 23));
        assert_eq!(service.name(), "metadata.tencentyun.com");
        let roles = get(&service, "/latest/meta-data/cam/security-credentials/");
        assert!(roles.starts_with("HTTP/1.1 200 OK") && roles.ends_with("CVMRole"));
        let creds = get(
            &service,
            "/latest/meta-data/cam/security-credentials/CVMRole",
        );
        let canary = service.report().canary;
        assert!(creds.contains(&canary.id) && creds.contains(&canary.secret));
        assert!(canary.id.starts_with("AKID") && canary.id.len() == 36);
        assert!(!creds.contains("2099"));
        let kinds: Vec<_> = service
            .report()
            .events
            .iter()
            .map(|e| e.kind.clone())
            .collect();
        assert_eq!(kinds, ["request", "request", "credentials"]);
        assert!(get(&service, "/latest/meta-data/instance-id").contains("ins-"));
        assert!(get(&service, "/nope").starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn every_provider_answers_its_own_layout() {
        for (id, path, expect) in [
            (
                "cloud-alibaba-ecs",
                "/latest/meta-data/region-id",
                "cn-hangzhou",
            ),
            (
                "cloud-alibaba-ecs",
                "/latest/meta-data/ram/security-credentials/EcsRamRole",
                "\"AccessKeyId\" : \"STS.N",
            ),
            ("cloud-digitalocean-droplet", "/metadata/v1/region", "nyc3"),
            (
                "cloud-digitalocean-droplet",
                "/metadata/v1.json",
                "droplet_id",
            ),
            (
                "cloud-digitalocean-droplet",
                "/metadata/v1/user-data",
                "DIGITALOCEAN_ACCESS_TOKEN=dop_v1_",
            ),
            ("cloud-vultr-vc2", "/v1.json", "regioncode"),
            ("cloud-vultr-vc2", "/latest/user-data", "VULTR_API_KEY="),
        ] {
            let service = service(id);
            let reply = get(&service, path);
            assert!(reply.starts_with("HTTP/1.1 200 OK"), "{id} {path}: {reply}");
            assert!(reply.contains(expect), "{id} {path}: {reply}");
        }
    }

    #[test]
    fn canaries_have_the_providers_form_and_nothing_that_names_a_sandbox() {
        let alnum = |text: &str| text.bytes().all(|b| b.is_ascii_alphanumeric());
        for _ in 0..50 {
            let tencent = Canary::of(MetadataStyle::Tencent);
            assert!(tencent.id.starts_with("AKID") && tencent.id.len() == 36 && alnum(&tencent.id));
            assert!(tencent.secret.len() == 32 && alnum(&tencent.secret));
            let alibaba = Canary::of(MetadataStyle::Alibaba);
            assert!(alibaba.id.starts_with("STS.N") && alnum(&alibaba.id[4..]));
            assert!(alibaba.secret.len() == 44 && alibaba.token.starts_with("CAIS"));
            let ocean = Canary::of(MetadataStyle::DigitalOcean);
            let hex = ocean.id.strip_prefix("dop_v1_").unwrap();
            assert!(
                hex.len() == 64
                    && hex
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            );
            let vultr = Canary::of(MetadataStyle::Vultr);
            assert!(
                vultr.id.len() == 36 && alnum(&vultr.id) && vultr.id == vultr.id.to_uppercase()
            );
            for canary in [&tencent, &alibaba, &ocean, &vultr] {
                for value in canary.values() {
                    let lower = value.to_lowercase();
                    // Random text could spell a word by chance only rarely; the
                    // fixed marker it replaces was in every value.
                    assert!(!lower.contains("antcanary"), "{value}");
                }
            }
        }
        assert!(utc(0) == "1970-01-01T00:00:00Z" && utc(1_793_394_000) == "2026-10-30T21:00:00Z");
    }

    #[test]
    fn canary_use_is_found_in_outbound_bytes_and_the_values_change_per_run() {
        let service = service("cloud-digitalocean-droplet");
        let first = service.report().canary.id;
        service.scan_outbound("203.0.113.9:80", b"GET /nothing HTTP/1.1\r\n\r\n");
        assert!(!service.has_events());
        let request = format!("GET /x HTTP/1.1\r\nAuthorization: Bearer {first}\r\n\r\n");
        service.scan_outbound("203.0.113.9:80", request.as_bytes());
        let events = service.report().events;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "canary-use");
        assert_eq!(events[0].endpoint, "203.0.113.9:80");
        assert!(events[0].detail.contains("Authorization"));
        service.begin_run("run-2");
        assert_ne!(service.report().canary.id, first);
        assert!(service.report().events.is_empty());
    }

    #[test]
    fn the_report_is_written_only_when_there_is_something_in_it() {
        let directory =
            std::env::temp_dir().join(format!("ant-meta-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&directory).unwrap();
        let service = service("cloud-vultr-vc2");
        assert!(!service.write_report(&directory).unwrap());
        assert!(read_report(&directory).is_none());
        get(&service, "/v1/hostname");
        assert!(service.write_report(&directory).unwrap());
        let report = read_report(&directory).unwrap();
        assert_eq!(report.provider, "cloud-vultr-vc2");
        assert_eq!(report.events.len(), 1);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn all_providers_have_a_service_address() {
        for provider in CLOUDS {
            assert!(provider.metadata_ip.parse::<Ipv4Addr>().is_ok());
        }
    }
}
