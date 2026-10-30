// SPDX-License-Identifier: GPL-3.0-only
//! Exercise cloud metadata through the real gateway, without upstream access.
use super::{
    Guest, WAIT,
    guest::{Connect, Tcp},
    no_data, scratch,
};
use crate::{
    route::{Gateway, GatewayNet, MetadataService, RouteConfig, RouteKind},
    stealth::{CLOUDS, MetadataStyle, NatNetwork},
};
use std::{net::Ipv4Addr, time::Duration};

#[test]
fn each_cloud_answers_locally_on_drop_and_inetsim_but_other_providers_stay_silent() {
    for provider in CLOUDS {
        let dir = scratch("cloud-modes");
        let service = MetadataService::new(provider, "instance-test", "guest-test");
        let gateway = Gateway::start_with(
            &dir,
            GatewayNet::from_nat(&NatNetwork::default()).unwrap(),
            Some(service.clone()),
        )
        .unwrap();
        let mut guest = Guest::connect(gateway.socket_path());
        let path = match provider.metadata {
            MetadataStyle::Tencent => "/latest/meta-data/instance-id",
            MetadataStyle::Alibaba => "/latest/meta-data/instance-id",
            MetadataStyle::DigitalOcean => "/metadata/v1/id",
            MetadataStyle::Vultr => "/v1/instanceid",
        };
        for kind in [RouteKind::Drop, RouteKind::InetSim] {
            gateway
                .claim(
                    "cloud-run",
                    RouteConfig::default().spec(no_data(), kind).unwrap(),
                )
                .unwrap();
            let (mut tcp, state) = Tcp::open(&mut guest, service.ip(), 80, WAIT);
            assert_eq!(state, Connect::Open, "{} {kind:?}", provider.id);
            tcp.send_all(
                &mut guest,
                format!("GET {path} HTTP/1.1\r\nHost: metadata\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            );
            let reply = tcp.read_to_end(&mut guest, WAIT);
            let text = String::from_utf8_lossy(&reply);
            assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
            assert!(text.ends_with("instance-test"), "{text}");
            for other in CLOUDS {
                let address: Ipv4Addr = other.metadata_ip.parse().unwrap();
                if address != service.ip() {
                    let (_, state) = Tcp::open(&mut guest, address, 80, Duration::from_millis(200));
                    assert_eq!(
                        state,
                        Connect::Silent,
                        "{} answered {} on {kind:?}",
                        provider.id,
                        other.id
                    );
                }
            }
            if kind == RouteKind::Drop {
                let (_, state) = Tcp::open(
                    &mut guest,
                    Ipv4Addr::new(203, 0, 113, 9),
                    80,
                    Duration::from_millis(200),
                );
                assert_eq!(
                    state,
                    Connect::Silent,
                    "Drop must not open an external connection"
                );
            }
            gateway.release("cloud-run");
        }
        drop(guest);
        drop(gateway);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
