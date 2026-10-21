// SPDX-License-Identifier: MIT
//! The addresses of QEMU's user-mode NAT: 10.0.2.0/24 with gateway 10.0.2.2
//! and DNS 10.0.2.3 by default, which QEMU and VirtualBox share; a profile
//! gives it a home network's instead. The guest learns them from the NAT's
//! DHCP server.
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NatNetwork {
    /// A private IPv4 network in CIDR form; empty keeps QEMU's 10.0.2.0/24.
    pub network: String,
    /// The router: the guest's default gateway.
    pub gateway: String,
    /// The DNS server the DHCP answer names; QEMU needs it apart from the
    /// gateway.
    pub dns: String,
    /// The first address DHCP hands out: the guest's.
    pub dhcp_start: String,
}

impl NatNetwork {
    /// A home router's network.
    pub fn home() -> Self {
        Self {
            network: "192.168.1.0/24".into(),
            gateway: "192.168.1.1".into(),
            dns: "192.168.1.10".into(),
            dhcp_start: "192.168.1.100".into(),
        }
    }

    /// The network address and prefix length.
    fn parse(&self) -> Result<(u32, u8), String> {
        let (address, prefix) = self
            .network
            .split_once('/')
            .ok_or_else(|| format!("NAT network {:?} is not address/prefix", self.network))?;
        let address: Ipv4Addr = address
            .parse()
            .map_err(|_| format!("NAT network {address:?} is not an IPv4 address"))?;
        let prefix: u8 = prefix
            .parse()
            .ok()
            .filter(|prefix| (8..=30).contains(prefix))
            .ok_or("NAT network prefix is 8 to 30 bits")?;
        let mask = u32::MAX << (32 - prefix);
        let network = u32::from(address);
        if network & !mask != 0 {
            return Err(format!("NAT network {} has host bits set", self.network));
        }
        // Private only: the guest's network must not hide public hosts, and
        // the capture and triage treat it as the local network.
        if !Ipv4Addr::from(network).is_private() || !Ipv4Addr::from(network | !mask).is_private() {
            return Err("NAT network must be private (10/8, 172.16/12 or 192.168/16)".into());
        }
        Ok((network, prefix))
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.network.is_empty() {
            return Ok(());
        }
        let (network, prefix) = self.parse()?;
        let mask = u32::MAX << (32 - prefix);
        let mut seen = Vec::new();
        for (name, text) in [
            ("gateway", &self.gateway),
            ("DNS server", &self.dns),
            ("DHCP start", &self.dhcp_start),
        ] {
            let address = text
                .parse::<Ipv4Addr>()
                .map(u32::from)
                .map_err(|_| format!("NAT {name} {text:?} is not an IPv4 address"))?;
            if address & mask != network || address == network || address == network | !mask {
                return Err(format!(
                    "NAT {name} {text} is not a host of {}",
                    self.network
                ));
            }
            if seen.contains(&address) {
                return Err("NAT gateway, DNS server and DHCP start must differ".into());
            }
            seen.push(address);
        }
        Ok(())
    }

    /// The `-netdev user` options, after `user,id=…`.
    pub(super) fn options(&self) -> String {
        if self.network.is_empty() {
            return String::new();
        }
        format!(
            ",net={},host={},dns={},dhcpstart={}",
            self.network, self.gateway, self.dns, self.dhcp_start
        )
    }
}
