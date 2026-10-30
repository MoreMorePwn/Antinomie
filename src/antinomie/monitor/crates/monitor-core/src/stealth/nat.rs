// SPDX-License-Identifier: GPL-3.0-only
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
            .ok_or_else(|| format!("Guest network {:?} is not address/prefix", self.network))?;
        let address: Ipv4Addr = address
            .parse()
            .map_err(|_| format!("Guest network {address:?} is not an IPv4 address"))?;
        let prefix: u8 = prefix
            .parse()
            .ok()
            .filter(|prefix| (8..=30).contains(prefix))
            .ok_or("Guest network prefix is 8 to 30 bits")?;
        let mask = u32::MAX << (32 - prefix);
        let network = u32::from(address);
        if network & !mask != 0 {
            return Err(format!("Guest network {} has host bits set", self.network));
        }
        // Private only: the guest's network must not hide public hosts, and
        // the capture and triage treat it as the local network.
        if !Ipv4Addr::from(network).is_private() || !Ipv4Addr::from(network | !mask).is_private() {
            return Err("Guest network must be private (10/8, 172.16/12 or 192.168/16)".into());
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
                .map_err(|_| format!("Guest network {name} {text:?} is not an IPv4 address"))?;
            if address & mask != network || address == network || address == network | !mask {
                return Err(format!(
                    "Guest network {name} {text} is not a host of {}",
                    self.network
                ));
            }
            if seen.contains(&address) {
                return Err("Guest network gateway, DNS server and DHCP start must differ".into());
            }
            seen.push(address);
        }
        Ok(())
    }

    /// The network as the Routed gateway hands it out: the address, prefix
    /// length, gateway, DNS server and the guest's address. QEMU's defaults
    /// when the profile gives none.
    pub(crate) fn lease_plan(
        &self,
    ) -> Result<(Ipv4Addr, u8, Ipv4Addr, Ipv4Addr, Ipv4Addr), String> {
        if self.network.is_empty() {
            return Ok((
                Ipv4Addr::new(10, 0, 2, 0),
                24,
                Ipv4Addr::new(10, 0, 2, 2),
                Ipv4Addr::new(10, 0, 2, 3),
                Ipv4Addr::new(10, 0, 2, 15),
            ));
        }
        self.validate()?;
        let (network, prefix) = self.parse()?;
        let address = |text: &str| text.parse::<Ipv4Addr>().map_err(|e| e.to_string());
        Ok((
            Ipv4Addr::from(network),
            prefix,
            address(&self.gateway)?,
            address(&self.dns)?,
            address(&self.dhcp_start)?,
        ))
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
