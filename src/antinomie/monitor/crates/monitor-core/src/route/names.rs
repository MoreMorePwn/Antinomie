// SPDX-License-Identifier: GPL-3.0-only
//! Fake addresses for the names the guest looks up on a proxied route. The
//! gateway answers every A query with an address from 198.18.0.0/16 and
//! remembers the name; when the guest connects to that address the proxy is
//! given the name, so the proxy resolves it and no lookup leaves the host.
use std::{collections::HashMap, net::Ipv4Addr};

/// Names kept; the oldest is replaced when a new one arrives after that.
const CAPACITY: u32 = 8192;

#[derive(Default)]
pub(crate) struct FakeIps {
    by_name: HashMap<String, u32>,
    by_slot: HashMap<u32, String>,
    next: u32,
}

impl FakeIps {
    fn address(slot: u32) -> Ipv4Addr {
        // Skip .0 so that no address ends in 0.
        Ipv4Addr::new(198, 18, ((slot + 1) >> 8) as u8, ((slot + 1) & 0xff) as u8)
    }

    pub fn is_fake(ip: Ipv4Addr) -> bool {
        ip.octets()[..2] == [198, 18]
    }

    /// The address for `name`, a new one the first time.
    pub fn address_for(&mut self, name: &str) -> Ipv4Addr {
        if let Some(slot) = self.by_name.get(name) {
            return Self::address(*slot);
        }
        let slot = self.next % CAPACITY;
        self.next = self.next.wrapping_add(1);
        if let Some(old) = self.by_slot.insert(slot, name.to_owned()) {
            self.by_name.remove(&old);
        }
        self.by_name.insert(name.to_owned(), slot);
        Self::address(slot)
    }

    pub fn name_for(&self, ip: Ipv4Addr) -> Option<&str> {
        let octets = ip.octets();
        if octets[..2] != [198, 18] {
            return None;
        }
        let slot = (u32::from(octets[2]) << 8 | u32::from(octets[3])).checked_sub(1)?;
        self.by_slot.get(&slot).map(String::as_str)
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_get_stable_addresses_and_old_ones_are_replaced() {
        let mut ips = FakeIps::default();
        let a = ips.address_for("a.example");
        assert_eq!(ips.address_for("a.example"), a);
        assert_eq!(ips.name_for(a), Some("a.example"));
        let b = ips.address_for("b.example");
        assert_ne!(a, b);
        for n in 0..CAPACITY {
            ips.address_for(&format!("n{n}.example"));
        }
        // a's slot was reused, so its address no longer names it.
        assert_ne!(ips.name_for(a), Some("a.example"));
        assert_eq!(ips.name_for(Ipv4Addr::new(8, 8, 8, 8)), None);
        assert_eq!(ips.name_for(Ipv4Addr::new(198, 18, 0, 0)), None);
        assert!(FakeIps::is_fake(a) && !FakeIps::is_fake(Ipv4Addr::new(198, 20, 0, 1)));
    }
}
