// SPDX-License-Identifier: GPL-3.0-only
//! The gateway's DHCP server: one lease for the one guest, the way QEMU's
//! user-mode network gives it, so the guest configures itself unchanged.
use std::net::Ipv4Addr;

const MAGIC: [u8; 4] = [99, 130, 83, 99];
const DISCOVER: u8 = 1;
const REQUEST: u8 = 3;
const OFFER: u8 = 2;
const ACK: u8 = 5;
const NAK: u8 = 6;
const LEASE_SECONDS: u32 = 86_400;

/// The addressing the gateway hands out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub guest: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub broadcast: Ipv4Addr,
}

fn option(options: &[u8], wanted: u8) -> Option<&[u8]> {
    let mut rest = options;
    while let Some((&code, tail)) = rest.split_first() {
        match code {
            0 => rest = tail,
            255 => return None,
            _ => {
                let (&len, tail) = tail.split_first()?;
                let len = usize::from(len);
                let value = tail.get(..len)?;
                if code == wanted {
                    return Some(value);
                }
                rest = &tail[len..];
            }
        }
    }
    None
}

/// The DHCP reply (a BOOTP payload) to a client message, or `None` for a
/// message that gets none.
pub fn reply(request: &[u8], lease: &Lease) -> Option<Vec<u8>> {
    if request.len() < 241 || request[0] != 1 || request[1] != 1 || request[2] != 6 {
        return None;
    }
    if request[236..240] != MAGIC {
        return None;
    }
    let options = &request[240..];
    let kind = *option(options, 53)?.first()?;
    let kind = match kind {
        DISCOVER => OFFER,
        REQUEST => {
            let asked = option(options, 50)
                .and_then(|value| <[u8; 4]>::try_from(value).ok())
                .map(Ipv4Addr::from)
                .or_else(|| {
                    let ciaddr = Ipv4Addr::new(request[12], request[13], request[14], request[15]);
                    (!ciaddr.is_unspecified()).then_some(ciaddr)
                });
            // A request for another server's offer (server id given and not
            // ours) is not answered.
            if let Some(server) = option(options, 54)
                && server != lease.gateway.octets()
            {
                return None;
            }
            if asked == Some(lease.guest) { ACK } else { NAK }
        }
        _ => return None,
    };
    let mut out = vec![0u8; 240];
    out[0] = 2;
    out[1] = 1;
    out[2] = 6;
    out[4..8].copy_from_slice(&request[4..8]);
    out[10..12].copy_from_slice(&request[10..12]);
    if kind != NAK {
        out[16..20].copy_from_slice(&lease.guest.octets());
    }
    out[20..24].copy_from_slice(&lease.gateway.octets());
    out[28..44].copy_from_slice(&request[28..44]);
    out[236..240].copy_from_slice(&MAGIC);
    out.extend_from_slice(&[53, 1, kind, 54, 4]);
    out.extend_from_slice(&lease.gateway.octets());
    if kind != NAK {
        out.extend_from_slice(&[51, 4]);
        out.extend_from_slice(&LEASE_SECONDS.to_be_bytes());
        out.extend_from_slice(&[1, 4]);
        out.extend_from_slice(&lease.mask.octets());
        out.extend_from_slice(&[3, 4]);
        out.extend_from_slice(&lease.gateway.octets());
        out.extend_from_slice(&[6, 4]);
        out.extend_from_slice(&lease.dns.octets());
        out.extend_from_slice(&[28, 4]);
        out.extend_from_slice(&lease.broadcast.octets());
    }
    out.push(255);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease() -> Lease {
        Lease {
            guest: Ipv4Addr::new(10, 0, 2, 15),
            gateway: Ipv4Addr::new(10, 0, 2, 2),
            dns: Ipv4Addr::new(10, 0, 2, 3),
            mask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(10, 0, 2, 255),
        }
    }

    fn client(kind: u8, extra: &[u8]) -> Vec<u8> {
        let mut message = vec![0u8; 240];
        message[0] = 1;
        message[1] = 1;
        message[2] = 6;
        message[4..8].copy_from_slice(&[1, 2, 3, 4]);
        message[28..34].copy_from_slice(&[0x52, 0x54, 0, 1, 2, 3]);
        message[236..240].copy_from_slice(&MAGIC);
        message.extend_from_slice(&[53, 1, kind]);
        message.extend_from_slice(extra);
        message.push(255);
        message
    }

    #[test]
    fn discover_gets_an_offer_with_the_network_settings() {
        let answer = reply(&client(DISCOVER, &[]), &lease()).unwrap();
        assert_eq!(&answer[16..20], &[10, 0, 2, 15]);
        assert_eq!(&answer[4..8], &[1, 2, 3, 4]);
        let options = &answer[240..];
        assert_eq!(option(options, 53), Some(&[OFFER][..]));
        assert_eq!(option(options, 3), Some(&[10, 0, 2, 2][..]));
        assert_eq!(option(options, 6), Some(&[10, 0, 2, 3][..]));
        assert_eq!(option(options, 1), Some(&[255, 255, 255, 0][..]));
    }

    #[test]
    fn request_for_the_lease_is_acked_and_for_another_address_refused() {
        let ack = reply(&client(REQUEST, &[50, 4, 10, 0, 2, 15]), &lease()).unwrap();
        assert_eq!(option(&ack[240..], 53), Some(&[ACK][..]));
        let nak = reply(&client(REQUEST, &[50, 4, 10, 0, 2, 99]), &lease()).unwrap();
        assert_eq!(option(&nak[240..], 53), Some(&[NAK][..]));
        assert_eq!(&nak[16..20], &[0, 0, 0, 0]);
        // Another server's offer, a release and a malformed message get none.
        assert!(reply(&client(REQUEST, &[54, 4, 9, 9, 9, 9]), &lease()).is_none());
        assert!(reply(&client(7, &[]), &lease()).is_none());
        assert!(reply(&[0; 100], &lease()).is_none());
        let mut truncated = client(DISCOVER, &[]);
        truncated.truncate(242);
        assert!(reply(&truncated, &lease()).is_none());
    }
}
