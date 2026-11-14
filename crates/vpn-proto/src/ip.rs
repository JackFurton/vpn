//! Just enough IPv4/IPv6 header parsing to route and log inner packets.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpHeader {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// IPv4 protocol or IPv6 next header (1 ICMP, 6 TCP, 17 UDP, 58 ICMPv6).
    /// For IPv6 this is the first header only, which may be an extension.
    pub protocol: u8,
    /// Length the header claims for the whole packet.
    pub total_len: usize,
}

impl IpHeader {
    /// Returns None for anything that isn't a well-formed IPv4 or IPv6
    /// header. Doesn't verify the IPv4 checksum; the tunnel AEAD already
    /// covers integrity.
    pub fn parse(p: &[u8]) -> Option<Self> {
        match p.first()? >> 4 {
            4 => {
                let h: &[u8; 20] = p.first_chunk()?;
                let ihl = usize::from(h[0] & 0x0f) * 4;
                let total_len = usize::from(u16::from_be_bytes([h[2], h[3]]));
                if ihl < 20 || total_len < ihl {
                    return None;
                }
                Some(Self {
                    src: Ipv4Addr::from(*sub::<4>(h, 12)).into(),
                    dst: Ipv4Addr::from(*sub::<4>(h, 16)).into(),
                    protocol: h[9],
                    total_len,
                })
            }
            6 => {
                let h: &[u8; 40] = p.first_chunk()?;
                Some(Self {
                    src: Ipv6Addr::from(*sub::<16>(h, 8)).into(),
                    dst: Ipv6Addr::from(*sub::<16>(h, 24)).into(),
                    protocol: h[6],
                    total_len: 40 + usize::from(u16::from_be_bytes([h[4], h[5]])),
                })
            }
            _ => None,
        }
    }
}

fn sub<const N: usize>(h: &[u8], at: usize) -> &[u8; N] {
    h[at..at + N]
        .try_into()
        .expect("caller checked header length")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Header of an 84-byte ping from 10.9.0.1 to 10.9.0.2.
    const ICMP_V4: [u8; 28] = [
        0x45, 0x00, 0x00, 0x54, 0x6d, 0x2c, 0x40, 0x00, 0x40, 0x01, 0xb9, 0x77, 10, 9, 0, 1, 10, 9,
        0, 2, 0x08, 0x00, 0xf7, 0xff, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn parses_ipv4() {
        let h = IpHeader::parse(&ICMP_V4).unwrap();
        assert_eq!(h.src, "10.9.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(h.dst, "10.9.0.2".parse::<IpAddr>().unwrap());
        assert_eq!((h.protocol, h.total_len), (1, 84));
    }

    #[test]
    fn parses_ipv6() {
        let mut p = [0u8; 40];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&8u16.to_be_bytes());
        p[6] = 58;
        p[8..24].copy_from_slice(&"fd00::1".parse::<Ipv6Addr>().unwrap().octets());
        p[24..40].copy_from_slice(&"fd00::2".parse::<Ipv6Addr>().unwrap().octets());
        let h = IpHeader::parse(&p).unwrap();
        assert_eq!(h.dst, "fd00::2".parse::<IpAddr>().unwrap());
        assert_eq!((h.protocol, h.total_len), (58, 48));
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(IpHeader::parse(&[]), None);
        assert_eq!(IpHeader::parse(&ICMP_V4[..19]), None);
        assert_eq!(IpHeader::parse(&[0x60; 39]), None);
        assert_eq!(IpHeader::parse(&[0x50; 40]), None);
        let mut short_ihl = ICMP_V4;
        short_ihl[0] = 0x44;
        assert_eq!(IpHeader::parse(&short_ihl), None);
        let mut short_total = ICMP_V4;
        short_total[2..4].copy_from_slice(&19u16.to_be_bytes());
        assert_eq!(IpHeader::parse(&short_total), None);
    }
}
