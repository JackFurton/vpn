//! Longest-prefix-match table from IP address to peer: "cryptokey routing".
//! The same table answers both "which peer does this outbound packet go to"
//! and "may this peer send from that source address".
//!
//! One hash map per prefix length in use, searched longest first. That's at
//! most 33 (IPv4) or 129 (IPv6) lookups, and in practice a handful, since
//! real configs use few distinct lengths. A compressed trie (what WireGuard
//! uses) does fewer memory accesses per lookup but is a lot more code.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use ipnet::IpNet;

#[derive(Debug, Clone)]
pub struct AllowedIps<T> {
    v4: Family<u32, T>,
    v6: Family<u128, T>,
}

#[derive(Debug, Clone)]
struct Family<K, T> {
    /// Prefix length to (masked network to value). BTreeMap so iterating in
    /// reverse visits the longest prefixes first.
    by_len: BTreeMap<u8, HashMap<K, T>>,
}

impl<T> Default for AllowedIps<T> {
    fn default() -> Self {
        Self {
            v4: Family {
                by_len: BTreeMap::new(),
            },
            v6: Family {
                by_len: BTreeMap::new(),
            },
        }
    }
}

impl<T: Clone + PartialEq> AllowedIps<T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Host bits in `net` are ignored. A later insert of the same network
    /// replaces the earlier value.
    pub fn insert(&mut self, net: IpNet, value: T) {
        let len = net.prefix_len();
        match net.trunc() {
            IpNet::V4(n) => self.v4.insert(len, u32::from(n.network()), value),
            IpNet::V6(n) => self.v6.insert(len, u128::from(n.network()), value),
        }
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<&T> {
        match ip {
            IpAddr::V4(a) => self.v4.lookup(u32::from(a)),
            IpAddr::V6(a) => self.v6.lookup(u128::from(a)),
        }
    }

    pub fn remove_value(&mut self, value: &T) {
        self.v4.remove_value(value);
        self.v6.remove_value(value);
    }
}

trait Bits: Copy + Eq + std::hash::Hash + std::ops::BitAnd<Output = Self> {
    fn mask(len: u8) -> Self;
}

impl Bits for u32 {
    fn mask(len: u8) -> Self {
        u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0)
    }
}

impl Bits for u128 {
    fn mask(len: u8) -> Self {
        u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0)
    }
}

impl<K: Bits, T: PartialEq> Family<K, T> {
    fn insert(&mut self, len: u8, network: K, value: T) {
        self.by_len.entry(len).or_default().insert(network, value);
    }

    fn lookup(&self, addr: K) -> Option<&T> {
        self.by_len
            .iter()
            .rev()
            .find_map(|(&len, nets)| nets.get(&(addr & K::mask(len))))
    }

    fn remove_value(&mut self, value: &T) {
        for nets in self.by_len.values_mut() {
            nets.retain(|_, v| v != value);
        }
        self.by_len.retain(|_, nets| !nets.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn longest_prefix_wins() {
        let mut t = AllowedIps::new();
        t.insert(net("0.0.0.0/0"), "default");
        t.insert(net("10.0.0.0/8"), "ten");
        t.insert(net("10.1.0.0/16"), "ten-one");
        t.insert(net("10.1.2.3/32"), "host");
        assert_eq!(t.lookup(ip("10.1.2.3")), Some(&"host"));
        assert_eq!(t.lookup(ip("10.1.2.4")), Some(&"ten-one"));
        assert_eq!(t.lookup(ip("10.2.0.1")), Some(&"ten"));
        assert_eq!(t.lookup(ip("192.0.2.1")), Some(&"default"));
    }

    #[test]
    fn families_are_separate() {
        let mut t = AllowedIps::new();
        t.insert(net("0.0.0.0/0"), 4);
        assert_eq!(t.lookup(ip("::1")), None);
        // A v4-mapped address is IPv6 here: inner packets carry real IPv6.
        assert_eq!(t.lookup(ip("::ffff:10.0.0.1")), None);
        t.insert(net("::/0"), 6);
        t.insert(net("fd00::/64"), 64);
        assert_eq!(t.lookup(ip("fd00::1")), Some(&64));
        assert_eq!(t.lookup(ip("fd01::1")), Some(&6));
        assert_eq!(t.lookup(ip("10.0.0.1")), Some(&4));
    }

    #[test]
    fn host_bits_are_ignored_and_remove_works() {
        let mut t = AllowedIps::new();
        t.insert(net("10.0.0.77/24"), 1);
        t.insert(net("10.0.1.0/24"), 2);
        assert_eq!(t.lookup(ip("10.0.0.5")), Some(&1));
        t.remove_value(&1);
        assert_eq!(t.lookup(ip("10.0.0.5")), None);
        assert_eq!(t.lookup(ip("10.0.1.5")), Some(&2));
    }

    // Against a plain linear scan over random prefixes and addresses, with
    // addresses biased towards the inserted prefixes so matches happen.
    #[test]
    fn matches_linear_scan() {
        let mut rng = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        for _ in 0..200 {
            let mut t = AllowedIps::new();
            let mut nets: Vec<(IpNet, usize)> = Vec::new();
            for v in 0..20 {
                let n = if next() % 2 == 0 {
                    let len = (next() % 33) as u8;
                    IpNet::V4(ipnet::Ipv4Net::new((next() as u32).into(), len).unwrap())
                } else {
                    let len = (next() % 129) as u8;
                    let a = (u128::from(next()) << 64) | u128::from(next());
                    IpNet::V6(ipnet::Ipv6Net::new(a.into(), len).unwrap())
                }
                .trunc();
                nets.retain(|(m, _)| *m != n);
                nets.push((n, v));
                t.insert(n, v);
            }
            for _ in 0..200 {
                let (base, _) = nets[(next() as usize) % nets.len()];
                let probe = match base {
                    IpNet::V4(n) => IpAddr::V4(
                        (u32::from(n.network()) | (next() as u32 & !u32::mask(n.prefix_len())))
                            .into(),
                    ),
                    IpNet::V6(n) => {
                        let r = (u128::from(next()) << 64) | u128::from(next());
                        IpAddr::V6(
                            (u128::from(n.network()) | (r & !u128::mask(n.prefix_len()))).into(),
                        )
                    }
                };
                let want = nets
                    .iter()
                    .filter(|(n, _)| n.contains(&probe))
                    .max_by_key(|(n, _)| n.prefix_len())
                    .map(|(_, v)| v);
                assert_eq!(t.lookup(probe), want, "{probe}");
            }
        }
    }
}
