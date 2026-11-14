//! TUN device: a virtual interface where the kernel hands us raw IP packets
//! routed into it, and accepts raw IP packets we write as if they arrived on
//! a wire. Needs CAP_NET_ADMIN (or root) to create.

use std::io;
use std::net::IpAddr;

use ipnet::IpNet;
use tun_rs::{AsyncDevice, DeviceBuilder};

pub struct Tun {
    dev: AsyncDevice,
    name: String,
}

impl Tun {
    /// Creates the interface, assigns `addresses` and brings it up. The
    /// prefix on each address also installs the route that sends that
    /// subnet's traffic into the device.
    pub fn create(name: Option<&str>, addresses: &[IpNet], mtu: u16) -> io::Result<Self> {
        let (v4, v6): (Vec<_>, Vec<_>) = addresses.iter().partition(|a| a.addr().is_ipv4());
        let mut builder = DeviceBuilder::new().mtu(mtu).enable(true);
        if let Some(name) = name {
            builder = builder.name(name);
        }
        if let Some(IpNet::V4(first)) = v4.first() {
            builder = builder.ipv4(first.addr(), first.prefix_len(), None);
        }
        for a in &v6 {
            if let IpNet::V6(a) = a {
                builder = builder.ipv6(a.addr(), a.prefix_len());
            }
        }
        let dev = builder.build_async()?;
        for a in v4.iter().skip(1) {
            if let (IpAddr::V4(addr), prefix) = (a.addr(), a.prefix_len()) {
                dev.add_address_v4(addr, prefix)?;
            }
        }
        let name = dev.name()?;
        Ok(Self { dev, name })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Reads one outbound IP packet. `buf` must hold at least the MTU.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.dev.recv(buf).await
    }

    /// Writes one inbound IP packet for the kernel to deliver.
    pub async fn send(&self, packet: &[u8]) -> io::Result<()> {
        self.dev.send(packet).await.map(drop)
    }
}
