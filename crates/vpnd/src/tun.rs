//! TUN device: a virtual interface where the kernel hands us raw IP packets
//! routed into it, and accepts raw IP packets we write as if they arrived on
//! a wire. Needs CAP_NET_ADMIN (or root) to create.

use std::io;
use std::net::IpAddr;

use ipnet::IpNet;
use tun_rs::{AsyncDevice, DeviceBuilder};

/// Space in front of each packet we write, for the virtio-net header Linux
/// offload puts there. Kept on every platform so the code path is one.
const HEADROOM: usize = 10;
#[cfg(target_os = "linux")]
const _: () = assert!(HEADROOM == tun_rs::VIRTIO_NET_HDR_LEN);
/// Enough MTU-sized buffers for one 64 KB offloaded read at the smallest
/// MTU we allow (1280).
const BATCH: usize = 64;

/// Packets from one read. With Linux offload the kernel can hand over one
/// 64 KB TCP segment, which arrives here split into MTU-sized packets.
pub struct TunRx {
    #[cfg(target_os = "linux")]
    raw: Vec<u8>,
    bufs: Vec<Vec<u8>>,
    sizes: Vec<usize>,
    n: usize,
}

impl TunRx {
    pub fn new(mtu: usize) -> Self {
        Self {
            #[cfg(target_os = "linux")]
            raw: vec![0; HEADROOM + 65_535],
            bufs: vec![vec![0; mtu]; BATCH],
            sizes: vec![0; BATCH],
            n: 0,
        }
    }

    pub fn packets(&self) -> impl Iterator<Item = &[u8]> {
        self.bufs[..self.n]
            .iter()
            .zip(&self.sizes)
            .map(|(b, &n)| &b[..n])
    }

    /// For tests: stands in for a read that returned `packet`.
    #[cfg(test)]
    pub fn set(&mut self, packet: &[u8]) {
        self.bufs[0][..packet.len()].copy_from_slice(packet);
        self.sizes[0] = packet.len();
        self.n = 1;
    }
}

/// Packets to write in one go. On Linux with offload, consecutive TCP
/// segments of one flow merge into one write (GRO).
#[derive(Default)]
pub struct TunTx {
    #[cfg(target_os = "linux")]
    gro: tun_rs::GROTable,
    bufs: Vec<Vec<u8>>,
    n: usize,
}

impl TunTx {
    pub fn push(&mut self, packet: &[u8]) {
        if self.n == self.bufs.len() {
            // GRO appends merged segments into the first packet's buffer,
            // and only if it already has room: it never reallocates.
            self.bufs.push(Vec::with_capacity(2 * HEADROOM + 65_535));
        }
        let b = &mut self.bufs[self.n];
        b.clear();
        b.resize(HEADROOM, 0);
        b.extend_from_slice(packet);
        self.n += 1;
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    pub fn packets(&self) -> impl Iterator<Item = &[u8]> {
        self.bufs[..self.n].iter().map(|b| &b[HEADROOM..])
    }

    pub fn clear(&mut self) {
        self.n = 0;
    }
}

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
        #[cfg(target_os = "linux")]
        {
            builder = builder.offload(true);
        }
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

    /// Reads one or more outbound IP packets.
    pub async fn recv_batch(&self, rx: &mut TunRx) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            rx.n = self
                .dev
                .recv_multiple(&mut rx.raw, &mut rx.bufs, &mut rx.sizes, 0)
                .await?;
        }
        #[cfg(not(target_os = "linux"))]
        {
            rx.sizes[0] = self.dev.recv(&mut rx.bufs[0]).await?;
            rx.n = 1;
            // One wakeup, then whatever else the kernel already queued.
            while rx.n < BATCH {
                match self.dev.try_recv(&mut rx.bufs[rx.n]) {
                    Ok(len) => {
                        rx.sizes[rx.n] = len;
                        rx.n += 1;
                    }
                    // WouldBlock, or an error the next recv reports.
                    Err(_) => break,
                }
            }
        }
        Ok(())
    }

    /// Writes every packet in `tx` for the kernel to deliver, and empties it.
    pub async fn send_batch(&self, tx: &mut TunTx) -> io::Result<()> {
        let n = std::mem::take(&mut tx.n);
        #[cfg(target_os = "linux")]
        let r = self
            .dev
            .send_multiple(&mut tx.gro, &mut tx.bufs[..n], HEADROOM)
            .await
            .map(drop);
        #[cfg(not(target_os = "linux"))]
        let r = {
            let mut r = Ok(());
            for b in &tx.bufs[..n] {
                if let Err(e) = self.dev.send(&b[HEADROOM..]).await {
                    r = Err(e);
                }
            }
            r
        };
        r
    }
}
