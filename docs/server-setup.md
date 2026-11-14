# Running an exit node

This takes a fresh Linux server with a public IP and turns it into a VPN
server whose clients can reach the internet through it. Every step here is
also run by `tests/netns.sh` in CI, using the same nftables file.

## 1. Install and configure vpnd

```sh
cargo build --release -p vpnd
sudo install target/release/vpnd /usr/local/bin/

vpnd keygen              # once for the server, once per client
```

Write `/etc/vpnd/server.toml`, starting from `examples/server.toml`, with one
`[[peer]]` per client, and `chmod 600` it. Each client gets a `/32` from the
tunnel subnet as its `allowed_ips`.

Open UDP 51820 (or whichever `listen_port` you chose) in any cloud firewall
or security group in front of the server.

### Run it as a service

```sh
sudo mv server.toml /etc/vpnd/vpn0.toml   # root:root, mode 600
sudo install -m 644 packaging/systemd/vpnd@.service /etc/systemd/system/
sudo systemctl enable --now vpnd@vpn0
journalctl -u vpnd@vpn0 -f
```

The instance name is both the config file's name and the interface name.
The unit runs vpnd as a throwaway user that has only `CAP_NET_ADMIN`.
systemd hands it a private copy of the config through `LoadCredential`, so
the file can stay readable only by root. vpnd gives up the capability once
the tunnel is up.

Or with Docker:

```sh
docker build -t vpnd .
docker run -d --cap-add NET_ADMIN --device /dev/net/tun -p 51820:51820/udp \
  -v /etc/vpnd/vpn0.toml:/etc/vpnd/vpnd.toml:ro vpnd
```

## 2. Turn on forwarding

By default Linux only delivers packets addressed to itself and drops the
rest. A VPN server has to pass packets from `tun0` out of `eth0` and back,
which is forwarding:

```sh
sudo tee /etc/sysctl.d/99-vpnd.conf <<'CONF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
CONF
sudo sysctl --system
```

## 3. NAT the tunnel subnet

Set `WAN` in [`examples/nftables-exit.conf`](../examples/nftables-exit.conf)
to the interface that holds the public IP (`ip route get 1.1.1.1` shows it),
then:

```sh
sudo nft -f examples/nftables-exit.conf
```

To keep it across reboots, put the file in `/etc/nftables.d/` or include it
from `/etc/nftables.conf`, and enable the `nftables` service. If your host
firewall's forward chain defaults to `drop`, also accept traffic between
`tun0` and `WAN` there.

IPv6 works the same way if you give the tunnel an IPv6 subnet. Either
masquerade it (NAT66, the same rule with `ip6 saddr`), or route a real
prefix from your provider to the server and skip NAT entirely.

## 4. Point a client's traffic at the tunnel

On the client, use `allowed_ips = ["0.0.0.0/0"]` so vpnd will send anything
to the server. Then tell the client's kernel to use the tunnel. `vpnd up`
doesn't touch the routing table yet beyond the tunnel subnet (#57), so for
now:

```sh
# Keep the tunnel's own UDP packets off the tunnel. Without this they'd be
# routed into tun0, encrypted, and routed into tun0 again.
sudo ip route add 203.0.113.10/32 via "$(ip route show default | awk '{print $3}')"

# Two halves of the address space beat the existing default route (a /1 is
# more specific than a /0) without deleting it, so taking the tunnel down
# restores normal routing by itself.
sudo ip route add 0.0.0.0/1 dev tun0
sudo ip route add 128.0.0.0/1 dev tun0
```

`curl https://ifconfig.me` from the client should now print the server's IP.

## What happens to one packet

A client at 10.8.0.2 opens a connection to 93.184.215.14:

1. The client's kernel looks up 93.184.215.14, matches `0.0.0.0/1 dev tun0`,
   and hands the packet to vpnd through the TUN device.
2. vpnd's routing table (`allowed_ips`) maps it to the server, so vpnd
   encrypts it and sends a UDP datagram from the client's real address to the
   server's port 51820. The outer packet takes the `/32` route, not the tunnel.
3. The server's vpnd authenticates and decrypts it, checks that the inner
   source 10.8.0.2 routes back to the peer that sent it, and writes the inner
   packet to `tun0`.
4. The server's kernel sees a packet for 93.184.215.14 arrive on `tun0`.
   Forwarding is on, so it routes it out of `eth0`.
5. On the way out, the `postrouting` hook masquerades the source from
   10.8.0.2 to the server's public IP, and conntrack records the mapping.
6. The reply comes back to the server's public IP. conntrack recognizes it,
   rewrites the destination back to 10.8.0.2, and the kernel routes it to
   `tun0` because of the `10.8.0.0/24` route that `vpnd up` installed.
7. The server's vpnd looks up 10.8.0.2, picks that client's session,
   encrypts, and sends it to the client's last known endpoint. The client
   decrypts it and writes it to its own `tun0`.

`conntrack -L` on the server shows the mappings from step 5 while traffic flows.
