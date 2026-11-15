# Benchmarks

Two kinds of numbers: microbenchmarks of the protocol core, and iperf3
through real tunnels between network namespaces.

```sh
cargo bench -p vpn-proto --bench transport
cargo build --release -p vpnd && sudo tests/bench.sh target/release/vpnd
```

`bench.sh` needs iperf3, wireguard-tools and python3. The Bench workflow runs
both on a GitHub runner, on demand and on PRs that touch the benchmarks:
https://github.com/JackFurton/vpn/actions/workflows/bench.yml

Numbers below were recorded on 2026-11-14: the protocol core at v0.2.0,
the tunnels after the socket buffer change below. Re-run before trusting them for anything newer.

## Protocol core

What one CPU core can do with no I/O at all. `session` is one
ChaCha20-Poly1305 encryption or decryption with the 16-byte header, padding
and replay window. `device` is a whole trip through two `Device`s: route
lookup, encrypt, parse, decrypt, cryptokey routing check, and out to the
other side's TUN. `handshake` is both sides of a Noise IK handshake.

| bench | Apple M5 | GitHub runner (AMD EPYC 9V74) |
|---|---|---|
| session/encrypt/64 | 373 ns | 1.77 us |
| session/decrypt/64 | 360 ns | 1.75 us |
| session/encrypt/1420 | 1.89 us (716 MiB/s) | 2.88 us (471 MiB/s) |
| session/decrypt/1420 | 1.89 us (717 MiB/s) | 2.86 us (473 MiB/s) |
| device/tun_to_tun/64 | 774 ns | 3.61 us |
| device/tun_to_tun/1420 | 3.83 us (353 MiB/s) | 5.89 us (230 MiB/s) |
| handshake | 212 us | 613 us |
| allowed_ips, /32 hit in 10k | 4.8 ns | 15 ns |
| allowed_ips, falls to /0 | 13 ns | 41 ns |

What this says:

- Everything `Device` does besides crypto costs 40 to 150 ns per packet:
  tun_to_tun is within that of encrypt plus decrypt. Routing is not where
  the time goes.
- One core can encrypt about 6 Gbit/s of full-size packets on the M5. That's
  the ceiling for a single-threaded tunnel (#70).
- 212 us per handshake is about 4,700 per second per core. The cookie
  defence kicks in at 128 per second, well before handshakes could saturate
  a core.
- On x86_64 each call has about 1.7 us of fixed cost that doesn't scale
  with packet size, which the M5 doesn't show. Not understood yet (#69).

## Tunnels

`bench.sh`: two namespaces joined by a veth pair, iperf3 TCP from one to
the other for 10 s. First the bare link, then through vpnd, then through
kernel WireGuard over the same link with the same keys and MTU (1420).

Colima VM on an Apple M5, 4 CPUs, Linux 6.8:

```
== TCP, one stream
veth               121.21 Gbit/s
vpnd                 3.98 Gbit/s   vpnd CPU: client 89%, server 97%
kernel wireguard     8.08 Gbit/s
== TCP, four streams
veth               253.83 Gbit/s
vpnd                 4.09 Gbit/s   vpnd CPU: client 96%, server 100%
kernel wireguard     8.56 Gbit/s
```

GitHub ubuntu-latest runner, 4 vCPUs of an AMD EPYC 9V45, Linux 7.0 (azure):

```
== TCP, one stream
veth                51.74 Gbit/s
vpnd                 3.05 Gbit/s   vpnd CPU: client 107%, server 110%
kernel wireguard     2.31 Gbit/s
== TCP, four streams
veth               142.41 Gbit/s
vpnd                 3.18 Gbit/s   vpnd CPU: client 108%, server 109%
kernel wireguard     2.35 Gbit/s
```

Runners land on different CPUs from run to run, so compare within a run,
not across them. The veth numbers are only there to show the link itself
isn't the limit.

### Batching (#68)

At v0.2.0 vpnd moved one packet per syscall: 1.04 Gbit/s against kernel
WireGuard's 8.22 on the M5 VM, and 0.42 against 1.50 on a runner. With
`perf trace` on the receiving side, 3 s of traffic took 93.7k `recvfrom`,
93.2k TUN `write`s, 99k `epoll_pwait`s and about 100k context switches a
second. That's one wakeup and two or three syscalls for every packet, with
the VM 60% idle, and crypto was only a quarter of vpnd's samples.

Now, on Linux:

- The TUN device runs with offload (IFF_VNET_HDR). The kernel hands vpnd
  whole 64 KB TCP segments, which tun-rs splits into MTU-sized packets.
- Encrypted packets to one peer leave in one `sendmsg` with UDP_SEGMENT
  (GSO), up to 44 full-size datagrams per call.
- UDP_GRO on receive hands back up to 44 datagrams per `recvmsg`.
- Decrypted packets go back to the TUN device in one batch, which tun-rs
  merges into large TCP segments (GRO).

Same 3 s on the receiving side afterwards: 22.8k `recvmsg`, 20.4k TUN
writes, about 23 packets per syscall. Crypto (ChaCha20 plus Poly1305) went
from a quarter of vpnd's CPU time to about 70%. That got the M5 VM to 2.37
Gbit/s and the runner to 3.05.

One trap: tun-rs only merges segments into a buffer that already has room
for the result, and never reallocates. With buffers sized to one packet,
nothing merged and every TUN write stayed 1430 bytes. Buffers now reserve
64 KB.

### Socket buffers

After batching, neither vpnd was busy: each used about 57% of a core with
the VM a third idle. The receiver's UDP socket was overflowing instead. In
5 s of one stream, 201 `UdpRcvbufErrors` and 2256 TCP retransmits inside the
tunnel. The default 208 KB buffer holds about three GSO bursts, so whenever
the sender got ahead of decryption datagrams were dropped and TCP halved
its window.

vpnd now asks for 7 MB send and receive buffers (what wireguard-go uses),
with SO_RCVBUFFORCE so `net.core.rmem_max` doesn't cap it while vpnd is
still root. Same run afterwards: no drops, no retransmits, 2.37 to 3.98
Gbit/s, and both ends at 90 to 100% of a core. From here one core of
crypto is the limit (#70).
