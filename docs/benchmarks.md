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

Numbers below were recorded on 2026-11-14 at v0.2.0. Re-run before trusting
them for anything newer.

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
veth               129.01 Gbit/s
vpnd                 1.04 Gbit/s   vpnd CPU: client 78%, server 76%
kernel wireguard     8.22 Gbit/s
== TCP, four streams
veth               233.41 Gbit/s
vpnd                 0.96 Gbit/s   vpnd CPU: client 79%, server 68%
kernel wireguard     9.53 Gbit/s
```

GitHub ubuntu-latest runner, 4 vCPUs of an AMD EPYC 9V74, Linux 7.0 (azure):

```
== TCP, one stream
veth                39.71 Gbit/s
vpnd                 0.42 Gbit/s   vpnd CPU: client 127%, server 124%
kernel wireguard     1.50 Gbit/s
== TCP, four streams
veth                78.58 Gbit/s
vpnd                 0.41 Gbit/s   vpnd CPU: client 126%, server 124%
kernel wireguard     1.48 Gbit/s
```

vpnd gets about a sixth of the crypto ceiling on the M5 (a tenth on the
runner), and four streams don't help. That points at per-packet costs outside the crypto: every packet
takes a TUN read and a UDP send on one side, and a UDP receive and TUN
write on the other, each a syscall with a copy. Kernel WireGuard pays none
of those, hands the stack whole 64 KB segments with GSO/GRO, and spreads
crypto over every core. Batching I/O is #68, and it should be profiled
before it's built.

The veth numbers are only there to show the link itself isn't the limit.
