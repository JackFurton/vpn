#!/usr/bin/env bash
# iperf3 between two network namespaces over three paths: the bare veth
# link, a vpnd tunnel, and kernel WireGuard. Same link, same MTU, so the
# gaps are the cost of each tunnel.
# Needs root, iperf3, wg and python3. Build vpnd with --release first.
# Usage: sudo tests/bench.sh target/release/vpnd [seconds]
set -euo pipefail

VPND=$(realpath "${1:?usage: bench.sh path/to/vpnd [seconds]}")
SECS=${2:-10}
[ "$(id -u)" = 0 ] || { echo "needs root" >&2; exit 1; }
WORK=$(mktemp -d)
# Ubuntu's AppArmor profile for wg only lets it read keys under /etc/wireguard.
mkdir -p /etc/wireguard
WGKEYS=$(mktemp -d /etc/wireguard/bench.XXXXXX)

cleanup() {
  status=$?
  [ $status -eq 0 ] || cat "$WORK"/*.log 2>/dev/null || true
  for ns in bench-a bench-b; do
    ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del $ns 2>/dev/null || true
  done
  rm -rf "$WORK" "$WGKEYS"
  exit $status
}
trap cleanup EXIT

for ns in bench-a bench-b; do ip netns add $ns; ip -n $ns link set lo up; done
ip link add veth-a netns bench-a type veth peer name veth-b netns bench-b
ip -n bench-a addr add 172.31.0.1/24 dev veth-a
ip -n bench-b addr add 172.31.0.2/24 dev veth-b
ip -n bench-a link set veth-a up
ip -n bench-b link set veth-b up

key() { "$VPND" keygen | awk -v f="$1:" '$1 == f { print $2 }'; }
a_priv=$(key private); a_pub=$(echo "$a_priv" | "$VPND" pubkey)
b_priv=$(key private); b_pub=$(echo "$b_priv" | "$VPND" pubkey)

pids=()
# vpnd on 10.8.0.0/24, port 51820.
for side in a b; do
  if [ $side = a ]; then priv=$a_priv peer=$b_pub n=1 m=2 endpoint=
  else priv=$b_priv peer=$a_pub n=2 m=1 endpoint='endpoint = "172.31.0.1:51820"'; fi
  cat > "$WORK/$side.toml" <<CONF
[interface]
private_key = "$priv"
listen_port = 51820
addresses = ["10.8.0.$n/24"]

[[peer]]
public_key = "$peer"
$endpoint
allowed_ips = ["10.8.0.$m/32"]
CONF
  chmod 600 "$WORK/$side.toml"
  ip netns exec bench-$side "$VPND" up -c "$WORK/$side.toml" -i tun0 > "$WORK/vpnd-$side.log" 2>&1 &
  pids+=($!)
done

# Kernel WireGuard on 10.9.0.0/24, port 51821, with the same keys. Both use
# Curve25519 keys in the same encoding, so vpnd's keys work as-is.
for side in a b; do
  if [ $side = a ]; then priv=$a_priv peer=$b_pub n=1 m=2 endpoint=()
  else priv=$b_priv peer=$a_pub n=2 m=1 endpoint=(endpoint 172.31.0.1:51821); fi
  echo "$priv" > "$WGKEYS/$side.key"
  ip -n bench-$side link add wg0 type wireguard
  ip netns exec bench-$side wg set wg0 listen-port 51821 private-key "$WGKEYS/$side.key" \
    peer "$peer" allowed-ips 10.9.0.$m/32 "${endpoint[@]}"
  ip -n bench-$side addr add 10.9.0.$n/24 dev wg0
  ip -n bench-$side link set wg0 mtu 1420 up
done

for ns in bench-a bench-b; do
  for _ in $(seq 50); do ip -n $ns link show tun0 > /dev/null 2>&1 && break; sleep 0.1; done
done
# Handshakes, so neither tunnel's first second is spent setting up.
ip netns exec bench-b ping -c 2 -W 2 10.8.0.1 > /dev/null
ip netns exec bench-b ping -c 2 -W 2 10.9.0.1 > /dev/null

ip netns exec bench-a iperf3 -s -D -I "$WORK/iperf3.pid" --logfile "$WORK/iperf3.log"
sleep 0.5

# CPU time (user + system, in clock ticks) of both vpnd processes.
vpnd_ticks() { for p in "${pids[@]}"; do awk '{ print $14 + $15 }' /proc/$p/stat; done | paste -sd' '; }

run() {
  local name=$1 addr=$2
  shift 2
  local before; before=$(vpnd_ticks)
  ip netns exec bench-b iperf3 -c "$addr" -t "$SECS" -J "$@" > "$WORK/out.json"
  python3 - "$name" "$WORK/out.json" "$before" "$(vpnd_ticks)" "$(getconf CLK_TCK)" "$SECS" <<'PY'
import json, sys
name, out, before, after, tck, secs = sys.argv[1:]
end = json.load(open(out))["end"]
gbits = end["sum_received"]["bits_per_second"] / 1e9
line = f"{name:<18} {gbits:6.2f} Gbit/s"
if name == "vpnd":
    # Kernel WireGuard runs in softirq and kworkers, so only vpnd gets this.
    used = [(int(a) - int(b)) / int(tck) / int(secs) * 100
            for b, a in zip(before.split(), after.split())]
    line += f"   vpnd CPU: client {used[1]:.0f}%, server {used[0]:.0f}%"
print(line)
PY
}

echo "== TCP, one stream, ${SECS}s, b to a ($(nproc) CPUs, $(uname -r))"
run "veth" 172.31.0.1
run "vpnd" 10.8.0.1
run "kernel wireguard" 10.9.0.1
echo "== TCP, four streams"
run "veth" 172.31.0.1 -P 4
run "vpnd" 10.8.0.1 -P 4
run "kernel wireguard" 10.9.0.1 -P 4
