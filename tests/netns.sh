#!/usr/bin/env bash
# End-to-end check: two network namespaces joined by a veth pair stand in for
# two hosts. vpnd runs in each, and traffic must cross the tunnel between them.
# Needs root. Usage: sudo tests/netns.sh target/debug/vpnd
set -euo pipefail

VPND=$(realpath "${1:?usage: netns.sh path/to/vpnd}")
[ "$(id -u)" = 0 ] || { echo "needs root" >&2; exit 1; }
WORK=$(mktemp -d)

cleanup() {
  status=$?
  if [ $status -ne 0 ]; then
    for side in a b; do echo "--- vpnd $side log"; cat "$WORK/$side.log" 2>/dev/null || true; done
  fi
  for ns in vpn-a vpn-b; do
    ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del $ns 2>/dev/null || true
  done
  rm -rf "$WORK"
  exit $status
}
trap cleanup EXIT

ip netns add vpn-a
ip netns add vpn-b
ip link add veth-a netns vpn-a type veth peer name veth-b netns vpn-b
ip -n vpn-a addr add 172.31.0.1/24 dev veth-a
ip -n vpn-b addr add 172.31.0.2/24 dev veth-b
for ns in vpn-a vpn-b; do ip -n $ns link set lo up; done
ip -n vpn-a link set veth-a up
ip -n vpn-b link set veth-b up

key() { "$VPND" keygen | awk -v f="$1:" '$1 == f { print $2 }'; }
a_priv=$(key private); a_pub=$(echo "$a_priv" | "$VPND" pubkey)
b_priv=$(key private); b_pub=$(echo "$b_priv" | "$VPND" pubkey)

cat > "$WORK/a.toml" <<CONF
[interface]
private_key = "$a_priv"
listen_port = 51820
addresses = ["10.8.0.1/24"]

[[peer]]
public_key = "$b_pub"
allowed_ips = ["10.8.0.2/32"]
CONF

cat > "$WORK/b.toml" <<CONF
[interface]
private_key = "$b_priv"
addresses = ["10.8.0.2/24"]

[[peer]]
public_key = "$a_pub"
endpoint = "172.31.0.1:51820"
allowed_ips = ["10.8.0.0/24"]
CONF
chmod 600 "$WORK"/*.toml

for side in a b; do
  RUST_LOG=${RUST_LOG:-debug} ip netns exec vpn-$side "$VPND" up -c "$WORK/$side.toml" -i tun0 > "$WORK/$side.log" 2>&1 &
done
for ns in vpn-a vpn-b; do
  for _ in $(seq 50); do ip -n $ns link show tun0 > /dev/null 2>&1 && break; sleep 0.1; done
  ip -n $ns link show tun0 > /dev/null
done

echo "== ping b -> a"
ip netns exec vpn-b ping -c 3 -W 2 10.8.0.1
echo "== ping a -> b"
ip netns exec vpn-a ping -c 3 -W 2 10.8.0.2
# 1392 bytes of ICMP payload + 28 bytes of headers = 1420, the tunnel MTU.
# Don't-fragment makes this fail if the outer packet doesn't fit the veth.
echo "== full-MTU ping with DF set"
ip netns exec vpn-b ping -c 2 -W 2 -M do -s 1392 10.8.0.1

echo "== TCP through the tunnel"
head -c 1000000 /dev/urandom > "$WORK/blob"
(cd "$WORK" && exec ip netns exec vpn-a python3 -m http.server 8000 --bind 10.8.0.1 > /dev/null 2>&1) &
for _ in $(seq 50); do ip netns exec vpn-b curl -s -o /dev/null http://10.8.0.1:8000/ && break; sleep 0.1; done
ip netns exec vpn-b curl -sf http://10.8.0.1:8000/blob -o "$WORK/got"
cmp "$WORK/blob" "$WORK/got"
echo "1 MB transferred intact"

echo "PASS"
