#!/usr/bin/env bash
# End-to-end check: network namespaces joined by veth pairs stand in for
# hosts. vpnd runs in each, and traffic must cross the tunnel between them.
# a is the server. b reaches it over IPv4 and c over IPv6 only, so a's one
# dual-stack socket has to serve both.
# Needs root. Usage: sudo tests/netns.sh target/debug/vpnd
set -euo pipefail

VPND=$(realpath "${1:?usage: netns.sh path/to/vpnd}")
[ "$(id -u)" = 0 ] || { echo "needs root" >&2; exit 1; }
WORK=$(mktemp -d)

cleanup() {
  status=$?
  if [ $status -ne 0 ]; then
    for side in a b c; do echo "--- vpnd $side log"; cat "$WORK/$side.log" 2>/dev/null || true; done
  fi
  for ns in vpn-a vpn-b vpn-c; do
    ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del $ns 2>/dev/null || true
  done
  rm -rf "$WORK"
  exit $status
}
trap cleanup EXIT

for ns in vpn-a vpn-b vpn-c; do ip netns add $ns; ip -n $ns link set lo up; done
ip link add veth-a netns vpn-a type veth peer name veth-b netns vpn-b
ip -n vpn-a addr add 172.31.0.1/24 dev veth-a
ip -n vpn-b addr add 172.31.0.2/24 dev veth-b
# nodad: skip duplicate address detection, which holds a new IPv6 address
# unusable for a second or so.
ip link add veth-a6 netns vpn-a type veth peer name veth-c netns vpn-c
ip -n vpn-a addr add fd31::1/64 dev veth-a6 nodad
ip -n vpn-c addr add fd31::3/64 dev veth-c nodad
ip -n vpn-a link set veth-a up
ip -n vpn-a link set veth-a6 up
ip -n vpn-b link set veth-b up
ip -n vpn-c link set veth-c up

key() { "$VPND" keygen | awk -v f="$1:" '$1 == f { print $2 }'; }
a_priv=$(key private); a_pub=$(echo "$a_priv" | "$VPND" pubkey)
b_priv=$(key private); b_pub=$(echo "$b_priv" | "$VPND" pubkey)
c_priv=$(key private); c_pub=$(echo "$c_priv" | "$VPND" pubkey)

cat > "$WORK/a.toml" <<CONF
[interface]
private_key = "$a_priv"
listen_port = 51820
addresses = ["10.8.0.1/24"]

[[peer]]
public_key = "$b_pub"
allowed_ips = ["10.8.0.2/32"]

[[peer]]
public_key = "$c_pub"
allowed_ips = ["10.8.0.3/32"]
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

cat > "$WORK/c.toml" <<CONF
[interface]
private_key = "$c_priv"
addresses = ["10.8.0.3/24"]

[[peer]]
public_key = "$a_pub"
endpoint = "[fd31::1]:51820"
allowed_ips = ["10.8.0.0/24"]
CONF
chmod 600 "$WORK"/*.toml

for side in a b c; do
  RUST_LOG=${RUST_LOG:-debug} ip netns exec vpn-$side "$VPND" up -c "$WORK/$side.toml" -i tun0 > "$WORK/$side.log" 2>&1 &
done
for ns in vpn-a vpn-b vpn-c; do
  for _ in $(seq 50); do ip -n $ns link show tun0 > /dev/null 2>&1 && break; sleep 0.1; done
  ip -n $ns link show tun0 > /dev/null
done

echo "== ping b -> a"
ip netns exec vpn-b ping -c 3 -W 2 10.8.0.1
echo "== ping a -> b"
ip netns exec vpn-a ping -c 3 -W 2 10.8.0.2
# 1392 bytes of ICMP payload + 28 bytes of headers = 1420, the tunnel MTU.
# Don't-fragment makes this fail if the outer packet doesn't fit the veth.
echo "== ping c -> a, outer transport IPv6"
ip netns exec vpn-c ping -c 3 -W 2 10.8.0.1
echo "== ping a -> c"
ip netns exec vpn-a ping -c 3 -W 2 10.8.0.3
grep -q 'listen=\[::\]:51820' "$WORK/a.log" || { echo "server isn't dual-stack"; exit 1; }
echo "== full-MTU ping with DF set"
ip netns exec vpn-b ping -c 2 -W 2 -M do -s 1392 10.8.0.1
# Over IPv6 the outer overhead is 80 bytes, so 1420 + 80 fills the 1500-byte
# veth exactly. This is the tight case for the default MTU.
ip netns exec vpn-c ping -c 2 -W 2 -M do -s 1392 10.8.0.1

echo "== TCP through the tunnel"
head -c 1000000 /dev/urandom > "$WORK/blob"
(cd "$WORK" && exec ip netns exec vpn-a python3 -m http.server 8000 --bind 10.8.0.1 > /dev/null 2>&1) &
for _ in $(seq 50); do ip netns exec vpn-b curl -s -o /dev/null http://10.8.0.1:8000/ && break; sleep 0.1; done
ip netns exec vpn-b curl -sf http://10.8.0.1:8000/blob -o "$WORK/got"
cmp "$WORK/blob" "$WORK/got"
echo "1 MB transferred intact"

echo "PASS"
