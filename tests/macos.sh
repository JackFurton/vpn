#!/usr/bin/env bash
# End-to-end on one host: vpnd brings up the OS tunnel interface, and the
# echo_peer example (a tunnel peer with no interface) answers pings sent
# through it. Written for macOS, where there are no network namespaces for
# netns.sh, but it runs on Linux too.
# Needs root for vpnd. Usage: sudo tests/macos.sh target/debug/vpnd target/debug/examples/echo_peer
set -euo pipefail

VPND=$(realpath "${1:?usage: macos.sh VPND ECHO_PEER}")
ECHO=$(realpath "${2:?usage: macos.sh VPND ECHO_PEER}")
[ "$(id -u)" = 0 ] || { echo "needs root" >&2; exit 1; }
WORK=$(mktemp -d)
PIDS=()

cleanup() {
  status=$?
  [ $status -ne 0 ] && { echo "--- vpnd log"; cat "$WORK/vpnd.log" 2>/dev/null || true; }
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  if [ -n "${PF_TOKEN:-}" ]; then
    pfctl -a com.apple/vpnd-test -F all 2>/dev/null || true
    pfctl -X "$PF_TOKEN" 2>/dev/null || true
  fi
  wait 2>/dev/null || true
  rm -rf "$WORK"
  exit $status
}
trap cleanup EXIT

key() { "$VPND" keygen | awk -v f="$1:" '$1 == f { print $2 }'; }
c_priv=$(key private); c_pub=$(echo "$c_priv" | "$VPND" pubkey)
e_priv=$(key private); e_pub=$(echo "$e_priv" | "$VPND" pubkey)

"$ECHO" 127.0.0.1:51820 "$e_priv" "$c_pub" 0.0.0.0/0 2> "$WORK/echo.log" &
PIDS+=($!)

run_client() {
  cat > "$WORK/client.toml" <<CONF
[interface]
private_key = "$c_priv"
addresses = ["10.8.0.2/24"]
${2:-}

[[peer]]
public_key = "$e_pub"
endpoint = "127.0.0.1:51820"
allowed_ips = [$1]
CONF
  chmod 600 "$WORK/client.toml"
  "$VPND" up -c "$WORK/client.toml" > "$WORK/vpnd.log" 2>&1 &
  CLIENT=$!
  PIDS+=($CLIENT)
  for _ in $(seq 50); do grep -q "tunnel up" "$WORK/vpnd.log" && break; sleep 0.1; done
  IFACE=$(sed -n 's/.*tunnel up.*interface="\([^"]*\)".*/\1/p' "$WORK/vpnd.log")
  [ -n "$IFACE" ] || { echo "vpnd didn't come up"; exit 1; }
  echo "interface $IFACE"
}

stop_client() {
  kill -INT "$CLIENT"
  wait "$CLIENT" || true
}

echo "== split tunnel"
run_client '"10.8.0.0/24"'
ping -c 3 10.8.0.1
stop_client

echo "== full tunnel"
run_client '"0.0.0.0/0"'
# 192.0.2.1 is a documentation address nothing answers on the real network.
# A reply proves the default route goes through the tunnel to echo_peer.
ping -c 3 192.0.2.1
stop_client
echo "== routes restored after exit"
if [ "$(uname)" = Darwin ]; then
  ! route -n get 192.0.2.1 2>/dev/null | grep -q "interface: $IFACE"
else
  ! ip route get 192.0.2.1 2>/dev/null | grep -q "dev $IFACE"
fi

if [ "$(uname)" = Darwin ]; then
  echo "== full tunnel, server changes address"
  # pf rewrites echo_peer's packets to come from 198.18.0.1, as if the
  # server had moved there. The client follows, and 198.18.0.1 is only
  # reachable by the default route, which the tunnel has captured. So vpnd
  # has to add a host route for it through the real default route.
  echo "nat on lo0 inet proto udp from 127.0.0.1 port 51820 to 127.0.0.1 -> 198.18.0.1 static-port" \
    | pfctl -a com.apple/vpnd-test -f - 2>/dev/null
  PF_TOKEN=$(pfctl -E 2>&1 | sed -n 's/^Token : //p')
  run_client '"0.0.0.0/0"'
  # Replies arrive from the new address; later pings are lost, since nothing
  # on the real network answers 198.18.0.1.
  ping -c 2 192.0.2.1 || true
  grep -q "endpoint route added.*ep=198.18.0.1" "$WORK/vpnd.log"
  via=$(route -n get 198.18.0.1 | awk '/interface:/ { print $2 }')
  echo "198.18.0.1 goes out $via"
  [ -n "$via" ] && [ "$via" != "$IFACE" ]
  stop_client
  pfctl -a com.apple/vpnd-test -F all 2>/dev/null
  pfctl -X "$PF_TOKEN" 2>/dev/null
  PF_TOKEN=
  echo "== endpoint route removed after exit"
  route -n get 198.18.0.1 | grep "destination: default" > /dev/null
fi

# Linux DNS goes through systemd-resolved, which tests/systemd.sh covers.
if [ "$(uname)" = Darwin ]; then
  echo "== DNS through the tunnel"
  # A fresh name each run, so nothing answers from cache.
  probe="probe-$$-$RANDOM.vpnd.test"
  run_client '"10.8.0.0/24"' 'dns = ["10.8.0.1"]'
  dscacheutil -q host -a name "$probe" | tee "$WORK/dns.out"
  grep -q "192.0.2.53" "$WORK/dns.out"
  stop_client
  echo "show State:/Network/Service/vpnd-$IFACE/DNS" | scutil | grep -q "No such key"
fi

echo "PASS"
