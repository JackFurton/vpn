#!/usr/bin/env bash
# Installs packaging/systemd/vpnd@.service on a real systemd host and checks
# the hardened service comes up, holds no privilege, and cleans up after
# itself, including handing DNS to systemd-resolved. Needs root.
# Usage: sudo tests/systemd.sh target/debug/vpnd target/debug/examples/echo_peer
set -euo pipefail

VPND=$(realpath "${1:?usage: systemd.sh VPND ECHO_PEER}")
ECHO=$(realpath "${2:?usage: systemd.sh VPND ECHO_PEER}")
REPO=$(cd "$(dirname "$0")/.." && pwd)
[ "$(id -u)" = 0 ] || { echo "needs root" >&2; exit 1; }
UNIT=vpnd@vpntest

cleanup() {
  status=$?
  if [ $status -ne 0 ]; then
    systemctl status "$UNIT" --no-pager || true
    journalctl -u "$UNIT" --no-pager -o cat | tail -30 || true
  fi
  systemctl stop "$UNIT" 2>/dev/null || true
  [ -n "${ECHO_PID:-}" ] && kill "$ECHO_PID" 2>/dev/null || true
  [ -n "${ECHO2_PID:-}" ] && kill "$ECHO2_PID" 2>/dev/null || true
  rm -f /etc/systemd/system/vpnd@.service /etc/vpnd/vpntest.toml /etc/sysusers.d/vpnd.conf
  systemctl daemon-reload
  exit $status
}
trap cleanup EXIT

install -m 755 "$VPND" /usr/local/bin/vpnd
install -d -m 700 /etc/vpnd
priv=$(vpnd keygen | awk '$1 == "private:" { print $2 }')
pub=$(echo "$priv" | vpnd pubkey)
echo_priv=$(vpnd keygen | awk '$1 == "private:" { print $2 }')
peer=$(echo "$echo_priv" | vpnd pubkey)
# A peer without an interface that answers pings and DNS, so the service has
# something real to talk to.
"$ECHO" 127.0.0.1:51898 "$echo_priv" "$pub" 0.0.0.0/0 2>/dev/null &
ECHO_PID=$!
cat > /etc/vpnd/vpntest.toml <<CONF
[interface]
private_key = "$priv"
listen_port = 51899
addresses = ["10.99.0.2/24"]
dns = ["10.99.0.1"]

[[peer]]
public_key = "$peer"
endpoint = "127.0.0.1:51898"
allowed_ips = ["10.99.0.1/32"]
CONF
chmod 600 /etc/vpnd/vpntest.toml
install -D -m 644 "$REPO/packaging/sysusers.d/vpnd.conf" /etc/sysusers.d/vpnd.conf
systemd-sysusers
install -m 644 "$REPO/packaging/systemd/vpnd@.service" /etc/systemd/system/
systemctl daemon-reload

echo "== start"
systemctl start "$UNIT"
for _ in $(seq 50); do
  systemctl is-active --quiet "$UNIT" && ip link show vpntest > /dev/null 2>&1 && break
  sleep 0.1
done
systemctl is-active --quiet "$UNIT"
ip -br addr show vpntest | grep -q 10.99.0.2/24
# Give vpnd a moment past "tunnel up" to drop its last capability.
for _ in $(seq 50); do
  journalctl -u "$UNIT" -o cat | grep -q "dropped privileges" && break
  sleep 0.1
done

echo "== running unprivileged"
pid=$(systemctl show -p MainPID --value "$UNIT")
grep -E '^(Uid|CapEff|CapPrm|CapAmb|NoNewPrivs)' "/proc/$pid/status"
uid=$(awk '/^Uid:/ { print $2 }' "/proc/$pid/status")
[ "$uid" = "$(id -u vpnd)" ] || { echo "running as uid $uid, not vpnd"; exit 1; }
grep -q '^CapEff:[[:space:]]*0000000000000000$' "/proc/$pid/status"
grep -q '^CapPrm:[[:space:]]*0000000000000000$' "/proc/$pid/status"

echo "== DNS through the tunnel via systemd-resolved"
resolvectl dns vpntest | tee /dev/stderr | grep -q 10.99.0.1
probe="probe-$$-$RANDOM.vpnd.test"
resolvectl query --cache=no "$probe" | tee /dev/stderr | grep -q 192.0.2.53

echo "== reload adds a peer without a restart"
echo2_priv=$(vpnd keygen | awk '$1 == "private:" { print $2 }')
"$ECHO" 127.0.0.1:51897 "$echo2_priv" "$pub" 0.0.0.0/0 2>/dev/null &
ECHO2_PID=$!
if ping -c 1 -W 1 10.99.0.3 > /dev/null; then echo "10.99.0.3 answered before it was added"; exit 1; fi
cat >> /etc/vpnd/vpntest.toml <<CONF

[[peer]]
public_key = "$(echo "$echo2_priv" | vpnd pubkey)"
endpoint = "127.0.0.1:51897"
allowed_ips = ["10.99.0.3/32"]
CONF
systemctl reload "$UNIT"
[ "$(systemctl show -p MainPID --value "$UNIT")" = "$pid" ] || { echo "reload restarted vpnd"; exit 1; }
journalctl -u "$UNIT" -o cat | grep "reloaded peers" | tail -1 | tee /dev/stderr | grep -q "added=1"
ping -c 3 -W 2 10.99.0.3

echo "== systemd's exposure score"
systemd-analyze security "$UNIT" --no-pager | tail -1

echo "== stop removes the interface"
systemctl stop "$UNIT"
# Not `! cmd`: set -e ignores a negated command's status.
if ip link show vpntest > /dev/null 2>&1; then echo "vpntest still exists"; exit 1; fi
if resolvectl dns vpntest > /dev/null 2>&1; then echo "vpntest still has DNS"; exit 1; fi

echo "PASS"
