#!/usr/bin/env bash
# Installs packaging/systemd/vpnd@.service on a real systemd host and checks
# the hardened service comes up, holds no privilege, and cleans up after
# itself. Needs root. Usage: sudo tests/systemd.sh target/debug/vpnd
set -euo pipefail

VPND=$(realpath "${1:?usage: systemd.sh path/to/vpnd}")
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
  rm -f /etc/systemd/system/vpnd@.service /etc/vpnd/vpntest.toml
  systemctl daemon-reload
  exit $status
}
trap cleanup EXIT

install -m 755 "$VPND" /usr/local/bin/vpnd
install -d -m 700 /etc/vpnd
priv=$(vpnd keygen | awk '$1 == "private:" { print $2 }')
peer=$(vpnd keygen | awk '$1 == "public:" { print $2 }')
cat > /etc/vpnd/vpntest.toml <<CONF
[interface]
private_key = "$priv"
listen_port = 51899
addresses = ["10.99.0.1/24"]

[[peer]]
public_key = "$peer"
allowed_ips = ["10.99.0.2/32"]
CONF
chmod 600 /etc/vpnd/vpntest.toml
install -m 644 "$REPO/packaging/systemd/vpnd@.service" /etc/systemd/system/
systemctl daemon-reload

echo "== start"
systemctl start "$UNIT"
for _ in $(seq 50); do
  systemctl is-active --quiet "$UNIT" && ip link show vpntest > /dev/null 2>&1 && break
  sleep 0.1
done
systemctl is-active --quiet "$UNIT"
ip -br addr show vpntest | grep -q 10.99.0.1/24
# Give vpnd a moment past "tunnel up" to drop its last capability.
for _ in $(seq 50); do
  journalctl -u "$UNIT" -o cat | grep -q "dropped privileges" && break
  sleep 0.1
done

echo "== running unprivileged"
pid=$(systemctl show -p MainPID --value "$UNIT")
grep -E '^(Uid|CapEff|CapPrm|CapAmb|NoNewPrivs)' "/proc/$pid/status"
uid=$(awk '/^Uid:/ { print $2 }' "/proc/$pid/status")
[ "$uid" != 0 ] || { echo "running as root"; exit 1; }
grep -q '^CapEff:[[:space:]]*0000000000000000$' "/proc/$pid/status"
grep -q '^CapPrm:[[:space:]]*0000000000000000$' "/proc/$pid/status"

echo "== systemd's exposure score"
systemd-analyze security "$UNIT" --no-pager | tail -1

echo "== stop removes the interface"
systemctl stop "$UNIT"
! ip link show vpntest > /dev/null 2>&1

echo "PASS"
