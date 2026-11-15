#!/usr/bin/env bash
# Throughput through one vpnd on one host, for macOS where bench.sh's
# namespaces don't exist. A UDP blaster sends through the tunnel interface
# to echo_peer, which echoes port 7 back, so every datagram crosses vpnd
# twice: encrypted on the way out, decrypted on the way back. echo_peer
# does the same crypto, so check vpnd's CPU to see which side is the limit.
# Needs root and python3. Build first: cargo build --release -p vpnd --bins --examples
# Usage: sudo tests/bench-macos.sh target/release/vpnd target/release/examples/echo_peer [seconds]
set -euo pipefail

VPND=$(realpath "${1:?usage: bench-macos.sh VPND ECHO_PEER [seconds]}")
ECHO=$(realpath "${2:?usage: bench-macos.sh VPND ECHO_PEER [seconds]}")
SECS=${3:-10}
[ "$(id -u)" = 0 ] || { echo "needs root" >&2; exit 1; }
WORK=$(mktemp -d)
PIDS=()

cleanup() {
  status=$?
  [ $status -eq 0 ] || cat "$WORK"/*.log 2>/dev/null || true
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$WORK"
  exit $status
}
trap cleanup EXIT

key() { "$VPND" keygen | awk -v f="$1:" '$1 == f { print $2 }'; }
c_priv=$(key private); c_pub=$(echo "$c_priv" | "$VPND" pubkey)
e_priv=$(key private); e_pub=$(echo "$e_priv" | "$VPND" pubkey)

"$ECHO" 127.0.0.1:51830 "$e_priv" "$c_pub" 10.8.0.2/32 2> "$WORK/echo.log" &
PIDS+=($!)
cat > "$WORK/client.toml" <<CONF
[interface]
private_key = "$c_priv"
addresses = ["10.8.0.2/24"]

[[peer]]
public_key = "$e_pub"
endpoint = "127.0.0.1:51830"
allowed_ips = ["10.8.0.1/32"]
CONF
chmod 600 "$WORK/client.toml"
"$VPND" up -c "$WORK/client.toml" > "$WORK/vpnd.log" 2>&1 &
VPND_PID=$!
PIDS+=($VPND_PID)
for _ in $(seq 50); do ping -c 1 -t 1 10.8.0.1 > /dev/null 2>&1 && break; sleep 0.1; done
ping -c 1 -t 2 10.8.0.1 > /dev/null

# CPU seconds (user + system) a process has used.
cpu() { ps -o time= -p "$1" | awk -F: '{ print $(NF-1) * 60 + $NF }'; }

cpu_model=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m)
echo "== UDP echo through vpnd, ${SECS}s ($(sysctl -n hw.ncpu) CPUs, $cpu_model, $(uname -sr))"
for size in 1400 100; do
  before_v=$(cpu $VPND_PID); before_e=$(cpu "${PIDS[0]}")
  python3 - "$size" "$SECS" <<'PY'
import socket, sys, time
size, secs = int(sys.argv[1]), float(sys.argv[2])
payload = b"\xab" * (size - 28)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
s.connect(("10.8.0.1", 7))
s.setblocking(False)
sent = got = written_off = 0
end = time.monotonic() + secs
last = time.monotonic()
while (now := time.monotonic()) < end:
    # Keep a bounded number in flight so the tunnel, not loss, sets the
    # pace. Anything unanswered after 20 ms counts as lost.
    if now - last > 0.02:
        written_off, last = sent - got, now
    while sent - got - written_off < 256:
        try:
            s.send(payload)
            sent += 1
        except BlockingIOError:
            break
        except OSError:  # ENOBUFS: the interface queue is full
            break
    try:
        while True:
            s.recv(65535)
            got += 1
            last = time.monotonic()
    except BlockingIOError:
        pass
gbits = got * size * 8 / secs / 1e9
print(f"{size:>5} B  {got / secs / 1e3:7.1f}k echoes/s  {gbits:5.2f} Gbit/s each way  (sent {sent}, lost {sent - got})")
PY
  after_v=$(cpu $VPND_PID); after_e=$(cpu "${PIDS[0]}")
  awk -v a="$before_v" -v b="$after_v" -v c="$before_e" -v d="$after_e" -v s="$SECS" \
    'BEGIN { printf "       vpnd CPU %.0f%%, echo_peer CPU %.0f%%\n", (b - a) / s * 100, (d - c) / s * 100 }'
done
