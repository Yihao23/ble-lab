#!/usr/bin/env bash
# Capture everything between bluetoothd and the controller while holding an
# LE discovery open.  ./capture.sh [minutes]   (default 5)
# Needs: dumpcap with permission on bluetooth-monitor (wireshark group), a
# running bluetoothd, python3-dbus. Output goes to captures/, which git ignores:
# a capture of the air holds your neighbours' addresses.
set -euo pipefail
cd "$(dirname "$0")"
MIN=${1:-5}
SECS=$((MIN * 60))
mkdir -p captures
OUT="captures/scan-$(date +%Y%m%d-%H%M)-${MIN}min.pcapng"
echo "writing $OUT"
dumpcap -q -i bluetooth-monitor -a "duration:$((SECS + 10))" -w "$OUT" &
DP=$!
sleep 1
python3 discovery_hold.py --seconds "$SECS"
wait "$DP"
python3 layers.py "$OUT"
