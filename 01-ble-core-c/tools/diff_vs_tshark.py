"""Differential test: ble_hci.c against Wireshark, on every report in a capture.

Unit tests check the cases I thought of. This checks the cases the radio
produced. Each LE advertising report event is decoded twice, once by tshark
and once by build/bleparse, and every field is compared.

Usage: python3 tools/diff_vs_tshark.py CAPTURE.pcapng [path/to/bleparse]
Exit status is non-zero if any report disagrees.
"""
import json
import subprocess
import sys


def first(v):
    return v[0] if isinstance(v, list) else v


def main():
    capture = sys.argv[1]
    bleparse = sys.argv[2] if len(sys.argv) > 2 else "build/bleparse"

    out = subprocess.run(
        ["tshark", "-r", capture, "-Y", "bthci_evt.le_meta_subevent == 0x02 || bthci_evt.le_meta_subevent == 0x0d",
         "-T", "json", "-x", "-J", "bthci_evt"],
        capture_output=True, text=True, check=True).stdout
    pkts = json.loads(out)

    hex_lines, expected = [], []
    for p in pkts:
        layers = p["_source"]["layers"]
        ev = layers["bthci_evt"]
        hex_lines.append(first(layers["bthci_evt_raw"]))
        expected.append({
            "evt_type": int(first(ev["bthci_evt.le_ext_advts_event_type"]), 16),
            "addr_type": int(first(ev["bthci_evt.le_peer_address_type"]), 0),
            "addr": first(ev["bthci_evt.bd_addr"]).lower(),
            "rssi": int(first(ev["bthci_evt.rssi"])),
            "tx_power": int(first(ev["bthci_evt.tx_power"])),
            "data_len": int(first(ev["bthci_evt.data_length"])),
        })

    got = subprocess.run([bleparse], input="\n".join(hex_lines) + "\n",
                         capture_output=True, text=True, check=True).stdout.splitlines()

    fields = ["evt_type", "addr_type", "addr", "rssi", "tx_power", "data_len"]
    mismatches, malformed_ad = [], 0
    if len(got) != len(expected):
        print(f"report count differs: tshark {len(expected)}, bleparse {len(got)}")
        return 1
    for i, (line, exp) in enumerate(zip(got, expected)):
        c = line.split("\t")
        if c[1].startswith("ERR"):
            mismatches.append((i, "parse error", line))
            continue
        mine = {"evt_type": int(c[2], 16), "addr_type": int(c[3]), "addr": c[4],
                "rssi": int(c[5]), "tx_power": int(c[6]), "data_len": int(c[7])}
        malformed_ad += c[8] == "0"
        for f in fields:
            if mine[f] != exp[f]:
                mismatches.append((i, f, f"tshark={exp[f]} bleparse={mine[f]}"))

    n = len(expected)
    print(f"{n} reports compared on {len(fields)} fields each ({n * len(fields)} values)")
    print(f"mismatches: {len(mismatches)}")
    print(f"reports whose AD payload is malformed: {malformed_ad}")
    for m in mismatches[:10]:
        print("  ", m)
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
