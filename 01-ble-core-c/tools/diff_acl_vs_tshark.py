#!/usr/bin/env python3
"""Every HCI ACL packet in a capture, decoded by this library and by Wireshark.

    python3 tools/diff_acl_vs_tshark.py CAPTURE.pcapng [path/to/aclparse]

Compares, per packet: connection handle, PB flag, L2CAP channel and length;
for ATT: opcode, the Attribute Handle where the PDU has one on the wire,
error code, MTU, and handle range. Wireshark also shows a handle for
READ_RSP and WRITE_RSP, taken from the request it matched — those have no
handle field, so they are not compared on it. Likewise Wireshark decodes the
attribute data inside READ_BY_TYPE_RSP and may report a starting or ending
handle found there; only the four range requests carry a range field.
"""
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "04-adv-privacy"))
from bleprivacy import monitor, pcapng  # noqa: E402

FIELDS = ["frame.number", "bthci_acl.chandle", "bthci_acl.pb_flag", "btl2cap.cid",
          "btl2cap.length", "btatt.opcode", "btatt.handle", "btatt.error_code",
          "btatt.client_rx_mtu", "btatt.server_rx_mtu", "btatt.starting_handle",
          "btatt.ending_handle"]
WITH_HANDLE = {0x01, 0x0A, 0x0C, 0x12, 0x52, 0x1B, 0x1D, 0xD2}
WITH_RANGE = {0x04, 0x06, 0x08, 0x10}


def norm(v, width):
    return "-" if v == "" else f"0x{int(v.split(',')[0], 0):0{width}x}"


def main(capture, aclparse):
    frames, hexes = [], []
    for p in pcapng.read_packets(capture):
        _, op, payload = monitor.split(p.data)
        if op in (monitor.ACL_TX, monitor.ACL_RX):
            frames.append(p.frame)
            hexes.append(payload.hex())
    ours = subprocess.run([aclparse], input="\n".join(hexes) + "\n",
                          capture_output=True, text=True, check=True).stdout.splitlines()
    out = subprocess.run(["tshark", "-r", capture, "-Y", "bthci_acl", "-T", "fields",
                          "-E", "separator=\t", "-E", "occurrence=a"] +
                         [a for f in FIELDS for a in ("-e", f)],
                         capture_output=True, text=True, check=True).stdout.splitlines()
    theirs = {int(r.split("\t")[0]): r.split("\t") for r in out}

    compared = mismatches = values = 0
    for frame, row in zip(frames, ours):
        c = row.split("\t")
        t = theirs.get(frame)
        if t is None or len(c) < 4 or c[3] != "OK":
            print(f"frame {frame}: not parsed by the library: {row}")
            mismatches += 1
            continue
        _, chandle, pb, cid, l2len, op, handle, err, cmtu, smtu, start, end = t
        want = [norm(chandle, 3), str(int(pb, 0)), norm(cid, 4), str(int(l2len.split(",")[0]))]
        got = [c[1], c[2], c[4], c[5]]
        if op:
            opv = int(op.split(",")[0], 0)
            mtu = cmtu or smtu
            want += ["OK", norm(op, 2),
                     norm(handle, 4) if opv in WITH_HANDLE else "-",
                     norm(err, 2), str(int(mtu, 0)) if mtu else "-",
                     norm(start, 4) if opv in WITH_RANGE else "-",
                     norm(end, 4) if opv in WITH_RANGE else "-"]
            got += c[6:13]
        compared += 1
        values += len(want)
        if got != want:
            mismatches += 1
            print(f"frame {frame}: ours {got}\n{'':>12}tshark {want}")
    print(f"{compared} ACL packets compared, {values} values")
    print(f"mismatches: {mismatches}")
    return 1 if mismatches else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else
                  str(pathlib.Path(__file__).resolve().parents[1] / "build" / "aclparse")))
