#!/usr/bin/env python3
"""Recompute the six digits of a real numeric-comparison pairing from its capture.

    python3 tools/pairing_from_capture.py CAPTURE.pcapng [path/to/bleg2]

For every pairing attempt in the capture (one per Pairing Request) this
takes the two public keys and the two nonces off the air, checks they were
read correctly by recomputing the responder's commitment Cb = f4(PKbx, PKax,
Nb, 0) and comparing it with the Pairing Confirm on air, then runs this
library's ble_sc_g2 through tools/bleg2.c. The number printed is the one
both screens showed — if the library is right.

The initiator is whichever side sent Pairing Request. In a bluetooth-monitor
capture, hci_mon opcode 5 is a packet the host received, 4 one it sent.
The f4 check needs pyca/cryptography; without it the check is skipped.
Needs tshark.
"""
import pathlib
import subprocess
import sys

PAIRING_REQUEST, CONFIRM, RANDOM, PUBLIC_KEY, DHKEY_CHECK = "0x01", "0x03", "0x04", "0x0c", "0x0d"
IO_CAP = {"0x00": "DisplayOnly", "0x01": "DisplayYesNo", "0x02": "KeyboardOnly",
          "0x03": "NoInputNoOutput", "0x04": "KeyboardDisplay"}


def smp_packets(capture):
    fields = ["hci_mon.opcode", "btsmp.opcode", "btsmp.io_capability",
              "btsmp.public_key_x", "btsmp.cfm_value", "btsmp.random_value"]
    out = subprocess.run(["tshark", "-r", str(capture), "-Y", "btsmp", "-T", "fields",
                          "-E", "separator=;"] + [a for f in fields for a in ("-e", f)],
                         capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        direction, op, io, pkx, cfm, rnd = line.split(";")
        yield {"dir": direction, "op": op, "io": io, "pkx": pkx, "cfm": cfm, "rnd": rnd}


def attempts(packets):
    """Split the packet stream at each Pairing Request. Returns a list: each
    attempt must be complete before anything reads it."""
    out = []
    for p in packets:
        if p["op"] == PAIRING_REQUEST:
            out.append([p])
        elif out:
            out[-1].append(p)
    return out


def f4_check(pkax, pkbx, nb, cb):
    """True/False if Cb on air equals f4(PKbx, PKax, Nb, 0); None without cryptography."""
    try:
        from cryptography.hazmat.primitives.ciphers import algorithms
        from cryptography.hazmat.primitives.cmac import CMAC
    except ImportError:
        return None
    msb = lambda h: bytes.fromhex(h)[::-1]         # on air LSB-first -> spec MSB-first
    c = CMAC(algorithms.AES(msb(nb)))
    c.update(msb(pkbx) + msb(pkax) + b"\x00")
    return c.finalize() == msb(cb)


def report(n, att, bleg2):
    init = att[0]["dir"]                            # the side that sent Pairing Request
    get = lambda initiator, op, key: next(
        (p[key] for p in att if (p["dir"] == init) == initiator and p["op"] == op and p[key]), None)
    io = [p["io"] for p in att if p["io"]][:2]
    pkax, pkbx = get(True, PUBLIC_KEY, "pkx"), get(False, PUBLIC_KEY, "pkx")
    na, nb, cb = get(True, RANDOM, "rnd"), get(False, RANDOM, "rnd"), get(False, CONFIRM, "cfm")
    done = sum(p["op"] == DHKEY_CHECK for p in att) == 2

    print(f"pairing attempt {n}: initiator {'received' if init == '5' else 'sent'} by this host; "
          f"IO {' / '.join(IO_CAP.get(i, i) for i in io)}; "
          f"{'completed (both DHKey checks)' if done else 'NOT completed'}")
    if None in (pkax, pkbx, na, nb):
        print("  keys or nonces missing: not a numeric-comparison exchange that got that far\n")
        return
    ok = f4_check(pkax, pkbx, nb, cb) if cb else None
    print(f"  Cb = f4(PKbx, PKax, Nb, 0) matches the Pairing Confirm on air: "
          f"{'yes' if ok else 'NO' if ok is False else 'not checked'}")
    out = subprocess.run([bleg2, pkax, pkbx, na, nb], capture_output=True, text=True, check=True)
    print(f"  ble_sc_g2: {out.stdout.strip()}\n")


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    here = pathlib.Path(__file__).resolve().parents[1]
    bleg2 = argv[2] if len(argv) > 2 else str(here / "build" / "bleg2")
    found = 0
    for n, att in enumerate(attempts(smp_packets(argv[1])), 1):
        report(n, att, bleg2)
        found += 1
    if not found:
        print("no Pairing Request in this capture")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
