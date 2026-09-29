"""Read a bluetooth-monitor capture one layer at a time and print what each
layer says. Every number in REPORT-01.md comes from this script.

    python3 layers.py captures/scan-*.pcapng

Addresses are never printed, only counted and classified.
"""
import pathlib
import statistics
import struct
import sys
from collections import Counter

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "04-adv-privacy"))
from bleprivacy import addr, hci, monitor, pcapng  # noqa: E402

# Linux monitor opcodes (include/net/bluetooth/hci_mon.h)
MON = {0: "NEW_INDEX", 1: "DEL_INDEX", 2: "COMMAND", 3: "EVENT", 4: "ACL_TX", 5: "ACL_RX",
       8: "OPEN_INDEX", 9: "CLOSE_INDEX", 10: "INDEX_INFO", 12: "SYSTEM_NOTE",
       14: "CTRL_OPEN", 15: "CTRL_CLOSE", 16: "CTRL_COMMAND", 17: "CTRL_EVENT"}
CMD = {0x2005: "LE Set Random Address", 0x2041: "LE Set Extended Scan Parameters",
       0x2042: "LE Set Extended Scan Enable", 0x2036: "LE Set Extended Advertising Parameters",
       0x2037: "LE Set Extended Advertising Data", 0x2038: "LE Set Extended Scan Response Data",
       0x2039: "LE Set Extended Advertising Enable", 0x0C52: "Write Extended Inquiry Response"}
MGMT_EVT = {0x0001: "Command Complete", 0x0012: "Device Found", 0x0013: "Discovering"}


def scan_params(p):
    """LE Set Extended Scan Parameters, Core Vol 4 Part E 7.8.64."""
    own, policy, phys = p[0], p[1], p[2]
    out, pos = [], 3
    for bit, name in ((0, "1M"), (2, "Coded")):
        if phys >> bit & 1:
            stype, ivl, win = struct.unpack_from("<BHH", p, pos)
            out.append(f"{name}: {'active' if stype else 'passive'}, "
                       f"interval {ivl * 0.625:g} ms, window {win * 0.625:g} ms")
            pos += 5
    return own, policy, out


def main(path):
    ops, cmds, evts, mgmt = Counter(), Counter(), Counter(), Counter()
    params, enables, rand_times, rand_kinds, rand_addrs = Counter(), Counter(), [], Counter(), set()
    adv = rsp = 0
    for pk in pcapng.read_packets(path):
        _, op, pl = monitor.split(pk.data)
        ops[op] += 1
        if op == monitor.COMMAND_PKT:
            (opcode,) = struct.unpack_from("<H", pl, 0)
            cmds[opcode] += 1
            body = pl[3:]
            if opcode == 0x2041:
                own, policy, phys = scan_params(body)
                params[(own, policy, tuple(phys))] += 1
            elif opcode == 0x2042:
                enables[struct.unpack_from("<BBHH", body)] += 1
            elif opcode == 0x2005:
                rand_times.append(pk.ts)
                rand_kinds[addr.kind(0x01, body[:6])] += 1
                rand_addrs.add(body[:6])
        elif op == monitor.EVENT_PKT:
            evts[pl[0] if pl[0] != hci.LE_META else (pl[0], pl[2])] += 1
            for r in hci.parse_adv_reports(pl):
                rsp += r.is_scan_response
                adv += not r.is_scan_response
        elif op == 17:                      # CTRL_EVENT: cookie(4), mgmt event code(2), ...
            mgmt[struct.unpack_from("<H", pl, 4)[0]] += 1

    print("1. Monitor layer: what the kernel copied to the capture")
    for k, v in sorted(ops.items()):
        print(f"   {MON.get(k, k):<13} {v:>6}")
    print("\n2. HCI commands, host -> controller")
    for k, v in cmds.most_common():
        print(f"   0x{k:04X} {CMD.get(k, '?'):<40} {v:>5}")
    for (own, policy, phys), v in params.items():
        print(f"   scan parameters x{v}: own address type {own}, filter policy {policy}")
        for line in phys:
            print(f"      {line}")
    for (en, dup, dur, per), v in sorted(enables.items()):
        print(f"   scan enable={en} filter_duplicates={dup} duration={dur} period={per}  x{v}")
    if len(rand_times) > 1:
        gaps = [b - a for a, b in zip(rand_times, rand_times[1:])]
        print(f"   scanner address set {len(rand_times)} times, {len(rand_addrs)} distinct, "
              f"kinds {dict(rand_kinds)}; every {statistics.median(gaps):.3f} s "
              f"(min {min(gaps):.3f}, max {max(gaps):.3f})")
    print("\n3. HCI events, controller -> host")
    for k, v in evts.most_common():
        name = f"LE Meta, subevent 0x{k[1]:02X}" if isinstance(k, tuple) else f"event 0x{k:02X}"
        print(f"   {name:<28} {v:>6}")
    print(f"   advertising reports {adv + rsp}: {adv} advertisements, {rsp} scan responses")
    print("\n4. Management events, kernel -> bluetoothd")
    for k, v in mgmt.most_common():
        print(f"   0x{k:04X} {MGMT_EVT.get(k, '?'):<20} {v:>6}")


if __name__ == "__main__":
    for p in sys.argv[1:] or sorted(pathlib.Path(__file__).parent.glob("captures/*.pcapng")):
        print(f"== {p}")
        main(p)
