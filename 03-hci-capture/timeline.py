"""One BLE connection, start to finish, from an HCI capture.

    python3 timeline.py CAPTURE.pcapng [--aclparse PATH] [--all]

Prints every step the host and the controller took — advertising stopped,
connection made, parameters negotiated, pairing or encryption from a stored
key, discovery, reads and writes, disconnection — one line each, then a
summary per connection: how long until it was encrypted, whether pairing
ran or a stored key was used, what the client asked for, why it ended.

HCI commands and events are decoded here. ACL data goes through project
01's C library (tools/aclparse), so the L2CAP and ATT fields come from the
same parser the unit tests and the Wireshark comparison check.

What a capture holds that this never prints: device addresses (only their
type), the remote device's name, and every key. The LTK the host hands the
controller in LE Long Term Key Request Reply is in the capture in clear —
anyone who can capture HCI can decrypt the link — so the line says that a
key was given, not which. SMP packets are shown by name only.
"""
import argparse
import pathlib
import struct
import subprocess
import sys
from dataclasses import dataclass, field

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "04-adv-privacy"))
from bleprivacy import monitor, pcapng  # noqa: E402

DEFAULT_ACLPARSE = pathlib.Path(__file__).resolve().parents[1] / "01-ble-core-c/build/aclparse"

CTRL_EVENT = 17                      # HCI_MON_CTRL_EVENT: a mgmt event, bluetoothd's view

# Core Vol 1 Part F: error codes, as far as a disconnection gives them.
REASON = {0x05: "Authentication Failure", 0x08: "Connection Timeout",
          0x13: "Remote User Terminated Connection",
          0x14: "Remote Device Terminated (Low Resources)",
          0x15: "Remote Device Terminated (Power Off)",
          0x16: "Connection Terminated by Local Host", 0x22: "LL Response Timeout",
          0x3B: "Unacceptable Connection Parameters",
          0x3D: "Connection Terminated due to MIC Failure",
          0x3E: "Connection Failed to be Established"}

PEER_TYPE = {0: "public", 1: "random", 2: "public identity (resolved from an RPA)",
             3: "random static identity (resolved from an RPA)"}
PHY = {1: "1M", 2: "2M", 3: "Coded"}

COMMAND = {0x0405: "Create Connection (BR/EDR)", 0x0406: "Disconnect",
           0x0419: "Remote Name Request (BR/EDR)",
           0x041B: "Read Remote Supported Features (BR/EDR)",
           0x041C: "Read Remote Extended Features (BR/EDR)",
           0x2016: "LE Read Remote Features", 0x201A: "LE Long Term Key Request Reply",
           0x201B: "LE Long Term Key Request Negative Reply",
           0x2020: "LE Remote Connection Parameter Request Reply",
           0x2021: "LE Remote Connection Parameter Request Negative Reply",
           0x2022: "LE Set Data Length", 0x2032: "LE Set PHY",
           0x2039: "LE Set Extended Advertising Enable", 0x200A: "LE Set Advertising Enable"}

MGMT = {0x0009: "New Link Key (BR/EDR)", 0x000A: "New Long Term Key", 0x000B: "Device Connected",
        0x000C: "Device Disconnected", 0x000D: "Connect Failed",
        0x000F: "User Confirmation Request", 0x0011: "Authentication Failed",
        0x0016: "Device Unpaired", 0x0018: "New Identity Resolving Key",
        0x0019: "New Signature Resolving Key", 0x001C: "New Connection Parameter"}
MGMT_KEYS = {0x0009, 0x000A, 0x0018, 0x0019}

SMP = {0x01: "Pairing Request", 0x02: "Pairing Response", 0x03: "Pairing Confirm",
       0x04: "Pairing Random", 0x05: "Pairing Failed", 0x06: "Encryption Information",
       0x07: "Central Identification", 0x08: "Identity Information",
       0x09: "Identity Address Information", 0x0A: "Signing Information",
       0x0B: "Security Request", 0x0C: "Pairing Public Key", 0x0D: "Pairing DHKey Check",
       0x0E: "Keypress Notification"}
SMP_PAIRING = {0x01, 0x02, 0x03, 0x04, 0x0C, 0x0D}   # the exchange itself, not key distribution

LE_SIG = {0x01: "Command Reject", 0x06: "Disconnection Request",
          0x07: "Disconnection Response", 0x12: "Connection Parameter Update Request",
          0x13: "Connection Parameter Update Response",
          0x14: "LE Credit Based Connection Request",
          0x15: "LE Credit Based Connection Response"}

BREDR_SIG = {0x01: "Command Reject", 0x02: "Connection Request", 0x03: "Connection Response",
             0x04: "Configure Request", 0x05: "Configure Response",
             0x06: "Disconnection Request", 0x07: "Disconnection Response",
             0x0A: "Information Request", 0x0B: "Information Response"}
PSM = {0x0001: "SDP", 0x0003: "RFCOMM", 0x000F: "BNEP", 0x0017: "AVCTP", 0x0019: "AVDTP"}

ATT = {0x01: "ERROR_RSP", 0x02: "EXCHANGE_MTU_REQ", 0x03: "EXCHANGE_MTU_RSP",
       0x04: "FIND_INFORMATION_REQ", 0x05: "FIND_INFORMATION_RSP",
       0x06: "FIND_BY_TYPE_VALUE_REQ", 0x07: "FIND_BY_TYPE_VALUE_RSP",
       0x08: "READ_BY_TYPE_REQ", 0x09: "READ_BY_TYPE_RSP", 0x0A: "READ_REQ",
       0x0B: "READ_RSP", 0x0C: "READ_BLOB_REQ", 0x0D: "READ_BLOB_RSP",
       0x10: "READ_BY_GROUP_TYPE_REQ", 0x11: "READ_BY_GROUP_TYPE_RSP",
       0x12: "WRITE_REQ", 0x13: "WRITE_RSP", 0x1B: "HANDLE_VALUE_NTF",
       0x1D: "HANDLE_VALUE_IND", 0x1E: "HANDLE_VALUE_CFM", 0x52: "WRITE_CMD",
       0xD2: "SIGNED_WRITE_CMD"}
ATT_DISCOVERY = {0x04, 0x06, 0x08, 0x10}


@dataclass
class Step:
    """One line of the timeline."""
    t: float           # seconds since the first packet
    way: str           # ">" host to controller, "<" controller to host, "=" bluetoothd
    layer: str
    text: str
    handle: int = None
    kind: str = ""     # a tag the summary counts: "connect", "smp", "att:0x0a", ...


@dataclass
class Connection:
    """What the summary needs to know about one connection."""
    handle: int
    transport: str
    start: float
    role: str = ""
    interval_ms: float = None
    csa: str = ""
    end: float = None
    reason: int = None
    first_att: float = None
    encrypted_at: float = None
    smp_pairing: int = 0
    smp_keys: int = 0
    ltk_requests: int = 0
    paired_before_ltk: bool = False
    att: dict = field(default_factory=dict)   # (way, opcode) -> count


def le16(b, pos):
    """Little-endian uint16 at @pos."""
    return struct.unpack_from("<H", b, pos)[0]


def decode_command(pl):
    """(text, handle, kind) for an HCI command packet, or None to leave it out."""
    if len(pl) < 3:
        return "malformed command", None, ""
    op, p = le16(pl, 0), pl[3:]
    name = COMMAND.get(op)
    if name is None:
        return None
    handle = le16(p, 0) & 0x0FFF if len(p) >= 2 and op not in (0x0405, 0x0419, 0x2039, 0x200A) else None
    if op == 0x201A:
        # Handle (2) then the 16-octet LTK. Never print the key.
        return f"{name}: handle 0x{handle:03x}, LTK given (16 octets, withheld)", handle, "ltk_reply"
    if op == 0x201B:
        return f"{name}: handle 0x{handle:03x} — no key for this device", handle, "ltk_negative"
    if op == 0x2020 and len(p) >= 10:
        lo, hi, lat, to = struct.unpack_from("<HHHH", p, 2)
        return (f"{name}: accept interval {lo * 1.25:g}–{hi * 1.25:g} ms, latency {lat}, "
                f"timeout {to * 10} ms"), handle, ""
    if op == 0x0406 and len(p) >= 3:
        return f"{name}: handle 0x{handle:03x}, reason 0x{p[2]:02x} {REASON.get(p[2], '')}".rstrip(), \
            handle, ""
    if op in (0x2039, 0x200A) and p:
        return f"{name}: {'on' if p[0] else 'off'}", None, "adv"
    if op in (0x0405, 0x0419):
        return f"{name} (address withheld)", None, ""
    if handle is not None:
        return f"{name}: handle 0x{handle:03x}", handle, ""
    return name, None, ""


def decode_le_meta(pl):
    """(text, handle, kind) for an LE Meta event, or None to leave it out."""
    sub, p = pl[2], pl[3:]
    if sub in (0x01, 0x0A, 0x29) and len(p) >= 9:
        status, handle, role, ptype = p[0], le16(p, 1) & 0x0FFF, p[3], p[4]
        if status:
            return f"LE Connection Complete: failed, status 0x{status:02x}", None, ""
        base = 11 if sub == 0x01 else 23        # skip peer address (and two RPAs)
        if len(p) < base + 6:
            return "LE Connection Complete: short event", handle, ""
        ivl, lat, to = struct.unpack_from("<HHH", p, base)
        name = "LE Connection Complete" if sub == 0x01 else "LE Enhanced Connection Complete"
        return (f"{name}: handle 0x{handle:03x}, we are {'central' if role == 0 else 'peripheral'}, "
                f"peer address {PEER_TYPE.get(ptype, ptype)}, interval {ivl * 1.25:g} ms, "
                f"latency {lat}, supervision timeout {to * 10} ms"), handle, \
            f"connect:{role}:{ivl * 1.25:g}"
    if sub == 0x03 and len(p) >= 9:
        status, handle = p[0], le16(p, 1) & 0x0FFF
        ivl, lat, to = struct.unpack_from("<HHH", p, 3)
        if status:
            return f"LE Connection Update Complete: failed, status 0x{status:02x}", handle, ""
        return (f"LE Connection Update Complete: interval {ivl * 1.25:g} ms, latency {lat}, "
                f"timeout {to * 10} ms"), handle, f"interval:{ivl * 1.25:g}"
    if sub == 0x04 and len(p) >= 3:
        return f"LE Read Remote Features Complete: status 0x{p[0]:02x}", le16(p, 1) & 0x0FFF, ""
    if sub == 0x05 and len(p) >= 12:
        handle = le16(p, 0) & 0x0FFF
        rand, ediv = p[2:10], le16(p, 10)
        how = ("Rand and EDIV 0: an LE Secure Connections key" if not any(rand) and ediv == 0
               else "Rand/EDIV set: a legacy-pairing key")
        return f"LE Long Term Key Request: the central starts encryption ({how})", handle, "ltk_request"
    if sub == 0x06 and len(p) >= 10:
        lo, hi, lat, to = struct.unpack_from("<HHHH", p, 2)
        return (f"LE Remote Connection Parameter Request: interval {lo * 1.25:g}–{hi * 1.25:g} ms, "
                f"latency {lat}, timeout {to * 10} ms"), le16(p, 0) & 0x0FFF, ""
    if sub == 0x07 and len(p) >= 10:
        tx, txt, rx, rxt = struct.unpack_from("<HHHH", p, 2)
        return (f"LE Data Length Change: up to {tx} octets out, {rx} in per packet"), \
            le16(p, 0) & 0x0FFF, ""
    if sub == 0x0C and len(p) >= 5:
        return (f"LE PHY Update Complete: TX {PHY.get(p[3], p[3])}, RX {PHY.get(p[4], p[4])}"
                + (f", status 0x{p[0]:02x}" if p[0] else "")), le16(p, 1) & 0x0FFF, ""
    if sub == 0x12 and len(p) >= 5:
        return "LE Advertising Set Terminated: advertising stopped, a central connected", \
            le16(p, 2) & 0x0FFF, "adv"
    if sub == 0x14 and len(p) >= 3:
        algo = "#2" if p[2] == 1 else "#1" if p[2] == 0 else f"0x{p[2]:02x}"
        return f"LE Channel Selection Algorithm: CSA {algo}", le16(p, 0) & 0x0FFF, f"csa:{algo}"
    return None


def decode_event(pl):
    """(text, handle, kind) for an HCI event packet, or None to leave it out."""
    if len(pl) < 2:
        return "malformed event", None, ""
    code = pl[0]
    if code == 0x3E and len(pl) >= 3:
        return decode_le_meta(pl)
    if code == 0x05 and len(pl) >= 6:
        handle, reason = le16(pl, 3) & 0x0FFF, pl[5]
        return (f"Disconnection Complete: reason 0x{reason:02x} {REASON.get(reason, '')}".rstrip()
                + (f", status 0x{pl[2]:02x}" if pl[2] else "")), handle, f"disconnect:{reason}"
    if code in (0x08, 0x59) and len(pl) >= 6:
        status, handle, on = pl[2], le16(pl, 3) & 0x0FFF, pl[5]
        if status:
            return f"Encryption Change: failed, status 0x{status:02x}", handle, ""
        size = f", key size {pl[6]}" if code == 0x59 and len(pl) >= 7 else ""
        return f"Encryption Change: {'on (AES-CCM)' if on else 'off'}{size}", handle, \
            "encrypted" if on else ""
    if code == 0x30 and len(pl) >= 5:
        return "Encryption Key Refresh Complete", le16(pl, 3) & 0x0FFF, "encrypted"
    if code == 0x03 and len(pl) >= 13:
        status, handle = pl[2], le16(pl, 3) & 0x0FFF
        if status:
            return f"Connection Complete (BR/EDR): failed, status 0x{status:02x}", None, ""
        return f"Connection Complete (BR/EDR): handle 0x{handle:03x}", handle, "connect_bredr"
    if code == 0x07:
        return "Remote Name Request Complete (BR/EDR) (name withheld)", None, ""
    if code == 0x0F and len(pl) >= 6 and pl[2]:
        op = le16(pl, 4)
        return f"Command Status: 0x{op:04X} {COMMAND.get(op, '')} failed, status 0x{pl[2]:02x}", None, ""
    if code == 0x0E and len(pl) >= 6 and pl[5]:
        op = le16(pl, 3)
        return f"Command Complete: 0x{op:04X} {COMMAND.get(op, '')} failed, status 0x{pl[5]:02x}", None, ""
    return None


def decode_mgmt(pl):
    """(text, kind) for a mgmt event bluetoothd received, or None to leave it out."""
    if len(pl) < 6:
        return None
    code = le16(pl, 4)
    name = MGMT.get(code)
    if name is None:
        return None
    if code in MGMT_KEYS:
        return f"mgmt {name}: bluetoothd stores it (key withheld)", "stored_key"
    if code == 0x000F:
        return f"mgmt {name}: the six digits go to the user", "confirm"
    return f"mgmt {name}", ""


def decode_acl(raw, row):
    """(layer, text, kind) for one ACL packet, from its bytes and its aclparse row."""
    f = row.split("\t")
    if len(f) < 4 or f[1] == "ACL_MALFORMED":
        return "ACL", "malformed", ""
    if f[3].startswith("L2CAP_"):
        return "L2CAP", {"L2CAP_-1": "first fragment", "L2CAP_-2": "continuation",
                         "L2CAP_-3": "malformed"}.get(f[3], f[3]), ""
    cid = int(f[4], 16)
    first = raw[8] if len(raw) > 8 else None
    if cid == 0x0006:
        return "SMP", SMP.get(first, f"code 0x{first:02x}" if first is not None else "empty"), \
            f"smp:{first}"
    if cid == 0x0005:
        return "L2CAP", "LE signalling: " + LE_SIG.get(first, f"code 0x{first:02x}"), ""
    if cid == 0x0001:
        text = "BR/EDR signalling: " + BREDR_SIG.get(first, f"code 0x{first:02x}")
        if first == 0x02 and len(raw) >= 14:
            psm = le16(raw, 12)
            text += f", PSM 0x{psm:04x} {PSM.get(psm, '')}".rstrip()
        return "L2CAP", text, ""
    if cid != 0x0004:
        return "L2CAP", f"channel 0x{cid:04x}, {f[5]} octets", ""
    if len(f) < 8 or f[6] != "OK":
        return "ATT", "malformed PDU", ""
    op = int(f[7], 16)
    text = ATT.get(op, f"opcode 0x{op:02x}")
    if f[8] != "-":
        text += f" handle {f[8]}"
    if f[9] != "-":
        text += f" error 0x{int(f[9], 16):02x}"
    if f[10] != "-":
        text += f" MTU {f[10]}"
    if f[11] != "-":
        text += f" range {f[11]}–{f[12]}"
    return "ATT", text, f"att:{op}"


def run_aclparse(packets, aclparse):
    """aclparse rows for the given ACL packets, in order."""
    if not packets:
        return []
    if not pathlib.Path(aclparse).exists():
        sys.exit(f"{aclparse} not found: build project 01 first "
                 "(cmake -S ../01-ble-core-c -B ../01-ble-core-c/build && cmake --build ...)")
    out = subprocess.run([str(aclparse)], input="\n".join(p.hex() for p in packets) + "\n",
                         capture_output=True, text=True, check=True).stdout
    rows = out.splitlines()
    if len(rows) != len(packets):
        sys.exit(f"aclparse returned {len(rows)} rows for {len(packets)} packets")
    return rows


def steps_from(path, aclparse=DEFAULT_ACLPARSE, include_mgmt=True):
    """Every step in the capture, in order."""
    raw, t0 = [], None
    for pk in pcapng.read_packets(path):
        _, op, pl = monitor.split(pk.data)
        if t0 is None:
            t0 = pk.ts
        raw.append((pk.ts - t0, op, pl))
    acl_rows = iter(run_aclparse([pl for _, op, pl in raw if op in (monitor.ACL_TX, monitor.ACL_RX)],
                                 aclparse))
    steps = []
    for t, op, pl in raw:
        if op == monitor.COMMAND_PKT:
            d = decode_command(pl)
            if d:
                steps.append(Step(t, ">", "HCI", d[0], d[1], d[2]))
        elif op == monitor.EVENT_PKT:
            d = decode_event(pl)
            if d:
                steps.append(Step(t, "<", "HCI", d[0], d[1], d[2]))
        elif op in (monitor.ACL_TX, monitor.ACL_RX):
            layer, text, kind = decode_acl(pl, next(acl_rows))
            handle = le16(pl, 0) & 0x0FFF if len(pl) >= 2 else None
            way = ">" if op == monitor.ACL_TX else "<"
            steps.append(Step(t, way, layer, text, handle, kind))
        elif op == CTRL_EVENT and include_mgmt:
            d = decode_mgmt(pl)
            if d:
                steps.append(Step(t, "=", "mgmt", d[0], None, d[1]))
    return steps


def connections(steps):
    """One Connection per connection made in the capture, from its steps."""
    conns, live = [], {}
    for s in steps:
        k = s.kind
        if k.startswith("connect:") or k == "connect_bredr":
            c = Connection(s.handle, "LE" if k != "connect_bredr" else "BR/EDR", s.t)
            if k != "connect_bredr":
                _, role, ivl = k.split(":")
                c.role, c.interval_ms = ("central" if role == "0" else "peripheral"), float(ivl)
            conns.append(c)
            live[s.handle] = c
            continue
        c = live.get(s.handle)
        if c is None:
            continue
        if k.startswith("csa:"):
            c.csa = k[4:]
        elif k.startswith("interval:"):
            c.interval_ms = float(k[9:])
        elif k.startswith("smp:"):
            code = int(k[4:]) if k[4:] != "None" else None
            if code in SMP_PAIRING:
                c.smp_pairing += 1
            elif code is not None:
                c.smp_keys += 1
        elif k == "ltk_request":
            c.ltk_requests += 1
            if c.ltk_requests == 1:
                c.paired_before_ltk = c.smp_pairing > 0
        elif k == "encrypted" and c.encrypted_at is None:
            c.encrypted_at = s.t
        elif k.startswith("att:"):
            key = (s.way, int(k[4:]))
            c.att[key] = c.att.get(key, 0) + 1
            if c.first_att is None:
                c.first_att = s.t
        elif k.startswith("disconnect:"):
            c.end, c.reason = s.t, int(k[11:])
            del live[s.handle]
    return conns


def collapse(steps):
    """Merge runs of identical lines (a burst of notifications) into one: (step, count, last_t)."""
    out = []
    for s in steps:
        if out and (out[-1][0].way, out[-1][0].layer, out[-1][0].text) == (s.way, s.layer, s.text):
            first, n, _ = out[-1]
            out[-1] = (first, n + 1, s.t)
        else:
            out.append((s, 1, s.t))
    return out


def summary(c):
    """Lines describing one connection."""
    ms = lambda t: f"{(t - c.start) * 1000:.0f} ms"      # noqa: E731
    lines = [f"{c.transport} connection, handle 0x{c.handle:03x}"
             + (f", we are {c.role}" if c.role else "")
             + (f", interval {c.interval_ms:g} ms" if c.interval_ms else "")
             + (f", CSA {c.csa}" if c.csa else "")]
    if c.smp_pairing:
        lines.append(f"  pairing ran: {c.smp_pairing} SMP pairing PDUs, {c.smp_keys} key-distribution PDUs")
    if c.encrypted_at is not None:
        how = ("after pairing on this connection" if c.paired_before_ltk or c.smp_pairing
               else "from a key stored at an earlier pairing — no SMP at all")
        lines.append(f"  encrypted {ms(c.encrypted_at)} after connecting, {how}")
    elif c.transport == "LE":
        lines.append("  never encrypted")
    if c.att:
        lines.append(f"  ATT: first PDU {ms(c.first_att)} after connecting")
        for way, who in (("<", "peer as client "), (">", "us as client   ")):
            n = lambda *ops: sum(c.att.get((way, op), 0) for op in ops)      # noqa: E731
            other = ">" if way == "<" else "<"
            errs = sum(v for (w, op), v in c.att.items() if w == other and op == 0x01)
            lines.append(f"    {who}: {n(*ATT_DISCOVERY)} discovery requests, {n(0x0A, 0x0C)} reads, "
                         f"{n(0x12, 0x52)} writes; {errs} error responses to it")
        ntf = sum(v for (w, op), v in c.att.items() if op in (0x1B, 0x1D) and w == ">")
        if ntf:
            lines.append(f"    notifications/indications we sent: {ntf}")
    if c.end is not None:
        lines.append(f"  ended after {c.end - c.start:.1f} s: 0x{c.reason:02x} {REASON.get(c.reason, '')}".rstrip())
    else:
        lines.append("  still up when the capture ended")
    return lines


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("capture")
    ap.add_argument("--aclparse", default=DEFAULT_ACLPARSE, help="path to project 01's aclparse")
    ap.add_argument("--all", action="store_true", help="do not merge runs of identical lines")
    a = ap.parse_args(argv)
    steps = steps_from(a.capture, a.aclparse)
    rows = [(s, 1, s.t) for s in steps] if a.all else collapse(steps)
    print("   t (s)    layer  event        > host to controller   < controller to host   = bluetoothd")
    for s, n, last in rows:
        more = f"   ×{n}, until {last:.3f} s" if n > 1 else ""
        print(f"{s.t:9.3f}  {s.way} {s.layer:<5}  {s.text}{more}")
    print()
    for c in connections(steps):
        print("\n".join(summary(c)))
        print()


if __name__ == "__main__":
    main()
