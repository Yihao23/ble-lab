"""Follow a device you paired with, through every address it used.

    python3 -m bleprivacy.irk --pairing PAIRING.pcapng CAPTURE [CAPTURE ...]
    python3 -m bleprivacy.irk --irk-file KEY.hex CAPTURE [CAPTURE ...]

Pairing hands each side the other's Identity Resolving Key in SMP Identity
Information. An HCI capture of the pairing therefore holds the IRK in clear
-- the link is encrypted on air, not on HCI. With it, every Resolvable
Private Address of that device can be recognised: the ones it connected
from, and the ones it advertised from, in captures before the pairing as
well as after.

For each capture this lists the connections (LE Connection Complete, peer
address) and the advertisers (address of each advertising report) whose
address is an RPA, and says which resolve. Every answer from this package's
Python ah() is checked against project 01's C library through
tools/blerpa, when that is built.

Prints neither the key nor any address. A file given with --irk-file holds
32 hex digits MSB first, as --irk of the main tool takes them; reading it
from a file keeps it out of shell history.
"""
import argparse
import datetime
import pathlib
import statistics
import struct
import subprocess
import sys
from dataclasses import dataclass

from . import addr as addrmod
from . import analyze, monitor, pcapng, rpa

DEFAULT_BLERPA = pathlib.Path(__file__).resolve().parents[2] / "01-ble-core-c/build/blerpa"

SMP_CID = 0x0006
SMP_IDENTITY_INFO = 0x08
SMP_IDENTITY_ADDR = 0x09
ID_TYPE = {0: "public", 1: "random static"}


@dataclass
class IdentityKey:
    """An IRK seen in SMP, with the identity address type that followed it."""
    t: float
    direction: str           # "received" (from the peer) or "sent" (ours)
    irk: bytes               # MSB first, as rpa.resolves() and the spec vectors take it
    id_type: str = ""


@dataclass
class Peer:
    """The other side of one LE connection, as the controller reported it."""
    t: float
    addr: bytes              # 6 octets LSB first, as HCI carries it
    addr_type: int           # 0 public, 1 random, 2/3 resolved by the controller


def packets(path):
    """(timestamp, monitor opcode, payload) for every packet of a capture."""
    for pk in pcapng.read_packets(path):
        if pk.linktype == pcapng.LINKTYPE_BLUETOOTH_LINUX_MONITOR:
            _, op, pl = monitor.split(pk.data)
            yield pk.ts, op, pl


def smp_identity_keys(pkts):
    """Every IRK carried by SMP Identity Information, in either direction.

    The key travels least significant octet first; it is returned MSB first.
    Only an unfragmented SMP PDU is read: Identity Information is 17 octets.
    """
    keys = []
    for t, op, pl in pkts:
        if op not in (monitor.ACL_TX, monitor.ACL_RX) or len(pl) < 9:
            continue
        if struct.unpack_from("<H", pl, 6)[0] != SMP_CID or ((pl[1] >> 4) & 0x3) == 0x1:
            continue
        code = pl[8]
        if code == SMP_IDENTITY_INFO and len(pl) >= 9 + 16:
            keys.append(IdentityKey(t, "received" if op == monitor.ACL_RX else "sent",
                                    bytes(pl[9:25][::-1])))
        elif code == SMP_IDENTITY_ADDR and len(pl) >= 10 and keys:
            keys[-1].id_type = ID_TYPE.get(pl[9], f"0x{pl[9]:02x}")
    return keys


def connection_peers(pkts):
    """The peer of every LE connection made: LE Connection Complete and Enhanced.

    When the controller resolved the peer itself (address type 2 or 3), the
    Enhanced event carries the identity in Peer_Address and the RPA the peer
    used in Peer_Resolvable_Private_Address; the RPA is what is returned.
    """
    peers = []
    for t, op, pl in pkts:
        if op != monitor.EVENT_PKT or len(pl) < 3 or pl[0] != 0x3E:
            continue
        sub, p = pl[2], pl[3:]
        if sub not in (0x01, 0x0A, 0x29) or len(p) < 11 or p[0] != 0:
            continue
        ptype, addr = p[4], bytes(p[5:11])
        if sub != 0x01 and ptype in (2, 3) and len(p) >= 23 and any(p[17:23]):
            addr = bytes(p[17:23])
        peers.append(Peer(t, addr, ptype))
    return peers


def blerpa_check(irk, addrs, blerpa=DEFAULT_BLERPA):
    """Answers of project 01's ble_rpa_resolve() for each address, or None if not built."""
    if not addrs or not pathlib.Path(blerpa).exists():
        return None
    irk_air = irk[::-1].hex()                      # blerpa takes the key as SMP sends it
    out = subprocess.run([str(blerpa)], input="".join(f"{irk_air} {a.hex()}\n" for a in addrs),
                         capture_output=True, text=True, check=True).stdout.split("\n")
    return [line.split("\t")[1] == "1" for line in out[:len(addrs)]]


def when(t):
    return datetime.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")


def describe(irk, path, blerpa=DEFAULT_BLERPA):
    """Lines describing which RPAs in one capture resolve with irk; and the
    (python answers, C answers) pair for the cross-check."""
    peers = connection_peers(packets(path))
    cap = analyze.load(path)
    tracks = sorted((t for t in analyze.build_tracks(cap).values() if t.kind == "rpa"),
                    key=lambda t: t.first)
    lines = [f"{pathlib.Path(path).name}"]
    conn_rpas = [p for p in peers if p.addr_type != 0 and addrmod.kind(1, p.addr) == "rpa"]
    hits = [rpa.resolves(irk, p.addr) for p in conn_rpas]
    lines.append(f"  connections: {len(peers)}, peer address an RPA in {len(conn_rpas)}, "
                 f"{len({p.addr for p in conn_rpas})} distinct; {sum(hits)} resolve")
    for p, h in zip(conn_rpas, hits):
        lines.append(f"    {when(p.t)}  {'resolves' if h else 'does not resolve'}")
    adv_hits = [rpa.resolves(irk, t.addr) for t in tracks]
    lines.append(f"  advertisers: {len(tracks)} RPAs; {sum(adv_hits)} resolve")
    for t, h in zip(tracks, adv_hits):
        if h:
            sd = sorted({f"0x{k[0]:04x}" for k in t.service_data})
            lines.append(f"    {(t.first - cap.t0) / 60:5.1f}-{(t.last - cap.t0) / 60:5.1f} min  "
                         f"{t.n} reports, RSSI median {statistics.median(t.rssi):g} dBm"
                         + (f", service data {', '.join(sd)}" if sd else ""))
    addrs = [p.addr for p in conn_rpas] + [t.addr for t in tracks]
    return lines, hits + adv_hits, blerpa_check(irk, addrs, blerpa)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="bleprivacy.irk", description=__doc__.split("\n\n")[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pairing", help="HCI capture of the pairing: take the IRK the peer sent")
    src.add_argument("--irk-file", help="file holding the IRK, 32 hex digits, MSB first")
    ap.add_argument("captures", nargs="+")
    ap.add_argument("--blerpa", default=DEFAULT_BLERPA, help="path to project 01's blerpa")
    a = ap.parse_args(argv)

    if a.pairing:
        keys = [k for k in smp_identity_keys(packets(a.pairing)) if k.direction == "received"]
        if not keys:
            ap.error(f"no Identity Information received in {a.pairing}")
        key = keys[-1]
        irk = key.irk
        print(f"IRK: received in SMP Identity Information at {when(key.t)} "
              f"(16 octets, withheld); identity address {key.id_type or 'not seen'}")
    else:
        irk = bytes.fromhex(pathlib.Path(a.irk_file).read_text().strip())
        if len(irk) != 16:
            ap.error("--irk-file must hold 16 octets")
        print("IRK: from file (16 octets, withheld)")
    print()

    py_all, c_all = [], []
    for path in a.captures:
        lines, py, c = describe(irk, path, a.blerpa)
        print("\n".join(lines))
        py_all += py
        if c is not None:
            c_all += c
    print()
    if not pathlib.Path(a.blerpa).exists():
        print("cross-check skipped: build project 01 for tools/blerpa")
    elif c_all == py_all:
        print(f"cross-check: project 01's ble_rpa_resolve agrees on all {len(py_all)} addresses")
    else:
        print(f"cross-check FAILED: {sum(x != y for x, y in zip(py_all, c_all))} disagreements")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
