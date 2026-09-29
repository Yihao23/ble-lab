"""HCI LE advertising reports — a Python mirror of 01-ble-core-c/src/ble_hci.c.

Same layouts, same bounds checks. The C library is what would ship on a
device; this is what a laptop runs over a capture. The test suite checks the
two agree, and both agree with Wireshark.
"""
import struct
from dataclasses import dataclass

LE_META = 0x3E
ADV_REPORT = 0x02
EXT_ADV_REPORT = 0x0D

EXT_CONNECTABLE = 0x0001
EXT_SCANNABLE = 0x0002
EXT_DIRECTED = 0x0004
EXT_SCAN_RSP = 0x0008
EXT_LEGACY = 0x0010

# Legacy (0x02) event types, mapped onto the extended bit layout so the rest
# of the code only ever sees one format.
_LEGACY_TO_EXT = {
    0x00: EXT_LEGACY | EXT_CONNECTABLE | EXT_SCANNABLE,     # ADV_IND
    0x01: EXT_LEGACY | EXT_CONNECTABLE | EXT_DIRECTED,      # ADV_DIRECT_IND
    0x02: EXT_LEGACY | EXT_SCANNABLE,                       # ADV_SCAN_IND
    0x03: EXT_LEGACY,                                       # ADV_NONCONN_IND
    0x04: EXT_LEGACY | EXT_SCAN_RSP | EXT_SCANNABLE,        # SCAN_RSP
}


@dataclass
class AdvReport:
    evt_type: int           # extended-format bits
    addr_type: int          # HCI address type: 0 public, 1 random, 2/3 identity
    addr: bytes             # 6 bytes, LSB-first as on air
    rssi: int
    tx_power: int           # 127 = not available
    data: bytes
    from_legacy_event: bool

    @property
    def addr_str(self):
        """Human order: most significant octet first."""
        return ":".join(f"{b:02X}" for b in reversed(self.addr))

    @property
    def is_scan_response(self):
        return bool(self.evt_type & EXT_SCAN_RSP)


class MalformedEvent(ValueError):
    pass


def parse_adv_reports(evt):
    """Reports in one HCI event (starting at the event code). [] if not an adv report."""
    if len(evt) < 4:
        raise MalformedEvent("shorter than an LE Meta header")
    if evt[0] != LE_META or evt[2] not in (ADV_REPORT, EXT_ADV_REPORT):
        return []
    param_len = evt[1]
    if param_len + 2 > len(evt) or param_len < 2:
        raise MalformedEvent("parameter length does not match the packet")
    sub, count = evt[2], evt[3]
    p, end = 4, 2 + param_len
    out = []
    for _ in range(count):
        if sub == ADV_REPORT:
            if end - p < 9:
                raise MalformedEvent("legacy report header truncated")
            etype, atype = evt[p], evt[p + 1]
            addr = bytes(evt[p + 2:p + 8])
            dlen = evt[p + 8]
            if end - p < 9 + dlen + 1:
                raise MalformedEvent("legacy report data overruns the event")
            data = bytes(evt[p + 9:p + 9 + dlen])
            rssi = struct.unpack_from("b", evt, p + 9 + dlen)[0]
            out.append(AdvReport(_LEGACY_TO_EXT.get(etype, EXT_LEGACY), atype, addr,
                                 rssi, 127, data, True))
            p += 9 + dlen + 1
        else:
            if end - p < 24:
                raise MalformedEvent("extended report header truncated")
            (etype,) = struct.unpack_from("<H", evt, p)
            atype = evt[p + 2]
            addr = bytes(evt[p + 3:p + 9])
            tx, rssi = struct.unpack_from("bb", evt, p + 12)
            dlen = evt[p + 23]
            if end - p < 24 + dlen:
                raise MalformedEvent("extended report data overruns the event")
            data = bytes(evt[p + 24:p + 24 + dlen])
            out.append(AdvReport(etype, atype, addr, rssi, tx, data, False))
            p += 24 + dlen
    return out
