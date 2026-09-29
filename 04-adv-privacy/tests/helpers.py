"""Synthetic advertising traffic for the analysis tests."""
import struct

from bleprivacy import ad as admod
from bleprivacy import addr as addrmod
from bleprivacy import analyze, hci

LEGACY_ADV_IND = hci.EXT_LEGACY | hci.EXT_CONNECTABLE | hci.EXT_SCANNABLE
LEGACY_NONCONN = hci.EXT_LEGACY


def address(top_bits, n):
    """6 bytes LSB-first; top two bits of the MSB set to top_bits."""
    b = bytearray(struct.pack("<Q", 0x0A0B0C0D0E00 + n)[:6])
    b[5] = (b[5] & 0x3F) | (top_bits << 6)
    return bytes(b)


def ad_bytes(*structures):
    """ad_bytes((type, payload), ...) -> AD-encoded bytes."""
    return b"".join(bytes([len(v) + 1, t]) + v for t, v in structures)


def service_data(uuid, payload):
    return (admod.SERVICE_DATA16, struct.pack("<H", uuid) + payload)


def manufacturer(cid, payload):
    return (admod.MANUFACTURER, struct.pack("<H", cid) + payload)


class Air:
    """Build a Capture by describing what each device advertised and when."""

    def __init__(self):
        self.sightings = []

    def device(self, addr, start, stop, *structures, rssi=-60, every=1.0,
               addr_type=0x01, evt_type=LEGACY_NONCONN):
        data = admod.parse(ad_bytes(*structures))
        k = addrmod.kind(addr_type, addr)
        s = hci.AdvReport(evt_type, addr_type, addr, rssi, 127, b"", False).addr_str
        t = start
        while t <= stop + 1e-9:
            self.sightings.append(analyze.Sighting(t, 0, addr, s, addr_type, k, rssi,
                                                   evt_type, data))
            t += every
        return s

    def capture(self, t0=0.0, t1=None):
        self.sightings.sort(key=lambda s: s.t)
        t1 = self.sightings[-1].t if t1 is None else t1
        return analyze.Capture(self.sightings, t0, t1, packets=len(self.sightings))
