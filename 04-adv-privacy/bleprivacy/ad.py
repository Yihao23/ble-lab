"""Advertising Data structures, and the parts of them that identify a device."""
import struct
from dataclasses import dataclass, field

FLAGS = 0x01
UUID16_INCOMPLETE = 0x02
UUID16_COMPLETE = 0x03
NAME_SHORT = 0x08
NAME_COMPLETE = 0x09
TX_POWER = 0x0A
SERVICE_DATA16 = 0x16
APPEARANCE = 0x19
MANUFACTURER = 0xFF

FLAG_LE_LIMITED = 0x01
FLAG_LE_GENERAL = 0x02


class MalformedAD(ValueError):
    pass


def iter_ad(data):
    """Yield (type, bytes). Raises MalformedAD on a length that overruns the buffer."""
    pos = 0
    while pos < len(data):
        flen = data[pos]
        if flen == 0:
            return                              # padding
        if flen > len(data) - pos - 1:
            raise MalformedAD(f"AD length {flen} at offset {pos} overruns {len(data)} bytes")
        yield data[pos + 1], bytes(data[pos + 2:pos + 1 + flen])
        pos += 1 + flen


@dataclass
class ParsedAD:
    types: tuple = ()
    flags: int = None
    name: str = None
    tx_power: int = None
    appearance: int = None
    uuid16: frozenset = frozenset()
    manufacturer: dict = field(default_factory=dict)     # company id -> payload
    service_data: dict = field(default_factory=dict)     # uuid16 -> payload
    malformed: bool = False


def parse(data):
    ad = ParsedAD()
    types, uuids = [], set()
    try:
        for t, v in iter_ad(data):
            types.append(t)
            if t == FLAGS and v:
                ad.flags = v[0]
            elif t in (NAME_COMPLETE, NAME_SHORT):
                ad.name = v.decode("utf-8", "replace")
            elif t == TX_POWER and v:
                ad.tx_power = struct.unpack("b", v[:1])[0]
            elif t == APPEARANCE and len(v) == 2:
                ad.appearance = struct.unpack("<H", v)[0]
            elif t in (UUID16_COMPLETE, UUID16_INCOMPLETE):
                uuids.update(struct.unpack_from("<H", v, i)[0] for i in range(0, len(v) - 1, 2))
            elif t == MANUFACTURER and len(v) >= 2:
                ad.manufacturer[struct.unpack("<H", v[:2])[0]] = v[2:]
            elif t == SERVICE_DATA16 and len(v) >= 2:
                ad.service_data[struct.unpack("<H", v[:2])[0]] = v[2:]
    except MalformedAD:
        ad.malformed = True
    ad.types = tuple(types)
    ad.uuid16 = frozenset(uuids)
    return ad
