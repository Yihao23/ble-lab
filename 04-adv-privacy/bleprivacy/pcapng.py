"""A pcapng reader in the standard library.

Only what a Bluetooth capture from dumpcap needs: Section Header, Interface
Description and Enhanced Packet blocks, both byte orders, and the if_tsresol
option. A block cut short at the end of the file — a capture that is still
being written, or was killed — ends the read cleanly instead of raising: the
packets before it are still good.
"""
import struct
from dataclasses import dataclass

SHB = 0x0A0D0D0A
IDB = 0x00000001
SPB = 0x00000003
EPB = 0x00000006
BYTE_ORDER_MAGIC = 0x1A2B3C4D

LINKTYPE_BLUETOOTH_LINUX_MONITOR = 254


@dataclass
class Packet:
    frame: int          # 1-based, counts every packet block, same as Wireshark
    ts: float           # seconds since the epoch, or None for a Simple Packet Block
    linktype: int
    data: bytes


class PcapngError(ValueError):
    pass


def _tsresol(options, endian):
    """Seconds per timestamp tick from the IDB options. Default 10^-6."""
    pos = 0
    while pos + 4 <= len(options):
        code, length = struct.unpack_from(endian + "HH", options, pos)
        if code == 0:                       # opt_endofopt
            break
        value = options[pos + 4:pos + 4 + length]
        if code == 9 and length == 1:       # if_tsresol
            v = value[0]
            return 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        pos += 4 + ((length + 3) & ~3)
    return 1e-6


class Reader:
    """Iterate a pcapng file. After iteration, .truncated says whether it was cut short."""

    def __init__(self, path):
        self.path = path
        self.truncated = False

    def __iter__(self):
        with open(self.path, "rb") as f:
            buf = f.read()

        endian = None
        interfaces = []                     # (linktype, seconds per tick)
        frame = 0
        pos = 0
        while pos + 12 <= len(buf):
            if buf[pos:pos + 4] == b"\x0a\x0d\x0d\x0a":
                magic = buf[pos + 8:pos + 12]
                if magic == struct.pack("<I", BYTE_ORDER_MAGIC):
                    endian = "<"
                elif magic == struct.pack(">I", BYTE_ORDER_MAGIC):
                    endian = ">"
                else:
                    raise PcapngError(f"bad byte-order magic at offset {pos}")
                interfaces = []
            if endian is None:
                raise PcapngError("file does not start with a pcapng Section Header Block")

            btype, blen = struct.unpack_from(endian + "II", buf, pos)
            if blen < 12 or blen % 4 or pos + blen > len(buf):
                self.truncated = True       # last block still being written: stop here
                return
            body = buf[pos + 8:pos + blen - 4]

            if btype == IDB:
                linktype, _reserved, _snaplen = struct.unpack_from(endian + "HHI", body, 0)
                interfaces.append((linktype, _tsresol(body[8:], endian)))
            elif btype == EPB:
                if_id, ts_hi, ts_lo, caplen, _orig = struct.unpack_from(endian + "IIIII", body, 0)
                frame += 1
                linktype, tick = interfaces[if_id]
                yield Packet(frame, ((ts_hi << 32) | ts_lo) * tick, linktype,
                             body[20:20 + caplen])
            elif btype == SPB:
                frame += 1
                (orig,) = struct.unpack_from(endian + "I", body, 0)
                linktype, _ = interfaces[0]
                yield Packet(frame, None, linktype, body[4:4 + orig])
            pos += blen
        if pos != len(buf):
            self.truncated = True           # fewer than 12 bytes left over


def read_packets(path):
    """Yield every Packet in the file. Use Reader directly to learn about truncation."""
    return iter(Reader(path))
