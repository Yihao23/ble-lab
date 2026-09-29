import os
import pathlib
import shutil
import struct
import subprocess
import tempfile
import unittest

from bleprivacy import analyze, pcapng

CAPTURES = pathlib.Path(__file__).resolve().parents[2] / "03-hci-capture/captures"


def block(btype, body, e="<"):
    body += b"\x00" * (-len(body) % 4)
    n = len(body) + 12
    return struct.pack(e + "II", btype, n) + body + struct.pack(e + "I", n)


def shb(e="<"):
    return block(pcapng.SHB, struct.pack(e + "IHHq", pcapng.BYTE_ORDER_MAGIC, 1, 0, -1), e)


def idb(linktype=254, tsresol=None, e="<"):
    opts = b""
    if tsresol is not None:
        opts = struct.pack(e + "HH", 9, 1) + bytes([tsresol, 0, 0, 0]) + struct.pack(e + "HH", 0, 0)
    return block(pcapng.IDB, struct.pack(e + "HHI", linktype, 0, 0) + opts, e)


def epb(ticks, data, e="<"):
    return block(pcapng.EPB, struct.pack(e + "IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF,
                                         len(data), len(data)) + data, e)


class Reader(unittest.TestCase):
    def read(self, raw):
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
            f.write(raw)
        self.addCleanup(os.unlink, f.name)
        r = pcapng.Reader(f.name)
        return list(r), r

    def test_both_byte_orders(self):
        for e in "<>":
            with self.subTest(endian=e):
                pk, r = self.read(shb(e) + idb(e=e) + epb(1_500_000, b"\x00\x00\x00\x03\x3e", e))
                self.assertEqual(len(pk), 1)
                self.assertEqual(pk[0].linktype, 254)
                self.assertAlmostEqual(pk[0].ts, 1.5)
                self.assertEqual(pk[0].data, b"\x00\x00\x00\x03\x3e")
                self.assertFalse(r.truncated)

    def test_nanosecond_resolution(self):
        pk, _ = self.read(shb() + idb(tsresol=9) + epb(2_000_000_000, b"x"))
        self.assertAlmostEqual(pk[0].ts, 2.0)

    def test_cut_mid_block_keeps_earlier_packets(self):
        raw = shb() + idb() + epb(1, b"good") + epb(2, b"cut short")
        for cut in range(1, 30):
            with self.subTest(cut=cut):
                pk, r = self.read(raw[:-cut])
                self.assertEqual([p.data for p in pk], [b"good"])
                self.assertTrue(r.truncated)

    def test_not_pcapng(self):
        with self.assertRaises(pcapng.PcapngError):
            self.read(b"\xd4\xc3\xb2\xa1" + bytes(20))


@unittest.skipUnless(shutil.which("tshark") and any(CAPTURES.glob("*.pcapng")),
                     "needs tshark and a local capture in 03-hci-capture/captures")
class AgainstWireshark(unittest.TestCase):
    """Same capture, two readers: the number of advertising reports must match."""

    def test_report_count(self):
        path = sorted(CAPTURES.glob("*.pcapng"))[0]
        out = subprocess.run(
            ["tshark", "-r", str(path), "-Y",
             "bthci_evt.le_meta_subevent == 0x02 || bthci_evt.le_meta_subevent == 0x0d",
             "-T", "fields", "-e", "bthci_evt.le_peer_address_type"],
            capture_output=True, text=True, check=True).stdout.split()
        types = [int(t, 0) for line in out for t in line.split(",")]
        cap = analyze.load(path)
        # load() drops anonymous reports (address type 0xFF): there is no address to track
        self.assertEqual(sum(t != 0xFF for t in types), len(cap.sightings))
        self.assertFalse(cap.truncated)


if __name__ == "__main__":
    unittest.main()
