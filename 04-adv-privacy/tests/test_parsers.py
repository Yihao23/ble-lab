"""The Python parsers must agree with the C library's fixtures, which were
checked field by field against Wireshark. One set of expectations, two
implementations."""
import pathlib
import re
import struct
import unittest

from bleprivacy import ad, hci, monitor

FIXTURES = pathlib.Path(__file__).resolve().parents[2] / "01-ble-core-c/tests/fixtures.h"


def load_c_fixtures():
    src = FIXTURES.read_text()
    arrays = {m[1]: bytes(int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", m[2]))
              for m in re.finditer(r"(REAL_EVT_\d+)\[\] = \{([^}]*)\}", src)}
    rows = re.findall(r'\{"([^"]+)", (REAL_EVT_\d+), sizeof \w+, 0x([0-9a-f]+)u, '
                      r'(-?\d+), (-?\d+), (-?\d+), (\d+)\}', src)
    return [(label, arrays[name], int(et, 16), int(at), int(rssi), int(tx), int(dl))
            for label, name, et, at, rssi, tx, dl in rows]


class AgreesWithC(unittest.TestCase):
    def test_every_c_fixture(self):
        fixtures = load_c_fixtures()
        self.assertEqual(len(fixtures), 7)
        for label, evt, et, at, rssi, tx, dlen in fixtures:
            with self.subTest(label):
                (r,) = hci.parse_adv_reports(evt)
                self.assertEqual((r.evt_type, r.addr_type, r.rssi, r.tx_power, len(r.data)),
                                 (et, at, rssi, tx, dlen))
                self.assertEqual(r.addr[:5], bytes.fromhex("1122334455"))
                self.assertEqual(r.addr[5] & 0x3F, 0x2A)
                self.assertFalse(ad.parse(r.data).malformed)


def legacy_event(evt_type, addr, data, rssi):
    body = bytes([0x02, 1, evt_type, 0x01]) + addr + bytes([len(data)]) + data + \
        struct.pack("b", rssi)
    return bytes([hci.LE_META, len(body)]) + body


class Legacy(unittest.TestCase):
    ADDR = bytes([1, 2, 3, 4, 5, 0xC6])

    def test_scan_rsp_maps_to_extended_bits(self):
        (r,) = hci.parse_adv_reports(legacy_event(0x04, self.ADDR, b"\x02\x01\x06", -70))
        self.assertTrue(r.from_legacy_event)
        self.assertTrue(r.is_scan_response)
        self.assertEqual(r.rssi, -70)
        self.assertEqual(r.addr_str, "C6:05:04:03:02:01")

    def test_data_overrun_is_malformed_not_a_crash(self):
        evt = bytearray(legacy_event(0x00, self.ADDR, b"\x02\x01\x06", -70))
        evt[12] = 200                         # data length now points past the end
        with self.assertRaises(hci.MalformedEvent):
            hci.parse_adv_reports(bytes(evt))

    def test_every_truncation_is_malformed_or_empty(self):
        evt = legacy_event(0x00, self.ADDR, b"\x02\x01\x06", -70)
        for n in range(len(evt)):
            with self.subTest(n=n):
                try:
                    hci.parse_adv_reports(evt[:n])
                except hci.MalformedEvent:
                    pass

    def test_other_events_are_ignored(self):
        self.assertEqual(hci.parse_adv_reports(bytes([0x0E, 0x04, 0x01, 0x0C, 0x20, 0x00])), [])


class AD(unittest.TestCase):
    def test_fields(self):
        p = ad.parse(bytes.fromhex("020105" "0319c103" "05ff4c00aabb" "0416f3fe01" "03090a0b"
                                   "020af4" "0503" "0f18" "1a18"))
        self.assertEqual(p.flags, 0x05)
        self.assertEqual(p.appearance, 0x03C1)
        self.assertEqual(p.manufacturer, {0x004C: b"\xaa\xbb"})
        self.assertEqual(p.service_data, {0xFEF3: b"\x01"})
        self.assertEqual(p.tx_power, -12)
        self.assertEqual(p.uuid16, {0x180F, 0x181A})
        self.assertFalse(p.malformed)

    def test_overrun_keeps_what_came_before(self):
        p = ad.parse(bytes.fromhex("020106" "09ff4c00"))
        self.assertTrue(p.malformed)
        self.assertEqual(p.flags, 0x06)

    def test_zero_length_is_padding(self):
        self.assertEqual(ad.parse(bytes.fromhex("020106" "00" "ffff")).types, (0x01,))


class Monitor(unittest.TestCase):
    def test_header_is_big_endian(self):
        self.assertEqual(monitor.split(b"\x00\x01\x00\x03\x3e"), (1, monitor.EVENT_PKT, b"\x3e"))

    def test_short(self):
        with self.assertRaises(ValueError):
            monitor.split(b"\x00\x00\x00")


if __name__ == "__main__":
    unittest.main()
