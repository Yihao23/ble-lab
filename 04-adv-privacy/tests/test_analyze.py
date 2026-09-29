import os
import unittest

from bleprivacy import analyze
from bleprivacy import addr as addrmod

from .helpers import Air, address, manufacturer, service_data

TOKEN = bytes.fromhex("4a17234c575944113241706600")      # random-looking, 13 bytes
OTHER = bytes.fromhex("9e01c2d7aa5b3f6e8810cc4d21")


def run(air, **kw):
    cap = air.capture(**kw)
    tr = analyze.build_tracks(cap)
    hs = analyze.find_handoffs(cap, tr)
    links = analyze.concurrent_links(tr)
    return cap, tr, hs, links, analyze.findings(cap, tr, hs, links)


def rules(fs):
    return sorted(f.rule for f in fs)


class Handoffs(unittest.TestCase):
    def test_identical_payload_defeats_rotation(self):
        air = Air()
        a = air.device(address(0, 1), 0, 300, service_data(0xFEF3, TOKEN))
        b = air.device(address(0, 2), 300.5, 600, service_data(0xFEF3, TOKEN), rssi=-80)
        _, _, hs, _, fs = run(air, t1=900)
        (h,) = hs
        self.assertEqual((h.old.addr_str, h.new.addr_str, h.strength), (a, b, "identical"))
        self.assertIn("P004", rules(fs))     # RSSI differs by 20 dB: the bytes alone link it

    def test_same_shape_same_rssi_is_probable(self):
        air = Air()
        air.device(address(0, 1), 0, 300, service_data(0xFEF3, TOKEN))
        air.device(address(0, 2), 300.5, 600, service_data(0xFEF3, OTHER), rssi=-62)
        _, _, (h,), _, fs = run(air, t1=900)
        self.assertEqual(h.strength, "probable")
        self.assertIn("P005", rules(fs))

    def test_different_rssi_and_payload_is_not_linked(self):
        air = Air()
        air.device(address(0, 1), 0, 300, service_data(0xFEF3, TOKEN))
        air.device(address(0, 2), 300.5, 600, service_data(0xFEF3, OTHER), rssi=-85)
        self.assertEqual(run(air, t1=900)[2], [])

    def test_gap_too_long(self):
        air = Air()
        air.device(address(0, 1), 0, 300, service_data(0xFEF3, TOKEN))
        air.device(address(0, 2), 330, 600, service_data(0xFEF3, TOKEN))
        self.assertEqual(run(air, t1=900)[2], [])

    def test_gap_scales_with_advertising_interval(self):
        air = Air()                          # advertises every 8 s: a 15 s gap is one lost packet
        air.device(address(0, 1), 0, 296, service_data(0xFEF3, TOKEN), every=8)
        air.device(address(0, 2), 311, 600, service_data(0xFEF3, TOKEN), every=8)
        self.assertEqual(len(run(air, t1=900)[2]), 1)

    def test_low_entropy_payload_is_not_an_identifier(self):
        # Red first: a real capture linked three Apple RPAs on this bitmap,
        # which every device with the same app state sends.
        bitmap = bytes.fromhex("0100000000000000000000000080000000")
        air = Air()
        air.device(address(1, 1), 0, 300, manufacturer(0x004C, bitmap))
        air.device(address(1, 2), 302, 600, manufacturer(0x004C, bitmap), rssi=-85)
        self.assertEqual(run(air, t1=900)[2], [])

    def test_kinds_do_not_mix(self):
        air = Air()
        air.device(address(0b11, 1), 0, 300, manufacturer(0x004C, TOKEN))
        air.device(address(0b01, 2), 300.5, 600, manufacturer(0x004C, TOKEN))
        self.assertEqual(run(air, t1=900)[2], [])

    def test_one_successor_each_and_chains(self):
        air = Air()
        air.device(address(0, 1), 0, 300, service_data(0xFEF3, TOKEN))
        air.device(address(0, 2), 300.5, 600, service_data(0xFEF3, TOKEN))
        air.device(address(0, 3), 300.7, 595, service_data(0xFEF3, TOKEN))   # a decoy
        air.device(address(0, 4), 600.5, 900, service_data(0xFEF3, TOKEN))
        cap, tr, hs, _, _ = run(air, t1=1200)
        (seq, links), = [c for c in analyze.chains(tr, hs) if len(c[0]) == 3]
        self.assertEqual([t.addr_str[-2:] for t in seq], ["01", "02", "04"])
        self.assertEqual(len({h.old.addr_str for h in hs}), len(hs))
        self.assertEqual(len({h.new.addr_str for h in hs}), len(hs))

    def test_capture_edges_are_not_rotations(self):
        air = Air()                          # starts with the capture: may have been there before
        air.device(address(0, 1), 0, 300, service_data(0xFEF3, TOKEN))
        air.device(address(0, 2), 5, 20, service_data(0xFEF3, TOKEN))
        cap, tr, _, _, _ = run(air, t1=900)
        self.assertEqual(analyze.rotation_stats(cap, tr), {})


class Concurrent(unittest.TestCase):
    def test_extended_payload_starting_with_the_legacy_one(self):
        air = Air()
        air.device(address(0, 1), 0, 600, service_data(0xFEF3, TOKEN))
        air.device(address(0, 2), 0, 600, service_data(0xFEF3, TOKEN + os.urandom(60)),
                   evt_type=0)
        (a, b, shared), = run(air)[3]
        self.assertEqual({f[0] for f in shared}, {"service_data"})


class Rules(unittest.TestCase):
    def test_public_name_with_own_address_limited_too_long(self):
        air = Air()
        addr = address(0, 0x1A2B - 0x0E00)
        air.device(addr, 0, 600, (0x01, b"\x05"), (0x09, b"lamp_1A2B"), addr_type=0x00)
        self.assertEqual(rules(run(air)[4]), ["P001", "P003", "S001"])

    def test_limited_discoverable_within_180_s_is_fine(self):
        air = Air()
        air.device(address(0b11, 1), 0, 170, (0x01, b"\x05"))
        self.assertNotIn("S001", rules(run(air, t1=600)[4]))

    def test_reserved_and_malformed(self):
        air = Air()
        air.device(address(0b10, 1), 0, 10, (0xFF, b"\x4c"))
        a = air.device(address(0b11, 2), 0, 10)
        air.sightings[-1].ad.malformed = True
        self.assertEqual(rules(run(air, t1=600)[4]), ["S002", "S003"])

    def test_long_lived_rpa(self):
        air = Air()
        air.device(address(0b01, 1), 60, 60 + 25 * 60, every=30)
        self.assertEqual(rules(run(air, t1=3600)[4]), ["P006"])

    def test_address_kind_helpers(self):
        self.assertTrue(addrmod.rotates(addrmod.NRPA))
        self.assertFalse(addrmod.rotates(addrmod.STATIC))


if __name__ == "__main__":
    unittest.main()
