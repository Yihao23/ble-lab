"""timeline.py on hand-built HCI packets: field offsets, the summary's
judgement of how a link got encrypted, and that no key is ever printed.

    cd 03-hci-capture && python3 -m unittest discover -s tests -t .
"""
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import timeline as tl  # noqa: E402

KEY = bytes(range(0xA0, 0xB0))          # 16 octets that must never appear in output


def le_meta(sub, params):
    body = bytes([sub]) + params
    return bytes([0x3E, len(body)]) + body


def command(opcode, params):
    return struct.pack("<HB", opcode, len(params)) + params


class Events(unittest.TestCase):
    def test_enhanced_connection_complete(self):
        p = (bytes([0x00]) + struct.pack("<H", 0x0801) + bytes([1, 1]) + b"\x11" * 6
             + b"\x22" * 6 + b"\x33" * 6 + struct.pack("<HHH", 24, 0, 500) + b"\x00")
        text, handle, kind = tl.decode_event(le_meta(0x0A, p))
        self.assertEqual(handle, 0x801)
        self.assertIn("peripheral", text)
        self.assertIn("interval 30 ms", text)
        self.assertIn("supervision timeout 5000 ms", text)
        self.assertEqual(kind, "connect:1:30")
        self.assertNotIn("11:11", text)           # no address
        self.assertNotIn("111111", text)

    def test_legacy_connection_complete_offsets(self):
        p = (bytes([0x00]) + struct.pack("<H", 0x0040) + bytes([0, 0]) + b"\x11" * 6
             + struct.pack("<HHH", 6, 4, 72) + b"\x00")
        text, handle, kind = tl.decode_event(le_meta(0x01, p))
        self.assertEqual(handle, 0x040)
        self.assertIn("central", text)
        self.assertIn("interval 7.5 ms, latency 4, supervision timeout 720 ms", text)

    def test_ltk_request_tells_secure_connections_from_legacy(self):
        sc = struct.pack("<H", 0x801) + bytes(8) + struct.pack("<H", 0)
        legacy = struct.pack("<H", 0x801) + bytes(range(1, 9)) + struct.pack("<H", 0x1234)
        self.assertIn("Secure Connections", tl.decode_event(le_meta(0x05, sc))[0])
        self.assertIn("legacy", tl.decode_event(le_meta(0x05, legacy))[0])
        self.assertEqual(tl.decode_event(le_meta(0x05, sc))[2], "ltk_request")

    def test_disconnection_reason(self):
        text, handle, kind = tl.decode_event(bytes([0x05, 4, 0x00]) + struct.pack("<H", 0x801) + b"\x3d")
        self.assertEqual(handle, 0x801)
        self.assertIn("MIC Failure", text)
        self.assertEqual(kind, "disconnect:61")

    def test_encryption_change(self):
        on = bytes([0x08, 4, 0x00]) + struct.pack("<H", 0x801) + b"\x01"
        failed = bytes([0x08, 4, 0x06]) + struct.pack("<H", 0x801) + b"\x00"
        self.assertEqual(tl.decode_event(on)[2], "encrypted")
        self.assertIn("failed", tl.decode_event(failed)[0])
        self.assertEqual(tl.decode_event(failed)[2], "")

    def test_channel_selection_algorithm(self):
        self.assertEqual(tl.decode_event(le_meta(0x14, struct.pack("<H", 0x801) + b"\x01"))[2], "csa:#2")
        self.assertEqual(tl.decode_event(le_meta(0x14, struct.pack("<H", 0x801) + b"\x00"))[2], "csa:#1")

    def test_successful_command_complete_is_left_out(self):
        ok = bytes([0x0E, 4, 1]) + struct.pack("<H", 0x201A) + b"\x00"
        bad = bytes([0x0E, 4, 1]) + struct.pack("<H", 0x201A) + b"\x12"
        self.assertIsNone(tl.decode_event(ok))
        self.assertIn("failed", tl.decode_event(bad)[0])

    def test_short_events_do_not_raise(self):
        for pl in (b"", b"\x3e", b"\x3e\x01\x0a", b"\x05\x01", b"\x08\x02\x00"):
            tl.decode_event(pl)


class Secrets(unittest.TestCase):
    def test_ltk_reply_never_shows_the_key(self):
        text, handle, kind = tl.decode_command(command(0x201A, struct.pack("<H", 0x801) + KEY))
        self.assertEqual(kind, "ltk_reply")
        self.assertEqual(handle, 0x801)
        self.assertIn("withheld", text)
        for b in KEY:
            self.assertNotIn(f"{b:02x}", text.lower().replace("0x801", ""))

    def test_mgmt_key_events_are_withheld(self):
        for code in (0x0009, 0x000A, 0x0018, 0x0019):
            pl = b"\x00" * 4 + struct.pack("<H", code) + KEY
            text, kind = tl.decode_mgmt(pl)
            self.assertIn("withheld", text)
            self.assertEqual(kind, "stored_key")
            self.assertNotIn(KEY.hex(), text)

    def test_create_connection_hides_the_address(self):
        text, _, _ = tl.decode_command(command(0x0405, b"\x11\x22\x33\x44\x55\x66" + bytes(7)))
        self.assertIn("withheld", text)
        self.assertNotIn("11", text)


class Acl(unittest.TestCase):
    def test_att_row(self):
        raw = bytes.fromhex("01280700030004000a2400")
        row = "1\t0x801\t2\tOK\t0x0004\t3\tOK\t0x0a\t0x0024\t-\t-\t-\t-"
        self.assertEqual(tl.decode_acl(raw, row), ("ATT", "READ_REQ handle 0x0024", "att:10"))

    def test_smp_by_name_only(self):
        raw = bytes.fromhex("0120150011000600" + "0c" + "ab" * 16)   # Pairing Public Key, cut short
        row = "1\t0x801\t2\tOK\t0x0006\t17\t-"
        layer, text, kind = tl.decode_acl(raw, row)
        self.assertEqual((layer, text, kind), ("SMP", "Pairing Public Key", "smp:12"))

    def test_bredr_connection_request_names_the_psm(self):
        raw = bytes.fromhex("00010c000800010002030400" + "0100" + "4000")
        row = "1\t0x100\t2\tOK\t0x0001\t8\t-"
        self.assertEqual(tl.decode_acl(raw, row)[1],
                         "BR/EDR signalling: Connection Request, PSM 0x0001 SDP")

    def test_fragment(self):
        self.assertEqual(tl.decode_acl(b"\x01\x10\x00\x00", "1\t0x801\t1\tL2CAP_-2")[1], "continuation")


def step(t, kind, handle=0x801, text="x", way="<", layer="HCI"):
    return tl.Step(t, way, layer, text, handle, kind)


class Summary(unittest.TestCase):
    def test_pairing_then_encryption(self):
        c, = tl.connections([step(0, "connect:1:30"), step(1, "smp:1"), step(2, "smp:12"),
                             step(3, "ltk_request"), step(3.1, "encrypted"), step(9, "disconnect:19")])
        self.assertEqual(c.smp_pairing, 2)
        self.assertTrue(c.paired_before_ltk)
        text = "\n".join(tl.summary(c))
        self.assertIn("after pairing on this connection", text)
        self.assertIn("encrypted 3100 ms after connecting", text)
        self.assertIn("0x13 Remote User Terminated Connection", text)

    def test_reconnection_with_stored_key(self):
        c, = tl.connections([step(0, "connect:1:30"), step(0.2, "ltk_request"),
                             step(0.25, "encrypted"), step(0.3, "smp:8")])
        self.assertEqual(c.smp_pairing, 0)
        self.assertEqual(c.smp_keys, 1)
        self.assertIn("stored at an earlier pairing", "\n".join(tl.summary(c)))

    def test_handles_reused_across_connections(self):
        cs = tl.connections([step(0, "connect:1:30"), step(1, "smp:1"), step(2, "disconnect:19"),
                             step(3, "connect:1:30"), step(4, "ltk_request"), step(4.1, "encrypted")])
        self.assertEqual(len(cs), 2)
        self.assertEqual(cs[1].smp_pairing, 0)
        self.assertIn("stored", "\n".join(tl.summary(cs[1])))
        self.assertIn("still up", "\n".join(tl.summary(cs[1])))

    def test_att_counted_per_side(self):
        c, = tl.connections([step(0, "connect:1:30"), step(1, "att:16", way="<"),
                             step(1.1, "att:17", way=">"), step(2, "att:10", way=">"),
                             step(2.1, "att:1", way="<"), step(3, "att:27", way=">")])
        text = "\n".join(tl.summary(c))
        self.assertIn("peer as client : 1 discovery requests, 0 reads", text)
        self.assertIn("us as client   : 0 discovery requests, 1 reads, 0 writes; 1 error", text)
        self.assertIn("notifications/indications we sent: 1", text)

    def test_steps_of_other_handles_are_ignored(self):
        c, = tl.connections([step(0, "connect:1:30"), step(1, "smp:1", handle=0x123)])
        self.assertEqual(c.smp_pairing, 0)

    def test_collapse(self):
        rows = tl.collapse([step(1, "", text="NTF"), step(2, "", text="NTF"),
                            step(3, "", text="other"), step(4, "", text="NTF")])
        self.assertEqual([(r[0].t, r[1], r[2]) for r in rows], [(1, 2, 2), (3, 1, 3), (4, 1, 4)])


if __name__ == "__main__":
    unittest.main()
