"""bleprivacy.irk on hand-built HCI traffic, with the spec's ah() vector:
the IRK's byte order out of SMP, which connection field holds the RPA, and
that neither the key nor an address is ever printed."""
import contextlib
import io
import os
import pathlib
import struct
import tempfile
import unittest

from bleprivacy import irk as irkmod
from bleprivacy import monitor

from .test_pcapng import epb, idb, shb

# Core Vol 3 Part H, D.7: IRK (MSB first) and the RPA 70:81:94:0D:FB:AA it makes.
IRK = bytes.fromhex("ec0234a357c8ad05341010a60a397d9b")
RPA = bytes.fromhex("aafb0d948170")              # LSB first, as HCI carries it
OTHER_RPA = bytes.fromhex("abfb0d948170")        # hash changed: must not resolve
IDENTITY = bytes.fromhex("665544332211")


def acl(op, code_and_params, pb=0x2, handle=0x001):
    """(t, op, payload): one SMP PDU in an ACL packet."""
    l2 = struct.pack("<HH", len(code_and_params), irkmod.SMP_CID) + code_and_params
    return (1.0, op, struct.pack("<HH", handle | pb << 12, len(l2)) + l2)


def enhanced_connection(peer_type, peer_addr, peer_rpa=bytes(6), status=0):
    p = (bytes([status]) + struct.pack("<H", 0x001) + bytes([1, peer_type]) + peer_addr
         + bytes(6) + peer_rpa + struct.pack("<HHH", 24, 0, 500) + b"\x00")
    body = bytes([0x0A]) + p
    return (2.0, monitor.EVENT_PKT, bytes([0x3E, len(body)]) + body)


class SmpKeys(unittest.TestCase):
    def test_irk_is_reversed_out_of_smp(self):
        keys = irkmod.smp_identity_keys([
            acl(monitor.ACL_RX, b"\x08" + IRK[::-1]),
            acl(monitor.ACL_RX, b"\x09\x00" + IDENTITY)])
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0].irk, IRK)
        self.assertEqual(keys[0].direction, "received")
        self.assertEqual(keys[0].id_type, "public")

    def test_direction_and_random_static_identity(self):
        keys = irkmod.smp_identity_keys([
            acl(monitor.ACL_TX, b"\x08" + bytes(16)),
            acl(monitor.ACL_TX, b"\x09\x01" + IDENTITY)])
        self.assertEqual((keys[0].direction, keys[0].id_type), ("sent", "random static"))

    def test_continuation_fragment_and_other_channels_ignored(self):
        keys = irkmod.smp_identity_keys([
            acl(monitor.ACL_RX, b"\x08" + IRK[::-1], pb=0x1),
            (1.0, monitor.ACL_RX, struct.pack("<HHHH", 0x2001, 21, 17, 0x0004) + b"\x08" + IRK)])
        self.assertEqual(keys, [])

    def test_short_packets_do_not_raise(self):
        irkmod.smp_identity_keys([(0, monitor.ACL_RX, b"\x01\x20\x05"),
                                  acl(monitor.ACL_RX, b"\x08\x01")])


class Peers(unittest.TestCase):
    def test_random_peer_address_is_the_rpa(self):
        peer, = irkmod.connection_peers([enhanced_connection(1, RPA)])
        self.assertEqual((peer.addr, peer.addr_type), (RPA, 1))

    def test_controller_resolved_peer_gives_its_rpa(self):
        peer, = irkmod.connection_peers([enhanced_connection(2, IDENTITY, RPA)])
        self.assertEqual(peer.addr, RPA)

    def test_failed_connection_ignored(self):
        self.assertEqual(irkmod.connection_peers([enhanced_connection(1, RPA, status=0x3E)]), [])


BLERPA = irkmod.DEFAULT_BLERPA


class CrossCheck(unittest.TestCase):
    def test_missing_tool_gives_none(self):
        self.assertIsNone(irkmod.blerpa_check(IRK, [RPA], "/nonexistent/blerpa"))

    @unittest.skipUnless(pathlib.Path(BLERPA).exists(), "project 01 not built")
    def test_c_library_agrees_on_the_spec_vector(self):
        self.assertEqual(irkmod.blerpa_check(IRK, [RPA, OTHER_RPA, IDENTITY]), [True, False, False])


def pcapng_file(packets):
    raw = shb() + idb()
    for i, (op, payload) in enumerate(packets):
        raw += epb(1_790_000_000_000_000 + i * 1000, struct.pack(">HH", 0, op) + payload)
    f = tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False)
    f.write(raw)
    f.close()
    return f.name


class Command(unittest.TestCase):
    def run_main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = irkmod.main(list(argv))
        return code, out.getvalue()

    def test_end_to_end_without_printing_secrets(self):
        pairing = pcapng_file([acl(monitor.ACL_RX, b"\x08" + IRK[::-1])[1:],
                               acl(monitor.ACL_RX, b"\x09\x00" + IDENTITY)[1:]])
        later = pcapng_file([enhanced_connection(1, RPA)[1:], enhanced_connection(1, OTHER_RPA)[1:]])
        self.addCleanup(os.unlink, pairing)
        self.addCleanup(os.unlink, later)
        code, text = self.run_main("--pairing", pairing, later)
        self.assertEqual(code, 0)
        self.assertIn("connections: 2, peer address an RPA in 2, 2 distinct; 1 resolve", text)
        self.assertIn("identity address public", text)
        for secret in (IRK, IRK[::-1], RPA, RPA[::-1], IDENTITY, IDENTITY[::-1]):
            self.assertNotIn(secret.hex(), text.replace(" ", "").lower())
            self.assertNotIn(":".join(f"{b:02x}" for b in secret), text.lower())

    def test_irk_file(self):
        later = pcapng_file([enhanced_connection(1, RPA)[1:]])
        with tempfile.NamedTemporaryFile("w", suffix=".hex", delete=False) as f:
            f.write(IRK.hex() + "\n")
        self.addCleanup(os.unlink, later)
        self.addCleanup(os.unlink, f.name)
        code, text = self.run_main("--irk-file", f.name, later)
        self.assertIn("1 distinct; 1 resolve", text)
        self.assertNotIn(IRK.hex(), text)

    def test_pairing_capture_without_a_key_is_an_error(self):
        empty = pcapng_file([enhanced_connection(1, RPA)[1:]])
        self.addCleanup(os.unlink, empty)
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            self.run_main("--pairing", empty, empty)


if __name__ == "__main__":
    unittest.main()
