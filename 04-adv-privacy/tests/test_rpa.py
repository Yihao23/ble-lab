import unittest

from bleprivacy import addr, rpa

# Core Spec v5.4, Vol 3 Part H, Appendix D.7 (ah random address hash)
IRK = bytes.fromhex("ec0234a357c8ad05341010a60a397d9b")
PRAND = bytes.fromhex("708194")
HASH = bytes.fromhex("0dfbaa")


class AES(unittest.TestCase):
    def test_fips197_appendix_c1(self):
        self.assertEqual(rpa.aes128_encrypt(bytes(range(16)),
                                            bytes.fromhex("00112233445566778899aabbccddeeff")),
                         bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"))

    def test_against_cryptography_if_installed(self):
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except ImportError:
            self.skipTest("cryptography not installed")
        import os
        for _ in range(200):
            k, m = os.urandom(16), os.urandom(16)
            enc = Cipher(algorithms.AES(k), modes.ECB()).encryptor()
            self.assertEqual(rpa.aes128_encrypt(k, m), enc.update(m) + enc.finalize())


class RPA(unittest.TestCase):
    def test_spec_vector(self):
        self.assertEqual(rpa.ah(IRK, PRAND), HASH)

    def test_resolves_spec_address(self):
        a = (PRAND + HASH)[::-1]              # on-air order is LSB-first
        self.assertTrue(rpa.resolves(IRK, a))
        self.assertEqual(addr.kind(0x01, a), addr.RPA)

    def test_wrong_key_or_flipped_bit(self):
        a = bytearray((PRAND + HASH)[::-1])
        self.assertFalse(rpa.resolves(bytes(16), bytes(a)))
        a[0] ^= 1
        self.assertFalse(rpa.resolves(IRK, bytes(a)))


class Kinds(unittest.TestCase):
    def test_top_two_bits(self):
        for top, k in ((0b11, addr.STATIC), (0b01, addr.RPA), (0b00, addr.NRPA),
                       (0b10, addr.RESERVED)):
            self.assertEqual(addr.kind(0x01, bytes(5) + bytes([top << 6])), k)

    def test_public_ignores_top_bits(self):
        self.assertEqual(addr.kind(0x00, bytes(5) + b"\x40"), addr.PUBLIC)


if __name__ == "__main__":
    unittest.main()
