"""Resolvable Private Address resolution, in pure Python.

The standard library has no AES, and this tool must run where pip cannot, so
AES-128 encryption is implemented here — the same algorithm, table for table,
as 01-ble-core-c/src/ble_aes.c. Tests check it against FIPS-197, the Bluetooth
spec's ah() vector, and the C library.

Give the tool the IRK of a device you own, and it can follow that device
through every address change. Nobody else can: that asymmetry is the whole
point of RPAs.
"""
_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(x):
    return ((x << 1) ^ (0x1B if x & 0x80 else 0)) & 0xFF


def _expand(key):
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [_SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= _RCON[i // 4 - 1]
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [b for word in w for b in word]


def aes128_encrypt(key, block):
    """AES-128 encrypt one 16-byte block. MSB-first, FIPS-197 byte order."""
    if len(key) != 16 or len(block) != 16:
        raise ValueError("AES-128 needs a 16-byte key and a 16-byte block")
    rk = _expand(key)
    s = [b ^ k for b, k in zip(block, rk[:16])]
    for rnd in range(1, 11):
        s = [_SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]         # ShiftRows
        if rnd < 10:
            m = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                m += [a[j] ^ t ^ _xtime(a[j] ^ a[(j + 1) % 4]) for j in range(4)]
            s = m
        s = [b ^ k for b, k in zip(s, rk[16 * rnd:16 * rnd + 16])]
    return bytes(s)


def ah(irk, r):
    """Random address hash, Core Vol 3 Part H 2.2.2. irk, r, result MSB-first."""
    return aes128_encrypt(irk, bytes(13) + bytes(r))[13:]


def resolves(irk, addr):
    """addr: 6 bytes LSB-first. True if it is an RPA made from this IRK."""
    if addr[5] >> 6 != 0b01:
        return False
    prand = bytes([addr[5], addr[4], addr[3]])
    return ah(irk, prand) == bytes([addr[2], addr[1], addr[0]])
