"""Address kinds, and pseudonyms so a report never publishes a real address.

A capture of the air around you holds your neighbours' devices. The report
this tool writes is meant to be shareable, so by default every address is
replaced by a keyed hash: stable within one run (the same device keeps the
same label), unlinkable across runs unless you pass the same --salt.
"""
import hashlib
import hmac
import os

PUBLIC, STATIC, RPA, NRPA, RESERVED = "public", "static", "rpa", "nrpa", "reserved"


def kind(addr_type, addr):
    """addr: 6 bytes LSB-first. addr_type: HCI address type."""
    if addr_type in (0x00, 0x02):               # public, public identity
        return PUBLIC
    top = addr[5] >> 6
    return {0b11: STATIC, 0b01: RPA, 0b00: NRPA}.get(top, RESERVED)


def rotates(k):
    return k in (RPA, NRPA)


class Pseudonymizer:
    def __init__(self, salt=None, reveal=False):
        self.key = salt.encode() if salt else os.urandom(16)
        self.reveal = reveal

    def __call__(self, addr_str, k):
        if self.reveal:
            return addr_str
        digest = hmac.new(self.key, addr_str.encode(), hashlib.sha256).hexdigest()
        return f"{k}#{digest[:6]}"
