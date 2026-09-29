"""Linux Bluetooth monitor encapsulation (pcap LINKTYPE 254).

Every packet from the `bluetooth-monitor` interface starts with a 4-byte
header written by libpcap in network byte order: adapter index, then opcode.
The opcode says what follows — an HCI event from the controller, a command
to it, ACL data, or the kernel's own bookkeeping.
"""
import struct

NEW_INDEX = 0
COMMAND_PKT = 2
EVENT_PKT = 3
ACL_TX = 4
ACL_RX = 5


def split(data):
    """Return (adapter_index, opcode, payload)."""
    if len(data) < 4:
        raise ValueError("monitor packet shorter than its header")
    adapter, opcode = struct.unpack_from(">HH", data, 0)
    return adapter, opcode, data[4:]
