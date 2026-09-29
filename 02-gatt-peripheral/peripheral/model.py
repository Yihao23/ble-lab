"""The device model: everything a GATT server decides, and nothing it does.

On a microcontroller this is the code in the SoftDevice / Zephyr write and
read callbacks: encode a sensor value in the format the Bluetooth SIG
specifies, validate what a client writes, pick the ATT error code when it is
wrong, and decide when a notification is worth sending. None of that needs a
radio, so none of it touches one here — it is plain Python, unit tested, and
the BlueZ D-Bus glue in gatt_bluez.py only moves bytes in and out of it.

Formats and error codes are from the Bluetooth SIG:
  * GATT Specification Supplement — Battery Level, Temperature
  * Core Spec Vol 3 Part F, 3.4.1.1 — ATT error codes
  * Core Specification Supplement Part B — common profile error codes
"""
from dataclasses import dataclass, field
import math
import struct

# --- 16-bit UUIDs assigned by the SIG --------------------------------------
BATTERY_SERVICE = 0x180F
BATTERY_LEVEL = 0x2A19
ENVIRONMENTAL_SENSING = 0x181A
TEMPERATURE = 0x2A6E

# --- 128-bit UUIDs for this lab's own service ------------------------------
CONTROL_SERVICE = "b1e1ab01-0000-4000-8000-00000000b1e1"
SAMPLE_INTERVAL = "b1e1ab02-0000-4000-8000-00000000b1e1"
IDENTIFY = "b1e1ab03-0000-4000-8000-00000000b1e1"


class AttError(Exception):
    """Raised by a write or read handler; carries the ATT error code to return."""

    WRITE_NOT_PERMITTED = 0x03
    INVALID_ATTRIBUTE_VALUE_LENGTH = 0x0D
    VALUE_NOT_ALLOWED = 0x13          # Core 5.x
    OUT_OF_RANGE = 0xFF               # CSS Part B, common profile error

    def __init__(self, code, reason):
        super().__init__(f"ATT error 0x{code:02X}: {reason}")
        self.code = code
        self.reason = reason


# --- value encodings --------------------------------------------------------

def encode_battery_level(percent):
    """Battery Level (0x2A19): uint8, 0..100 percent."""
    if not 0 <= percent <= 100:
        raise ValueError(f"battery level {percent} outside 0..100")
    return bytes([int(percent)])


TEMPERATURE_UNKNOWN = b"\x00\x80"     # sint16 0x8000: "value is not known"


def encode_temperature(celsius):
    """Temperature (0x2A6E): sint16, little-endian, resolution 0.01 degC.

    Rounds to the nearest 0.01. None or NaN encodes as the spec's "not known"
    value rather than as 0 degC, which a client would believe.
    """
    if celsius is None or (isinstance(celsius, float) and math.isnan(celsius)):
        return TEMPERATURE_UNKNOWN
    raw = round(celsius * 100)
    if not -32767 <= raw <= 32767:            # -32768 is reserved for "not known"
        raise ValueError(f"temperature {celsius} degC does not fit sint16 * 0.01")
    return struct.pack("<h", raw)


def encode_temperature_millideg(millideg):
    """Temperature from integer millidegrees — the form Linux sysfs reports.

    Integer arithmetic end to end, rounding half away from zero. Routing a
    fixed-point sensor reading through a float first is how 21.005 degC turns
    into 21.00: 21.005 has no exact binary representation and is stored as
    21.00499999..., which rounds down. A thermistor ADC on an MCU hands over
    an integer too; this is the path firmware should take.
    """
    if millideg is None:
        return TEMPERATURE_UNKNOWN
    centi = (millideg + 5) // 10 if millideg >= 0 else -((-millideg + 5) // 10)
    if not -32767 <= centi <= 32767:
        raise ValueError(f"temperature {millideg} mdegC does not fit sint16 * 0.01")
    return struct.pack("<h", centi)


def decode_temperature(data):
    """Inverse of encode_temperature. Returns degC, or None for "not known"."""
    (raw,) = struct.unpack("<h", data)
    return None if raw == -32768 else raw / 100


# --- the writable characteristic -------------------------------------------

SAMPLE_INTERVAL_MIN_MS = 100
SAMPLE_INTERVAL_MAX_MS = 10_000


def parse_sample_interval(data):
    """Sample interval: uint16 little-endian milliseconds, 100..10000.

    Two different mistakes, two different errors, because they point at two
    different fixes on the client side: the wrong length means the client
    encoded the type wrong; the wrong value means it encoded it right but
    asked for something the device will not do.
    """
    if len(data) != 2:
        raise AttError(AttError.INVALID_ATTRIBUTE_VALUE_LENGTH,
                       f"expected 2 bytes, got {len(data)}")
    (ms,) = struct.unpack("<H", data)
    if not SAMPLE_INTERVAL_MIN_MS <= ms <= SAMPLE_INTERVAL_MAX_MS:
        raise AttError(AttError.OUT_OF_RANGE,
                       f"{ms} ms outside {SAMPLE_INTERVAL_MIN_MS}..{SAMPLE_INTERVAL_MAX_MS}")
    return ms


def parse_identify(data):
    """Identify: one byte, the number of seconds to blink (1..30)."""
    if len(data) != 1:
        raise AttError(AttError.INVALID_ATTRIBUTE_VALUE_LENGTH,
                       f"expected 1 byte, got {len(data)}")
    if not 1 <= data[0] <= 30:
        raise AttError(AttError.VALUE_NOT_ALLOWED, f"{data[0]} s outside 1..30")
    return data[0]


# --- notification policy ----------------------------------------------------

@dataclass
class NotifyPolicy:
    """When is a notification worth the airtime?

    Notify when a subscribed client would see a different value, and on a slow
    heartbeat otherwise so it can tell a silent device from a dead one. Never
    faster than min_gap_s: a noisy sensor must not flood the link, because
    every notification costs the peripheral a radio event and battery.
    """
    min_gap_s: float = 0.5
    heartbeat_s: float = 30.0
    subscribed: bool = False
    _last_sent_value: bytes = None
    _last_sent_at: float = field(default=-math.inf)

    def should_send(self, now, value):
        if not self.subscribed:
            return False
        if now - self._last_sent_at < self.min_gap_s:
            return False
        changed = value != self._last_sent_value
        stale = now - self._last_sent_at >= self.heartbeat_s
        return changed or stale

    def mark_sent(self, now, value):
        self._last_sent_value = value
        self._last_sent_at = now

    def subscribe(self, on):
        self.subscribed = on
        if on:                                  # a new subscriber gets a value at once
            self._last_sent_value = None
            self._last_sent_at = -math.inf


# --- the device -------------------------------------------------------------

@dataclass
class Device:
    """State of the peripheral, and the handlers the GATT glue calls."""
    battery_percent: int = 100
    temperature_mdeg: int = None
    sample_interval_ms: int = 1000
    identify_until: float = 0.0
    battery_notify: NotifyPolicy = field(default_factory=NotifyPolicy)
    temperature_notify: NotifyPolicy = field(default_factory=NotifyPolicy)

    def read(self, char):
        if char == BATTERY_LEVEL:
            return encode_battery_level(self.battery_percent)
        if char == TEMPERATURE:
            return encode_temperature_millideg(self.temperature_mdeg)
        if char == SAMPLE_INTERVAL:
            return struct.pack("<H", self.sample_interval_ms)
        raise KeyError(char)

    def write(self, char, data, now=0.0):
        if char == SAMPLE_INTERVAL:
            self.sample_interval_ms = parse_sample_interval(data)
            return
        if char == IDENTIFY:
            self.identify_until = now + parse_identify(data)
            return
        raise AttError(AttError.WRITE_NOT_PERMITTED, f"{char} is not writable")

    def update_sensors(self, battery_percent=None, temperature_mdeg=None):
        if battery_percent is not None:
            self.battery_percent = max(0, min(100, int(battery_percent)))
        self.temperature_mdeg = temperature_mdeg

    def due_notifications(self, now):
        """Return [(char, value)] that should be notified now, and record them."""
        out = []
        for char, policy in ((BATTERY_LEVEL, self.battery_notify),
                             (TEMPERATURE, self.temperature_notify)):
            value = self.read(char)
            if policy.should_send(now, value):
                policy.mark_sent(now, value)
                out.append((char, value))
        return out

    def identifying(self, now):
        return now < self.identify_until
