import math
import struct
import unittest

from peripheral.model import (
    BATTERY_LEVEL, IDENTIFY, SAMPLE_INTERVAL, TEMPERATURE, TEMPERATURE_UNKNOWN,
    AttError, Device, NotifyPolicy, decode_temperature, encode_battery_level,
    encode_temperature, encode_temperature_millideg, parse_identify, parse_sample_interval)


class Encodings(unittest.TestCase):
    def test_battery_level_is_one_byte_percent(self):
        self.assertEqual(encode_battery_level(94), b"\x5e")
        self.assertEqual(encode_battery_level(0), b"\x00")
        self.assertEqual(encode_battery_level(100), b"\x64")

    def test_battery_level_rejects_out_of_range(self):
        with self.assertRaises(ValueError):
            encode_battery_level(101)

    def test_temperature_is_sint16_centidegrees_little_endian(self):
        self.assertEqual(encode_temperature(23.45), struct.pack("<h", 2345))
        self.assertEqual(encode_temperature(23.45), b"\x29\x09")
        self.assertEqual(encode_temperature(-5.0), struct.pack("<h", -500))

    def test_float_input_cannot_round_what_it_cannot_represent(self):
        # This test was red first, asserting 21.01. It was wrong: 21.005 is
        # stored as 21.00499999..., so the nearest 0.01 really is 21.00.
        from decimal import Decimal
        self.assertLess(Decimal(21.005), Decimal("21.005"))   # exact value of the float
        self.assertEqual(decode_temperature(encode_temperature(21.005)), 21.0)

    def test_integer_millidegrees_round_exactly(self):
        # The real sensor path: sysfs gives 21005, integers round it correctly.
        self.assertEqual(decode_temperature(encode_temperature_millideg(21005)), 21.01)
        self.assertEqual(decode_temperature(encode_temperature_millideg(21004)), 21.0)
        self.assertEqual(decode_temperature(encode_temperature_millideg(-21005)), -21.01)
        self.assertEqual(encode_temperature_millideg(47050), b"\x61\x12")   # 4705
        self.assertEqual(encode_temperature_millideg(None), TEMPERATURE_UNKNOWN)

    def test_unknown_temperature_is_not_zero_degrees(self):
        # A missing reading must not reach the phone as 0.00 degC.
        self.assertEqual(encode_temperature(None), TEMPERATURE_UNKNOWN)
        self.assertEqual(encode_temperature(math.nan), TEMPERATURE_UNKNOWN)
        self.assertIsNone(decode_temperature(TEMPERATURE_UNKNOWN))

    def test_temperature_that_does_not_fit_is_refused(self):
        with self.assertRaises(ValueError):
            encode_temperature(400.0)       # 40000 > 32767


class WriteValidation(unittest.TestCase):
    def test_sample_interval_accepts_bounds(self):
        self.assertEqual(parse_sample_interval(struct.pack("<H", 100)), 100)
        self.assertEqual(parse_sample_interval(struct.pack("<H", 10000)), 10000)

    def test_wrong_length_and_wrong_value_are_different_errors(self):
        with self.assertRaises(AttError) as length:
            parse_sample_interval(b"\x10")
        self.assertEqual(length.exception.code, AttError.INVALID_ATTRIBUTE_VALUE_LENGTH)

        with self.assertRaises(AttError) as value:
            parse_sample_interval(struct.pack("<H", 50))
        self.assertEqual(value.exception.code, AttError.OUT_OF_RANGE)

    def test_sample_interval_is_little_endian(self):
        # 0x03E8 = 1000 ms. Sent big-endian it would read as 0xE803 = 59395.
        self.assertEqual(parse_sample_interval(b"\xe8\x03"), 1000)
        with self.assertRaises(AttError):
            parse_sample_interval(b"\x03\xe8")

    def test_identify(self):
        self.assertEqual(parse_identify(b"\x05"), 5)
        for bad in (b"", b"\x05\x00"):
            with self.assertRaises(AttError) as e:
                parse_identify(bad)
            self.assertEqual(e.exception.code, AttError.INVALID_ATTRIBUTE_VALUE_LENGTH)
        with self.assertRaises(AttError) as e:
            parse_identify(b"\x00")
        self.assertEqual(e.exception.code, AttError.VALUE_NOT_ALLOWED)


class Notifications(unittest.TestCase):
    def test_nothing_is_sent_to_nobody(self):
        p = NotifyPolicy()
        self.assertFalse(p.should_send(0.0, b"\x01"))

    def test_new_subscriber_gets_a_value_at_once(self):
        p = NotifyPolicy()
        p.subscribe(True)
        self.assertTrue(p.should_send(0.0, b"\x01"))

    def test_unchanged_value_is_not_resent_until_heartbeat(self):
        p = NotifyPolicy(min_gap_s=0.5, heartbeat_s=30.0)
        p.subscribe(True)
        p.mark_sent(0.0, b"\x01")
        self.assertFalse(p.should_send(10.0, b"\x01"))
        self.assertTrue(p.should_send(30.0, b"\x01"))

    def test_rate_limit_holds_back_a_noisy_sensor(self):
        p = NotifyPolicy(min_gap_s=0.5)
        p.subscribe(True)
        p.mark_sent(0.0, b"\x01")
        self.assertFalse(p.should_send(0.1, b"\x02"))     # changed, but too soon
        self.assertTrue(p.should_send(0.6, b"\x02"))

    def test_resubscribe_resets(self):
        p = NotifyPolicy()
        p.subscribe(True)
        p.mark_sent(0.0, b"\x01")
        p.subscribe(False)
        self.assertFalse(p.should_send(100.0, b"\x02"))
        p.subscribe(True)
        self.assertTrue(p.should_send(100.0, b"\x01"))


class DeviceBehaviour(unittest.TestCase):
    def test_reads(self):
        d = Device(battery_percent=94, temperature_mdeg=47050)
        self.assertEqual(d.read(BATTERY_LEVEL), b"\x5e")
        self.assertEqual(decode_temperature(d.read(TEMPERATURE)), 47.05)
        self.assertEqual(d.read(SAMPLE_INTERVAL), b"\xe8\x03")

    def test_valid_write_changes_state(self):
        d = Device()
        d.write(SAMPLE_INTERVAL, struct.pack("<H", 250))
        self.assertEqual(d.sample_interval_ms, 250)

    def test_invalid_write_leaves_state_alone(self):
        d = Device()
        with self.assertRaises(AttError):
            d.write(SAMPLE_INTERVAL, struct.pack("<H", 20000))
        self.assertEqual(d.sample_interval_ms, 1000)

    def test_read_only_characteristic_refuses_writes(self):
        d = Device()
        with self.assertRaises(AttError) as e:
            d.write(BATTERY_LEVEL, b"\x10")
        self.assertEqual(e.exception.code, AttError.WRITE_NOT_PERMITTED)

    def test_identify_runs_for_the_requested_time(self):
        d = Device()
        d.write(IDENTIFY, b"\x03", now=100.0)
        self.assertTrue(d.identifying(102.9))
        self.assertFalse(d.identifying(103.0))

    def test_only_subscribed_characteristics_notify(self):
        d = Device(battery_percent=90, temperature_mdeg=40000)
        d.temperature_notify.subscribe(True)
        sent = d.due_notifications(0.0)
        self.assertEqual([c for c, _ in sent], [TEMPERATURE])

    def test_a_changing_temperature_notifies_but_a_steady_battery_does_not(self):
        d = Device(battery_percent=90, temperature_mdeg=40000)
        d.battery_notify.subscribe(True)
        d.temperature_notify.subscribe(True)
        self.assertEqual(len(d.due_notifications(0.0)), 2)
        d.update_sensors(battery_percent=90, temperature_mdeg=41500)
        sent = d.due_notifications(1.0)
        self.assertEqual([c for c, _ in sent], [TEMPERATURE])

    def test_sensor_update_clamps_battery(self):
        d = Device()
        d.update_sensors(battery_percent=130)
        self.assertEqual(d.battery_percent, 100)


if __name__ == "__main__":
    unittest.main()
