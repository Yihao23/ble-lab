"""The D-Bus objects must not shadow what dbus.service.Object sets on itself.

dbus.service.Object.__init__ assigns instance attributes such as _name and
_object_path. A method of the same name on a subclass is silently replaced
by that value. That is how every GATT read once failed with ATT error 0x0E
the first time a phone connected, while every model test passed: nothing
exercised this layer until a real client did.
"""
import unittest

try:
    import dbus.service
except ImportError:                        # python3-dbus is a system package
    dbus = None


@unittest.skipIf(dbus is None, "python3-dbus not installed")
class NoShadowedAttributes(unittest.TestCase):
    def test_no_method_shadows_a_base_attribute(self):
        from peripheral import advertisement, gatt_bluez

        # An unexported Object sets the same instance attributes as an exported one.
        taken = set(vars(dbus.service.Object()))
        self.assertIn("_name", taken)        # the one that bit
        for cls in (gatt_bluez.Application, gatt_bluez.Service,
                    gatt_bluez.Characteristic, advertisement.Advertisement):
            for attr in vars(cls):
                with self.subTest(cls=cls.__name__, attr=attr):
                    self.assertNotIn(attr, taken)


if __name__ == "__main__":
    unittest.main()
