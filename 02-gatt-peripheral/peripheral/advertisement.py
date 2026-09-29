"""The LE advertisement: what a phone sees before it ever connects.

Legacy advertising carries at most 31 bytes, and every AD structure costs two
bytes of header on top of its data. The custom 128-bit control service would
cost 18 bytes on its own, so it is left out: a client finds it through GATT
service discovery after connecting.

What bluetoothd actually sends to the controller for this object (read off
the HCI capture, see the README):

    LE Set Extended Advertising Data   flags 0x06 (3) + UUID16 180F 181A (6) = 9 bytes
    LE Set Extended Scan Response Data name "BLE-Lab" (9)
    LE Set Extended Advertising Params legacy PDUs, connectable + scannable,
                                       1280 ms interval, own address public

Without Discoverable=True bluetoothd sends no Flags AD at all, and without
flags the advertisement is not discoverable in the GAP sense. The name goes
in the scan response, so a passive scanner never learns it.
"""
import dbus
import dbus.service

LE_ADVERTISEMENT_IFACE = "org.bluez.LEAdvertisement1"
DBUS_PROP_IFACE = "org.freedesktop.DBus.Properties"


class Advertisement(dbus.service.Object):
    PATH = "/org/bluez/blelab/advertisement0"

    def __init__(self, bus, name, service_uuids):
        self.name = name
        self.service_uuids = service_uuids
        super().__init__(bus, self.PATH)

    def get_path(self):
        return dbus.ObjectPath(self.PATH)

    def get_properties(self):
        return {LE_ADVERTISEMENT_IFACE: {
            "Type": "peripheral",
            "ServiceUUIDs": dbus.Array(self.service_uuids, signature="s"),
            "LocalName": dbus.String(self.name),
            "Discoverable": dbus.Boolean(True),     # or bluetoothd omits the Flags AD
        }}

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        return self.get_properties()[LE_ADVERTISEMENT_IFACE]

    @dbus.service.method(LE_ADVERTISEMENT_IFACE)
    def Release(self):
        pass
