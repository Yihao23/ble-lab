"""BlueZ D-Bus glue: export the device model as a GATT application.

Structure follows BlueZ's own test/example-gatt-server. This file makes no
protocol decisions: reads, writes and notifications are all delegated to
peripheral.model.Device. What it does own is the translation of an
AttError into the only D-Bus error names BlueZ knows how to turn into ATT
error codes (bluetoothd: dbus_error_to_att_ecode).
"""
import logging

import dbus
import dbus.exceptions
import dbus.service

from . import model

log = logging.getLogger("gatt")

BLUEZ = "org.bluez"
DBUS_OM_IFACE = "org.freedesktop.DBus.ObjectManager"
DBUS_PROP_IFACE = "org.freedesktop.DBus.Properties"
GATT_MANAGER_IFACE = "org.bluez.GattManager1"
GATT_SERVICE_IFACE = "org.bluez.GattService1"
GATT_CHRC_IFACE = "org.bluez.GattCharacteristic1"


def uuid16(u):
    return f"0000{u:04x}-0000-1000-8000-00805f9b34fb"


def _bluez_error(name):
    return type(name, (dbus.exceptions.DBusException,),
                {"_dbus_error_name": f"org.bluez.Error.{name}"})


InvalidValueLength = _bluez_error("InvalidValueLength")
NotPermitted = _bluez_error("NotPermitted")
Failed = _bluez_error("Failed")


def att_error_to_dbus(err):
    """BlueZ can express only a few ATT errors over D-Bus.

    0x0D and 0x03 have a D-Bus name that maps straight to them. 0x13 (Value
    Not Allowed) and 0xFF (Out of Range) have none, so they go out as
    Failed — which bluetoothd sends as some other code. Which one reaches
    the phone is an open question this repo answers with a capture, not a
    guess: see the project README.
    """
    if err.code == model.AttError.INVALID_ATTRIBUTE_VALUE_LENGTH:
        return InvalidValueLength(err.reason)
    if err.code == model.AttError.WRITE_NOT_PERMITTED:
        return NotPermitted(err.reason)
    return Failed(f"wanted ATT 0x{err.code:02X}: {err.reason}")


class Application(dbus.service.Object):
    def __init__(self, bus):
        self.path = "/"
        self.services = []
        super().__init__(bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_service(self, service):
        self.services.append(service)

    @dbus.service.method(DBUS_OM_IFACE, out_signature="a{oa{sa{sv}}}")
    def GetManagedObjects(self):
        objects = {}
        for s in self.services:
            objects[s.get_path()] = s.get_properties()
            for c in s.characteristics:
                objects[c.get_path()] = c.get_properties()
        return objects


class Service(dbus.service.Object):
    def __init__(self, bus, index, uuid, primary=True):
        self.path = f"/org/bluez/blelab/service{index}"
        self.bus = bus
        self.uuid = uuid
        self.primary = primary
        self.characteristics = []
        super().__init__(bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def get_properties(self):
        return {GATT_SERVICE_IFACE: {
            "UUID": self.uuid,
            "Primary": self.primary,
            "Characteristics": dbus.Array([c.get_path() for c in self.characteristics],
                                          signature="o"),
        }}

    def add(self, chrc):
        self.characteristics.append(chrc)
        return chrc

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        return self.get_properties()[GATT_SERVICE_IFACE]


class Characteristic(dbus.service.Object):
    """One characteristic, backed by the device model under a model key."""

    def __init__(self, bus, service, index, uuid, flags, device, key, clock):
        self.path = f"{service.path}/char{index}"
        self.service = service
        self.uuid = uuid
        self.flags = flags
        self.device = device
        self.key = key
        self.clock = clock
        self.policy = None           # set for characteristics that notify
        super().__init__(bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def get_properties(self):
        return {GATT_CHRC_IFACE: {
            "Service": self.service.get_path(),
            "UUID": self.uuid,
            "Flags": dbus.Array(self.flags, signature="s"),
        }}

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        return self.get_properties()[GATT_CHRC_IFACE]

    @dbus.service.method(GATT_CHRC_IFACE, in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        value = self.device.read(self.key)
        log.info("read  %-10s -> %s   (from %s)", self._label(), value.hex(),
                 options.get("device", "?"))
        return dbus.Array(value, signature="y")

    @dbus.service.method(GATT_CHRC_IFACE, in_signature="aya{sv}")
    def WriteValue(self, value, options):
        data = bytes(value)
        try:
            self.device.write(self.key, data, now=self.clock())
        except model.AttError as err:
            log.warning("write %-10s <- %s   REFUSED %s", self._label(), data.hex(), err)
            raise att_error_to_dbus(err)
        log.info("write %-10s <- %s   ok", self._label(), data.hex())

    @dbus.service.method(GATT_CHRC_IFACE)
    def StartNotify(self):
        if self.policy is not None:
            self.policy.subscribe(True)
            log.info("notify %-10s subscribed", self._label())

    @dbus.service.method(GATT_CHRC_IFACE)
    def StopNotify(self):
        if self.policy is not None:
            self.policy.subscribe(False)
            log.info("notify %-10s unsubscribed", self._label())

    @dbus.service.signal(DBUS_PROP_IFACE, signature="sa{sv}as")
    def PropertiesChanged(self, interface, changed, invalidated):
        pass

    def notify(self, value):
        self.PropertiesChanged(GATT_CHRC_IFACE,
                               {"Value": dbus.Array(value, signature="y")}, [])
        log.info("notify %-10s -> %s", self._label(), value.hex())

    def _label(self):
        # Not "_name": dbus.service.Object.__init__ sets self._name to the
        # bus name (None here), which silently replaced a method of that name.
        # Every read then raised TypeError, and bluetoothd sent the phone
        # ATT error 0x0E, Unlikely Error.
        return {model.BATTERY_LEVEL: "battery", model.TEMPERATURE: "temp",
                model.SAMPLE_INTERVAL: "interval", model.IDENTIFY: "identify"}.get(self.key, "?")


def build_application(bus, device, clock):
    """Three services. Returns (app, {model key: Characteristic})."""
    app = Application(bus)
    chrcs = {}

    battery = Service(bus, 0, uuid16(model.BATTERY_SERVICE))
    c = battery.add(Characteristic(bus, battery, 0, uuid16(model.BATTERY_LEVEL),
                                   ["read", "notify"], device, model.BATTERY_LEVEL, clock))
    c.policy = device.battery_notify
    chrcs[model.BATTERY_LEVEL] = c
    app.add_service(battery)

    env = Service(bus, 1, uuid16(model.ENVIRONMENTAL_SENSING))
    c = env.add(Characteristic(bus, env, 0, uuid16(model.TEMPERATURE),
                               ["read", "notify"], device, model.TEMPERATURE, clock))
    c.policy = device.temperature_notify
    chrcs[model.TEMPERATURE] = c
    app.add_service(env)

    ctrl = Service(bus, 2, model.CONTROL_SERVICE)
    chrcs[model.SAMPLE_INTERVAL] = ctrl.add(Characteristic(
        bus, ctrl, 0, model.SAMPLE_INTERVAL, ["read", "write"],
        device, model.SAMPLE_INTERVAL, clock))
    # Writing Identify needs an encrypted link from a pairing with MITM
    # protection. BlueZ enforces that before WriteValue is ever called.
    chrcs[model.IDENTIFY] = ctrl.add(Characteristic(
        bus, ctrl, 1, model.IDENTIFY, ["encrypt-authenticated-write"],
        device, model.IDENTIFY, clock))
    app.add_service(ctrl)
    return app, chrcs
