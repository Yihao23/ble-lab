"""Run the peripheral: python3 -m peripheral [--seconds N]

Registers a GATT application and an advertisement with bluetoothd, then
samples the laptop's real battery and temperature on a timer and notifies
subscribed clients. Connect from nRF Connect (Android / iOS) to talk to it.
"""
import argparse
import logging
import sys
import time

import dbus
import dbus.mainloop.glib
from gi.repository import GLib

from . import model, sensors
from .advertisement import Advertisement
from .gatt_bluez import BLUEZ, GATT_MANAGER_IFACE, build_application, uuid16

log = logging.getLogger("peripheral")
ADAPTER_IFACE = "org.bluez.Adapter1"
AD_MANAGER_IFACE = "org.bluez.LEAdvertisingManager1"


def find_adapter(bus):
    om = dbus.Interface(bus.get_object(BLUEZ, "/"), "org.freedesktop.DBus.ObjectManager")
    for path, ifaces in om.GetManagedObjects().items():
        if GATT_MANAGER_IFACE in ifaces and AD_MANAGER_IFACE in ifaces:
            return path
    sys.exit("no adapter with GATT and advertising support")


def main():
    ap = argparse.ArgumentParser(description="BLE-Lab GATT peripheral on BlueZ")
    ap.add_argument("--name", default="BLE-Lab")
    ap.add_argument("--seconds", type=float, default=0,
                    help="stop after this long (0 = run until Ctrl-C)")
    ap.add_argument("--thermal-zone", default=None,
                    help="thermal zone type to report, e.g. SEN1 (default: first zone)")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)-10s %(message)s",
                        datefmt="%H:%M:%S")

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    adapter_path = find_adapter(bus)
    obj = bus.get_object(BLUEZ, adapter_path)
    gatt_manager = dbus.Interface(obj, GATT_MANAGER_IFACE)
    ad_manager = dbus.Interface(obj, AD_MANAGER_IFACE)

    clock = time.monotonic
    device = model.Device()
    device.update_sensors(sensors.battery_percent(), sensors.temperature_mdeg(args.thermal_zone))
    app, chrcs = build_application(bus, device, clock)
    adv = Advertisement(bus, args.name, [uuid16(model.BATTERY_SERVICE),
                                         uuid16(model.ENVIRONMENTAL_SENSING)])
    loop = GLib.MainLoop()

    def registered(what):
        return lambda: log.info("%s registered with bluetoothd", what)

    def failed(what):
        def handler(error):
            log.error("%s registration failed: %s", what, error)
            loop.quit()
        return handler

    gatt_manager.RegisterApplication(app.get_path(), {},
                                     reply_handler=registered("GATT application"),
                                     error_handler=failed("GATT application"))
    ad_manager.RegisterAdvertisement(adv.get_path(), {},
                                     reply_handler=registered("advertisement"),
                                     error_handler=failed("advertisement"))

    def tick():
        now = clock()
        device.update_sensors(sensors.battery_percent(),
                              sensors.temperature_mdeg(args.thermal_zone))
        for key, value in device.due_notifications(now):
            chrcs[key].notify(value)
        if device.identifying(now):
            log.info("identify: *blink*")
        GLib.timeout_add(device.sample_interval_ms, tick)   # interval may have changed
        return False

    GLib.timeout_add(device.sample_interval_ms, tick)
    if args.seconds:
        GLib.timeout_add(int(args.seconds * 1000), loop.quit)

    log.info("battery %s%%, temperature %s mdegC, adapter %s",
             device.battery_percent, device.temperature_mdeg, adapter_path)
    try:
        loop.run()
    except KeyboardInterrupt:
        pass
    finally:
        for call, path in ((ad_manager.UnregisterAdvertisement, adv.get_path()),
                           (gatt_manager.UnregisterApplication, app.get_path())):
            try:
                call(path)
            except dbus.DBusException:
                pass
        log.info("unregistered, bye")


if __name__ == "__main__":
    main()
