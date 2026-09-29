"""Hold an LE discovery session open on the local adapter for N seconds.

BlueZ only scans while some D-Bus client holds a discovery session, and it
stops the moment that client disconnects. dumpcap on `bluetooth-monitor` sees
the HCI traffic, but something has to keep the radio listening. This is that
something, and nothing more: it records no data itself.

DuplicateData=True turns off the controller's duplicate filter, so every
advertisement is reported rather than one per address. Rotation analysis in
project 04 needs the repeats: an address lifetime is first-seen to last-seen.

Usage:  python3 discovery_hold.py --seconds 1800
"""
import argparse
import sys

import dbus
import dbus.mainloop.glib
from gi.repository import GLib

BLUEZ = "org.bluez"
ADAPTER_IFACE = "org.bluez.Adapter1"


def find_adapter(bus):
    om = dbus.Interface(bus.get_object(BLUEZ, "/"), "org.freedesktop.DBus.ObjectManager")
    for path, ifaces in om.GetManagedObjects().items():
        if ADAPTER_IFACE in ifaces:
            return path
    sys.exit("no Bluetooth adapter found on D-Bus")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seconds", type=int, default=600)
    args = ap.parse_args()

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    path = find_adapter(bus)
    adapter = dbus.Interface(bus.get_object(BLUEZ, path), ADAPTER_IFACE)

    adapter.SetDiscoveryFilter({
        "Transport": dbus.String("le"),
        "DuplicateData": dbus.Boolean(True),
    })
    adapter.StartDiscovery()
    print(f"discovering on {path} for {args.seconds}s", flush=True)

    loop = GLib.MainLoop()

    def stop():
        try:
            adapter.StopDiscovery()
        except dbus.DBusException:
            pass
        loop.quit()
        return False

    GLib.timeout_add_seconds(args.seconds, stop)
    try:
        loop.run()
    except KeyboardInterrupt:
        stop()
    print("discovery stopped", flush=True)


if __name__ == "__main__":
    main()
