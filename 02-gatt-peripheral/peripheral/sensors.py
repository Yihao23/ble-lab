"""Real readings from the laptop this peripheral runs on.

The Battery Service reports the machine's actual battery; the temperature is
a real thermal zone. Both come from sysfs as integers (percent, and
millidegrees Celsius), and stay integers all the way into the GATT value.
"""
from pathlib import Path

POWER = Path("/sys/class/power_supply")
THERMAL = Path("/sys/class/thermal")


def battery_percent():
    for bat in sorted(POWER.glob("BAT*")):
        try:
            return int((bat / "capacity").read_text().strip())
        except (OSError, ValueError):
            continue
    return None


def list_thermal_zones():
    zones = []
    for z in sorted(THERMAL.glob("thermal_zone*")):
        try:
            zones.append((z.name, (z / "type").read_text().strip()))
        except OSError:
            continue
    return zones


def temperature_mdeg(zone_type=None):
    """Millidegrees from the first zone whose type matches, or the first zone."""
    for z in sorted(THERMAL.glob("thermal_zone*")):
        try:
            if zone_type and (z / "type").read_text().strip() != zone_type:
                continue
            return int((z / "temp").read_text().strip())
        except (OSError, ValueError):
            continue
    return None
