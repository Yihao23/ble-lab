"""python -m bleprivacy CAPTURE.pcapng [--format text|md|json] [-o FILE]"""
import argparse
import sys

from . import analyze, report, rpa


def main(argv=None):
    ap = argparse.ArgumentParser(prog="bleprivacy",
                                 description="Address-rotation and linkability audit of a "
                                             "Linux btmon/bluetooth-monitor capture.")
    ap.add_argument("capture", help="pcapng or pcap, link type 254 (Bluetooth Linux monitor)")
    ap.add_argument("--format", choices=("text", "md", "json"), default="text")
    ap.add_argument("-o", "--output", help="write here instead of stdout")
    ap.add_argument("--salt", help="pseudonym key; the same salt gives the same labels "
                                   "across runs (default: random per run)")
    ap.add_argument("--show-addresses", action="store_true",
                    help="print real addresses (do not publish the result)")
    ap.add_argument("--show-names", action="store_true",
                    help="print advertised names (do not publish the result)")
    ap.add_argument("--irk", action="append", default=[], metavar="HEX",
                    help="Identity Resolving Key, 32 hex digits, MSB first; lists which "
                         "RPAs in the capture resolve with it (repeatable)")
    a = ap.parse_args(argv)

    cap = analyze.load(a.capture)
    text = report.render(cap, a.format, a.salt, a.show_addresses, a.show_names)

    if a.irk:
        tracks = analyze.build_tracks(cap)
        lines = ["", "IRK resolution"]
        for hexkey in a.irk:
            irk = bytes.fromhex(hexkey)
            if len(irk) != 16:
                ap.error(f"--irk must be 16 bytes, got {len(irk)}")
            hits = [t for t in tracks.values()
                    if t.kind == "rpa" and rpa.resolves(irk, t.addr)]
            lines.append(f"  {hexkey[:4]}..: {len(hits)} of "
                         f"{sum(t.kind == 'rpa' for t in tracks.values())} RPAs resolve")
            for t in sorted(hits, key=lambda t: t.first):
                lines.append(f"    {t.addr_str if a.show_addresses else 'rpa'}  "
                             f"{(t.first - cap.t0) / 60:5.1f}-{(t.last - cap.t0) / 60:5.1f} min")
        if a.format != "json":
            text += "\n".join(lines) + "\n"
        else:
            print("\n".join(lines), file=sys.stderr)

    if a.output:
        with open(a.output, "w") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
