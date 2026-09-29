"""Render an analysis as text, Markdown, or JSON — pseudonymised by default.

A report is meant to be shared, a capture is not. Addresses become keyed
hashes (addr.Pseudonymizer) and advertised names are withheld unless asked
for: a name like "Kitchen-Lamp-1A2B" is as identifying as the address.
"""
import json
from collections import Counter

from . import analyze
from . import addr as addrmod


def _mins(s):
    return f"{s / 60:.1f}"


class Report:
    def __init__(self, capture, pseudo, show_names=False):
        self.c = capture
        self.p = pseudo
        self.show_names = show_names
        self.tracks = analyze.build_tracks(capture)
        self.handoffs = analyze.find_handoffs(capture, self.tracks)
        self.links = analyze.concurrent_links(self.tracks)
        self.chains = analyze.chains(self.tracks, self.handoffs)
        self.findings = analyze.findings(capture, self.tracks, self.handoffs, self.links)
        self.rotation = analyze.rotation_stats(capture, self.tracks)

    def label(self, track):
        return self.p(track.addr_str, track.kind)

    def name(self, track):
        if not track.names:
            return ""
        n = track.names.most_common(1)[0][0]
        return n if self.show_names else f"<{len(n)} chars>"

    # ---- structured form: the JSON output, and what text/markdown render from
    def as_dict(self):
        c = self.c
        kinds = Counter(t.kind for t in self.tracks.values())
        return {
            "capture": {
                "packets": c.packets, "hci_events": c.events,
                "adv_reports": len(c.sightings), "malformed_events": c.malformed_events,
                "duration_s": round(c.t1 - c.t0, 1), "truncated": c.truncated,
                "subevents": {f"0x{k:02X}": v for k, v in sorted(c.subevents.items())},
                "extended_reports_with_legacy_bit": c.legacy_bit_reports,
            },
            "addresses": dict(sorted(kinds.items())),
            "rotation_lifetimes_min": {k: [round(x / 60, 1) for x in v]
                                       for k, v in sorted(self.rotation.items())},
            "chains": [{
                "addresses": [self.label(t) for t in seq],
                "span_min": round((seq[-1].last - seq[0].first) / 60, 1),
                "links": [h.strength for h in links],
            } for seq, links in self.chains],
            "findings": [{
                "rule": f.rule, "severity": f.severity,
                "subject": self.p(f.subject, f.kind),
                "message": f.message.format(related=self.p(*f.related)) if f.related
                else f.message,
            } for f in self.findings],
            "devices": [{
                "address": self.label(t), "kind": t.kind,
                "first_s": round(t.first - c.t0, 1), "last_s": round(t.last - c.t0, 1),
                "reports": t.n, "rssi_median": round(t.rssi_median),
                "adv_interval_ms": t.report_interval_ms,
                "name": self.name(t),
                "company_ids": sorted({f"0x{cid:04X}" for cid, _ in t.manufacturer}),
                "service_uuids": sorted({f"0x{u:04X}" for u, _ in t.service_data}
                                        | {f"0x{u:04X}" for u in t.uuid16}),
            } for t in sorted(self.tracks.values(), key=lambda t: (t.first, t.addr_str))],
        }

    def text(self, markdown=False):
        d = self.as_dict()
        cap = d["capture"]
        h = (lambda s: f"\n## {s}\n") if markdown else (lambda s: f"\n{s}\n{'-' * len(s)}")
        code = "```" if markdown else ""
        out = []
        out.append("# BLE advertising privacy report" if markdown else "BLE advertising privacy report")
        out.append(f"\n{cap['packets']} packets, {cap['hci_events']} HCI events, "
                   f"{cap['adv_reports']} advertising reports over {_mins(cap['duration_s'])} min"
                   + (" (capture file truncated)" if cap["truncated"] else ""))
        out.append(f"subevents: {cap['subevents']}; malformed events: {cap['malformed_events']}")
        out.append("addresses: " + ", ".join(f"{v} {k}" for k, v in d["addresses"].items()))

        out.append(h("Findings"))
        out.append(code)
        for f in d["findings"]:
            out.append(f"{f['rule']}  {f['severity']:<7}  {f['subject']:<14}  {f['message']}")
        if not d["findings"]:
            out.append("none")
        out.append(code)

        out.append(h("Linked addresses"))
        out.append("Addresses joined by handoffs: one device, several addresses, one trace.\n")
        out.append(code)
        for ch in d["chains"]:
            arrows = "".join(f" -{'=' if s == 'identical' else '?'}-> {a}"
                             for s, a in zip(ch["links"], ch["addresses"][1:]))
            out.append(f"{ch['span_min']:>5} min  {ch['addresses'][0]}{arrows}")
        if not d["chains"]:
            out.append("none")
        out.append(code)
        out.append("-=-> identical payload bytes on both sides;  -?-> same shape, "
                   "same RSSI, seconds apart")

        out.append(h("Address lifetimes (birth and death both observed)"))
        out.append(code)
        for k, v in d["rotation_lifetimes_min"].items():
            out.append(f"{k:<7} n={len(v):<3} min {min(v):5.1f}  median {v[len(v) // 2]:5.1f}  "
                       f"max {max(v):5.1f}  min")
        out.append(code)

        out.append(h("Devices"))
        out.append(code)
        out.append(f"{'address':<14} {'from':>6} {'to':>6} {'reports':>7} {'rssi':>5} "
                   f"{'ivl ms':>6}  ids")
        for t in d["devices"]:
            ids = " ".join(t["company_ids"] + t["service_uuids"])
            nm = f"  name {t['name']}" if t["name"] else ""
            out.append(f"{t['address']:<14} {_mins(t['first_s']):>6} {_mins(t['last_s']):>6} "
                       f"{t['reports']:>7} {t['rssi_median']:>5} "
                       f"{t['adv_interval_ms'] if t['adv_interval_ms'] else '-':>6}  {ids}{nm}")
        out.append(code)
        return "\n".join(line for line in out if line != "" or markdown) + "\n"

    def json(self):
        return json.dumps(self.as_dict(), indent=2) + "\n"


def render(capture, fmt="text", salt=None, show_addresses=False, show_names=False):
    r = Report(capture, addrmod.Pseudonymizer(salt, reveal=show_addresses), show_names)
    return {"text": lambda: r.text(False), "md": lambda: r.text(True), "json": r.json}[fmt]()
