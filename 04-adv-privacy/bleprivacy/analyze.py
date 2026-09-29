"""From HCI captures to address tracks, rotations, and privacy findings.

The question (Lecture 10): a device rotates its address so an observer cannot
link its sightings into a trace. Does the rotation hold? It fails if anything
else in the packet stays constant across the change — the same bytes are an
identifier just as much as the same address. It also fails, more weakly, if
the old address stops and a new one with the same shape starts at the same
signal strength a second later: that is the timing-and-space reasoning
CrossLink uses across protocols, applied inside one.
"""
from collections import Counter
from dataclasses import dataclass, field
from statistics import median

from . import ad as admod
from . import addr as addrmod
from . import hci, monitor, pcapng

MAX_HANDOFF_GAP_S = 10.0     # old address gone, new one appears within this ...
HANDOFF_GAP_INTERVALS = 2.5   # ... or within 2.5 advertising intervals, if that is longer
EDGE_MARGIN_S = 30.0          # ignore "appeared"/"vanished" this close to capture ends
RSSI_TOLERANCE_DB = 8.0
MIN_IDENTIFIER_BYTES = 6      # shorter payloads are too likely to collide by chance
MIN_DISTINCT_BYTE_VALUES = 4  # 01 00 00 .. 80 00 is a bitmap, not a fingerprint
MIN_ROTATION_S = 60.0         # shorter-lived addresses are bursts, not rotation periods
LIMITED_DISCOVERABLE_MAX_S = 180.0   # TGAP(lim_adv_timeout), Core Vol 3 Part C App. A


@dataclass
class Sighting:
    t: float
    frame: int
    addr: bytes
    addr_str: str
    addr_type: int
    kind: str
    rssi: int
    evt_type: int
    ad: admod.ParsedAD

    @property
    def scan_rsp(self):
        return bool(self.evt_type & hci.EXT_SCAN_RSP)


@dataclass
class Capture:
    sightings: list
    t0: float
    t1: float
    packets: int = 0
    events: int = 0
    malformed_events: int = 0
    legacy_bit_reports: int = 0
    subevents: Counter = field(default_factory=Counter)
    truncated: bool = False


def load(path):
    reader = pcapng.Reader(path)
    sightings, packets, events, malformed = [], 0, 0, 0
    subevents, legacy_bit = Counter(), 0
    t0 = t1 = None
    for pk in reader:
        packets += 1
        if pk.ts is not None:
            t0 = pk.ts if t0 is None else t0
            t1 = pk.ts
        if pk.linktype != pcapng.LINKTYPE_BLUETOOTH_LINUX_MONITOR:
            continue
        _, op, payload = monitor.split(pk.data)
        if op != monitor.EVENT_PKT:
            continue
        events += 1
        try:
            reports = hci.parse_adv_reports(payload)
        except hci.MalformedEvent:
            malformed += 1
            continue
        if reports:
            subevents[payload[2]] += 1
        for r in reports:
            if r.addr_type == 0xFF:                  # anonymous advertising: no address
                continue
            legacy_bit += bool(r.evt_type & hci.EXT_LEGACY) and not r.from_legacy_event
            sightings.append(Sighting(pk.ts, pk.frame, r.addr, r.addr_str, r.addr_type,
                                      addrmod.kind(r.addr_type, r.addr), r.rssi,
                                      r.evt_type, admod.parse(r.data)))
    return Capture(sightings, t0 or 0.0, t1 or 0.0, packets, events, malformed,
                   legacy_bit, subevents, reader.truncated)


@dataclass
class Track:
    """Everything heard from one address."""
    addr_str: str
    addr: bytes
    kind: str
    first: float = None
    last: float = None
    n: int = 0
    rssi: list = field(default_factory=list)
    names: Counter = field(default_factory=Counter)
    manufacturer: Counter = field(default_factory=Counter)     # (cid, payload)
    service_data: Counter = field(default_factory=Counter)     # (uuid, payload)
    appearance: set = field(default_factory=set)
    uuid16: set = field(default_factory=set)
    ad_types: set = field(default_factory=set)
    evt_types: Counter = field(default_factory=Counter)
    limited_first: float = None
    limited_last: float = None
    adv_times: list = field(default_factory=list)
    malformed_ad: int = 0

    def add(self, s):
        self.first = s.t if self.first is None else self.first
        self.last = s.t
        self.n += 1
        self.rssi.append(s.rssi)
        self.evt_types[s.evt_type] += 1
        a = s.ad
        self.malformed_ad += a.malformed
        self.ad_types.add(a.types)
        if a.name:
            self.names[a.name] += 1
        for cid, pl in a.manufacturer.items():
            self.manufacturer[(cid, pl)] += 1
        for uuid, pl in a.service_data.items():
            self.service_data[(uuid, pl)] += 1
        if a.appearance is not None:
            self.appearance.add(a.appearance)
        self.uuid16 |= a.uuid16
        if a.flags is not None and a.flags & admod.FLAG_LE_LIMITED:
            self.limited_first = s.t if self.limited_first is None else self.limited_first
            self.limited_last = s.t
        if not s.scan_rsp:
            self.adv_times.append(s.t)

    @property
    def lifetime(self):
        return self.last - self.first

    @property
    def rssi_median(self):
        return median(self.rssi)

    @property
    def report_interval_ms(self):
        t = self.adv_times
        gaps = [b - a for a, b in zip(t, t[1:]) if b > a]
        return round(median(gaps) * 1000) if gaps else None

    def _payloads(self):
        yield from (("manufacturer", cid, pl) for cid, pl in self.manufacturer)
        yield from (("service_data", u, pl) for u, pl in self.service_data)

    def identifiers(self):
        """Byte-level identifiers: any one shared across a rotation links it.

        (field, key, bytes). A payload counts only if it could plausibly be
        unique to one device: long enough, and not mostly one repeated value.
        """
        out = {("name", None, n.encode()) for n in self.names}
        out |= {p for p in self._payloads() if looks_unique(p[2])}
        return out

    def shape(self):
        """What kind of device this is, without anything that identifies which one.

        Payload lengths are format, not identity, so they belong here; so do
        whole payloads too low-entropy to identify anything (status bitmaps).
        """
        return (self.kind,
                frozenset((f, k, len(pl)) for f, k, pl in self._payloads()),
                frozenset(p for p in self._payloads() if not looks_unique(p[2])),
                frozenset(self.appearance), frozenset(self.uuid16),
                frozenset(self.ad_types), frozenset(self.evt_types))


def looks_unique(payload):
    return (len(payload) >= MIN_IDENTIFIER_BYTES
            and len(set(payload)) >= MIN_DISTINCT_BYTE_VALUES)


def shared_identifiers(a, b):
    """Identifiers of a and b that match exactly, or where one payload begins
    with the whole of the other (a device repeating its legacy payload at the
    front of a longer extended one)."""
    out = set()
    for fa, ka, va in a.identifiers():
        for fb, kb, vb in b.identifiers():
            if fa == fb and ka == kb and (va.startswith(vb) or vb.startswith(va)):
                out.add((fa, ka, min(va, vb, key=len)))
    return out


def build_tracks(capture):
    tracks = {}
    for s in capture.sightings:
        t = tracks.get(s.addr_str)
        if t is None:
            t = tracks[s.addr_str] = Track(s.addr_str, s.addr, s.kind)
        t.add(s)
    return tracks


@dataclass
class Handoff:
    old: Track
    new: Track
    gap_s: float
    shared: set             # identifiers present in both; empty for a probable link
    rssi_delta_db: float

    @property
    def strength(self):
        return "identical" if self.shared else "probable"


def find_handoffs(capture, tracks):
    """Pair each vanished random address with the one that replaced it.

    Static addresses are included: the spec lets them change only at power
    cycle, but some devices rotate them on a timer, and the capture decides.
    """
    rand = [t for t in tracks.values() if t.kind != addrmod.PUBLIC]
    vanished = [t for t in rand if t.last < capture.t1 - EDGE_MARGIN_S]
    appeared = [t for t in rand if t.first > capture.t0 + EDGE_MARGIN_S]

    candidates = []
    for old in vanished:
        for new in appeared:
            gap = new.first - old.last
            ivl = (old.report_interval_ms or 0) / 1000
            if not 0 <= gap <= max(MAX_HANDOFF_GAP_S, HANDOFF_GAP_INTERVALS * ivl):
                continue
            if old.shape() != new.shape():
                continue
            shared = shared_identifiers(old, new)
            drssi = abs(old.rssi_median - new.rssi_median)
            if shared or drssi <= RSSI_TOLERANCE_DB:
                candidates.append(Handoff(old, new, gap, shared, drssi))

    # Each address has at most one predecessor and one successor. Strongest first.
    candidates.sort(key=lambda h: (not h.shared, h.gap_s, h.rssi_delta_db))
    used_old, used_new, chosen = set(), set(), []
    for h in candidates:
        if h.old.addr_str in used_old or h.new.addr_str in used_new:
            continue
        used_old.add(h.old.addr_str)
        used_new.add(h.new.addr_str)
        chosen.append(h)
    return chosen


def concurrent_links(tracks):
    """Pairs of random addresses on air at the same time that share an identifier:
    one device running two advertising sets, each with its own address."""
    rand = sorted((t for t in tracks.values() if t.kind != addrmod.PUBLIC),
                  key=lambda t: t.first)
    out = []
    for i, a in enumerate(rand):
        for b in rand[i + 1:]:
            if b.first > a.last:
                break
            shared = shared_identifiers(a, b)
            if shared:
                out.append((a, b, shared))
    return out


def chains(tracks, handoffs):
    """Follow handoffs into per-device address sequences."""
    nxt = {h.old.addr_str: h for h in handoffs}
    has_prev = {h.new.addr_str for h in handoffs}
    out = []
    for a, t in tracks.items():
        if a in has_prev or a not in nxt:
            continue
        seq, links, cur = [t], [], a
        while cur in nxt:
            h = nxt[cur]
            links.append(h)
            seq.append(h.new)
            cur = h.new.addr_str
        out.append((seq, links))
    out.sort(key=lambda c: -len(c[0]))
    return out


@dataclass
class Finding:
    rule: str
    severity: str           # error > warning > info
    subject: str            # address, pseudonymised by the reporter
    kind: str
    message: str
    related: tuple = None   # (address, kind) of the other side, if any


SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}


def _addr_hex_in_name(track):
    """Does the advertised name spell out part of the device's own address?"""
    tail = [f"{track.addr[1]:02X}{track.addr[0]:02X}", f"{track.addr[0]:02X}{track.addr[1]:02X}"]
    for name in track.names:
        up = name.upper().replace(":", "").replace("-", "")
        for frag in tail:
            if frag in up:
                return name, frag
    return None


def findings(capture, tracks, handoffs, links=()):
    out = []
    span = capture.t1 - capture.t0

    for t in tracks.values():
        mins = t.lifetime / 60
        if t.kind == addrmod.PUBLIC and t.lifetime >= 60:
            out.append(Finding("P001", "warning", t.addr_str, t.kind,
                               f"public address, heard for {mins:.1f} of {span / 60:.1f} min: "
                               f"trackable wherever it goes, it never changes"))
        elif t.kind == addrmod.STATIC and t.lifetime >= 600:
            out.append(Finding("P002", "info", t.addr_str, t.kind,
                               f"random static address unchanged for {mins:.1f} min"))
        hit = _addr_hex_in_name(t)
        if hit:
            name, frag = hit
            out.append(Finding("P003", "warning", t.addr_str, t.kind,
                               f"advertised name ({len(name)} chars) contains the last two "
                               f"bytes of the device's own address"))
        if (t.kind == addrmod.RPA and t.lifetime > 20 * 60):
            out.append(Finding("P006", "info", t.addr_str, t.kind,
                               f"RPA did not rotate for {mins:.1f} min "
                               f"(Lecture 10 measured 7-20 min on phones)"))
        if t.limited_first is not None:
            held = t.limited_last - t.limited_first
            if held > LIMITED_DISCOVERABLE_MAX_S:
                out.append(Finding("S001", "warning", t.addr_str, t.kind,
                                   f"advertised LE Limited Discoverable for {held / 60:.1f} min; "
                                   f"the spec caps it at {LIMITED_DISCOVERABLE_MAX_S:.0f} s "
                                   f"(TGAP(lim_adv_timeout))"))
        if t.kind == addrmod.RESERVED:
            out.append(Finding("S002", "error", t.addr_str, t.kind,
                               "random address with reserved top bits 10: not valid in any spec"))
        if t.malformed_ad:
            out.append(Finding("S003", "warning", t.addr_str, t.kind,
                               f"{t.malformed_ad} reports with malformed AD structures"))

    for h in handoffs:
        if h.shared:
            what = sorted({f[0] for f in h.shared})
            out.append(Finding("P004", "error", h.old.addr_str, h.old.kind,
                               f"rotation defeated: new address appeared {h.gap_s:.1f} s later "
                               f"carrying identical {', '.join(what)} bytes"))
        else:
            out.append(Finding("P005", "warning", h.old.addr_str, h.old.kind,
                               f"probable handoff: same device shape reappeared {h.gap_s:.1f} s "
                               f"later at RSSI within {h.rssi_delta_db:.0f} dB"))
    for a, b, shared in links:
        what = sorted({f[0] for f in shared})
        out.append(Finding("P007", "warning", a.addr_str, a.kind,
                           f"on air at the same time as {{related}}, carrying the same "
                           f"{', '.join(what)} bytes: two advertising sets, one device",
                           (b.addr_str, b.kind)))
    out.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.rule, f.subject))
    return out


def rotation_stats(capture, tracks):
    """{kind: sorted lifetimes} for random addresses whose birth and death were
    both observed. A lower bound on the rotation period: the device may have
    been out of range for part of it."""
    out = {}
    for t in tracks.values():
        if (t.kind != addrmod.PUBLIC
                and t.first > capture.t0 + EDGE_MARGIN_S
                and t.last < capture.t1 - EDGE_MARGIN_S
                and t.lifetime >= MIN_ROTATION_S):
            out.setdefault(t.kind, []).append(t.lifetime)
    return {k: sorted(v) for k, v in out.items()}
