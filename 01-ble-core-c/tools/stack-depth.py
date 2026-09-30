#!/usr/bin/env python3
"""Worst-case stack depth of every function, along the call graph GCC emitted.

A .su file gives each function's own frame. That is not what a caller needs:
calling ble_rpa_resolve_any also puts ble_rpa_resolve, ble_ah and the AES on
the stack, one above the other. This adds the frames up along the deepest
path, using the call graph from -fcallgraph-info=su (.ci files) — the graph
after inlining, which is the one that runs, not the one in the source.

    tools/size-cortex-m.sh          # writes build/cortex-m/<cpu>/*.ci
    tools/stack-depth.py            # every cpu found there

Not included: interrupts. An ISR that fires at the deepest point stacks its
own frame on top, plus what the core pushes on exception entry: 32 bytes,
more on a Cortex-M4F with floating-point context to save. Also not
included: compiler-runtime helpers such as __aeabi_uidivmod, which GCC
inserts after the call graph is written, so they never appear in it.
size-cortex-m.sh lists them.

Exits 1 if any chain reaches a function with no known frame (a libc call the
compiler emitted, say) or recursion, since then there is no bound to report.
"""
import pathlib
import re
import sys

NODE = re.compile(r'node: \{ title: "([^"]+)" label: "([^"]*)"')
EDGE = re.compile(r'edge: \{ sourcename: "([^"]+)" targetname: "([^"]+)"')
FRAME = re.compile(r'\\n(\d+) bytes \((\w+)')


def load(directory):
    """Frames by function and callees by function, merged across .ci files."""
    frame, kind, calls = {}, {}, {}
    for ci in sorted(directory.glob("*.ci")):
        text = ci.read_text()
        for title, label in NODE.findall(text):
            m = FRAME.search(label)
            if m:                                   # defined in this file
                frame[title] = int(m.group(1))
                kind[title] = m.group(2)
            calls.setdefault(title, set())
        for src, dst in EDGE.findall(text):
            calls.setdefault(src, set()).add(dst)
    return frame, kind, calls


def deepest(fn, frame, calls, memo, active):
    """(bytes, path) of the deepest chain from fn; bytes is None if unbounded."""
    if fn in memo:
        return memo[fn]
    if fn in active:                                # recursion: no static bound
        return None, [fn, "(recursion)"]
    if fn not in frame:                             # defined outside the library
        return None, [fn, "(unknown frame)"]
    active.add(fn)
    best = (0, [])
    for callee in sorted(calls.get(fn, ())):
        size, path = deepest(callee, frame, calls, memo, active)
        if size is None:
            best = (None, path)
            break
        if size > best[0]:
            best = (size, path)
    active.discard(fn)
    size = None if best[0] is None else frame[fn] + best[0]
    memo[fn] = (size, [fn] + best[1])
    return memo[fn]


def short(name):
    return name.split(":")[-1]                      # "src/ble_aes.c:ble_copy" -> "ble_copy"


def report(directory):
    frame, kind, calls = load(directory)
    memo, problems = {}, 0
    public = sorted(f for f in frame if ":" not in f)   # static functions are file-qualified
    rows = []
    for fn in public:
        size, path = deepest(fn, frame, calls, memo, set())
        rows.append((size, fn, path))
        if size is None or kind[fn] != "static":
            problems += 1
    rows.sort(key=lambda r: (r[0] is not None, r[0] or 0), reverse=True)

    print(f"== {directory.name}: worst-case stack of each public function ==")
    for size, fn, path in rows:
        chain = " -> ".join(f"{short(p)} ({frame[p]})" if p in frame else p for p in path)
        print(f"{'UNBOUNDED' if size is None else size:>9}  {chain}")
    return problems


def main(argv):
    root = pathlib.Path(__file__).resolve().parents[1] / "build" / "cortex-m"
    dirs = [pathlib.Path(a) for a in argv[1:]] or sorted(p for p in root.iterdir() if p.is_dir())
    if not dirs:
        sys.exit(f"no call graphs under {root}: run tools/size-cortex-m.sh first")
    problems = 0
    for d in dirs:
        problems += report(d)
        print()
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
