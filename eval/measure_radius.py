"""Measure the Hamming-distance distribution between two obfuscated builds of the
same class — the measurement that unblocks the store's radius, plus the Charikar
analytical cross-check (radius ↔ cosine similarity).

Method (twinflame's free-oracle trick, reused): given two builds of one app, each
with its R8 `mapping.txt`, join the maps on the *original* class name to pair
"the same class, built two ways" — then histogram the Hamming distance between
their 128-bit structural signatures. The signature is name-free, so what this
captures is the drift R8 *optimization/shrinking* induces, which is exactly the
"pristine library class vs the app's embedded copy" drift the store must tolerate.

Split by app-vs-library (by original package) because library classes are what
the store actually indexes.

Usage:
    python -m eval.measure_radius \
        --build lax=corpus/records/contacts__1.5.0__lax.tfr:corpus/oss_matrix/contacts/1.5.0/lax/mapping.txt \
        --build strict=corpus/records/contacts__1.5.0__strict.tfr:corpus/oss_matrix/contacts/1.5.0/strict/mapping.txt \
        --pair lax strict
"""

from __future__ import annotations

import argparse
import math
from collections import Counter
from pathlib import Path
from typing import Dict, Iterator, Optional, Tuple

from twinflame.prepare import load_record

# Original-name (dotted) prefixes that mark bundled third-party library code —
# the classes the store will hold. Kept local so the harness depends only on
# twinflame.load_record.
LIBRARY_PREFIXES = (
    "android.", "androidx.", "com.google.", "kotlin.", "kotlinx.",
    "java.", "javax.", "org.jetbrains.", "dagger.", "okhttp3.", "okio.",
    "retrofit2.", "com.squareup.", "io.reactivex.", "org.apache.",
)

_SYNTHETIC_MARKERS = ("$$ExternalSynthetic", "$$Lambda$")
_REMOVED_MARKER = "R8$$REMOVED"


def parse_class_mapping(text: str) -> Dict[str, str]:
    """`{original_fqcn: obfuscated_fqcn}` from a ProGuard mapping.txt (class lines
    only). Mirrors twinflame's eval/mapping.parse_class_mapping."""
    out: Dict[str, str] = {}
    for raw in text.splitlines():
        if not raw or raw[0].isspace():
            continue
        line = raw.strip()
        if line.startswith("#") or not line.endswith(":"):
            continue
        original, sep, obf = line[:-1].partition(" -> ")
        if sep and original.strip() and obf.strip():
            out[original.strip()] = obf.strip()
    return out


def _fqcn(cls) -> str:
    return f"{cls.package}.{cls.name}" if cls.package else cls.name


def _is_library(original_fqcn: str) -> bool:
    return original_fqcn.startswith(LIBRARY_PREFIXES)


def _is_synthetic(original_fqcn: str) -> bool:
    return any(m in original_fqcn for m in _SYNTHETIC_MARKERS)


def load_pairs(
    rec_x: str, map_x: str, rec_y: str, map_y: str,
) -> Iterator[Tuple[str, int, int]]:
    """Yield (original_fqcn, sig_x, sig_y) for classes present, with a signature,
    in both builds — joined on original name via the two mappings."""
    mx = parse_class_mapping(Path(map_x).read_text())
    my = parse_class_mapping(Path(map_y).read_text())
    by_x = {_fqcn(c): c for c in load_record(rec_x).classes}
    by_y = {_fqcn(c): c for c in load_record(rec_y).classes}
    for original, ox in mx.items():
        oy = my.get(original)
        if oy is None:
            continue
        if _REMOVED_MARKER in ox or _REMOVED_MARKER in oy or _is_synthetic(original):
            continue
        cx, cy = by_x.get(ox), by_y.get(oy)
        if cx is None or cy is None or cx.signature is None or cy.signature is None:
            continue
        yield original, cx.signature.combined, cy.signature.combined


def histogram(pairs: Iterator[Tuple[str, int, int]]
              ) -> Tuple[Counter, Counter, Counter]:
    """Return (all, library-only, app-only) Hamming-distance histograms."""
    h_all: Counter = Counter()
    h_lib: Counter = Counter()
    h_app: Counter = Counter()
    for original, sx, sy in pairs:
        d = (sx ^ sy).bit_count()
        h_all[d] += 1
        (h_lib if _is_library(original) else h_app)[d] += 1
    return h_all, h_lib, h_app


def _percentile(h: Counter, pct: float) -> Optional[int]:
    total = sum(h.values())
    if not total:
        return None
    cum = 0
    for d in range(max(h) + 1):
        cum += h.get(d, 0)
        if cum / total >= pct:
            return d
    return max(h)


def _cosine_for_radius(r: int, bits: int = 128) -> float:
    """Charikar: expected Hamming = (theta/pi)*bits, so theta = pi*r/bits and
    cosine = cos(theta). The similarity R=r implies."""
    return math.cos(math.pi * r / bits)


def report(label: str, h: Counter) -> None:
    total = sum(h.values())
    print(f"\n=== {label}: {total} class pairs ===")
    if not total:
        print("  (none)")
        return
    for pct in (0.50, 0.90, 0.95, 0.99):
        r = _percentile(h, pct)
        print(f"  p{int(pct * 100):<2} Hamming = {r:<3}  "
              f"(implied cosine sim ≈ {_cosine_for_radius(r):.3f})")
    # compact histogram
    print("  distribution (Hamming -> count):")
    cum = 0
    for d in range(max(h) + 1):
        c = h.get(d, 0)
        if c == 0:
            continue
        cum += c
        bar = "#" * min(40, 40 * c // max(h.values()))
        print(f"    {d:3d} {c:7d} {cum/total:6.1%} {bar}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--build", action="append", metavar="NAME=REC:MAP", required=True,
                   help="a named build: NAME=record.tfr:mapping.txt (repeatable)")
    p.add_argument("--pair", nargs=2, action="append", metavar=("X", "Y"),
                   required=True, help="measure drift between builds X and Y (repeatable)")
    args = p.parse_args(argv)

    builds: Dict[str, Tuple[str, str]] = {}
    for spec in args.build:
        name, _, rest = spec.partition("=")
        rec, _, mp = rest.partition(":")
        builds[name] = (rec, mp)

    grand_all: Counter = Counter()
    grand_lib: Counter = Counter()
    for x, y in args.pair:
        rec_x, map_x = builds[x]
        rec_y, map_y = builds[y]
        h_all, h_lib, h_app = histogram(load_pairs(rec_x, map_x, rec_y, map_y))
        print(f"\n########## {x}  vs  {y} ##########")
        report("all classes", h_all)
        report("library classes", h_lib)
        report("app classes", h_app)
        grand_all.update(h_all)
        grand_lib.update(h_lib)

    if len(args.pair) > 1:
        print("\n########## AGGREGATE ##########")
        report("all pairs, all classes", grand_all)
        report("all pairs, library classes", grand_lib)

    # The store's actionable number: the radius that captures 95% of library
    # classes, and whether that lands in the cheap exact-MIH regime.
    r95 = _percentile(grand_lib if sum(grand_lib.values()) else grand_all, 0.95)
    if r95 is not None:
        regime = ("exact pigeonhole/MIH, cheap" if r95 <= 6
                  else "MIH still fine" if r95 <= 14 else "wide — banding territory")
        print(f"\n>>> library-class p95 Hamming = {r95} "
              f"(cosine ≈ {_cosine_for_radius(r95):.3f}) -> store radius regime: {regime}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
