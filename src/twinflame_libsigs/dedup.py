"""Version-range dedup — collapse a library's version history into distinct
class signatures, each tagged with the version range(s) it appears in.

Adjacent library versions share the overwhelming majority of their classes, so
storing "versions x classes" would multiply N for no discrimination gain. The
collapse groups by (coord, signature) and records which sampled versions each
signature was seen in; `compact_ranges` then renders those hits as contiguous
ranges *relative to the sampled version order* (contiguity against versions we
never scraped would be a claim we can't back).

Range syntax: "1.2.0..1.4.1" (inclusive, both ends sampled), a bare version for
a singleton. `..` because a hyphen is ambiguous inside real version strings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Sequence, Tuple


@dataclass(frozen=True)
class ClassSig:
    coord: str                    # "group:artifact"
    version: str                  # the version this signature was observed in
    signature: int                # twinflame 128-bit combined signature
    fqcn: str = ""                # class name in this version (metadata only)
    strings: Tuple[str, ...] = () # class string constants (Tier-3 anchors)
    instructions: int = 0         # total instruction count (min-instr filter)


@dataclass
class DedupedEntry:
    coord: str
    signature: int
    versions: List[str] = field(default_factory=list)
    fqcn: str = ""                # from the first observation (rename-stable
                                  # within a signature-identical group in practice)
    strings: Tuple[str, ...] = ()
    instructions: int = 0


def dedup_by_signature(sigs: Iterable[ClassSig]) -> List[DedupedEntry]:
    """Collapse identical (coord, signature) across versions into one entry that
    records every version the signature appeared in. Metadata (fqcn, strings,
    instruction count) is taken from the first observation — entries in the
    same group are structurally identical, so any representative serves."""
    table: Dict[Tuple[str, int], DedupedEntry] = {}
    for cs in sigs:
        key = (cs.coord, cs.signature)
        e = table.get(key)
        if e is None:
            e = table[key] = DedupedEntry(
                coord=cs.coord, signature=cs.signature, fqcn=cs.fqcn,
                strings=cs.strings, instructions=cs.instructions)
        if cs.version not in e.versions:
            e.versions.append(cs.version)
    return list(table.values())


def compact_ranges(versions: Sequence[str], order: Sequence[str]) -> List[str]:
    """Render the versions a signature was seen in as inclusive ranges over the
    coordinate's *sampled* version order. `order` is every sampled version of
    the coordinate, oldest first; `versions` is the subset this entry hit.
    Versions not in `order` (shouldn't happen, but a stale cache could) are
    kept as singletons at the end rather than dropped."""
    pos = {v: i for i, v in enumerate(order)}
    known = sorted((v for v in versions if v in pos), key=pos.__getitem__)
    stray = sorted(v for v in versions if v not in pos)
    out: List[str] = []
    i = 0
    while i < len(known):
        j = i
        while j + 1 < len(known) and pos[known[j + 1]] == pos[known[j]] + 1:
            j += 1
        out.append(known[i] if i == j else f"{known[i]}..{known[j]}")
        i = j + 1
    return out + stray


def assign_payload_ids(
    entries: Sequence[DedupedEntry],
    version_order: Dict[str, Sequence[str]],
) -> Tuple[List[Tuple[int, int, Tuple[str, ...]]], dict]:
    """Turn deduped entries into the detector-build stream plus the sidecar.

    Returns (`build_stream`, `sidecar`):
      build_stream — [(payload_id, signature, strings)] as `LibraryDetector.build`
                     expects;
      sidecar      — payload_id (str, for JSON) -> {coord, ranges, fqcn}, the
                     metadata a hit resolves to (`library:<coord>@<range>`).

    `version_order` maps coord -> its sampled versions, oldest first (the
    scraper's sampling order; rebuildable by sorting scraped versions).
    """
    build_stream: List[Tuple[int, int, Tuple[str, ...]]] = []
    sidecar: dict = {}
    for pid, e in enumerate(entries):
        build_stream.append((pid, e.signature, e.strings))
        sidecar[str(pid)] = {
            "coord": e.coord,
            "ranges": compact_ranges(e.versions, version_order.get(e.coord, ())),
            "fqcn": e.fqcn,
        }
    return build_stream, sidecar
