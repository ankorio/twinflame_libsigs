"""Version-range dedup — collapse a library's version history into distinct
class signatures, each tagged with the version range(s) it appears in.

Interface only for now; the collapse logic is trivial (group by (coord, sig),
merge the contributing versions into ranges), but the *inputs* depend on the
scraper/prepare pipeline that isn't built yet, so this stays a documented seam.
See the version-range dedup design.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Tuple


@dataclass
class ClassSig:
    coord: str          # "group:artifact"
    version: str        # the version this signature was observed in
    signature: int      # twinflame 128-bit combined signature


@dataclass
class DedupedEntry:
    coord: str
    signature: int
    versions: List[str] = field(default_factory=list)   # collapsed later to ranges


def dedup_by_signature(sigs: Iterable[ClassSig]) -> List[DedupedEntry]:
    """Collapse identical (coord, signature) across versions into one entry that
    records every version the signature appeared in. Range-compaction of the
    version list is a downstream formatting step (needs the coordinate's version
    order, which the scraper knows)."""
    table: Dict[Tuple[str, int], DedupedEntry] = {}
    for cs in sigs:
        key = (cs.coord, cs.signature)
        e = table.get(key)
        if e is None:
            e = table[key] = DedupedEntry(coord=cs.coord, signature=cs.signature)
        e.versions.append(cs.version)
    return list(table.values())


def assign_payload_ids(entries: Iterable[DedupedEntry]
                       ) -> Tuple[List[Tuple[int, int]], dict]:
    """Turn deduped entries into the builder's (signature, payload_id) stream
    plus the id -> metadata sidecar dict. One payload id per (coord, signature).
    """
    build_stream: List[Tuple[int, int]] = []
    sidecar: dict = {}
    for pid, e in enumerate(entries):
        build_stream.append((e.signature, pid))
        sidecar[str(pid)] = {"coord": e.coord, "versions": sorted(set(e.versions))}
    return build_stream, sidecar
