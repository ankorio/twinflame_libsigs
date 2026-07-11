"""LibraryDetector — tie the signature store and string-anchor index together
into the tiered lookup the radius measurement argued for.

For each app class, in order of confidence:

  Tier 1  exact signature (Hamming 0)   — ~half of library classes, zero-FP, free
  Tier 2  signature within a radius      — most of the rest, exact via MIH
  Tier 3  distinctive shared string      — the wide-drift tail signatures miss
                                            (Project Zero: strings beat hashing)

A hit resolves to a payload id → the caller's metadata (library coordinate +
version range, or here just the library class's original name).

Uses the native MIH store (`tfls_mih`) when built; falls back to a brute-force
signature scan otherwise, so the detector is usable without the Rust toolchain.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .strings import StringAnchorIndex

# The corpus-validated operating point (findings: radius 4 + min-instr 20 ->
# P 0.83 / R 0.65, all three tiers contributing). Radius is applied here at
# query time; the min-instr filter is applied when the pack is *built*.
DEFAULT_RADIUS = 4

try:  # native exact multi-index Hamming store
    import tfls_mih  # type: ignore
    _HAVE_NATIVE = True
except ImportError:  # pragma: no cover - exercised only without the wheel
    _HAVE_NATIVE = False


@dataclass(frozen=True)
class Detection:
    payload_id: int
    tier: int          # 1 exact, 2 signature-radius, 3 string anchor
    distance: int      # Hamming distance (tiers 1–2); -1 for a string hit
    score: float       # string evidence (tier 3); 1.0 for an exact signature


class _BruteStore:
    """Fallback exact Hamming store when the native module isn't built."""

    def __init__(self, entries: Sequence[Tuple[int, int]]):
        self._entries = list(entries)  # (sig, payload_id)

    def query_with_dist(self, sig: int, r: int) -> List[Tuple[int, int]]:
        return [(pid, d) for s, pid in self._entries
                if (d := (s ^ sig).bit_count()) <= r]


class LibraryDetector:
    __slots__ = ("_sig_store", "_strings", "_radius", "_payloads")

    def __init__(self, sig_store, strings: StringAnchorIndex, radius: int,
                 payloads: Optional[Dict[str, dict]] = None):
        self._sig_store = sig_store
        self._strings = strings
        self._radius = radius
        self._payloads = payloads or {}

    @classmethod
    def build(
        cls,
        entries: Iterable[Tuple[int, int, Sequence[str]]],
        *,
        radius: int = DEFAULT_RADIUS,
    ) -> "LibraryDetector":
        """`entries` = (payload_id, signature, class strings)."""
        sig_entries: List[Tuple[int, int]] = []
        str_entries: List[Tuple[int, Sequence[str]]] = []
        for pid, sig, strings in entries:
            sig_entries.append((sig, pid))
            str_entries.append((pid, strings))
        if _HAVE_NATIVE:
            # max(6, ...) guards the smallest-store case: m<6 gives >24-bit
            # substrings the native build rejects.
            m = max(6, tfls_mih.suggest_m(len(sig_entries) or 1))
            sig_store = tfls_mih.MihStore.build(sig_entries, m)
        else:
            sig_store = _BruteStore(sig_entries)
        return cls(sig_store, StringAnchorIndex.build(str_entries), radius)

    @classmethod
    def from_pack(
        cls,
        path: str | Path,
        *,
        radius: int = DEFAULT_RADIUS,
        expect_stamp: Optional[str] = None,
    ) -> "LibraryDetector":
        """Load a catalogue pack (`pack.py`) and build the in-memory stores.
        Pass twinflame's current `SIGNATURE_STAMP` as `expect_stamp` to refuse
        a stale pack (`StaleStoreError`) instead of mismatched distances."""
        from .pack import read_pack
        entries, payloads, _ = read_pack(path, expect_stamp=expect_stamp)
        det = cls.build(entries, radius=radius)
        det._payloads = payloads
        return det

    def resolve(self, d: Detection) -> Optional[dict]:
        """Sidecar metadata for a detection: {coord, ranges, fqcn}; None when
        the detector was built without a pack sidecar."""
        return self._payloads.get(str(d.payload_id))

    def label(self, d: Detection) -> str:
        """Provenance label for a detection: `library:<coord>@<ranges>`, or a
        bare payload reference when no sidecar is loaded."""
        m = self.resolve(d)
        if m is None:
            return f"library:payload/{d.payload_id}"
        ranges = ",".join(m.get("ranges", ())) or "?"
        return f"library:{m['coord']}@{ranges}"

    def detect(self, sig: int, strings: Sequence[str]) -> Optional[Detection]:
        """Best library match for one app class, tried tier by tier."""
        # Tier 1 + 2: closest signature within the radius.
        hits = self._sig_store.query_with_dist(sig, self._radius)
        if hits:
            pid, dist = min(hits, key=lambda t: t[1])
            tier = 1 if dist == 0 else 2
            return Detection(payload_id=pid, tier=tier, distance=dist, score=1.0)
        # Tier 3: distinctive shared string.
        s = self._strings.query(strings)
        if s:
            pid, score = s[0]
            return Detection(payload_id=pid, tier=3, distance=-1, score=score)
        return None

    @property
    def native(self) -> bool:
        return _HAVE_NATIVE
