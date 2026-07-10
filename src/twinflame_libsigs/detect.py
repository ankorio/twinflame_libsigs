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
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .strings import StringAnchorIndex

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
    __slots__ = ("_sig_store", "_strings", "_radius")

    def __init__(self, sig_store, strings: StringAnchorIndex, radius: int):
        self._sig_store = sig_store
        self._strings = strings
        self._radius = radius

    @classmethod
    def build(
        cls,
        entries: Iterable[Tuple[int, int, Sequence[str]]],
        *,
        radius: int = 8,
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
