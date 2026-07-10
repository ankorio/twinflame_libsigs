"""String-anchor index — the fast path that complements signature lookup.

The radius measurement found a wide tail of library classes whose signature drifts
>12 bits under R8, and Project Zero's statically-linked-vuln work found string
matching beats structural hashing
in ~90% of real cases. R8 renames identifiers but *cannot rewrite the content of
a string constant* — a class name literal, log tag, URL, or error message a
library class carries survives into the app verbatim. So a distinctive string
shared between an app class and a library class is strong, rename-invariant
evidence they are the same class, independent of how far the signature moved.

This index is deliberately Python, not native: string lookup is a dict hit
(already fast), there are far fewer distinctive strings than signature probes,
and keeping it out of the MIH store avoids pushing string data across the FFI.
It is IDF-weighted exactly like twinflame's own `anchor.py`, so a string held by
one library class is worth far more than one held by hundreds.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Sequence, Tuple

# Strings shorter than this, or purely numeric, carry too little signal — same
# thresholds as twinflame's anchor stage.
MIN_STRING_LEN = 4
# A string held by more than this many library classes is boilerplate/shared
# runtime noise (e.g. "UTF-8", "Android"); it is dropped as non-distinctive so
# it can neither bloat the index nor mint weak matches.
MAX_DOC_FREQUENCY = 8
# Minimum accumulated IDF evidence for a (app-class -> library-class) string hit
# to be reported. ~1.0 = roughly "one reasonably distinctive shared string".
DEFAULT_MIN_SCORE = 1.0


def useful_strings(strings: Iterable[str]) -> set[str]:
    return {s for s in strings if len(s) >= MIN_STRING_LEN and not s.isdigit()}


class StringAnchorIndex:
    """Maps a distinctive library string -> the payload ids (library classes)
    that contain it, with per-string IDF weights. Built offline alongside the
    signature store; queried per app class."""

    __slots__ = ("_by_string", "_idf", "_n")

    def __init__(self, by_string: Dict[str, Tuple[int, ...]],
                 idf: Dict[str, float], n: int) -> None:
        self._by_string = by_string
        self._idf = idf
        self._n = n

    @classmethod
    def build(cls, entries: Iterable[Tuple[int, Sequence[str]]]) -> "StringAnchorIndex":
        """`entries` = (payload_id, class strings). Keeps only distinctive strings
        (length/­numeric filtered, document frequency <= MAX_DOC_FREQUENCY)."""
        postings: Dict[str, List[int]] = defaultdict(list)
        n = 0
        for payload_id, strings in entries:
            n += 1
            for s in useful_strings(strings):
                postings[s].append(payload_id)
        by_string: Dict[str, Tuple[int, ...]] = {}
        idf: Dict[str, float] = {}
        norm = math.log(n + 1) or 1.0
        for s, ids in postings.items():
            if len(ids) > MAX_DOC_FREQUENCY:
                continue  # non-distinctive shared-runtime string
            by_string[s] = tuple(ids)
            idf[s] = math.log((n + 1) / len(ids)) / norm  # in (0, 1]
        return cls(by_string, idf, n)

    def __len__(self) -> int:
        return len(self._by_string)

    def query(self, app_strings: Iterable[str], *,
              min_score: float = DEFAULT_MIN_SCORE) -> List[Tuple[int, float]]:
        """Library payload ids sharing distinctive strings with an app class,
        as (payload_id, score) sorted best-first. Score is the summed IDF of the
        shared distinctive strings."""
        scores: Counter = Counter()
        for s in useful_strings(app_strings):
            ids = self._by_string.get(s)
            if ids is None:
                continue
            w = self._idf[s]
            for pid in ids:
                scores[pid] += w
        return sorted(
            ((pid, sc) for pid, sc in scores.items() if sc >= min_score),
            key=lambda t: (-t[1], t[0]),
        )

    def best(self, app_strings: Iterable[str], *,
             min_score: float = DEFAULT_MIN_SCORE) -> int | None:
        """The single best-matching library payload id, or None."""
        hits = self.query(app_strings, min_score=min_score)
        return hits[0][0] if hits else None
