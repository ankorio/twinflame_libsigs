"""Radius clustering of 128-bit signatures over the exact Hamming store.

`cluster_by_radius` groups signatures that are *transitively* within a small
Hamming radius of each other (single-linkage): one exact MIH store is built
over every signature, each signature is unioned with its radius neighbours,
and the union-find components come out as index groups. Callers that need a
per-group representative (medoid, mode, ...) pick it themselves — this module
is signatures-in, index-groups-out, with nothing library- or family-specific.

Single-linkage means a chain a~b~c ends up in one group even when
d(a, c) > radius; that is the wanted semantics for "the same class drifting
a few bits across builds", and the reason callers should keep the radius
conservative (chains amplify a generous one).
"""
from __future__ import annotations

import sys
from typing import List, Sequence

from .detect import _BruteStore

try:  # native exact multi-index Hamming store
    import tfls_mih  # type: ignore
    _HAVE_NATIVE = True
except ImportError:  # pragma: no cover - exercised only without the wheel
    _HAVE_NATIVE = False

# Above this many signatures the O(n^2) brute fallback stops being "a moment";
# warn rather than refuse (correctness is identical, only time differs).
_BRUTE_WARN_THRESHOLD = 20_000


class UnionFind:
    """Disjoint sets over 0..n-1: path-halving find, union by size."""

    def __init__(self, n: int):
        self._parent = list(range(n))
        self._size = [1] * n

    def find(self, i: int) -> int:
        parent = self._parent
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self._size[ra] < self._size[rb]:
            ra, rb = rb, ra
        self._parent[rb] = ra
        self._size[ra] += self._size[rb]

    def groups(self) -> List[List[int]]:
        """Members of each set, grouped by root, in first-seen order."""
        by_root: dict[int, List[int]] = {}
        for i in range(len(self._parent)):
            by_root.setdefault(self.find(i), []).append(i)
        return list(by_root.values())


def cluster_by_radius(sigs: Sequence[int], *, radius: int) -> List[List[int]]:
    """Single-linkage groups of indices into `sigs` whose signatures are
    transitively within `radius` Hamming bits. Duplicate signature values are
    distinct indices and merge at distance 0. `radius=0` is exact grouping."""
    n = len(sigs)
    if n == 0:
        return []
    entries = [(sig, i) for i, sig in enumerate(sigs)]
    if _HAVE_NATIVE:
        # max(6, ...) guards the smallest-store case: m<6 gives >24-bit
        # substrings the native build rejects (same guard as detect.build).
        m = max(6, tfls_mih.suggest_m(n))
        store = tfls_mih.MihStore.build(entries, m)
    else:
        if n > _BRUTE_WARN_THRESHOLD:
            print(f"cluster_by_radius: tfls_mih not installed; brute-force "
                  f"pass over {n:,} signatures will be slow", file=sys.stderr)
        store = _BruteStore(entries)
    uf = UnionFind(n)
    for i, sig in enumerate(sigs):
        for j, _dist in store.query_with_dist(sig, radius):
            uf.union(i, j)
    return uf.groups()
