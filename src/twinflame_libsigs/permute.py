"""Deterministic bit-permutations for the store's banding tables.

These permutations are the store's *own* index concern — they decide which shard
an entry lands in and nothing else. They are **not** required to match
twinflame's internal `LSHIndex` permutations; what must match twinflame is the
128-bit signature *content*, which the store guards via the recorded
`sig_stamp`. The seed used here is written into the header so the reader
reconstructs bit-identical permutations at query time.

The permutation is a full 128-bit shuffle. Table 0 is a spread of the whole
signature; further tables rotate which bits become the high-order prefix, so a
neighbour whose few differing bits fall in one table's prefix block still shares
another table's prefix (banding recall — see the storage design study).
"""

from __future__ import annotations

import random
from typing import List

from .layout import SIGNATURE_BITS


def gen_permutations(n: int, seed: int) -> List[List[int]]:
    if n <= 0:
        raise ValueError("n must be > 0")
    rng = random.Random(seed)
    perms: List[List[int]] = []
    for _ in range(n):
        p = list(range(SIGNATURE_BITS))
        rng.shuffle(p)
        perms.append(p)
    return perms


def apply_permutation(value: int, perm: List[int]) -> int:
    """Map bit `perm[i]` of `value` to bit `i` of the result."""
    out = 0
    for i, src in enumerate(perm):
        if (value >> src) & 1:
            out |= 1 << i
    return out
