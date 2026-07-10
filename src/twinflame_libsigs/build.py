"""Build an immutable `.tfls` store from library class signatures.

This is the *offline* side: it runs once per catalogue refresh, is allowed to be
slow, and produces a memory-mappable file the tool then queries in microseconds.
Given an iterable of `(signature:int, payload_id:int)` it:

  1. materialises the distinct entries (dedup is the caller's job — see
     `dedup.py`; the builder assumes the ids it is handed are already the
     version-range-collapsed set),
  2. for each of `n_tables` bit-permutations, counting-sorts the entries by the
     `prefix_bits` high bits of their permuted signature and writes the
     prefix directory + entry pool,
  3. stamps the header with the twinflame `sig_stamp` and permutation seed.

The pure-Python permutation apply is O(128) per entry per table; at millions of
entries this is the build's cost centre and the obvious first target for a
vectorised/native rewrite. It is deliberately simple here — correctness first,
and the build is not on the query hot path.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

from . import layout
from .layout import ENTRY_SIZE, Header, SIGNATURE_BYTES
from .permute import apply_permutation, gen_permutations

Entry = Tuple[int, int]   # (signature, payload_id)

DEFAULT_N_TABLES = 6
DEFAULT_PREFIX_BITS = 18
DEFAULT_SEED = 0xA9C1D


def build_store(
    entries: Iterable[Entry],
    path: str | Path,
    *,
    sig_stamp: str,
    n_tables: int = DEFAULT_N_TABLES,
    prefix_bits: int = DEFAULT_PREFIX_BITS,
    seed: int = DEFAULT_SEED,
) -> Header:
    """Write a `.tfls` store to `path`; return the header that describes it."""
    ents: List[Entry] = list(entries)
    n = len(ents)
    h = Header(prefix_bits=prefix_bits, n_tables=n_tables, seed=seed,
               n_entries=n, sig_stamp=sig_stamp)
    perms = gen_permutations(n_tables, seed)
    n_buckets = 1 << prefix_bits

    path = Path(path)
    with open(path, "wb") as f:
        f.write(h.pack())

        # Directories first (all n_tables), then the entry pools — matches the
        # offset arithmetic in layout.py. We compute both per table in one pass
        # and stage the entry pools in memory-order to write after the
        # directories. For very large N this staging is the memory ceiling; a
        # streaming two-pass writer is the scale-up path (the storage design study).
        directories: List[bytes] = []
        pools: List[bytes] = []
        for perm in perms:
            order, dir_offsets = _counting_sort_by_prefix(
                ents, perm, prefix_bits, n_buckets)
            directories.append(
                struct.pack(f"<{n_buckets + 1}Q", *dir_offsets))
            pools.append(_pack_pool(ents, order))

        for d in directories:
            f.write(d)
        for p in pools:
            f.write(p)

    return h


def _counting_sort_by_prefix(
    ents: Sequence[Entry], perm: List[int], prefix_bits: int, n_buckets: int,
) -> Tuple[List[int], List[int]]:
    """Return (entry order, directory offsets) grouping entries by permuted
    prefix. `order[j]` is the index into `ents` of the j-th entry in shard
    order; `offsets[b]` is the first position of prefix `b` (offsets has
    n_buckets+1 entries, offsets[-1] == len)."""
    shift = layout.SIGNATURE_BITS - prefix_bits
    counts = [0] * (n_buckets + 1)
    prefixes = [0] * len(ents)
    for i, (sig, _payload) in enumerate(ents):
        pfx = apply_permutation(sig, perm) >> shift
        prefixes[i] = pfx
        counts[pfx + 1] += 1
    for b in range(1, n_buckets + 1):
        counts[b] += counts[b - 1]
    offsets = counts[:]                      # copy: directory = prefix -> start
    order = [0] * len(ents)
    cursor = counts[:]
    for i in range(len(ents)):
        pfx = prefixes[i]
        order[cursor[pfx]] = i
        cursor[pfx] += 1
    return order, offsets


def _pack_pool(ents: Sequence[Entry], order: Sequence[int]) -> bytes:
    buf = bytearray(len(order) * ENTRY_SIZE)
    off = 0
    for j in order:
        sig, payload = ents[j]
        buf[off:off + SIGNATURE_BYTES] = sig.to_bytes(SIGNATURE_BYTES, "little")
        off += SIGNATURE_BYTES
        buf[off:off + layout.PAYLOAD_BYTES] = payload.to_bytes(
            layout.PAYLOAD_BYTES, "little")
        off += layout.PAYLOAD_BYTES
    return bytes(buf)
