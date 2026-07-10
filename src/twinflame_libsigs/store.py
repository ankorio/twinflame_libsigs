"""Memory-mapped reader for a `.tfls` library-signature store — the query hot
path used *inside* a twinflame diff/score run.

    NOTE: this is the original *prototype* (approximate LSH banding). The
    production store is the exact native Multi-Index Hashing implementation in
    `../../native/` (Rust + pyo3 module `tfls_mih`), which is both exact and
    faster at twinflame's R=12 — see the MIH storage design. This module is kept as
    the design reference and for the on-disk prefix-directory format study.

Opening the store maps the file; there is no parse and no index build. A query
is, per table: permute the query signature, index the prefix directory to get
the shard's byte range (O(1), the "rainbow-table" lookup), then scan that shard
computing true Hamming distance on the original signatures. Candidates within
the radius are unioned across tables and returned as payload ids.

    with LibSigStore.open("android.tfls") as store:
        store.verify_stamp(twinflame_signature_stamp)   # refuse a stale store
        for cls in app.classes:
            hits = store.query(compute_signature(cls).combined, k=4)
            if hits:
                mark_library(cls, hits)

The store holds payload ids only; resolve them against the `.idx.json` sidecar
for coordinate / version-range metadata.
"""

from __future__ import annotations

import mmap
from pathlib import Path
from typing import Dict, Iterator, List, Set

from . import layout
from .layout import ENTRY_SIZE, Header, SIGNATURE_BYTES
from .permute import apply_permutation, gen_permutations


class StaleStoreError(RuntimeError):
    """The store's signatures were computed under a different twinflame
    signature algorithm than the caller is running — Hamming distances between
    them are meaningless. Rebuild the store (offline) before querying."""


class LibSigStore:
    __slots__ = ("_header", "_mm", "_perms", "_shift", "_dir_base", "_ent_base")

    def __init__(self, header: Header, mm: mmap.mmap) -> None:
        self._header = header
        self._mm = mm
        self._perms = gen_permutations(header.n_tables, header.seed)
        self._shift = layout.SIGNATURE_BITS - header.prefix_bits
        self._dir_base = [layout.directory_offset(header, t)
                          for t in range(header.n_tables)]
        self._ent_base = [layout.entries_offset(header, t)
                          for t in range(header.n_tables)]

    # --- lifecycle ------------------------------------------------------------

    @classmethod
    def open(cls, path: str | Path) -> "LibSigStore":
        f = open(path, "rb")
        try:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        finally:
            f.close()   # mmap keeps its own handle to the mapping
        header = Header.unpack(mm)
        expected = layout.total_size(header)
        if len(mm) < expected:
            raise ValueError(
                f"truncated store: {len(mm)} bytes, header implies {expected}")
        return cls(header, mm)

    def close(self) -> None:
        self._mm.close()

    def __enter__(self) -> "LibSigStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def header(self) -> Header:
        return self._header

    def verify_stamp(self, sig_stamp: str) -> None:
        if self._header.sig_stamp != sig_stamp:
            raise StaleStoreError(
                f"store built under signature stamp {self._header.sig_stamp!r}, "
                f"caller runs {sig_stamp!r}")

    # --- query ----------------------------------------------------------------

    def query(self, sig: int, k: int, probe_bits: int = 0) -> Set[int]:
        """Payload ids whose signature is within Hamming distance `k` of `sig`.

        `probe_bits` optionally also scans prefixes within Hamming distance
        `probe_bits` of the query prefix (per table), recovering neighbours
        whose differing bits flipped the prefix into an adjacent shard. Default
        0 (exact shard only); banding across tables is the primary recall lever.
        """
        hits: Set[int] = set()
        pbits = self._header.prefix_bits
        for t, perm in enumerate(self._perms):
            prefix = apply_permutation(sig, perm) >> self._shift
            for probe in _probe_prefixes(prefix, pbits, probe_bits):
                self._scan_shard(t, probe, sig, k, hits)
        return hits

    def query_best(self, sig: int, k: int, probe_bits: int = 0) -> Dict[int, int]:
        """Like `query` but returns {payload_id: min Hamming distance} — useful
        when the caller wants the closest library version, not just presence."""
        best: Dict[int, int] = {}
        pbits = self._header.prefix_bits
        for t, perm in enumerate(self._perms):
            prefix = apply_permutation(sig, perm) >> self._shift
            for probe in _probe_prefixes(prefix, pbits, probe_bits):
                for payload, dist in self._scan_shard_dist(t, probe, sig, k):
                    if payload not in best or dist < best[payload]:
                        best[payload] = dist
        return best

    def _shard_range(self, table: int, prefix: int) -> tuple[int, int]:
        base = self._dir_base[table]
        lo = int.from_bytes(self._mm[base + prefix * 8: base + prefix * 8 + 8],
                            "little")
        hi = int.from_bytes(self._mm[base + (prefix + 1) * 8:
                                     base + (prefix + 1) * 8 + 8], "little")
        return lo, hi

    def _scan_shard(self, table: int, prefix: int, sig: int, k: int,
                    out: Set[int]) -> None:
        lo, hi = self._shard_range(table, prefix)
        ent = self._ent_base[table]
        mm = self._mm
        pos = ent + lo * ENTRY_SIZE
        end = ent + hi * ENTRY_SIZE
        while pos < end:
            cand = int.from_bytes(mm[pos: pos + SIGNATURE_BYTES], "little")
            if (cand ^ sig).bit_count() <= k:
                out.add(int.from_bytes(
                    mm[pos + SIGNATURE_BYTES: pos + ENTRY_SIZE], "little"))
            pos += ENTRY_SIZE

    def _scan_shard_dist(self, table: int, prefix: int, sig: int, k: int
                         ) -> Iterator[tuple[int, int]]:
        lo, hi = self._shard_range(table, prefix)
        ent = self._ent_base[table]
        mm = self._mm
        pos = ent + lo * ENTRY_SIZE
        end = ent + hi * ENTRY_SIZE
        while pos < end:
            cand = int.from_bytes(mm[pos: pos + SIGNATURE_BYTES], "little")
            dist = (cand ^ sig).bit_count()
            if dist <= k:
                payload = int.from_bytes(
                    mm[pos + SIGNATURE_BYTES: pos + ENTRY_SIZE], "little")
                yield payload, dist
            pos += ENTRY_SIZE


def _probe_prefixes(prefix: int, prefix_bits: int, radius: int
                    ) -> Iterator[int]:
    yield prefix
    if radius >= 1:
        for i in range(prefix_bits):
            yield prefix ^ (1 << i)
        if radius >= 2:
            for i in range(prefix_bits):
                for j in range(i + 1, prefix_bits):
                    yield prefix ^ (1 << i) ^ (1 << j)
