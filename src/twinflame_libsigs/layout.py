"""On-disk layout for a `.tfls` library-signature store — the format shared by
the builder (`build.py`) and the memory-mapped reader (`store.py`).

The store is an **immutable, memory-mapped, prefix-directory + sorted-pool**
file — the concrete realisation of the "rainbow table" idea: precompute a
direct index from a signature's high-order prefix bits to the on-disk shard that
holds its near-neighbours, so a query is an O(1) array index into the directory
followed by a short bounded scan, with **no per-run index build and no parse**.

Layout (single file, little-endian throughout)::

    [ header            : HEADER_SIZE bytes                    ]
    [ directory table 0 : (2**prefix_bits + 1) * u64          ]
    [ directory table 1 : ...                                 ]
    ...                  (n_tables directories)
    [ entries table 0   : n_entries * ENTRY_SIZE bytes        ]
    [ entries table 1   : ...                                 ]
    ...                  (n_tables entry pools)

Each of the `n_tables` tables is the *same* set of N entries, reordered by a
distinct bit-permutation of the 128-bit signature (multi-table banding — see
the storage design). Within a table, entries are grouped
(counting-sorted) by the `prefix_bits` high bits of their *permuted* signature;
`directory[prefix]` is the start offset (in entry units) of that prefix's shard
and `directory[prefix+1]` its end, so the shard is the half-open entry range
`[directory[prefix], directory[prefix+1])`.

An entry is `ENTRY_SIZE` bytes: the **original** (un-permuted) 128-bit signature
as 16 LE bytes, followed by a `PAYLOAD_BYTES`-byte payload id. Hamming distance
is always evaluated on the original signature; the permutation only decides
which shard an entry lands in. Payload ids index a separate metadata sidecar
(`<store>.idx.json`: id -> coordinate + version-range + record digest); the
binary store deliberately holds ids only, so the hot path never touches strings.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

MAGIC = b"TFLS"          # twinflame library signatures
FORMAT_VERSION = 1

SIGNATURE_BITS = 128
SIGNATURE_BYTES = SIGNATURE_BITS // 8     # 16
PAYLOAD_BYTES = 8                         # u64 payload id
ENTRY_SIZE = SIGNATURE_BYTES + PAYLOAD_BYTES   # 24

# Fixed header. Keep every field 8-byte friendly and leave reserved room so the
# format can grow without moving the section offsets' arithmetic.
#   magic(4) ver(u16) flags(u16) prefix_bits(u32) n_tables(u32)
#   seed(u64) n_entries(u64) sig_stamp(16 ascii) reserved(...)
_HEAD = struct.Struct("<4s H H I I Q Q 16s")
HEADER_SIZE = 128
assert _HEAD.size <= HEADER_SIZE


@dataclass(frozen=True)
class Header:
    prefix_bits: int
    n_tables: int
    seed: int
    n_entries: int
    sig_stamp: str          # twinflame SIGNATURE_STAMP the sigs were computed under
    flags: int = 0
    format_version: int = FORMAT_VERSION

    def pack(self) -> bytes:
        raw = _HEAD.pack(
            MAGIC, self.format_version, self.flags,
            self.prefix_bits, self.n_tables, self.seed, self.n_entries,
            self.sig_stamp.encode("ascii")[:16].ljust(16, b"\0"),
        )
        return raw.ljust(HEADER_SIZE, b"\0")

    @classmethod
    def unpack(cls, buf) -> "Header":
        magic, ver, flags, prefix_bits, n_tables, seed, n_entries, stamp = \
            _HEAD.unpack_from(buf, 0)
        if magic != MAGIC:
            raise ValueError(f"not a .tfls store (magic {magic!r})")
        if ver != FORMAT_VERSION:
            raise ValueError(f"unsupported .tfls format version {ver}")
        return cls(
            prefix_bits=prefix_bits, n_tables=n_tables, seed=seed,
            n_entries=n_entries, sig_stamp=stamp.rstrip(b"\0").decode("ascii"),
            flags=flags, format_version=ver,
        )


# --- section offset arithmetic (identical in builder and reader) ---------------

def directory_len(prefix_bits: int) -> int:
    """Number of u64 slots in one table's prefix directory."""
    return (1 << prefix_bits) + 1


def directory_offset(h: Header, table: int) -> int:
    return HEADER_SIZE + table * directory_len(h.prefix_bits) * 8


def entries_base(h: Header) -> int:
    return HEADER_SIZE + h.n_tables * directory_len(h.prefix_bits) * 8


def entries_offset(h: Header, table: int) -> int:
    return entries_base(h) + table * h.n_entries * ENTRY_SIZE


def total_size(h: Header) -> int:
    return entries_offset(h, h.n_tables)


def prefix_of(permuted: int, prefix_bits: int) -> int:
    return permuted >> (SIGNATURE_BITS - prefix_bits)
