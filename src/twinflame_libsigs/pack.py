"""The catalogue pack — the shippable asset the detector loads at run start.

A pack is what the offline pipeline (scrape -> dedup -> min-instr filter)
produces and what a twinflame run consumes. It is two files:

    <name>.tflp       binary: header + per-payload (signature, strings), in
                      payload-id order (the id IS the record index)
    <name>.idx.json   sidecar: payload id -> {coord, ranges, fqcn} + build meta

The pack deliberately stores the *inputs* to the detector, not the built MIH
tables: the native MIH build is sub-second at the design point (see the
benchmark in findings), so persisting its layout would buy microseconds of
startup at the cost of coupling the asset format to the native internals.
`LibraryDetector.from_pack` is therefore: read, verify stamp, build in memory.

Staleness: the header carries twinflame's `SIGNATURE_STAMP`; loading with a
different current stamp raises `StaleStoreError` (Hamming distances between
different signature algorithms are meaningless). The fix is an offline rebuild
from the scrape cache — `.sigs.json` files carry their stamp too, so the
scraper knows exactly which versions to redo.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .store import StaleStoreError

PACK_MAGIC = b"TFLP"
PACK_FORMAT = 1
SIGNATURE_BYTES = 16

# entries = what LibraryDetector.build takes: (payload_id, signature, strings)
Entry = Tuple[int, int, Tuple[str, ...]]


def sidecar_path(pack: str | Path) -> Path:
    p = Path(pack)
    return p.with_name(p.stem + ".idx.json")


def write_pack(
    path: str | Path,
    entries: Sequence[Entry],
    sidecar: dict,
    *,
    sig_stamp: str,
    meta: Optional[dict] = None,
) -> None:
    """`entries` must be in payload-id order with ids 0..n-1 (what
    `dedup.assign_payload_ids` emits); the record index encodes the id."""
    path = Path(path)
    stamp_b = sig_stamp.encode()
    with open(path, "wb") as f:
        f.write(PACK_MAGIC)
        f.write(struct.pack("<IIQ", PACK_FORMAT, len(stamp_b), len(entries)))
        f.write(stamp_b)
        for i, (pid, sig, strings) in enumerate(entries):
            if pid != i:
                raise ValueError(f"entries must be dense in payload-id order (got id {pid} at index {i})")
            f.write(sig.to_bytes(SIGNATURE_BYTES, "little"))
            # DEX strings are MUTF-8: lone UTF-16 surrogates are legal there
            # but not in strict UTF-8, so pass them through symmetrically.
            enc = [s.encode("utf-8", "surrogatepass") for s in strings]
            f.write(struct.pack("<I", len(enc)))
            for b in enc:
                f.write(struct.pack("<I", len(b)))
                f.write(b)
    doc = {"format": PACK_FORMAT, "sig_stamp": sig_stamp,
           "n_entries": len(entries), "meta": meta or {}, "payloads": sidecar}
    sidecar_path(path).write_text(json.dumps(doc))


def read_pack(
    path: str | Path, *, expect_stamp: Optional[str] = None,
) -> Tuple[List[Entry], Dict[str, dict], str]:
    """Returns (entries, payload sidecar, pack's sig_stamp). If `expect_stamp`
    is given (twinflame's current SIGNATURE_STAMP), a mismatch raises
    `StaleStoreError` instead of returning meaningless distances."""
    path = Path(path)
    data = path.read_bytes()
    if data[:4] != PACK_MAGIC:
        raise ValueError(f"{path}: not a .tflp pack (bad magic)")
    fmt, stamp_len, n = struct.unpack_from("<IIQ", data, 4)
    if fmt != PACK_FORMAT:
        raise ValueError(f"{path}: pack format v{fmt}, reader supports v{PACK_FORMAT}")
    off = 4 + 16
    sig_stamp = data[off:off + stamp_len].decode()
    off += stamp_len
    if expect_stamp is not None and sig_stamp != expect_stamp:
        raise StaleStoreError(
            f"pack was built for signature stamp {sig_stamp!r}, current is "
            f"{expect_stamp!r}; rebuild the pack from the scrape cache")
    entries: List[Entry] = []
    for pid in range(n):
        sig = int.from_bytes(data[off:off + SIGNATURE_BYTES], "little")
        off += SIGNATURE_BYTES
        (n_str,) = struct.unpack_from("<I", data, off)
        off += 4
        strings = []
        for _ in range(n_str):
            (ln,) = struct.unpack_from("<I", data, off)
            off += 4
            strings.append(data[off:off + ln].decode("utf-8", "surrogatepass"))
            off += ln
        entries.append((pid, sig, tuple(strings)))

    sc = sidecar_path(path)
    payloads: Dict[str, dict] = {}
    if sc.exists():
        doc = json.loads(sc.read_text())
        # Labels are payload-id lookups: a sidecar from a different build
        # resolves ids to the wrong coordinates, silently. Refuse it.
        if doc.get("sig_stamp") != sig_stamp or doc.get("n_entries") != n:
            raise ValueError(
                f"{sc.name} does not match {path.name} "
                f"(stamp {doc.get('sig_stamp')!r}/{sig_stamp!r}, "
                f"entries {doc.get('n_entries')}/{n}): pack and sidecar are "
                f"built as a pair and must be installed together")
        payloads = doc.get("payloads", {})
    return entries, payloads, sig_stamp
