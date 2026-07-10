"""Correctness: the store's query recall/precision against brute force.

Precision is exact by construction — every returned candidate is Hamming-checked
against the original signature, so there are never false positives. Recall is a
property of the banding parameters (n_tables / prefix_bits / probe_bits); these
tests pin the *precision* guarantee always, and record the *recall* the default
parameters actually achieve at a given radius so a parameter regression is
visible.
"""

from __future__ import annotations

import random

import pytest

from twinflame_libsigs.build import build_store
from twinflame_libsigs.layout import SIGNATURE_BITS
from twinflame_libsigs.store import LibSigStore, StaleStoreError

STAMP = "deadbeefcafe0001"


def _rand_sig(rng: random.Random) -> int:
    return rng.getrandbits(SIGNATURE_BITS)


def _flip(sig: int, bits: int, rng: random.Random) -> int:
    positions = rng.sample(range(SIGNATURE_BITS), bits)
    for p in positions:
        sig ^= (1 << p)
    return sig


def _brute(entries, sig, k):
    return {pid for s, pid in entries if (s ^ sig).bit_count() <= k}


def test_precision_is_exact(tmp_path):
    rng = random.Random(1)
    entries = [(_rand_sig(rng), i) for i in range(2000)]
    path = tmp_path / "s.tfls"
    build_store(entries, path, sig_stamp=STAMP, n_tables=6, prefix_bits=8)
    with LibSigStore.open(path) as store:
        for _ in range(200):
            q = _rand_sig(rng)
            hits = store.query(q, k=6)
            # every hit is genuinely within radius (no false positives)
            byid = dict(entries)
            for pid in hits:
                assert (byid[pid] ^ q).bit_count() <= 6


def test_self_lookup_always_found(tmp_path):
    rng = random.Random(2)
    entries = [(_rand_sig(rng), i) for i in range(3000)]
    path = tmp_path / "s.tfls"
    build_store(entries, path, sig_stamp=STAMP, n_tables=6, prefix_bits=10)
    with LibSigStore.open(path) as store:
        for s, pid in entries:
            hits = store.query(s, k=0)   # distance 0 = the entry itself
            assert pid in hits


def test_near_neighbor_recall_default_params(tmp_path):
    """A planted neighbour a few bits away is recovered by banding. Records the
    recall the default-ish params hit at small radius — the regime the store is
    meant for (library class vs its pristine original, not app-vs-app R=12)."""
    rng = random.Random(3)
    base = [(_rand_sig(rng), i) for i in range(5000)]
    path = tmp_path / "s.tfls"
    build_store(base, path, sig_stamp=STAMP, n_tables=8, prefix_bits=10)
    found = 0
    trials = 300
    with LibSigStore.open(path) as store:
        for t in range(trials):
            s, pid = base[rng.randrange(len(base))]
            q = _flip(s, rng.randint(1, 4), rng)   # 1..4 bits away
            if pid in store.query(q, k=4):
                found += 1
    recall = found / trials
    # Banding at 8 tables recovers the large majority of ≤4-bit neighbours.
    assert recall >= 0.90, f"recall regressed to {recall:.2%}"


def test_probe_bits_improves_recall(tmp_path):
    rng = random.Random(4)
    base = [(_rand_sig(rng), i) for i in range(5000)]
    path = tmp_path / "s.tfls"
    build_store(base, path, sig_stamp=STAMP, n_tables=4, prefix_bits=12)
    def recall(probe):
        found = 0
        with LibSigStore.open(path) as store:
            for _ in range(200):
                s, pid = base[rng.randrange(len(base))]
                q = _flip(s, rng.randint(1, 4), rng)
                if pid in store.query(q, k=4, probe_bits=probe):
                    found += 1
        return found / 200
    assert recall(1) >= recall(0)


def test_stale_stamp_rejected(tmp_path):
    path = tmp_path / "s.tfls"
    build_store([(1, 0), (2, 1)], path, sig_stamp=STAMP, n_tables=2,
                prefix_bits=4)
    with LibSigStore.open(path) as store:
        store.verify_stamp(STAMP)                 # ok
        with pytest.raises(StaleStoreError):
            store.verify_stamp("0000000000000000")
