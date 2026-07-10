"""Exercise the native MIH extension (`tfls_mih`) if it's been built.

Skipped when the wheel isn't installed, so the pure-Python test suite still runs
without the Rust toolchain. Build it with:
    (cd native && maturin develop --release --features python)
"""

from __future__ import annotations

import random

import pytest

tfls_mih = pytest.importorskip(
    "tfls_mih", reason="native extension not built (see native/README.md)")


def _brute(codes, q, r):
    return sorted(i for i, c in enumerate(codes) if bin(c ^ q).count("1") <= r)


def test_native_exact_vs_brute_force():
    rng = random.Random(0)
    n = 20_000
    codes = [rng.getrandbits(128) for _ in range(n)]
    store = tfls_mih.MihStore.build(list(zip(codes, range(n))),
                                    tfls_mih.suggest_m(n))
    assert len(store) == n
    for _ in range(60):
        if rng.random() < 0.5:
            q = codes[rng.randrange(n)]
            for _ in range(rng.randint(0, 12)):
                q ^= 1 << rng.randrange(128)
        else:
            q = rng.getrandbits(128)
        assert sorted(store.query(q, 12)) == _brute(codes, q, 12)


def test_native_query_with_dist():
    rng = random.Random(1)
    codes = [rng.getrandbits(128) for _ in range(5000)]
    store = tfls_mih.MihStore.build(list(zip(codes, range(len(codes)))), 8)
    # a code queried against itself is at distance 0
    for i in (0, 100, 4999):
        hits = dict(store.query_with_dist(codes[i], 0))
        assert hits.get(i) == 0


def test_suggest_m_stays_in_valid_range():
    for n in (0, 1, 2, 1000, 1_000_000, 50_000_000):
        m = tfls_mih.suggest_m(n)
        assert 6 <= m <= 16
        assert 128 // m <= tfls_mih.MAX_SUBSTRING_BITS
