"""Radius clustering: union-find semantics and single-linkage grouping."""

import pytest

from twinflame_libsigs.cluster import UnionFind, cluster_by_radius


def _sig(seed: int) -> int:
    # deterministic, well-spread 128-bit values
    return (seed * 0x9E3779B97F4A7C15) & ((1 << 128) - 1)


def _flip(sig: int, *bits: int) -> int:
    for b in bits:
        sig ^= 1 << b
    return sig


def _as_sets(groups):
    return {frozenset(g) for g in groups}


# ---- UnionFind --------------------------------------------------------------

def test_union_find_basics():
    uf = UnionFind(4)
    assert uf.find(0) != uf.find(1)
    uf.union(0, 1)
    assert uf.find(0) == uf.find(1)
    uf.union(2, 3)
    uf.union(1, 2)  # transitivity across prior unions
    assert len({uf.find(i) for i in range(4)}) == 1
    assert _as_sets(uf.groups()) == {frozenset({0, 1, 2, 3})}


def test_union_find_self_union_is_noop():
    uf = UnionFind(2)
    uf.union(0, 0)
    assert _as_sets(uf.groups()) == {frozenset({0}), frozenset({1})}


# ---- cluster_by_radius ------------------------------------------------------

def test_identical_signatures_merge():
    groups = cluster_by_radius([_sig(1), _sig(1), _sig(2)], radius=0)
    assert _as_sets(groups) == {frozenset({0, 1}), frozenset({2})}


def test_within_radius_merges_beyond_stays_apart():
    base = _sig(3)
    groups = cluster_by_radius(
        [base, _flip(base, 0, 1), _flip(base, 10, 20, 30, 40, 50, 60)],
        radius=4)
    assert _as_sets(groups) == {frozenset({0, 1}), frozenset({2})}


def test_transitive_chain_merges_past_radius():
    # a~b and b~c within radius, but d(a, c) = 8 > radius: single-linkage
    # must still put all three in one group.
    a = _sig(4)
    b = _flip(a, 0, 1, 2, 3)
    c = _flip(b, 4, 5, 6, 7)
    assert (a ^ c).bit_count() == 8
    groups = cluster_by_radius([a, b, c], radius=4)
    assert _as_sets(groups) == {frozenset({0, 1, 2})}


def test_radius_zero_is_exact_grouping():
    a, b = _sig(5), _flip(_sig(5), 0)
    groups = cluster_by_radius([a, b], radius=0)
    assert _as_sets(groups) == {frozenset({0}), frozenset({1})}


def test_empty_input():
    assert cluster_by_radius([], radius=4) == []


def test_brute_fallback_parity(monkeypatch):
    import twinflame_libsigs.cluster as cluster_mod
    sigs = [_sig(i) for i in range(20)] + [_flip(_sig(3), 1), _sig(7)]
    native = cluster_by_radius(sigs, radius=4)
    monkeypatch.setattr(cluster_mod, "_HAVE_NATIVE", False)
    brute = cluster_by_radius(sigs, radius=4)
    assert _as_sets(native) == _as_sets(brute)
