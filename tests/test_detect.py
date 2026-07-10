"""LibraryDetector tiering: exact signature, signature-radius, string anchor.

Runs against the brute-force fallback (no native module needed), so the tier
logic is covered regardless of whether the Rust wheel is built.
"""

from __future__ import annotations

from twinflame_libsigs.detect import LibraryDetector


def _sig(bits):
    v = 0
    for b in bits:
        v |= 1 << b
    return v


def test_tier1_exact_signature():
    lib_sig = _sig([1, 2, 3, 100])
    det = LibraryDetector.build([(7, lib_sig, ["Lib.Class.marker"])], radius=8)
    d = det.detect(lib_sig, [])
    assert d is not None and d.payload_id == 7 and d.tier == 1 and d.distance == 0


def test_tier2_within_radius():
    lib_sig = _sig([1, 2, 3, 100])
    q = lib_sig ^ (1 << 50) ^ (1 << 51)  # 2 bits away
    det = LibraryDetector.build([(7, lib_sig, [])], radius=8)
    d = det.detect(q, [])
    assert d is not None and d.tier == 2 and d.distance == 2


def test_tier3_string_when_signature_too_far():
    lib_sig = _sig(range(0, 40))          # far from the query signature
    q = _sig(range(80, 128))              # >8 bits away -> no signature hit
    det = LibraryDetector.build(
        [(9, lib_sig, ["okhttp3.internal.Http2Connection"])], radius=8)
    d = det.detect(q, ["okhttp3.internal.Http2Connection", "noise"])
    assert d is not None and d.tier == 3 and d.payload_id == 9


def test_no_detection_returns_none():
    det = LibraryDetector.build([(1, _sig([0, 1, 2]), ["only-lib-string"])], radius=4)
    assert det.detect(_sig(range(60, 128)), ["unrelated-app-string"]) is None


def test_exact_beats_radius_when_both_present():
    exact = _sig([5, 6, 7, 8])
    near = exact ^ (1 << 40)
    det = LibraryDetector.build([(1, exact, []), (2, near, [])], radius=8)
    d = det.detect(exact, [])
    assert d.payload_id == 1 and d.tier == 1  # closest (distance 0) wins
