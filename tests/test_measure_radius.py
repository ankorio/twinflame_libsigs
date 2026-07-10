"""Regression tests for the radius-measurement harness's pure logic (mapping
parse, Charikar radius→cosine, histogram + percentiles). The full run needs the
corpus + twinflame; these lock the math."""

from __future__ import annotations

import math
import sys
from collections import Counter
from pathlib import Path

import pytest

# The harness imports twinflame at module load; skip cleanly without it.
pytest.importorskip("twinflame", reason="twinflame not importable")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "eval"))
import measure_radius as mr  # noqa: E402


def test_parse_class_mapping_class_lines_only():
    text = (
        "# a comment\n"
        "org.foo.Bar -> a.b:\n"
        "    int field -> a\n"
        "    void method() -> b\n"
        "org.foo.Baz -> a.c:\n"
    )
    m = mr.parse_class_mapping(text)
    assert m == {"org.foo.Bar": "a.b", "org.foo.Baz": "a.c"}


def test_cosine_for_radius_matches_charikar():
    # expected Hamming = (theta/pi)*bits  =>  cosine = cos(pi*r/bits)
    assert mr._cosine_for_radius(0) == pytest.approx(1.0)
    assert mr._cosine_for_radius(64) == pytest.approx(0.0, abs=1e-9)  # 90 degrees
    assert mr._cosine_for_radius(12) == pytest.approx(math.cos(math.pi * 12 / 128))


def test_is_library_classification():
    assert mr._is_library("androidx.core.app.ActivityCompat")
    assert mr._is_library("kotlin.collections.CollectionsKt")
    assert not mr._is_library("com.example.myapp.MainActivity")


def test_histogram_splits_lib_and_app_and_counts_distance():
    # (original, sig_x, sig_y): distance = popcount(x ^ y)
    pairs = [
        ("androidx.core.X", 0b1111, 0b1111),   # lib, d=0
        ("androidx.core.Y", 0b1111, 0b1011),   # lib, d=1
        ("com.app.Z", 0b0, 0b111),             # app, d=3
    ]
    h_all, h_lib, h_app = mr.histogram(iter(pairs))
    assert h_all == Counter({0: 1, 1: 1, 3: 1})
    assert h_lib == Counter({0: 1, 1: 1})
    assert h_app == Counter({3: 1})
    assert mr._percentile(h_lib, 0.5) == 0
    assert mr._percentile(h_lib, 1.0) == 1
