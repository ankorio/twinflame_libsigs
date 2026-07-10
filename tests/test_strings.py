"""String-anchor index: distinctiveness filtering + IDF-weighted matching."""

from __future__ import annotations

from twinflame_libsigs.strings import (
    MAX_DOC_FREQUENCY,
    StringAnchorIndex,
    useful_strings,
)


def test_useful_strings_filters_short_and_numeric():
    assert useful_strings(["ok", "1234", "RoomDatabase", "a.b.c.Widget"]) == {
        "RoomDatabase", "a.b.c.Widget"}


def test_distinctive_string_matches_its_library_class():
    idx = StringAnchorIndex.build([
        (10, ["okhttp3.internal.Http2Connection", "shared-const"]),
        (11, ["retrofit2.Retrofit$Builder", "shared-const"]),
        (12, ["kotlinx.coroutines.JobSupport"]),
    ])
    # an app class carrying okhttp's distinctive literal resolves to id 10
    assert idx.best(["okhttp3.internal.Http2Connection", "unrelated"]) == 10
    assert idx.best(["retrofit2.Retrofit$Builder"]) == 11


def test_common_string_dropped_as_nondistinctive():
    # a string present in more than MAX_DOC_FREQUENCY classes is boilerplate
    entries = [(i, ["UTF-8", f"unique-tag-{i}-xyz"]) for i in range(MAX_DOC_FREQUENCY + 3)]
    idx = StringAnchorIndex.build(entries)
    # "UTF-8" was dropped -> no match on it
    assert idx.query(["UTF-8"]) == []
    # but a genuinely unique per-class string still resolves
    assert idx.best(["unique-tag-2-xyz"]) == 2


def test_idf_ranks_rarer_string_higher():
    # id 0 shares a rare string; id 1 shares a more common one
    entries = [
        (0, ["rare-lib-marker-0000"]),
        (1, ["semi-common"]),
        (2, ["semi-common"]),
        (3, ["semi-common"]),
    ]
    idx = StringAnchorIndex.build(entries)
    hits = dict(idx.query(["rare-lib-marker-0000", "semi-common"], min_score=0.0))
    assert hits[0] > hits[1]  # rarer string carries more evidence


def test_no_match_below_min_score():
    idx = StringAnchorIndex.build([(0, ["x" * 5] * 1)])
    assert idx.query(["nothing-shared-here"]) == []
