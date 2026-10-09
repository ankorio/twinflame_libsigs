"""Catalogue-pack pipeline: dedup -> ranges -> pack roundtrip -> detector."""

import json

import pytest

from twinflame_libsigs.dedup import (
    ClassSig, assign_payload_ids, compact_ranges, dedup_by_signature)
from twinflame_libsigs.detect import LibraryDetector
from twinflame_libsigs.pack import (
    describe_pack, read_meta, read_pack, sidecar_path, utc_now_iso, write_pack)
from twinflame_libsigs.store import StaleStoreError

OKHTTP = "com.squareup.okhttp3:okhttp"
ORDER = ["3.12.0", "3.14.9", "4.0.1", "4.9.3", "4.12.0"]


def _sig(seed: int) -> int:
    # deterministic, well-spread 128-bit values
    return (seed * 0x9E3779B97F4A7C15) & ((1 << 128) - 1)


# ---- dedup ---------------------------------------------------------------

def test_dedup_collapses_versions_and_keeps_metadata():
    sigs = [
        ClassSig(OKHTTP, v, _sig(1), fqcn="okhttp3.Request",
                 strings=("http/1.1",), instructions=90)
        for v in ("3.12.0", "3.14.9", "4.0.1")
    ] + [ClassSig(OKHTTP, "4.12.0", _sig(2), fqcn="okhttp3.Cache", instructions=40)]
    entries = dedup_by_signature(sigs)
    assert len(entries) == 2
    by_sig = {e.signature: e for e in entries}
    assert by_sig[_sig(1)].versions == ["3.12.0", "3.14.9", "4.0.1"]
    assert by_sig[_sig(1)].strings == ("http/1.1",)
    assert by_sig[_sig(1)].instructions == 90
    assert by_sig[_sig(2)].versions == ["4.12.0"]


def test_dedup_same_signature_across_coords_stays_separate():
    entries = dedup_by_signature([
        ClassSig("a:a", "1.0", _sig(3)),
        ClassSig("b:b", "1.0", _sig(3)),
    ])
    assert len(entries) == 2


# ---- range compaction ------------------------------------------------------

def test_compact_ranges_contiguous_run():
    assert compact_ranges(["3.12.0", "3.14.9", "4.0.1"], ORDER) == ["3.12.0..4.0.1"]


def test_compact_ranges_gap_splits():
    assert compact_ranges(["3.12.0", "4.0.1", "4.9.3"], ORDER) == \
        ["3.12.0", "4.0.1..4.9.3"]


def test_compact_ranges_singletons_and_full_span():
    assert compact_ranges(["4.9.3"], ORDER) == ["4.9.3"]
    assert compact_ranges(list(ORDER), ORDER) == ["3.12.0..4.12.0"]


def test_compact_ranges_unknown_version_kept_as_stray():
    assert compact_ranges(["3.12.0", "9.9.9"], ORDER) == ["3.12.0", "9.9.9"]


# ---- pack roundtrip ---------------------------------------------------------

def _pack_fixture(tmp_path, stamp="stamp-a"):
    sigs = [
        ClassSig(OKHTTP, "3.12.0", _sig(1), fqcn="okhttp3.Request",
                 strings=("http/1.1", "OkHttp"), instructions=90),
        ClassSig(OKHTTP, "3.14.9", _sig(1), fqcn="okhttp3.Request",
                 strings=("http/1.1", "OkHttp"), instructions=90),
        ClassSig(OKHTTP, "4.12.0", _sig(2), fqcn="okhttp3.Cache",
                 strings=("Cache-Control",), instructions=40),
    ]
    stream, sidecar = assign_payload_ids(
        dedup_by_signature(sigs), {OKHTTP: ORDER})
    path = tmp_path / "lib.tflp"
    write_pack(path, stream, sidecar, sig_stamp=stamp, meta={"coords": [OKHTTP]})
    return path, stream, sidecar


def test_pack_roundtrip(tmp_path):
    path, stream, sidecar = _pack_fixture(tmp_path)
    entries, payloads, stamp = read_pack(path)
    assert stamp == "stamp-a"
    assert entries == stream
    assert payloads == {k: v for k, v in sidecar.items()}
    assert sidecar_path(path).exists()
    meta0 = payloads["0"]
    assert meta0["coord"] == OKHTTP
    assert meta0["ranges"] == ["3.12.0..3.14.9"]


def test_pack_stamp_guard(tmp_path):
    path, _, _ = _pack_fixture(tmp_path, stamp="stamp-a")
    with pytest.raises(StaleStoreError):
        read_pack(path, expect_stamp="stamp-b")
    read_pack(path, expect_stamp="stamp-a")  # matching stamp is fine


def test_pack_roundtrips_mutf8_surrogate_strings(tmp_path):
    # DEX strings are MUTF-8: lone UTF-16 surrogates occur in real artifacts
    # (found in the seed scrape) and must survive the pack roundtrip.
    weird = "prefix-\ud800-suffix"
    path = tmp_path / "s.tflp"
    write_pack(path, [(0, _sig(7), (weird,))], {"0": {}}, sig_stamp="s")
    entries, _, _ = read_pack(path)
    assert entries[0][2] == (weird,)


def test_read_meta_roundtrip_and_missing_sidecar(tmp_path):
    path, _, _ = _pack_fixture(tmp_path)
    assert read_meta(path) == {"coords": [OKHTTP]}
    sidecar_path(path).unlink()
    assert read_meta(path) == {}


def test_describe_pack_reads_sidecar_only(tmp_path):
    sigs = [
        ClassSig(OKHTTP, "3.12.0", _sig(1), fqcn="okhttp3.Request",
                 strings=("http/1.1",), instructions=90),
        ClassSig(OKHTTP, "4.12.0", _sig(2), fqcn="okhttp3.Cache", instructions=40),
    ]
    stream, sidecar = assign_payload_ids(dedup_by_signature(sigs), {OKHTTP: ORDER})
    path = tmp_path / "lib.tflp"
    built = utc_now_iso()
    assert built.endswith("Z") and "." not in built    # seconds precision
    write_pack(path, stream, sidecar, sig_stamp="stamp-a",
               meta={"coords": [OKHTTP], "versions": 2, "classes_seen": 2,
                     "classes_below_min_instr": 0, "min_instr": 20,
                     "built": built})
    d = describe_pack(path)
    assert d["path"] == str(path.resolve())
    assert d["sidecar"] == str(sidecar_path(path).resolve())
    assert d["n_entries"] == 2
    assert d["coords"] == 1 and d["versions"] == 2
    assert d["classes_seen"] == 2 and d["min_instr"] == 20
    assert d["built"] == built and d["built_from"] == "meta"
    assert d["size_bytes"] == path.stat().st_size + sidecar_path(path).stat().st_size

    # Describing must not depend on the pack body: corrupt it and ask again.
    path.write_bytes(b"not a pack")
    assert describe_pack(path)["n_entries"] == 2


def test_describe_pack_falls_back_to_mtime(tmp_path):
    path, _, _ = _pack_fixture(tmp_path)           # meta without `built`
    d = describe_pack(path)
    assert d["built_from"] == "mtime"
    assert d["built"].endswith("Z") and len(d["built"]) == len("2026-01-01T00:00:00Z")
    assert d["coords"] == 1 and d["versions"] is None   # count missing -> None

    sidecar_path(path).unlink()
    with pytest.raises(FileNotFoundError):
        describe_pack(path)


def test_pack_rejects_mismatched_sidecar(tmp_path):
    # A sidecar from a different build resolves payload ids to the wrong
    # coordinates; read_pack must refuse the pair rather than mislabel.
    path, _, _ = _pack_fixture(tmp_path, stamp="stamp-a")
    stale = sidecar_path(path)
    doc = json.loads(stale.read_text())
    for tamper in ({"sig_stamp": "stamp-old"}, {"n_entries": 999}):
        stale.write_text(json.dumps(doc | tamper))
        with pytest.raises(ValueError, match="installed together"):
            read_pack(path)
    stale.write_text(json.dumps(doc))
    read_pack(path)  # restored pair is fine

    stale.unlink()   # a *missing* sidecar stays tolerated (labels degrade)
    _, payloads, _ = read_pack(path)
    assert payloads == {}


def test_pack_rejects_sparse_payload_ids(tmp_path):
    with pytest.raises(ValueError):
        write_pack(tmp_path / "bad.tflp", [(1, _sig(1), ())], {}, sig_stamp="s")


# ---- detector from pack -----------------------------------------------------

def test_detector_from_pack_detects_and_labels(tmp_path):
    path, _, _ = _pack_fixture(tmp_path)
    det = LibraryDetector.from_pack(path, expect_stamp="stamp-a")

    hit = det.detect(_sig(1), ())            # exact signature
    assert hit is not None and hit.tier == 1
    assert det.label(hit) == f"library:{OKHTTP}@3.12.0..3.14.9"

    near = det.detect(_sig(2) ^ 0b111, ())   # 3 bits away -> radius tier
    assert near is not None and near.tier == 2 and near.distance == 3
    assert det.label(near) == f"library:{OKHTTP}@4.12.0"

    s = det.detect(_sig(999), ("Cache-Control", "zzz"))  # string tier
    assert s is not None and s.tier == 3
    assert det.resolve(s)["fqcn"] == "okhttp3.Cache"

    assert det.detect(_sig(999), ("zzz",)) is None
