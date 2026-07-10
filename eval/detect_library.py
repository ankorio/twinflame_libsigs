"""End-to-end demo: identify known library classes inside an obfuscated APK.

Setup (all from the twinflame corpus, verifiable via R8 mappings):
  - "known library" = the library classes (androidx/kotlin/...) of one build,
    keyed by their original FQCN.
  - "APK under test" = a differently/​more-obfuscated build of the same app.
  - We build the signature store + string-anchor index from the known-library
    side, then for each test-APK class ask the LibraryDetector which library
    class it is — and check the answer against the mapping oracle.

Oracle: a test class (obfuscated) joins to its original name via the test build's
mapping; the known-library side is keyed by original name, so a detection is
*correct* iff it resolves to the same original.

Usage:
  python -m eval.detect_library \
     --lib   corpus/records/contacts__1.6.0__lax.tfr:corpus/oss_matrix/contacts/1.6.0/lax/mapping.txt \
     --apk   corpus/records/contacts__1.6.0__strict.tfr:corpus/oss_matrix/contacts/1.6.0/strict/mapping.txt \
     --radius 8
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, Tuple

from twinflame.prepare import load_record
from twinflame_libsigs.detect import LibraryDetector

from measure_radius import LIBRARY_PREFIXES, parse_class_mapping, _fqcn, _is_library


def _load(spec: str):
    rec, _, mp = spec.partition(":")
    return list(load_record(rec).classes), parse_class_mapping(Path(mp).read_text())


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--lib", required=True, metavar="REC:MAP",
                   help="known-library build (record:mapping)")
    p.add_argument("--apk", required=True, metavar="REC:MAP",
                   help="obfuscated build under test (record:mapping)")
    p.add_argument("--radius", type=int, default=8)
    p.add_argument("--min-instr", type=int, default=0,
                   help="skip classes with fewer total instructions (they have "
                        "colliding structural signatures); mirrors twinflame --min-instr")
    p.add_argument("--examples", type=int, default=8)
    args = p.parse_args(argv)

    lib_classes, lib_map = _load(args.lib)
    apk_classes, apk_map = _load(args.apk)

    # invert mappings: obfuscated FQCN (as stored in the record) -> original
    lib_obf_to_orig = {obf: orig for orig, obf in lib_map.items()}
    apk_obf_to_orig = {obf: orig for orig, obf in apk_map.items()}

    # Known library: build the store from the lib build's *library* classes,
    # payload id -> original library FQCN.
    id_to_orig: Dict[int, str] = {}
    entries = []
    for c in lib_classes:
        orig = lib_obf_to_orig.get(_fqcn(c))
        if orig is None or not _is_library(orig) or c.signature is None:
            continue
        if c.total_instructions < args.min_instr:
            continue  # trivial class: signature collides, unreliable to index
        pid = len(id_to_orig)
        id_to_orig[pid] = orig
        entries.append((pid, c.signature.combined, c.strings))
    orig_to_id = {o: i for i, o in id_to_orig.items()}

    detector = LibraryDetector.build(entries, radius=args.radius)
    print(f"known-library store: {len(entries)} classes "
          f"({'native MIH' if detector.native else 'brute-force fallback'}), "
          f"string index built.")

    # Query every test-APK class; verify against the oracle.
    tp = fp = fn = 0
    by_tier: Dict[int, int] = {1: 0, 2: 0, 3: 0}
    examples = []
    tested = 0
    detected_libs: Dict[str, int] = {}
    truth_libs: Dict[str, int] = {}

    def _lib_root(fqcn: str) -> str:
        parts = fqcn.split(".")
        return ".".join(parts[:3]) if len(parts) >= 3 else fqcn

    for c in apk_classes:
        if c.total_instructions < args.min_instr:
            continue  # not indexed on the store side either; skip symmetrically
        orig = apk_obf_to_orig.get(_fqcn(c))
        truth_is_lib = orig is not None and _is_library(orig) and orig in orig_to_id
        det = detector.detect(c.signature.combined if c.signature else 0, c.strings)
        if truth_is_lib:
            tested += 1
            truth_libs[_lib_root(orig)] = truth_libs.get(_lib_root(orig), 0) + 1
        if det is not None:
            correct = truth_is_lib and id_to_orig[det.payload_id] == orig
            if correct:
                tp += 1
                by_tier[det.tier] += 1
                root = _lib_root(id_to_orig[det.payload_id])
                detected_libs[root] = detected_libs.get(root, 0) + 1
                if len(examples) < args.examples and det.tier in (2, 3):
                    examples.append((_fqcn(c), id_to_orig[det.payload_id], det))
            else:
                fp += 1
        elif truth_is_lib:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    print(f"\nlibrary classes in test APK (oracle): {tested}")
    print(f"correct detections (TP): {tp}   false (FP): {fp}   missed (FN): {fn}")
    print(f"  by tier — exact(1): {by_tier[1]}  radius(2): {by_tier[2]}  string(3): {by_tier[3]}")
    print(f"precision: {precision:.4f}   recall: {recall:.4f}   f1: {f1:.4f}")

    if examples:
        print("\nexample recoveries (obfuscated class -> recovered library class):")
        for obf, orig, det in examples:
            how = f"tier{det.tier}," + (f"Ham={det.distance}" if det.tier != 3
                                        else f"str={det.score:.2f}")
            print(f"  {obf:28} -> {orig}   [{how}]")

    # The practical answer: which libraries are present? Aggregate per library
    # root — robust to per-class noise (a library is "present" if many of its
    # classes are detected).
    print("\ndetected libraries (root package: #classes detected / #in APK):")
    for root in sorted(detected_libs, key=lambda r: -detected_libs[r])[:12]:
        print(f"  {root:45} {detected_libs[root]:5} / {truth_libs.get(root, 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
