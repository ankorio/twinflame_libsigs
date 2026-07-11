"""`twinflame-libsigs` — the offline pipeline and store inspection, from the shell.

The full catalogue path is two idempotent steps you can re-run any time:

    twinflame-libsigs scrape -C cache/                      # catalogue -> .sigs.json cache
    twinflame-libsigs build  -C cache/ -o libsigs.tflp      # cache -> shippable pack

plus `detect` (probe an APK against a pack — the end-to-end check), and the
older store-study commands `info`/`query` for the pure-Python `.tfls` format.
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

from .layout import Header, total_size
from .store import LibSigStore

# The corpus-validated precision knob: classes below this instruction count
# have colliding structural signatures and are never indexed (0.56 -> 0.83
# measured precision lift). Mirrors twinflame's --min-instr.
DEFAULT_MIN_INSTR = 20


def _cmd_scrape(args) -> int:
    from .catalogue import load_catalogue
    from .scraper import scrape_catalogue

    entries = load_catalogue(args.catalogue)
    cache = Path(args.cache)
    cache.mkdir(parents=True, exist_ok=True)
    results = scrape_catalogue(entries, cache, max_versions=args.max_versions)
    ok = sum(1 for arts in results.values() for a in arts if not a.error)
    bad = sum(1 for arts in results.values() for a in arts if a.error)
    print(f"\nscraped {ok} artifact versions across {len(results)} coordinates"
          + (f"  ({bad} failed)" if bad else ""))
    return 0 if ok else 1


def _cmd_build(args) -> int:
    from twinflame.prepare import SIGNATURE_STAMP

    from .dedup import ClassSig, assign_payload_ids, dedup_by_signature
    from .pack import write_pack
    from .scraper import iter_cached_sigs, ver_key

    cache = Path(args.cache)
    sigs: list[ClassSig] = []
    versions_by_coord: dict[str, set] = defaultdict(set)
    n_classes = n_skipped = n_stale = 0
    for art in iter_cached_sigs(cache):
        if art.sig_stamp != SIGNATURE_STAMP:
            n_stale += 1
            continue
        versions_by_coord[art.coord].add(art.version)
        for c in art.classes:
            n_classes += 1
            if c.instructions < args.min_instr:
                n_skipped += 1
                continue
            sigs.append(ClassSig(coord=art.coord, version=art.version,
                                 signature=c.signature, fqcn=c.fqcn,
                                 strings=c.strings, instructions=c.instructions))
    if not sigs:
        print(f"no usable .sigs.json under {cache} "
              f"({n_stale} stale-stamp files skipped)" if n_stale else
              f"no usable .sigs.json under {cache} — run `scrape` first",
              file=sys.stderr)
        return 1

    entries = dedup_by_signature(sigs)
    order = {c: sorted(vs, key=ver_key) for c, vs in versions_by_coord.items()}
    stream, sidecar = assign_payload_ids(entries, order)
    meta = {
        "coords": sorted(versions_by_coord),
        "versions": sum(len(v) for v in versions_by_coord.values()),
        "classes_seen": n_classes,
        "classes_below_min_instr": n_skipped,
        "min_instr": args.min_instr,
    }
    write_pack(args.output, stream, sidecar, sig_stamp=SIGNATURE_STAMP, meta=meta)
    kept = n_classes - n_skipped
    print(f"pack: {args.output}")
    print(f"  coordinates:       {len(versions_by_coord)}"
          f"  ({meta['versions']} scraped versions"
          + (f", {n_stale} stale files ignored" if n_stale else "") + ")")
    print(f"  classes:           {n_classes:,} seen, {n_skipped:,} below "
          f"min-instr {args.min_instr} -> {kept:,} indexed")
    print(f"  distinct entries:  {len(entries):,} "
          f"(version dedup {kept / len(entries):.2f}x)" if entries else "")
    return 0


def _cmd_detect(args) -> int:
    from twinflame.prepare import SIGNATURE_STAMP, prepare

    from .detect import LibraryDetector

    det = LibraryDetector.from_pack(args.pack, radius=args.radius,
                                    expect_stamp=SIGNATURE_STAMP)
    rec = prepare(args.apk)
    per_lib: dict[str, int] = defaultdict(int)
    by_tier = {1: 0, 2: 0, 3: 0}
    probed = 0
    for c in rec.classes:
        if c.signature is None or c.total_instructions < args.min_instr:
            continue
        probed += 1
        hit = det.detect(c.signature.combined, c.strings)
        if hit is None:
            continue
        by_tier[hit.tier] += 1
        m = det.resolve(hit)
        per_lib[m["coord"] if m else f"payload/{hit.payload_id}"] += 1

    total = sum(by_tier.values())
    print(f"{args.apk}: {probed} classes probed, {total} library hits "
          f"(exact {by_tier[1]} / radius {by_tier[2]} / string {by_tier[3]})")
    print(f"\ndetected libraries (>= {args.min_classes} classes):")
    for coord, n in sorted(per_lib.items(), key=lambda kv: -kv[1]):
        if n >= args.min_classes:
            print(f"  {coord:50} {n:5} classes")
    return 0


def _cmd_info(args) -> int:
    with LibSigStore.open(args.store) as s:
        h: Header = s.header
        print(f"store:        {args.store}")
        print(f"format:       v{h.format_version}")
        print(f"sig_stamp:    {h.sig_stamp}")
        print(f"entries (N):  {h.n_entries:,}")
        print(f"tables (L):   {h.n_tables}")
        print(f"prefix_bits:  {h.prefix_bits}")
        print(f"seed:         {h.seed:#x}")
        print(f"total_size:   {total_size(h):,} bytes")
    return 0


def _cmd_query(args) -> int:
    sig = int(args.signature, 0)
    with LibSigStore.open(args.store) as s:
        best = s.query_best(sig, k=args.radius, probe_bits=args.probe)
        if not best:
            print("no library class within radius", file=sys.stderr)
            return 1
        for pid, dist in sorted(best.items(), key=lambda kv: kv[1]):
            print(f"payload={pid}\thamming={dist}")
    return 0


def _quiet_androguard() -> None:
    # androguard (twinflame's dex parser) logs per-map-item DEBUG lines through
    # loguru's default sink — thousands of lines per artifact. Keep warnings.
    try:
        from loguru import logger
        logger.remove()
        logger.add(sys.stderr, level="WARNING")
    except ImportError:
        pass


def main(argv=None) -> int:
    _quiet_androguard()
    p = argparse.ArgumentParser(prog="twinflame-libsigs")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scrape", help="feed the cache from a library catalogue")
    ps.add_argument("-c", "--catalogue", default=None,
                    help="catalogue file (default: the built-in seed)")
    ps.add_argument("-C", "--cache", default="libsigs-cache",
                    help="scrape cache directory (default: %(default)s)")
    ps.add_argument("-n", "--max-versions", type=int, default=8,
                    help="sampled versions per coordinate (default: %(default)s)")
    ps.set_defaults(func=_cmd_scrape)

    pb = sub.add_parser("build", help="build a catalogue pack from the cache")
    pb.add_argument("-C", "--cache", default="libsigs-cache")
    pb.add_argument("-o", "--output", default="libsigs.tflp")
    pb.add_argument("--min-instr", type=int, default=DEFAULT_MIN_INSTR,
                    help="skip classes below this instruction count "
                         "(precision filter, default: %(default)s)")
    pb.set_defaults(func=_cmd_build)

    pd = sub.add_parser("detect", help="probe an APK against a pack")
    pd.add_argument("pack")
    pd.add_argument("apk", help="APK / .dex / dex directory")
    pd.add_argument("-R", "--radius", type=int, default=4)
    pd.add_argument("--min-instr", type=int, default=DEFAULT_MIN_INSTR)
    pd.add_argument("--min-classes", type=int, default=5,
                    help="library-level aggregation floor (default: %(default)s)")
    pd.set_defaults(func=_cmd_detect)

    pi = sub.add_parser("info", help="print a .tfls store's header")
    pi.add_argument("store")
    pi.set_defaults(func=_cmd_info)

    pq = sub.add_parser("query", help="probe a .tfls store with one signature")
    pq.add_argument("store")
    pq.add_argument("signature", help="128-bit signature (e.g. 0x...)")
    pq.add_argument("-R", "--radius", type=int, default=4)
    pq.add_argument("--probe", type=int, default=0, help="prefix probe radius")
    pq.set_defaults(func=_cmd_query)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
