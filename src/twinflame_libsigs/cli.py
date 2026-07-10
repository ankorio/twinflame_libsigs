"""`twinflame-libsigs` — inspect and query a `.tfls` store from the shell.

The offline *build-from-catalogue* path (scrape → d8 → prepare → dedup → build)
is not wired here yet; this CLI covers what already works end-to-end: inspecting
a store and probing it with a signature. Building from an in-memory stream is the
`build.build_store` API, exercised by the tests.
"""

from __future__ import annotations

import argparse
import sys

from .layout import Header, total_size
from .store import LibSigStore


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


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="twinflame-libsigs")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("info", help="print a store's header")
    pi.add_argument("store")
    pi.set_defaults(func=_cmd_info)

    pq = sub.add_parser("query", help="probe a store with one signature")
    pq.add_argument("store")
    pq.add_argument("signature", help="128-bit signature (e.g. 0x...)")
    pq.add_argument("-R", "--radius", type=int, default=4)
    pq.add_argument("--probe", type=int, default=0, help="prefix probe radius")
    pq.set_defaults(func=_cmd_query)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
