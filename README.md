# twinflame_libsigs

A known-library **signature store** for [twinflame](https://github.com/ankorio/twinflame):
an offline builder plus a memory-mapped query reader for a large,
version-deduplicated dictionary of library class signatures, computed in
twinflame's own 128-bit signature space.

twinflame queries it to label app classes as known-library code — which feeds
`provenance.py`, demotes third-party churn in the change report, and (the reason
this exists) excludes library classes from the family side of **containment
scoring** so shared runtimes don't inflate the score. That exclusion is
`score.py`'s blocking dependency: today it uses a package-prefix denylist
stopgap; this project replaces it with an evidence-based dictionary.

## Status

Early. What's real and tested:

- **The production store — native, exact** (`native/`, Rust): a Multi-Index
  Hashing near-neighbour store (Norouzi et al., TPAMI 2014). Exact radius-`r`
  Hamming search, verified equal to brute force. Measured at R=12: **8.5 µs/query
  at 200k, 167 µs at 5M**, sub-second build; ~6× faster than the Python prototype
  and exact (vs ≥90% recall). pyo3 module `tfls_mih` lets twinflame call it
  directly (128-bit signatures ↔ Python ints).
- **The Python prototype** (`src/twinflame_libsigs/`): the original approximate
  LSH-banding store + the on-disk prefix-directory format study. Kept as design
  reference; superseded by `native/` for production.

Scaffolded, not built:

- **The catalogue/scraper** (Maven + Google-Maven → d8 → `twinflame prepare`),
  **version-range dedup** (`dedup.py`, interface), and the **radius measurement**
  (`eval/measure_radius.py`) that decides the store parameters.
- **Native persistence** — the MIH store is in-memory; serialize it to a
  mmap file so the tool loads instead of rebuilds (rebuild is sub-second, so
  low priority). See `native/README.md`.

## Design & background

The full design study — why the storage layout is what it is, the finding that
twinflame's R=12 radius breaks exact *pigeonhole* (Manku) indexing, the
multi-index-hashing escape that fixes it, the measured radius, and the prior-art
survey (near-neighbour search, TPL detection, malware fingerprinting) — lives in
the workspace knowledge library (`docs/libsigs/` and `docs/knowledge-base/` at the
repo parent), which is the source of truth and is not shipped with this package.

## Try it

```sh
pip install -e '.[test]'          # reader/builder need only the stdlib + twinflame
python -m pytest tests/           # storage correctness + recall
```

```python
from twinflame_libsigs.build import build_store
from twinflame_libsigs.store import LibSigStore

build_store([(sig0, 0), (sig1, 1)], "demo.tfls", sig_stamp="<twinflame stamp>")
with LibSigStore.open("demo.tfls") as store:
    hits = store.query(query_sig, k=4)   # payload ids within Hamming 4
```

## Boundary with twinflame

twinflame core imports only the stdlib-only reader (`store.py`). The builder, its
network/Maven/d8 dependencies, and the signature **data** are an offline asset
and never enter the twinflame wheel. See DESIGN §9.
