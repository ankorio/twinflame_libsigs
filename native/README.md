# native — MIH store in Rust

The production storage/query core for twinflame_libsigs: an exact
**Multi-Index Hashing** near-neighbour store for 128-bit twinflame signatures,
after Norouzi, Punjani & Fleet (TPAMI 2014). std-only core (compiles offline);
optional pyo3 binding for Python.

Supersedes the Python prototype in `../src/twinflame_libsigs/` (approximate
banding). The design rationale and literature survey live in the workspace
knowledge library (`docs/libsigs/` and `docs/knowledge-base/` at the repo parent).

## Why MIH

Exact radius-`r` Hamming search by splitting the 128 bits into `m` disjoint
substrings: two codes within `r` agree within `floor(r/m)` on some substring
(pigeonhole), so `m` substring tables suffice — no false negatives, and
false positives are removed by a final 128-bit verify. `m ≈ 128/log2(N)`
(≈6–8 for millions of signatures); **do not over-split** — too-narrow substrings
have huge exact buckets (measured: m=16 is 70× slower than m=6 at 5M).

## Measured (this machine, R=12, exact)

| N | m | build | query/class | per 10k-class app |
|--:|--:|--:|--:|--:|
| 200k | 8 | 0.01 s | 8.5 µs | 0.09 s |
| 1M | 8 | 0.07 s | 45.6 µs | 0.46 s |
| 5M | 6 | 0.72 s | 167 µs | 1.67 s |

~6× faster than the Python prototype and exact (vs ≥90% recall); ~250× faster
build. From Python (300k, via the wheel): build 0.13 s, 33 µs/class, exact.

## Build & test

```sh
# core: correctness (exact vs brute force) + benchmark, no Python needed
cargo test --release
cargo run --release --bin bench

# Python extension module `tfls_mih`
maturin develop --release --features python     # into the active venv
python -c "import tfls_mih; s=tfls_mih.MihStore.build([(1,0),(2,1)], 6); print(s.query(1, 12))"
```

## Release (wheel)

`.github/workflows/native-wheels.yml` builds manylinux x86_64 wheels for
CPython 3.11-3.13 with maturin-action and publishes them to PyPI as `tfls-mih`
(Trusted Publishing) when a `native-v<version>` tag is pushed; the tag must
match `[project].version` in `pyproject.toml`. `workflow_dispatch` runs the
build only (wheels as a job artifact).

## API (Python)

```python
from tfls_mih import MihStore, suggest_m
store = MihStore.build([(sig, payload_id), ...], suggest_m(n))
store.query(sig, r)             # -> [payload ids within Hamming r]
store.query_with_dist(sig, r)   # -> [(payload id, distance), ...]  (closest version)
len(store); store.m
```

Signatures cross as Python ints (pyo3 `u128` ↔ `int`), matching twinflame's
`Signature.combined`.

## Not yet done

- **Persistence.** `MihStore` is in-memory; the offline builder needs to
  serialize it to a mmap-friendly file so the tool loads instead of rebuilds.
  (Rebuild is sub-second at 5M, so this is a convenience/startup win, not a
  blocker.)
- **`sig_stamp` guard** in the native path (the Python store already refuses a
  stale stamp; the native store should carry and check it too).
- **rayon** parallel build if build time ever matters (it does not yet).
