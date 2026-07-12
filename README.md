# twinflame_libsigs

A known-library **signature store** for [twinflame](https://github.com/ankorio/twinflame):
an offline builder plus a memory-mapped query reader for a large,
version-deduplicated dictionary of library class signatures, computed in
twinflame's own 128-bit signature space.

twinflame queries it to label app classes as known-library code — which feeds
`provenance.py`, demotes third-party churn in the change report, and (the reason
this exists) excludes library classes from the family side of **containment
scoring** so shared runtimes don't inflate the score.

## Status

Beta. The core pipeline is complete end-to-end — **catalogue → `scrape` →
`build` → `detect`** — and the resulting pack is consumed by twinflame's
`--libsigs` integration. What's real and tested:

- **The build pipeline** (`src/twinflame_libsigs/`): the Maven/Google-Maven
  scraper (idempotent per-coordinate cache), version-range dedup (`dedup.py`),
  and the packer that emits a single `.tflp` pack plus its coordinate sidecar.
  Driven by the `twinflame-libsigs` CLI (`scrape`/`build`/`detect`/`info`/`query`).
- **The production store — native, exact** (`native/`, Rust): a Multi-Index
  Hashing near-neighbour store (Norouzi et al., TPAMI 2014). Exact radius-`r`
  Hamming search, verified equal to brute force. Measured at R=12: **8.5 µs/query
  at 200k, 167 µs at 5M**, sub-second build; ~6× faster than the Python prototype
  and exact (vs ≥90% recall). pyo3 module `tfls_mih` lets twinflame call it
  directly. **Optional**: `detect.py` falls back to a pure-Python brute-force
  store when the native module isn't built, so the pipeline works without it —
  the native wheel is a performance accelerator, not a requirement.
- **The Python prototype** (`store.py` / `build.py`, the `.tfls` format): the
  original approximate LSH-banding store + on-disk prefix-directory study. Kept
  as design reference; superseded by the `.tflp` pack + native store above.

Not yet built:

- **Native persistence** — the MIH store is rebuilt in memory at load from the
  pack's stored signatures (sub-second, so low priority). Serializing it to its
  own mmap file is future work. See `native/README.md`.

## Requirements

- **twinflame ≥ 0.3.0b1** — the first release carrying the `--libsigs`
  integration and the `SIGNATURE_STAMP` this store's packs are validated against.
  A pack is only valid for the twinflame signature stamp it was built against.
- The **builder** additionally needs the `[build]` extra (`requests`) and an
  Android `d8` on `PATH` (from the Android SDK cmdline-tools) to turn downloaded
  `.aar`/`.jar` artifacts into DEX. The **query/reader** path needs neither —
  only the stdlib + twinflame.

## Install

```sh
pip install twinflame-libsigs              # reader + CLI (pure Python)
pip install 'twinflame-libsigs[build]'     # + scraper deps (requests); d8 must be on PATH
```

The signature **data pack** is not shipped on PyPI — it is a generated asset.
Download a prebuilt `.tflp` from the GitHub Releases page and place it at
`~/.cache/twinflame/libsigs.tflp`, where twinflame auto-discovers it. Or build
your own (below).

## Usage

Build a pack from a catalogue of Maven coordinates, then let twinflame use it:

```sh
# 1. scrape upstream releases into a local cache (idempotent; re-runnable)
twinflame-libsigs scrape -c catalogues/full-2026-07.txt -C libsigs-cache

# 2. build the deduplicated pack from the cache
twinflame-libsigs build -C libsigs-cache -o libsigs.tflp

# 3a. probe an APK directly
twinflame-libsigs detect app.apk libsigs.tflp

# 3b. or install it for twinflame's auto-discovery
cp libsigs.tflp ~/.cache/twinflame/libsigs.tflp
twinflame old.apk new.apk            # library classes now labeled / demoted
```

`twinflame --libsigs <pack>` and `$TWINFLAME_LIBSIGS` override the discovery
path. The catalogue is a plain-text list of `group:artifact  <repo>` lines; see
`catalogues/full-2026-07.txt`.

## Design & background

The full design study — why the storage layout is what it is, the finding that
twinflame's R=12 radius breaks exact *pigeonhole* (Manku) indexing, the
multi-index-hashing escape that fixes it, the measured radius, and the prior-art
survey (near-neighbour search, TPL detection, malware fingerprinting) — lives in
the workspace knowledge library (`docs/libsigs/` and `docs/knowledge-base/` at the
repo parent), which is the source of truth and is not shipped with this package.

## Boundary with twinflame

twinflame core imports only the stdlib-only reader. The builder, its
network/Maven/d8 dependencies, and the signature **data** are an offline asset
and never enter the twinflame wheel.
