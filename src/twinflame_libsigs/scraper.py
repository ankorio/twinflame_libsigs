"""Offline scraper: fetch known-library artifacts from Maven-style repositories,
convert them to DEX with `d8`, and compute twinflame signatures for their classes.

This is the *feed* side of the store and is deliberately kept out of the twinflame
core wheel (network + Android SDK `d8` dependency). It is allowed to be slow.

Pipeline per (coordinate, version):
    maven-metadata.xml  ->  pick artifact (.aar preferred, else .jar)
    .aar                ->  unzip -> classes.jar
    classes.jar / .jar  ->  d8 --min-api  ->  classes*.dex
    dex dir             ->  twinflame.prepare  ->  [(fqcn, signature, strings, #instr)]
    result              ->  <cache>/<coord>/<stem>.sigs.json     (the idempotency unit)

A version whose `.sigs.json` already exists with a matching twinflame
`SIGNATURE_STAMP` (and artifact digest, when the artifact is still on disk) is
skipped wholesale — re-running the scraper over the same catalogue only does
new work, so it can run from cron.

Version sampling is intentionally coarse: one representative (latest patch) per
`major.minor` line, pre-releases dropped — a spread of real releases, not every
sequential patch.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

# ---- repositories --------------------------------------------------------
REPOS = {
    "google-maven": "https://dl.google.com/android/maven2",
    "maven-central": "https://repo1.maven.org/maven2",
    "jitpack": "https://jitpack.io",
}

_PRERELEASE = re.compile(r"(?i)(alpha|beta|rc|snapshot|dev|preview|-m\d|eap)")
_VER_NUM = re.compile(r"^\d+(\.\d+)*")

SIGS_FORMAT = 1  # bump when the .sigs.json shape changes


def _coord_path(coord: str) -> str:
    """'androidx.appcompat:appcompat' -> 'androidx/appcompat/appcompat'."""
    group, artifact = coord.split(":")
    return f"{group.replace('.', '/')}/{artifact}"


def _coord_dir(cache: Path, coord: str) -> Path:
    return cache / _coord_path(coord).replace("/", "__")


def _http_get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "twinflame-libsigs/0.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


# ---- version discovery + sampling ---------------------------------------
def list_versions(coord: str, repo: str) -> List[str]:
    """All published versions from the repo's maven-metadata.xml."""
    base = REPOS[repo]
    url = f"{base}/{_coord_path(coord)}/maven-metadata.xml"
    root = ET.fromstring(_http_get(url))
    return [v.text for v in root.findall(".//versions/version") if v.text]


def ver_key(v: str) -> Tuple[int, ...]:
    m = _VER_NUM.match(v)
    nums = m.group(0).split(".") if m else []
    return tuple(int(x) for x in nums) if nums else (0,)


def sample_major_versions(versions: Iterable[str], max_n: int = 8,
                          include_prerelease: bool = False) -> List[str]:
    """One representative (latest patch) per major.minor line; pre-releases
    dropped unless asked. If more than `max_n` remain, keep an even spread that
    always includes the oldest and newest."""
    stable = [v for v in versions
              if include_prerelease or not _PRERELEASE.search(v)]
    by_minor: dict[Tuple[int, int], str] = {}
    for v in stable:
        k = ver_key(v)
        mm = (k[0], k[1] if len(k) > 1 else 0)
        if mm not in by_minor or ver_key(v) > ver_key(by_minor[mm]):
            by_minor[mm] = v
    picked = sorted(by_minor.values(), key=ver_key)
    if len(picked) <= max_n:
        return picked
    # even spread, keep endpoints
    idx = sorted({round(i * (len(picked) - 1) / (max_n - 1)) for i in range(max_n)})
    return [picked[i] for i in idx]


# ---- download + dex ------------------------------------------------------
@dataclass(frozen=True)
class ScrapedClass:
    fqcn: str
    signature: int            # twinflame 128-bit combined signature
    strings: Tuple[str, ...]  # class string constants (Tier-3 anchor source)
    instructions: int         # total instruction count (min-instr precision filter)


@dataclass
class Artifact:
    coord: str
    version: str
    repo: str
    packaging: str            # 'aar' | 'jar'
    path: Path                # downloaded file
    digest: str = ""          # sha256 of the downloaded file
    dex_dir: Optional[Path] = None
    classes: List[ScrapedClass] = field(default_factory=list)
    error: str = ""
    from_cache: bool = False  # classes came from a .sigs.json, not a fresh run
    sig_stamp: str = ""       # twinflame SIGNATURE_STAMP the classes were computed under


def download(coord: str, version: str, repo: str, cache: Path) -> Artifact:
    base = REPOS[repo]
    _, artifact = coord.split(":")
    stem = f"{artifact}-{version}"
    dest_dir = _coord_dir(cache, coord)
    dest_dir.mkdir(parents=True, exist_ok=True)
    last_err = ""
    for pkg in ("aar", "jar"):
        url = f"{base}/{_coord_path(coord)}/{version}/{stem}.{pkg}"
        dest = dest_dir / f"{stem}.{pkg}"
        if dest.exists() and dest.stat().st_size > 0:
            return Artifact(coord, version, repo, pkg, dest,
                            digest=_sha256(dest))
        try:
            data = _http_get(url)
            dest.write_bytes(data)
            return Artifact(coord, version, repo, pkg, dest,
                            digest=hashlib.sha256(data).hexdigest())
        except urllib.error.HTTPError as e:
            last_err = f"{pkg}: HTTP {e.code}"
        except Exception as e:  # noqa: BLE001
            last_err = f"{pkg}: {e}"
    return Artifact(coord, version, repo, "?", dest_dir / stem, error=last_err or "not found")


def _sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _find_d8() -> str:
    home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if home:
        bts = sorted((Path(home) / "build-tools").glob("*/d8"),
                     key=lambda p: ver_key(p.parent.name), reverse=True)
        if bts:
            return str(bts[0])
    d8 = shutil.which("d8")
    if d8:
        return d8
    raise FileNotFoundError("d8 not found; set ANDROID_HOME or put d8 on PATH")


def artifact_to_dex(art: Artifact, workdir: Path, min_api: int = 21) -> Artifact:
    """.aar/.jar -> a directory containing classes*.dex."""
    d8 = _find_d8()
    work = workdir / f"{Path(art.path).stem}"
    work.mkdir(parents=True, exist_ok=True)
    if art.packaging == "aar":
        with zipfile.ZipFile(art.path) as z:
            jar = work / "classes.jar"
            try:
                jar.write_bytes(z.read("classes.jar"))
            except KeyError:
                art.error = "aar has no classes.jar"
                return art
        code_jar = jar
    else:
        code_jar = art.path
    out = work / "dex"
    out.mkdir(exist_ok=True)
    proc = subprocess.run(
        [d8, "--min-api", str(min_api), "--output", str(out), str(code_jar)],
        capture_output=True, text=True)
    dex_files = list(out.glob("*.dex"))
    if not dex_files:
        art.error = f"d8 produced no dex (rc={proc.returncode}): {proc.stderr[-300:]}"
        return art
    art.dex_dir = out
    return art


def signatures_for(art: Artifact) -> Artifact:
    """Compute twinflame signatures for every class in the dexed artifact."""
    from twinflame.prepare import SIGNATURE_STAMP, prepare
    rec = prepare(str(art.dex_dir))
    art.sig_stamp = SIGNATURE_STAMP
    out: List[ScrapedClass] = []
    for c in rec.classes:
        if c.signature is None:
            continue
        fq = f"{c.package}.{c.name}" if c.package else c.name
        out.append(ScrapedClass(fqcn=fq, signature=c.signature.combined,
                                strings=tuple(c.strings),
                                instructions=c.total_instructions))
    art.classes = out
    return art


# ---- per-version persistence (the idempotency unit) ----------------------
def sigs_path(cache: Path, coord: str, version: str) -> Path:
    _, artifact = coord.split(":")
    return _coord_dir(cache, coord) / f"{artifact}-{version}.sigs.json"


def save_sigs(art: Artifact, cache: Path) -> Path:
    from twinflame.prepare import SIGNATURE_STAMP
    p = sigs_path(cache, art.coord, art.version)
    doc = {
        "format": SIGS_FORMAT,
        "coord": art.coord,
        "version": art.version,
        "repo": art.repo,
        "packaging": art.packaging,
        "digest": art.digest,
        "sig_stamp": SIGNATURE_STAMP,
        "classes": [
            [c.fqcn, f"{c.signature:032x}", list(c.strings), c.instructions]
            for c in art.classes
        ],
    }
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc))
    tmp.replace(p)
    return p


def load_sigs(p: Path) -> Optional[Artifact]:
    """Read a persisted per-version result; None if unreadable/stale-format.
    The `SIGNATURE_STAMP` check is the caller's (it decides staleness policy)."""
    try:
        doc = json.loads(p.read_text())
        if doc.get("format") != SIGS_FORMAT:
            return None
        art = Artifact(doc["coord"], doc["version"], doc["repo"],
                       doc["packaging"], p, digest=doc["digest"], from_cache=True)
        art.classes = [
            ScrapedClass(fqcn=fq, signature=int(sig, 16),
                         strings=tuple(strings), instructions=n)
            for fq, sig, strings, n in doc["classes"]
        ]
        art.sig_stamp = doc["sig_stamp"]
        return art
    except (OSError, ValueError, KeyError):
        return None


def _cached_result(coord: str, version: str, cache: Path) -> Optional[Artifact]:
    """A previously scraped version we can reuse: sigs.json present, twinflame's
    current SIGNATURE_STAMP, and — when the artifact file is still on disk —
    a matching digest. (Digest is trusted when the artifact was cleaned up, so
    offline re-runs stay idempotent.)"""
    from twinflame.prepare import SIGNATURE_STAMP
    p = sigs_path(cache, coord, version)
    if not p.exists():
        return None
    art = load_sigs(p)
    if art is None or art.sig_stamp != SIGNATURE_STAMP:
        return None
    _, artifact = coord.split(":")
    on_disk = _coord_dir(cache, coord) / f"{artifact}-{version}.{art.packaging}"
    if on_disk.exists() and _sha256(on_disk) != art.digest:
        return None
    return art


# ---- orchestration -------------------------------------------------------
def _fetch_and_dex(coord: str, version: str, repo: str, cache: Path) -> Artifact:
    """Download + dex one version, falling back to a KMP sibling artifact when
    the primary has no bytecode (Kotlin-multiplatform releases publish an
    empty/redirect primary): `<artifact>-jvm` (Square convention — okhttp 5.x,
    okio 3.x) or `<artifact>-android` (androidx convention — lifecycle >= 2.8.7,
    collection >= 1.3). The result keeps the canonical coordinate so
    attribution stays stable."""
    art = download(coord, version, repo, cache)
    if not art.error:
        art = artifact_to_dex(art, cache / "dex")
    if art.error and ("no dex" in art.error or "no classes.jar" in art.error
                      or "not found" in art.error):
        group, artifact = coord.split(":")
        for suffix in ("-jvm", "-android"):
            alt = download(f"{group}:{artifact}{suffix}", version, repo, cache)
            if not alt.error:
                alt = artifact_to_dex(alt, cache / "dex")
            if not alt.error:
                alt.coord = coord
                return alt
    return art


def scrape_library(coord: str, repo: str, cache: Path, *, max_versions: int = 8,
                   log=print) -> List[Artifact]:
    """Full pipeline for one coordinate across a sampled set of versions.
    Versions already in the cache (matching stamp + digest) are not re-scraped."""
    versions = list_versions(coord, repo)
    picked = sample_major_versions(versions, max_n=max_versions)
    log(f"[{coord}] {len(versions)} published -> {len(picked)} sampled: {', '.join(picked)}")
    arts: List[Artifact] = []
    for v in picked:
        cached = _cached_result(coord, v, cache)
        if cached is not None:
            log(f"    {v:<12} cached  {len(cached.classes):>5} classes")
            arts.append(cached)
            continue
        art = _fetch_and_dex(coord, v, repo, cache)
        if art.error:
            log(f"    {v:<12} FAILED: {art.error}")
            arts.append(art); continue
        art = signatures_for(art)
        save_sigs(art, cache)
        log(f"    {v:<12} {art.packaging}  {len(art.classes):>5} classes  ({art.path.stat().st_size//1024} KB)")
        arts.append(art)
    return arts


def scrape_catalogue(entries, cache: Path, *, max_versions: int = 8,
                     log=print) -> dict[str, List[Artifact]]:
    """Scrape every catalogue entry; per-coordinate failures don't stop the run."""
    results: dict[str, List[Artifact]] = {}
    for e in entries:
        try:
            results[e.coord] = scrape_library(e.coord, e.repo, cache,
                                              max_versions=max_versions, log=log)
        except Exception as exc:  # noqa: BLE001 - a cron feed must survive one bad coord
            log(f"[{e.coord}] FAILED: {exc}")
            results[e.coord] = []
    return results


def iter_cached_sigs(cache: Path) -> Iterable[Artifact]:
    """Every persisted .sigs.json under the cache — the builder's input."""
    for p in sorted(cache.glob("*/*.sigs.json")):
        art = load_sigs(p)
        if art is not None:
            yield art
