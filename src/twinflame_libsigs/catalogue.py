"""The library catalogue — which (coordinate, repository) pairs the scraper
feeds from.

A catalogue is a plain-text format so it can live outside the wheel and be
extended without code changes:

    # comment
    com.squareup.okhttp3:okhttp        maven-central
    androidx.appcompat:appcompat       google-maven

The built-in seed below is the classic "found in every APK" set — the same
territory LibScout's profile collection covers (AndroidX/support, Google
Play services fringe, Square, Kotlin, the big JSON/image/reactive libraries)
— expressed as coordinates rather than binary profiles, since our pipeline
re-derives signatures from the artifacts themselves.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List


@dataclass(frozen=True)
class CatalogueEntry:
    coord: str   # "group:artifact"
    repo: str    # key into scraper.REPOS


SEED_TEXT = """
# --- AndroidX (google-maven) ---------------------------------------------
androidx.appcompat:appcompat                       google-maven
androidx.core:core                                 google-maven
androidx.fragment:fragment                         google-maven
androidx.recyclerview:recyclerview                 google-maven
androidx.constraintlayout:constraintlayout        google-maven
androidx.lifecycle:lifecycle-runtime               google-maven
androidx.lifecycle:lifecycle-viewmodel             google-maven
androidx.room:room-runtime                         google-maven
androidx.work:work-runtime                         google-maven
com.google.android.material:material               google-maven

# --- Kotlin runtime (maven-central) ---------------------------------------
org.jetbrains.kotlin:kotlin-stdlib                 maven-central
org.jetbrains.kotlinx:kotlinx-coroutines-core      maven-central
org.jetbrains.kotlinx:kotlinx-coroutines-android   maven-central

# --- Square stack ----------------------------------------------------------
com.squareup.okhttp3:okhttp                        maven-central
com.squareup.okio:okio                             maven-central
com.squareup.retrofit2:retrofit                    maven-central
com.squareup.picasso:picasso                       maven-central
com.squareup.moshi:moshi                           maven-central

# --- JSON / serialization ---------------------------------------------------
com.google.code.gson:gson                          maven-central
com.fasterxml.jackson.core:jackson-databind        maven-central

# --- images / UI ------------------------------------------------------------
com.github.bumptech.glide:glide                    maven-central
com.airbnb.android:lottie                          maven-central

# --- reactive / events ------------------------------------------------------
io.reactivex.rxjava2:rxjava                        maven-central
io.reactivex.rxjava3:rxjava                        maven-central
org.greenrobot:eventbus                            maven-central

# --- misc classics ----------------------------------------------------------
com.jakewharton.timber:timber                      maven-central
com.google.guava:guava                             maven-central
"""


def parse_catalogue(text: str) -> List[CatalogueEntry]:
    """Parse the two-column text format; blank lines and `#` comments ignored."""
    entries: List[CatalogueEntry] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2 or ":" not in parts[0]:
            raise ValueError(f"catalogue line {lineno}: expected 'group:artifact repo', got {raw!r}")
        entries.append(CatalogueEntry(coord=parts[0], repo=parts[1]))
    return entries


def parse_catalogue_json(text: str) -> List[CatalogueEntry]:
    """The corpus-inventory JSON shape (`bench_results/scrape_seed_libraries.json`):
    a list of {"coordinate": ..., "repository": ..., ...}, ordered by how many
    corpus apps bundle the library. Extra keys are ignored."""
    import json
    doc = json.loads(text)
    seen: set = set()
    entries: List[CatalogueEntry] = []
    for item in doc:
        coord, repo = item["coordinate"], item["repository"]
        if coord not in seen:
            seen.add(coord)
            entries.append(CatalogueEntry(coord=coord, repo=repo))
    return entries


def load_catalogue(path: str | Path | None = None) -> List[CatalogueEntry]:
    """The seed catalogue, or the one at `path` if given (two-column text, or
    the corpus-inventory JSON when the file ends in .json)."""
    if path is None:
        return parse_catalogue(SEED_TEXT)
    p = Path(path)
    if p.suffix == ".json":
        return parse_catalogue_json(p.read_text())
    return parse_catalogue(p.read_text())
