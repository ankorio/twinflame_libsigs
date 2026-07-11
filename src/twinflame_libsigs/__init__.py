"""twinflame_libsigs — a known-library signature store for twinflame.

Offline builder (`build`) + memory-mapped query reader (`store`) for a large,
version-deduplicated dictionary of library class signatures, computed in
twinflame's own 128-bit signature space. The tool queries it to label app
classes as known-library code (feeding provenance, demoting library churn in
the change report, and excluding libraries from the family side of containment
scoring).

This package depends on twinflame as a library for signature *content*; the
scraper / d8 toolchain that feeds the builder is offline-only and never enters
the twinflame core distribution. See the storage design study.
"""

from .detect import Detection, LibraryDetector
from .layout import Header
from .store import LibSigStore, StaleStoreError
from .strings import StringAnchorIndex

__all__ = ["LibSigStore", "StaleStoreError", "Header", "StringAnchorIndex",
           "LibraryDetector", "Detection"]
__version__ = "0.0.1"
