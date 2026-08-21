"""Phase 2 — secret extraction over the recorded corpus.

Extraction iterates manifest rows (fetch events), not blobs: provenance
(headers, URL, status) lives on the row. Body-bearing extractors run once per
unique sha256 and fan sightings out to every row carrying that hash;
header/cookie scanning runs per row (design §8).
"""

from .core import (
    LOOSE,
    STRICT,
    Sighting,
    canonicalize,
    scan_headers,
    scan_text,
)
from .registry import EXTRACTORS, extract_blob

__all__ = [
    "LOOSE", "STRICT", "Sighting", "canonicalize",
    "scan_headers", "scan_text", "EXTRACTORS", "extract_blob",
]
