"""Extraction core: the two patterns, canonical normalization, sighting model.

Canonical form (CONTEXT.md): `VISUALPING{` + exactly 16 lowercase hex + `}`.
Sightings are normalized — hex case-folded, whitespace inside braces stripped
— before comparison, and the distinct-count target (8) counts canonical
STRICT-validated values only.

Challenge rules: secrets in response headers or cookies are staging
placeholders — disqualified. They are still recorded and reported (one summary
line), but excluded from the distinct count and from needs-review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# The two patterns, always (design §8). LOOSE is a tripwire: hits that fail
# STRICT go to the needs-review bucket and must exit via a documented ruling.
STRICT = re.compile(rb"VISUALPING\{[0-9a-f]{16}\}")
LOOSE = re.compile(rb"VISUALPING\s*\{[^}]{0,80}\}")

_HEX16 = re.compile(r"^[0-9a-f]{16}$")


def canonicalize(raw: bytes) -> str | None:
    """Normalize a raw LOOSE match to canonical form; None if it cannot be a
    valid secret. Case-folds hex, strips whitespace inside braces."""
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return None
    m = re.match(r"(?i)VISUALPING\s*\{\s*([0-9a-fA-F]{16})\s*\}", text)
    if not m:
        return None
    return "VISUALPING{" + m.group(1).lower() + "}"


@dataclass
class Sighting:
    """One observed candidate. `canonical` is set when STRICT-validated;
    LOOSE-only sightings carry the raw bytes and land in needs-review."""
    canonical: str | None
    raw: bytes
    how_found: str          # extractor id or 'manual_review'
    url: str                # provenance: the fetch event
    sha256: str
    disqualified: bool = False
    disqualified_reason: str = ""

    @property
    def strict(self) -> bool:
        return self.canonical is not None


def scan_text(data: bytes, *, how_found: str, url: str, sha256: str) -> list[Sighting]:
    """Run both patterns over a byte string; STRICT sightings canonicalized,
    LOOSE-only hits returned as non-strict sightings (needs-review feed)."""
    out: list[Sighting] = []
    strict_spans: list[tuple[int, int]] = []
    for m in STRICT.finditer(data):
        strict_spans.append(m.span())
        out.append(Sighting(
            canonical=canonicalize(m.group(0)), raw=m.group(0),
            how_found=how_found, url=url, sha256=sha256,
        ))
    for m in LOOSE.finditer(data):
        if any(s[0] <= m.start() < s[1] for s in strict_spans):
            continue  # already captured as STRICT
        canon = canonicalize(m.group(0))
        out.append(Sighting(
            canonical=canon, raw=m.group(0),
            how_found=how_found, url=url, sha256=sha256,
        ))
    return out


def scan_headers(headers: dict, *, url: str, sha256: str) -> list[Sighting]:
    """Per-row header/cookie scan. Matches are disqualified per the challenge
    rule (staging placeholders) — recorded, reported, excluded from the count."""
    out: list[Sighting] = []
    for name, value in headers.items():
        if name.lower() not in ("set-cookie",) and "visualping" not in value.lower():
            continue
        for m in LOOSE.finditer(value.encode("utf-8", errors="replace")):
            canon = canonicalize(m.group(0))
            out.append(Sighting(
                canonical=canon, raw=m.group(0),
                how_found=f"header:{name}", url=url, sha256=sha256,
                disqualified=True, disqualified_reason="header_rule",
            ))
    return out
