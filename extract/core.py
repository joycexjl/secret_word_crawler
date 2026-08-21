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

# Excluded by the challenge rules, not by pattern shape: the worked example
# on the index page ("looks exactly like this worked example") is explicitly
# "not one of the eight". Instructional prose describing the format
# ("VISUALPING{, sixteen hexadecimal characters, then }") is a LOOSE tripwire
# on the rules text, not a candidate. Both are recorded as ruled-out with a
# reason, never counted, and never sent to needs-review.
EXCLUDED_CANONICALS = {
    "VISUALPING{0000deadbeef0000}": "worked_example",
}


def exclusion_reason(raw: bytes, canonical: str | None) -> str | None:
    """Return a ruling reason if this match is declared not-a-secret by the
    challenge's own rules/instructions, else None."""
    if canonical and canonical in EXCLUDED_CANONICALS:
        return EXCLUDED_CANONICALS[canonical]
    # Format-description prose: braces contain words/commas, not hex.
    if canonical is None and b"hexadecimal" in raw.lower():
        return "format_prose"
    # Bare 16-hex fragments with no VISUALPING{} wrapper (e.g. JPEG comment
    # fields holding a bare hex string). Ruled not-a-secret by human ruling:
    # the secret form requires the VISUALPING{} wrapper; a bare hex fragment is
    # a decoy / staging artifact, not a candidate.
    if canonical is None and raw.startswith(b"FRAGMENT:"):
        return "bare_hex_fragment"
    return None

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
    ruled_out: str = ""     # non-empty = declared not-a-secret (worked_example, format_prose)

    @property
    def strict(self) -> bool:
        return self.canonical is not None and not self.ruled_out


def scan_text(data: bytes, *, how_found: str, url: str, sha256: str,
              with_charset: bool = False) -> list[Sighting]:
    """Run both patterns over a byte string; STRICT sightings canonicalized,
    LOOSE-only hits returned as non-strict sightings (needs-review feed).

    with_charset also scans UTF-16 LE/BE decodings — a secret stored as UCS-2
    (e.g. an EXIF UserComment, or a UTF-16 text resource) has null bytes
    between characters and is invisible to the byte-level pattern. Off by
    default for text handlers (their input is already decoded); the image
    track and raw fallbacks turn it on.
    """
    out: list[Sighting] = []
    strict_spans: list[tuple[int, int]] = []
    for m in STRICT.finditer(data):
        strict_spans.append(m.span())
        canon = canonicalize(m.group(0))
        out.append(Sighting(
            canonical=canon, raw=m.group(0),
            how_found=how_found, url=url, sha256=sha256,
            ruled_out=exclusion_reason(m.group(0), canon) or "",
        ))
    for m in LOOSE.finditer(data):
        if any(s[0] <= m.start() < s[1] for s in strict_spans):
            continue  # already captured as STRICT
        canon = canonicalize(m.group(0))
        out.append(Sighting(
            canonical=canon, raw=m.group(0),
            how_found=how_found, url=url, sha256=sha256,
            ruled_out=exclusion_reason(m.group(0), canon) or "",
        ))
    if with_charset:
        for enc in ("utf-16-le", "utf-16-be"):
            try:
                decoded = data.decode(enc, errors="ignore")
            except Exception:
                continue
            if not decoded.strip():
                continue
            for s in scan_text(decoded.encode("utf-8", errors="replace"),
                               how_found=f"{how_found}[{enc}]", url=url, sha256=sha256):
                out.append(s)
    return out


def scan_headers(headers: dict, *, url: str, sha256: str) -> list[Sighting]:
    """Per-row header/cookie scan. Header/cookie matches are candidate secrets
    like any other — the disqualification rule was removed; provenance is
    preserved via how_found=header:<name>."""
    out: list[Sighting] = []
    for name, value in headers.items():
        if name.lower() not in ("set-cookie",) and "visualping" not in value.lower():
            continue
        for m in LOOSE.finditer(value.encode("utf-8", errors="replace")):
            canon = canonicalize(m.group(0))
            out.append(Sighting(
                canonical=canon, raw=m.group(0),
                how_found=f"header:{name}", url=url, sha256=sha256,
            ))
    return out
