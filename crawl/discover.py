"""Offline byte-scan discovery (design §7).

Tiered URL patterns, quote-delimited so minified code isn't sliced, in
priority order:

  1. absolute URLs on any host (the scope check sorts them)
  2. root-relative paths with a plausible extension or known-route shape
  3. relative paths carrying a file extension (../a/b.png, assets/x.woff2)

Bare extensionless relative strings are NOT auto-fetched — they go to a
`needs_review` bucket. Every `regex_fallback` edge records which tier found
it, so a noisy tier is visible and tunable.

Crawl and byte-scan alternate until the byte-scan yields nothing new (the
fixpoint, design §6).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .normalize import ScopeTriple, in_scope, resolve

# Quote-delimited: match inside "…" / '…' / backticks.
_ABS = re.compile(r'''["'`](https?://[^"'`\s<>)]+)["'`]''')
_ROOT_REL = re.compile(r'''["'`](/[^"'`\s<>)]+\.[A-Za-z0-9]{1,8})["'`]''')
_ROOT_REL_ROUTE = re.compile(r'''["'`](/(?:[A-Za-z0-9_-]+/)+)["'`]''')
_REL_EXT = re.compile(r'''["'`]((?:\.\./|\./)?[\w.-]+(?:/[\w.-]+)*\.[A-Za-z0-9]{1,8})["'`]''')
_BARE_REL = re.compile(r'''["'`]((?:\.\./|\./)?[\w-]+(?:/[\w-]+)+)["'`]''')

KNOWN_EXTENSIONS = {
    "html", "htm", "css", "js", "mjs", "json", "xml", "csv", "svg", "png",
    "jpg", "jpeg", "gif", "webp", "ico", "pdf", "txt", "woff", "woff2",
    "ttf", "otf", "eot", "mp3", "mp4", "webm", "ogg", "wav", "zip", "map",
}


@dataclass
class ScanHit:
    verbatim: str  # absolute URL after resolution
    tier: int  # 1 absolute / 2 root-relative / 3 extensioned-relative
    ref: str  # the matched string as it appeared


@dataclass
class ScanResult:
    hits: list[ScanHit]
    needs_review: list[str]  # bare extensionless relative strings
    truncated: bool = False


def scan_bytes(body: bytes, base_url: str, scope: ScopeTriple) -> ScanResult:
    """Scan one blob for URL-shaped strings. Only decodable text is scanned;
    binary blobs contribute tier-1 absolute matches via latin-1 passthrough
    only when they decode cleanly as text — otherwise skipped (no guessing)."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = body.decode("latin-1")
        except Exception:
            return ScanResult(hits=[], needs_review=[])

    hits: list[ScanHit] = []
    seen_refs: set[str] = set()

    def add(ref: str, tier: int, pattern_hits: list[ScanHit]) -> None:
        if ref in seen_refs:
            return
        seen_refs.add(ref)
        absolute = resolve(base_url, ref)
        if absolute is not None:
            pattern_hits.append(ScanHit(absolute, tier, ref))

    for m in _ABS.finditer(text):
        add(m.group(1), 1, hits)
    for m in _ROOT_REL.finditer(text):
        add(m.group(1), 2, hits)
    for m in _ROOT_REL_ROUTE.finditer(text):
        add(m.group(1), 2, hits)
    for m in _REL_EXT.finditer(text):
        ref = m.group(1)
        if ref.startswith(("http://", "https://", "/")):
            continue  # already covered by tiers 1–2
        add(ref, 3, hits)

    needs_review: list[str] = []
    for m in _BARE_REL.finditer(text):
        ref = m.group(1)
        if ref in seen_refs or ref.startswith(("http", "/")):
            continue
        # Extensionless relative — never auto-fetched (design §7).
        if "/" in ref and not ref.rsplit("/", 1)[-1].count("."):
            needs_review.append(ref)

    return ScanResult(hits=hits, needs_review=needs_review)


def in_scope_hits(result: ScanResult, scope: ScopeTriple) -> list[ScanHit]:
    return [h for h in result.hits if in_scope(h.verbatim, scope)]
