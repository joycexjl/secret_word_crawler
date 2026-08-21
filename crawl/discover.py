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

# CSS-specific reference forms (ADR 0002): the tiered patterns are
# quote-delimited, but CSS's signature forms — url(...) unquoted, @import —
# slip through. These run over CSS blobs and inline style text alike; data:
# URIs and #fragment refs fall out at resolve()/scope-check like everything
# else (no special-casing).
_CSS_URL = re.compile(r"""url\(\s*['"]?([^'")]+?)['"]?\s*\)""")
_CSS_IMPORT = re.compile(r"""@import\s+(?:url\(\s*)?['"]([^'"]+)['"]""")

# Sourcemap reference (ADR 0002): the //# sourceMappingURL= comment is
# quote-free, so the tiered patterns can miss it; a dedicated pre-pass gives
# the edge how=sourcemap attribution instead of regex_fallback.
_SOURCEMAP = re.compile(r"^[ \t]*//[#@]\s*sourceMappingURL=(\S+)", re.MULTILINE)

KNOWN_EXTENSIONS = {
    "html", "htm", "css", "js", "mjs", "json", "xml", "csv", "svg", "png",
    "jpg", "jpeg", "gif", "webp", "ico", "pdf", "txt", "woff", "woff2",
    "ttf", "otf", "eot", "mp3", "mp4", "webm", "ogg", "wav", "zip", "map",
    "vtt", "webmanifest",
}


@dataclass
class ScanHit:
    verbatim: str  # absolute URL after resolution
    tier: int  # 1 absolute / 2 root-relative / 3 extensioned-relative / 0 mechanism-specific
    ref: str  # the matched string as it appeared
    how: str = ""  # edge attribution; "" collapses to regex_fallback(tierN)
    hint: str = ""  # rel value / header name context for the edge record


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

    def add(ref: str, tier: int, pattern_hits: list[ScanHit], how: str = "") -> None:
        if ref in seen_refs:
            return
        seen_refs.add(ref)
        absolute = resolve(base_url, ref)
        if absolute is not None:
            pattern_hits.append(ScanHit(absolute, tier, ref, how))

    # Mechanism-specific pre-passes run first so their attribution wins.
    for m in _SOURCEMAP.finditer(text):
        add(m.group(1), 2, hits, how="sourcemap")
    for m in _CSS_URL.finditer(text):
        add(m.group(1), 2, hits, how="css_url")
    for m in _CSS_IMPORT.finditer(text):
        add(m.group(1), 2, hits, how="css_url")
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
    # Declared paths in robots/sitemap-style files: "Disallow: /path",
    # "Allow: /path", "<loc>/path</loc>" — bare declarations, not quoted URLs,
    # so the tiered patterns miss them (M6 grilling: robots Disallow maps
    # no-inbound-link pages).
    for m in re.finditer(r"(?im)^\s*(?:Disallow|Allow)\s*:\s*(/\S*)", text):
        add(m.group(1), 2, hits)
    for m in re.finditer(r"<loc>\s*(https?://[^<]+|/[^<]+?)\s*</loc>", text, re.I):
        add(m.group(1), 2, hits)

    needs_review: list[str] = []
    for m in _BARE_REL.finditer(text):
        ref = m.group(1)
        if ref in seen_refs or ref.startswith(("http", "/")):
            continue
        # Extensionless relative — never auto-fetched (design §7).
        if "/" in ref and not ref.rsplit("/", 1)[-1].count("."):
            needs_review.append(ref)

    return ScanResult(hits=hits, needs_review=needs_review)


# -- offline scanners over stored fetch artifacts (ADR 0002) ------------------
# These run against manifest rows / blobs, not the live crawl: re-runnable
# against an existing out/ without re-requesting, and the crawl loop stays
# GET-and-store.

_LINK_HEADER_ENTRIES = re.compile(r""",\s*(?=<)""")  # split on commas that open a new <...>
_LINK_HEADER_ONE = re.compile(r"""<([^>]*)>\s*((?:;[^,]*)?)""")
_LINK_REL = re.compile(r""";\s*rel\s*=\s*"?([^";]+)"?""")


def scan_link_header(value: str, base_url: str) -> list[ScanHit]:
    """RFC 8288 `Link:` header, parsed structurally. rel value becomes the ref
    hint; entries go through the same resolve() as every other surface."""
    hits: list[ScanHit] = []
    for part in _LINK_HEADER_ENTRIES.split(value):
        m = _LINK_HEADER_ONE.match(part.strip())
        if not m:
            continue
        target, params = m.group(1).strip(), m.group(2)
        rel_m = _LINK_REL.search(params)
        rel = rel_m.group(1).strip() if rel_m else ""
        absolute = resolve(base_url, target)
        if absolute is not None:
            hits.append(ScanHit(absolute, 0, target,
                                how="http_link_header", hint=rel))
    return hits


def scan_header_values(headers: dict, base_url: str) -> list[ScanHit]:
    """Every other response header value gets the tiered pattern scan
    (`how=http_header:<name>`) — this author has form for custom headers.
    `link` is handled structurally above; `location` is excluded (redirects
    are the fetch layer's job — scanning it would double-count)."""
    hits: list[ScanHit] = []
    seen: set[str] = set()
    for name, value in headers.items():
        lname = name.lower()
        if lname == "link":
            for h in scan_link_header(value, base_url):
                if h.verbatim not in seen:
                    seen.add(h.verbatim)
                    hits.append(h)
            continue
        if lname == "location":
            continue
        for m in _ABS.finditer(str(value)):
            absolute = m.group(1)
            if absolute not in seen:
                seen.add(absolute)
                hits.append(ScanHit(absolute, 0, m.group(1),
                                    how=f"http_header:{lname}"))
        for m in _ROOT_REL.finditer(str(value)):
            absolute = resolve(base_url, m.group(1))
            if absolute is not None and absolute not in seen:
                seen.add(absolute)
                hits.append(ScanHit(absolute, 0, m.group(1),
                                    how=f"http_header:{lname}"))
    return hits


def scan_json_values(body: bytes, base_url: str) -> list[ScanHit]:
    """URL-shaped strings anywhere in a JSON blob (ADR 0002): one mechanism
    covers web manifests (start_url/icons/shortcuts), sourcemap `sources`
    arrays, and any config.json. The hint is the JSON path — no field-name
    semantics. Tier discipline applies: absolute + root-relative +
    extensioned-relative auto-fetch; bare extensionless strings are ignored
    here (the blob's own byte-scan already buckets them for review)."""
    import json as _json

    try:
        data = _json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return []

    hits: list[ScanHit] = []
    seen: set[str] = set()

    def consider(ref: str) -> None:
        ref = ref.strip()
        if not ref or ref in seen:
            return
        if ref.startswith(("http://", "https://")):
            absolute = ref
        elif ref.startswith(("/", "./", "../")):
            absolute = resolve(base_url, ref)
            if absolute is None:
                return
        else:
            return  # bare relative — needs-review discipline lives in scan_bytes
        seen.add(ref)
        hits.append(ScanHit(absolute, 0, ref, how="json_value"))

    def walk(node) -> None:
        if isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
        elif isinstance(node, str):
            consider(node)

    walk(data)
    return hits


def in_scope_hits(result: ScanResult, scope: ScopeTriple) -> list[ScanHit]:
    return [h for h in result.hits if in_scope(h.verbatim, scope)]
