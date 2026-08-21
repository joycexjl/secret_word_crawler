"""URL canonicalisation, resolution, and scope check.

The single place where bugs silently cost pages (design §6), so this module is
pure and unit-tested up front.

Identity model (CONTEXT.md):
  - verbatim URL: exactly as discovered; what goes on the wire and into edge
    records. Never fabricated.
  - canon key: dedup/frontier/graph identity — scheme/host lowercased, default
    port stripped, path normalised, query parameters SORTED, fragment dropped.
    The sorted form is a key, never a request target.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class ScopeTriple:
    scheme: str
    host: str
    port: int


def _split_port(netloc: str) -> tuple[str, int | None]:
    """Split host[:port]; IPv6 literals kept bracketed."""
    if netloc.startswith("["):
        end = netloc.find("]")
        host = netloc[: end + 1]
        rest = netloc[end + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, None
    if ":" in netloc:
        host, _, port = netloc.rpartition(":")
        if port.isdigit():
            return host, int(port)
        return netloc, None
    return netloc, None


def normalize_path(path: str) -> str:
    """Resolve `.`/`..` segments; preserve trailing slash and emptiness."""
    if not path:
        return path
    trailing = path.endswith("/")
    normed = posixpath.normpath(path)
    if path.startswith("/") and not normed.startswith("/"):
        normed = "/" + normed
    if trailing and not normed.endswith("/"):
        normed += "/"
    if normed == "." and not path.startswith("."):
        normed = ""
    return normed


def canon_key(url: str) -> str:
    """Canonical identity: lower scheme/host, default port stripped, path
    normalised, query params sorted, fragment dropped."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host, port = _split_port(parts.netloc)
    host = host.lower()
    netloc = host
    if port is not None and port != DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{port}"
    path = normalize_path(parts.path)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    pairs.sort()
    query = urlencode(pairs)
    return urlunsplit((scheme, netloc, path, query, ""))


def scope_triple(url: str) -> ScopeTriple | None:
    """Effective (scheme, host, port) with default-port fill-in; None if the
    URL has no host (relative reference handed here by mistake)."""
    parts = urlsplit(url)
    if not parts.netloc:
        return None
    scheme = parts.scheme.lower()
    host, port = _split_port(parts.netloc)
    if port is None:
        port = DEFAULT_PORTS.get(scheme)
        if port is None:
            return None
    return ScopeTriple(scheme, host.lower(), port)


def in_scope(url: str, scope: ScopeTriple) -> bool:
    t = scope_triple(url)
    return t is not None and t == scope


def resolve(base: str, ref: str) -> str | None:
    """Resolve ref against the per-document base URL. Returns an absolute URL
    or None for non-HTTP(S) schemes / unresolvable refs.

    The base is the *page's* `<base href>` when present, else the page URL;
    the caller (Tier 0 harvest) threads it in (design §6).
    """
    from urllib.parse import urljoin

    ref = ref.strip()
    if not ref or ref.startswith("#"):
        return None
    if re.match(r"(?i)^(data|javascript|mailto|tel|blob|about):", ref):
        return None
    absolute = urljoin(base, ref)
    parts = urlsplit(absolute)
    if parts.scheme.lower() not in ("http", "https"):
        return None
    if not parts.netloc:
        return None
    return absolute
