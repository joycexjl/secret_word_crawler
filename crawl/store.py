"""Content-addressed blob store + append-only manifest.

- blobs/<sha256>  raw response bodies (immutable, provenance-free)
- manifest.jsonl  one record per fetch event (design §5 schema)

Many fetch events can share one blob; extraction over bodies runs once per
unique blob and fans sightings out to every manifest row carrying the hash.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

# Small magic-byte signature table (design §7 — `python-magic` optional later).
_SIGNATURES: list[tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"%PDF-", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"wOFF", "font/woff"),
    (b"wOF2", "font/woff2"),
    (b"\x00\x01\x00\x00\x00", "font/ttf"),
    (b"OggS", "application/ogg"),
    (b"RIFF", "application/riff"),
    (b"\x1f\x8b", "application/gzip"),
    (b"ID3", "audio/mpeg"),
]


def sniff_type(body: bytes) -> str:
    """Content type from magic bytes; '' when nothing matches."""
    head = body[:64]
    for sig, ctype in _SIGNATURES:
        if head.startswith(sig):
            return ctype
    stripped = body[:512].lstrip()
    low = stripped[:64].lower()
    if low.startswith((b"<!doctype html", b"<html")):
        return "text/html"
    if low.startswith(b"<?xml"):
        if b"<svg" in stripped[:1024].lower():
            return "image/svg+xml"
        return "application/xml"
    if low.startswith(b"<svg"):
        return "image/svg+xml"
    try:
        body[:4096].decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return "application/octet-stream" if body else ""
    if stripped.startswith((b"{", b"[")):
        return "application/json"
    return "text/plain"


def url_ext(url: str) -> str:
    """Extension from the URL path (lowercased, no dot); '' if none."""
    from urllib.parse import urlsplit

    name = urlsplit(url).path.rsplit("/", 1)[-1]
    if "." in name and not name.startswith("."):
        return name.rsplit(".", 1)[-1].lower()
    return ""


def normalize_content_type(header_value: str | None) -> str:
    """Lowercased, parameters stripped; '' when absent."""
    if not header_value:
        return ""
    return header_value.split(";", 1)[0].strip().lower()


class BlobStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.blobs_dir = self.root / "blobs"
        self.blobs_dir.mkdir(parents=True, exist_ok=True)

    def put(self, body: bytes) -> str:
        """Store body content-addressed; returns sha256 hex."""
        digest = hashlib.sha256(body).hexdigest()
        path = self.blobs_dir / digest
        if not path.exists():
            path.write_bytes(body)
        return digest

    def get(self, sha256: str) -> bytes:
        return (self.blobs_dir / sha256).read_bytes()


class Manifest:
    """Append-only manifest.jsonl — one record per fetch event."""

    def __init__(self, root: Path):
        self.path = Path(root) / "manifest.jsonl"
        self._fh = self.path.open("a", encoding="utf-8")

    def write(self, record: dict) -> None:
        self._fh.write(json.dumps(record, sort_keys=True) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_record(
    *,
    url: str,
    canon: str,
    final_url: str,
    status: int,
    content_type_header: str | None,
    headers: dict,
    body: bytes,
    sha256: str,
    first_seen_depth: int,
    retries: int = 0,
) -> dict:
    """Build a §5 manifest record. rendered_sha256 / idle_timeout /
    blocked_notice default to M1 values; M2/M3 fill them in."""
    return {
        "url": url,
        "canon_key": canon,
        "final_url": final_url,
        "status": status,
        "content_type": normalize_content_type(content_type_header),
        "url_ext": url_ext(url),
        "sniffed_type": sniff_type(body),
        "sha256": sha256,
        "rendered_sha256": None,
        "length": len(body),
        "headers": headers,
        "first_seen_depth": first_seen_depth,
        "retries": retries,
        "idle_timeout": False,
        "blocked_notice": False,
        "fetched_at": now_iso(),
    }
