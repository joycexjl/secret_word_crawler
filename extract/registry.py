"""Extractor registry keyed by content-type prefix (design §8).

Each handler receives the blob bytes and yields *text surfaces* — byte
strings worth grepping with STRICT/LOOSE — tagged with a sub-mechanism so
the report can say where in the resource a secret lived (comment, string
literal, text layer, …).

The registry's key set is also M3's unhandled-types detector: a content type
the site served that matches no handler here is a named Phase 2 gap.
"""

from __future__ import annotations

import base64
import binascii
import csv
import html as html_mod
import io
import json
import re
from urllib.parse import unquote_to_bytes
from xml.etree import ElementTree

# handler id -> (content-type prefixes, callable)
# callable(body: bytes) -> list[tuple[sub_mechanism, bytes]]


def _surfaces_html(body: bytes) -> list[tuple[str, bytes]]:
    """HTML: tags stripped (so a word split across <span>s still matches),
    plus comments and display:none content explicitly kept."""
    out: list[tuple[str, bytes]] = []
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return out
    # Comments are a first-class surface.
    for m in re.finditer(r"<!--(.*?)-->", text, re.DOTALL):
        out.append(("html_comment", m.group(1).encode("utf-8", errors="replace")))
    # Full text with tags stripped — split-across-tags words rejoin here.
    stripped = re.sub(r"<script.*?</script>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    stripped = re.sub(r"<style.*?</style>", " ", stripped, flags=re.DOTALL | re.IGNORECASE)
    stripped = re.sub(r"<[^>]+>", "", stripped)
    stripped = html_mod.unescape(stripped)
    out.append(("html_text", stripped.encode("utf-8", errors="replace")))
    # display:none / hidden elements — content the browser hides but serves.
    for m in re.finditer(
        r"<[^>]+(?:display\s*:\s*none|hidden)[^>]*>(.*?)</[^>]+>",
        text, re.DOTALL | re.IGNORECASE,
    ):
        inner = re.sub(r"<[^>]+>", "", m.group(1))
        out.append(("html_hidden", inner.encode("utf-8", errors="replace")))
    return out


def _surfaces_code(body: bytes) -> list[tuple[str, bytes]]:
    """CSS / JS: comments and string literals."""
    out: list[tuple[str, bytes]] = []
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return out
    for m in re.finditer(r"/\*(.*?)\*/", text, re.DOTALL):
        out.append(("comment_block", m.group(1).encode("utf-8", errors="replace")))
    for m in re.finditer(r"//[^\n]*", text):
        out.append(("comment_line", m.group(0).encode("utf-8", errors="replace")))
    for m in re.finditer(r'''(["'`])((?:\\.|(?!\1).)*)\1''', text, re.DOTALL):
        out.append(("string_literal", m.group(2).encode("utf-8", errors="replace")))
    out.append(("raw", body))  # fallback: the whole thing
    return out


def _surfaces_json(body: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    try:
        data = json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        out.append(("raw", body))
        return out

    def walk(node, path: str):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        elif isinstance(node, str):
            out.append((f"json_value:{path}", node.encode("utf-8", errors="replace")))

    walk(data, "$")
    return out


def _surfaces_xml(body: bytes) -> list[tuple[str, bytes]]:
    """XML / SVG: every element's text plus comments. SVG is XML — no OCR."""
    out: list[tuple[str, bytes]] = []
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return out
    for m in re.finditer(r"<!--(.*?)-->", text, re.DOTALL):
        out.append(("xml_comment", m.group(1).encode("utf-8", errors="replace")))
    try:
        root = ElementTree.fromstring(text)
        for el in root.iter():
            if el.text and el.text.strip():
                tag = el.tag.rsplit("}", 1)[-1]
                out.append((f"xml_text:{tag}", el.text.encode("utf-8", errors="replace")))
    except ElementTree.ParseError:
        out.append(("raw", body))
    return out


def _surfaces_csv(body: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    try:
        text = body.decode("utf-8", errors="replace")
        for i, r in enumerate(csv.reader(io.StringIO(text))):
            for j, cell in enumerate(r):
                if cell:
                    out.append((f"csv_cell:r{i}c{j}", cell.encode("utf-8", errors="replace")))
    except Exception:
        out.append(("raw", body))
    return out


def _surfaces_text(body: bytes) -> list[tuple[str, bytes]]:
    return [("raw", body)]


def _surfaces_sourcemap(body: bytes) -> list[tuple[str, bytes]]:
    """Sourcemap (ADR 0002): one surface per `sourcesContent` entry, tagged
    with the carrier path — the original pre-bundle file name is part of the
    provenance. Entries are scanned raw: the canonical form is caught wherever
    it sits, and recursive type-dispatch into entry contents would multiply
    how_found complexity for no new coverage. Keyed on URL extension, so this
    fires even when the server mislabels the map as application/json (the JSON
    walker would shred the blob into one surface per string)."""
    out: list[tuple[str, bytes]] = []
    try:
        data = json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        out.append(("raw", body))
        return out
    contents = data.get("sourcesContent") if isinstance(data, dict) else None
    if not isinstance(contents, list):
        out.append(("raw", body))
        return out
    sources = data.get("sources") or []
    for i, entry in enumerate(contents):
        if not isinstance(entry, str):
            continue
        carrier = sources[i] if i < len(sources) and isinstance(sources[i], str) else f"sourcesContent[{i}]"
        out.append((f"sourcemap:{carrier}", entry.encode("utf-8", errors="replace")))
    out.append(("raw", body))  # the map itself: mappings names, sourceRoot, etc.
    return out


# Long enough to be payload, short enough to catch a 28-byte secret (38-char
# run + padding). Padding is part of the match so decode sees the full blob.
_B64_BLOB = re.compile(rb"[A-Za-z0-9+/]{32,}={0,2}")
_DATA_URI = re.compile(rb"data:[^;,]*;base64,([A-Za-z0-9+/=]+)")
_PERCENT = re.compile(rb"(?:%[0-9A-Fa-f]{2}){4,}")
_HTML_ENTITY_BLOB = re.compile(rb"(?:&(?:#\d+|#x[0-9a-fA-F]+|[a-z]+);){4,}")


def _surfaces_decoded(body: bytes) -> list[tuple[str, bytes]]:
    """Decoded variants (design §8): base64 blobs, data: URIs, percent-encoding,
    HTML entities. The pattern is re-run over each decoding."""
    out: list[tuple[str, bytes]] = []
    for m in _DATA_URI.finditer(body):
        try:
            out.append(("decoded:data_uri", base64.b64decode(m.group(1), validate=False)))
        except (binascii.Error, ValueError):
            pass
    for m in _B64_BLOB.finditer(body):
        blob = m.group(0)
        if len(blob) % 4:
            continue
        try:
            decoded = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        if decoded and decoded != blob:
            out.append(("decoded:base64", decoded))
    for m in _PERCENT.finditer(body):
        try:
            out.append(("decoded:percent", unquote_to_bytes(m.group(0).decode("ascii"))))
        except Exception:
            pass
    for m in _HTML_ENTITY_BLOB.finditer(body):
        try:
            decoded = html_mod.unescape(m.group(0).decode("ascii", errors="replace"))
            out.append(("decoded:html_entities", decoded.encode("utf-8", errors="replace")))
        except Exception:
            pass
    return out


# Registry: content-type prefix -> handler. Prefix match, first hit wins.
EXTRACTORS: list[tuple[str, callable]] = [
    ("text/html", _surfaces_html),
    ("text/css", _surfaces_code),
    ("application/javascript", _surfaces_code),
    ("text/javascript", _surfaces_code),
    ("application/json", _surfaces_json),
    ("application/xml", _surfaces_xml),
    ("text/xml", _surfaces_xml),
    ("image/svg+xml", _surfaces_xml),
    ("text/csv", _surfaces_csv),
    ("text/plain", _surfaces_text),
    ("text/vtt", _surfaces_text),  # WebVTT subtitle files are pure text
    # image/*, application/pdf: M5 (metadata + pixel sweep; OCR deferred).
]


def handler_for(content_type: str, url_ext: str = ""):
    if url_ext == "map":
        return _surfaces_sourcemap
    for prefix, fn in EXTRACTORS:
        if content_type.startswith(prefix):
            return fn
    # M5: raster images and PDFs are handled by the image-forensics track
    # (metadata + pixel sweep), which runs per-blob in run.py — they have a
    # handler for coverage purposes even though they aren't text surfaces.
    if content_type.startswith("image/") and content_type != "image/svg+xml":
        return _image_passthrough
    if content_type == "application/pdf":
        return _pdf_text_layer
    return None


def _image_passthrough(body: bytes) -> list[tuple[str, bytes]]:
    """Raster images yield no text surfaces here; the pixel sweep (M5,
    images.py) is their real extractor. Returning the empty list keeps the
    coverage claim honest: 'has a handler' means the sweep ran."""
    return []


def _pdf_text_layer(body: bytes) -> list[tuple[str, bytes]]:
    """PDF text-layer scan: pull text out of stream objects (rasterise-and-
    read is deferred with OCR). A naive but honest first pass: literal strings
    inside BT/ET text objects."""
    out: list[tuple[str, bytes]] = []
    for m in re.finditer(rb"BT(.*?)ET", body, re.DOTALL):
        for sm in re.finditer(rb"\((?:\\.|[^\\()])*\)", m.group(1)):
            literal = sm.group(0)[1:-1]
            literal = re.sub(rb"\\([\\()])", rb"\1", literal)
            out.append(("pdf_text", literal))
    out.append(("raw", body))  # fallback greps the whole object stream
    return out


def extract_blob(content_type: str, body: bytes, url_ext: str = "") -> list[tuple[str, bytes]]:
    """All text surfaces for a blob: its type handler plus decoded variants
    (decoding is content-type-agnostic — a base64 blob can live anywhere).
    url_ext routes .map blobs to the sourcemap handler regardless of the
    declared content-type."""
    surfaces: list[tuple[str, bytes]] = []
    handler = handler_for(content_type, url_ext)
    if handler is not None:
        surfaces.extend(handler(body))
    surfaces.extend(_surfaces_decoded(body))
    return surfaces
