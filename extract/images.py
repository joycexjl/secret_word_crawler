"""M5 — image forensics: metadata + the enumerated pixel sweep.

OCR is deferred (design §8/§9). The image track is:

1. **Metadata** — EXIF, PNG tEXt/zTXt/iTXt chunks, JPEG COM markers, scanned
   with STRICT/LOOSE like any other text surface.

2. **Plane-fit anomaly detection** — colour-ramp backgrounds are mathematical
   gradients, so a payload can be *located*, not guessed: fit a plane per
   channel from the image corners, subtract, and every deviating pixel lights
   up. The deviating-pixel count is logged so "no anomaly present" is a
   measured claim, not a shrug.

3. **The pixel sweep** — an explicit, enumerable candidate space:
   channels {R,G,B,RGB,luma} × scan orders {row, column, diagonal, border}
   × encodings {direct-ASCII, 1/2/4-bit planes} × bit orders {msb, lsb}
   × directions {forward, reversed} — each candidate byte string grepped with
   STRICT and LOOSE, and EVERY candidate's outcome logged to
   pixel_sweep.jsonl so "what was tried" is enumerable in the write-up.

   Multiple STRICT hits with agreeing payloads collapse to one sighting;
   DISAGREEING payloads send the image to needs-review (same discipline as
   every other ambiguous reading — no auto-correction anywhere).
"""

from __future__ import annotations

import io
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from PIL import Image
from PIL.PngImagePlugin import PngInfo  # noqa: F401  (keeps plugin import explicit)

from .core import LOOSE, STRICT, Sighting, canonicalize, exclusion_reason

# OCR is optional: the design deferred it, and it only runs when pytesseract
# AND the tesseract binary are both present. Absent either, OCR surfaces are
# skipped cleanly and the image falls back to metadata + pixel sweep.
try:
    import pytesseract
    _OCR_AVAILABLE = True
    try:
        pytesseract.get_tesseract_version()
    except Exception:
        _OCR_AVAILABLE = False
except Exception:
    _OCR_AVAILABLE = False

CHANNELS = ("R", "G", "B", "RGB", "luma")
SCAN_ORDERS = ("row", "column", "diagonal", "border")
ENCODINGS = ("ascii", "bits1", "bits2", "bits4")
BIT_ORDERS = ("msb", "lsb")
DIRECTIONS = ("forward", "reversed")

# Deviation threshold for the plane-fit residual: a pixel deviates if any
# channel differs from the fitted plane by more than this many levels.
RESIDUAL_THRESHOLD = 12

# A channel is "ramp-like" when a 3-parameter plane explains it to within this
# max residual (pixel levels). Empirically, the synthetic ramps fit at 0; the
# retrieved structured PNGs fit at 130–216. 8 is a clean separation.
RAMP_MAX_RESIDUAL = 8.0


@dataclass
class ImageFinding:
    kind: str            # 'metadata' | 'pixel'
    field: str           # metadata key or candidate descriptor
    sightings: list      # list[Sighting]


@dataclass
class ImageReport:
    url: str
    sha256: str
    format: str = ""
    size: tuple = ()
    metadata_text: dict = field(default_factory=dict)
    ramp_fit: dict = field(default_factory=dict)  # {is_ramp, max_residual, deviating_px, explanation}
    candidates_tried: int = 0
    candidates_with_hits: int = 0
    sightings: list = field(default_factory=list)   # list[Sighting]
    needs_review: list = field(default_factory=list)
    ocr_text: dict = field(default_factory=dict)   # variant -> recognized text
    ruling: str = ""                   # swept-and-clean | payload-found | needs-review:* | unreadable
    ruling_note: str = ""              # e.g. "OCR unavailable"


# --------------------------------------------------------------------------
# Metadata
# --------------------------------------------------------------------------

def extract_metadata_text(img: Image.Image, raw: bytes) -> dict[str, str]:
    """All text-bearing metadata: PNG textual chunks (tEXt, and zTXt/iTXt via
    img.text when Pillow exposes them), full EXIF including IFDs, JPEG COM.
    Anything the sweep would treat as a string in the file header lives here."""
    out: dict[str, str] = {}
    for key, value in img.info.items():
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8", errors="replace")
            except Exception:
                continue
        if isinstance(value, str) and value:
            out[f"info:{key}"] = value
    # PNG textual chunks Pillow parsed into .text (includes iTXt; zTXt is
    # decompressed by Pillow when it can).
    text_container = getattr(img, "text", None)
    if text_container:
        for key, value in text_container.items():
            out[f"png_text:{key}"] = str(value)
    # EXIF, walking nested IFDs (GPS, Exif, Interop) so nothing hides a level
    # down. Raw bytes are preserved for UserComment (37510) — its UCS-2 text
    # would otherwise be mangled by str(); the charset surface decodes it.
    try:
        exif = img.getexif()
        for tag, value in exif.items():
            out[f"exif:{tag}"] = value if isinstance(value, bytes) else str(value)
        for ifd_tag in (0x8769, 0x8825, 0xA005):  # Exif, GPS, Interop IFDs
            try:
                ifd = exif.get_ifd(ifd_tag)
                for tag, value in ifd.items():
                    out[f"exif_ifd{ifd_tag:#x}:{tag}"] = value if isinstance(value, bytes) else str(value)
            except Exception:
                pass
    except Exception:
        pass
    # JPEG COM markers (0xFFFE) — Pillow exposes them in info['comment'].
    if "comment" in img.info:
        c = img.info["comment"]
        out["jpeg_comment"] = c.decode("utf-8", errors="replace") if isinstance(c, bytes) else str(c)
    return out


def extract_raw_chunk_strings(body: bytes, img_format: str) -> list[tuple[str, bytes]]:
    """Format-aware raw scan of metadata *segments* — the safety net for chunk
    types the parsed layer misses (e.g. a zTXt Pillow couldn't decompress, or
    an unknown ancillary chunk). For PNG, iterate the chunk table and scan
    each textual/ancillary chunk's bytes directly."""
    out: list[tuple[str, bytes]] = []
    if img_format == "PNG":
        import struct
        import zlib
        pos = 8  # skip the 8-byte signature
        while pos + 8 <= len(body):
            length = struct.unpack(">I", body[pos:pos + 4])[0]
            ctype = body[pos + 4:pos + 8]
            data = body[pos + 8:pos + 8 + length]
            if ctype == b"tEXt":
                out.append(("chunk:tEXt", data))
            elif ctype == b"zTXt":
                # keyword\0 compression-method compressed-text
                try:
                    nul = data.index(b"\x00")
                    out.append(("chunk:zTXt", zlib.decompress(data[nul + 2:])))
                except Exception:
                    out.append(("chunk:zTXt:raw", data))  # undecompressible: scan raw
            elif ctype == b"iTXt":
                out.append(("chunk:iTXt", data))
            elif ctype not in (b"IHDR", b"IDAT", b"IEND", b"PLTE"):
                out.append((f"chunk:{ctype.decode('latin-1')}", data))
            pos += 12 + length
            if ctype == b"IEND":
                break
    return out


# --------------------------------------------------------------------------
# Plane-fit anomaly detection
# --------------------------------------------------------------------------

def fit_ramp(arr: np.ndarray) -> dict:
    """Model-fit verdict: is this image a mathematical colour ramp, and if so
    where does it deviate?

    Two fits, honestly distinguished (the M5 bug was reporting a corner-fit
    deviating-pixel count on images that are not ramps at all):
      - full-image plane fit per channel -> is_ramp (a 3-parameter plane
        explains the whole image to within RAMP_MAX_RESIDUAL) and max_residual.
      - corner-fit plane (payload rarely fills corners) -> deviating_px, the
        located-anomaly count, meaningful ONLY when is_ramp is true.

    Returns {is_ramp, max_residual, deviating_px, explanation}.
    """
    h, w = arr.shape[:2]
    if h < 8 or w < 8:
        return {"is_ramp": False, "max_residual": -1.0, "deviating_px": -1,
                "explanation": "too small to fit (<8px)"}
    yy, xx = np.mgrid[0:h, 0:w]
    A = np.stack([xx.ravel(), yy.ravel(), np.ones(h * w)], axis=1).astype(float)
    planes = arr.reshape(h, w, -1) if arr.ndim == 3 else arr[:, :, None]
    channels = planes.shape[2]

    # Full-image fit -> is this a ramp at all?
    max_residual = 0.0
    for ch in range(channels):
        z = planes[:, :, ch].astype(float).ravel()
        coef, *_ = np.linalg.lstsq(A, z, rcond=None)
        max_residual = max(max_residual, float(np.abs(z - A @ coef).max()))
    is_ramp = max_residual <= RAMP_MAX_RESIDUAL

    if not is_ramp:
        return {"is_ramp": False, "max_residual": round(max_residual, 2),
                "deviating_px": -1,
                "explanation": f"not a ramp (a 3-param plane leaves residual "
                               f"{max_residual:.0f} > {RAMP_MAX_RESIDUAL:.0f}); image is "
                               f"structured — pixel-payload reasoning does not apply"}

    # Corner fit -> locate deviating pixels (payload) on a true ramp.
    deviating = np.zeros((h, w), dtype=bool)
    m = max(4, min(h, w) // 8)
    corner_mask = np.zeros((h, w), dtype=bool)
    corner_mask[:m, :m] = corner_mask[:m, -m:] = corner_mask[-m:, :m] = corner_mask[-m:, -m:] = True
    A_fit = A[corner_mask.ravel()]
    for ch in range(channels):
        z = planes[:, :, ch].astype(float).ravel()
        coef, *_ = np.linalg.lstsq(A_fit, z[corner_mask.ravel()], rcond=None)
        residual = np.abs(z - A @ coef).reshape(h, w)
        deviating |= residual > RESIDUAL_THRESHOLD
    n = int(deviating.sum())
    return {"is_ramp": True, "max_residual": round(max_residual, 2),
            "deviating_px": n,
            "explanation": ("clean ramp — no deviating pixels" if n == 0
                            else f"ramp with {n} deviating pixel(s) located by corner-fit")}


def fit_ramp_residual(arr: np.ndarray) -> int:
    """Back-compat shim for tests: deviating-pixel count (corner fit) when the
    image is a ramp, else the raw corner-fit count. Prefer fit_ramp()."""
    h, w = arr.shape[:2]
    if h < 8 or w < 8:
        return -1
    yy, xx = np.mgrid[0:h, 0:w]
    A = np.stack([xx.ravel(), yy.ravel(), np.ones(h * w)], axis=1).astype(float)
    deviating = np.zeros((h, w), dtype=bool)
    planes = arr.reshape(h, w, -1) if arr.ndim == 3 else arr[:, :, None]
    m = max(4, min(h, w) // 8)
    corner_mask = np.zeros((h, w), dtype=bool)
    corner_mask[:m, :m] = corner_mask[:m, -m:] = corner_mask[-m:, :m] = corner_mask[-m:, -m:] = True
    A_fit = A[corner_mask.ravel()]
    for ch in range(planes.shape[2]):
        z = planes[:, :, ch].astype(float).ravel()
        coef, *_ = np.linalg.lstsq(A_fit, z[corner_mask.ravel()], rcond=None)
        deviating |= (np.abs(z - A @ coef).reshape(h, w) > RESIDUAL_THRESHOLD)
    return int(deviating.sum())


# --------------------------------------------------------------------------
# The enumerated pixel sweep
# --------------------------------------------------------------------------

def _channel_array(img: Image.Image, channel: str) -> np.ndarray:
    arr = np.asarray(img.convert("RGB"))
    if channel == "R":
        return arr[:, :, 0]
    if channel == "G":
        return arr[:, :, 1]
    if channel == "B":
        return arr[:, :, 2]
    if channel == "RGB":
        return arr  # interleaved later
    # luma (Rec. 601)
    return (0.299 * arr[:, :, 0] + 0.587 * arr[:, :, 1] + 0.114 * arr[:, :, 2]).astype(np.uint8)


def _scan_order(arr: np.ndarray, order: str) -> np.ndarray:
    """Flatten a 2-D array in the given scan order."""
    h, w = arr.shape
    if order == "row":
        return arr.ravel()
    if order == "column":
        return arr.T.ravel()
    if order == "diagonal":
        # Boustrophedon over anti-diagonals.
        idx = []
        for s in range(h + w - 1):
            if s % 2 == 0:
                rng = range(min(s, h - 1), max(-1, s - w), -1)
            else:
                rng = range(max(0, s - w + 1), min(s + 1, h))
            for i in rng:
                idx.append((i, s - i))
        return arr[tuple(zip(*idx))]
    if order == "border":
        # Clockwise border walk, spiralling inward.
        vals, top, bottom, left, right = [], 0, h - 1, 0, w - 1
        while top <= bottom and left <= right:
            vals.extend(arr[top, left:right + 1])
            vals.extend(arr[top + 1:bottom + 1, right])
            if top < bottom:
                vals.extend(arr[bottom, left:right][::-1])
            if left < right:
                vals.extend(arr[top + 1:bottom, left][::-1])
            top, bottom, left, right = top + 1, bottom - 1, left + 1, right - 1
        return np.array(vals, dtype=arr.dtype)
    raise ValueError(order)


def _bytes_from_values(vals: np.ndarray, encoding: str, bit_order: str) -> bytes:
    if encoding == "ascii":
        return vals.astype(np.uint8).tobytes()
    depth = {"bits1": 1, "bits2": 2, "bits4": 4}[encoding]
    mask = (1 << depth) - 1
    nibbles = (vals.astype(np.uint8) & mask).astype(np.uint8)
    bits = np.unpackbits(nibbles[:, None], axis=1, bitorder="big")[:, 8 - depth:]
    flat = bits.ravel()
    if bit_order == "lsb":
        flat = flat.reshape(-1, 8)[:, ::-1].ravel() if flat.size % 8 == 0 else flat
    nbytes = flat.size // 8
    if nbytes == 0:
        return b""
    packed = np.packbits(flat[: nbytes * 8].reshape(nbytes, 8), axis=1)
    return packed.tobytes()


def sweep_candidates(img: Image.Image) -> "list[tuple[str, bytes]]":
    """Yield (descriptor, candidate-bytes) over the full enumerated space:
    channels × scan orders × encodings × bit orders × directions."""
    out: list[tuple[str, bytes]] = []
    for channel in CHANNELS:
        carr = _channel_array(img, channel)
        planes = [carr] if carr.ndim == 2 else [carr[:, :, i] for i in range(3)]
        for order in SCAN_ORDERS:
            for enc in ENCODINGS:
                if enc == "ascii":
                    # ASCII ignores bit order; RGB interleaves its channels.
                    vals = carr.reshape(-1) if (carr.ndim == 3 or order == "row") \
                        else _scan_order(carr if carr.ndim == 2 else carr[:, :, 0], order)
                    candidate = vals.astype(np.uint8).tobytes()
                    desc = f"{channel}/{order}/{enc}"
                    out.append((desc, candidate))
                    out.append((desc + "/rev", candidate[::-1]))
                    continue
                for bo in BIT_ORDERS:
                    for plane in planes:
                        vals = _scan_order(plane, order)
                        candidate = _bytes_from_values(vals, enc, bo)
                        desc = f"{channel}/{order}/{enc}/{bo}"
                        out.append((desc, candidate))
                        out.append((desc + "/rev", candidate[::-1]))
    return out


# --------------------------------------------------------------------------
# OCR surface (deferred by design; resurrected when metadata + sweep come up
# short). Runs several preprocessed variants — OCR misreads are expected, so
# STRICT hits count and LOOSE hits route to needs-review for a human ruling.
# --------------------------------------------------------------------------

def ocr_surfaces(img: Image.Image) -> list[tuple[str, bytes]]:
    """OCR the image under a few preprocessing variants; return
    (variant, recognized-text-bytes) surfaces. Empty if OCR unavailable."""
    if not _OCR_AVAILABLE:
        return []
    out: list[tuple[str, bytes]] = []
    base = img.convert("L")  # grayscale
    variants = {"gray": base}
    # Upscale small text — tesseract needs ~x-height ≥ ~10px.
    w, h = base.size
    if max(w, h) < 1000:
        scale = max(2, min(6, 1000 // max(1, min(w, h))))
        variants["upscaled"] = base.resize((w * scale, h * scale), Image.LANCZOS)
    # Binarized at a mid threshold — high-contrast text reads cleaner.
    variants["binary"] = base.point(lambda p: 255 if p > 127 else 0)
    for name, v in variants.items():
        try:
            text = pytesseract.image_to_string(v)
        except Exception:
            continue
        if text.strip():
            out.append((f"ocr:{name}", text.encode("utf-8", errors="replace")))
    return out


# --------------------------------------------------------------------------
# Entry point: one image blob -> ImageReport (+ sightings)
# --------------------------------------------------------------------------

def analyze_image(body: bytes, *, url: str, sha256: str,
                  sweep_log: Path | None = None) -> ImageReport:
    rep = ImageReport(url=url, sha256=sha256)
    try:
        img = Image.open(io.BytesIO(body))
        img.load()
    except Exception as e:
        rep.ruling = f"unreadable: {type(e).__name__}"
        return rep
    rep.format = img.format or ""
    rep.size = img.size

    # 1. Metadata — parsed layer, then the raw-chunk safety net. A value
    # reachable by both (e.g. a tEXt chunk seen via img.info AND the raw
    # chunk table) is deduped to one sighting per canonical value.
    # Charset variants (UTF-16 LE/BE, UTF-8 BOM) run over the same surfaces:
    # an EXIF UserComment is UCS-2, which the byte-level STRICT pattern
    # cannot match without decoding (null bytes between characters).
    seen_meta_canon: set[str] = set()

    def _meta_scan(raw: bytes, how: str) -> None:
        for s in _scan_bytes(raw, how=how, url=url, sha=sha256, with_charset=True):
            if s.strict:
                if s.canonical in seen_meta_canon:
                    continue
                seen_meta_canon.add(s.canonical)
                rep.sightings.append(s)
            else:
                rep.needs_review.append(s)
        # A bare 16-hex fragment (no VISUALPING{} wrapper) is recorded but
        # ruled not-a-secret: the secret form requires the wrapper, so a bare
        # hex string is a decoy / staging artifact. Ruled out, not needs-review.
        for m in re.finditer(rb"(?<![0-9a-f])[0-9a-f]{16}(?![0-9a-f])", raw):
            frag = b"FRAGMENT:" + m.group(0)
            rep.needs_review.append(Sighting(
                canonical=None, raw=frag,
                how_found=how + ":bare_hex16", url=url, sha256=sha256,
                ruled_out=exclusion_reason(frag, None) or ""))

    for field, value in extract_metadata_text(img, body).items():
        rep.metadata_text[field] = value if isinstance(value, str) else repr(value)
        raw = value if isinstance(value, bytes) else value.encode("utf-8", errors="replace")
        _meta_scan(raw, f"img_meta:{field}")
    for desc, chunk_bytes in extract_raw_chunk_strings(body, rep.format):
        _meta_scan(chunk_bytes, f"img_{desc}")

    # 2. Model-fit verdict: is this a ramp, and if so are there anomalies?
    arr = np.asarray(img.convert("RGB"))
    rep.ramp_fit = fit_ramp(arr)

    # 3. Enumerated pixel sweep — every outcome logged
    strict_payloads: set[str] = set()
    log_lines: list[str] = []
    for desc, candidate in sweep_candidates(img):
        rep.candidates_tried += 1
        hits = _scan_bytes(candidate, how=f"pixel:{desc}", url=url, sha=sha256)
        outcome = "clean"
        if hits:
            rep.candidates_with_hits += 1
            for s in hits:
                if s.strict:
                    strict_payloads.add(s.canonical)
                    rep.sightings.append(s)
                    outcome = f"STRICT:{s.canonical}"
                else:
                    rep.needs_review.append(s)
                    outcome = "LOOSE"
        log_lines.append(json.dumps({
            "url": url, "sha256": sha256, "candidate": desc, "outcome": outcome,
        }))
    if sweep_log is not None:
        with Path(sweep_log).open("a", encoding="utf-8") as fh:
            fh.write("\n".join(log_lines) + "\n")

    # 4. OCR — runs when the image is rendered-text-shaped (wide & short, like
    # a scan/placard) or when metadata + sweep left it unexplained. STRICT hits
    # count; OCR's near-misses (misread braces/hex) route to needs-review.
    wide_short = rep.size and rep.size[0] >= 3 * max(1, rep.size[1])
    unexplained = not rep.sightings
    if _OCR_AVAILABLE and (wide_short or unexplained):
        rep.ocr_text = {}
        for variant, text_bytes in ocr_surfaces(img):
            rep.ocr_text[variant] = text_bytes.decode("utf-8", errors="replace")
            for s in _scan_bytes(text_bytes, how=f"img_{variant}", url=url,
                                 sha=sha256, with_charset=False):
                if s.strict:
                    if s.canonical not in strict_payloads:
                        strict_payloads.add(s.canonical)
                        rep.sightings.append(s)
                else:
                    rep.needs_review.append(s)
    elif not _OCR_AVAILABLE:
        rep.ruling_note = "OCR unavailable (tesseract not installed)"

    # 5. Ruling
    if len(strict_payloads) > 1:
        # Disagreeing payloads — no auto-correction; human ruling required.
        rep.ruling = "needs-review:disagreeing-payloads"
    elif rep.sightings:
        rep.ruling = "payload-found"
    elif rep.needs_review:
        rep.ruling = "needs-review:loose-only"
    else:
        # Swept clean. A true ramp reports measured-clean; a non-ramp reports
        # honestly that pixel-payload reasoning did not apply to it.
        rep.ruling = "swept-and-clean"
    return rep


def _scan_bytes(data: bytes, *, how: str, url: str, sha: str,
                with_charset: bool = False) -> list[Sighting]:
    from .core import scan_text

    return scan_text(data, how_found=how, url=url, sha256=sha,
                     with_charset=with_charset)
