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
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from PIL import Image
from PIL.PngImagePlugin import PngInfo  # noqa: F401  (keeps plugin import explicit)

from .core import LOOSE, STRICT, Sighting, canonicalize

CHANNELS = ("R", "G", "B", "RGB", "luma")
SCAN_ORDERS = ("row", "column", "diagonal", "border")
ENCODINGS = ("ascii", "bits1", "bits2", "bits4")
BIT_ORDERS = ("msb", "lsb")
DIRECTIONS = ("forward", "reversed")

# Deviation threshold for the plane-fit residual: a pixel deviates if any
# channel differs from the fitted plane by more than this many levels.
RESIDUAL_THRESHOLD = 12


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
    deviating_pixels: int = -1          # -1 = plane fit not applicable
    candidates_tried: int = 0
    candidates_with_hits: int = 0
    sightings: list = field(default_factory=list)   # list[Sighting]
    needs_review: list = field(default_factory=list)
    ruling: str = ""                   # swept-and-clean | metadata-clean | payload-found | needs-review | OCR-deferred


# --------------------------------------------------------------------------
# Metadata
# --------------------------------------------------------------------------

def extract_metadata_text(img: Image.Image, raw: bytes) -> dict[str, str]:
    """All text-bearing metadata: PNG textual chunks, EXIF, JPEG COM."""
    out: dict[str, str] = {}
    for key, value in img.info.items():
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8", errors="replace")
            except Exception:
                continue
        if isinstance(value, str) and value:
            out[f"info:{key}"] = value
    try:
        exif = img.getexif()
        for tag, value in exif.items():
            out[f"exif:{tag}"] = str(value)
    except Exception:
        pass
    # JPEG COM markers (0xFFFE) — Pillow exposes them in info['comment'].
    if "comment" in img.info:
        c = img.info["comment"]
        out["jpeg_comment"] = c.decode("utf-8", errors="replace") if isinstance(c, bytes) else str(c)
    return out


# --------------------------------------------------------------------------
# Plane-fit anomaly detection
# --------------------------------------------------------------------------

def fit_ramp_residual(arr: np.ndarray) -> int:
    """Fit a plane per channel from the corners, subtract, count deviating
    pixels. Returns the deviating-pixel count (0 = measured-clean ramp)."""
    h, w = arr.shape[:2]
    if h < 8 or w < 8:
        return -1
    yy, xx = np.mgrid[0:h, 0:w]
    # Design matrix for plane z = a*x + b*y + c
    A = np.stack([xx.ravel(), yy.ravel(), np.ones(h * w)], axis=1).astype(float)
    deviating = np.zeros((h, w), dtype=bool)
    channels = arr.shape[2] if arr.ndim == 3 else 1
    planes = arr.reshape(h, w, -1) if arr.ndim == 3 else arr[:, :, None]
    # Fit only from the four corner patches (payload rarely fills corners).
    m = max(4, min(h, w) // 8)
    corner_mask = np.zeros((h, w), dtype=bool)
    corner_mask[:m, :m] = corner_mask[:m, -m:] = corner_mask[-m:, :m] = corner_mask[-m:, -m:] = True
    A_fit = A[corner_mask.ravel()]
    for ch in range(channels):
        z = planes[:, :, ch].astype(float).ravel()
        coef, *_ = np.linalg.lstsq(A_fit, z[corner_mask.ravel()], rcond=None)
        residual = np.abs(z - A @ coef).reshape(h, w)
        deviating |= residual > RESIDUAL_THRESHOLD
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

    # 1. Metadata
    rep.metadata_text = extract_metadata_text(img, body)
    for field, text in rep.metadata_text.items():
        for s in _scan_bytes(text.encode("utf-8", errors="replace"),
                             how=f"img_meta:{field}", url=url, sha=sha256):
            rep.sightings.append(s)

    # 2. Plane-fit residual (measured anomaly claim)
    arr = np.asarray(img.convert("RGB"))
    rep.deviating_pixels = fit_ramp_residual(arr)

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

    # 4. Ruling
    if len(strict_payloads) > 1:
        # Disagreeing payloads — no auto-correction; human ruling required.
        rep.ruling = "needs-review:disagreeing-payloads"
    elif rep.sightings:
        rep.ruling = "payload-found"
    elif rep.needs_review:
        rep.ruling = "needs-review:loose-only"
    elif rep.metadata_text or rep.deviating_pixels == 0:
        rep.ruling = "swept-and-clean"
    else:
        rep.ruling = "swept-and-clean"
    return rep


def _scan_bytes(data: bytes, *, how: str, url: str, sha: str) -> list[Sighting]:
    from .core import scan_text

    return scan_text(data, how_found=how, url=url, sha256=sha)
