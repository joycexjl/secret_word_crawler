"""Unit tests for M5: image metadata, plane-fit residual, pixel sweep."""

import io
import tempfile
import unittest
from pathlib import Path

import numpy as np
from PIL import Image

from extract.images import (
    analyze_image,
    fit_ramp_residual,
    sweep_candidates,
)

SECRET = b"VISUALPING{cafebabecafebabe}"


def make_ramp(w=64, h=64) -> np.ndarray:
    """A clean mathematical colour gradient (the ramp)."""
    yy, xx = np.mgrid[0:h, 0:w]
    arr = np.zeros((h, w, 3), dtype=np.uint8)
    arr[:, :, 0] = (xx * 255 // max(w - 1, 1)).astype(np.uint8)
    arr[:, :, 1] = (yy * 255 // max(h - 1, 1)).astype(np.uint8)
    arr[:, :, 2] = ((xx + yy) * 255 // max(w + h - 2, 1)).astype(np.uint8)
    return arr


def png_bytes(arr: np.ndarray) -> bytes:
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, format="PNG")
    return buf.getvalue()


def embed_ascii(arr: np.ndarray, payload: bytes, x0=4, y0=4) -> np.ndarray:
    """Embed payload bytes directly as R-channel pixel values (row order) —
    the high-order-bit 'visible against the ramp' case from design §9."""
    out = arr.copy()
    i = 0
    for y in range(y0, arr.shape[0]):
        for x in range(x0, arr.shape[1]):
            if i >= len(payload):
                return out
            out[y, x, 0] = payload[i]
            i += 1
    return out


class TestPlaneFit(unittest.TestCase):
    def test_clean_ramp_measured_zero(self):
        n = fit_ramp_residual(make_ramp())
        self.assertEqual(n, 0)

    def test_payload_lights_up(self):
        arr = embed_ascii(make_ramp(), SECRET)
        n = fit_ramp_residual(arr)
        self.assertGreater(n, 0)  # anomaly located, not guessed

    def test_fit_ramp_verdict_on_clean_ramp(self):
        from extract.images import fit_ramp
        v = fit_ramp(make_ramp())
        self.assertTrue(v["is_ramp"])
        self.assertEqual(v["deviating_px"], 0)

    def test_fit_ramp_verdict_on_non_ramp(self):
        from extract.images import fit_ramp
        import numpy as np
        rng = np.random.default_rng(7)
        noise = rng.integers(0, 255, (48, 48, 3), dtype=np.uint8)
        v = fit_ramp(noise)
        self.assertFalse(v["is_ramp"])
        self.assertEqual(v["deviating_px"], -1)  # N/A, not a scary count
        self.assertIn("not a ramp", v["explanation"])


class TestSweep(unittest.TestCase):
    def test_recovers_direct_ascii_payload(self):
        body = png_bytes(embed_ascii(make_ramp(), SECRET))
        with tempfile.TemporaryDirectory() as td:
            rep = analyze_image(body, url="http://h/ramp.png",
                                sha256="x" * 64, sweep_log=Path(td) / "sweep.jsonl")
            canons = {s.canonical for s in rep.sightings if s.strict}
            self.assertIn(SECRET.decode(), canons)
            self.assertEqual(rep.ruling, "payload-found")
            self.assertGreater(rep.candidates_tried, 100)
            # Every candidate's outcome was logged.
            logged = (Path(td) / "sweep.jsonl").read_text().strip().splitlines()
            self.assertEqual(len(logged), rep.candidates_tried)

    def test_clean_image_swept_and_clean(self):
        body = png_bytes(make_ramp())
        with tempfile.TemporaryDirectory() as td:
            rep = analyze_image(body, url="http://h/clean.png",
                                sha256="y" * 64, sweep_log=Path(td) / "sweep.jsonl")
            self.assertEqual(rep.ruling, "swept-and-clean")
            self.assertEqual(rep.candidates_with_hits, 0)
            self.assertTrue(rep.ramp_fit["is_ramp"])
            self.assertEqual(rep.ramp_fit["deviating_px"], 0)

    def test_candidate_space_is_enumerable(self):
        img = Image.fromarray(make_ramp(16, 16))
        descs = [d for d, _ in sweep_candidates(img)]
        self.assertTrue(any("luma/column/bits4/lsb" in d for d in descs))
        self.assertTrue(any(d.endswith("/rev") for d in descs))


class TestMetadata(unittest.TestCase):
    def test_png_text_chunk(self):
        from PIL.PngImagePlugin import PngInfo

        img = Image.fromarray(make_ramp(32, 32))
        meta = PngInfo()
        meta.add_text("Comment", SECRET.decode())
        buf = io.BytesIO()
        img.save(buf, format="PNG", pnginfo=meta)
        rep = analyze_image(buf.getvalue(), url="http://h/meta.png", sha256="z" * 64)
        canons = {s.canonical for s in rep.sightings if s.strict}
        self.assertIn(SECRET.decode(), canons)


if __name__ == "__main__":
    unittest.main()
