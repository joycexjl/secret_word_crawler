"""Unit tests for M4: extraction core, handlers, fan-out, header scanning."""

import base64
import json
import tempfile
import unittest
from pathlib import Path

from extract.core import STRICT, LOOSE, canonicalize, scan_headers, scan_text
from extract.registry import extract_blob, handler_for
from extract.run import run

GOOD = b"VISUALPING{0123456789abcdef}"
GOOD2 = b"VISUALPING{aaaaaaaaaaaaaaaa}"


class TestPatterns(unittest.TestCase):
    def test_strict_matches_canonical(self):
        self.assertEqual(STRICT.findall(GOOD), [GOOD])

    def test_strict_rejects_uppercase_hex(self):
        self.assertEqual(STRICT.findall(b"VISUALPING{0123456789ABCDEF}"), [])

    def test_loose_catches_uppercase_for_normalization(self):
        hits = scan_text(b"VISUALPING{0123456789ABCDEF}", how_found="t", url="u", sha256="s")
        self.assertEqual(hits[0].canonical, "VISUALPING{0123456789abcdef}")
        self.assertTrue(hits[0].strict)

    def test_canonicalize_strips_inner_whitespace(self):
        self.assertEqual(
            canonicalize(b"VISUALPING{ 0123456789abcdef }"),
            "VISUALPING{0123456789abcdef}",
        )

    def test_loose_garbage_not_strict(self):
        hits = scan_text(b"VISUALPING{not-a-secret}", how_found="t", url="u", sha256="s")
        self.assertEqual(len(hits), 1)
        self.assertIsNone(hits[0].canonical)

    def test_worked_example_ruled_out(self):
        # The index page's worked example is explicitly "not one of the eight".
        hits = scan_text(b"VISUALPING{0000deadbeef0000}", how_found="t", url="u", sha256="s")
        self.assertEqual(hits[0].ruled_out, "worked_example")
        self.assertFalse(hits[0].strict)  # ruled-out is not counted as strict

    def test_format_prose_ruled_out(self):
        # "the literal string VISUALPING{, sixteen hexadecimal characters, then }"
        hits = scan_text(b"VISUALPING{, sixteen hexadecimal characters, then }",
                         how_found="t", url="u", sha256="s")
        self.assertEqual(hits[0].ruled_out, "format_prose")

    def test_real_secret_not_ruled_out(self):
        hits = scan_text(GOOD, how_found="t", url="u", sha256="s")
        self.assertEqual(hits[0].ruled_out, "")
        self.assertTrue(hits[0].strict)

    def test_bare_hex_fragment_ruled_out(self):
        # A bare 16-hex string with no VISUALPING{} wrapper (JPEG comment decoy)
        # is ruled not-a-secret — the secret form requires the wrapper.
        from extract.core import exclusion_reason
        self.assertEqual(exclusion_reason(b"FRAGMENT:5a6b01d97bfffdc3", None),
                         "bare_hex_fragment")
        # and a real canonical value is never ruled a fragment
        self.assertIsNone(exclusion_reason(GOOD, "VISUALPING{0123456789abcdef}"))


class TestHandlers(unittest.TestCase):
    def test_html_split_across_tags(self):
        body = b"<p>VISUALPING{0123<span>4567</span>89abcdef}</p>"
        surfaces = extract_blob("text/html", body)
        joined = b"\n".join(data for _, data in surfaces)
        hits = scan_text(joined, how_found="t", url="u", sha256="s")
        self.assertEqual(hits[0].canonical, "VISUALPING{0123456789abcdef}")

    def test_html_comment_surface(self):
        body = b"<!-- VISUALPING{0123456789abcdef} -->"
        surfaces = dict((sub, data) for sub, data in extract_blob("text/html", body))
        self.assertIn(GOOD, surfaces["html_comment"])

    def test_html_display_none_kept(self):
        body = b'<div style="display:none">VISUALPING{0123456789abcdef}</div>'
        subs = [sub for sub, _ in extract_blob("text/html", body)]
        self.assertIn("html_hidden", subs)

    def test_js_string_literal(self):
        body = b'const k = "VISUALPING{0123456789abcdef}";'
        surfaces = extract_blob("application/javascript", body)
        joined = b"\n".join(d for _, d in surfaces)
        self.assertIn(GOOD, joined)

    def test_json_flatten(self):
        body = json.dumps({"a": {"b": ["VISUALPING{0123456789abcdef}"]}}).encode()
        surfaces = extract_blob("application/json", body)
        self.assertTrue(any(GOOD in d for _, d in surfaces))

    def test_svg_text_node(self):
        body = b'<svg xmlns="http://www.w3.org/2000/svg"><text>VISUALPING{0123456789abcdef}</text></svg>'
        surfaces = extract_blob("image/svg+xml", body)
        self.assertTrue(any(GOOD in d for _, d in surfaces))

    def test_decoded_base64(self):
        blob = base64.b64encode(GOOD)
        surfaces = extract_blob("text/plain", blob)
        self.assertTrue(any(GOOD in d for _, d in surfaces))

    def test_decoded_data_uri(self):
        body = b'<img src="data:text/plain;base64,' + base64.b64encode(GOOD) + b'">'
        surfaces = extract_blob("text/html", body)
        self.assertTrue(any(GOOD in d for _, d in surfaces))

    def test_decoded_percent(self):
        body = b"%".join(f"{b:02X}".encode() for b in GOOD)
        body = b"%" + body
        surfaces = extract_blob("text/plain", body)
        self.assertTrue(any(GOOD in d for _, d in surfaces))

    def test_decoded_html_entities(self):
        body = b"".join(f"&#{b};".encode() for b in GOOD)
        surfaces = extract_blob("text/plain", body)
        self.assertTrue(any(GOOD in d for _, d in surfaces))

    def test_image_and_pdf_have_handlers_since_m5(self):
        # M5 filled the gap M3's unhandled-types detector would have named:
        # raster images route to the pixel sweep, PDFs to the text-layer scan.
        self.assertIsNotNone(handler_for("image/png"))
        self.assertIsNotNone(handler_for("application/pdf"))
        # The image handler is a passthrough — the sweep is the extractor.
        self.assertEqual(handler_for("image/png")(b"\x89PNG"), [])


class TestHeaderScanning(unittest.TestCase):
    def test_header_match_counts_as_candidate(self):
        # The disqualification rule was removed: a header STRICT match is a
        # candidate secret, provenance preserved via how_found.
        headers = {"x-provisioning-note": GOOD.decode()}
        hits = scan_headers(headers, url="u", sha256="s")
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0].strict)
        self.assertFalse(hits[0].disqualified)
        self.assertEqual(hits[0].how_found, "header:x-provisioning-note")
        self.assertEqual(hits[0].canonical, "VISUALPING{0123456789abcdef}")

    def test_cookie_scanned(self):
        headers = {"set-cookie": "secret=" + GOOD.decode()}
        hits = scan_headers(headers, url="u", sha256="s")
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0].strict)


class TestRunnerFanOut(unittest.TestCase):
    def _mk_out(self, rows, blobs):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        (root / "blobs").mkdir()
        for sha, body in blobs.items():
            (root / "blobs" / sha).write_bytes(body)
        (root / "manifest.jsonl").write_text(
            "\n".join(json.dumps(r) for r in rows) + "\n"
        )
        return td, root

    def test_shared_blob_fans_out_to_both_rows(self):
        import hashlib
        body = b"<html>" + GOOD + b"</html>"
        sha = hashlib.sha256(body).hexdigest()
        rows = [
            {"url": "http://h/a", "canon_key": "http://h/a", "status": 200,
             "content_type": "text/html", "sha256": sha, "headers": {}},
            {"url": "http://h/b", "canon_key": "http://h/b", "status": 200,
             "content_type": "text/html", "sha256": sha, "headers": {}},
        ]
        td, root = self._mk_out(rows, {sha: body})
        with td:
            res = run(root)
            canon = "VISUALPING{0123456789abcdef}"
            urls = {s["url"] for s in res["secrets"][canon]}
            self.assertEqual(urls, {"http://h/a", "http://h/b"})

    def test_rendered_only_divergence_named(self):
        import hashlib
        raw = b"<html><body>plain</body></html>"
        rendered = b"<html><body>plain " + GOOD2 + b"</body></html>"
        rsha_raw = hashlib.sha256(raw).hexdigest()
        rsha_ren = hashlib.sha256(rendered).hexdigest()
        rows = [{"url": "http://h/", "canon_key": "http://h/", "status": 200,
                 "content_type": "text/html", "sha256": rsha_raw,
                 "rendered_sha256": rsha_ren, "headers": {}}]
        td, root = self._mk_out(rows, {rsha_raw: raw, rsha_ren: rendered})
        with td:
            res = run(root)
            self.assertEqual(res["divergences"][0]["corpus"], "rendered_only")
            self.assertEqual(res["distinct_strict"], 1)


if __name__ == "__main__":
    unittest.main()
