"""Unit tests for ADR 0002: link-bearing surfaces beyond the anchor tag."""

import unittest

from crawl.discover import (
    in_scope_hits,
    scan_bytes,
    scan_header_values,
    scan_json_values,
    scan_link_header,
)
from crawl.normalize import ScopeTriple
from extract.registry import extract_blob, handler_for

SCOPE = ScopeTriple("http", "54.214.7.161", 80)
BASE = "http://54.214.7.161/docs/"
HOST = "http://54.214.7.161"


class TestCssEdges(unittest.TestCase):
    def test_unquoted_url(self):
        body = b"body { background-image: url(/static/bg.png); }"
        r = scan_bytes(body, BASE, SCOPE)
        hits = {h.verbatim: h.how for h in r.hits}
        self.assertEqual(hits.get(f"{HOST}/static/bg.png"), "css_url")

    def test_quoted_url(self):
        body = b"@font-face { src: url('../fonts/a.woff2'); }"
        r = scan_bytes(body, BASE, SCOPE)
        hits = {h.verbatim: h.how for h in r.hits}
        self.assertEqual(hits.get(f"{HOST}/fonts/a.woff2"), "css_url")

    def test_import_forms(self):
        body = b'@import "theme.css";\n@import url(/x/print.css);'
        r = scan_bytes(body, BASE, SCOPE)
        urls = [h.verbatim for h in r.hits if h.how == "css_url"]
        self.assertIn(f"{HOST}/docs/theme.css", urls)
        self.assertIn(f"{HOST}/x/print.css", urls)

    def test_data_uri_and_fragment_not_hits(self):
        body = b"a{background:url(data:image/png;base64,iVBORw0KGgo=)} b{fill:url(#grad)}"
        r = scan_bytes(body, BASE, SCOPE)
        self.assertEqual([h for h in r.hits if h.how == "css_url"], [])


class TestSourcemapEdge(unittest.TestCase):
    def test_sourcemappingurl_attribution(self):
        body = b"!function(){}();\n//# sourceMappingURL=analytics.js.map\n"
        r = scan_bytes(body, "http://54.214.7.161/static/js/analytics.js", SCOPE)
        hits = {h.verbatim: h.how for h in r.hits}
        self.assertEqual(
            hits.get("http://54.214.7.161/static/js/analytics.js.map"), "sourcemap"
        )


class TestHeaderScanners(unittest.TestCase):
    def test_link_header_structural(self):
        hits = scan_link_header('</style.css>; rel="stylesheet", <https://x.example/a>; rel=preload', BASE)
        by_url = {h.verbatim: h for h in hits}
        self.assertEqual(by_url[f"{HOST}/style.css"].how, "http_link_header")
        self.assertEqual(by_url[f"{HOST}/style.css"].hint, "stylesheet")
        # Out-of-scope entry still recorded as a hit (scope check is downstream)
        self.assertIn("https://x.example/a", by_url)

    def test_header_values_pattern_scanned(self):
        headers = {
            "x-archive-source": 'see "/internal/backup.zip" for details',
            "location": "/redirect-target",  # excluded: fetch layer owns redirects
            "content-type": "text/html",
        }
        hits = scan_header_values(headers, BASE)
        urls = {h.verbatim: h.how for h in hits}
        self.assertEqual(urls.get(f"{HOST}/internal/backup.zip"),
                         "http_header:x-archive-source")
        self.assertNotIn(f"{HOST}/redirect-target", urls)

    def test_link_header_dispatched_inside_scan_header_values(self):
        hits = scan_header_values({"link": '</m/app.webmanifest>; rel="manifest"'}, BASE)
        self.assertEqual(hits[0].how, "http_link_header")
        self.assertEqual(hits[0].verbatim, f"{HOST}/m/app.webmanifest")


class TestJsonValueScan(unittest.TestCase):
    def test_manifest_fields(self):
        body = (b'{"start_url": "/app/", "icons": [{"src": "/i/icon.png"}],'
                b' "shortcuts": [{"url": "https://other.example/x"}],'
                b' "name": "not a url"}')
        hits = scan_json_values(body, f"{HOST}/manifest.json")
        urls = {h.verbatim: h.how for h in hits}
        self.assertEqual(urls[f"{HOST}/app/"], "json_value")
        self.assertEqual(urls[f"{HOST}/i/icon.png"], "json_value")
        self.assertIn("https://other.example/x", urls)  # recorded; scope filters later
        self.assertEqual(len([u for u in urls if "not a url" in u]), 0)

    def test_relative_resolution_against_blob_url(self):
        body = b'{"sources": ["../src/admin.js", "webpack://./x.js"]}'
        hits = scan_json_values(body, f"{HOST}/static/js/a.js.map")
        urls = [h.verbatim for h in hits]
        self.assertIn(f"{HOST}/static/src/admin.js", urls)
        self.assertNotIn("webpack://./x.js", urls)  # unresolvable scheme, dropped

    def test_invalid_json_no_crash(self):
        self.assertEqual(scan_json_values(b"not json{", BASE), [])


class TestSourcemapExtractor(unittest.TestCase):
    MAP = (b'{"version": 3,'
           b' "sources": ["webpack://./src/admin/config.js", "./util.js"],'
           b' "sourcesContent": ['
           b'   "// pre-bundle source\\nvar P = \'VISUALPING{aaaa1111bbbb2222}\';",'
           b'   "export const x = 1;"],'
           b' "mappings": "AAAA"}')

    def test_map_ext_routes_to_sourcemap_handler(self):
        self.assertIsNotNone(handler_for("application/json", url_ext="map"))
        surfaces = extract_blob("application/json", self.MAP, url_ext="map")
        tags = [t for t, _ in surfaces]
        self.assertIn("sourcemap:webpack://./src/admin/config.js", tags)
        self.assertIn("sourcemap:./util.js", tags)
        self.assertIn("raw", tags)

    def test_carrier_path_surface_carries_secret(self):
        surfaces = dict(extract_blob("application/json", self.MAP, url_ext="map"))
        payload = surfaces["sourcemap:webpack://./src/admin/config.js"]
        self.assertIn(b"VISUALPING{aaaa1111bbbb2222}", payload)

    def test_map_beats_json_shredding(self):
        # Without url_ext routing, the JSON walker would emit json_value:…
        # surfaces instead of carrier-path surfaces.
        surfaces = extract_blob("application/json", self.MAP, url_ext="map")
        self.assertFalse(any(t.startswith("json_value") for t, _ in surfaces))

    def test_malformed_map_falls_back_to_raw(self):
        surfaces = extract_blob("text/plain", b"{broken", url_ext="map")
        self.assertEqual([t for t, _ in surfaces], ["raw"])


class TestVttExtractor(unittest.TestCase):
    def test_text_vtt_has_handler(self):
        self.assertIsNotNone(handler_for("text/vtt"))
        surfaces = extract_blob("text/vtt", b"WEBVTT\n\n00:00.000 --> 00:01.000\nhello")
        self.assertIn(("raw", b"WEBVTT\n\n00:00.000 --> 00:01.000\nhello"), surfaces)


if __name__ == "__main__":
    unittest.main()
