"""Unit tests for M2: discover.py tiers and graph.py post-hoc BFS depths."""

import unittest

from crawl.discover import in_scope_hits, scan_bytes
from crawl.graph import bfs_depths
from crawl.normalize import ScopeTriple

SCOPE = ScopeTriple("http", "54.214.7.161", 80)
BASE = "http://54.214.7.161/docs/"


class TestByteScanTiers(unittest.TestCase):
    def test_tier1_absolute(self):
        body = b'fetch("http://54.214.7.161/api/data.json")'
        r = scan_bytes(body, BASE, SCOPE)
        self.assertEqual([h.verbatim for h in r.hits], ["http://54.214.7.161/api/data.json"])
        self.assertEqual(r.hits[0].tier, 1)

    def test_tier1_out_of_scope_kept_then_filtered(self):
        body = b'fetch("https://evil.example.com/x.json")'
        r = scan_bytes(body, BASE, SCOPE)
        self.assertEqual(len(r.hits), 1)  # recorded…
        self.assertEqual(in_scope_hits(r, SCOPE), [])  # …but not enqueued

    def test_tier2_root_relative_with_extension(self):
        body = b"img.src = '/assets/logo.png';"
        r = scan_bytes(body, BASE, SCOPE)
        self.assertIn("http://54.214.7.161/assets/logo.png", [h.verbatim for h in r.hits])

    def test_tier2_known_route_shape(self):
        body = b'nav("/wiki/shard-schedule/")'
        r = scan_bytes(body, BASE, SCOPE)
        self.assertIn("http://54.214.7.161/wiki/shard-schedule/", [h.verbatim for h in r.hits])

    def test_tier3_relative_with_extension(self):
        body = b'url("../fonts/a.woff2")'
        r = scan_bytes(body, BASE, SCOPE)
        self.assertIn("http://54.214.7.161/fonts/a.woff2", [h.verbatim for h in r.hits])

    def test_bare_extensionless_goes_to_needs_review(self):
        body = b'load("reports/monthly")'
        r = scan_bytes(body, BASE, SCOPE)
        self.assertIn("reports/monthly", r.needs_review)
        self.assertNotIn(
            "http://54.214.7.161/docs/reports/monthly", [h.verbatim for h in r.hits]
        )

    def test_quote_delimited_no_slicing(self):
        # Unquoted junk in minified code must not match.
        body = b"var a=http://54.214.7.161/x.png;var b=1"
        r = scan_bytes(body, BASE, SCOPE)
        self.assertEqual(r.hits, [])

    def test_binary_blob_no_crash(self):
        body = bytes(range(256)) * 4
        r = scan_bytes(body, BASE, SCOPE)
        self.assertIsInstance(r.hits, list)


class TestPostHocDepths(unittest.TestCase):
    def test_bfs_shortest_path_wins(self):
        edges = [
            {"src": "http://54.214.7.161/", "dst": "http://54.214.7.161/a", "how": "a_href"},
            {"src": "http://54.214.7.161/a", "dst": "http://54.214.7.161/b", "how": "a_href"},
            # Late-arriving shortcut must not overwrite b's depth of 2... and
            # a direct edge from root must record depth 1 even if seen later.
            {"src": "http://54.214.7.161/", "dst": "http://54.214.7.161/b", "how": "xhr"},
        ]
        d = bfs_depths(edges, "http://54.214.7.161/")
        self.assertEqual(d["http://54.214.7.161/"], 0)
        self.assertEqual(d["http://54.214.7.161/a"], 1)
        self.assertEqual(d["http://54.214.7.161/b"], 1)  # shortest path

    def test_unreachable_not_in_depths(self):
        edges = [{"src": "http://x/", "dst": "http://y/", "how": "a_href"}]
        d = bfs_depths(edges, "http://54.214.7.161/")
        self.assertNotIn("http://y/", d)


if __name__ == "__main__":
    unittest.main()
