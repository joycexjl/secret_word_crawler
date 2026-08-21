"""Unit tests for M3: report.py — blocked notices, disagreements,
duplication case split, inventory aggregation."""

import unittest

from crawl.report import (
    build_disagreements,
    build_duplication,
    build_filetype_inventory,
    build_unhandled,
    is_blocked_notice,
)


def row(url, ct, ext, sniff, sha="a" * 64, length=10, canon=None, status=200):
    return {
        "url": url, "canon_key": canon or url, "status": status,
        "content_type": ct, "url_ext": ext, "sniffed_type": sniff,
        "sha256": sha, "length": length,
    }


class TestBlockedNotice(unittest.TestCase):
    def test_geo_block_phrase_matches(self):
        self.assertTrue(is_blocked_notice(200, b"This page is only visible to users in Germany."))

    def test_non_200_never_blocked(self):
        self.assertFalse(is_blocked_notice(404, b"only visible to"))

    def test_normal_page_not_blocked(self):
        self.assertFalse(is_blocked_notice(200, b"<html>ordinary page</html>"))


class TestInventory(unittest.TestCase):
    def test_aggregates_and_marks_extractor(self):
        rows = [
            row("http://h/a", "text/html", "html", "text/html", length=100),
            row("http://h/b", "text/html", "html", "text/html", length=50),
            row("http://h/c.png", "image/png", "png", "image/png", sha="b" * 64),
            row("http://h/d", "application/x-bogus", "", "application/octet-stream", sha="c" * 64),
        ]
        inv = {i["content_type"]: i for i in build_filetype_inventory(rows)}
        self.assertEqual(inv["text/html"]["count"], 2)
        self.assertEqual(inv["text/html"]["bytes"], 150)
        self.assertTrue(inv["image/png"]["has_extractor"])
        self.assertFalse(inv["application/x-bogus"]["has_extractor"])
        self.assertEqual(build_unhandled(build_filetype_inventory(rows)), ["application/x-bogus"])


class TestDisagreements(unittest.TestCase):
    def test_png_served_as_html_flagged(self):
        rows = [row("http://h/x.png", "text/html", "png", "image/png")]
        d = build_disagreements(rows)
        self.assertEqual(len(d), 1)

    def test_octet_stream_sniffing_pdf_flagged(self):
        rows = [row("http://h/dl", "application/octet-stream", "", "application/pdf")]
        self.assertEqual(len(build_disagreements(rows)), 1)

    def test_agreeing_row_quiet(self):
        rows = [row("http://h/a.png", "image/png", "png", "image/png")]
        self.assertEqual(build_disagreements(rows), [])

    def test_extensionless_route_not_flagged(self):
        # No extension -> ext carries no opinion; header+sniff agreeing is fine.
        rows = [row("http://h/report/", "text/html", "", "text/html")]
        self.assertEqual(build_disagreements(rows), [])


class TestDuplication(unittest.TestCase):
    def test_same_bytes_different_urls(self):
        sha = "d" * 64
        rows = [
            row("http://h/a/img.png", "image/png", "png", "image/png", sha=sha),
            row("http://h/b/img.png", "image/png", "png", "image/png", sha=sha),
        ]
        dup = build_duplication(rows, [])
        self.assertEqual(dup[0]["case"], "same_bytes_different_urls")
        self.assertEqual(len(dup[0]["urls"]), 2)

    def test_same_url_multiple_referrers(self):
        sha = "e" * 64
        rows = [row("http://h/shared.png", "image/png", "png", "image/png", sha=sha)]
        edges = [
            {"src": "http://h/p1", "dst": "http://h/shared.png", "how": "img_src"},
            {"src": "http://h/p2", "dst": "http://h/shared.png", "how": "img_src"},
        ]
        dup = build_duplication(rows, edges)
        self.assertEqual(dup[0]["case"], "same_url_multiple_referrers")
        self.assertEqual(len(dup[0]["referrers"]), 2)

    def test_singly_referenced_single_url_not_duplication(self):
        rows = [row("http://h/once.png", "image/png", "png", "image/png", sha="f" * 64)]
        edges = [{"src": "http://h/p1", "dst": "http://h/once.png", "how": "img_src"}]
        self.assertEqual(build_duplication(rows, edges), [])


if __name__ == "__main__":
    unittest.main()
