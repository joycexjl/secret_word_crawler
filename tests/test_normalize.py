"""Unit tests for crawl/normalize.py — the one module worth testing up front
(design §6: "the single place where bugs silently cost you pages")."""

import unittest

from crawl.normalize import (
    ScopeTriple,
    canon_key,
    in_scope,
    normalize_path,
    resolve,
    scope_triple,
)

SCOPE = ScopeTriple("http", "54.214.7.161", 80)


class TestCanonKey(unittest.TestCase):
    def test_lowercases_scheme_and_host(self):
        self.assertEqual(
            canon_key("HTTP://EXAMPLE.COM/Path"),
            "http://example.com/Path",
        )

    def test_strips_default_port(self):
        self.assertEqual(canon_key("http://example.com:80/a"), "http://example.com/a")
        self.assertEqual(canon_key("https://example.com:443/a"), "https://example.com/a")

    def test_keeps_nondefault_port(self):
        self.assertEqual(canon_key("http://example.com:8080/a"), "http://example.com:8080/a")

    def test_drops_fragment(self):
        self.assertEqual(canon_key("http://example.com/a#frag"), "http://example.com/a")

    def test_sorts_query_params(self):
        self.assertEqual(
            canon_key("http://example.com/a?b=2&a=1"),
            "http://example.com/a?a=1&b=2",
        )

    def test_duplicate_bait_same_key(self):
        # Recon: query-param duplicate bait must collapse to one canon key.
        self.assertEqual(
            canon_key("http://54.214.7.161/docs/?ref=related"),
            canon_key("http://54.214.7.161/docs/?ref=related#top"),
        )
        self.assertNotEqual(
            canon_key("http://54.214.7.161/docs/?ref=related"),
            canon_key("http://54.214.7.161/docs/"),
        )

    def test_param_order_collapses(self):
        self.assertEqual(
            canon_key("http://example.com/r?a=1&b=2"),
            canon_key("http://example.com/r?b=2&a=1"),
        )

    def test_path_dotdot_normalised(self):
        self.assertEqual(canon_key("http://example.com/a/b/../c"), "http://example.com/a/c")

    def test_trailing_slash_distinct(self):
        # /page and /page/ are distinct URLs; the server decides (design §6).
        self.assertNotEqual(
            canon_key("http://example.com/page"),
            canon_key("http://example.com/page/"),
        )

    def test_blank_query_value_preserved(self):
        self.assertEqual(canon_key("http://example.com/a?x="), "http://example.com/a?x=")


class TestNormalizePath(unittest.TestCase):
    def test_dotdot(self):
        self.assertEqual(normalize_path("/a/b/../c"), "/a/c")

    def test_trailing_slash_kept(self):
        self.assertEqual(normalize_path("/a/b/"), "/a/b/")

    def test_root(self):
        self.assertEqual(normalize_path("/"), "/")


class TestScope(unittest.TestCase):
    def test_in_scope(self):
        self.assertTrue(in_scope("http://54.214.7.161/", SCOPE))
        self.assertTrue(in_scope("http://54.214.7.161:80/x", SCOPE))

    def test_https_out(self):
        self.assertFalse(in_scope("https://54.214.7.161/", SCOPE))

    def test_other_port_out(self):
        self.assertFalse(in_scope("http://54.214.7.161:8080/", SCOPE))

    def test_other_host_out(self):
        self.assertFalse(in_scope("http://example.com/", SCOPE))

    def test_default_port_fill(self):
        t = scope_triple("http://54.214.7.161/x")
        self.assertEqual(t, SCOPE)


class TestResolve(unittest.TestCase):
    base = "http://54.214.7.161/docs/"

    def test_relative(self):
        self.assertEqual(resolve(self.base, "a.png"), "http://54.214.7.161/docs/a.png")

    def test_root_relative(self):
        self.assertEqual(resolve(self.base, "/x/y"), "http://54.214.7.161/x/y")

    def test_absolute(self):
        self.assertEqual(resolve(self.base, "http://54.214.7.161/z"), "http://54.214.7.161/z")

    def test_base_href_override(self):
        self.assertEqual(
            resolve("http://54.214.7.161/assets/", "x.css"),
            "http://54.214.7.161/assets/x.css",
        )

    def test_rejects_non_http_schemes(self):
        for ref in ("javascript:void(0)", "mailto:a@b.c", "data:image/png;base64,xx", "#frag", ""):
            self.assertIsNone(resolve(self.base, ref), ref)


if __name__ == "__main__":
    unittest.main()
