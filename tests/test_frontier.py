"""Unit tests for crawl/frontier.py — accounting invariant and caps."""

import unittest

from crawl.frontier import Frontier, query_template


class TestQueryTemplate(unittest.TestCase):
    def test_path_plus_sorted_names(self):
        self.assertEqual(query_template("http://h/report/?page=3"), "/report/?page")
        self.assertEqual(
            query_template("http://h/x?b=1&a=2"), "/x?a&b"
        )

    def test_values_ignored(self):
        self.assertEqual(
            query_template("http://h/report/?page=1"),
            query_template("http://h/report/?page=99"),
        )


class TestFrontierAccounting(unittest.TestCase):
    def test_enqueue_and_fetch(self):
        f = Frontier()
        self.assertEqual(f.add("http://h/", "http://h/", 0), "enqueued")
        item = f.pop()
        self.assertEqual(item, ("http://h/", "http://h/", 0))
        f.mark_fetched("http://h/")
        f.assert_accounting()
        self.assertEqual(f.counts()["fetched"], 1)

    def test_duplicate_key(self):
        f = Frontier()
        f.add("http://h/a?x=1", "http://h/a?x=1", 0)
        # Same canon key reached again -> duplicate, not re-enqueued.
        self.assertEqual(f.add("http://h/a?x=1", "http://h/a?x=1#f", 1), "duplicate_key")
        self.assertEqual(f.pending, 1)

    def test_out_of_scope_terminal(self):
        f = Frontier()
        f.add("http://h/a", "http://h/a", 0)
        f.pop()
        f.mark_out_of_scope("http://h/a")
        f.assert_accounting()

    def test_unaccounted_fails_assert(self):
        f = Frontier()
        f.add("http://h/a", "http://h/a", 0)
        with self.assertRaises(AssertionError):
            f.assert_accounting()

    def test_global_cap(self):
        f = Frontier(max_resources=2)
        f.add("http://h/1", "http://h/1", 0)
        f.add("http://h/2", "http://h/2", 0)
        self.assertEqual(f.add("http://h/3", "http://h/3", 0), "capped")
        self.assertTrue(any(h.kind == "global" for h in f.cap_hits))
        # Capped keys are still accounted (errored with a loud reason).
        f.pop(); f.mark_fetched("http://h/1")
        f.pop(); f.mark_fetched("http://h/2")
        f.assert_accounting()
        self.assertIn("MAX_RESOURCES", f.errors["http://h/3"])

    def test_template_cap(self):
        f = Frontier(per_template_cap=3)
        for n in range(3):
            self.assertEqual(
                f.add(f"http://h/report/?page={n}", f"http://h/report/?page={n}", 0),
                "enqueued",
            )
        self.assertEqual(
            f.add("http://h/report/?page=3", "http://h/report/?page=3", 0),
            "capped",
        )
        self.assertTrue(any(h.kind == "template" for h in f.cap_hits))

    def test_retry_reenqueue_after_drain(self):
        f = Frontier()
        f.add("http://h/a", "http://h/a", 0)
        f.pop()
        f.defer_for_retry("http://h/a", "http://h/a", 0)
        self.assertIsNone(f.pop())
        f.drain_retries()
        self.assertIsNotNone(f.pop())


if __name__ == "__main__":
    unittest.main()
