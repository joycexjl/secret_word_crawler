"""Frontier: queue, seen-set, terminal-state accounting, caps.

Loop invariant (design §6): every canon key ever discovered ends in exactly
one terminal state —

    fetched | out_of_scope | errored | duplicate_key

and the four sets partition `seen`. The accounting assert IS the completeness
argument.

Safety valves: global MAX_RESOURCES plus a per-query-template cap (template =
path + sorted query parameter *names*, values ignored), so an unbounded
`/report/?page=N` space truncates at the template cap regardless of the global
budget. Hitting either cap is recorded loudly — a silent cap invalidates every
completeness claim.
"""

from __future__ import annotations

import logging
from collections import deque
from urllib.parse import parse_qsl, urlsplit

log = logging.getLogger("crawl.frontier")

TERMINAL_STATES = ("fetched", "out_of_scope", "errored", "duplicate_key")


def query_template(url: str) -> str:
    """Path + sorted query parameter names, values ignored."""
    parts = urlsplit(url)
    names = sorted({name for name, _ in parse_qsl(parts.query, keep_blank_values=True)})
    return parts.path + ("?" + "&".join(names) if names else "")


class CapHit:
    """A loud bounded-coverage admission (design §6/§10)."""

    def __init__(self, kind: str, key: str):
        self.kind = kind  # "global" | "template"
        self.key = key

    def __repr__(self) -> str:  # pragma: no cover
        return f"CapHit({self.kind}: {self.key})"


class Frontier:
    def __init__(self, max_resources: int = 500, per_template_cap: int = 60):
        self.max_resources = max_resources
        self.per_template_cap = per_template_cap

        self._queue: deque[tuple[str, str, int]] = deque()  # (canon, verbatim, depth)
        self.seen: set[str] = set()  # every canon key ever discovered
        self.verbatim_by_canon: dict[str, str] = {}  # first verbatim URL per key
        self.depth_by_canon: dict[str, int] = {}  # first_seen_depth (forensics)
        self.states: dict[str, str] = {}  # canon -> terminal state
        self.errors: dict[str, str] = {}  # canon -> reason (errored only)
        self._template_counts: dict[str, int] = {}  # template -> fetched count
        self.cap_hits: list[CapHit] = []
        self.retry_queue: deque[tuple[str, str, int]] = deque()
        self._retry_counts: dict[str, int] = {}

    # -- discovery -----------------------------------------------------------

    def add(self, canon: str, verbatim: str, depth: int) -> str:
        """Register a discovered canon key.

        Returns one of: "enqueued", "duplicate_key", "capped".
        Duplicate verbatim duplicates are recorded as edges by the caller and
        marked `duplicate_key` here at terminal-accounting time via
        `mark_duplicate_seen`.
        """
        if canon in self.seen:
            return "duplicate_key"
        if len(self.seen) >= self.max_resources:
            log.warning("GLOBAL CAP hit (%d): %s recorded but capped", self.max_resources, canon)
            self.cap_hits.append(CapHit("global", canon))
            self.seen.add(canon)  # seen, but will be recorded as capped
            self.states[canon] = "errored"
            self.errors[canon] = "capped: MAX_RESOURCES reached before first fetch"
            return "capped"
        template = query_template(canon)
        if self._template_counts.get(template, 0) >= self.per_template_cap:
            log.warning("TEMPLATE CAP hit on %r: %s truncated", template, canon)
            self.cap_hits.append(CapHit("template", template))
            self.seen.add(canon)
            self.states[canon] = "errored"
            self.errors[canon] = f"capped: per-template cap on {template!r}"
            return "capped"
        # Count at enqueue: the cap bounds how much of an unbounded template
        # space (e.g. /report/?page=N) ever enters the queue, not just how
        # much completes — a drain-slow flood must not inflate `seen`.
        self._template_counts[template] = self._template_counts.get(template, 0) + 1
        self.seen.add(canon)
        self.verbatim_by_canon[canon] = verbatim
        self.depth_by_canon[canon] = depth
        self._queue.append((canon, verbatim, depth))
        return "enqueued"

    # -- draining ------------------------------------------------------------

    def pop(self) -> tuple[str, str, int] | None:
        """Next (canon, verbatim, depth) to fetch; None when drained."""
        if self._queue:
            return self._queue.popleft()
        return None

    def drain_retries(self) -> None:
        """Re-enqueue transient failures for their single retry, after the
        main queue has drained (natural delay — design §6)."""
        while self.retry_queue:
            self._queue.append(self.retry_queue.popleft())

    @property
    def pending(self) -> int:
        return len(self._queue)

    # -- terminal states -----------------------------------------------------

    def mark_fetched(self, canon: str) -> None:
        self.states[canon] = "fetched"

    def mark_out_of_scope(self, canon: str) -> None:
        self.states[canon] = "out_of_scope"

    def mark_duplicate_seen(self, canon: str) -> None:
        """A canon key already in `seen` was reached again via a different
        verbatim URL. It keeps its existing terminal state; this is a no-op
        placeholder for symmetry with the accounting vocabulary."""
        # `duplicate_key` as a *state* applies to a canon key whose fetch was
        # skipped because an earlier verbatim URL with the same key was
        # fetched. Since identity IS the canon key, the first fetch covers it;
        # repeats only append edges. Tracked for the report's edge records.
        pass

    def mark_errored(self, canon: str, reason: str) -> None:
        self.states[canon] = "errored"
        self.errors[canon] = reason

    def defer_for_retry(self, canon: str, verbatim: str, depth: int) -> bool:
        """Queue a transient failure for its single retry. Returns False when
        the retry was already spent — the caller then marks it errored."""
        n = self._retry_counts.get(canon, 0)
        self._retry_counts[canon] = n + 1
        if n >= 1:
            return False
        self.retry_queue.append((canon, verbatim, depth))
        return True

    def retries_used(self, canon: str) -> int:
        return self._retry_counts.get(canon, 0)

    # -- accounting ----------------------------------------------------------

    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in TERMINAL_STATES}
        for state in self.states.values():
            out[state] += 1
        out["seen"] = len(self.seen)
        return out

    def assert_accounting(self) -> None:
        c = self.counts()
        total = sum(c[s] for s in TERMINAL_STATES)
        assert total == c["seen"], (
            f"accounting imbalance: {total} terminal vs {c['seen']} seen; "
            f"unaccounted: {sorted(k for k in self.seen if k not in self.states)[:10]}"
        )
