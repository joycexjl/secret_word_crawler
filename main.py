"""M2 — crawl: fetch every in-scope resource, expand 2xx HTML, fixpoint loop.

Loop shape (design §6):

  1. Browser phase — drain the frontier: FETCH everything (bytes recorded via
     the API request context), EXPAND 2xx HTML pages (Tier 0 DOM harvest +
     Tier 1 passive observation in a real page).
  2. Byte-scan phase — run discover.py over every blob; enqueue new in-scope
     canon keys as `regex_fallback` edges.

Alternate until the byte-scan yields nothing new (the fixpoint). Termination
asserts the accounting invariant: fetched + out_of_scope + errored +
duplicate_key == seen.

Config lives in CONFIG below (design §11). Credentials from the environment,
never hardcoded. No resume: any failure means a clean re-crawl from an empty
out/ (a full run is minutes; the site is not ours).
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from collections import Counter
from pathlib import Path

log = logging.getLogger("crawl")

from crawl.browser import CrawlBrowser
from crawl.discover import (
    in_scope_hits,
    scan_bytes,
    scan_header_values,
    scan_json_values,
)
from crawl.frontier import Frontier
from crawl.graph import EdgeStore, bfs_depths, export_dot, load_edges
from crawl.normalize import ScopeTriple, canon_key, in_scope
from crawl.report import (
    build_disagreements,
    build_duplication,
    build_filetype_inventory,
    build_unhandled,
    is_blocked_notice,
    load_manifest,
    write_coverage_md,
    write_filetypes_md,
)
from crawl.store import BlobStore, Manifest, make_record
from crawl.envfile import load_dotenv

CONFIG = {
    "scope": ScopeTriple("http", "54.214.7.161", 80),
    "seed_url": "http://54.214.7.161/",
    "username_env": "VISUALPING_USER",
    "password_env": "VISUALPING_PASS",
    "delay_range": (0.25, 0.5),
    # Global cap raised 500 -> 2000 (locked in M6 grilling): 500 fired and left
    # pages unfetched, invalidating the fixpoint completeness argument. The
    # per-template cap (60) is what bounds the unbounded /report/?page=N flood;
    # politeness is the serial 250-500ms delay, not the global ceiling. The
    # coverage report records loudly if even 2000 caps out.
    "max_resources": 2000,
    "per_template_cap": 60,
    "expected_secrets": 8,
    "tier2_enabled": True,  # Tier 2 interaction itself lands after M2
    "out_dir": Path(__file__).parent / "out",
}

# Declared-but-possibly-unlinked paths (M6 grilling): robots.txt Disallow
# entries map no-inbound-link pages; sitemap/manifest/humans/security.txt and
# the 404 handler are classic declared surfaces. Seeded into the frontier so
# the crawl reaches them even if nothing links to them. The byte-scan reads
# their contents for further paths.
DECLARED_PATH_SEEDS = [
    "/robots.txt",
    "/sitemap.xml",
    "/manifest.json",
    "/humans.txt",
    "/.well-known/security.txt",
    "/favicon.ico",
]


def is_expandable(record: dict) -> bool:
    """Only 2xx HTML pages are expanded (design §3: fetch ≠ expand)."""
    return (
        200 <= record["status"] < 300
        and record["content_type"].startswith("text/html")
    )


def main() -> int:
    level = getattr(logging, os.environ.get("CRAWL_LOG", "INFO").upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )
    load_dotenv()  # .env fills VISUALPING_USER/PASS unless already in env
    username = os.environ.get(CONFIG["username_env"])
    password = os.environ.get(CONFIG["password_env"])
    if not username or not password:
        print(
            f"credentials missing: set {CONFIG['username_env']} and "
            f"{CONFIG['password_env']} in the environment or in .env",
            file=sys.stderr,
        )
        return 2

    out_dir: Path = CONFIG["out_dir"]
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"error: {out_dir} is not empty — no resume; clear it first", file=sys.stderr)
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    log.info("crawl start: seed=%s scope=%s:%s:%s caps=(global=%d, per-template=%d)",
             CONFIG["seed_url"], CONFIG["scope"].scheme, CONFIG["scope"].host,
             CONFIG["scope"].port, CONFIG["max_resources"], CONFIG["per_template_cap"])

    store = BlobStore(out_dir)
    manifest = Manifest(out_dir)
    edges = EdgeStore(out_dir)
    frontier = Frontier(
        max_resources=CONFIG["max_resources"],
        per_template_cap=CONFIG["per_template_cap"],
    )
    scope: ScopeTriple = CONFIG["scope"]
    seed = CONFIG["seed_url"]
    root_canon = canon_key(seed)
    frontier.add(root_canon, seed, depth=0)
    # Declared-path seeds (robots/sitemap/manifest/etc.): reachable even if no
    # page links to them. Recorded as edges from the root with how=seed.
    for path in DECLARED_PATH_SEEDS:
        url = f"http://{scope.host}{path}"
        if in_scope(url, scope):
            frontier.add(canon_key(url), url, depth=1)
            edges.write(src=root_canon, dst=canon_key(url), how="seed",
                        hint="declared-path", depth=0)
    log.info("seeded %d declared-path candidates", len(DECLARED_PATH_SEEDS))

    redirect_outs: list[dict] = []
    needs_review_urls: set[str] = set()
    scanned_blobs: set[str] = set()  # sha256 already byte-scanned
    scanned_headers: set[str] = set()  # canon keys whose headers are link-scanned

    with CrawlBrowser(
        scope, username, password, delay_range=CONFIG["delay_range"]
    ) as browser:

        def record_edge(src_canon: str, dst_verbatim: str, how: str, hint: str, depth: int) -> None:
            dst_canon = canon_key(dst_verbatim)
            edges.write(src=src_canon, dst=dst_canon, how=how, hint=hint, depth=depth)
            if not in_scope(dst_verbatim, scope):
                if dst_canon not in frontier.seen:
                    frontier.seen.add(dst_canon)
                    frontier.states[dst_canon] = "out_of_scope"
                return
            outcome = frontier.add(dst_canon, dst_verbatim, depth + 1)
            if outcome == "duplicate_key":
                pass  # edge already appended above; node keeps first-seen depth

        # -- fixpoint: alternate browser phase and byte-scan phase -----------
        round_no = 0
        while True:
            round_no += 1
            made_progress = False
            log.info("── browser phase (round %d): frontier has %d pending", round_no, frontier.pending)

            # Browser phase: drain the frontier.
            while True:
                item = frontier.pop()
                if item is None:
                    frontier.drain_retries()
                    item = frontier.pop()
                    if item is None:
                        break
                canon, verbatim, depth = item
                made_progress = True
                log.info("fetch [%d left, depth %d] %s", frontier.pending, depth, verbatim)

                result = browser.fetch(verbatim)
                if result.ok:
                    sha = store.put(result.body)
                    record = make_record(
                        url=verbatim, canon=canon, final_url=result.final_url,
                        status=result.status,
                        content_type_header=result.headers.get("content-type"),
                        headers=result.headers, body=result.body, sha256=sha,
                        first_seen_depth=depth,
                    )
                    # Blocked notice: a real, accounted fetch whose body is a
                    # policy block — a named coverage exception (design §5/§10).
                    record["blocked_notice"] = is_blocked_notice(result.status, result.body)
                    log.info("  → %d %s, %d bytes, sha=%s…%s", result.status,
                             record["content_type"] or "(no content-type)",
                             record["length"], sha[:8], "")
                    if record["blocked_notice"]:
                        log.warning("  ⚠ blocked notice (policy block/interstitial): %s", verbatim)

                    # Redirect: record the edge; flag redirect-outs for ruling.
                    if result.final_url != verbatim:
                        final_canon = canon_key(result.final_url)
                        edges.write(src=canon, dst=final_canon, how="redirect",
                                    hint=f"HTTP {result.status}", depth=depth)
                        if not in_scope(result.final_url, scope):
                            log.warning("  ⚠ redirect-OUT to %s (flagged for manual ruling)",
                                        result.final_url)
                            redirect_outs.append({"from": verbatim, "to": result.final_url})
                        else:
                            log.info("  → redirect to %s", result.final_url)
                            if final_canon != canon and final_canon not in frontier.seen:
                                frontier.add(final_canon, result.final_url, depth)

                    # Expand: 2xx HTML gets a real page render (Tier 0/1).
                    if is_expandable(record):
                        log.debug("  expanding (Tier 0/1 render): %s", result.final_url)
                        exp = browser.expand(result.final_url)
                        if exp.ok:
                            record["rendered_sha256"] = store.put(exp.rendered_html)
                            if exp.interacted_html:
                                record["interacted_sha256"] = store.put(exp.interacted_html)
                                record["clicks"] = exp.clicks
                            record["idle_timeout"] = exp.idle_timeout
                            if exp.late_mutations:
                                record["late_mutations"] = exp.late_mutations
                            if exp.closed_shadow_roots:
                                record["closed_shadow_roots"] = exp.closed_shadow_roots
                            if exp.shadow_root_count:
                                record["shadow_roots"] = exp.shadow_root_count
                            if exp.unexplained_interactives:
                                record["unexplained_interactives"] = exp.unexplained_interactives
                            new_edges = 0
                            for d in exp.discovered:
                                before = len(frontier.seen)
                                record_edge(canon, d.verbatim, d.how, d.hint, depth)
                                if len(frontier.seen) > before:
                                    new_edges += 1
                                    log.debug("    + %-14s %s", d.how, d.verbatim)
                            log.info("  expanded: %d URLs discovered (%d new), "
                                     "shadow=%d closed=%d late_mut=%d idle_to=%s "
                                     "interactives=%d clicks=%d",
                                     len(exp.discovered), new_edges, exp.shadow_root_count,
                                     exp.closed_shadow_roots, exp.late_mutations,
                                     exp.idle_timeout, exp.unexplained_interactives,
                                     exp.clicks)
                        else:
                            log.warning("  expand failed: %s", exp.error)
                            record["expand_error"] = exp.error

                    manifest.write(record)
                    frontier.mark_fetched(canon)
                elif result.transient and frontier.defer_for_retry(canon, verbatim, depth):
                    log.warning("  transient failure (%s); retry queued", result.error)
                else:
                    log.warning("  ✗ errored: %s", result.error)
                    frontier.mark_errored(canon, result.error)
                    manifest.write({
                        "url": verbatim, "canon_key": canon, "status": result.status,
                        "error": result.error, "first_seen_depth": depth,
                        "retries": frontier.retries_used(canon),
                    })

            # Byte-scan phase: discover URLs hidden in non-HTML bytes, plus
            # the offline scanners (ADR 0002): response-header links and
            # URL-valued JSON strings. All emit into the same frontier under
            # the same fixpoint.
            log.info("── byte-scan phase (round %d): %d blob(s) already scanned",
                     round_no, len(scanned_blobs))
            new_from_scan = 0
            blobs_this_round = 0

            def enqueue_scan_hit(row: dict, hit) -> None:
                nonlocal new_from_scan
                hit_canon = canon_key(hit.verbatim)
                if hit_canon in frontier.seen:
                    return
                how = hit.how or "regex_fallback"
                hint = hit.hint or (f"tier{hit.tier}" if not hit.how else "")
                edges.write(src=row["canon_key"], dst=hit_canon,
                            how=how, hint=hint,
                            depth=row.get("first_seen_depth", 0))
                frontier.add(hit_canon, hit.verbatim,
                             row.get("first_seen_depth", 0) + 1)
                new_from_scan += 1
                log.info("  scan found (%s): %s", how, hit.verbatim)

            for row_path in [out_dir / "manifest.jsonl"]:
                for line in row_path.read_text().splitlines():
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    sha = row.get("sha256")
                    if not sha:
                        continue

                    # Header-borne links (ADR 0002): Link: parsed structurally,
                    # all other header values pattern-scanned. Once per row.
                    row_canon = row.get("canon_key", row["url"])
                    if row_canon not in scanned_headers:
                        scanned_headers.add(row_canon)
                        for hit in scan_header_values(row.get("headers", {}),
                                                      row["url"]):
                            if in_scope(hit.verbatim, scope):
                                enqueue_scan_hit(row, hit)

                    if sha in scanned_blobs:
                        continue
                    scanned_blobs.add(sha)
                    blobs_this_round += 1
                    blob = store.get(sha)
                    scan = scan_bytes(blob, row["url"], scope)
                    needs_review_urls.update(scan.needs_review)
                    for hit in in_scope_hits(scan, scope):
                        enqueue_scan_hit(row, hit)

                    # URL-valued JSON strings (ADR 0002): web manifests,
                    # sourcemap `sources` arrays, any config.json.
                    if row.get("content_type", "").startswith(
                            ("application/json", "application/manifest+json")
                    ) or row.get("url_ext") in ("json", "map", "webmanifest"):
                        for hit in scan_json_values(blob, row["url"]):
                            if in_scope(hit.verbatim, scope):
                                enqueue_scan_hit(row, hit)

            log.info("── round %d done: %d blob(s) scanned, %d new URL(s) from byte-scan, "
                     "%d pending", round_no, blobs_this_round, new_from_scan, frontier.pending)
            if frontier.pending == 0 and new_from_scan == 0:
                log.info("fixpoint reached after %d round(s): frontier empty AND byte-scan "
                         "found nothing new", round_no)
                break
            if not made_progress and new_from_scan == 0:
                break

    edges.close()
    manifest.close()
    log.info("frontier drained: %d seen; closing stores, exporting reports", len(frontier.seen))

    # -- export: graph, depth histogram, inventory, coverage report ----------
    all_edges = load_edges(out_dir)
    manifest_rows = load_manifest(out_dir)
    depths = bfs_depths(all_edges, root_canon)
    dot_path = export_dot(out_dir, all_edges, manifest_rows, frontier.states, seed)

    frontier.assert_accounting()
    c = frontier.counts()
    hist = Counter(depths.values())

    # M3 reports — all derived from the on-disk artifacts.
    fetched_rows = [r for r in manifest_rows if "sha256" in r]
    inventory = build_filetype_inventory(fetched_rows)
    disagreements = build_disagreements(fetched_rows)
    unhandled = build_unhandled(inventory)
    duplication = build_duplication(fetched_rows, all_edges)
    filetypes_path = write_filetypes_md(out_dir, inventory, disagreements, unhandled)
    coverage_path = write_coverage_md(
        out_dir,
        counts=c,
        depth_hist=dict(sorted(hist.items())),
        cap_hits=frontier.cap_hits,
        blocked_notices=[r for r in fetched_rows if r.get("blocked_notice")],
        errors=frontier.errors,
        redirect_outs=redirect_outs,
        needs_review=sorted(needs_review_urls),
        disqualified_header_sightings=0,  # populated by Phase 2 extraction
        duplication=duplication,
        unhandled=unhandled,
        idle_timeouts=[r["url"] for r in fetched_rows if r.get("idle_timeout")],
        late_mutations=[r["url"] for r in fetched_rows if r.get("late_mutations")],
        closed_shadow_roots=[r["url"] for r in fetched_rows if r.get("closed_shadow_roots")],
        unexplained_interactives=[r["url"] for r in fetched_rows if r.get("unexplained_interactives")],
    )

    print("=== M3 coverage accounting ===")
    for state in ("fetched", "out_of_scope", "errored", "duplicate_key"):
        print(f"  {state:<14} {c[state]}")
    print(f"  {'seen':<14} {c['seen']}")
    print(f"depth histogram (post-hoc BFS): {dict(sorted(hist.items()))}")
    print(f"filetypes: {len(inventory)} distinct; unhandled: {unhandled or 'none'}")
    print(f"disagreements: {len(disagreements)}; duplication groups: {len(duplication)}")
    print(f"artifacts: {dot_path.name}, {filetypes_path.name}, {coverage_path.name}")

    loudly = []
    if frontier.cap_hits:
        loudly.append("CAPS HIT (bounded-coverage admission):")
        loudly += [f"  {h.kind}: {h.key}" for h in frontier.cap_hits]
    if redirect_outs:
        loudly.append(f"REDIRECT-OUTS for manual ruling: {len(redirect_outs)}")
    if needs_review_urls:
        loudly.append(f"NEEDS-REVIEW extensionless refs: {len(needs_review_urls)}")
    bn = [r["url"] for r in fetched_rows if r.get("blocked_notice")]
    if bn:
        loudly.append(f"BLOCKED NOTICES (coverage exception): {len(bn)}")
    if unhandled:
        loudly.append(f"UNHANDLED TYPES (Phase 2 gap): {unhandled}")
    if browser.blocked_out_of_scope:
        loudly.append(f"network-layer blocked out-of-scope requests: {len(browser.blocked_out_of_scope)}")
    if browser.blocked_mutations:
        loudly.append(f"network-layer blocked non-GET: {len(browser.blocked_mutations)}")
    idle = [r["url"] for r in manifest_rows if r.get("idle_timeout")]
    if idle:
        loudly.append(f"idle_timeout pages: {len(idle)}")
    late = [r["url"] for r in manifest_rows if r.get("late_mutations")]
    if late:
        loudly.append(f"late_mutation tripwire pages: {len(late)}")
    closed = [r["url"] for r in manifest_rows if r.get("closed_shadow_roots")]
    if closed:
        loudly.append(f"CLOSED shadow roots (cannot walk): {len(closed)}")

    if loudly:
        print("!! findings:")
        for line in loudly:
            print("  " + line)
    log.info("crawl done in %.1fs: %d fetched, %d errored, %d out-of-scope, "
             "%d edge(s), %d blob(s) → %s",
             time.monotonic() - started, c["fetched"], c["errored"],
             c["out_of_scope"], len(all_edges), len(scanned_blobs), out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
