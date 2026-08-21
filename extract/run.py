"""Extraction runner — iterates manifest rows (fetch events), not blobs.

- Body-bearing extractors run once per unique sha256 and fan sightings out to
  every row carrying that hash (design §8).
- Header/cookie scanning runs per row; matches are disqualified per the
  challenge rule and reported in one summary line.
- HTML pages are a DUAL corpus: raw bytes (`html_raw`) and the rendered-DOM
  snapshot (`html_rendered`). A value found in only one corpus is a named
  divergence finding (the site mutates its DOM both ways — recon §13).
- LOOSE hits failing STRICT go to the needs-review bucket, which has a forced
  exit criterion: every entry resolved via documented correction or ruled
  not-a-secret in writing.

Offline: reads out/manifest.jsonl + out/blobs/, writes out/secrets.json and
out/extraction.md. Never touches the network (design §1: record first,
extract later).
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path

from .core import Sighting, scan_headers, scan_text
from .images import analyze_image
from .registry import extract_blob, handler_for

log = logging.getLogger("crawl.extract")

EXPECTED_SECRETS = 8


def _sighting_key(s: Sighting) -> tuple:
    return (s.canonical, s.raw, s.url, s.how_found)


def run(out_dir: Path, expected: int = EXPECTED_SECRETS) -> dict:
    out_dir = Path(out_dir)
    rows = [
        json.loads(l)
        for l in (out_dir / "manifest.jsonl").read_text().splitlines()
        if l.strip()
    ]
    fetched = [r for r in rows if "sha256" in r]
    log.info("extract: %d manifest rows, %d fetched, %d unique blobs",
             len(rows), len(fetched), len({r["sha256"] for r in fetched}))

    by_hash: dict[str, list[dict]] = defaultdict(list)
    for r in fetched:
        by_hash[r["sha256"]].append(r)

    strict: dict[str, list[Sighting]] = defaultdict(list)   # canonical -> sightings
    needs_review: list[Sighting] = []
    disqualified: list[Sighting] = []
    divergences: list[dict] = []   # raw-only / rendered-only findings
    unhandled: list[str] = []
    image_reports: list = []       # coverage hook: every image, with its ruling
    sweep_log = out_dir / "pixel_sweep.jsonl"
    if sweep_log.exists():
        sweep_log.unlink()  # fresh per run; the log is per-run evidence

    # -- body extraction, once per unique blob, fanned out to carrier rows ---
    for sha, group in by_hash.items():
        ct = group[0]["content_type"]
        body = (out_dir / "blobs" / sha).read_bytes()
        if handler_for(ct) is None:
            unhandled.append(ct)
            log.warning("no extractor for %s (%s)", ct, group[0]["url"])
        log.debug("extract %s (%s, %d bytes, %d row(s))", sha[:8], ct, len(body), len(group))

        # M5 image track: metadata + enumerated pixel sweep, once per unique
        # blob, sightings fanned out to every carrier row (design §8/§9).
        if ct.startswith("image/") and ct != "image/svg+xml":
            log.info("  pixel sweep: %s", group[0]["url"])
            rep = analyze_image(body, url=group[0]["url"], sha256=sha,
                                sweep_log=sweep_log)
            log.info("    deviating px=%d, %d candidates, %d with hits → %s",
                     rep.deviating_pixels, rep.candidates_tried,
                     rep.candidates_with_hits, rep.ruling)
            image_reports.append(rep)
            for s in rep.sightings:
                for row in group:
                    _route(Sighting(s.canonical, s.raw, s.how_found,
                                    row["url"], sha), strict, needs_review)
            for s in rep.needs_review:
                needs_review.append(s)

        surfaces = extract_blob(ct, body)
        for sub, data in surfaces:
            for row in group:
                for s in scan_text(data, how_found=f"{ct}:{sub}",
                                     url=row["url"], sha256=sha):
                    _route(s, strict, needs_review)

        # Dual corpus for HTML: the rendered snapshot is a separate blob.
        for row in group:
            rsha = row.get("rendered_sha256")
            if not rsha:
                continue
            rendered = (out_dir / "blobs" / rsha).read_bytes()
            for sub, data in extract_blob("text/html", rendered):
                for s in scan_text(data, how_found=f"rendered:{sub}",
                                   url=row["url"], sha256=rsha):
                    _route(s, strict, needs_review)

    # -- divergence findings: raw-only vs rendered-only ----------------------
    # Only meaningful on pages that actually have BOTH corpora (a rendered
    # snapshot exists only for expanded 2xx HTML). Per-page comparison avoids
    # false "raw_only" flags on resources that were never rendered at all.
    pages = [r for r in fetched if r.get("rendered_sha256")]
    for row in pages:
        raw_c = {c for c, ss in strict.items()
                 if any(s.url == row["url"] and not s.how_found.startswith("rendered:")
                        for s in ss)}
        ren_c = {c for c, ss in strict.items()
                 if any(s.url == row["url"] and s.how_found.startswith("rendered:")
                        for s in ss)}
        for c in sorted(raw_c - ren_c):
            divergences.append({"canonical": c, "corpus": "raw_only", "url": row["url"],
                                "note": "in raw bytes, absent from rendered DOM (deleted on load?)"})
        for c in sorted(ren_c - raw_c):
            divergences.append({"canonical": c, "corpus": "rendered_only", "url": row["url"],
                                "note": "injected by script; not in raw bytes"})

    # -- header/cookie scan, per row; disqualified per challenge rule --------
    for row in fetched:
        for s in scan_headers(row.get("headers", {}), url=row["url"], sha256=row["sha256"]):
            disqualified.append(s)

    result = {
        "expected": expected,
        "distinct_strict": len(strict),
        "count_met": len(strict) >= expected,
        "secrets": {
            c: [{"url": s.url, "sha256": s.sha256, "how_found": s.how_found}
                for s in ss]
            for c, ss in sorted(strict.items())
        },
        "needs_review": [
            {"raw": s.raw.decode("utf-8", errors="replace"), "url": s.url,
             "how_found": s.how_found}
            for s in needs_review
        ],
        "disqualified_count": len(disqualified),
        "disqualified": [
            {"raw": s.raw.decode("utf-8", errors="replace"), "url": s.url,
             "where": s.how_found}
            for s in disqualified
        ],
        "divergences": divergences,
        "unhandled_types": sorted(set(unhandled)),
        "images": [
            {"url": r.url, "sha256": r.sha256, "format": r.format,
             "size": list(r.size), "deviating_pixels": r.deviating_pixels,
             "candidates_tried": r.candidates_tried,
             "candidates_with_hits": r.candidates_with_hits,
             "ruling": r.ruling}
            for r in image_reports
        ],
        "images_without_secret": [
            {"url": r.url, "ruling": r.ruling}
            for r in image_reports if r.ruling != "payload-found"
        ],
    }
    (out_dir / "secrets.json").write_text(json.dumps(result, indent=2))
    _write_report(out_dir, result)
    for canon in result["secrets"]:
        log.info("  ✓ secret: %s", canon)
    for n in result["needs_review"]:
        log.warning("  needs-review: %s @ %s", n["raw"], n["url"])
    log.info("extract done: %d/%d distinct STRICT, %d needs-review, %d disqualified, "
             "%d divergences → secrets.json, extraction.md",
             result["distinct_strict"], result["expected"], len(result["needs_review"]),
             result["disqualified_count"], len(result["divergences"]))
    return result


def _route(s: Sighting, strict: dict, needs_review: list) -> None:
    if s.strict:
        strict[s.canonical].append(s)
    else:
        needs_review.append(s)


def _write_report(out_dir: Path, r: dict) -> None:
    lines = ["# Extraction report", ""]
    status = "✅ met" if r["count_met"] else "⚠️ SHORT"
    lines.append(f"**Distinct STRICT secrets: {r['distinct_strict']} / {r['expected']} — {status}**")
    lines.append("")
    lines.append("## Secrets (canonical → sightings)")
    lines.append("")
    for canon, sightings in r["secrets"].items():
        lines.append(f"### `{canon}` ({len(sightings)} sighting(s))")
        for s in sightings:
            lines.append(f"- {s['url']} — `{s['how_found']}`")
        lines.append("")
    lines.append("## Divergences (raw vs rendered corpus)")
    lines.append("")
    lines += [f"- `{d['canonical']}` — **{d['corpus']}**: {d['note']}"
              for d in r["divergences"]] or ["_None._"]
    lines.append("")
    lines.append("## Needs-review bucket")
    lines.append("")
    lines.append("_Every entry must exit via a documented ruling (manual_review correction_")
    lines.append("_or ruled not-a-secret). Non-empty at submission weakens completeness._")
    lines.append("")
    lines += [f"- `{n['raw']}` @ {n['url']} (`{n['how_found']}`)"
              for n in r["needs_review"]] or ["_Empty._"]
    lines.append("")
    lines.append(f"## Disqualified sightings: {r['disqualified_count']}")
    lines.append("")
    lines.append("_Header/cookie matches are staging placeholders per challenge rules —_")
    lines.append("_recorded here, excluded from the count._")
    lines.append("")
    lines += [f"- `{d['raw']}` @ {d['url']} ({d['where']})"
              for d in r["disqualified"]] or []
    lines.append("")
    lines.append(f"## Unhandled content types: {r['unhandled_types'] or 'none'}")
    lines.append("")
    lines.append("## Image forensics (M5)")
    lines.append("")
    lines.append("_Coverage hook: every image either yielded a secret or was positively_")
    lines.append("_examined and ruled out. Full per-candidate log: `pixel_sweep.jsonl`._")
    lines.append("")
    lines.append("| image | format | deviating px | candidates | hits | ruling |")
    lines.append("|---|---|---|---|---|---|")
    for im in r["images"]:
        lines.append(
            f"| {im['url']} | {im['format']} | {im['deviating_pixels']} | "
            f"{im['candidates_tried']} | {im['candidates_with_hits']} | {im['ruling']} |"
        )
    if r["images_without_secret"]:
        lines.append("")
        lines.append("**Images with no secret (the still-unexplained queue):**")
        for im in r["images_without_secret"]:
            lines.append(f"- {im['url']} — {im['ruling']}")
    (out_dir / "extraction.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    import os
    import sys

    logging.basicConfig(
        level=getattr(logging, os.environ.get("CRAWL_LOG", "INFO").upper(), logging.INFO),
        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
        datefmt="%H:%M:%S", stream=sys.stderr,
    )
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "out")
    res = run(root)
    print(f"distinct STRICT: {res['distinct_strict']}/{res['expected']} "
          f"({'MET' if res['count_met'] else 'SHORT'})")
    print(f"needs-review: {len(res['needs_review'])}; "
          f"disqualified: {res['disqualified_count']}; "
          f"divergences: {len(res['divergences'])}")
