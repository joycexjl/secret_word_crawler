"""Extraction runner — iterates manifest rows (fetch events), not blobs.

- Body-bearing extractors run once per unique sha256 and fan sightings out to
  every row carrying that hash (design §8).
- Header/cookie scanning runs per row; matches count as candidate secrets
  (the disqualification rule was removed), de-duped by canon key.
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
    ruled_out: list[Sighting] = []   # worked examples / format prose — declared not-a-secret
    divergences: list[dict] = []   # raw-only / rendered-only findings
    unhandled: list[str] = []
    image_reports: list = []       # coverage hook: every image, with its ruling
    sweep_log = out_dir / "pixel_sweep.jsonl"
    if sweep_log.exists():
        sweep_log.unlink()  # fresh per run; the log is per-run evidence

    # -- body extraction, once per unique blob, fanned out to carrier rows ---
    for sha, group in by_hash.items():
        ct = group[0]["content_type"]
        url_ext = group[0].get("url_ext", "")
        body = (out_dir / "blobs" / sha).read_bytes()
        if handler_for(ct, url_ext) is None:
            unhandled.append(ct)
            log.warning("no extractor for %s (%s)", ct, group[0]["url"])
        log.debug("extract %s (%s, %d bytes, %d row(s))", sha[:8], ct, len(body), len(group))

        # M5 image track: metadata + enumerated pixel sweep, once per unique
        # blob, sightings fanned out to every carrier row (design §8/§9).
        if ct.startswith("image/") and ct != "image/svg+xml":
            log.info("  pixel sweep: %s", group[0]["url"])
            rep = analyze_image(body, url=group[0]["url"], sha256=sha,
                                sweep_log=sweep_log)
            rf = rep.ramp_fit
            log.info("    ramp_fit(is_ramp=%s, max_res=%s, dev_px=%s), "
                     "%d candidates, %d with hits → %s",
                     rf.get("is_ramp"), rf.get("max_residual"), rf.get("deviating_px"),
                     rep.candidates_tried, rep.candidates_with_hits, rep.ruling)
            for s in rep.sightings:
                for row in group:
                    _route(Sighting(s.canonical, s.raw, s.how_found,
                                    row["url"], sha, ruled_out=s.ruled_out),
                           strict, needs_review, ruled_out)
            # OCR consensus + hex-repair FIRST: if the passes merge to a STRICT
            # candidate, the raw per-pass OCR reads are resolved evidence, not
            # open needs-review entries (M6 report bug 1 — write-back).
            merged, how = _ocr_consensus(rep)
            if merged:
                for row in group:
                    _route(Sighting(merged, merged.encode(), how, row["url"], sha),
                           strict, needs_review, ruled_out)
                # This image yielded a secret — it is NOT unresolved.
                rep.ruling = "payload-found"
                # Drop the raw OCR reads the consensus just resolved.
                rep.needs_review = [s for s in rep.needs_review
                                    if not s.how_found.startswith("img_ocr:")]
            for s in rep.needs_review:
                _route(s, strict, needs_review, ruled_out)  # ruled_out fragments diverted
            image_reports.append(rep)

        surfaces = extract_blob(ct, body, url_ext=url_ext)
        for sub, data in surfaces:
            for row in group:
                for s in scan_text(data, how_found=f"{ct}:{sub}",
                                   url=row["url"], sha256=sha,
                                   with_charset=(sub == "raw")):
                    _route(s, strict, needs_review, ruled_out)

        # Dual corpus for HTML: the rendered snapshot is a separate blob.
        for row in group:
            rsha = row.get("rendered_sha256")
            if not rsha:
                continue
            rendered = (out_dir / "blobs" / rsha).read_bytes()
            for sub, data in extract_blob("text/html", rendered):
                for s in scan_text(data, how_found=f"rendered:{sub}",
                                   url=row["url"], sha256=rsha,
                                   with_charset=(sub == "raw")):
                    _route(s, strict, needs_review, ruled_out)

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

    # -- header/cookie scan, per row ----------------------------------------
    # Header/cookie matches are candidate secrets like any other (the
    # disqualification rule was removed). De-duped by canon key: the same
    # secret served at trailing-slash / query-param variants counts once.
    seen_header: set[tuple] = set()
    for row in fetched:
        row_canon = row.get("canon_key", row["url"])
        for s in scan_headers(row.get("headers", {}), url=row["url"], sha256=row["sha256"]):
            key = (s.canonical or s.raw, row_canon)
            if key in seen_header:
                continue
            seen_header.add(key)
            _route(s, strict, needs_review, ruled_out)

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
        "ruled_out": [
            {"raw": s.raw.decode("utf-8", errors="replace"), "url": s.url,
             "how_found": s.how_found, "reason": s.ruled_out}
            for s in ruled_out
        ],
        "divergences": divergences,
        "unhandled_types": sorted(set(unhandled)),
        "images": [
            {"url": r.url, "sha256": r.sha256, "format": r.format,
             "size": list(r.size), "ramp_fit": r.ramp_fit,
             "candidates_tried": r.candidates_tried,
             "candidates_with_hits": r.candidates_with_hits,
             "ocr_text": r.ocr_text,
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
    for ro in result.get("ruled_out", []):
        log.info("  ruled-out (%s): %s", ro["reason"], ro["raw"][:48])
    log.info("extract done: %d/%d distinct STRICT, %d needs-review, "
             "%d divergences → secrets.json, extraction.md",
             result["distinct_strict"], result["expected"], len(result["needs_review"]),
             len(result["divergences"]))
    return result


def _ocr_consensus(rep) -> tuple[str | None, str]:
    """Automated OCR hex-repair: merge OCR passes into a STRICT candidate.

    Confusion-class repair is forced by the format — every non-hex OCR char
    maps to exactly one hex char (l/I→1, O/o→0, S/s→5, B→8, G→6, Z/z→2,
    q/g→9) — so no human judgment is involved. Acceptance (hybrid, per locked
    design):
      1. Whole-candidate: ≥2 passes normalize to the SAME valid 16-hex window.
      2. Per-position fallback: each position decided by a strict majority of
         the hex-reading passes, with ≥2/3 of passes hex-consistent there.
    Genuine ties / no majority -> (None, '') and the passes stay in
    needs-review. Returns (canonical, how_found)."""
    import re as _re
    from collections import Counter

    from .core import STRICT as _STRICT

    _NORMALIZE = str.maketrans({
        "l": "1", "I": "1", "O": "0", "o": "0", "S": "5", "s": "5",
        "B": "8", "G": "6", "Z": "2", "z": "2", "q": "9", "g": "9",
    })
    HEXSET = set("0123456789abcdef")

    def best_window(text: str) -> str | None:
        m = _re.search(r"(?i)VISUALPING", text)
        if not m:
            return None
        tail = text[m.end():]
        best, best_score = None, -1
        for i in range(0, max(1, len(tail) - 15)):
            w = tail[i:i + 16].translate(_NORMALIZE).lower()
            score = sum(c in HEXSET for c in w)
            if score > best_score:
                best, best_score = w, score
        return best

    per_pass = [w for w in (best_window(t) for t in rep.ocr_text.values()) if w]
    if len(per_pass) < 2:
        return None, ""

    def valid(s: str) -> bool:
        return bool(_STRICT.fullmatch(("VISUALPING{" + s + "}").encode()))

    # 1. Whole-candidate agreement.
    for window, n in Counter(per_pass).most_common():
        if n >= 2 and valid(window):
            return "VISUALPING{" + window + "}", "img_ocr:consensus+hex_repair"

    # 2. Per-position majority with a hex-consistency quorum.
    n = len(per_pass)
    quorum = (2 * n + 2) // 3  # ≥2/3 of passes must read hex at the position
    merged = []
    for i in range(16):
        votes = [p[i] for p in per_pass if i < len(p)]
        hex_votes = [v for v in votes if v in HEXSET]
        if len(hex_votes) < quorum:
            return None, ""  # too few passes read hex here -> ambiguous
        top, top_n = Counter(hex_votes).most_common(1)[0]
        if top_n * 2 <= len(hex_votes):
            return None, ""  # no strict majority -> tie -> needs-review
        merged.append(top)
    candidate = "".join(merged)
    if valid(candidate):
        return "VISUALPING{" + candidate + "}", "img_ocr:consensus+hex_repair"
    return None, ""


def _route(s: Sighting, strict: dict, needs_review: list,
           ruled_out: list | None = None) -> None:
    if s.ruled_out:
        if ruled_out is not None:
            ruled_out.append(s)
        return  # declared not-a-secret by the challenge's own rules
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
    lines.append("## Ruled out (declared not-a-secret by the challenge's own rules)")
    lines.append("")
    lines.append("_Worked examples and format-description prose — recorded for audit,_")
    lines.append("_never counted, never sent to needs-review._")
    lines.append("")
    lines += [f"- `{ro['raw']}` @ {ro['url']} — **{ro['reason']}**"
              for ro in r.get("ruled_out", [])] or ["_None._"]
    lines.append("")
    lines.append("_Header/cookie matches are counted as candidate secrets (the_")
    lines.append("_disqualification rule was removed); provenance is `header:<name>`._")
    lines.append("")
    lines.append(f"## Unhandled content types: {r['unhandled_types'] or 'none'}")
    lines.append("")
    lines.append("## Image forensics (M5)")
    lines.append("")
    lines.append("_Coverage hook: every image either yielded a secret or was positively_")
    lines.append("_examined and ruled out. Full per-candidate log: `pixel_sweep.jsonl`._")
    lines.append("")
    lines.append("| image | format | ramp fit | candidates | hits | ruling |")
    lines.append("|---|---|---|---|---|---|")
    for im in r["images"]:
        rf = im.get("ramp_fit", {})
        if rf.get("is_ramp"):
            fit = f"ramp, {rf.get('deviating_px', 0)} deviant px"
        else:
            fit = f"not a ramp (residual {rf.get('max_residual', '?')})"
        lines.append(
            f"| {im['url']} | {im['format']} | {fit} | "
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
          f"ruled-out: {len(res.get('ruled_out', []))}; "
          f"divergences: {len(res['divergences'])}")
