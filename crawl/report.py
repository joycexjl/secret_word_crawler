"""M3 — filetype inventory, disagreement list, duplication report,
blocked-notice detection, coverage report with named exceptions.

The site is expected to hide secrets in non-HTML resources, so knowing
exactly what it serves IS the roadmap for Phase 2 (design §7). All reports
read from the on-disk artifacts (manifest.jsonl, edges.jsonl) — re-runnable
offline against a completed crawl.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

# Phase 2 extractor registry keys (design §8) — the unhandled-types report is
# set(inventory) - set(EXTRACT_HANDLERS), the primary gap detector.
EXTRACT_HANDLERS = {
    "text/html", "text/css", "application/javascript", "text/javascript",
    "application/json", "application/xml", "text/xml", "text/csv",
    "image/svg+xml", "image/png", "image/jpeg", "image/gif", "image/webp",
    "application/pdf", "text/plain", "text/vtt", "application/manifest+json",
}

# Blocked-notice detection (design §5): a 200 whose body is a policy block or
# interstitial. The list starts with the recon-discovered literal and grows
# only by explicit additions.
BLOCKED_NOTICE_PATTERNS = [
    re.compile(r"only visible to", re.IGNORECASE),
]

# Extension → expected sniffed/MIME families, for the disagreement list.
_EXT_EXPECT = {
    "html": {"text/html"}, "htm": {"text/html"},
    "css": {"text/css"}, "js": {"application/javascript", "text/javascript"},
    "mjs": {"application/javascript", "text/javascript"},
    "json": {"application/json"}, "xml": {"application/xml", "text/xml"},
    "csv": {"text/csv"}, "svg": {"image/svg+xml"},
    "png": {"image/png"}, "jpg": {"image/jpeg"}, "jpeg": {"image/jpeg"},
    "gif": {"image/gif"}, "webp": {"image/webp"}, "ico": {"image/x-icon", "image/vnd.microsoft.icon"},
    "pdf": {"application/pdf"}, "txt": {"text/plain"},
    "woff": {"font/woff"}, "woff2": {"font/woff2"},
    "ttf": {"font/ttf"}, "otf": {"font/otf"},
    "zip": {"application/zip"}, "mp3": {"audio/mpeg"}, "mp4": {"video/mp4"},
}


def is_blocked_notice(status: int, body: bytes) -> bool:
    """A response whose body matches a policy-block/interstitial pattern.

    Status-agnostic: the geo-gated page answers 403 with a 'only visible to'
    body — that IS the block, and CONTEXT.md counts it as fetched + flagged
    blocked_notice. Gating on 200 would exclude the canonical case."""
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return False
    return any(p.search(text) for p in BLOCKED_NOTICE_PATTERNS)


def _signals_agree(row: dict) -> bool:
    """The three type signals (design §7) agree when the header type and the
    sniffed type match, and the URL extension (if any) expects that type."""
    ct, sniff, ext = row["content_type"], row["sniffed_type"], row["url_ext"]
    if ct and sniff and ct != sniff:
        # text/plain sniff on HTML-served-as-text etc. are real disagreements
        return False
    if ext and ext in _EXT_EXPECT:
        expected = _EXT_EXPECT[ext]
        if ct and ct not in expected:
            return False
        if sniff and sniff not in expected and sniff != "text/plain":
            return False
    return True


def build_filetype_inventory(rows: list[dict]) -> list[dict]:
    """One row per distinct content_type: count, bytes, examples, extractor?"""
    by_type: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        if "content_type" in r:
            by_type[r["content_type"] or "(none)"].append(r)
    inventory = []
    for ct, group in sorted(by_type.items()):
        inventory.append({
            "content_type": ct,
            "count": len(group),
            "bytes": sum(g.get("length", 0) for g in group),
            "examples": [g["url"] for g in group[:3]],
            # .map blobs have a dedicated extractor keyed on URL extension
            # (ADR 0002), whatever content-type the server declared.
            "has_extractor": ct in EXTRACT_HANDLERS
            or any(g.get("url_ext") == "map" for g in group),
        })
    return inventory


def build_disagreements(rows: list[dict]) -> list[dict]:
    """Every resource where the three type signals do not agree — expected to
    be short and worth reading line by line (design §7)."""
    out = []
    for r in rows:
        if "content_type" not in r:
            continue
        if not _signals_agree(r):
            out.append({
                "url": r["url"],
                "content_type": r["content_type"],
                "url_ext": r["url_ext"],
                "sniffed_type": r["sniffed_type"],
                "sha256": r["sha256"],
            })
    return out


def build_unhandled(inventory: list[dict]) -> list[str]:
    """set(inventory) - set(EXTRACT_HANDLERS) — Phase 2's gap detector."""
    return [i["content_type"] for i in inventory if not i["has_extractor"]]


def build_duplication(rows: list[dict], edges: list[dict]) -> list[dict]:
    """Group manifest rows by sha256; each hash served at >1 row is a
    first-class artifact (design §7). Two shapes, distinguished:

    - same asset URL referenced by multiple pages: one row, many inbound edges
    - different URLs serving identical bytes: deliberate duplication, an
      authorial signal URL-level dedup alone would miss
    """
    inbound: dict[str, list[str]] = defaultdict(list)
    for e in edges:
        inbound[e["dst"]].append(e["src"])

    by_hash: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        if "sha256" in r:
            by_hash[r["sha256"]].append(r)

    out = []
    for sha, group in sorted(by_hash.items()):
        urls = sorted({g["url"] for g in group})
        referrers = sorted({src for g in group for src in inbound.get(g["canon_key"], [])})
        if len(urls) > 1:
            case = "same_bytes_different_urls"
        elif len(referrers) > 1:
            case = "same_url_multiple_referrers"
        else:
            continue
        out.append({
            "sha256": sha, "case": case, "urls": urls,
            "referrers": referrers,
            "content_type": group[0]["content_type"],
            "length": group[0].get("length", 0),
        })
    return out


def write_filetypes_md(root: Path, inventory: list[dict], disagreements: list[dict],
                       unhandled: list[str]) -> Path:
    lines = ["# Filetype inventory", ""]
    lines.append("| content_type | count | bytes | extractor? | examples |")
    lines.append("|---|---|---|---|---|")
    for i in inventory:
        ex = "<br>".join(i["examples"])
        lines.append(
            f"| `{i['content_type']}` | {i['count']} | {i['bytes']} | "
            f"{'yes' if i['has_extractor'] else '**NO**'} | {ex} |"
        )
    lines += ["", "## Signal disagreements", ""]
    if disagreements:
        lines.append("| url | header | ext | sniffed |")
        lines.append("|---|---|---|---|")
        for d in disagreements:
            lines.append(
                f"| {d['url']} | `{d['content_type']}` | `{d['url_ext']}` | `{d['sniffed_type']}` |"
            )
    else:
        lines.append("_None — all three type signals agree everywhere._")
    lines += ["", "## Unhandled types (Phase 2 gap detector)", ""]
    lines.append("_(empty = every served type has at least one extractor)_" if not unhandled
                 else "\n".join(f"- `{u}`" for u in unhandled))
    path = Path(root) / "filetypes.md"
    path.write_text("\n".join(lines) + "\n")
    return path


def write_coverage_md(
    root: Path,
    *,
    counts: dict[str, int],
    depth_hist: dict[int, int],
    cap_hits: list,
    blocked_notices: list[dict],
    errors: dict[str, str],
    redirect_outs: list[dict],
    needs_review: list[str],
    disqualified_header_sightings: int,
    duplication: list[dict],
    unhandled: list[str],
    idle_timeouts: list[str],
    late_mutations: list[str],
    closed_shadow_roots: list[str],
    unexplained_interactives: list[str],
) -> Path:
    """The completeness argument (design §10): five numbers that must
    balance, plus every named exception bounding the claim honestly."""
    lines = ["# Coverage report", ""]
    lines.append("## Terminal-state accounting")
    lines.append("")
    for state in ("fetched", "out_of_scope", "errored", "duplicate_key"):
        lines.append(f"- **{state}**: {counts[state]}")
    lines.append(f"- **seen (total)**: {counts['seen']}")
    lines.append("")
    lines.append("## Depth histogram (post-hoc BFS from `/`)")
    lines.append("")
    lines.append("_Flattens = complete; still rising at max = stopped early._")
    lines.append("")
    for d in sorted(depth_hist):
        lines.append(f"- depth {d}: {depth_hist[d]}")
    lines.append("")

    lines.append("## Named exceptions")
    lines.append("")
    lines.append("### Template truncations (bounded-coverage admissions)")
    caps = [h for h in cap_hits]
    lines += [f"- {h.kind}: `{h.key}`" for h in caps] or ["_None — no cap fired._"]
    lines.append("")
    lines.append("### Blocked notices (evidence gathered, content unreachable)")
    lines += [f"- {b['url']}" for b in blocked_notices] or ["_None._"]
    lines.append("")
    lines.append("### Terminal errors (secrets behind these are outside this crawl's evidence)")
    lines += [f"- `{u}` — {why}" for u, why in sorted(errors.items())] or ["_None._"]
    lines.append("")
    lines.append("### Redirect-outs (redirects to out-of-scope targets, for manual ruling)")
    lines += [f"- {r['from']} → {r['to']}" for r in redirect_outs] or ["_None._"]
    lines.append("")
    lines.append(f"### Header/cookie sightings")
    lines.append("Header/cookie matches are **counted** as candidate secrets (the "
                 "disqualification rule was removed); see `extraction.md`. "
                 f"{disqualified_header_sightings} recorded here for the crawl-phase ledger.")
    lines.append("")

    lines.append("## Duplication (keyed by sha256)")
    lines.append("")
    if duplication:
        for d in duplication:
            lines.append(f"### `{d['sha256'][:16]}…` — {d['case']}")
            lines.append(f"- type `{d['content_type']}`, {d['length']} bytes")
            lines += [f"- url: {u}" for u in d["urls"]]
            lines += [f"- referrer: {r}" for r in d["referrers"]]
            lines.append("")
    else:
        lines.append("_No blob served at more than one URL, and no URL multiply referenced._")
        lines.append("")

    lines.append("## Residual queues")
    lines.append("")
    lines.append(f"- Unhandled content types: {unhandled or 'none'}")
    lines.append(f"- Needs-review extensionless refs: {len(needs_review)}")
    lines.append(f"- idle_timeout pages: {idle_timeouts or 'none'}")
    lines.append(f"- late_mutation tripwire pages: {late_mutations or 'none'}")
    lines.append(f"- closed shadow roots on: {closed_shadow_roots or 'none'}")
    lines.append(f"- unexplained interactives on: {unexplained_interactives or 'none'}")

    path = Path(root) / "coverage.md"
    path.write_text("\n".join(lines) + "\n")
    return path


def load_manifest(root: Path) -> list[dict]:
    path = Path(root) / "manifest.jsonl"
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
