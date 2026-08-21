# Site Crawler — Design Doc

**Target:** `http://54.214.7.161/`
**Goal:** recover eight `VISUALPING{<16 hex>}` secret words, and be able to argue the crawl was complete.
**Stack:** Python 3.11+, Playwright (sync API), Chromium.
**Auth:** HTTP Basic Auth on every request to the target (see §2 and ADR 0001).

---

## 1. Framing

The challenge hint — *"not everything a browser sees is an `<a>` tag"* and *"some secret words live in other kinds of resources"* — points at two distinct problems that are easy to conflate:

1. **Reachability.** Finding every resource the site serves.
2. **Extraction.** Pulling secrets out of resources once you have the bytes.

These have different failure modes and different debugging loops, so the design keeps them strictly separate. Phase 1 solves reachability and produces a full inventory of what the site is made of. Extraction is a separate offline pass over the saved bytes, added in Phase 2.

The practical payoff: when extraction needs a new capability (OCR, PDF text, pixel forensics), it is a re-run over local disk in seconds, not another crawl against someone else's server.

---

## 2. Goals and non-goals

### Goals

- Discover every resource reachable from `/` using a real browser, including references that are not `<a href>`.
- Emit a **directed graph** of the site: nodes are resources, edges are references, each edge labelled with *how* it was discovered.
- Emit a **filetype inventory**: every content type the site serves, with counts, examples, and disagreements between the three type signals.
- Persist every response body so extraction never needs to re-fetch.
- Terminate with an auditable accounting of every URL ever seen.

### Non-goals

- Off-host crawling. Scope is the `(scheme, host, port)` triple `(http, 54.214.7.161, 80)` — anything else (including `https:` and other ports) is recorded as an edge and marked out-of-scope. Enforcement is at the **network layer**: a route interceptor aborts every out-of-scope request, so Basic Auth credentials physically cannot leave the target host (ADR 0001). The frontier still records the edges.
- Form submission and state-mutating requests. The crawler is **GET-only**. During Tier 2 interaction, non-GET requests are aborted by the interceptor and logged as `blocked_mutation` findings.
- Speed. Simplicity and politeness win. Note: recon (2026-08-21) found `/report/?page=N` pagination that is **unbounded** (still self-linking at N=100), so "small site" is not a safe assumption — see the per-template cap in §6.

---

## 3. Design principles

**Record first, extract later.** The browser is a recorder. Every HTTP response it receives — HTML, CSS, JS, images, XHR, fonts — is written to a content-addressed store with its headers. Extraction reads from that store.

**Discovery is tiered and escalating.** Cheap mechanisms first; expensive interaction only if coverage signals say it's needed. The escalation decision is logged, because *having a stopping rule* is more defensible than exhaustive clicking.

**Completeness is an invariant, not a vibe.** A URL leaves the frontier only by entering exactly one terminal state (`fetched` / `out_of_scope` / `errored` / `duplicate_key`). The loop asserts the accounting balances. That assertion is the completeness argument.

**Fetch ≠ expand.** Every in-scope resource is *fetched* (bytes recorded). Only 2xx HTML pages are *expanded* (discovery tiers run against them). Non-HTML resources are fetched via the API request context — never loaded in a browser page, so Chromium's synthetic wrapper documents cannot pollute the edge graph. URLs hidden inside non-HTML bytes are discovered by the offline byte-scan, not by expansion.

**Every unknown is surfaced, never swallowed.** No bare `except: pass`. Unhandled content types, failed fetches, and unexplained resources all appear in a report rather than disappearing.

---

## 4. Architecture

```
visualping-crawler/
├── main.py               # BFS orchestration
├── crawl/
│   ├── normalize.py      # URL canonicalisation + scope check   (pure, testable)
│   ├── frontier.py       # queue, seen-set, terminal-state accounting
│   ├── browser.py        # Playwright session, response recorder, nav shim
│   ├── store.py          # content-addressed blob store + manifest
│   ├── discover.py       # bytes + type -> candidate URLs
│   ├── graph.py          # node/edge model, DOT export
│   └── report.py         # filetype inventory, coverage report
├── extract/              # Phase 2 — secret extractors
└── out/
    ├── blobs/<sha256>    # raw response bodies
    ├── manifest.jsonl    # one record per fetched resource
    ├── edges.jsonl       # one record per reference
    ├── graph.dot         # rendered link graph
    ├── filetypes.md      # filetype inventory
    └── coverage.md       # terminal-state accounting
```

### Concurrency model

Synchronous, serial, single page. The main page graph is expected to be small, but the report pagination is unbounded, so total fetches are bounded by the caps in §6, not by optimism. Async would buy nothing and would cost real debugging time against a fixed effort budget. It is also the polite choice against a host that is not ours.

---

## 5. Data model

### Manifest record — one per fetched resource

```python
{
  "url":            str,   # verbatim URL as requested (never fabricated)
  "canon_key":      str,   # dedup/frontier identity (query params sorted, fragment dropped)
  "final_url":      str,   # after redirects
  "status":         int,
  "content_type":   str,   # from response header, lowercased, params stripped
  "url_ext":        str,   # extension from URL path, or ""
  "sniffed_type":   str,   # from magic bytes
  "sha256":         str,   # body hash -> blobs/<sha256>
  "rendered_sha256": str,  # rendered-DOM snapshot blob (HTML pages only), else null
  "length":         int,
  "headers":        dict,  # full response headers
  "first_seen_depth": int, # frontier depth when first reached (forensics)
  "retries":        int,   # 0 or 1 (transient failures retried once)
  "idle_timeout":   bool,  # networkidle never settled within the bounded wait
  "blocked_notice": bool,  # 200 body matched a policy-block/interstitial pattern
  "fetched_at":     str,   # ISO8601
}
```

Storing all three type signals (`content_type`, `url_ext`, `sniffed_type`) is deliberate — see §7.

Storing full `headers` is deliberate even though challenge rules declare header secrets **disqualified** (staging placeholders — see §8): header sightings are recorded and reported, and a header value that also appears in a body corroborates that value.

`blocked_notice` covers responses like the recon-discovered `/status/eu-region/` (200 with a geo-block notice): the fetch is real and accounted, but the content is a coverage **exception** named in the completeness section. The detection pattern list (starting with the literal "only visible to") grows only by explicit additions.

### Edge record — one per reference

```python
{
  "src":   str,   # normalised URL of the referring resource
  "dst":   str,   # normalised URL of the referenced resource
  "how":   str,   # discovery mechanism (see below)
  "hint":  str,   # anchor text / alt text / CSS selector / JSON key path
  "depth": int,   # depth of src
}
```

`how` is the highest-value field in the whole system. Values:

| `how` | Meaning |
|---|---|
| `a_href` | ordinary anchor |
| `img_src`, `srcset`, `picture_source` | image references |
| `css_url` | `url()` in a stylesheet or inline style |
| `link_rel` | `<link>` — stylesheet, manifest, alternate, icon |
| `script_src` | `<script src>` |
| `iframe_src`, `object_data`, `embed_src` | embedded documents |
| `form_action`, `area_href`, `meta_refresh` | other markup references |
| `xhr` | observed via `page.on("response")`, not present in markup |
| `js_navigation` | captured by the navigation shim |
| `click` | discovered only by Tier 2 interaction |
| `redirect` | `final_url != url` (redirect-outs to other scope triples flagged separately) |
| `header_link` | `Link:` response header |
| `regex_fallback` | found by offline byte-scan, no structural source (tier recorded) |
| `shadow_dom` | harvested from inside an open shadow root |

This field is what lets the write-up say something concrete: *"three resources were reachable only via `xhr` and `js_navigation` edges — no anchor anywhere on the site pointed at them."* It is also a self-diagnostic: if `regex_fallback` is discovering resources the browser tiers missed, the interaction layer has a hole.

### Node model

Nodes are **resources**, not just pages. Derived from the manifest plus any `dst` never fetched (out-of-scope or errored). Attributes: `url`, `depth`, `content_type`, `status`, `sha256`, `state`, `is_page` (HTML and non-error).

---

## 6. Phase 1a — Crawl and graph

### URL normalisation

The single place where bugs silently cost you pages, and therefore the only module worth unit-testing up front.

Rules:
- Lowercase scheme and host; strip default port.
- Resolve relative against the **per-document base**: Tier 0 harvests `<base href>` first on every page and threads it into that page's resolution.
- Drop the fragment.
- The **verbatim URL** (query string preserved verbatim) is what goes on the wire and into edge records. The **canon key** (same, but query parameters sorted) is the identity used by `seen`, the frontier, and graph nodes. Two verbatim URLs sharing a canon key: the first is fetched, later ones append edges and are recorded `duplicate_key`. The sorted form is a key, never a request target.
- Normalise `/a/b/../c` path segments.
- Treat `/page` and `/page/` as distinct URLs (the server decides), but reconcile them later via body hash.

Scope check: the `(scheme, host, port)` triple must equal `(http, 54.214.7.161, 80)`. Everything else becomes an edge with `state: out_of_scope` — and is also aborted at the network layer (ADR 0001), so a redirect to an out-of-scope target is recorded as a `redirect` edge and flagged as a **redirect-out** for manual ruling.

### Frontier and the loop invariant

```
seen          = every canon key ever discovered
fetched       ⊂ seen   — got a response, manifest record written
out_of_scope  ⊂ seen   — outside the scope triple, never requested
errored       ⊂ seen   — request failed terminally; reason recorded
duplicate_key ⊂ seen   — canon key already fetched via another verbatim URL
```

The loop terminates when the queue is empty **and** a byte-scan pass over the whole blob store yields no new in-scope URLs (the fixpoint — see below), and then asserts:

```python
assert len(fetched) + len(out_of_scope) + len(errored) + len(duplicate_key) == len(seen)
```

Those five numbers get printed and written to `coverage.md`. If they balance, no URL was silently dropped.

**Retry discipline.** 4xx/410 is terminal immediately (the server answered). Timeouts, 5xx, and connection resets get exactly one retry, attempted after the queue drains (natural delay, no sleep logic). Terminally errored URLs are named with their reasons in the completeness section.

**Safety valves.** `MAX_RESOURCES = 500` (global) plus a **per-query-template cap of ~60** — a template being path + sorted parameter *names*, so `/report/?page=N` truncates at 60 pages regardless of the global budget. There is deliberately **no `MAX_DEPTH`**: canon-key BFS never revisits, so depth is bounded by resource count, and the depth histogram is the detector (§10) rather than a guardrail. Hitting either cap is logged **loudly** at the top of the coverage report as a bounded-coverage admission, because a silent cap invalidates every completeness claim in this document. URLs are only ever followed as actually served — the crawler never synthesizes `page=N+1` guesses.

### The fixpoint loop

`main.py` alternates two phases until stable:

1. **Browser phase** — drain the frontier (fetch everything, expand HTML).
2. **Byte-scan phase** — run `discover.py` over every blob in the store; enqueue new in-scope canon keys.

Termination is guaranteed (`seen` is monotone, capped by `MAX_RESOURCES`). `how: regex_fallback` on an edge honestly means "found by byte-scan, no structural source." Re-scanning after improving a pattern tier is seconds over local disk — the payoff of record-first.

### Discovery tiers

**Tier 0 — DOM harvest.** At the **canonical snapshot moment** — `domcontentloaded`, then a bounded wait for `networkidle` (3–5s explicit timeout, wrapped: on timeout harvest anyway and set `idle_timeout` on the manifest record) — one pass over the rendered DOM collecting `<base href>` first, then every URL-bearing attribute: `[href]`, `[src]`, `[srcset]`, `[action]`, `[data]`, `[poster]`, `[style*=url]`, plus `<meta http-equiv=refresh>` and any `data-*` attribute whose value looks path-shaped. The harvest **recursively descends open shadow roots** and records per-page shadow-root counts. The init script patches `attachShadow` to record closed roots at attach time — closed roots cannot be walked, so any occurrence is a loud report entry and counts toward the Tier 2 trigger. Immediately after the harvest, the rendered DOM is serialized into the blob store (`rendered_sha256`) so the graph and the extraction corpus describe the same moment. A `MutationObserver` installed by the init script logs post-snapshot mutations as `late_mutation` tripwires — a page that mutates late gets a targeted longer-wait re-visit, decided by a human reading the report.

**Tier 1 — Passive browser observation.**
- `page.on("response")` records *every* response the browser fetched, including XHR to JSON endpoints and lazily-loaded assets. These become `xhr` edges.
- `page.add_init_script()` installs, before page scripts run, a shim patching `location.assign`, `location.replace`, `window.open`, `history.pushState`/`replaceState`, and the `location` setter to push intended URLs onto a global array read after load. These become `js_navigation` edges. **Same-document history mutations are passed through** (faithful, harmless); **hard navigations are recorded then swallowed** (returning a dummy for `window.open`) — the frontier visits the target properly in its own fresh page, and the harvest context is never torn down mid-page.

**Tier 2 — Bounded interaction.** Triggered mechanically by the **unexplained-interactives** count: elements matching the clickable selectors (`[role=button]`, `[onclick]`, `cursor: pointer`) whose page visit produced *no* associated network or navigation activity. If that count is zero and the fixpoint has converged, Tier 2 is skipped and the decision is written down; if nonzero, exactly those elements are clicked — each in a *fresh* page load, non-GET requests aborted and logged as `blocked_mutation`, navigations and new network activity recorded, page discarded. Closed shadow roots also count toward the trigger. The secret count (fewer than eight) remains as a secondary, post-extraction check.

### Graph output

`edges.jsonl` plus a `graph.dot` render. Node styling by content type; edges styled by `how` so non-anchor references are visually obvious.

Assertions run at export:
- Every node is reachable from `/` in the edge graph.
- No node has `state: unfetched`.
- The **depth histogram uses post-hoc graph distance** — BFS over `edges.jsonl` from `/`, computed at export — not first-seen order, which is mechanism-accidental (an XHR found by a deep JS file is not a deep page). `first_seen_depth` stays on manifest records for forensics. If the histogram's maximum depth is still increasing at termination, the crawl stopped early; if a template cap fired, the histogram is read alongside that admission.

**On revisits:** when BFS reaches an already-seen node, append the edge but leave the node's recorded `depth` and first-seen path unchanged. Otherwise "shortest path from `/`" gets overwritten by whichever edge happened to arrive last.

---

## 7. Phase 1b — Filetype inventory

The site is expected to hide secrets in non-HTML resources, so knowing exactly what it serves *is* the roadmap for Phase 2.

### Three signals per resource

Each is independently fallible:

| Signal | Source | Fails when |
|---|---|---|
| `content_type` | response header | server misconfigured, or deliberately misleading |
| `url_ext` | URL path | extensionless routes, or extension that lies |
| `sniffed_type` | magic bytes (`python-magic` or a small signature table) | ambiguous or truncated content |

### Reports

**Inventory** — one row per distinct `content_type`: count, total bytes, up to three example URLs, and whether an extractor exists for it in Phase 2.

**Disagreement list** — every resource where the three signals do not agree. A `.png` served as `text/html`, or an `application/octet-stream` that sniffs as PDF, is exactly the kind of thing this challenge rewards noticing. This list is expected to be short and is worth reading line by line.

**Unhandled types** — `set(inventory) - set(EXTRACT_HANDLERS)`. Comes for free from the handler-registry dispatch, and is the primary gap detector for Phase 2: an empty list is a real coverage claim, a non-empty one says precisely where to look next.

### Byte-scan patterns (`discover.py`)

Tiered patterns, quote-delimited (matched inside `"…"` / `'…'` / backticks so minified code isn't sliced), in priority order:

1. Absolute URLs on any host (the scope check sorts them).
2. Root-relative paths with a plausible extension or known-route shape.
3. Relative paths carrying a file extension (`../a/b.png`, `assets/x.woff2`).

Bare extensionless relative strings are **not** auto-fetched — they go to a `needs_review` bucket in the report. Every `regex_fallback` edge records which tier found it, so a noisy tier is visible and tunable.

### Content-hash reconciliation

Group manifest records by `sha256`. Identical bytes served at multiple URLs get collapsed for processing (each body extractor runs once per unique blob, sightings fanned out to every manifest row carrying the hash).

The **duplication section** of the report makes this a first-class artifact: for each sha256 with more than one manifest row, list the URLs and their referrer chains. The two cases render differently and both are quotable in the write-up:

- Two pages referencing **the same asset URL** — one row, multiple inbound edges: ordinary asset reuse.
- Two **different URLs** serving identical bytes — deliberate duplication, which URL-level dedup alone would miss, and an authorial signal that the asset matters.

---

## 8. Phase 2 — Extraction (outline)

A registry keyed by content-type prefix, each entry providing an extractor. **Extraction iterates manifest rows (fetch events), not blobs** — provenance (headers, URL, status) lives on the row. Body-bearing extractors run once per unique `sha256` and fan sightings out to every row carrying that hash; header/cookie scanning runs per row.

```python
secrets: dict[str, list[dict]]   # canonical value -> [{url, sha256, how_found}, ...]
```

**Canonical form:** `VISUALPING{` + 16 lowercase hex + `}`. Sightings are normalized (hex case-folded, whitespace inside braces stripped) before dedup, and the distinct-count target — **8** — counts canonical STRICT-validated values only. All STRICT sightings of one canonical value must agree after normalization; a disagreement is an extractor bug and fails loudly.

**Disqualified sightings.** Challenge rules: secrets in response headers or cookies are staging placeholders and do not count. Headers are still recorded and scanned, but matches are classified `disqualified: header_rule`, excluded from the count and from needs-review, and summarized in one line of the report.

Planned handlers:

- **HTML — dual corpus.** Raw bytes first (`html_raw`), rendered-DOM snapshot second (`html_rendered`): regex over text with tags stripped (so a word split across `<span>`s still matches), plus comments and `display:none` content. Recon confirmed the site mutates its DOM both ways (the index deletes a list item on load; `main.js` injects nav links), so a value found in only one corpus is a named finding.
- **CSS / JS** — comments and string literals.
- **JSON / XML / CSV** — flatten and scan every value.
- **SVG** — `<text>` nodes and comments; it is XML, no OCR needed.
- **Images** — metadata chunks, then the pixel sweep (§9). **OCR is deferred**: images are recorded, deduped by hash, and swept; rendered-text images that resist the sweep land in the unexplained queue with an "OCR deferred" ruling, and resurrecting OCR is the first move if the count falls short.
- **PDF** — text layer scan (rasterise-and-read deferred with OCR).
- **Headers and cookies** — scanned per row; matches disqualified per the rule above.
- **Decoded variants** — base64 blobs, `data:` URIs, percent-encoding, HTML entities; the pattern is re-run over each decoding.

Two patterns, always:

```python
STRICT = re.compile(rb'VISUALPING\{[0-9a-f]{16}\}')
LOOSE  = re.compile(rb'VISUALPING\s*\{[^}]{0,80}\}')   # tripwire
```

`LOOSE` hits that fail `STRICT` go to the **needs-review bucket**, which has a forced exit criterion: every entry is resolved to a canonical value via a documented correction (recorded `how_found: manual_review`) or ruled not-a-secret in writing. A non-empty bucket at submission weakens the completeness claim and must be declared.

---

## 9. Phase 3 — Image forensics

Images are recorded and deduped by sha256 (the known duplicated secret image is processed once, sightings fanned out to both pages). **OCR is deferred** (§8) — the image track is metadata + the pixel sweep.

**Colour-ramp images with pixel-level payloads.** Because the background is a mathematical gradient, the payload can be located rather than guessed: fit a plane per channel from the image corners, subtract, and every deviating pixel lights up in scan order. The plane-fit residual summary (deviating-pixel count) is logged so "no anomaly present" is a measured claim.

The brute-force sweep runs over an **explicit, enumerable candidate space** — channels {R,G,B,RGB,luma} × scan orders {row, column, diagonal, border walk} × encodings {direct-ASCII, 1/2/4-bit planes} × bit orders {msb, lsb} × directions {forward, reversed} ≈ 160 candidates per image — grepping each candidate byte string with `STRICT` and `LOOSE`. **Every candidate's outcome is logged to `pixel_sweep.jsonl`**, so "what was tried" is enumerable in the write-up. Multiple STRICT hits with agreeing payloads collapse to one sighting; **disagreeing payloads send the image to needs-review** for a manual ruling (same discipline as every other ambiguous reading — no auto-correction anywhere in the pipeline).

Where an anomaly is **visible** against the ramp, the data is in high-order bits and the pixel triples are likely ASCII directly.

**Coverage hook:** a report listing images that produced no secret. That is the "still unexplained" queue; each entry needs a ruling (swept-and-clean, metadata-clean, or "OCR deferred"). It should end empty or fully accounted for.

---

## 10. How we know the crawl was complete

Five independent arguments, in decreasing strength:

1. **Terminal-state accounting.** Every canon key ever seen ended in exactly one of fetched / out-of-scope / errored / duplicate_key. Asserted in code, printed in `coverage.md`.
2. **Fixpoint.** The crawl terminates only when the frontier is empty *and* a byte-scan over the full blob store yields no new in-scope URL (mechanism, §6 — not just an argument).
3. **Unhandled-type report empty.** Every content type the site served was passed to at least one extractor.
4. **Graph connectivity.** Every node reachable from `/`; the depth histogram (post-hoc graph distance) flattens rather than truncating at a cap.
5. **Unexplained-resource queue empty.** Every image and non-HTML resource either yielded a secret or was positively examined and ruled out — and the needs-review bucket is empty or its residue is declared.

Named exceptions that bound the claim honestly:

- **Template truncations** — any per-template cap that fired (e.g. `/report/?page=N` beyond ~60), listed as bounded-coverage admissions.
- **Blocked notices** — `blocked_notice` URLs (e.g. the geo-gated `/status/eu-region/`): evidence gathered, content unreachable from this network.
- **Terminal errors** — errored URLs with reasons; secrets behind them, if any, are outside this crawl's evidence.
- **Disqualified sightings** — header/cookie matches excluded per challenge rules, counted in one line.
- **Redirect-outs** — redirects to out-of-scope targets, flagged for manual ruling.

Stated honestly in the submission: **finding 8 of 8 is a sufficiency result, not a completeness result.** The five arguments above are what support completeness; the count is what supports being done.

---

## 11. Operational notes

- **Politeness:** serial requests, 250–500ms delay, identifying User-Agent, Basic Auth on every in-scope request. The server rejects HEAD (501 — Python `http.server` behind nginx), so everything is GET, which the GET-only rule already guarantees.
- **Reproducibility over resumability:** **no resume** — any failure means a clean re-crawl from an empty `out/` (a full run is minutes; the site is not ours and repeat-load is bounded by the caps). Append-only logs exist for auditability, not replay.
- **Reproducibility:** the crawl is a single command writing to `out/`; the whole extraction phase can be re-run offline against `out/blobs/`.
- **Config:** target scope triple, credentials (read from environment, never hardcoded), delay, caps (`MAX_RESOURCES`, per-template cap), `EXPECTED_SECRETS`, and tier-2 enablement in one dict at the top of `main.py`.

---

## 12. Milestones

| Milestone | Deliverable | Budget |
|---|---|---|
| **M1** | Normalise (canon key + verbatim) + frontier + store + browser harness with route-layer scope lock, credential containment, GET-only interceptor. Manifest populating. | ~40 min |
| **M2** | Bounded-idle navigation, navigation shim (pass-through/swallow split), shadow-walking Tier 0, rendered-DOM snapshots, MutationObserver tripwire, Tier 0/1 edges, fixpoint loop, template caps, `graph.dot`, coverage accounting. | ~60 min |
| **M3** | Filetype inventory, disagreement list, duplication report, blocked-notice detection, coverage report with named exceptions. | ~30 min |
| **M4** | Extraction registry + text handlers (dual-corpus HTML, CSS/JS, JSON/XML/CSV, SVG) + header-disqualification + decoded variants. | ~30 min |
| **M5** | Image handlers: metadata + enumerated pixel sweep with full outcome logging. (OCR deferred.) | ~30 min |
| **M6** | Write-up: approach, completeness argument with named exceptions, graph render. | ~30 min |

M1–M3 are Phase 1 and stand alone: at the end of M3 the site's shape and composition are fully known, which determines how much of M4–M5 is actually needed.

---

## 13. Recon findings (2026-08-21, settled by live probing)

- **Challenge rules (from the index page):** eight passwords; every password click-reachable from `/` — "no hidden URLs, no robots.txt tricks"; not every link is an `<a>` tag; look at everything the server gives you; **header secrets are disqualified staging placeholders**; keep sending Basic Auth. The worked example says "not one of the seven" — treated as stale copy; the target is 8.
- **JS-injected navigation confirmed:** `main.js` injects 7 nav links (`/docs/upstream-sample-channel/`, `/notes/archive-region/`, `/wiki/shard-schedule/`, `/docs/change-signal-anchor/`, `/wiki/rule-change/`, `/wiki/digest-session-ledger/`, `/wiki/domain-queue-backoff/`) at runtime. Raw-HTML-only crawling would miss them.
- **DOM deletion confirmed:** an inline script on `/` removes the 4th rule `<li>` after load — raw bytes and rendered DOM genuinely diverge.
- **Unbounded pagination:** `/report/?page=N` still self-links at N=100 — handled by the per-template cap.
- **Geo-blocked page:** `/status/eu-region/` returns 200 with a Germany-only notice (this IP reads as Canada) — a `blocked_notice` coverage exception.
- **Server:** nginx fronting a Python `http.server`-style backend; HEAD → 501, so all probes are GET.
- **Query-param duplicate bait present:** `/docs/?ref=related`, `/products/?hl=en`, `/help/?utm_source=internal` — exercises the canon-key logic.

Remaining open questions (to be answered by the M1–M3 crawl itself):

- Do the two pages carrying the known secret image reference the **same asset URL**, or different URLs with identical bytes? (Both handled; the duplication report distinguishes them.)
- Are the colour-ramp images PNG or JPEG? Lossy compression rules out low-bit-plane encoding and prunes the sweep's candidate space.
- Does the site serve any JSON/XHR endpoints beyond what recon saw?
- Are there extensionless routes? Determines how much weight the sniffed-type signal carries.
