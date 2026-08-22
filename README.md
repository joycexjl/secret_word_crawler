# secret_word_crawler

A Playwright-based crawler built for the Visualping secret-word challenge:
recover all **8 secret words** (`VISUALPING{<16 lowercase hex>}`) hidden across
`http://54.214.7.161/`, and be able to argue the crawl was complete.

The work is split into two strictly separate phases (see `docs/crawler-design.md`):

1. **Crawl** (`main.py`) — record everything: fetch every in-scope resource in a
   real browser, persist every response body, and emit a site graph + coverage
   report. Never analyses content.
2. **Extract** (`extract/run.py`) — offline pass over the saved bytes: text
   surfaces, response headers, JSON values, image metadata, pixel forensics,
   and OCR. Re-runnable in seconds without touching the network.

## Requirements

- Python 3.11+ (developed on 3.14)
- [Playwright](https://playwright.dev/python/) with Chromium
- [Tesseract](https://tesseract-ocr.github.io/) 5.x on PATH (image OCR)
- Python packages: `playwright`, `pillow`, `pytesseract`, `numpy`

Setup:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install playwright pillow pytesseract numpy
.venv/bin/python -m playwright install chromium
brew install tesseract   # macOS; or your platform's package manager
```

> **Always run with `.venv/bin/python`.** The system Python lacks the OCR
> dependencies and will silently drop the image-derived secret.

## Configuration

Create a `.env` in the repo root (gitignored — never commit credentials):

```dotenv
# Basic Auth credentials for the target (required)
VISUALPING_USER=...
VISUALPING_PASS=...

# Optional geo-bypass proxy, for geo-gated surfaces like /status/eu-region/.
# All three must be set to activate; traffic still passes the network-layer
# scope lock (ADR 0001).
PROXY_SERVER=...
PROXY_USER=...
PROXY_PASS=...
```

All other knobs (scope, seed URL, caps, politeness delay, Tier 2 toggle) live
in the `CONFIG` dict at the top of `main.py` — edit there, not via flags.

## Running

### 1. Crawl

```sh
rm -rf out          # no resume: out/ must be empty before each run
.venv/bin/python main.py
```

Progress goes to stderr (set `CRAWL_LOG=DEBUG` for more). A full run takes
minutes. The crawl alternates a browser phase (fetch + render + DOM harvest)
and a byte-scan phase (regex/header/JSON link discovery over saved bodies)
until neither finds anything new — the fixpoint.

### 2. Extract secrets

```sh
.venv/bin/python -m extract.run [out_dir]   # default: out
```

Fully offline. Writes `out/secrets.json` and `out/extraction.md`, and prints
`distinct STRICT: N/8 (MET|SHORT)`.

### 3. Submission write-up (optional)

```sh
.venv/bin/python docs/writeup.py [out_dir] [docs/SUBMISSION.md]
```

Regenerates `docs/SUBMISSION.md` from the on-disk artifacts.

## Output artifacts (`out/`)

| file | contents |
|---|---|
| `manifest.jsonl` | one row per fetch event: URL, status, headers, body hash, depth |
| `blobs/` | every response body, content-addressed by sha256 |
| `edges.jsonl` | every discovered reference, labelled with *how* (`a_href`, `script_src`, `redirect`, …) |
| `graph.dot` | the site graph (render: `dot -Tpng out/graph.dot -o graph.png`) |
| `coverage.md` | completeness accounting: state counts, caps hit, blocked pages, tripwires |
| `filetypes.md` | content-type inventory + signal disagreements |
| `secrets.json` / `extraction.md` | extraction results: secrets, needs-review, ruled-out, image forensics |
| `pixel_sweep.jsonl` | per-candidate image pixel-sweep evidence log |

## Tests

```sh
.venv/bin/python -m pytest tests/            # unit/integration suites
.venv/bin/python tests/proxy_smoke.py        # geo-proxy connectivity check
```

## Safety properties (by design)

- **Scope lock at the network layer**: out-of-scope requests are blocked in the
  browser's routing layer, not just filtered from the frontier (ADR 0001).
- **GET-only**: non-GET requests are blocked and counted.
- **Credentials never leave the target host** (ADR 0001).
- **Politeness**: serial fetches with a 250–500 ms delay; caps are recorded
  loudly in `coverage.md` rather than silently truncating coverage.

## Further reading

- `docs/crawler-design.md` — the full design doc (goals, tiers, invariants)
- `docs/adr/` — architectural decision records
- `CONTEXT.md` — domain glossary (the arbiter when a term's meaning is disputed)
- `docs/SUBMISSION.md` — the challenge submission write-up
