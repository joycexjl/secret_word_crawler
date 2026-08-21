# CONTEXT

Glossary for the secret-word crawler. Domain terms only — no implementation
details, no plans. When a term's meaning is disputed, this file is the arbiter.

## Core terms

### Secret word
A string of the canonical form `VISUALPING{` + exactly 16 lowercase hex
characters + `}`. Sightings are normalized (hex case-folded, whitespace inside
braces stripped) before comparison. Only STRICT-validated values count toward
the target of **eight distinct secret words**. The index page's "not one of
the seven" phrasing is stale copy; the target is eight.

### Fetch event (manifest row)
One HTTP request issued and answered. The unit of extraction, accounting, and
provenance. Carries the verbatim request URL, final URL after redirects,
status, all three type signals, full response headers, body hash, and depth.
Distinct from the [[blob]]: many fetch events can share one blob.

### Blob
A raw response body, content-addressed by sha256. Immutable, provenance-free
on its own — provenance lives on the [[fetch event]]. Extraction over bodies
runs once per unique blob and fans sightings out to every fetch event that
carried it.

### Rendered DOM snapshot
The serialized DOM of an HTML page at the [[canonical snapshot moment]],
stored as its own blob and linked to the fetch event via `rendered_sha256`.
Distinct corpus from the raw bytes: scripts can inject content (rendered-only)
or delete it (raw-only). Divergence between the two corpora is a finding.

### Canonical snapshot moment
The single, defined moment at which the Tier 0 harvest and the rendered DOM
snapshot are taken: after `domcontentloaded` plus a bounded wait for network
idle (~3–5s, then proceed regardless, flagging `idle_timeout`). Mutations
after this moment are logged as `late_mutation` tripwires, not harvested.

### Canon key
The identity of a URL for dedup, frontier, and graph purposes: lowercased
scheme and host, default port stripped, path normalized, **query parameters
sorted**, fragment dropped. Distinct from the [[verbatim URL]] — the first
fetch event for a canon key is performed; later same-key URLs are recorded as
`duplicate_key` and never re-fetched.

### Verbatim URL
The URL exactly as discovered, used on the wire and in edge records. Never
fabricated (the sorted-query form is a key, not a request target).

### Resource states
Every discovered canon key ends in exactly one terminal state:

- `fetched` — response received, manifest row written
- `out_of_scope` — outside the [[scope triple]], never requested
- `errored` — request failed terminally (one retry for transient failures;
  4xx is terminal immediately); reason recorded
- `duplicate_key` — canon key already fetched via a different verbatim URL

The accounting invariant: these four sets partition everything ever seen.

### Scope triple
`(scheme, host, port)` = `(http, 54.214.7.161, 80)`. Anything else —
including `https:` and other ports on the same IP — is out of scope.
Out-of-scope requests are blocked at the network layer, so credentials
physically cannot leave the target host.

### Fetch vs. expand
**Fetch**: obtain a resource's bytes (any content type, via API request —
never browser-rendered, so synthetic DOMs can't pollute the edge graph).
**Expand**: run discovery tiers against a resource. Only HTML pages with 2xx
status are expanded. URLs hidden in non-HTML bytes are found by the offline
[[byte-scan]], not by expansion.

### Byte-scan
Offline discovery pass over every blob, using tiered URL patterns
(absolute / root-relative / extensioned-relative; quote-delimited).
Extensionless relative strings go to a review bucket, never auto-fetched.
Crawl and byte-scan alternate until the byte-scan yields nothing new
(the fixpoint).

### Query template
A path plus sorted query parameter *names*, ignoring values. Unbounded
parameter spaces (e.g. `/report/?page=N`) are capped per template (~60),
with the truncation recorded loudly as a bounded-coverage admission.

### Unexplained interactive
A clickable-looking element whose page visit produced no associated network
or navigation activity. A nonzero count is the mechanical trigger for
Tier 2 interaction, which clicks exactly those elements.

### Blocked notice
A 200 response whose body is a policy block or interstitial (e.g. the
geo-gated `/status/eu-region/`). Counted as `fetched` (the server answered),
flagged `blocked_notice`, and named as a **coverage exception** in the
completeness argument: evidence gathered, content unreachable. No automated
bypass.

### Disqualified sighting
A secret-word match in a response header or cookie. Challenge rules declare
these staging placeholders: recorded and reported, but excluded from the
distinct count and from the needs-review flow.

### Needs-review bucket
LOOSE-pattern hits that fail STRICT validation (e.g. OCR-less garbled
readings, split-across-tags, sweep disagreements). Every entry must exit via
a documented ruling: corrected to a canonical value (recorded as
`manual_review`) or ruled not-a-secret. A non-empty bucket at submission
weakens the completeness claim and must be declared.

### Depth (reporting)
Post-hoc BFS distance from `/` over the recorded edge graph, computed at
export. Distinct from `first_seen_depth` (when the frontier first reached the
node), which is kept for forensics. There is no depth cap; the depth
histogram flattening is a completeness detector, not a guardrail.

### Duplication case
One blob served at multiple URLs, or one URL referenced by multiple pages.
Both are reported in a dedicated section keyed by sha256; the two shapes are
distinguished (deliberate duplication is an authorial signal).
