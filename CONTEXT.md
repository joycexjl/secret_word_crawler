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
The serialized DOM of an HTML page at a [[canonical snapshot moment]],
stored as its own blob and linked to the fetch event via `rendered_sha256`
(load moment) or `interacted_sha256` (post-interaction moment). Distinct
corpora from the raw bytes: scripts can inject content (rendered-only) or
delete it (raw-only), and interaction can surface DOM that exists only after
a click. Divergence between any two of the three corpora is a finding.

### Canonical snapshot moment
The defined moments at which harvest and DOM serialization happen. There are
two: the **load moment** (after `domcontentloaded` plus a bounded wait for
network idle, ~3–5s, then proceed regardless, flagging `idle_timeout`) and,
when Tier 2 interaction ran, the **post-interaction moment** (after the
click sequence completes). Mutations after the load moment and outside the
interaction sequence are logged as `late_mutation` tripwires, not harvested.

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
with the truncation recorded loudly as a bounded-coverage admission. Where
a probe shows the space is a uniform generated template with no
page-dependent content (as `/report/?page=N` was: `page=0` and `page=abc`
both clamp to page 1, `page=61` is the next identical-structure slice),
the template is declared a bounded-coverage exception rather than crawled
to fixpoint.

### Unexplained interactive
A clickable-looking element whose page visit produced no associated network
or navigation activity. A nonzero count is the mechanical trigger for
Tier 2 interaction. Tier 2's click set is *semantic*, not the flagged set:
`button`, `[role=tab]`, `<summary>`, `[role=button]`, and carousel next/prev
controls — each clicked once, except carousel arrows, which are clicked
repeatedly up to a step cap (~10) until the serialized-DOM hash repeats
(a fixpoint). The harvest is the post-interaction snapshot, one per page.

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

### Link-bearing surface
Any place a URL can hide besides an `<a href>`: a `sourceMappingURL` comment,
CSS `url()`/`@import`, non-anchor HTML attributes (`<track src>`, `<link>`,
`<meta http-equiv="refresh">`, …), JS string constants and navigation calls,
HTTP response headers (`Link:` structurally, all others pattern-scanned), and
URL-valued JSON fields (`start_url`, `icons[].src`, a sourcemap's `sources`
array). All emit edges into the same [[frontier]] under the same tier
discipline and the same fixpoint — no source gets its own fetch policy.
Service workers are treated statically: the registration call is recorded
(`how=sw_register`), `sw.js` is fetched as bytes, and its precache list is
read out of the source text, never executed.

### Carrier path
The original file path of a sourcemap `sourcesContent` entry
(e.g. `webpack://./src/admin/config.js`). When a secret is found in
pre-bundle source, the carrier path is part of the sighting's provenance —
"which original file carried it" — recorded in the surface tag rather than
as a URL.

### Surface fragment
A byte range *inside* a [[blob]] whose content type differs from the
container's — an inline `<script>` or `<style>` body in an HTML page, or any
attribute value (`data-*`, `alt`, `title`, `<meta content>`, `aria-label`).
A fragment is a *surface*, not a virtual resource: it has no canon key, no
fetch event, no sha256 of its own, and is never fetched or expanded. Its
provenance chains container → fragment → sub-mechanism
(`text/html:inline_script:string_literal`), so the code extractor's
sub-surfaces (comment, string literal, raw) can be applied to the fragment's
bytes without pretending the fragment was ever a response. Attribute
fragments are tagged per attribute name (`text/html:html_attr:data-key`),
because when a secret lands in an attribute, *which* attribute is part of
the finding. Only inline `<script>`/`<style>` bodies get the code sub-split —
they alone carry a different grammar; attribute values are scanned as-is.
This keeps the [[fetch event]] partition invariant intact: fragments were
never requested, so they join no accounting set.
