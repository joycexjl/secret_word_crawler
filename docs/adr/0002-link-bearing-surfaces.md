# Link-bearing surfaces beyond the anchor tag

The crawl's discovery was anchor-centric: edges came from the Tier 0 DOM
harvest and a quote-delimited byte-scan, which left whole classes of
references invisible — unquoted CSS `url()`, `Link:` response headers,
URL-valued JSON fields, and sourcemap references. We decided to treat every
link-bearing surface uniformly: all of them emit edges into the same
frontier, under the same tier discipline, joining the same crawl/scan
fixpoint — and all new scanners run offline against the blob store and
manifest, not inside the crawl loop.

Specific rulings:

- **Sourcemaps**: `.map` blobs get a dedicated extractor keyed on URL
  extension (not content-type — a map served as `application/json` must not
  be shredded into 80k per-string surfaces). One surface per `sourcesContent`
  entry, tagged with the carrier path, scanned raw — no recursive type
  dispatch into entry contents. The `sources` array is scanned for URL-shaped
  strings under normal tier discipline (`webpack://` lands in `out_of_scope`).
  The `sourceMappingURL` comment gets a dedicated pre-pass so the edge
  records `how=sourcemap` instead of generic `regex_fallback`.
- **CSS**: edges come from byte-scan patterns over CSS blobs (`url()` quoted
  and unquoted, `@import`) — no computed-style harvest at expand time. Every
  URL the computed style could produce is declared in the stylesheet text;
  reading the source keeps the fetch-vs-expand doctrine clean (CSS is read,
  never rendered). Extraction needed nothing: comments and `content:` values
  were already surfaces.
- **Response headers**: parsed offline from the stored manifest, not at fetch
  time — re-runnable against an existing crawl without re-requesting, and the
  crawl loop stays GET-and-store. `Link:` is parsed structurally (rel value
  as hint); all other header values get the tiered pattern scan
  (`how=http_header:<name>`), because this author has form for putting things
  in custom headers. `Location` is excluded — redirects are already handled
  by the fetch layer.
- **JSON**: instead of a manifest-specific field walker, every JSON blob's
  string values go through the tiered byte-scan with the JSON path as hint
  (`$.shortcuts[0].url`). One mechanism covers web manifests, sourcemap
  `sources`, and any `config.json`. No field-name semantics — a manifest's
  `scope` is fetched like any other string and 404s honestly if it's not a
  resource.
- **Service workers**: static treatment only. `navigator.serviceWorker.register`
  is patched in the init script to record `how=sw_register`; `sw.js` is
  fetched as bytes and its precache list read from source text. Actually
  registering the worker and enumerating CacheStorage was rejected — this
  author's tricks are static-content tricks, and a runtime-computed precache
  inventory is a hypothetical not worth an execution environment.
- **Re-crawl**: the new capability triggers a clean re-crawl from `/`, not an
  offline delta against the existing store. New edge sources change discovery
  *during* the crawl (a CSS `url()` found on page 1 changes what page 2's
  cycle fetches), so a delta-append would mix depth semantics by edge vintage
  and quietly break the depth-histogram completeness detector.

**Consequences**: the edge vocabulary (`how=`) grows
(`sourcemap`, `css_url`, `http_link_header`, `http_header:<name>`,
`json_value`, `sw_register`, plus corrected `track_src` / `video_src` /
`audio_src` labels replacing mislabeled `img_src`), and the report's
mechanism breakdown becomes the evidence that these surfaces were actually
covered. `vtt` and `webmanifest` join the known-extension set and `text/vtt`
gets a plain-text extractor. The domain terms "link-bearing surface" and
"carrier path" are defined in CONTEXT.md.
