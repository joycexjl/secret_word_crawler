# 1. Credentials never leave the target host

Date: 2026-08-21

## Status

Accepted

## Context

The challenge requires HTTP Basic Auth credentials on every request to the
target. Playwright's `http_credentials` option answers any 401 challenge on
**any** origin — if a page references a third-party URL that issues an auth
challenge, the browser would send the credentials there. The design also
declares off-host crawling a non-goal, but originally enforced that only at
the frontier (a scheduling decision), leaving the network layer able to leak.

## Decision

Scope is enforced at the network layer: a route interceptor aborts every
request whose `(scheme, host, port)` is not `(http, 54.214.7.161, 80)`,
and credentials are provided via `http_credentials` on the same context.
The frontier still records out-of-scope edges for the graph and the
accounting, but the request can never be made. During Tier 2 interaction the
interceptor additionally aborts non-GET requests, logging them as
`blocked_mutation` findings.

## Consequences

- Credential exfiltration to an off-host origin is impossible by
  construction, not by discipline.
- "Out-of-scope ⇒ never fetched" is guaranteed even if frontier logic has a
  bug (defense in depth).
- Off-host subresources (CDN assets, fonts) will fail to load in the
  browser; this is accepted — they are out of scope anyway, and the failures
  are visible in the response recorder.
- Changing the target (or allowing an off-host dependency) requires editing
  the interceptor, a deliberate act, not a config slip.
