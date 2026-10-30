# v1.0.0 — Local stable release

v1.0.0 builds on the v0.2.0 DNS/TLS workflow and is the first version with a versioned scoring model and an explicit local-access guard.

### What's changed

- Scores now include a distinct signal for brand-bearing subdomains above an unrelated registrable domain.
- Approximate brand spelling is checked across hostname pieces; lure keywords are matched as tokens/phrases rather than arbitrary substrings.
- New triage bands are low `0–34`, review `35–64`, and high `65–100`.
- Existing v0.2.0 SQLite databases migrate automatically, and previously stored candidates are re-scored under model `1.0`.
- Hostname normalization rejects IP literals, malformed bare ports, and URLs containing user information.
- Requests from non-loopback clients are rejected; browser state-changing requests with a cross-origin Origin/Referer are blocked.
- Response security headers, a favicon, and spreadsheet-formula escaping for CSV text fields are included.
- Runtime requirements no longer install pytest; the local private test suite is not published to Git.

### Still out of scope

No page content retrieval, screenshotting, favicon comparison, passive DNS, machine learning, or automatic takedown submission. DNS/TLS is supporting evidence only; the scoring rules have not been calibrated against a representative labeled dataset. This release remains local-only and should not be exposed as a public service.
