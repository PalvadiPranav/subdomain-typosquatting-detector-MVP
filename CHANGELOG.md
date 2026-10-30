# Changelog

Not every internal change is listed here; these are the changes relevant to a user of the application.

## v1.0.0 — Local stable release

- Added model version tracking and a startup migration for databases created by v0.2.0; stored findings are recalculated with the v1 rules once.
- Added a distinct signal for brand-related text placed in a subdomain above an unrelated registrable domain.
- Improved approximate spelling detection by comparing hostname pieces, and changed lure-keyword matching to whole tokens/phrases.
- Set documented triage bands to low `0–34`, review `35–64`, and high `65–100`. These remain heuristic thresholds, not validated probabilities.
- Rejects IP literals, malformed bare ports, and URLs containing credentials during hostname normalization.
- Added loopback-client enforcement, same-origin checks for state-changing browser requests, and response security headers.
- Added safer CSV handling for spreadsheet-formula-like text and a favicon, avoiding the recurring `/favicon.ico` 404.
- Moved pytest out of runtime dependencies. The private test suite and test workflow are kept out of Git; a screenshot of the local run is included in the README.
- Continues to display DNS/TLS observations as separate supporting evidence; they are not included in the score.

## v0.2.0 — DNS and TLS enrichment

- Added on-demand DNS lookups for A, AAAA, CNAME, MX, NS, TXT, CAA, and SOA records.
- Added verified TLS certificate metadata from public IPs returned by DNS, without sending HTTP requests or retrieving page content.
- Saved timestamped enrichment runs in SQLite and exposed the latest results and prior-run summaries in the candidate detail page.
- Included the latest enrichment timestamp, source summary, DNS, and TLS JSON in CSV exports.

## v0.1.0 — Initial detection MVP

- Added brand seed management, manual candidate entry, hostname normalization, and a rules-based score with an explanation per signal.
- Added low-volume Certificate Transparency discovery using `crt.sh`.
- Added analyst verdicts, notes, a local SQLite database, a dashboard, and CSV export.
