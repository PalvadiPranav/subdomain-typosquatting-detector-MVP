# Architecture Notes

## Current release: v1.0.0

The application is a local, single-user FastAPI service. Its pipeline is intentionally limited to public CT metadata discovery, hostname-based triage, explicit DNS/TLS enrichment, analyst verdicts, and CSV export.

## Data flow

1. A user adds a brand, official domains, and optional keywords.
2. A candidate is entered manually or discovered through a small set of public `crt.sh` metadata searches.
3. The hostname is normalized and parsed using a bundled Public Suffix List snapshot when `tldextract` is installed.
4. The scoring model produces an explainable triage priority and records scoring-model version `1.0`.
5. On the candidate detail page, a user can explicitly start DNS/TLS enrichment.
6. DNS lookups are performed through the configured recursive resolver. A verified TLS handshake is attempted only against public addresses found in the DNS response.
7. Enrichment observations are stored with timestamps and source metadata. Earlier runs are retained in SQLite; the interface shows the most recent results and a short run history.
8. Analysts record a verdict and notes, then export findings to CSV when needed.

## Scoring model 1.0

Signals include hostname/brand similarity, whole-token lure keywords, negative evidence for configured official domains, brand-bearing text in a subdomain above an unrelated registrable domain, selected shared-hosting suffixes, IDN/punycode presence, and CT source context. The published bands are low `0–34`, review `35–64`, and high `65–100`. The bands are heuristic. The score is not a probability and has not been calibrated against a representative, independently labelled dataset.

DNS/TLS observations are deliberately not score inputs in this version. Page content, favicons, passive DNS, infrastructure-reputation feeds, and analyst-history learning are not yet implemented.

## DNS collection

The app queries A, AAAA, CNAME, MX, NS, TXT, CAA, and SOA using the machine's configured recursive resolver through `dnspython`. Queries have bounded timeouts and run concurrently in a bounded worker pool. Each result includes a state (answer, no answer, NXDOMAIN, timeout, resolver error, or error), values, TTL when available, source, resolver nameservers, and observation timestamp.

These are live resolver lookups, not passive DNS history. Results may vary by resolver and time.

## TLS collection

The application attempts a short TCP/TLS connection to port 443 for up to three global public IPs returned by the DNS stage. It uses Python's default CA trust store and verifies the certificate chain and hostname. It does not disable verification to force metadata collection and does not issue an HTTP request. Private, loopback, link-local, and reserved addresses are never contacted by this collector.

A successful handshake records the certificate subject, issuer, serial number, SANs, validity, expiry interval, fingerprint, negotiated TLS version and cipher, connected IP, source, and timestamp. Failures are saved as status/error categories without fabricating certificate details.

## Persistence and upgrade path

SQLite stores brands, hostnames, scoring explanations, analyst verdicts, and enrichment runs. `init_db()` adds the `scoring_version` column when opening a v0.2.0 database that predates the field. At startup, the app re-scores rows with an older scoring version and updates their score explanation and timestamp without changing `first_seen`, `last_seen`, analyst verdict, notes, or enrichment history.

## Local security controls

- The default run command binds Uvicorn to `127.0.0.1`.
- Middleware also rejects non-loopback clients, so binding to a network interface by mistake does not make the app remotely accessible through normal requests.
- State-changing requests with an Origin or Referer header must match the request host.
- Responses include baseline security headers and disable caching.
- CSV export prefixes text that could be interpreted as a spreadsheet formula.
- The application still has no user accounts or multi-user permissions. Keep it local and do not treat these controls as a hardening guarantee for production deployment.

## Known limits

- CT token search may miss misspellings where the brand token itself changes, and not all hostnames appear in CT.
- A matching name, CT record, hosting suffix, DNS record, or valid TLS certificate is not proof of maliciousness.
- No HTML fetching, screenshots, favicon/logo comparison, passive DNS, ML classifier, automated blocking, or takedown submission.
- Thresholds are hand-selected heuristics and need evaluation against a permissioned labelled dataset.
- Automated tests are retained locally and excluded from Git; the README includes an image of the local test run.
