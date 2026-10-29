# Architecture Notes

## Version 0.2.0

The application remains a local, single-user FastAPI application. This release adds an on-demand DNS/TLS enrichment path to the existing CT-discovery and analyst-review workflow.

## Data flow

1. A user adds a brand and official domains.
2. The app adds a candidate manually or queries the public `crt.sh` metadata endpoint.
3. The hostname is normalized, deduplicated, and scored using the existing rules engine.
4. On the candidate detail page, the user explicitly starts DNS/TLS enrichment.
5. DNS records are queried through the configured recursive resolver. Each record type stores a status, returned values, TTL when available, resolver details, source, and observation timestamp.
6. A verified TLS handshake is attempted only against public IP addresses returned by the DNS collection. The app does not send HTTP requests.
7. DNS/TLS results are stored as an immutable enrichment run, preserving earlier observations.
8. The detail page presents the latest run and previous run summaries. CSV export includes the latest enrichment timestamp and source summary.

## Enrichment scope

DNS types queried: A, AAAA, CNAME, MX, NS, TXT, CAA, and SOA. DNS queries use per-query timeouts and run concurrently with a bounded worker pool. NoAnswer, NXDOMAIN, timeout, resolver error, and successful answer states are kept separately.

TLS connects only to public global IP addresses collected in the DNS response, uses a short timeout, validates both the chain and hostname using Python's default CA trust store, and limits attempts to three public IP addresses. Private, loopback, link-local, and reserved targets are not contacted. The TLS step performs no HTTP request or page fetch.

The source is a direct DNS resolver lookup, not passive DNS history. Passive DNS is intentionally not included because it requires a provider and authorized credentials.

## Persistence

The `enrichment_runs` table stores `host_id`, collection timestamp, source summary, and serialized DNS/TLS results. `CREATE TABLE IF NOT EXISTS` keeps initialization safe for an existing v0.1 SQLite database.

## Current limitations

- DNS/TLS metadata are evidence for analysts and do not yet affect the risk score.
- The TLS certificate metadata is available only when chain and hostname verification succeed.
- DNS answers vary across resolvers and time.
- The application has no authentication or CSRF protection and should remain bound to localhost.
- The automated tests are retained locally but ignored by Git; a validation screenshot is embedded in the README.
