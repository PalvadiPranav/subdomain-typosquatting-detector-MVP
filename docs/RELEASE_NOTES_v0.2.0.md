# v0.2.0 — DNS and TLS enrichment

This release added an on-demand DNS/TLS collection step to the original hostname-discovery workflow.

- DNS lookups for A, AAAA, CNAME, MX, NS, TXT, CAA, and SOA.
- Timestamped answers, TTL values when available, resolver/source metadata, and separate error states.
- Verified TLS handshake against a public IP returned by DNS, with certificate details stored only when certificate and hostname validation succeed.
- Enrichment run history in SQLite and latest DNS/TLS information in the CSV export.

The release did not add passive DNS, page fetching, content similarity, or automatic takedown actions. DNS/TLS data did not affect the risk score.
