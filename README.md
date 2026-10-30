# Subdomain Typosquatting Detection Platform

A small, local-first defensive tool for keeping track of hostnames that might impersonate a brand. It brings basic Certificate Transparency discovery, hostname scoring, DNS/TLS evidence, analyst notes, and CSV export into one place.

**Current release:** `v1.0.0`
**Scoring model:** `1.0`
**Built with:** Python, FastAPI, SQLite, Jinja2, dnspython, and Python's TLS libraries

This is a single-user local application for learning, research, and defensive triage. It is not an internet-wide scanner, and a score is not a probability or proof that a site is malicious.

## What it does

- Keep a list of monitored brands, their official domains, and optional keywords.
- Add candidate hostnames manually or search public Certificate Transparency metadata through `crt.sh`.
- Normalize hostnames, handle IDNs/punycode, and determine registrable domains using a bundled Public Suffix List snapshot.
- Explain why a candidate received its score, including brand similarity, lure words, brand text in a third-party subdomain, selected shared-hosting suffixes, punycode, discovery source, and negative evidence for configured official domains.
- Run DNS lookups for A, AAAA, CNAME, MX, NS, TXT, CAA, and SOA records on demand.
- Inspect TLS certificate metadata through a verified handshake to a public IP on port 443.
- Save timestamped DNS/TLS observations and keep previous collection runs in SQLite.
- Record analyst verdicts and notes, filter the findings queue, and export results to CSV.
- Keep existing v0.2 databases: startup adds the scoring-version field if needed and recalculates older scores using the v1 rules.

## Run it on Linux

Tested with Python 3.11+ on Linux distributions such as Parrot OS, Kali, and Ubuntu.

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
```

Extract the downloaded project ZIP, open a terminal in the extracted folder, then run:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. The health endpoint is at <http://127.0.0.1:8000/health>, and the API docs are at <http://127.0.0.1:8000/docs>.

The application creates `data/app.db` on first start. It holds monitored brands, candidate hostnames, analyst notes, and enrichment history, so it stays on your computer and is excluded from Git.

## A quick first run

1. Add a brand such as `Acme Demo` with the official domain `acme.example`.
2. Add the fictional candidate `acme-login.provider.example` and leave its source as `manual`.
3. Open the candidate to see its score breakdown.
4. Try recording a verdict and a short analyst note.
5. For a separate real-world DNS/TLS connectivity check, add `example.com` as a candidate and select **Run DNS + TLS checks** on its detail page.
6. Export the results using **Download CSV**.

The `.example` names are reserved demonstration data. They are useful for scoring and interface tests, but they will not return meaningful public DNS/TLS results. Use only brands you own or are authorized to monitor when using live discovery.

## How the score works

The score is a rules-based **triage priority**, not a calibrated likelihood of phishing. The v1.0 model considers:

| Signal | What it contributes |
|---|---|
| Brand-name similarity | Exact and substring matches, plus conservative approximate spelling matches in hostname pieces. |
| Login/lure keywords | Whole-token matches such as `login`, `verify`, `account`, `secure`, or configured keywords. |
| Official-domain evidence | A negative contribution when the candidate is at or beneath a configured official domain. |
| Brand in third-party subdomain | Additional context when brand-related text appears to the left of a different registrable domain. This targets the project's subdomain-abuse use case. |
| Shared-hosting context | A small signal for selected delegated hosting suffixes; the provider's presence is not proof of abuse. |
| IDN/punycode indicator | Flags labels using the `xn--` representation for manual visual review. |
| Discovery source | A small context signal when a candidate came from Certificate Transparency. Discovery itself is not evidence of maliciousness. |

The starting bands are **low: 0–34**, **review: 35–64**, and **high: 65–100**. These are heuristic thresholds selected to make the review queue useful; they have not been calibrated against a representative labeled dataset. DNS/TLS, page content, and reputation data are collected or planned separately and do not yet change the score. Always read the reasons behind a score before acting on it.

## DNS and TLS details

### DNS

The application asks the machine's configured recursive DNS resolver for the supported record types. It stores the returned values, TTL when available, resolver information, status, source, and observation timestamp. It keeps `NXDOMAIN`, no-answer, timeout, and resolver-error outcomes distinct. A missing record is not evidence that a hostname is safe.

These are current lookups, **not passive DNS history**. Results can differ between networks and over time. Passive DNS is not configured in this release; add it only when an appropriate provider and permitted account are available.

### TLS

The app attempts a short TLS handshake on port 443 only to public IPs collected during that DNS run. It uses Python's default certificate store to verify the certificate chain and hostname. It does not disable verification to force a result, send an HTTP request, load the page, or submit a form. When verification succeeds, it stores certificate subject/issuer, serial number, SANs, validity dates, days remaining, SHA-256 fingerprint, TLS version, cipher, connected IP, timestamp, and source. When the handshake fails, the failure category is stored instead of inventing certificate details.

## Local validation

The project is developed and tested locally. The test source files and test workflow are intentionally not published in this repository; the image below is a record of the private test run. The DNS/TLS unit tests mock network responses, so a green test run confirms the tested code paths—not live availability of any DNS resolver or website.

![Private local validation run](docs/images/private-test-results.png)

## Project layout

```text
subdomain-typosquatting-detector/
├── app/
│   ├── main.py              # Dashboard routes and analyst workflow
│   ├── database.py          # SQLite storage and v0.2 database migration
│   ├── discovery.py         # Low-volume crt.sh CT search
│   ├── enrichment.py        # DNS records and verified TLS metadata
│   ├── normalization.py     # Hostname validation and PSL-aware parsing
│   ├── scoring.py           # Explainable v1 triage rules
│   ├── version.py           # App and scoring-model versions
│   ├── templates/           # Dashboard and candidate details
│   └── static/              # CSS and favicon
├── data/                    # Local database; excluded from Git
├── docs/images/             # README image
├── scripts/                 # Optional fictional demo data
├── ARCHITECTURE.md
├── CHANGELOG.md
├── requirements.txt
└── README.md
```

## Known limits

- This release focuses on discovery, hostname triage, DNS/TLS metadata, and analyst workflow. It does not fetch webpage HTML, take browser screenshots, compare favicons/logos, or use machine learning.
- CT search can miss typos where the brand token itself has changed; it does not cover every hostname on the internet.
- DNS/TLS observations do not affect the current risk score.
- The score and thresholds have not been validated as a predictive model.
- There is no passive DNS integration or automatic takedown submission.
- The app is intended for local use. It has no account system or multi-user access controls. It rejects non-loopback client connections and checks the origin of browser POSTs as additional safeguards, but that does not make it suitable for public deployment.

## Safety and privacy

Run the server bound to `127.0.0.1`; do not use `--host 0.0.0.0`. Monitor only brands you own or are authorized to assess. Check the CT provider's terms and avoid repeatedly issuing large searches. Do not submit credentials, exploit websites, or automatically block/report a hostname based only on a score. Keep `data/app.db`, secrets, and investigation notes private.

## Versions

- [`v0.2.0` release notes](docs/RELEASE_NOTES_v0.2.0.md) — added on-demand DNS/TLS enrichment to the initial CT and analyst-review workflow.
- [`v1.0.0` release notes](docs/RELEASE_NOTES_v1.0.0.md) — tightened hostname validation, updated the scoring model, added a v0.2 database migration, and added local-access/export safeguards.
- Full history is recorded in [`CHANGELOG.md`](CHANGELOG.md).

## References

- [crt.sh](https://crt.sh/) — public Certificate Transparency search.
- [dnspython resolver documentation](https://dnspython.readthedocs.io/en/stable/resolver.html) — DNS query behavior and timeouts.
- [Python `ssl` documentation](https://docs.python.org/3/library/ssl.html) — TLS and certificate handling.
- [FastAPI documentation](https://fastapi.tiangolo.com/) — web application framework.
