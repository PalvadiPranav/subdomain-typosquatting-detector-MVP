[README.md](https://github.com/user-attachments/files/33785625/README.md)
# Subdomain Typosquatting Detection Platform

A small defensive cybersecurity project for finding and reviewing suspicious hostnames that resemble monitored brands. It uses Certificate Transparency (CT) search results to discover candidates, applies a rules-based score, stores analyst decisions, and exports findings to CSV.

**Version:** 0.1.0  
**Status:** MVP  
**Built with:** Python, FastAPI, SQLite, Jinja2, and pytest

> This is an early version, not a complete phishing-detection service. It does not fetch webpage content, take screenshots, use passive DNS, or automatically submit takedown requests. A score is only a way to prioritize review; it does not prove that a site is malicious.

## Features

- Add brands, official domains, and keywords to monitor.
- Add candidate hostnames manually and avoid duplicate entries.
- Search public Certificate Transparency metadata through `crt.sh`.
- Normalize hostnames, handle IDN/punycode, and use Public Suffix List data where available.
- View an explainable rules-based score and the signals that contributed to it.
- Record analyst verdicts and notes.
- Store results locally in SQLite and export them as CSV.

## Technology

- Python 3.11 or newer
- FastAPI and Uvicorn
- Jinja2 templates and CSS
- SQLite
- `httpx2` for CT metadata requests
- `tldextract` with its bundled Public Suffix List snapshot
- `pytest` for tests

If `tldextract` is unavailable, the application has a limited fallback for hostname parsing. That fallback does not cover the complete Public Suffix List.

## Installation on Linux

These commands work on Parrot OS, Kali, Ubuntu, and similar distributions.

### 1. Install the prerequisites

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip unzip
```

### 2. Open the project folder

If the ZIP is in `~/Downloads`, extract it and enter the project directory:

```bash
cd ~/Downloads
unzip subdomain-typosquatting-detector.zip
cd subdomain-typosquatting-detector
```

If you already extracted the project, just `cd` into that folder.

### 3. Set up Python

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Activate `.venv` again whenever you open a new terminal for this project.

### 4. Run the application

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open these addresses in a browser:

- Dashboard: <http://127.0.0.1:8000>
- API documentation: <http://127.0.0.1:8000/docs>
- Health check: <http://127.0.0.1:8000/health>

Press `Ctrl+C` in the terminal to stop the server. The app creates `data/app.db` for local storage.

## First run

1. Add a brand and its official domain. For a test, use `Acme Demo` and `acme.example`.
2. Add a fictional candidate such as `acme-login.provider.example`.
3. Open the result to see how its score was calculated.
4. Record a verdict and a short explanation.
5. Use **Export CSV** to download the findings.

The `.example` names are reserved examples, not reports about real websites. Demo records can also be loaded by stopping the server and running:

```bash
python scripts/seed_demo.py
```

Then start the server again.

## Run the tests

With the virtual environment active, run this from the project root:

```bash
pytest -q
```

## Windows setup

In PowerShell, run these commands from the project directory:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

If PowerShell blocks environment activation, use Command Prompt and run:

```bat
.venv\Scripts\activate.bat
```

## Project structure

```text
subdomain-typosquatting-detector/
├── app/
│   ├── main.py              # Web routes and form handling
│   ├── database.py          # SQLite setup and queries
│   ├── normalization.py     # Hostname normalization and suffix parsing
│   ├── scoring.py           # Rules-based risk score
│   ├── discovery.py         # Certificate Transparency lookup
│   ├── templates/           # Dashboard and finding pages
│   └── static/              # CSS
├── data/                    # Local database; should not be committed
├── scripts/                 # Demo-data helper
├── tests/                   # Automated tests
├── .github/workflows/       # GitHub Actions test workflow
├── ARCHITECTURE.md
├── requirements.txt
├── pyproject.toml
└── README.md
```

Python imports and paths are case-sensitive on Linux, so keep the file names unchanged unless you update the corresponding imports too.

## How scoring works

The current scoring model uses a small set of rules:

- **Brand similarity:** up to 30 points for matching or closely resembling configured brand tokens.
- **Login-related keywords:** up to 15 points for words such as `login`, `verify`, `account`, or `secure`.
- **Shared-hosting context:** 8 points for selected common hosted-subdomain patterns. This is context, not proof of abuse.
- **Punycode indicator:** 8 points to flag a hostname for closer inspection.
- **CT source context:** 3 points to record how the candidate was discovered.
- **Official-domain evidence:** up to 30 points deducted when a hostname is at or beneath a configured official domain.

The final score is limited to the range 0–100. The current thresholds are **high** (80–100), **review** (50–79), and **low** (0–49). With the current signals, the maximum possible score is 64, so the high tier cannot currently be reached. That is deliberate: the MVP does not yet have page-content or reputation signals strong enough to justify high scores.

The score is a prioritization aid, not a probability of phishing. Always inspect the evidence before drawing a conclusion.

## Certificate Transparency discovery

The app performs a small number of token searches against the public `crt.sh` JSON endpoint. It normalizes and deduplicates returned hostnames, checks their relevance, and stores candidates. It does not connect to the discovered hostnames as part of CT discovery.

CT data has gaps. A hostname not appearing in the results may still exist, and a CT record does not mean the associated site is live or malicious. The current token search can also miss some misspellings; bounded typo permutations are planned for a later version.

## Roadmap

**Next: DNS and TLS details**

Add DNS records and certificate metadata with timestamps and source information. Passive DNS can be added when an appropriate provider and permitted account are available.

**Then: better hostname and content signals**

Add carefully limited typo permutations and improve the way shared-subdomain providers are identified. If page fetching is introduced, it should run in an isolated worker with strict timeouts, response-size limits, restricted network access, and redirect checks. Favicon and page-content comparisons should come after those safeguards are in place.

**Finally: evaluation and optional machine learning**

Build a labeled dataset and compare the current rules with richer evidence. Report precision, recall, false-positive rate, missing-data rate, and discovery delay against a clear baseline. A machine-learning model should only be considered once enough examples have been reviewed and labeled.

## Safety and privacy

- This version is intended for local use. It has no authentication or CSRF protection, so do not expose it to the public internet. Keep it bound to `127.0.0.1`; do not use `--host 0.0.0.0` with this version.
- Only monitor brands you own or are authorized to assess.
- Do not submit credentials, interact with login forms, or exploit candidate sites.
- Do not block or report a hostname based only on its score. Review the evidence first.
- Follow the terms and rate limits of any discovery provider you use.
- The local database may contain investigation notes and hostnames. Keep it private; the `.gitignore` file should exclude local data and environment files from Git.

## References

- [crt.sh](https://crt.sh/) — public Certificate Transparency search.
- [FastAPI form handling](https://fastapi.tiangolo.com/tutorial/request-forms/) — documentation for form handling.
- [FastAPI database tutorial](https://fastapi.tiangolo.com/tutorial/sql-databases/) — background for database-backed applications.
- [GitHub: Adding locally hosted code](https://docs.github.com/en/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github?platform=linux) — guide for publishing an existing local project.
