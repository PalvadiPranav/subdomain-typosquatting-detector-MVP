# Subdomain Typosquatting Detection Platform

**Status:** Working MVP · **Version:** 0.1.0 · **Purpose:** Defensive cybersecurity / brand-protection research

A local web application to monitor brand seeds, collect candidate hostnames from a public Certificate Transparency (CT) search endpoint, calculate an explainable rules-based triage score, record analyst verdicts, and export findings as CSV.

> **Important:** This is a first MVP, not a complete internet-wide phishing detection service. It does not fetch webpage content, take screenshots, query a passive-DNS provider, perform automated takedowns, or use machine learning. Those should be added as separately tested modules. The score is not a probability and is not proof a site is malicious.

## MVP features

- Brand seed management: name, official domains, and optional keywords.
- Manual candidate entry and deduplication.
- Low-volume passive CT metadata lookup via `crt.sh`.
- Hostname normalization, IDNA/punycode handling, and bundled Public Suffix List parsing including private suffix rules.
- Explainable 0–100 scoring contributions with negative evidence for configured official domains.
- Alert tiers: high (80–100), review (50–79), low (0–49).
- Analyst verdicts and notes: true positive, false positive, authorized/legitimate, parked, needs more evidence.
- SQLite persistence and CSV export.
- Unit tests for normalization and scoring.

## Technology

- Python 3.11+ recommended
- FastAPI + Uvicorn
- Jinja2 templates and plain CSS
- SQLite (built into Python)
- `httpx` for the CT metadata API
- `tldextract` with its bundled PSL snapshot (no runtime PSL download)
- A conservative built-in fallback is included for offline environments where `tldextract` is unavailable; the fallback is not a complete Public Suffix List.
- `pytest`

## Start here (Parrot OS / Kali / Ubuntu / other Linux)

### 1. Unzip and open the project folder

Download and extract the ZIP, then open a terminal in the extracted directory. Example:

```bash
cd ~/Downloads
unzip subdomain-typosquatting-detector.zip
cd subdomain-typosquatting-detector
```

If you extracted it somewhere else, use that folder path instead. The project root should contain `README.md`, `requirements.txt`, `app/`, `tests/`, and `scripts/`.

### 2. Check Python and Git

```bash
python3 --version
git --version
```

Python 3.11 or newer is recommended. If Git is missing on a Debian-based distro:

```bash
sudo apt update
sudo apt install git python3 python3-venv python3-pip
```

### 3. Create a virtual environment

Run this from the project root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Whenever you return to the project in a new terminal, activate it again with `source .venv/bin/activate`.

### 4. Start the application

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000** in your browser. API documentation is at **http://127.0.0.1:8000/docs**, and health status is at **http://127.0.0.1:8000/health**.

The app creates `data/app.db` automatically. That local database is ignored by Git and should normally remain private.

To stop the server, press `Ctrl+C` in the terminal.

### 5. First use

1. Add a brand. For a safe first exercise, use `Acme Demo` and official domain `acme.example` (a reserved example namespace).
2. Add a candidate hostname such as `acme-login.provider.example` as a fictional exercise input. The application does not assert that this hostname is malicious.
3. Open the finding to inspect each scoring contribution.
4. Record a verdict and a short rationale.
5. Export the queue from **Export CSV**.
6. To try sample data automatically, stop the server and run `python scripts/seed_demo.py`, then start the server again. The sample records are fictional examples, not threat-intelligence claims.

### 6. Run tests

From the project root with the virtual environment active:

```bash
pytest -q
```

## Windows setup (PowerShell)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

If PowerShell blocks activation, you can use Command Prompt instead:

```bat
.venv\Scripts\activate.bat
```

## Project folder and file naming

```text
subdomain-typosquatting-detector/
├── app/
│   ├── __init__.py          # Marks app as a Python package
│   ├── main.py              # FastAPI routes and form handling
│   ├── database.py          # SQLite connection and schema
│   ├── normalization.py     # Hostname cleaning and PSL-aware parsing
│   ├── scoring.py           # Explainable rules-based score
│   ├── discovery.py         # crt.sh CT discovery adapter
│   ├── templates/
│   │   ├── base.html
│   │   ├── dashboard.html
│   │   └── detail.html
│   └── static/
│       └── style.css
├── data/                    # Local runtime database (ignored by Git)
├── .github/workflows/
│   └── tests.yml            # GitHub Actions CI test run
├── scripts/
│   └── seed_demo.py         # Optional fictional demo data
├── tests/
│   ├── test_normalization.py
│   └── test_scoring.py
├── .env.example
├── .gitignore
├── LICENSE
├── README.md
├── pyproject.toml           # pytest configuration
└── requirements.txt
```

Keep file and directory names exactly as shown. Python imports are case-sensitive on Linux.

## How the MVP scores a candidate

The rules-only baseline combines:

- **Brand-name similarity (up to 30 points):** exact token, substring, and approximate similarity against configured brand tokens.
- **Login/lure keywords (up to 15 points):** configured words such as `login`, `verify`, `account`, or `secure`.
- **Shared-hosting context (8 points):** selected common hosted-subdomain suffixes. This is context only, not evidence of maliciousness.
- **Punycode indicator (8 points):** calls for visual inspection, not automatic classification.
- **CT source context (3 points):** indicates how it was discovered, not that it is malicious.
- **Official-domain evidence (-30 points):** if the hostname is at or beneath one of the configured official domains, the score is reduced. Check that seed entries are correct.

The total is clamped to 0–100. Tiers are high ≥80, review 50–79, and low <50. **With only the current signals, the maximum possible score is 64, so the high tier is intentionally unreachable in v0.1.** This prevents weak metadata signals from producing a high-confidence alert before content/reputation evidence is implemented. Do not inflate scores or lower thresholds just to make the dashboard look more active.

## How CT discovery works

The dashboard makes a small number of token searches against the public `crt.sh` JSON endpoint. Results are deduplicated, normalized, filtered for relevance, and saved. The app does not connect to the hostnames returned by CT. CT coverage has limitations: a lack of results does not mean a hostname does not exist, and CT presence is not evidence of phishing. The first-pass token search may miss misspellings where the brand token itself was changed; scoped permutation discovery is a future module.

## Roadmap for the next releases

### v0.2 — Enrichment

- Add passive DNS via a provider account that you are permitted to use.
- Add DNS records and TLS metadata, with timestamps and source provenance.
- If page metadata is collected later, run it in an isolated worker with tight timeouts, response-size caps, egress restrictions, redirect revalidation, and blocks for loopback/private/link-local/metadata IPs.
- Add favicon/content fingerprints only after safe collection and retention controls are in place.

### v0.3 — Improved discovery

- Add bounded typo permutations (deletion, insertion, substitution, adjacent transposition, and selected homoglyphs).
- Query approved sources using explicit request budgets and backoff.
- Improve provider discovery using evidence, confidence decay, and analyst review instead of treating the PSL as a complete reseller directory.

### v0.4 — Evaluation and ML

- Build a labeled dataset with documented collection dates and label rationale.
- Compare hostname-only scoring with content and infrastructure features.
- Evaluate precision, recall, false-positive rate per tier, missing-data rate, and lead time against an explicit baseline.
- Train a classifier only after enough reviewed data exists; use a time-based/grouped holdout to avoid near-duplicate leakage.
- Keep score explanations and model/rule versions visible.

## Safety and privacy notes

- This app is designed to run locally. It has **no authentication or CSRF protection** and must not be exposed to the internet as-is. Bind to `127.0.0.1`; do not use `--host 0.0.0.0` for this version.
- Use it only for defensive monitoring of brands you own or are authorized to monitor.
- Do not enter credentials into candidate sites, submit forms, exploit sites, or automatically block/report a hostname based solely on a heuristic score.
- Review source/provider terms and rate limits before using live discovery.
- The database may contain sensitive investigation notes and observed hostnames. It is deliberately excluded from Git by `.gitignore`.

## Put it on GitHub (your first Git workflow)

### A. Inspect files before committing

From the project root:

```bash
git status --short
cat .gitignore
```

Make sure no `data/app.db`, `.env`, API keys, passwords, personal investigation notes, or screenshots of sensitive data are being committed. The supplied `.gitignore` excludes local databases and environment files.

### B. Initialize Git locally

```bash
git init
git add README.md ARCHITECTURE.md requirements.txt pyproject.toml .gitignore .env.example LICENSE app tests scripts .github data/.gitkeep
git status --short
git commit -m "Build subdomain typosquatting detection MVP"
git branch -M main
```

If Git asks you to set an identity, configure your public commit author details:

```bash
git config --global user.name "Your Name"
git config --global user.email "your-public-or-noreply-email@example.com"
```

Then rerun the commit command. Use an email you are comfortable associating with commits; GitHub provides a no-reply email option in account settings.

### C. Create an empty repository on GitHub

1. Sign in to GitHub and select **New repository**.
2. Name it `subdomain-typosquatting-detector`.
3. Add a short description, for example: `Defensive subdomain typosquatting detection MVP with CT discovery and explainable scoring`.
4. Choose Public if you want it visible in your portfolio, or Private while developing.
5. Do **not** initialize it with a README, license, or `.gitignore` because this project already has them.
6. Create the repository and copy its HTTPS repository URL.

### D. Connect the local folder and push

Replace `YOUR-USERNAME` with your GitHub username:

```bash
git remote add origin https://github.com/YOUR-USERNAME/subdomain-typosquatting-detector.git
git push -u origin main
```

If you copied a different repository URL from GitHub, use that exact URL instead. Follow GitHub's current authentication prompt; do not paste a password or token into source files. After the push, refresh the repository page and confirm that the README and `app/` files appear.

### E. Make future updates

After editing files and testing:

```bash
source .venv/bin/activate
pytest -q
git status --short
git add app tests README.md
git commit -m "Add hostname enrichment feature"
git push
```

Only include the folders/files you changed. Never use `git add .` blindly until you understand the output of `git status --short`.

## Portfolio-ready repository checklist

- [ ] Add screenshots from fictional/demo data only.
- [ ] Include a short architecture diagram and a sample report export.
- [ ] Record test results and known limitations.
- [ ] Include a labeled, permitted evaluation dataset or clear instructions to reproduce it.
- [ ] Add a release tag after a stable milestone: `git tag v0.1.0 && git push origin v0.1.0`.
- [ ] Do not claim full phishing detection or production readiness while key evidence sources are not implemented.

## Reference documentation

- [crt.sh JSON query examples](https://learn.secbyte.org/tools/ct-lookup-api) — CT results are discovery candidates, not proof that a hostname is live or malicious.
- [FastAPI form data](https://fastapi.tiangolo.com/tutorial/request-forms/) — used for dashboard forms.
- [FastAPI SQL database tutorial](https://fastapi.tiangolo.com/tutorial/sql-databases/) — background for the local persistence pattern.
- [GitHub Docs: adding locally hosted code to GitHub](https://docs.github.com/en/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github?platform=linux) — official reference for initializing a repository and pushing an existing project.
