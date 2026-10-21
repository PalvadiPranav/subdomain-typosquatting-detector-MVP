[README.md](https://github.com/user-attachments/files/33785173/README.md)
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
- `httpx2` for the CT metadata API
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

## What I'd like to add next

This first version is intentionally small. I want to make sure the discovery and scoring work reliably before adding more data sources or automatic analysis. These are the next improvements I'd like to work on; the version numbers are rough milestones, not release promises.

### v0.2 — Add more useful evidence

- Add DNS records and TLS certificate details, including when each observation was collected.
- Connect to a passive-DNS provider if I have access to a suitable account and its terms allow this use.
- If I add page fetching, run it in an isolated worker. It will need strict timeouts, response-size limits, restricted network access, and checks on every redirect so it cannot reach local or private services.
- Look at favicon and page-content fingerprints once collection and data-retention rules are in place.

### v0.3 — Find more lookalike hostnames

- Generate a limited number of likely typos, such as missing, extra, swapped, or substituted characters.
- Keep queries rate-limited and use sources whose terms permit this kind of lookup.
- Improve the list of hosting and subdomain providers using observed evidence and analyst review. The Public Suffix List is useful, but it is not a complete reseller directory.

### v0.4 — Test how well it works

- Put together a labeled dataset and record when and why each example was labeled.
- Compare the current hostname-only approach with versions that include content and infrastructure evidence.
- Report precision, recall, false positives, missing data, and discovery delay against a clearly described baseline.
- Consider a small machine-learning model only after there are enough reviewed examples. Keep related hostnames together when splitting the data so near-duplicates do not make the results look better than they are.

## Safety and privacy

For now, this project is meant to run on my own machine. It does not have authentication or CSRF protection, so it should not be exposed as a public web service. Keep the server bound to `127.0.0.1`; don't run this version with `--host 0.0.0.0`.

A few other things to keep in mind:

- Use the tool for defensive monitoring of brands you own or have permission to assess.
- Don't enter credentials into candidate sites, submit forms, or try to exploit them.
- Don't block or report a hostname just because its score is high. Check the evidence first.
- Check the terms and rate limits of any discovery provider before using it.
- The local database can contain investigation notes and hostnames, so it stays out of Git. The `.gitignore` file is there to help prevent it from being uploaded by accident.

## Putting the project on GitHub

If this project is already in a local Git repository, you can skip the `git init` step. Before committing anything, check what Git is about to include:

```bash
git status --short
cat .gitignore
```

Make sure the output does not include `data/app.db`, `.env` files, API keys, passwords, or private investigation notes.

### If this is the first commit

Run these commands from the project folder. If you've already made a commit, don't repeat this section just to update the README.

```bash
git init
git add README.md ARCHITECTURE.md requirements.txt pyproject.toml .gitignore .env.example LICENSE app tests scripts .github data/.gitkeep
git status --short
git commit -m "Build subdomain typosquatting detection MVP"
git branch -M main
```

If Git asks who you are, set the name and email you want attached to your commits:

```bash
git config --global user.name "Your Name"
git config --global user.email "your-email@example.com"
```

You can use GitHub's no-reply email if you don't want your personal email shown in public commit details.

### Connect to GitHub

Create a repository on GitHub named `subdomain-typosquatting-detector`. If the code is already on your computer, leave the new GitHub repository empty—don't create another README or license there.

Copy the HTTPS URL from the repository's **Code** button. Then check whether a remote has already been configured:

```bash
git remote -v
```

If there is no `origin`, add it:

```bash
git remote add origin https://github.com/YOUR-USERNAME/subdomain-typosquatting-detector.git
```

If `origin` already exists but points to the wrong URL, update it instead:

```bash
git remote set-url origin https://github.com/YOUR-USERNAME/subdomain-typosquatting-detector.git
```

Replace the example URL with the exact URL for your own repository. GitHub does not accept your account password for Git pushes over HTTPS. Sign in using GitHub CLI (`gh auth login`), SSH, or another supported authentication method; never save an access token in this README or in your source code.

Once the URL and authentication are correct, push the branch:

```bash
git push -u origin main
```

### Updating the project later

After changing a file, run the tests and check the changes before committing:

```bash
source .venv/bin/activate
pytest -q
git status --short
```

If you only changed this README, you can commit just that file:

```bash
git add README.md
git commit -m "Make README clearer"
git push
```

If you changed application code or tests too, stage those files as well. I avoid using `git add .` without checking `git status` first, because it can include files I didn't mean to publish.

## Before showing this in a portfolio

The project is still an MVP, so I want the repository to show both what works and what still needs work. Before presenting it as a finished project, I plan to:

- Add screenshots using fictional demo data.
- Include a simple architecture diagram and an example CSV export.
- Keep the test results and known limitations up to date.
- Explain how to reproduce the evaluation and where the test data came from.
- Add a release tag once a version is stable, for example: `git tag v0.1.0 && git push origin v0.1.0`.

I won't describe it as a complete phishing-detection system while content analysis, reputation sources, and a proper evaluation are still missing.

## References

- [crt.sh JSON query examples](https://learn.secbyte.org/tools/ct-lookup-api) — useful for trying CT lookups; results are candidates, not proof of abuse.
- [FastAPI form data](https://fastapi.tiangolo.com/tutorial/request-forms/) — documentation for the form handling used by the dashboard.
- [FastAPI SQL database tutorial](https://fastapi.tiangolo.com/tutorial/sql-databases/) — background reading for database-backed FastAPI applications.
- [GitHub Docs: adding locally hosted code to GitHub](https://docs.github.com/en/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github?platform=linux) — instructions for pushing an existing project.
