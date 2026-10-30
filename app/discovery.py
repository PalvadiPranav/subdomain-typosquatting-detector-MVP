"""Passive Certificate Transparency discovery adapter (crt.sh JSON endpoint)."""
from __future__ import annotations

import json
import re
from typing import Iterable

try:
    import httpx2 as httpx  # Preferred client for current Starlette/FastAPI environments.
except ImportError:  # Keep discovery usable in older/offline environments.
    import httpx

from .normalization import is_under_domain, normalize_hostname, registrable_domain

CRT_SH_URL = "https://crt.sh/"
USER_AGENT = "SubdomainTyposquattingDetector/1.0.0 (student defensive research; low-volume query)"


def _tokens(brand_name: str, official_domains: Iterable[str]) -> list[str]:
    # Prefer official-domain labels; display names can contain generic words like "Group" or "Demo".
    domain_tokens = []
    for domain in official_domains:
        root = registrable_domain(domain)
        part = root.split(".")[0].lower()
        if len(part) >= 3:
            domain_tokens.append(part)
    if domain_tokens:
        return list(dict.fromkeys(domain_tokens))[:3]
    name_tokens = []
    for item in re.split(r"[^a-z0-9]+", (brand_name or "").lower()):
        if len(item) >= 3:
            name_tokens.append(item)
    return list(dict.fromkeys(name_tokens))[:3]


def _looks_related(host: str, tokens: list[str]) -> bool:
    # Keep first-pass result set relevant. Fuzzy near-miss detection for arbitrary domains
    # requires a broader discovery source or a separate carefully budgeted permutation stage.
    labels = re.split(r"[^a-z0-9]+", host)
    return any(token in host or any(token == label for label in labels) for token in tokens)


def discover_ct_candidates(brand_name: str, official_domains: list[str], max_candidates: int = 100) -> dict:
    """Search crt.sh for a few brand tokens and return candidate hostnames and status text.

    This queries public CT metadata only. It does not connect to discovered sites.
    """
    tokens = _tokens(brand_name, official_domains)
    if not tokens:
        return {"candidates": [], "queries": 0, "message": "No usable brand token found; use a name or official domain with at least three characters."}

    found: set[str] = set()
    failures: list[str] = []
    queries = 0
    with httpx.Client(timeout=httpx.Timeout(12.0, connect=5.0), follow_redirects=False,
                       headers={"User-Agent": USER_AGENT}) as client:
        for token in tokens:
            queries += 1
            try:
                # Stream the body and stop as soon as the hard size limit is crossed,
                # rather than downloading an unbounded response and checking afterward.
                body_chunks: list[bytes] = []
                total_bytes = 0
                oversized = False
                with client.stream("GET", CRT_SH_URL, params={"q": f"%{token}%", "output": "json"}) as response:
                    response.raise_for_status()
                    for chunk in response.iter_bytes(chunk_size=65_536):
                        total_bytes += len(chunk)
                        if total_bytes > 8_000_000:
                            oversized = True
                            break
                        body_chunks.append(chunk)
                if oversized:
                    failures.append(f"Query '{token}' returned an oversized response; skipped.")
                    continue
                records = json.loads(b"".join(body_chunks))
                if not isinstance(records, list):
                    failures.append(f"Query '{token}' did not return the expected JSON array.")
                    continue
                # Certificate records frequently repeat names; cap the amount processed per query.
                for record in records[:2500]:
                    raw_names = str(record.get("name_value") or record.get("common_name") or "")
                    for raw in raw_names.splitlines():
                        raw = raw.strip()
                        if not raw:
                            continue
                        try:
                            host = normalize_hostname(raw)
                        except ValueError:
                            continue
                        if any(is_under_domain(host, domain) for domain in official_domains):
                            continue
                        if _looks_related(host, [token]):
                            found.add(host)
                        if len(found) >= max_candidates:
                            break
                    if len(found) >= max_candidates:
                        break
                if len(found) >= max_candidates:
                    break
            except (httpx.HTTPError, ValueError) as exc:
                failures.append(f"Query '{token}' failed: {type(exc).__name__}.")

    result = sorted(found)[:max_candidates]
    if failures and result:
        message = f"Found {len(result)} candidate(s); some CT queries failed. " + " ".join(failures[:2])
    elif failures:
        message = "No candidates returned. " + " ".join(failures[:3])
    else:
        message = f"CT lookup completed: {len(result)} candidate hostname(s) retained from {queries} query/queries. Review all results; CT presence is not evidence of phishing by itself."
    return {"candidates": result, "queries": queries, "message": message}
