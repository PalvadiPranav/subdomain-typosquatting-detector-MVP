"""Explainable baseline scoring. This is a triage score, not a probability."""
from __future__ import annotations

import difflib
import re
from typing import Iterable

from .normalization import is_under_domain, registrable_domain

LURE_KEYWORDS = {
    "login", "log-in", "signin", "sign-in", "account", "verify", "verification",
    "secure", "support", "password", "billing", "auth", "wallet", "update",
    "confirm", "recover", "webmail", "sso", "office", "payment",
}

# Context only: the presence of one of these hosting suffixes is not proof of abuse.
SHARED_HOSTING_SUFFIXES = {
    "github.io", "pages.dev", "netlify.app", "vercel.app", "web.app",
    "firebaseapp.com", "wixsite.com", "wordpress.com", "blogspot.com",
    "weebly.com", "azurewebsites.net",
}


def _brand_tokens(brand_name: str, official_domains: Iterable[str]) -> list[str]:
    tokens = set()
    for token in re.split(r"[^a-z0-9]+", (brand_name or "").lower()):
        if len(token) >= 3:
            tokens.add(token)
    for domain in official_domains:
        root = registrable_domain(domain)
        # registrable_domain includes suffix; take the label immediately before it.
        ext_domain = root.split(".")[0]
        if len(ext_domain) >= 3:
            tokens.add(ext_domain.lower())
    return sorted(tokens, key=len, reverse=True)


def score_hostname(
    hostname: str,
    brand_name: str,
    official_domains: Iterable[str],
    custom_keywords: Iterable[str] = (),
    source: str = "manual",
) -> dict:
    """Return score, tier, and auditable signal breakdown for a candidate hostname."""
    hostname = hostname.lower().rstrip(".")
    official_domains = [d.lower().rstrip(".") for d in official_domains]
    tokens = _brand_tokens(brand_name, official_domains)
    labels = hostname.split(".")
    label_tokens = [t for label in labels for t in re.split(r"[^a-z0-9]+", label) if t]

    signals: list[dict] = []

    # Name similarity: maximum 30 points. Use labels and hyphen-delimited parts.
    name_score = 0
    name_reason = "No strong brand-name match found in hostname labels."
    best_token = None
    best_label = None
    for brand_token in tokens:
        for label in labels[:-1] if len(labels) > 1 else labels:
            parts = [p for p in re.split(r"[^a-z0-9]+", label) if p]
            exact_part = brand_token in parts
            substring = brand_token in label
            ratio = difflib.SequenceMatcher(None, brand_token, label).ratio()
            if exact_part:
                candidate_score = 30
            elif substring:
                candidate_score = 27
            elif ratio >= 0.60:
                candidate_score = round(30 * ratio)
            else:
                candidate_score = 0
            if candidate_score > name_score:
                name_score = candidate_score
                best_token, best_label = brand_token, label
    if name_score:
        name_reason = f"Brand token '{best_token}' resembles or appears in hostname label '{best_label}'."
    signals.append({"name": "Brand-name similarity", "points": name_score, "reason": name_reason})

    # Lure words: maximum 15 points. Tokenization avoids matching 'login' inside arbitrary prose.
    all_keywords = {k.lower().strip() for k in LURE_KEYWORDS}
    all_keywords.update(k.lower().strip() for k in custom_keywords if k.strip())
    observed_keywords = sorted(k for k in all_keywords if k in hostname)
    keyword_score = min(15, 10 * len(observed_keywords))
    signals.append({
        "name": "Login/lure keywords",
        "points": keyword_score,
        "reason": ("Matched: " + ", ".join(observed_keywords[:5]) + ("…" if len(observed_keywords) > 5 else ".")) if observed_keywords else "No configured login/lure keyword matched.",
    })

    host_is_official = any(is_under_domain(hostname, domain) for domain in official_domains)
    negative = -30 if host_is_official else 0
    signals.append({
        "name": "Official-domain evidence",
        "points": negative,
        "reason": "Hostname is at or beneath a configured official domain; verify the seed configuration." if host_is_official else "Hostname is not beneath a configured official domain.",
    })

    shared_suffix = next((suffix for suffix in sorted(SHARED_HOSTING_SUFFIXES, key=len, reverse=True)
                          if is_under_domain(hostname, suffix)), None)
    provider_score = 8 if shared_suffix else 0
    signals.append({
        "name": "Shared-hosting context",
        "points": provider_score,
        "reason": f"Hostname is under the configured hosting suffix '{shared_suffix}'. This is context only, not proof of abuse." if shared_suffix else "No configured shared-hosting suffix matched.",
    })

    idn_score = 8 if "xn--" in hostname else 0
    signals.append({
        "name": "IDN/punycode indicator",
        "points": idn_score,
        "reason": "Punycode label present; visually inspect the decoded name." if idn_score else "No punycode label detected.",
    })

    ct_score = 3 if source.lower().startswith("ct:") or source.lower().startswith("certificate transparency") else 0
    signals.append({
        "name": "Discovery source context",
        "points": ct_score,
        "reason": "Candidate was discovered from a Certificate Transparency source; this is discovery evidence, not proof of maliciousness." if ct_score else "Candidate was added manually or from another source.",
    })

    score = max(0, min(100, sum(signal["points"] for signal in signals)))
    if score >= 80:
        tier = "high"
    elif score >= 50:
        tier = "review"
    else:
        tier = "low"
    return {"score": score, "tier": tier, "signals": signals,
            "registered_domain": registrable_domain(hostname),
            "model_note": "Baseline rules-only score; not a calibrated probability. Content and reputation features are not implemented in this MVP."}
