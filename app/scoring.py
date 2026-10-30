"""Explainable hostname triage scoring; this is not a calibrated probability."""
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

# Initial, deliberately transparent thresholds. Validate these against labelled data
# before interpreting any score as predictive performance.
REVIEW_THRESHOLD = 35
HIGH_THRESHOLD = 65


def _brand_tokens(brand_name: str, official_domains: Iterable[str]) -> list[str]:
    tokens: set[str] = set()
    for token in re.split(r"[^a-z0-9]+", (brand_name or "").lower()):
        if len(token) >= 3:
            tokens.add(token)
    for domain in official_domains:
        root = registrable_domain(domain)
        label = root.split(".")[0]
        if len(label) >= 3:
            tokens.add(label.lower())
    return sorted(tokens, key=len, reverse=True)


def _parts(value: str) -> list[str]:
    return [part for part in re.split(r"[^a-z0-9]+", value.lower()) if part]


def _matched_keywords(hostname: str, custom_keywords: Iterable[str]) -> list[str]:
    # Compare whole normalized tokens/sequences, not arbitrary substrings such as
    # "login" inside "blogging". A multiword keyword may span hyphen/dot boundaries.
    host_parts = _parts(hostname.replace(".", "-"))
    matches: list[str] = []
    keywords = {k.lower().strip() for k in LURE_KEYWORDS}
    keywords.update(k.lower().strip() for k in custom_keywords if k and k.strip())
    for keyword in sorted(keywords):
        key_parts = _parts(keyword)
        if not key_parts:
            continue
        width = len(key_parts)
        if any(host_parts[index:index + width] == key_parts
               for index in range(len(host_parts) - width + 1)):
            matches.append(keyword)
    return matches


def score_hostname(
    hostname: str,
    brand_name: str,
    official_domains: Iterable[str],
    custom_keywords: Iterable[str] = (),
    source: str = "manual",
) -> dict:
    """Return a bounded 0–100 risk-priority score and an auditable signal breakdown.

    Thresholds are heuristic triage bands, not measured probabilities. DNS/TLS,
    page-content, reputation, and analyst-history signals are intentionally not
    included in this baseline model.
    """
    hostname = hostname.lower().rstrip(".")
    official_domains = [d.lower().rstrip(".") for d in official_domains]
    tokens = _brand_tokens(brand_name, official_domains)
    labels = hostname.split(".")
    label_parts = [(label, _parts(label)) for label in labels[:-1] if label]

    signals: list[dict] = []

    # Brand-name evidence: exact token or substring matches are strongest. Compare
    # hyphen-separated hostname pieces individually so a near miss such as
    # "netfl1x-login" can be detected without requiring the full label to match.
    name_score = 0
    name_reason = "No strong brand-name match found in hostname labels."
    best_token = best_label = best_piece = None
    best_kind = ""
    best_ratio = 0.0
    for brand_token in tokens:
        for label, parts in label_parts or [(labels[0], _parts(labels[0]))]:
            candidate_score = 0
            kind = ""
            matched_piece = label
            label_ratio = 0.0
            if brand_token in parts:
                candidate_score, kind, matched_piece = 30, "exact token", brand_token
            elif brand_token in label:
                candidate_score, kind, matched_piece = 27, "substring", label
            else:
                comparisons = [
                    (difflib.SequenceMatcher(None, brand_token, part).ratio(), part)
                    for part in parts if abs(len(brand_token) - len(part)) <= 2
                ]
                if comparisons:
                    label_ratio, matched_piece = max(comparisons, key=lambda item: item[0])
                if label_ratio >= 0.72:
                    candidate_score, kind = round(30 * label_ratio), "approximate spelling"
            if candidate_score > name_score:
                name_score = candidate_score
                best_token, best_label, best_piece, best_kind = brand_token, label, matched_piece, kind
                best_ratio = label_ratio
    if name_score:
        if best_kind == "approximate spelling":
            name_reason = (
                f"Hostname piece '{best_piece}' in label '{best_label}' is a near spelling of brand token "
                f"'{best_token}' (string similarity {best_ratio:.2f}); inspect manually."
            )
        else:
            name_reason = f"Brand token '{best_token}' {best_kind} appears in hostname label '{best_label}'."
    signals.append({"name": "Brand-name similarity", "points": name_score, "reason": name_reason})

    matched_keywords = _matched_keywords(hostname, custom_keywords)
    keyword_score = min(15, 10 + 5 * (len(matched_keywords) - 1)) if matched_keywords else 0
    signals.append({
        "name": "Login/lure keywords",
        "points": keyword_score,
        "reason": ("Matched: " + ", ".join(matched_keywords[:5]) + ("…" if len(matched_keywords) > 5 else "."))
                  if matched_keywords else "No configured login/lure keyword matched as a whole token or phrase.",
    })

    host_is_official = any(is_under_domain(hostname, domain) for domain in official_domains)
    negative = -30 if host_is_official else 0
    signals.append({
        "name": "Official-domain evidence",
        "points": negative,
        "reason": "Hostname is at or beneath a configured official domain; verify the seed configuration."
                  if host_is_official else "Hostname is not beneath a configured official domain.",
    })

    # Specific to this project's subdomain-abuse goal: brand text in a left-hand
    # subdomain while the registrable domain is a different, non-official namespace.
    root = registrable_domain(hostname)
    external_subdomain = hostname[:-len(root) - 1] if hostname.endswith("." + root) else ""
    brand_in_external_subdomain = bool(external_subdomain) and not host_is_official and any(
        token in _parts(external_subdomain) or token in external_subdomain for token in tokens
    )
    subdomain_score = 12 if brand_in_external_subdomain else 0
    signals.append({
        "name": "Brand in third-party subdomain",
        "points": subdomain_score,
        "reason": (f"Brand-related text appears in a subdomain above the unrelated registrable domain '{root}'. "
                   "This matches the hosting pattern being investigated, but is not proof of abuse.")
                  if subdomain_score else "No brand-bearing subdomain above an unrelated registrable domain was identified.",
    })

    shared_suffix = next((suffix for suffix in sorted(SHARED_HOSTING_SUFFIXES, key=len, reverse=True)
                          if is_under_domain(hostname, suffix)), None)
    provider_score = 8 if shared_suffix else 0
    signals.append({
        "name": "Shared-hosting context",
        "points": provider_score,
        "reason": f"Hostname is under configured hosting suffix '{shared_suffix}'. This is context only, not proof of abuse."
                  if shared_suffix else "No configured shared-hosting suffix matched.",
    })

    idn_score = 8 if any(label.startswith("xn--") for label in labels) else 0
    signals.append({
        "name": "IDN/punycode indicator",
        "points": idn_score,
        "reason": "An IDN punycode label is present; visually inspect the decoded name."
                  if idn_score else "No punycode label detected.",
    })

    ct_score = 3 if source.lower().startswith("ct:") or source.lower().startswith("certificate transparency") else 0
    signals.append({
        "name": "Discovery source context",
        "points": ct_score,
        "reason": "Candidate was discovered from a Certificate Transparency source; this is discovery evidence, not proof of maliciousness."
                  if ct_score else "Candidate was added manually or from another source.",
    })

    score = max(0, min(100, sum(signal["points"] for signal in signals)))
    if score >= HIGH_THRESHOLD:
        tier = "high"
    elif score >= REVIEW_THRESHOLD:
        tier = "review"
    else:
        tier = "low"
    return {
        "score": score,
        "tier": tier,
        "signals": signals,
        "registered_domain": root,
        "model_note": (
            "Rules-based triage priority, not a calibrated probability. Initial thresholds are heuristic. "
            "DNS/TLS, page-content, reputation, and labelled-history features do not yet affect the score."
        ),
    }
