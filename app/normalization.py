"""Hostname normalization and Public Suffix List-aware domain extraction."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

try:
    import tldextract
except ImportError:  # Allows the MVP to run offline; install requirements for full PSL support.
    tldextract = None

# Use the PSL snapshot bundled with tldextract; do not fetch an updated list at runtime.
_EXTRACT = (tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
            if tldextract is not None else None)

# Conservative fallback for offline environments without tldextract. This is not a full PSL.
_FALLBACK_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "edu.au",
    "co.nz", "net.nz", "org.nz", "co.in", "firm.in", "net.in", "org.in", "gen.in",
    "ind.in", "com.sg", "com.my", "com.br", "com.cn", "co.jp", "com.jp", "com.mx",
    "com.tr", "co.za", "com.ar", "com.tw", "com.hk", "github.io", "pages.dev",
    "appspot.com", "blogspot.com", "wordpress.com", "netlify.app", "vercel.app",
    "web.app", "firebaseapp.com", "wixsite.com", "azurewebsites.net",
}
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_hostname(value: str) -> str:
    """Normalize a bare hostname, accepting a pasted URL but rejecting paths/IPs only by format.

    This does not establish ownership or safety. It only canonicalizes the hostname string.
    """
    raw = (value or "").strip()
    if not raw:
        raise ValueError("Enter a hostname, for example login.example.org.")

    if "://" in raw:
        parsed = urlsplit(raw)
        raw = parsed.hostname or ""
    else:
        raw = raw.split("/", 1)[0]
        # Remove an optional port from a hostname entry. IPv6 literals are not supported here.
        if raw.count(":") == 1:
            raw = raw.rsplit(":", 1)[0]

    raw = raw.strip().rstrip(".").lower()
    if raw.startswith("*."):
        raw = raw[2:]
    if not raw or len(raw) > 253 or "." not in raw:
        raise ValueError("Enter a fully-qualified hostname containing at least one dot.")

    try:
        ascii_host = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("The hostname could not be normalized using IDNA.") from exc

    labels = ascii_host.split(".")
    if any(not _LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("Hostname labels may contain letters, digits, and hyphens only; labels cannot start or end with a hyphen.")
    return ascii_host


def registrable_domain(hostname: str) -> str:
    """Return the PSL-aware registrable domain (including private suffix rules when known)."""
    hostname = hostname.rstrip(".").lower()
    if _EXTRACT is not None:
        result = _EXTRACT(hostname)
        return result.top_domain_under_public_suffix or hostname
    labels = hostname.split(".")
    if len(labels) < 2:
        return hostname
    last_two = ".".join(labels[-2:])
    suffix_size = 2 if last_two in _FALLBACK_MULTI_SUFFIXES else 1
    if len(labels) <= suffix_size:
        return hostname
    return ".".join(labels[-(suffix_size + 1):])


def is_under_domain(hostname: str, domain: str) -> bool:
    """True when hostname is exactly domain or is a subdomain of it."""
    host = hostname.rstrip(".").lower()
    root = domain.rstrip(".").lower()
    return host == root or host.endswith("." + root)
