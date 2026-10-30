"""Hostname normalization and Public Suffix List-aware domain extraction."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

try:
    import tldextract
except ImportError:  # Allows offline use; install requirements for bundled PSL support.
    tldextract = None

# Use tldextract's bundled PSL snapshot; never download a list at runtime.
_EXTRACT = (
    tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
    if tldextract is not None
    else None
)

# Conservative fallback only. This is not a full Public Suffix List.
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
    """Normalize a hostname or pasted HTTP(S) URL to a validated ASCII hostname.

    This function only validates/canonicalizes a name. It does not establish
    ownership, reachability, trust, or maliciousness. IP literals are rejected
    because this application investigates hostnames rather than arbitrary IPs.
    """
    raw = (value or "").strip()
    if not raw:
        raise ValueError("Enter a hostname, for example login.example.org.")

    if "://" in raw:
        try:
            parsed = urlsplit(raw)
        except ValueError as exc:
            raise ValueError("Enter a valid hostname or HTTP(S) URL.") from exc
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Only HTTP or HTTPS URLs can be converted to hostnames.")
        if parsed.username or parsed.password:
            raise ValueError("URLs containing usernames or passwords are not accepted.")
        try:
            # Access .port to force urlsplit to validate malformed port values.
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("Enter a valid hostname or numeric port.") from exc
        raw = parsed.hostname or ""
    else:
        raw = raw.split("/", 1)[0]
        # A bare hostname may include a port, but only a numeric, valid one.
        if raw.count(":") == 1:
            host_part, port_part = raw.rsplit(":", 1)
            if not port_part.isdigit() or not 1 <= int(port_part) <= 65535:
                raise ValueError("If you include a port, it must be a number between 1 and 65535.")
            raw = host_part

    raw = raw.strip().rstrip(".").lower()
    if raw.startswith("*."):
        raw = raw[2:]
    if not raw or len(raw) > 253 or "." not in raw:
        raise ValueError("Enter a fully-qualified hostname containing at least one dot.")

    try:
        ascii_host = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("The hostname could not be normalized using IDNA.") from exc

    try:
        ipaddress.ip_address(ascii_host)
    except ValueError:
        pass
    else:
        raise ValueError("Enter a hostname, not an IP address.")

    labels = ascii_host.split(".")
    if any(not _LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError(
            "Hostname labels may contain letters, digits, and hyphens only; "
            "labels cannot start or end with a hyphen."
        )
    return ascii_host


def registrable_domain(hostname: str) -> str:
    """Return the PSL-aware registrable domain, including known private suffixes."""
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
    """True when hostname equals a domain or is a subdomain on a label boundary."""
    host = hostname.rstrip(".").lower()
    root = domain.rstrip(".").lower()
    return host == root or host.endswith("." + root)
