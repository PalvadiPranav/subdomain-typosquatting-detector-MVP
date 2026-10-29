"""DNS and TLS enrichment for candidate hostnames.

DNS data is obtained from the machine's configured recursive resolver. TLS details
come from a short, direct TLS handshake to a public IP on port 443. This is not a
passive-DNS history service and does not fetch web pages.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import ipaddress
import socket
import ssl
from typing import Any

import dns.exception
import dns.resolver

from .normalization import normalize_hostname

DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA")
DNS_TIMEOUT_SECONDS = 1.8
TLS_TIMEOUT_SECONDS = 3.5
MAX_DNS_VALUES = 12
MAX_VALUE_LENGTH = 700
MAX_TLS_IPS = 3


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _query_dns_type(hostname: str, record_type: str) -> dict[str, Any]:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = DNS_TIMEOUT_SECONDS
    observed_at = utc_now()
    common: dict[str, Any] = {
        "type": record_type,
        "observed_at": observed_at,
        "source": "System-configured recursive DNS resolver via dnspython",
        "resolver_nameservers": [str(ns) for ns in resolver.nameservers],
        "status": "unknown",
        "values": [],
        "ttl_seconds": None,
        "detail": "",
    }
    try:
        answer = resolver.resolve(hostname, record_type, lifetime=DNS_TIMEOUT_SECONDS, search=False)
        values = [record.to_text()[:MAX_VALUE_LENGTH] for record in list(answer)[:MAX_DNS_VALUES]]
        common.update({
            "status": "answer" if values else "no_answer",
            "values": values,
            "ttl_seconds": int(answer.rrset.ttl) if answer.rrset is not None else None,
            "detail": f"Returned {len(values)} value(s)" if values else "No values returned",
        })
    except dns.resolver.NXDOMAIN:
        common.update(status="nxdomain", detail="Name does not exist according to this resolver")
    except dns.resolver.NoAnswer:
        common.update(status="no_answer", detail="No record of this type was returned")
    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
        common.update(status="timeout", detail="Resolver timed out")
    except dns.resolver.NoNameservers:
        common.update(status="resolver_error", detail="No configured nameserver returned a usable response")
    except Exception as exc:  # Keep one record's error from stopping the whole run.
        common.update(status="error", detail=type(exc).__name__)
    return common


def collect_dns_records(hostname: str) -> dict[str, Any]:
    """Query a bounded set of public DNS record types and return timestamped evidence."""
    host = normalize_hostname(hostname)
    records: dict[str, dict[str, Any]] = {}
    # Each worker owns a separate resolver. This keeps the UI reasonably responsive
    # while every individual lookup still has a strict timeout.
    with ThreadPoolExecutor(max_workers=len(DNS_RECORD_TYPES)) as pool:
        futures = {pool.submit(_query_dns_type, host, record_type): record_type for record_type in DNS_RECORD_TYPES}
        for future in as_completed(futures):
            record_type = futures[future]
            try:
                records[record_type] = future.result()
            except Exception as exc:  # Defensive boundary around a provider/library error.
                records[record_type] = {
                    "type": record_type,
                    "observed_at": utc_now(),
                    "source": "System-configured recursive DNS resolver via dnspython",
                    "resolver_nameservers": [],
                    "status": "error",
                    "values": [],
                    "ttl_seconds": None,
                    "detail": type(exc).__name__,
                }
    ordered = [records[record_type] for record_type in DNS_RECORD_TYPES]
    return {
        "hostname": host,
        "observed_at": utc_now(),
        "source": "System-configured recursive DNS resolver via dnspython",
        "record_types_queried": list(DNS_RECORD_TYPES),
        "records": ordered,
    }


def _public_ip_addresses(dns_result: dict[str, Any]) -> list[str]:
    addresses: list[str] = []
    for record in dns_result.get("records", []):
        if record.get("type") not in {"A", "AAAA"} or record.get("status") != "answer":
            continue
        for value in record.get("values", []):
            # A/AAAA RDATA should be a bare IP, but parse defensively.
            try:
                ip = ipaddress.ip_address(str(value).strip())
            except ValueError:
                continue
            if ip.is_global and str(ip) not in addresses:
                addresses.append(str(ip))
    return addresses[:MAX_TLS_IPS]


def _flatten_name(name_parts: Any) -> str:
    chunks: list[str] = []
    for relative_name in name_parts or ():
        for key, value in relative_name:
            chunks.append(f"{key}={value}")
    return ", ".join(chunks)


def _cert_timestamp(value: str | None) -> str | None:
    if not value:
        return None
    try:
        seconds = ssl.cert_time_to_seconds(value)
        return datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=0).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def _certificate_fields(sock: ssl.SSLSocket, hostname: str, ip: str) -> dict[str, Any]:
    cert = sock.getpeercert()
    der = sock.getpeercert(binary_form=True)
    not_before = _cert_timestamp(cert.get("notBefore"))
    not_after = _cert_timestamp(cert.get("notAfter"))
    san = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"][:50]
    expiry_days = None
    if not_after:
        expiry_dt = datetime.fromisoformat(not_after)
        expiry_days = int((expiry_dt - datetime.now(timezone.utc)).total_seconds() // 86400)
    cipher = sock.cipher()
    return {
        "status": "ok",
        "observed_at": utc_now(),
        "source": "Direct TLS handshake to the resolved public IP on port 443; certificate chain and hostname verified by Python's default CA store",
        "hostname": hostname,
        "port": 443,
        "connected_ip": ip,
        "tls_version": sock.version(),
        "cipher": cipher[0] if cipher else None,
        "certificate": {
            "subject": _flatten_name(cert.get("subject")),
            "issuer": _flatten_name(cert.get("issuer")),
            "serial_number": cert.get("serialNumber"),
            "not_before_utc": not_before,
            "not_after_utc": not_after,
            "days_until_expiry": expiry_days,
            "subject_alt_names": san,
            "sha256_fingerprint": hashlib.sha256(der).hexdigest().upper(),
            "hostname_verified": True,
            "chain_verified": True,
        },
        "detail": "TLS handshake succeeded and the certificate validated",
    }


def collect_tls_metadata(hostname: str, dns_result: dict[str, Any]) -> dict[str, Any]:
    """Inspect certificate metadata from a bounded verified TLS handshake.

    The service never sends HTTP requests. It only connects to public IPs returned
    by the DNS collection step, checks a maximum of three addresses, and verifies
    the certificate chain and hostname using the system trust store.
    """
    host = normalize_hostname(hostname)
    base: dict[str, Any] = {
        "hostname": host,
        "port": 443,
        "observed_at": utc_now(),
        "source": "Direct TLS handshake using the system CA trust store",
        "status": "not_attempted",
        "connected_ip": None,
        "tls_version": None,
        "cipher": None,
        "certificate": None,
        "detail": "",
    }
    ips = _public_ip_addresses(dns_result)
    if not ips:
        base["detail"] = "Skipped: no public A/AAAA address was collected. Private, loopback, link-local, and reserved IP addresses are never contacted."
        return base

    errors: list[str] = []
    context = ssl.create_default_context()
    for ip in ips:
        try:
            with socket.create_connection((ip, 443), timeout=TLS_TIMEOUT_SECONDS) as raw_socket:
                with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                    return _certificate_fields(tls_socket, host, ip)
        except ssl.SSLCertVerificationError:
            # We intentionally do not retry with verification disabled: this MVP only
            # stores certificate details if the chain and hostname validate.
            errors.append("certificate_verification_failed")
        except (OSError, ssl.SSLError, TimeoutError) as exc:
            errors.append(type(exc).__name__)
        except Exception as exc:
            errors.append(type(exc).__name__)

    base["status"] = "failed"
    base["detail"] = "; ".join(dict.fromkeys(errors)) or "TLS handshake failed"
    return base


def enrich_hostname(hostname: str) -> dict[str, Any]:
    host = normalize_hostname(hostname)
    dns_data = collect_dns_records(host)
    tls_data = collect_tls_metadata(host, dns_data)
    return {
        "hostname": host,
        "fetched_at": utc_now(),
        "dns": dns_data,
        "tls": tls_data,
        "source_summary": "DNS: system-configured recursive resolver; TLS: direct verified handshake to a public resolved address",
    }
