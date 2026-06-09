"""
Threat-intelligence enrichment.

For every distinct source IP found in the alert set, look up context:
geolocation, ASN and reputation. The result is attached to each alert as an
``IPIntel`` object, and an alert pointing at a known-malicious IP gets its
severity escalated.

Results are cached per IP so the same address is never looked up twice in a run.
"""

from __future__ import annotations

import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional, Protocol

from ids.event import Alert, IPIntel

# Reputation -> how far to bump severity when an alert's IP matches.
_SEVERITY_LADDER = ["low", "medium", "high", "critical"]


def _escalate(severity: str, steps: int) -> str:
    try:
        idx = _SEVERITY_LADDER.index(severity)
    except ValueError:
        return severity
    return _SEVERITY_LADDER[min(idx + steps, len(_SEVERITY_LADDER) - 1)]


def _is_private(ip: str) -> bool:
    """
    True only for genuinely internal (RFC 1918 / loopback / link-local) IPs.

    Note: Python's ``is_private`` also flags the documentation ranges
    (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) as private. Those are the
    ranges used in examples and sample data, so we exclude them here and treat
    them as routable for intel-lookup purposes.
    """

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    doc_ranges = (
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    )
    if any(addr in net for net in doc_ranges):
        return False
    return addr.is_private


class IntelProvider(Protocol):
    """A source of threat intelligence for an IP address"""

    def lookup(self, ip: str) -> IPIntel:  # pragma: no cover - interface
        ...


class LocalFeedProvider:
    """
    Offline provider backed by a JSON reputation feed.

    Feed format (see intel_feed.json):
        {
          "203.0.113.5": {
            "country": "RU", "asn": "AS12345",
            "reputation": "malicious", "abuse_score": 95,
            "categories": ["ssh-bruteforce", "scanner"]
          }
        }
    """

    def __init__(self, feed_path: Optional[str] = None):
        self.feed: dict[str, dict] = {}
        if feed_path and os.path.exists(feed_path):
            with open(feed_path, "r", encoding="utf-8") as fh:
                self.feed = json.load(fh)

    def lookup(self, ip: str) -> IPIntel:
        if _is_private(ip):
            return IPIntel(ip=ip, is_private=True, reputation="clean",
                           source="local")
        entry = self.feed.get(ip)
        if not entry:
            return IPIntel(ip=ip, reputation="unknown", source="local")
        return IPIntel(
            ip=ip,
            country=entry.get("country"),
            asn=entry.get("asn"),
            reputation=entry.get("reputation", "unknown"),
            abuse_score=entry.get("abuse_score"),
            categories=entry.get("categories", []),
            source="local",
        )


class AbuseIPDBProvider:
    """
    Live provider querying the AbuseIPDB v2 API.

    Requires an API key (passed in or via the ABUSEIPDB_KEY env var). Falls
    back gracefully to an 'unknown' verdict on any network or quota error so a
    transient failure never crashes the pipeline.
    """

    ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: Optional[str] = None, timeout: float = 5.0):
        self.api_key = api_key or os.environ.get("ABUSEIPDB_KEY")
        self.timeout = timeout

    def lookup(self, ip: str) -> IPIntel:  # pragma: no cover - needs network
        if _is_private(ip):
            return IPIntel(ip=ip, is_private=True, reputation="clean",
                           source="abuseipdb")
        if not self.api_key:
            return IPIntel(ip=ip, reputation="unknown", source="abuseipdb")
        try:
            qs = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
            req = urllib.request.Request(
                f"{self.ENDPOINT}?{qs}",
                headers={"Key": self.api_key, "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.load(resp)["data"]
        except (urllib.error.URLError, KeyError, ValueError, TimeoutError):
            return IPIntel(ip=ip, reputation="unknown", source="abuseipdb")

        score = payload.get("abuseConfidenceScore", 0)
        reputation = (
            "malicious" if score >= 50 else
            "suspicious" if score >= 10 else "clean"
        )
        return IPIntel(
            ip=ip,
            country=payload.get("countryCode"),
            asn=f"AS{payload['asn']}" if payload.get("asn") else None,
            reputation=reputation,
            abuse_score=score,
            categories=[str(c) for c in payload.get("reports", [])][:5],
            source="abuseipdb",
        )


class Enricher:
    """Enriches alerts with IP intelligence and escalates severity."""

    def __init__(self, provider: IntelProvider):
        self.provider = provider
        self._cache: dict[str, IPIntel] = {}

    def _lookup_cached(self, ip: str) -> IPIntel:
        if ip not in self._cache:
            self._cache[ip] = self.provider.lookup(ip)
        return self._cache[ip]

    def enrich(self, alerts: list[Alert]) -> list[Alert]:
        for alert in alerts:
            if not alert.src_ip:
                continue
            intel = self._lookup_cached(alert.src_ip)
            alert.intel = intel
            # A malicious IP escalates the alert two rungs; suspicious, one.
            if intel.reputation == "malicious":
                alert.severity = _escalate(alert.severity, 2)
            elif intel.reputation == "suspicious":
                alert.severity = _escalate(alert.severity, 1)
        return alerts
