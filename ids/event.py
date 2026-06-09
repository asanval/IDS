"""
Normalized event model shared by all parsers and detectors.

Every source (auth logs, web logs, pcap) is converted into a common Event
so detection logic does not care where the data came from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class Event:
    """A single normalized observation from a log line or network packet."""

    timestamp: datetime
    source: str                       # "auth", "web", "network"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None     # "tcp", "udp", "http", "ssh"
    action: Optional[str] = None       # "login_failed", "login_ok", "request"
    user: Optional[str] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_status: Optional[int] = None
    bytes: int = 0
    raw: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        """Uniform field access used by the rule engine."""
        
        if hasattr(self, key):
            return getattr(self, key)
        return self.extra.get(key, default)


@dataclass
class Alert:
    """An alert raised by a detector when a threat pattern matches."""

    timestamp: datetime
    severity: str                      # "low", "medium", "high", "critical"
    category: str                      # e.g. "brute_force", "port_scan"
    title: str
    description: str
    src_ip: Optional[str] = None
    detector: str = ""
    evidence: list[str] = field(default_factory=list)
    mitre: Optional[str] = None        # MITRE ATT&CK technique id, e.g. "T1110"
    # Threat-intelligence context attached by the enrichment stage.
    intel: Optional["IPIntel"] = None
    # Correlation metadata, set when this alert is part of an attack chain.
    correlation_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        data = {
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "src_ip": self.src_ip,
            "detector": self.detector,
            "evidence": self.evidence,
        }
        if self.mitre:
            data["mitre"] = self.mitre
        if self.intel:
            data["intel"] = self.intel.to_dict()
        if self.correlation_id:
            data["correlation_id"] = self.correlation_id
        return data


@dataclass
class IPIntel:
    """Threat-intelligence context for a single IP address."""

    ip: str
    is_private: bool = False
    country: Optional[str] = None
    asn: Optional[str] = None
    reputation: str = "unknown"        # "clean", "suspicious", "malicious"
    abuse_score: Optional[int] = None  # 0-100, higher is worse
    categories: list[str] = field(default_factory=list)
    source: str = ""                   # which feed produced this

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "is_private": self.is_private,
            "country": self.country,
            "asn": self.asn,
            "reputation": self.reputation,
            "abuse_score": self.abuse_score,
            "categories": self.categories,
            "source": self.source,
        }
