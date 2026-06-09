"""
Correlation engine.

A correlation rule fires when an ordered sequence of alert categories is seen
from the same source IP within a time window. The result is a new, higher-
severity ``Alert`` that references the IDs of its constituent alerts, mapped to
a MITRE ATT&CK technique where applicable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Optional

from ids.event import Alert


@dataclass
class CorrelationRule:
    name: str
    sequence: list[str]
    severity: str
    description: str
    window_seconds: int = 600
    mitre: Optional[str] = None
    require_order: bool = True


# Default attack-chain rules. Each models a recognizable intrusion pattern.
DEFAULT_RULES: list[CorrelationRule] = [
    CorrelationRule(
        name="Probable host compromise via SSH",
        sequence=["brute_force", "auth_success"],
        severity="critical",
        description=(
            "An SSH brute-force burst was followed by a successful login from "
            "the same source, indicating a likely account compromise."
        ),
        window_seconds=600,
        mitre="T1110",  # Brute Force
    ),
    CorrelationRule(
        name="Recon followed by targeted access",
        sequence=["port_scan", "recon"],
        severity="high",
        description=(
            "A port scan was followed by connections to high-risk service "
            "ports from the same source: reconnaissance turning into access "
            "attempts."
        ),
        window_seconds=600,
        mitre="T1046",  # Network Service Discovery
    ),
    CorrelationRule(
        name="Web enumeration escalating to exploitation",
        sequence=["enumeration", "web_attack"],
        severity="high",
        description=(
            "Web path/enumeration activity was followed by an exploitation "
            "attempt (SQLi or path traversal) from the same source."
        ),
        window_seconds=600,
        mitre="T1190",  # Exploit Public-Facing Application
    ),
]


@dataclass
class _Group:
    """All alerts from one source IP, kept sorted by time"""

    alerts: list[Alert] = field(default_factory=list)


class CorrelationEngine:
    def __init__(self, rules: Optional[list[CorrelationRule]] = None):
        self.rules = rules if rules is not None else DEFAULT_RULES

    def correlate(self, alerts: list[Alert]) -> list[Alert]:
        """
        Return new correlation alerts derived from the input alerts.

        Does not modify the input list; the caller decides how to merge.
        """

        # Group by source IP.
        groups: dict[str, _Group] = {}
        for a in alerts:
            if not a.src_ip:
                continue
            groups.setdefault(a.src_ip, _Group()).alerts.append(a)

        # For same source IP, checks for a chain rule
        derived: list[Alert] = []
        for ip, group in groups.items():
            ordered = sorted(group.alerts, key=lambda a: a.timestamp)
            for rule in self.rules:
                match = self._match_sequence(ordered, rule)
                if match:
                    derived.append(self._build_alert(ip, rule, match))
        return derived

    @staticmethod
    def _match_sequence(ordered: list[Alert], rule: CorrelationRule):
        """
        Find alerts satisfying the rule's category sequence and window.

        Returns the list of matching alerts, or None.
        """
        window = timedelta(seconds=rule.window_seconds)

        if rule.require_order:
            # Each next category must appear at or after the previous
            # match, within the window from the first match.
            idx = 0
            anchor_ts = None
            collected: list[Alert] = []
            for alert in ordered:
                if alert.category == rule.sequence[idx]:
                    if anchor_ts is None:
                        anchor_ts = alert.timestamp
                    if alert.timestamp - anchor_ts <= window:
                        collected.append(alert)
                        idx += 1
                        if idx == len(rule.sequence):
                            return collected
            return None

        # Every category must appear at least once within a window.
        present = {c: None for c in rule.sequence}
        for alert in ordered:
            if alert.category in present and present[alert.category] is None:
                present[alert.category] = alert
        if all(present.values()):
            times = [a.timestamp for a in present.values()]  # type: ignore
            if max(times) - min(times) <= window:
                return list(present.values())  # type: ignore
        return None

    @staticmethod
    def _build_alert(ip: str, rule: CorrelationRule, members: list[Alert]) -> Alert:
        cid = f"corr-{ip}-{rule.sequence[0]}"
        evidence = [
            f"chain: {' -> '.join(rule.sequence)}",
            f"{len(members)} correlated alerts from {ip}",
        ]
        for m in members:
            m.correlation_id = cid
            evidence.append(f"  - [{m.severity}] {m.title} @ {m.timestamp.isoformat()}")
        return Alert(
            timestamp=members[-1].timestamp,
            severity=rule.severity,
            category="correlation",
            title=rule.name,
            description=rule.description,
            src_ip=ip,
            detector="correlation",
            evidence=evidence,
            mitre=rule.mitre,
            correlation_id=cid,
        )
