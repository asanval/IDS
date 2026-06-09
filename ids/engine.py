""" Engine: glue between parsers, detectors, correlation, enrichment, reporting """

from __future__ import annotations

import json
from typing import Iterable, Optional

from ids.detectors.anomaly import AnomalyDetector
from ids.detectors.correlation import CorrelationEngine
from ids.detectors.rule_engine import RuleEngine
from ids.event import Alert, Event
from ids.intel.enrich import Enricher

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class IDSEngine:
    """Runs detection, then correlation, then enrichment over an event stream.

    Pipeline stages:
      1. Detection   -- rule engine + anomaly detector raise base alerts.
      2. Correlation -- attack chains across base alerts become new alerts.
      3. Enrichment  -- threat-intel context is attached and severities are
                        escalated for malicious/suspicious source IPs.

    Correlation runs before enrichment so chains are built from raw detector
    output; enrichment then escalates both base and correlation alerts.
    """

    def __init__(
        self,
        rule_engine: RuleEngine,
        anomaly: AnomalyDetector,
        correlation: Optional[CorrelationEngine] = None,
        enricher: Optional[Enricher] = None,
    ):
        self.rule_engine = rule_engine
        self.anomaly = anomaly
        self.correlation = correlation
        self.enricher = enricher

    def analyze(self, events: Iterable[Event]) -> list[Alert]:
        alerts: list[Alert] = []

        # Stage 1: detection in a single pass
        for event in events:
            alerts.extend(self.rule_engine.evaluate(event))
            self.anomaly.observe(event)
        alerts.extend(self.anomaly.finalize())

        # Stage 2: correlation across the base alerts
        if self.correlation is not None:
            alerts.extend(self.correlation.correlate(alerts))

        # Suppress informational alerts that did not become part of a chain:
        # a successful login on its own is benign noise, but if correlation
        # tagged it (e.g. it followed a brute-force burst) it is kept as
        # evidence.
        alerts = [
            a for a in alerts
            if a.severity != "info" or a.correlation_id is not None
        ]

        # Stage 3: threat-intel enrichment + severity escalation.
        if self.enricher is not None:
            alerts = self.enricher.enrich(alerts)

        alerts.sort(key=lambda a: (_SEVERITY_ORDER.get(a.severity, 9), a.timestamp))
        return alerts


def _intel_line(a: Alert) -> str:
    if not a.intel or a.intel.is_private:
        return ""
    i = a.intel
    bits = []
    if i.country:
        bits.append(i.country)
    if i.asn:
        bits.append(i.asn)
    bits.append(f"reputation={i.reputation}")
    if i.abuse_score is not None:
        bits.append(f"abuse={i.abuse_score}")
    if i.categories:
        bits.append("tags=" + ",".join(i.categories))
    return "           intel: " + " | ".join(bits) + "\n"


def format_report(alerts: list[Alert]) -> str:
    if not alerts:
        return "No threats detected.\n"
    lines = [f"IDS ALERT REPORT  ({len(alerts)} alert(s))", "=" * 60]
    for a in alerts:
        mitre = f" [ATT&CK {a.mitre}]" if a.mitre else ""
        block = (
            f"[{a.severity.upper():8}] {a.category:16} {a.title}{mitre}\n"
            f"           time={a.timestamp.isoformat()} src={a.src_ip} "
            f"detector={a.detector}\n"
            f"{_intel_line(a)}"
            f"           {a.description}\n"
            f"           evidence: {'; '.join(a.evidence)}"
        )
        lines.append(block)
    return "\n".join(lines) + "\n"


def alerts_to_json(alerts: list[Alert]) -> str:
    return json.dumps([a.to_dict() for a in alerts], indent=2)
