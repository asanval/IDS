"""
Signature/rule-based detector.

Rules are declarative (loaded from YAML).

Two rule types:
  - "match": fires when a single event matches all conditions.
  - "threshold": fires when N matching events from the same key (e.g. src_ip)
    occur within a time window (stateful, for brute force / scanning).

Event -> Alert
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Any, Iterable

import yaml

from ids.event import Alert, Event

def _condition_matches(event: Event, conditions: dict[str, Any]) -> bool:
    for field_name, expected in conditions.items():
        actual = event.get(field_name)
        if isinstance(expected, dict):
            if "contains" in expected:
                if actual is None or expected["contains"] not in str(actual):
                    return False
            if "in" in expected and actual not in expected["in"]:
                return False
            if "regex" in expected:
                import re
                if actual is None or not re.search(expected["regex"], str(actual)):
                    return False
        else:
            if actual != expected:
                return False
    return True

class RuleEngine:
    """Loads YAML rules and evaluates events against them."""

    def __init__(self, rules: list[dict[str, Any]]):
        self.rules = rules
        
        # Per-rule, per-key sliding window of timestamps for thresholds.
        self._windows: dict[str, dict[str, deque]] = defaultdict(
            lambda: defaultdict(deque)
        )

    @classmethod
    def from_yaml(cls, path: str) -> "RuleEngine":
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return cls(data.get("rules", []))

    def evaluate(self, event: Event) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.rules:
            if not _condition_matches(event, rule.get("conditions", {})):
                continue
            if rule.get("type") == "threshold":
                alert = self._handle_threshold(rule, event)
                if alert:
                    alerts.append(alert)
            else:
                alerts.append(self._build_alert(rule, event, [event.raw]))
        return alerts

    def _handle_threshold(self, rule: dict[str, Any], event: Event):
        key_field = rule.get("group_by", "src_ip")
        key = str(event.get(key_field))
        window = timedelta(seconds=rule.get("window_seconds", 60))
        count = rule.get("count", 5)

        dq = self._windows[rule["name"]][key]
        dq.append(event.timestamp)
        while dq and event.timestamp - dq[0] > window:
            dq.popleft()

        if len(dq) >= count:
            evidence = [
                f"{len(dq)} matching events from {key} "
                f"within {rule.get('window_seconds', 60)}s"
            ]
            dq.clear()  # avoid re-firing every subsequent event
            return self._build_alert(rule, event, evidence)
        return None

    @staticmethod
    def _build_alert(rule: dict[str, Any], event: Event, evidence: list[str]) -> Alert:
        return Alert(
            timestamp=event.timestamp,
            severity=rule.get("severity", "medium"),
            category=rule.get("category", "rule"),
            title=rule.get("name", "rule match"),
            description=rule.get("description", ""),
            src_ip=event.src_ip,
            detector="rule_engine",
            evidence=evidence,
            mitre=rule.get("mitre"),
        )

    def run(self, events: Iterable[Event]) -> list[Alert]:
        alerts: list[Alert] = []
        for event in events:
            alerts.extend(self.evaluate(event))
        return alerts