"""
Statistical anomaly detector.

Complements the signature engine: instead of known patterns, it flags
behavior that deviates from a learned baseline.

Signals:
  - Distinct destination ports per source IP   -> horizontal/port scan.
  - HTTP 4xx/5xx error ratio per source IP     -> enumeration / fuzzing.
  - Request/connection volume z-score per IP   -> volumetric outliers.

Event -> Alert
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from typing import Iterable

from ids.event import Alert, Event


class AnomalyDetector:
    def __init__(
        self,
        port_scan_threshold: int = 15,
        error_ratio_threshold: float = 0.6,
        min_requests_for_ratio: int = 20,
        zscore_threshold: float = 3.0,
    ):
        self.port_scan_threshold = port_scan_threshold
        self.error_ratio_threshold = error_ratio_threshold
        self.min_requests_for_ratio = min_requests_for_ratio
        self.zscore_threshold = zscore_threshold

        self._ports: dict[str, set[int]] = defaultdict(set)
        self._requests: dict[str, int] = defaultdict(int)
        self._errors: dict[str, int] = defaultdict(int)
        self._last_ts: dict[str, Any] = {}  # type: ignore[name-defined]

    def observe(self, event: Event) -> None:
        """Gets IP, port, amount, status and timestamp information"""

        ip = event.src_ip
        if not ip:
            return
        if event.dst_port is not None:
            self._ports[ip].add(event.dst_port)
        if event.source == "web":
            self._requests[ip] += 1
            if event.http_status and event.http_status >= 400:
                self._errors[ip] += 1
        self._last_ts[ip] = event.timestamp

    def finalize(self) -> list[Alert]:
        """Compute anomalies after observing the full event stream"""

        alerts: list[Alert] = []

        # Volumetric z-score baseline across all sources.
        volumes = list(self._requests.values())
        mean = statistics.mean(volumes) if volumes else 0.0
        stdev = statistics.pstdev(volumes) if len(volumes) > 1 else 0.0

        # Alert in case same source IP access different ports (port scan attack)
        for ip, ports in self._ports.items():
            if len(ports) >= self.port_scan_threshold:
                alerts.append(
                    Alert(
                        timestamp=self._last_ts[ip],
                        severity="high",
                        category="port_scan",
                        title="Possible port scan",
                        description=(
                            f"{ip} contacted {len(ports)} distinct ports, "
                            f"above baseline threshold of {self.port_scan_threshold}."
                        ),
                        src_ip=ip,
                        detector="anomaly",
                        evidence=[f"distinct_ports={len(ports)}"],
                    )
                )

        # Alert in case source IP produces HTTP errores (fuzzing attack)
        for ip, total in self._requests.items():
            if total >= self.min_requests_for_ratio:
                ratio = self._errors[ip] / total
                if ratio >= self.error_ratio_threshold:
                    alerts.append(
                        Alert(
                            timestamp=self._last_ts[ip],
                            severity="medium",
                            category="enumeration",
                            title="High HTTP error ratio",
                            description=(
                                f"{ip} produced a {ratio:.0%} error ratio over "
                                f"{total} requests, suggesting fuzzing/enumeration."
                            ),
                            src_ip=ip,
                            detector="anomaly",
                            evidence=[f"errors={self._errors[ip]}", f"total={total}"],
                        )
                    )

            if stdev > 0:
                z = (total - mean) / stdev
                if z >= self.zscore_threshold:
                    alerts.append(
                        Alert(
                            timestamp=self._last_ts[ip],
                            severity="medium",
                            category="volume_anomaly",
                            title="Volumetric outlier",
                            description=(
                                f"{ip} request volume is {z:.1f} standard "
                                f"deviations above the mean."
                            ),
                            src_ip=ip,
                            detector="anomaly",
                            evidence=[f"requests={total}", f"zscore={z:.2f}"],
                        )
                    )
        return alerts

    def run(self, events: Iterable[Event]) -> list[Alert]:
        for event in events:
            self.observe(event)
        return self.finalize()
