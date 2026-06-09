"""
Command-line interface for the hybrid IDS

Usage examples:
  python -m ids.cli --auth samples/auth.log --web samples/access.log \
      --flows samples/flows.csv --rules rules/default.yaml
  python -m ids.cli --web samples/access.log --enrich --json
"""

from __future__ import annotations

import argparse
import sys
from itertools import chain

from ids.detectors.anomaly import AnomalyDetector
from ids.detectors.correlation import CorrelationEngine
from ids.detectors.rule_engine import RuleEngine
from ids.engine import IDSEngine, alerts_to_json, format_report
from ids.intel.enrich import AbuseIPDBProvider, Enricher, LocalFeedProvider
from ids.parsers.auth_log import parse_auth_log
from ids.parsers.network import parse_flow_csv, parse_pcap
from ids.parsers.web_log import parse_web_log


def build_event_stream(args):
    streams = []
    if args.auth:
        streams.append(parse_auth_log(args.auth))
    if args.web:
        streams.append(parse_web_log(args.web))
    if args.flows:
        streams.append(parse_flow_csv(args.flows))
    if args.pcap:
        streams.append(parse_pcap(args.pcap))
    if not streams:
        print("error: provide at least one input (--auth/--web/--flows/--pcap)",
              file=sys.stderr)
        sys.exit(2)
    # Merge sources and sort chronologically so thresholds work correctly.
    events = list(chain.from_iterable(streams))
    events.sort(key=lambda e: e.timestamp)
    return events


def build_enricher(args):
    """Pick a threat-intel provider based on the flags given."""
    if not args.enrich:
        return None
    if args.intel_provider == "abuseipdb":
        return Enricher(AbuseIPDBProvider())  # reads ABUSEIPDB_KEY from env
    return Enricher(LocalFeedProvider(args.intel_feed))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Hybrid IDS: rule + anomaly detection with correlation "
                    "and threat-intel enrichment."
    )
    parser.add_argument("--auth", help="path to an SSH/auth log")
    parser.add_argument("--web", help="path to a web access log (combined format)")
    parser.add_argument("--flows", help="path to a CSV flow export")
    parser.add_argument("--pcap", help="path to a pcap file (requires scapy)")
    parser.add_argument("--rules", default="rules/default.yaml",
                        help="path to the YAML rule file")
    parser.add_argument("--json", action="store_true",
                        help="emit alerts as JSON instead of a text report")
    parser.add_argument("--no-correlate", action="store_true",
                        help="disable the correlation engine")
    parser.add_argument("--enrich", action="store_true",
                        help="enrich alerts with threat-intel for source IPs")
    parser.add_argument("--intel-provider", choices=["local", "abuseipdb"],
                        default="local",
                        help="intel source when --enrich is set (default: local)")
    parser.add_argument("--intel-feed", default="intel_feed.json",
                        help="path to the local reputation feed (local provider)")
    args = parser.parse_args(argv)

    # Load events, correlation engine and enricher
    events = build_event_stream(args)
    correlation = None if args.no_correlate else CorrelationEngine()
    enricher = build_enricher(args)

    # Create engine
    engine = IDSEngine(
        RuleEngine.from_yaml(args.rules), # Rules declared in yaml
        AnomalyDetector(), # Anomaly detector
        correlation=correlation, # Correlation between anomalies
        enricher=enricher, # Enrocher IPs information
    )

    alerts = engine.analyze(events)

    if args.json:
        print(alerts_to_json(alerts))
    else:
        print(f"Processed {len(events)} events from merged sources.\n")
        print(format_report(alerts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
