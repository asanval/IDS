""" 
Network parser.

Reads connection events from either a .pcap file (via scapy, if installed)
or a simple CSV of flows
"""

from __future__ import annotations

import csv
from datetime import datetime
from typing import Iterator

from ids.event import Event


def parse_flow_csv(path: str) -> Iterator[Event]:
    """Yield network Events from a CSV flow export."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            try:
                ts = datetime.fromisoformat(row["timestamp"])
            except (ValueError, KeyError):
                continue
            yield Event(
                timestamp=ts,
                source="network",
                src_ip=row.get("src_ip") or None,
                dst_ip=row.get("dst_ip") or None,
                dst_port=int(row["dst_port"]) if row.get("dst_port") else None,
                protocol=(row.get("protocol") or "").lower() or None,
                action="connection",
                bytes=int(row["bytes"]) if row.get("bytes") else 0,
                raw=",".join(row.values()),
                extra={"flags": row.get("flags", "")},
            )


def parse_pcap(path: str) -> Iterator[Event]:
    """Yield network Events from a pcap file using scapy if available."""
    try:
        from scapy.all import IP, TCP, UDP, rdpcap  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "scapy is not installed. Either `pip install scapy` or use a "
            "CSV flow file with parse_flow_csv()."
        ) from exc

    for pkt in rdpcap(path):  # pragma: no cover - requires scapy + pcap
        if IP not in pkt:
            continue
        ip = pkt[IP]
        dst_port = None
        proto = "ip"
        flags = ""
        if TCP in pkt:
            proto, dst_port = "tcp", int(pkt[TCP].dport)
            flags = str(pkt[TCP].flags)
        elif UDP in pkt:
            proto, dst_port = "udp", int(pkt[UDP].dport)
        yield Event(
            timestamp=datetime.fromtimestamp(float(pkt.time)),
            source="network",
            src_ip=ip.src,
            dst_ip=ip.dst,
            dst_port=dst_port,
            protocol=proto,
            action="connection",
            bytes=len(pkt),
            extra={"flags": flags},
        )
