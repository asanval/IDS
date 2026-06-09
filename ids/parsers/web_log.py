""" Parser for web server access logs in the Combined Log Format """

from __future__ import annotations

import re
from datetime import datetime
from typing import Iterator, Optional

from ids.event import Event

# Combined Log Format:
# 203.0.113.5 - - [12/May/2025:09:14:01 +0000] "GET /admin HTTP/1.1" 404 512 "-" "curl/8.0"
_LINE = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) \S+ \S+ '
    r'\[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>[^ ]+) [^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)'
)


def _parse_ts(value: str) -> Optional[datetime]:
    try:
        return datetime.strptime(value.split()[0], "%d/%b/%Y:%H:%M:%S")
    except (ValueError, IndexError):
        return None


def parse_web_log(path: str) -> Iterator[Event]:
    """Yield normalized Events from a web access log file."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = _LINE.search(line)
            if not m:
                continue
            ts = _parse_ts(m.group("ts"))
            if ts is None:
                continue
            raw_bytes = m.group("bytes")
            yield Event(
                timestamp=ts,
                source="web",
                src_ip=m.group("ip"),
                protocol="http",
                action="request",
                http_method=m.group("method"),
                http_path=m.group("path"),
                http_status=int(m.group("status")),
                bytes=0 if raw_bytes == "-" else int(raw_bytes),
                raw=line.rstrip("\n"),
            )
