""" Parser for Linux auth logs (sshd messages in /var/log/auth.log) """

from __future__ import annotations

import re
from datetime import datetime
from typing import Iterator, Optional

from ids.event import Event

# Example lines:
# May 12 09:14:01 host sshd[2123]: Failed password for invalid user admin from 203.0.113.5 port 51020 ssh2
# May 12 09:14:07 host sshd[2124]: Accepted password for deploy from 198.51.100.7 port 51290 ssh2

_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
)
_ACCEPTED = re.compile(
    r"Accepted password for (?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
)
_TS = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})")


def _parse_ts(line: str, year: int) -> Optional[datetime]:
    m = _TS.match(line)
    if not m:
        return None
    try:
        return datetime.strptime(f"{year} {m.group('ts')}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def parse_auth_log(path: str, year: int = 2025) -> Iterator[Event]:
    """Yield normalized Events from an auth log file."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            ts = _parse_ts(line, year)
            if ts is None:
                continue

            m = _FAILED.search(line)
            if m:
                yield Event(
                    timestamp=ts,
                    source="auth",
                    src_ip=m.group("ip"),
                    dst_port=int(m.group("port")),
                    protocol="ssh",
                    action="login_failed",
                    user=m.group("user"),
                    raw=line,
                )
                continue

            m = _ACCEPTED.search(line)
            if m:
                yield Event(
                    timestamp=ts,
                    source="auth",
                    src_ip=m.group("ip"),
                    dst_port=int(m.group("port")),
                    protocol="ssh",
                    action="login_ok",
                    user=m.group("user"),
                    raw=line,
                )
