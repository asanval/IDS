""" Test suite for the hybrid IDS. Run with: python -m pytest -q """

from datetime import datetime, timedelta

from ids.detectors.anomaly import AnomalyDetector
from ids.detectors.rule_engine import RuleEngine
from ids.event import Event
from ids.parsers.auth_log import parse_auth_log
from ids.parsers.web_log import parse_web_log
from ids.parsers.network import parse_flow_csv


def _evt(**kw):
    kw.setdefault("timestamp", datetime(2025, 5, 12, 9, 0, 0))
    kw.setdefault("source", "web")
    return Event(**kw)


# ---------- parsers ----------

def test_auth_parser(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text(
        "May 12 09:14:01 h sshd[1]: Failed password for invalid user root "
        "from 203.0.113.5 port 51020 ssh2\n"
        "May 12 09:14:07 h sshd[2]: Accepted password for deploy "
        "from 198.51.100.7 port 51290 ssh2\n"
    )
    events = list(parse_auth_log(str(p)))
    assert len(events) == 2
    assert events[0].action == "login_failed"
    assert events[0].src_ip == "203.0.113.5"
    assert events[1].action == "login_ok"
    assert events[1].user == "deploy"


def test_web_parser(tmp_path):
    p = tmp_path / "access.log"
    p.write_text(
        '203.0.113.5 - - [12/May/2025:09:14:01 +0000] '
        '"GET /admin HTTP/1.1" 404 512 "-" "curl/8.0"\n'
    )
    events = list(parse_web_log(str(p)))
    assert len(events) == 1
    assert events[0].http_status == 404
    assert events[0].http_path == "/admin"


def test_flow_parser(tmp_path):
    p = tmp_path / "flows.csv"
    p.write_text(
        "timestamp,src_ip,dst_ip,dst_port,protocol,flags,bytes\n"
        "2025-05-12T09:00:00,203.0.113.99,10.0.0.5,22,tcp,S,60\n"
    )
    events = list(parse_flow_csv(str(p)))
    assert len(events) == 1
    assert events[0].dst_port == 22
    assert events[0].protocol == "tcp"


# ---------- rule engine ----------

def test_rule_match_regex():
    engine = RuleEngine([{
        "name": "SQLi", "type": "match", "category": "web_attack",
        "severity": "high",
        "conditions": {"http_path": {"regex": "(?i)union\\s+select"}},
    }])
    hit = _evt(http_path="/x?q=1 UNION SELECT pwd")
    miss = _evt(http_path="/home")
    assert len(engine.evaluate(hit)) == 1
    assert len(engine.evaluate(miss)) == 0


def test_rule_threshold_fires_once():
    engine = RuleEngine([{
        "name": "BF", "type": "threshold", "category": "brute_force",
        "severity": "high", "group_by": "src_ip",
        "count": 3, "window_seconds": 60,
        "conditions": {"action": "login_failed"},
    }])
    t0 = datetime(2025, 5, 12, 9, 0, 0)
    alerts = []
    for i in range(5):
        e = Event(timestamp=t0 + timedelta(seconds=i * 5), source="auth",
                  src_ip="203.0.113.5", action="login_failed")
        alerts += engine.evaluate(e)
    # 5 failures, threshold 3, window resets after firing -> exactly one alert.
    assert len(alerts) == 1
    assert alerts[0].category == "brute_force"


def test_threshold_respects_window():
    engine = RuleEngine([{
        "name": "BF", "type": "threshold", "group_by": "src_ip",
        "count": 3, "window_seconds": 10,
        "conditions": {"action": "login_failed"},
    }])
    t0 = datetime(2025, 5, 12, 9, 0, 0)
    alerts = []
    # events 30s apart never accumulate within a 10s window
    for i in range(5):
        e = Event(timestamp=t0 + timedelta(seconds=i * 30), source="auth",
                  src_ip="1.1.1.1", action="login_failed")
        alerts += engine.evaluate(e)
    assert len(alerts) == 0


# ---------- anomaly detector ----------

def test_port_scan_detection():
    det = AnomalyDetector(port_scan_threshold=10)
    t0 = datetime(2025, 5, 12, 9, 0, 0)
    for port in range(12):
        det.observe(Event(timestamp=t0, source="network",
                          src_ip="203.0.113.99", dst_port=port))
    alerts = det.finalize()
    assert any(a.category == "port_scan" for a in alerts)


def test_error_ratio_detection():
    det = AnomalyDetector(min_requests_for_ratio=10, error_ratio_threshold=0.5)
    t0 = datetime(2025, 5, 12, 9, 0, 0)
    for i in range(20):
        det.observe(Event(timestamp=t0, source="web", src_ip="203.0.113.50",
                          http_status=404 if i < 15 else 200))
    alerts = det.finalize()
    assert any(a.category == "enumeration" for a in alerts)


def test_clean_traffic_no_alerts():
    det = AnomalyDetector()
    engine = RuleEngine([])
    t0 = datetime(2025, 5, 12, 9, 0, 0)
    for i in range(5):
        e = Event(timestamp=t0 + timedelta(seconds=i), source="web",
                  src_ip="198.51.100.7", http_status=200, dst_port=443)
        assert engine.evaluate(e) == []
        det.observe(e)
    assert det.finalize() == []


# ---------- threat-intel enrichment ----------

from ids.intel.enrich import Enricher, LocalFeedProvider
from ids.detectors.correlation import CorrelationEngine
from ids.event import Alert


def _alert(category, severity, src_ip, ts_offset=0):
    return Alert(
        timestamp=datetime(2025, 5, 12, 9, 0, 0) + timedelta(seconds=ts_offset),
        severity=severity, category=category,
        title=category, description="", src_ip=src_ip,
        detector="test",
    )


def test_local_feed_lookup(tmp_path):
    feed = tmp_path / "feed.json"
    feed.write_text(
        '{"203.0.113.5": {"country": "RU", "asn": "AS1", '
        '"reputation": "malicious", "abuse_score": 95, '
        '"categories": ["scanner"]}}'
    )
    prov = LocalFeedProvider(str(feed))
    intel = prov.lookup("203.0.113.5")
    assert intel.reputation == "malicious"
    assert intel.country == "RU"
    assert intel.abuse_score == 95


def test_enrichment_escalates_severity(tmp_path):
    feed = tmp_path / "feed.json"
    feed.write_text(
        '{"203.0.113.5": {"reputation": "malicious", "abuse_score": 95}}'
    )
    enricher = Enricher(LocalFeedProvider(str(feed)))
    alerts = [_alert("brute_force", "high", "203.0.113.5")]
    enriched = enricher.enrich(alerts)
    # malicious -> escalate two rungs from high -> critical
    assert enriched[0].severity == "critical"
    assert enriched[0].intel.reputation == "malicious"


def test_enrichment_unknown_ip_no_escalation(tmp_path):
    feed = tmp_path / "feed.json"
    feed.write_text("{}")
    enricher = Enricher(LocalFeedProvider(str(feed)))
    alerts = [_alert("brute_force", "high", "203.0.113.250")]
    enriched = enricher.enrich(alerts)
    assert enriched[0].severity == "high"
    assert enriched[0].intel.reputation == "unknown"


def test_enrichment_caches_lookups(tmp_path):
    feed = tmp_path / "feed.json"
    feed.write_text('{"203.0.113.5": {"reputation": "clean"}}')

    class CountingProvider(LocalFeedProvider):
        calls = 0
        def lookup(self, ip):
            CountingProvider.calls += 1
            return super().lookup(ip)

    enricher = Enricher(CountingProvider(str(feed)))
    enricher.enrich([_alert("a", "low", "203.0.113.5"),
                     _alert("b", "low", "203.0.113.5")])
    assert CountingProvider.calls == 1  # second alert hit the cache


# ---------- correlation ----------

def test_correlation_detects_ssh_compromise():
    engine = CorrelationEngine()
    alerts = [
        _alert("brute_force", "high", "203.0.113.5", ts_offset=0),
        _alert("auth_success", "info", "203.0.113.5", ts_offset=30),
    ]
    derived = engine.correlate(alerts)
    assert any(a.category == "correlation" and a.severity == "critical"
               for a in derived)
    assert any(a.mitre == "T1110" for a in derived)


def test_correlation_respects_order():
    engine = CorrelationEngine()
    # success BEFORE brute force should not form the compromise chain
    alerts = [
        _alert("auth_success", "info", "1.2.3.4", ts_offset=0),
        _alert("brute_force", "high", "1.2.3.4", ts_offset=30),
    ]
    derived = engine.correlate(alerts)
    assert not any(a.title == "Probable host compromise via SSH"
                   for a in derived)


def test_correlation_separates_by_ip():
    engine = CorrelationEngine()
    # two halves of a chain but from different IPs -> no correlation
    alerts = [
        _alert("brute_force", "high", "1.1.1.1", ts_offset=0),
        _alert("suspicious_auth", "medium", "2.2.2.2", ts_offset=30),
    ]
    derived = engine.correlate(alerts)
    assert derived == []


# ---------- benign traffic / false-positive resistance ----------

from ids.engine import IDSEngine
from ids.parsers.auth_log import parse_auth_log as _pa
from ids.parsers.web_log import parse_web_log as _pw
from ids.parsers.network import parse_flow_csv as _pf


def _full_engine():
    return IDSEngine(
        RuleEngine.from_yaml("rules/default.yaml"),
        AnomalyDetector(),
        correlation=CorrelationEngine(),
    )


def test_benign_logins_do_not_alert(tmp_path):
    """A handful of legitimate, well-spaced successful logins must stay quiet."""
    p = tmp_path / "auth.log"
    lines = []
    for i, (u, ip) in enumerate(
        [("alice", "198.51.100.10"), ("bob", "198.51.100.11"),
         ("carol", "198.51.100.12"), ("deploy", "198.51.100.7")] * 2
    ):
        # 5 minutes apart -> never a burst
        hh, mm = 9, i * 5
        lines.append(
            f"May 12 {hh:02d}:{mm:02d}:00 web01 sshd[{3000+i}]: "
            f"Accepted password for {u} from {ip} port {40000+i} ssh2"
        )
    p.write_text("\n".join(lines) + "\n")

    events = sorted(_pa(str(p)), key=lambda e: e.timestamp)
    alerts = _full_engine().analyze(events)
    # No actionable (non-info) alerts from clean logins.
    actionable = [a for a in alerts if a.severity != "info"]
    assert actionable == []


def test_single_typo_failure_is_not_brute_force(tmp_path):
    """One failed attempt then a success (a typo) must not trip brute force."""
    p = tmp_path / "auth.log"
    p.write_text(
        "May 12 09:00:00 web01 sshd[1]: Failed password for alice "
        "from 198.51.100.10 port 40500 ssh2\n"
        "May 12 09:00:08 web01 sshd[2]: Accepted password for alice "
        "from 198.51.100.10 port 40501 ssh2\n"
    )
    events = sorted(_pa(str(p)), key=lambda e: e.timestamp)
    alerts = _full_engine().analyze(events)
    assert not any(a.category == "brute_force" for a in alerts)
    assert not any(a.category == "correlation" for a in alerts)


def test_benign_web_browsing_does_not_alert(tmp_path):
    """Normal browsing with mostly-200 responses must not look like enumeration."""
    p = tmp_path / "access.log"
    paths = ["/", "/products", "/about", "/static/css/main.css", "/api/v1/status"]
    lines = []
    base_min = 0
    for i in range(60):
        base_min += 1
        ip = f"198.51.100.{20 + (i % 10)}"
        path = paths[i % len(paths)]
        code = 200 if i % 15 else 404  # rare natural 404
        ts = f"12/May/2025:09:{base_min % 60:02d}:{i % 60:02d}"
        lines.append(f'{ip} - - [{ts} +0000] "GET {path} HTTP/1.1" {code} 1200 "-" "Mozilla/5.0"')
    p.write_text("\n".join(lines) + "\n")

    events = sorted(_pw(str(p)), key=lambda e: e.timestamp)
    alerts = _full_engine().analyze(events)
    assert alerts == []


def test_high_volume_single_port_is_not_a_scan(tmp_path):
    """A busy host hammering ONE port (e.g. HTTPS) is not a port scan."""
    p = tmp_path / "flows.csv"
    rows = ["timestamp,src_ip,dst_ip,dst_port,protocol,flags,bytes"]
    for i in range(50):
        rows.append(
            f"2025-05-12T09:{i % 60:02d}:00,198.51.100.50,10.0.0.5,443,tcp,PA,2000"
        )
    p.write_text("\n".join(rows) + "\n")

    events = sorted(_pf(str(p)), key=lambda e: e.timestamp)
    alerts = _full_engine().analyze(events)
    assert not any(a.category == "port_scan" for a in alerts)


def test_attacks_still_detected_among_benign(tmp_path):
    """End-to-end: with the shipped sample data, the real attacks fire and
    no benign internal IP raises an actionable alert."""
    engine = _full_engine()
    events = []
    events += list(_pa("samples/auth.log"))
    events += list(_pw("samples/access.log"))
    events += list(_pf("samples/flows.csv"))
    events.sort(key=lambda e: e.timestamp)
    alerts = engine.analyze(events)

    cats = {a.category for a in alerts}
    assert {"brute_force", "port_scan", "web_attack", "correlation"} <= cats
    # No actionable alert points at the internal/benign range.
    actionable = [a for a in alerts if a.severity != "info"]
    assert all(not (a.src_ip or "").startswith("198.51.100")
               for a in actionable)
