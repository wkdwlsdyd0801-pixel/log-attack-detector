"""Tests for parsing, the rule logic and the metric calculation."""
from datetime import datetime, timedelta, timezone

import pytest

from demo_data import generate
from detector import Request, RuleDetector, benchmark, parse_line, score

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def req(path="/", status=200, method="GET", ip="203.0.113.5", offset=0):
    return Request(ip, T0 + timedelta(seconds=offset), method, path, status, "test")


def test_parse_valid_and_malformed():
    line = '198.51.100.1 - - [01/Feb/2026:10:00:00 +0000] "GET /a?b=1 HTTP/1.1" 200 12 "-" "x y"'
    parsed = parse_line(line)
    assert (parsed.ip, parsed.path, parsed.status) == ("198.51.100.1", "/a?b=1", 200)
    assert parse_line("not a log line") is None


@pytest.mark.parametrize("path,expected", [
    ("/p?id=1%27%20OR%201%3D1", "sqli"),
    ("/s?q=%3Cscript%3Ealert(1)%3C/script%3E", "xss"),
    ("/d?f=..%2F..%2Fetc%2Fpasswd", "traversal"),
    ("/ping?h=%3B%20cat%20x", "cmdi"),
])
def test_signatures_match_encoded_attacks(path, expected):
    assert RuleDetector().check(req(path)) == expected


@pytest.mark.parametrize("path", [
    "/search?q=how+to+select+a+union+rep",
    "/search?q=javascript+script+for+a+play",
    "/search?q=cat+food",
])
def test_signatures_ignore_benign_keywords(path):
    assert RuleDetector().check(req(path)) == ""


def test_brute_force_needs_repeated_failures():
    detector = RuleDetector()
    results = [detector.check(req("/login", 401, "POST", offset=i)) for i in range(5)]
    assert results == ["", "", "", "", "brute_force"]


def test_slow_failures_outside_window_do_not_alert():
    detector = RuleDetector()
    assert not any(detector.check(req("/login", 401, "POST", offset=i * 30)) for i in range(10))


def test_failure_counters_are_per_client():
    detector = RuleDetector()
    alerts = [detector.check(req("/login", 401, "POST", ip=f"203.0.113.{i}", offset=i)) for i in range(10)]
    assert not any(alerts)


def test_404_burst_alerts_as_scanner():
    detector = RuleDetector()
    assert [detector.check(req(f"/x{i}", 404, offset=i)) for i in range(5)][-1] == "scanner"


def test_score_counts_and_zero_division():
    assert score([True, True, False, False], [1, 0, 1, 0]) == {
        "precision": 0.5, "recall": 0.5, "f1": 0.5, "tp": 1, "fp": 1, "fn": 1}
    assert score([False, False], [1, 0])["precision"] == 0.0


def test_demo_data_is_deterministic():
    assert generate(1000, 5, novel=True) == generate(1000, 5, novel=True)


def test_benchmark_shape_and_sanity():
    result = benchmark(train_lines=4000, test_lines=4000)
    overall = result["overall"]
    # Thresholds are loose on purpose: they catch a broken pipeline, not small drift.
    assert overall["rules"]["precision"] > 0.8 and overall["ml"]["recall"] > 0.5
    # By definition an OR-combination cannot lose true positives.
    assert overall["hybrid"]["tp"] >= max(overall["rules"]["tp"], overall["ml"]["tp"])
