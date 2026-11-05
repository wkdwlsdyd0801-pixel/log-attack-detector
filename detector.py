#!/usr/bin/env python3
"""
log-attack-detector: detect web attacks in access logs and measure the result.

Three detectors are compared on the same held-out data:
  - rules  : regex signatures plus per-client sliding windows. Explainable and
             needs no training, but it only knows the patterns somebody wrote.
  - ml     : logistic regression over character n-grams of the decoded URL.
             It generalises across syntax, but sees one request at a time.
  - hybrid : alert if either fires. Catches more, at the cost of both false-alarm sets.

Precision and recall are reported instead of accuracy: with about 12% attacks, a
detector that never alerts is already 88% "accurate" and completely useless.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import unquote_plus

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

from demo_data import generate

LINE = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]*" '
                  r'(?P<status>\d{3}) (?P<size>\d+|-) "[^"]*" "(?P<agent>[^"]*)"$')

# Signatures need attack structure (a quote before OR, a tag opening), not bare keywords,
# because words like "select" and "script" also appear in ordinary searches.
SIGNATURES = {
    "sqli": re.compile(r"('|\")\s*(or|and)\b|\bunion\s+select\b|'\s*(--|#)|\bsleep\s*\(", re.I),
    "xss": re.compile(r"<\s*script\b|<[^>]+\bon\w+\s*=|javascript:", re.I),
    "traversal": re.compile(r"\.\.(/|\\)|\.\.\.\.//|/etc/(passwd|shadow)|win\.ini", re.I),
    "cmdi": re.compile(r"(;|\||&&|`|\$\()\s*(cat|id|ls|whoami|uname|nc|ping)\b", re.I),
}
FAILED_LOGIN_LIMIT, FAILED_LOGIN_WINDOW = 5, 60   # above typo level, below any useful attack rate
NOT_FOUND_LIMIT, NOT_FOUND_WINDOW = 5, 30         # humans rarely hit five dead links in 30 s


@dataclass
class Request:
    ip: str
    when: datetime
    method: str
    path: str
    status: int
    agent: str


def parse_line(line: str) -> Request | None:
    """Parse a combined-format line. Returns None when malformed, because a single
    corrupt line must not stop analysis of an entire log."""
    match = LINE.match(line.strip())
    if not match:
        return None
    try:
        when = datetime.strptime(match["time"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    return Request(match["ip"], when, match["method"], match["path"], int(match["status"]), match["agent"])


def normalise(path: str) -> str:
    """Decode the URL once, as an application would, so that %27 matches a quote.
    WHY once: this is a deliberate baseline. Double-encoded payloads stay encoded here,
    and the benchmark shows what that costs the rule set."""
    return unquote_plus(path)


class RuleDetector:
    """Signature matching plus sliding windows. State is kept per client IP, because
    brute force and scanning are invisible when each request is viewed alone."""

    def __init__(self) -> None:
        self.failures: dict[str, deque] = defaultdict(deque)
        self.not_found: dict[str, deque] = defaultdict(deque)

    @staticmethod
    def _over_limit(events: deque, when: datetime, window: int, limit: int) -> bool:
        events.append(when)
        # Drop expired entries so that memory and the count both reflect only the window.
        while (when - events[0]).total_seconds() > window:
            events.popleft()
        return len(events) >= limit

    def check(self, req: Request) -> str:
        """Return the alert name, or an empty string for no alert."""
        decoded = normalise(req.path)
        for name, pattern in SIGNATURES.items():
            if pattern.search(decoded):
                return name
        if req.method == "POST" and "login" in req.path and req.status == 401:
            if self._over_limit(self.failures[req.ip], req.when, FAILED_LOGIN_WINDOW, FAILED_LOGIN_LIMIT):
                return "brute_force"
        if req.status == 404:
            if self._over_limit(self.not_found[req.ip], req.when, NOT_FOUND_WINDOW, NOT_FOUND_LIMIT):
                return "scanner"
        return ""


def train_model(requests: list[Request], labels: list[int], seed: int = 0):
    """Train on the URL only. The IP is left out on purpose: in generated data it would
    reveal the label and yield a perfect score that means nothing in production."""
    model = make_pipeline(
        # Character n-grams capture syntax such as ' OR and <svg/ without a tokenizer.
        TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), min_df=2, sublinear_tf=True),
        # class_weight compensates for attacks being the minority class.
        LogisticRegression(max_iter=1000, class_weight="balanced", random_state=seed),
    )
    model.fit([normalise(r.path) for r in requests], labels)
    return model


def score(predicted: list[bool], actual: list[int]) -> dict:
    """Precision, recall and F1 from the confusion counts."""
    tp = sum(p and a == 1 for p, a in zip(predicted, actual))
    fp = sum(p and a == 0 for p, a in zip(predicted, actual))
    fn = sum(not p and a == 1 for p, a in zip(predicted, actual))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3), "tp": tp, "fp": fp, "fn": fn}


def run_rules(requests: list[Request]) -> list[bool]:
    detector = RuleDetector()   # fresh state: windows must not leak between datasets
    return [bool(detector.check(r)) for r in requests]


def _parse_rows(rows):
    parsed = [(parse_line(line), label, kind) for line, label, kind in rows]
    parsed = [row for row in parsed if row[0] is not None]
    return [p[0] for p in parsed], [p[1] for p in parsed], [p[2] for p in parsed]


def benchmark(train_lines: int = 20000, test_lines: int = 20000, seed: int = 1) -> dict:
    """Train on known payloads, then test on another seed that includes unseen payloads."""
    train_req, train_y, _ = _parse_rows(generate(train_lines, seed))
    test_req, test_y, kinds = _parse_rows(generate(test_lines, seed + 1000, novel=True))

    model = train_model(train_req, train_y, seed)
    rules = run_rules(test_req)
    ml = [bool(p) for p in model.predict([normalise(r.path) for r in test_req])]
    hybrid = [a or b for a, b in zip(rules, ml)]

    per_type: dict[str, dict] = {}
    for kind in sorted({k for k in kinds if k}):
        indices = [i for i, k in enumerate(kinds) if k == kind]
        # Recall per attack type shows which detector misses what; a single total hides it.
        per_type[kind] = {
            "count": len(indices),
            "rules": round(sum(rules[i] for i in indices) / len(indices), 3),
            "ml": round(sum(ml[i] for i in indices) / len(indices), 3),
            "hybrid": round(sum(hybrid[i] for i in indices) / len(indices), 3),
        }
    return {
        "test_lines": len(test_y),
        "attack_share": round(sum(test_y) / len(test_y), 3),
        "overall": {"rules": score(rules, test_y), "ml": score(ml, test_y), "hybrid": score(hybrid, test_y)},
        "recall_by_type": per_type,
    }


def print_benchmark(result: dict) -> None:
    print(f"test lines: {result['test_lines']}  attack share: {result['attack_share']:.1%}\n")
    print(f"{'detector':<10}{'precision':>10}{'recall':>9}{'f1':>8}{'tp':>7}{'fp':>7}{'fn':>7}")
    for name, s in result["overall"].items():
        print(f"{name:<10}{s['precision']:>10.3f}{s['recall']:>9.3f}{s['f1']:>8.3f}{s['tp']:>7}{s['fp']:>7}{s['fn']:>7}")
    print(f"\n{'recall by type':<16}{'count':>7}{'rules':>8}{'ml':>8}{'hybrid':>8}")
    for kind, s in result["recall_by_type"].items():
        print(f"{kind:<16}{s['count']:>7}{s['rules']:>8.3f}{s['ml']:>8.3f}{s['hybrid']:>8.3f}")


def scan_file(path: str) -> int:
    """Run the rules on a real log file. Rules need no labels or training data."""
    detector = RuleDetector()
    alerts = skipped = 0
    with open(path, encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, start=1):
            req = parse_line(line)
            if req is None:
                skipped += 1
                continue
            alert = detector.check(req)
            if alert:
                alerts += 1
                # json.dumps escapes control characters, preventing log injection in our output.
                print(json.dumps({"line": number, "alert": alert, "ip": req.ip, "path": req.path}))
    print(f"{alerts} alerts, {skipped} unparsed lines", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect web attacks in access logs.")
    commands = parser.add_subparsers(dest="command", required=True)
    bench = commands.add_parser("benchmark", help="compare the detectors on held-out demo data")
    bench.add_argument("--seed", type=int, default=1)
    bench.add_argument("--json", action="store_true")
    scan = commands.add_parser("scan", help="run the rules on an access log")
    scan.add_argument("logfile")
    args = parser.parse_args(argv)
    if args.command == "scan":
        return scan_file(args.logfile)
    result = benchmark(seed=args.seed)
    print(json.dumps(result, indent=2)) if args.json else print_benchmark(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
