"""
demo_data: a small labelled log generator, so this repository runs on its own.

Train and test sets deliberately differ. The test set adds payload styles and
scanner paths that never appear in training, because scoring a model on the
strings it memorised would overstate how well it handles new attacks.

IPs are RFC 5737 documentation addresses, and nothing here sends network traffic.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

KNOWN = {
    "sqli": ["' OR '1'='1", "1' OR 1=1-- -", "' UNION SELECT NULL,NULL-- -", "admin'-- -"],
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"],
    "traversal": ["../../../../etc/passwd", "....//....//etc/passwd", "..\\..\\windows\\win.ini"],
    "cmdi": ["; cat /etc/passwd", "| id", "$(uname -a)"],
}
# Held out of training: other syntax for the same attack families.
NOVEL = {
    "sqli": ["1' AND SLEEP(5)-- -", "1) OR (1=1", "' oR 2>1#", "1;WAITFOR DELAY '0:0:5'--"],
    "xss": ["<svg/onload=alert(1)>", "<body onpageshow=alert(1)>", "<iframe src=javascript:alert(1)>"],
    "traversal": ["..;/..;/etc/hosts", "/proc/self/environ", "..%c0%af..%c0%afetc/hosts"],
    "cmdi": ["`whoami`", "&& nc -h", "|| ping -c 1 localhost"],
}
ENDPOINT = {"sqli": "/products?id=", "xss": "/search?q=", "traversal": "/download?file=", "cmdi": "/tools/ping?host="}
SCAN_KNOWN = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/backup.zip", "/config.php", "/shell.php", "/db.sql"]
SCAN_NOVEL = ["/.svn/entries", "/server-status", "/actuator/env", "/cgi-bin/test.cgi", "/dump.tar.gz", "/manager/html"]
PAGES = ["/", "/products", "/products/42", "/cart", "/about", "/blog", "/contact", "/account", "/static/app.js", "/static/app.css"]
# Benign requests that look suspicious, so keyword matching pays a false-positive cost.
TRICKY = ["/search?q=how+to+select+a+union+rep", "/search?q=drop+table+tennis+lessons", "/search?q=javascript+script+for+a+play",
          "/search?q=alert+me+when+back+in+stock", "/search?q=cat+food", "/docs/etc/install-guide", "/search?q=1+or+2+monitors"]
TRICKY_TEST = ["/search?q=sleep+mask+and+union+jack", "/search?q=onload+time+tips", "/blog/passwd-managers-compared", "/search?q=whoami+podcast"]
BROWSER = "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"
TOOL = "python-requests/2.32"


def _line(ip, when, method, path, status, size, agent):
    stamp = when.strftime("%d/%b/%Y:%H:%M:%S %z")
    return f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"'


def _encode(payload, rng):
    # Double encoding is the rarest form and is what a decode-once rule set will miss.
    roll = rng.random()
    if roll < 0.6:
        return quote(payload, safe="")
    if roll < 0.85:
        return quote(payload, safe="").replace("%20", "+")
    return quote(quote(payload, safe=""), safe="")


def generate(lines: int, seed: int, novel: bool = False, attack_ratio: float = 0.12) -> list[tuple[str, int, str]]:
    """Return (log_line, label, attack_type) rows in time order, exactly `lines` long."""
    rng = random.Random(seed)
    clock = datetime(2026, 2, 1, tzinfo=timezone.utc)
    rows: list[tuple[datetime, str, int, str]] = []
    attacks = 0

    def add(ip, when, method, path, status, size, agent, label, kind):
        rows.append((when, _line(ip, when, method, path, status, size, agent), label, kind))

    while len(rows) < lines:
        clock += timedelta(seconds=rng.uniform(0.5, 15))
        when = clock
        if attacks < attack_ratio * (len(rows) + 1):
            ip = f"203.0.113.{rng.randint(1, 254)}"
            kind = rng.choices(["sqli", "xss", "traversal", "cmdi", "brute_force", "scanner"], weights=[6, 6, 6, 6, 1, 2])[0]
            if kind == "brute_force":
                for _ in range(rng.randint(12, 30)):
                    add(ip, when, "POST", "/login", 401, 310, rng.choice([BROWSER, TOOL]), 1, kind)
                    when += timedelta(seconds=rng.uniform(0.2, 3))
                    attacks += 1
            elif kind == "scanner":
                pool = SCAN_KNOWN + (SCAN_NOVEL if novel else [])
                for path in rng.sample(pool, k=rng.randint(6, len(pool))):
                    add(ip, when, "GET", path, 404, rng.randint(150, 600), TOOL, 1, kind)
                    when += timedelta(seconds=rng.uniform(0.05, 1.5))
                    attacks += 1
            else:
                # In the novel set most payloads are unseen, so memorisation cannot carry the score.
                for _ in range(rng.randint(1, 5)):
                    pool = NOVEL[kind] if novel and rng.random() < 0.7 else KNOWN[kind]
                    path = ENDPOINT[kind] + _encode(rng.choice(pool), rng)
                    # The endpoint is shared with benign traffic below, so it cannot identify attacks alone.
                    add(ip, when, "GET", path, rng.choice([200, 200, 400, 403, 500]), rng.randint(150, 4000),
                        rng.choice([BROWSER, BROWSER, TOOL]), 1, kind)
                    when += timedelta(seconds=rng.uniform(0.2, 6))
                    attacks += 1
        else:
            ip = f"198.51.100.{rng.randint(1, 254)}"
            for _ in range(rng.randint(2, 8)):
                roll = rng.random()
                if roll < 0.12:
                    path = rng.choice(TRICKY + (TRICKY_TEST if novel else []))
                elif roll < 0.22:
                    path = f"/products?id={rng.randint(1, 500)}"
                elif roll < 0.30:
                    path = f"/download?file=manual-{rng.randint(1, 40)}.pdf"
                elif roll < 0.36:
                    path = f"/tools/ping?host=10.0.0.{rng.randint(1, 254)}"
                elif roll < 0.5:
                    path = f"/search?q={rng.choice(['laptop', 'usb+cable', 'monitor', 'desk+lamp'])}"
                else:
                    path = rng.choice(PAGES)
                status = 404 if rng.random() < 0.03 else 200
                add(ip, when, "GET", path, status, rng.randint(300, 40000), BROWSER, 0, "")
                when += timedelta(seconds=rng.uniform(1, 30))
            if rng.random() < 0.08:  # honest typos keep the brute-force threshold meaningful
                for _ in range(rng.randint(1, 3)):
                    add(ip, when, "POST", "/login", 401, 310, BROWSER, 0, "")
                    when += timedelta(seconds=rng.uniform(4, 20))
    rows.sort(key=lambda row: row[0])
    return [(line, label, kind) for _, line, label, kind in rows[:lines]]
