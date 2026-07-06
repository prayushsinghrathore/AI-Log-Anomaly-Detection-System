"""Generate a synthetic access.log with realistic traffic + injected anomalies.

Usage:
    python scripts/generate_sample_logs.py --out data/sample_access.log --n 5000
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta, timezone

NORMAL_PATHS = [
    "/", "/index.html", "/about", "/products", "/products/1", "/products/2",
    "/cart", "/checkout", "/static/app.css", "/static/app.js", "/api/items",
    "/api/user/profile", "/images/logo.png", "/favicon.ico", "/blog",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]

# Suspicious paths used by the injected attack traffic.
ATTACK_PATHS = [
    "/admin", "/wp-login.php", "/.env", "/phpmyadmin", "/etc/passwd",
    "/api/user?id=1' OR '1'='1", "/../../etc/shadow", "/shell.php",
    "/wp-admin/admin-ajax.php", "/config.php.bak",
]

BOT_AGENTS = [
    "sqlmap/1.7", "Nikto/2.5", "python-requests/2.31", "curl/8.4", "-",
]

LOG_FMT = (
    '{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"'
)


def _fmt_ts(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S %z")


def _normal_ip(rnd: random.Random) -> str:
    return f"192.168.{rnd.randint(0, 5)}.{rnd.randint(1, 254)}"


def generate(n: int, seed: int = 7) -> list[str]:
    rnd = random.Random(seed)
    start = datetime(2026, 7, 5, 0, 0, 0, tzinfo=timezone.utc)
    lines: list[str] = []

    for i in range(n):
        # Traffic clusters during business hours, sparse overnight.
        t = start + timedelta(seconds=int(i * 86400 / max(n, 1)))
        roll = rnd.random()

        if roll < 0.03:
            # Anomaly: scanner / attack traffic from a small set of hostile IPs.
            ip = f"45.13.{rnd.randint(0, 3)}.{rnd.randint(1, 254)}"
            path = rnd.choice(ATTACK_PATHS)
            method = rnd.choice(["GET", "POST", "GET", "DELETE", "TRACE"])
            status = rnd.choice([401, 403, 404, 500, 404, 403])
            size = rnd.randint(0, 512)
            ua = rnd.choice(BOT_AGENTS)
        elif roll < 0.045:
            # Anomaly: unusually large data exfil-style responses.
            ip = _normal_ip(rnd)
            path = rnd.choice(["/api/export", "/download/backup.zip"])
            method = "GET"
            status = 200
            size = rnd.randint(5_000_000, 50_000_000)
            ua = rnd.choice(USER_AGENTS)
        else:
            # Normal traffic.
            ip = _normal_ip(rnd)
            path = rnd.choice(NORMAL_PATHS)
            method = rnd.choice(["GET", "GET", "GET", "POST", "HEAD"])
            status = rnd.choice([200, 200, 200, 200, 301, 304, 404])
            size = rnd.randint(200, 8000)
            ua = rnd.choice(USER_AGENTS)

        lines.append(
            LOG_FMT.format(
                ip=ip, ts=_fmt_ts(t), method=method, path=path,
                status=status, size=size, ref="-", ua=ua,
            )
        )

    return lines


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="data/sample_access.log")
    ap.add_argument("--n", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    import os

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    lines = generate(args.n, args.seed)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} log lines to {args.out}")


if __name__ == "__main__":
    main()
