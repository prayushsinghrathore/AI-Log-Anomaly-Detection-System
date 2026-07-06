"""Parse web-server access logs into a structured DataFrame.

Supports the Apache/Nginx "combined" log format, e.g.:

    12.34.56.78 - - [06/Jul/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1043 "-" "Mozilla/5.0 ..."
"""

from __future__ import annotations

import re
from typing import Iterable, List

import pandas as pd

LOG_COLUMNS = [
    "ip",
    "timestamp",
    "method",
    "path",
    "protocol",
    "status",
    "bytes",
    "referer",
    "user_agent",
]

# Combined log format regex.
_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]*)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)

_TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_log_lines(lines: Iterable[str]) -> pd.DataFrame:
    """Parse an iterable of raw log lines into a normalized DataFrame.

    Unparseable lines are skipped. The returned DataFrame always has the
    columns listed in ``LOG_COLUMNS`` plus a parsed ``datetime`` column.
    """
    records: List[dict] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        match = _LOG_PATTERN.match(line)
        if not match:
            continue
        records.append(match.groupdict())

    df = pd.DataFrame(records, columns=LOG_COLUMNS)

    if df.empty:
        df["datetime"] = pd.Series(dtype="datetime64[ns, UTC]")
        return df

    # Type coercion. bytes can be "-" for empty responses.
    df["status"] = pd.to_numeric(df["status"], errors="coerce").astype("Int64")
    df["bytes"] = pd.to_numeric(
        df["bytes"].replace("-", "0"), errors="coerce"
    ).fillna(0).astype("int64")
    df["datetime"] = pd.to_datetime(
        df["timestamp"], format=_TIMESTAMP_FORMAT, errors="coerce", utc=True
    )

    return df


def parse_log_file(path: str) -> pd.DataFrame:
    """Parse a log file from disk into a normalized DataFrame."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_log_lines(fh)
