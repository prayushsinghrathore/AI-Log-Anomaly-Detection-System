"""Turn parsed log records into numeric features for anomaly detection.

The features are designed to surface the kinds of behaviour a security
analyst cares about: error bursts, unusually large/small responses,
high-frequency clients (scanners / brute-force), odd request methods,
long or suspicious URLs, and off-hours activity.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

FEATURE_COLUMNS = [
    "status",
    "bytes_log",
    "is_client_error",
    "is_server_error",
    "hour",
    "path_length",
    "ua_length",
    "method_code",
    "ip_request_count",
    "ip_error_rate",
    "ip_unique_paths",
]

# Common HTTP methods mapped to a small integer; anything unusual gets a
# distinct high code so rare methods (e.g. from scanners) stand out.
_METHOD_CODES = {"GET": 0, "POST": 1, "HEAD": 2, "PUT": 3, "DELETE": 4, "OPTIONS": 5}
_METHOD_OTHER = 9


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """Build a per-request numeric feature matrix from parsed logs.

    Returns a DataFrame indexed identically to ``df`` with the columns in
    ``FEATURE_COLUMNS``. Per-IP aggregates are broadcast back onto each row.
    """
    if df.empty:
        return pd.DataFrame(columns=FEATURE_COLUMNS)

    feats = pd.DataFrame(index=df.index)

    status = df["status"].fillna(0).astype(int)
    feats["status"] = status
    feats["bytes_log"] = np.log1p(df["bytes"].clip(lower=0))
    feats["is_client_error"] = ((status >= 400) & (status < 500)).astype(int)
    feats["is_server_error"] = (status >= 500).astype(int)

    feats["hour"] = df["datetime"].dt.hour.fillna(0).astype(int)
    feats["path_length"] = df["path"].fillna("").str.len()
    feats["ua_length"] = df["user_agent"].fillna("").str.len()
    feats["method_code"] = (
        df["method"].map(_METHOD_CODES).fillna(_METHOD_OTHER).astype(int)
    )

    # Per-IP behavioural aggregates.
    grp = df.assign(_is_err=(status >= 400).astype(int)).groupby("ip")
    ip_count = grp["ip"].transform("size")
    ip_err_rate = grp["_is_err"].transform("mean")
    ip_unique_paths = grp["path"].transform("nunique")

    feats["ip_request_count"] = ip_count.values
    feats["ip_error_rate"] = ip_err_rate.values
    feats["ip_unique_paths"] = ip_unique_paths.values

    return feats[FEATURE_COLUMNS].astype(float)
