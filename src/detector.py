"""Isolation Forest wrapper for log anomaly detection."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


@dataclass
class AnomalyDetector:
    """Fit/score log feature matrices with an Isolation Forest.

    Parameters
    ----------
    contamination:
        Expected proportion of anomalies. Drives the decision threshold.
    n_estimators:
        Number of trees in the forest.
    random_state:
        Seed for reproducible results.
    """

    contamination: float = 0.03
    n_estimators: int = 200
    random_state: int = 42

    def __post_init__(self) -> None:
        self._scaler = StandardScaler()
        self._model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self._fitted = False

    def fit_predict(self, features: pd.DataFrame) -> pd.DataFrame:
        """Fit on ``features`` and return per-row results.

        Returns a DataFrame with the same index as ``features`` containing:
          - ``anomaly``: bool, True if the row is flagged as anomalous
          - ``score``: raw Isolation Forest decision score (lower = more anomalous)
          - ``anomaly_score``: normalized 0..1 severity (higher = more anomalous)
        """
        if features.empty:
            return pd.DataFrame(
                columns=["anomaly", "score", "anomaly_score"]
            )

        X = self._scaler.fit_transform(features.values)
        labels = self._model.fit_predict(X)  # -1 anomaly, 1 normal
        scores = self._model.decision_function(X)
        self._fitted = True

        # Normalize so higher == more anomalous, in [0, 1].
        lo, hi = scores.min(), scores.max()
        span = (hi - lo) or 1.0
        severity = 1.0 - (scores - lo) / span

        return pd.DataFrame(
            {
                "anomaly": labels == -1,
                "score": scores,
                "anomaly_score": severity,
            },
            index=features.index,
        )
