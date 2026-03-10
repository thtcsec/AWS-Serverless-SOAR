"""
AWS SOAR — ML Anomaly Detection Engine
Uses Isolation Forest for behavioral anomaly detection on security events.
Falls back to statistical z-score when model is not yet trained.
"""

from __future__ import annotations

import logging
import math
from typing import Any, Dict, List, Optional

logger = logging.getLogger("aws-soar.anomaly")


class AnomalyDetector:
    """Detect anomalous security events using Isolation Forest or z-score fallback."""

    FEATURE_KEYS = [
        "hour_of_day",
        "day_of_week",
        "ip_reputation_score",
        "action_risk_level",
        "request_frequency",
    ]

    def __init__(self) -> None:
        self._model: Any = None
        self._trained = False
        self._history: List[List[float]] = []

    def train(self, historical_data: List[Dict[str, float]]) -> bool:
        """Train the Isolation Forest model on historical feature vectors."""
        if len(historical_data) < 10:
            logger.warning("Not enough data to train anomaly model (need >= 10 samples)")
            return False

        try:
            from sklearn.ensemble import IsolationForest

            features = [self._extract_features(d) for d in historical_data]
            self._history = features

            self._model = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42,
            )
            self._model.fit(features)
            self._trained = True
            logger.info(f"Anomaly model trained on {len(features)} samples")
            return True
        except ImportError:
            logger.warning("scikit-learn not available, using z-score fallback")
            self._history = [self._extract_features(d) for d in historical_data]
            return False
        except Exception as e:
            logger.error(f"Failed to train anomaly model: {e}")
            return False

    def predict(self, event_features: Dict[str, float]) -> float:
        """
        Predict anomaly score for an event.
        Returns a score from -1.0 (anomalous) to 1.0 (normal).
        """
        features = self._extract_features(event_features)

        if self._trained and self._model is not None:
            try:
                score = self._model.decision_function([features])[0]
                return float(score)
            except Exception as e:
                logger.warning(f"Model prediction failed, falling back to z-score: {e}")

        return self._zscore_fallback(features)

    def is_anomalous(self, score: float, threshold: float = -0.5) -> bool:
        """Determine if a score indicates anomalous behavior."""
        return score < threshold

    def _extract_features(self, data: Dict[str, float]) -> List[float]:
        """Extract ordered feature vector from a dict."""
        return [float(data.get(k, 0.0)) for k in self.FEATURE_KEYS]

    def _zscore_fallback(self, features: List[float]) -> float:
        """Simple z-score based anomaly detection when ML model is unavailable."""
        if len(self._history) < 2:
            return 0.0  # Not enough data, assume normal

        # Calculate mean and std for each feature
        n = len(self._history)
        total_zscore = 0.0
        feature_count = len(features)

        for i in range(feature_count):
            col = [row[i] for row in self._history]
            mean = sum(col) / n
            variance = sum((x - mean) ** 2 for x in col) / n
            std = math.sqrt(variance) if variance > 0 else 1.0

            z = abs(features[i] - mean) / std
            total_zscore += z

        avg_zscore = total_zscore / feature_count if feature_count > 0 else 0.0

        # Convert z-score to a decision_function-like score
        # High z-score → negative score (anomalous)
        if avg_zscore > 3.0:
            return -1.0
        elif avg_zscore > 2.0:
            return -0.5
        elif avg_zscore > 1.5:
            return 0.0
        else:
            return 0.5
