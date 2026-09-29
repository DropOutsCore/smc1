"""
securemailscope/ml/classifier.py
-----------------------------------
Risk classification and anomaly detection.

Risk Classifier (RandomForestClassifier)
-----------------------------------------
Trained using weak supervision from the rule engine — rules produce
guaranteed-correct labels so the model works from day one without
hand-labeled data. The model can then generalize beyond explicit rules.

feature_importances_ are exposed for explainability: every prediction
surfaces the top contributing feature names so analysts understand WHY
a session is rated high-risk.

Anomaly Detector (IsolationForest)
------------------------------------
Trained on the observed session baseline (all sessions in a PCAP).
Flags sessions that deviate from the learned normal, catching
misconfigurations or attack patterns the rule engine has no rule for yet.

Model persistence
-----------------
Models are saved with joblib.  Retraining is a separate CLI command
(`securemailscope retrain`) and is NEVER invoked during analysis.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from securemailscope.ml.features import FEATURE_NAMES, NUM_FEATURES

logger = logging.getLogger(__name__)

_MODELS_DIR = Path(__file__).parent / "models"
_CLASSIFIER_PATH = _MODELS_DIR / "risk_classifier.joblib"
_ANOMALY_PATH = _MODELS_DIR / "anomaly_detector.joblib"

# Risk label mapping
RISK_LABELS = ["low", "medium", "high", "critical"]
_LABEL_TO_INT = {lab: i for i, lab in enumerate(RISK_LABELS)}
_INT_TO_LABEL = {i: lab for i, lab in enumerate(RISK_LABELS)}


class RiskClassifier:
    """
    Wrapper around scikit-learn RandomForestClassifier.

    Can be used in two modes:
    1. Loaded from disk (normal analysis) — load()
    2. Rule-supervised inline training — train_from_rule_labels()
    """

    def __init__(self):
        self._model: Optional[RandomForestClassifier] = None
        self._is_trained = False

    def load(self) -> bool:
        """Load a previously trained model from disk. Returns True if successful."""
        if not _CLASSIFIER_PATH.exists():
            logger.info("No saved risk classifier found at %s", _CLASSIFIER_PATH)
            return False
        try:
            self._model = joblib.load(_CLASSIFIER_PATH)
            self._is_trained = True
            logger.info("Loaded risk classifier from %s", _CLASSIFIER_PATH)
            return True
        except Exception as exc:
            logger.warning("Failed to load risk classifier: %s", exc)
            return False

    def save(self) -> None:
        """Persist the trained model to disk."""
        if self._model is None:
            raise RuntimeError("No model to save — train first.")
        _MODELS_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._model, _CLASSIFIER_PATH)
        logger.info("Saved risk classifier to %s", _CLASSIFIER_PATH)

    def train_from_rule_labels(
        self,
        feature_matrix: np.ndarray,
        rule_severity_labels: list[str],
    ) -> None:
        """
        Train using rule-engine outputs as weak-supervision labels.

        Parameters
        ----------
        feature_matrix : np.ndarray, shape (n_sessions, NUM_FEATURES)
        rule_severity_labels : list[str]
            Per-session highest severity from the rule engine.
            Values must be in RISK_LABELS.
        """
        if len(feature_matrix) < 4:
            logger.warning("Too few samples (%d) to train classifier.", len(feature_matrix))
            return

        y = np.array([_LABEL_TO_INT.get(lab, 0) for lab in rule_severity_labels])
        self._model = RandomForestClassifier(
            n_estimators=200,
            max_depth=8,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(feature_matrix, y)
        self._is_trained = True
        logger.info(
            "Trained risk classifier on %d samples, %d features",
            len(feature_matrix), NUM_FEATURES,
        )

    def predict(self, feature_vector: np.ndarray) -> tuple[str, float, list[str]]:
        """
        Predict risk label for one session.

        Returns
        -------
        (label, confidence, contributing_factors)
            label — one of RISK_LABELS
            confidence — probability of the predicted class [0,1]
            contributing_factors — top-5 feature names by importance
        """
        if not self._is_trained or self._model is None:
            return "unknown", 0.0, []

        x = feature_vector.reshape(1, -1)
        proba = self._model.predict_proba(x)[0]
        pred_idx = int(np.argmax(proba))
        label = _INT_TO_LABEL.get(pred_idx, "unknown")
        confidence = float(proba[pred_idx])

        # Explainability: top features by importance × feature value
        importances = self._model.feature_importances_
        weighted = importances * np.abs(feature_vector)
        top_indices = np.argsort(weighted)[::-1][:5]
        contributing_factors = [
            f"{FEATURE_NAMES[i]} (importance={importances[i]:.3f})"
            for i in top_indices
            if importances[i] > 0.001
        ]

        return label, confidence, contributing_factors


class AnomalyDetector:
    """
    IsolationForest-based anomaly detector.

    Trained on the full set of sessions in a PCAP to establish a
    per-environment normal baseline.  Negative scores (below 0) indicate
    anomalous sessions — the further below 0, the more anomalous.
    """

    def __init__(self):
        self._model: Optional[IsolationForest] = None

    def load(self) -> bool:
        if not _ANOMALY_PATH.exists():
            return False
        try:
            self._model = joblib.load(_ANOMALY_PATH)
            logger.info("Loaded anomaly detector from %s", _ANOMALY_PATH)
            return True
        except Exception as exc:
            logger.warning("Failed to load anomaly detector: %s", exc)
            return False

    def save(self) -> None:
        if self._model is None:
            raise RuntimeError("No model to save — fit first.")
        _MODELS_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._model, _ANOMALY_PATH)
        logger.info("Saved anomaly detector to %s", _ANOMALY_PATH)

    def fit(self, feature_matrix: np.ndarray) -> None:
        """Fit the anomaly detector on all sessions (unsupervised)."""
        if len(feature_matrix) < 2:
            logger.warning("Too few samples to fit anomaly detector.")
            return
        contamination = min(0.1, max(0.01, 1.0 / len(feature_matrix)))
        self._model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(feature_matrix)
        self._is_fitted = True
        logger.info("Fitted anomaly detector on %d sessions", len(feature_matrix))

    def score(self, feature_vector: np.ndarray) -> tuple[bool, float]:
        """
        Score one session for anomaly.

        Returns
        -------
        (is_anomaly, anomaly_score)
            is_anomaly — True if the session is an outlier
            anomaly_score — raw decision function score (negative = anomalous)
        """
        if self._model is None:
            return False, 0.0
        x = feature_vector.reshape(1, -1)
        score = float(self._model.decision_function(x)[0])
        prediction = int(self._model.predict(x)[0])
        is_anomaly = prediction == -1
        return is_anomaly, score
