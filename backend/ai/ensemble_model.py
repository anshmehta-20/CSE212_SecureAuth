"""
ai/ensemble_model.py – 3-model ensemble: IsolationForest + One-Class SVM + LOF.

Training strategy:
  • On first use the models are trained on synthetic "normal" login patterns.
  • Fitted models are persisted to disk via model_persistence.py.
  • At inference time, each model votes (+1 = normal, -1 = anomaly).
  • The ensemble score is converted to a 0-100 risk score.
"""

import os
import sys
import logging
import numpy as np
import random
from datetime import datetime, timedelta
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ai.feature_engineering import FEATURE_NAMES

logger = logging.getLogger(__name__)

N_FEATURES = len(FEATURE_NAMES)   # 19


# ─────────────────────────────────────────────────────────────────
# Synthetic normal training data
# ─────────────────────────────────────────────────────────────────

def _generate_normal_data(n=800) -> np.ndarray:
    """
    Generate synthetic features representing *normal* logins:
      - Business hours, low IP risk, no VPN, small velocity, etc.
    """
    import math
    data = []
    for _ in range(n):
        hour  = random.choice(list(range(8, 20)))   # 8 AM – 8 PM
        dow   = random.randint(0, 4)                # Mon–Fri
        is_we = 0
        is_biz = 1
        delta_h = random.uniform(12, 48)

        loc_ch  = 0 if random.random() < 0.92 else 1
        dev_ch  = 0 if random.random() < 0.90 else 1
        vel     = random.randint(0, 2)
        typing  = random.uniform(2.8, 6.0)

        ip_risk = random.uniform(0.0, 0.25)
        vpn     = 0 if random.random() < 0.95 else 1
        ctry_ch = loc_ch

        fail_r  = random.uniform(0.0, 0.10)
        acct_age = random.randint(30, 1800)
        freq_7d = random.randint(1, 10)

        angle_h = 2 * math.pi * hour / 24
        angle_d = 2 * math.pi * dow  / 7

        row = [
            hour, dow, is_we, is_biz, delta_h,
            loc_ch, dev_ch, vel, typing,
            ip_risk, vpn, ctry_ch,
            fail_r, acct_age, freq_7d,
            math.sin(angle_h), math.cos(angle_h),
            math.sin(angle_d), math.cos(angle_d),
        ]
        data.append(row)
    return np.array(data, dtype=float)


# ─────────────────────────────────────────────────────────────────
# EnsembleModel
# ─────────────────────────────────────────────────────────────────

class EnsembleModel:
    """
    Three-model ensemble authenticator.

    Models:
      • IsolationForest  – tree-based outlier detection
      • OneClassSVM      – kernel-based boundary
      • LocalOutlierFactor (novelty=True) – density-based

    Voting: each model casts +1 (normal) or -1 (anomaly).
    """

    def __init__(self):
        self.if_model   = None   # IsolationForest
        self.svm_model  = None   # OneClassSVM
        self.lof_model  = None   # LocalOutlierFactor
        self._trained   = False

        # Lazy-import heavy deps at init time
        self._load_or_train()

    # ── Train / Load ──────────────────────────────────────────────

    def _load_or_train(self):
        from ai.model_persistence import load_models, save_models

        models = load_models()
        if models:
            self.if_model, self.svm_model, self.lof_model = models
            self._trained = True
            logger.info("Ensemble: loaded pre-trained models from disk.")
        else:
            self._train()

    def _train(self):
        from sklearn.ensemble    import IsolationForest
        from sklearn.svm         import OneClassSVM
        from sklearn.neighbors   import LocalOutlierFactor
        from ai.model_persistence import save_models

        logger.info("Ensemble: training on synthetic normal data …")
        X = _generate_normal_data(1000)

        self.if_model = IsolationForest(
            n_estimators=200,
            contamination=0.05,
            random_state=42,
        )
        self.if_model.fit(X)

        self.svm_model = OneClassSVM(
            kernel='rbf',
            nu=0.05,
            gamma='scale',
        )
        self.svm_model.fit(X)

        self.lof_model = LocalOutlierFactor(
            n_neighbors=20,
            contamination=0.05,
            novelty=True,
        )
        self.lof_model.fit(X)

        self._trained = True
        save_models(self.if_model, self.svm_model, self.lof_model)
        logger.info("Ensemble: training complete & models saved.")

    # ── Predict ───────────────────────────────────────────────────

    def predict(self, feature_vector: np.ndarray) -> dict:
        """
        Returns:
          {
            risk_score: float 0-100,
            risk_level: str,
            confidence: float 0-1,
            model_votes: dict,
            raw_scores: dict,
          }
        """
        if not self._trained:
            raise RuntimeError("Ensemble not trained yet.")

        X = feature_vector  # shape (1, N_FEATURES)

        # ── Get raw anomaly scores ────────────────────────────────
        if_score  = float(self.if_model.score_samples(X)[0])   # more negative = more anomalous
        svm_score = float(self.svm_model.score_samples(X)[0])
        lof_score = float(self.lof_model.score_samples(X)[0])

        # ── Model votes ──────────────────────────────────────────
        if_vote  = self.if_model.predict(X)[0]     # +1 or -1
        svm_vote = self.svm_model.predict(X)[0]
        lof_vote = self.lof_model.predict(X)[0]

        votes = {'IsolationForest': if_vote,
                 'OneClassSVM':     svm_vote,
                 'LocalOutlierFactor': lof_vote}

        anomaly_count = sum(1 for v in votes.values() if v == -1)

        # ── Convert to 0-100 risk score ───────────────────────────
        # Normalize each raw score to [0, 1] (higher internal score = more normal)
        def _norm(score, lo=-0.6, hi=0.1):
            """Clip and invert: high score → low risk."""
            clipped = max(lo, min(hi, score))
            normalized = (clipped - lo) / (hi - lo)   # 0 = anomalous, 1 = normal
            return 1.0 - normalized                     # flip: 0 = normal, 1 = anomalous

        r_if  = _norm(if_score,  -0.60,  0.05)
        r_svm = _norm(svm_score, -0.80,  0.05)
        r_lof = _norm(lof_score, -1.50, -0.10)

        # Weighted average (IF gets higher weight as most reliable for this use-case)
        raw_risk = (0.45 * r_if + 0.30 * r_svm + 0.25 * r_lof)

        # Bonus penalty when multiple models agree on anomaly
        if anomaly_count == 2:
            raw_risk = min(1.0, raw_risk + 0.10)
        if anomaly_count == 3:
            raw_risk = min(1.0, raw_risk + 0.20)

        risk_score = round(raw_risk * 100, 1)

        # ── Risk level ────────────────────────────────────────────
        if risk_score < 40:
            risk_level = 'LOW'
        elif risk_score < 70:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'HIGH'

        # ── Confidence ────────────────────────────────────────────
        agreement = anomaly_count if anomaly_count >= 2 else (3 - anomaly_count)
        confidence = round(0.70 + (agreement / 3) * 0.25, 2)

        normal_models = [k for k, v in votes.items() if v == 1]
        anomaly_models = [k for k, v in votes.items() if v == -1]

        return {
            'risk_score':  risk_score,
            'risk_level':  risk_level,
            'confidence':  confidence,
            'model_votes': votes,
            'anomaly_count': anomaly_count,
            'normal_models': normal_models,
            'anomaly_models': anomaly_models,
            'raw_scores': {
                'isolation_forest': round(if_score, 4),
                'one_class_svm':    round(svm_score, 4),
                'lof':              round(lof_score, 4),
            },
        }


# ── Singleton instance (loaded once per process) ──────────────────
_ensemble: Optional[EnsembleModel] = None


def get_ensemble() -> EnsembleModel:
    global _ensemble
    if _ensemble is None:
        _ensemble = EnsembleModel()
    return _ensemble
