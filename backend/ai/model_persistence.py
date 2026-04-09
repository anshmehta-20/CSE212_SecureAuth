"""
ai/model_persistence.py – Save and load sklearn models via joblib.
"""

import os
import logging
import joblib
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Persist to Config/models/ folder relative to project root
_backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_project_dir = os.path.dirname(_backend_dir)
MODELS_DIR   = os.path.join(_project_dir, 'config', 'models')

IF_PATH  = os.path.join(MODELS_DIR, 'isolation_forest.pkl')
SVM_PATH = os.path.join(MODELS_DIR, 'one_class_svm.pkl')
LOF_PATH = os.path.join(MODELS_DIR, 'local_outlier_factor.pkl')


def save_models(if_model, svm_model, lof_model):
    """Persist trained models to disk."""
    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(if_model,  IF_PATH)
    joblib.dump(svm_model, SVM_PATH)
    joblib.dump(lof_model, LOF_PATH)
    logger.info("Models saved to %s", MODELS_DIR)


def load_models() -> Optional[Tuple]:
    """Load models from disk. Returns tuple or None if not found."""
    if not all(os.path.exists(p) for p in [IF_PATH, SVM_PATH, LOF_PATH]):
        return None
    try:
        if_model  = joblib.load(IF_PATH)
        svm_model = joblib.load(SVM_PATH)
        lof_model = joblib.load(LOF_PATH)
        logger.info("Models loaded from disk.")
        return if_model, svm_model, lof_model
    except Exception as exc:
        logger.warning("Failed to load models: %s – will retrain.", exc)
        return None


def delete_models():
    """Delete cached models (force retrain on next startup)."""
    for path in [IF_PATH, SVM_PATH, LOF_PATH]:
        if os.path.exists(path):
            os.remove(path)
    logger.info("Cached models deleted.")
