"""
ai/explainable_ai.py – SHAP-based human-readable explanation of risk decisions.
"""

import logging
import numpy as np
from typing import Optional

from ai.feature_engineering import FEATURE_NAMES

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
# SHAP explainer (KernelExplainer works for all sklearn models)
# ─────────────────────────────────────────────────────────────────

def _get_explainer(model, background_data: np.ndarray):
    """Return a SHAP explainer for the given model."""
    try:
        import shap
        # Use TreeExplainer for IsolationForest, KernelExplainer for others
        model_type = type(model).__name__
        if model_type == 'IsolationForest':
            return shap.TreeExplainer(model)
        else:
            # KernelExplainer needs a small background sample
            bg = shap.sample(background_data, min(50, len(background_data)))
            return shap.KernelExplainer(model.score_samples, bg)
    except Exception as exc:
        logger.warning("SHAP explainer init failed: %s", exc)
        return None


def compute_shap_values(model, feature_vector: np.ndarray, background: np.ndarray):
    """Compute SHAP values for the given feature vector."""
    explainer = _get_explainer(model, background)
    if explainer is None:
        return None
    try:
        import shap
        shap_values = explainer.shap_values(feature_vector)
        if isinstance(shap_values, list):
            shap_values = shap_values[0]
        return shap_values.flatten()
    except Exception as exc:
        logger.warning("SHAP computation failed: %s", exc)
        return None


# ─────────────────────────────────────────────────────────────────
# Human-readable explanation generator
# ─────────────────────────────────────────────────────────────────

_FEATURE_TEMPLATES = {
    'hour_of_day': {
        'high':  'Login at {val:.0f}:00 is very unusual (typically associated with attacks)',
        'low':   'Login time ({val:.0f}:00) is within normal hours',
    },
    'is_weekend': {
        'high':  'Login on a weekend is unusual for this account',
        'low':   'Weekday login matches your normal pattern',
    },
    'is_business_hours': {
        'high':  'Login outside business hours raises suspicion',
        'low':   'Login during business hours – expected',
    },
    'time_since_last_login': {
        'high':  'Very long gap since last login ({val:.0f}h) – possible account takeover',
        'low':   'Login frequency matches your typical pattern',
    },
    'location_change': {
        'high':  'Location is different from your usual locations – possible travel or attack',
        'low':   'Login from a familiar location',
    },
    'device_change': {
        'high':  'New device detected – first time logging in from this device',
        'low':   'Recognized device',
    },
    'login_velocity': {
        'high':  'Multiple login attempts in a short window – possible credential stuffing',
        'low':   'Login rate is normal',
    },
    'typing_speed': {
        'high':  'Unusual input speed – possible automated script',
        'low':   'Typing speed appears human-like',
    },
    'ip_risk_score': {
        'high':  'IP address has a high risk score ({val:.0%}) – known malicious range',
        'low':   'IP address appears clean',
    },
    'vpn_detected': {
        'high':  'VPN or proxy detected – often used to hide true location',
        'low':   'No VPN detected',
    },
    'country_change': {
        'high':  'Country change detected since last login',
        'low':   'Same country as previous logins',
    },
    'failed_login_ratio': {
        'high':  'High ratio of failed logins ({val:.0%}) – brute force indicator',
        'low':   'Low failed login ratio – normal',
    },
}


def generate_explanation(
    risk_score: float,
    risk_level: str,
    feature_vector: np.ndarray,
    model_votes: dict,
    shap_values: Optional[np.ndarray] = None,
) -> str:
    """
    Build a human-readable, SHAP-informed explanation string.
    Falls back to heuristic rules if SHAP is unavailable.
    """
    fv = feature_vector.flatten()
    fmap = dict(zip(FEATURE_NAMES, fv))

    # ── Determine weights ────────────────────────────────────────
    if shap_values is not None and len(shap_values) == len(FEATURE_NAMES):
        weights = dict(zip(FEATURE_NAMES, np.abs(shap_values)))
    else:
        weights = _heuristic_weights(fmap)

    # Top contributing features (highest absolute SHAP)
    top_features = sorted(weights.items(), key=lambda x: x[1], reverse=True)[:6]

    # ── Build bullet points ──────────────────────────────────────
    bullets = []
    for feat_name, weight in top_features:
        if weight < 0.01:
            continue
        val    = fmap.get(feat_name, 0)
        tmpl   = _FEATURE_TEMPLATES.get(feat_name)
        if tmpl is None:
            continue
        # Determine if this feature is flagging high or low risk
        is_risky = _is_risky(feat_name, val)
        key      = 'high' if is_risky else 'low'
        try:
            bullet = tmpl[key].format(val=val)
        except (KeyError, ValueError):
            bullet = tmpl[key]
        if is_risky or risk_level != 'LOW':
            bullets.append(('⚠️' if is_risky else '✅', bullet))

    # ── Header ──────────────────────────────────────────────────
    if risk_level == 'LOW':
        header  = '✅ LOGIN ALLOWED\n'
        summary = 'Login appears normal. Welcome back!'
    elif risk_level == 'MEDIUM':
        header  = '⚠️  MEDIUM RISK – MFA REQUIRED\n'
        summary = 'Some unusual patterns detected. Additional verification needed.'
    else:
        header  = '🚫 LOGIN BLOCKED\n'
        summary = 'Multiple high-risk indicators detected. For your security, we\'ve blocked this attempt.'

    # ── Models voted ─────────────────────────────────────────────
    anomaly_models = [k for k, v in model_votes.items() if v == -1]
    model_line     = ''
    if anomaly_models:
        model_line = f'\nModels flagged: {", ".join(anomaly_models)}'

    # ── Assemble ─────────────────────────────────────────────────
    analysis_lines = '\n'.join(
        f'  • {emoji} {text}' for emoji, text in bullets
    ) if bullets else '  • Login appears normal. Welcome back!'

    explanation = (
        f'{header}\n'
        f'Risk Score: {risk_score:.0f}/100\n\n'
        f'Summary: {summary}\n\n'
        f'Analysis:\n{analysis_lines}'
        f'{model_line}\n\n'
        f'Recommendation: {"Contact support if this wasn\'t you." if risk_level == "HIGH" else "Review if unexpected."}'
    )
    return explanation


def _is_risky(feature: str, value: float) -> bool:
    """Heuristic: is the feature value in a risky range?"""
    rules = {
        'hour_of_day':          lambda v: v < 6 or v > 22,
        'is_weekend':           lambda v: v == 1,
        'is_business_hours':    lambda v: v == 0,
        'time_since_last_login':lambda v: v > 96,
        'location_change':      lambda v: v == 1,
        'device_change':        lambda v: v == 1,
        'login_velocity':       lambda v: v >= 5,
        'typing_speed':         lambda v: v < 1.0 or v > 15,
        'ip_risk_score':        lambda v: v > 0.5,
        'vpn_detected':         lambda v: v == 1,
        'country_change':       lambda v: v == 1,
        'failed_login_ratio':   lambda v: v > 0.3,
        'account_age_days':     lambda v: v < 3,
        'login_frequency_7d':   lambda v: v > 30,
    }
    fn = rules.get(feature)
    return bool(fn(value)) if fn else False


def _heuristic_weights(fmap: dict) -> dict:
    """Fallback weights when SHAP is unavailable."""
    weights = {}
    for feat, val in fmap.items():
        if _is_risky(feat, val):
            weights[feat] = 0.5
        else:
            weights[feat] = 0.1
    return weights
