"""
ai/explainable_ai.py - Human-readable explanation generation for risk decisions.
"""

import logging
from typing import Optional

import numpy as np

from ai.feature_engineering import FEATURE_NAMES

logger = logging.getLogger(__name__)


def _get_explainer(model, background_data: np.ndarray):
    try:
        import shap

        model_type = type(model).__name__
        if model_type == 'IsolationForest':
            return shap.TreeExplainer(model)

        bg = shap.sample(background_data, min(50, len(background_data)))
        return shap.KernelExplainer(model.score_samples, bg)
    except Exception as exc:
        logger.warning("SHAP explainer init failed: %s", exc)
        return None


def compute_shap_values(model, feature_vector: np.ndarray, background: np.ndarray):
    explainer = _get_explainer(model, background)
    if explainer is None:
        return None

    try:
        shap_values = explainer.shap_values(feature_vector)
        if isinstance(shap_values, list):
            shap_values = shap_values[0]
        return shap_values.flatten()
    except Exception as exc:
        logger.warning("SHAP computation failed: %s", exc)
        return None


_FEATURE_TEMPLATES = {
    'hour_of_day': {
        'high': 'Login at {val:.0f}:00 is outside the usual pattern for this account',
        'low': 'Login time ({val:.0f}:00) falls within the normal pattern',
    },
    'is_weekend': {
        'high': 'Weekend activity is less common for this account',
        'low': 'Weekday timing matches the account history',
    },
    'is_business_hours': {
        'high': 'Login happened outside business hours',
        'low': 'Login happened during business hours',
    },
    'time_since_last_login': {
        'high': 'There has been a long gap since the last login ({val:.0f}h)',
        'low': 'Time since the last login is consistent with recent activity',
    },
    'location_change': {
        'high': 'Location differs from the most recent trusted login',
        'low': 'Location matches the recent trusted pattern',
    },
    'device_change': {
        'high': 'This looks like a new device for the account',
        'low': 'Device fingerprint matches the recent trusted pattern',
    },
    'login_velocity': {
        'high': 'There have been multiple attempts in a short window',
        'low': 'Login attempt rate looks normal',
    },
    'typing_speed': {
        'high': 'Typing speed looks unusual for a normal interactive login',
        'low': 'Typing speed looks human and consistent',
    },
    'ip_risk_score': {
        'high': 'IP reputation is elevated ({val:.0%})',
        'low': 'IP reputation looks acceptable for this login',
    },
    'vpn_detected': {
        'high': 'A VPN or proxy signal was detected for this request',
        'low': 'No VPN or proxy signal was detected',
    },
    'country_change': {
        'high': 'Country differs from the recent login pattern',
        'low': 'Country matches the recent login pattern',
    },
    'failed_login_ratio': {
        'high': 'The account history contains a high share of blocked attempts ({val:.0%})',
        'low': 'Blocked-attempt history for this account is low',
    },
    'account_age_days': {
        'high': 'This is still a very new account ({val:.0f} days old)',
        'low': 'The account has an established trust history',
    },
    'login_frequency_7d': {
        'high': 'Recent 7-day login frequency ({val:.0f}) is unusually high',
        'low': 'Recent 7-day login frequency looks stable',
    },
}


def generate_explanation(
    risk_score: float,
    risk_level: str,
    feature_vector: np.ndarray,
    model_votes: dict,
    shap_values: Optional[np.ndarray] = None,
) -> str:
    fv = feature_vector.flatten()
    fmap = dict(zip(FEATURE_NAMES, fv))

    if shap_values is not None and len(shap_values) == len(FEATURE_NAMES):
        weights = dict(zip(FEATURE_NAMES, np.abs(shap_values)))
    else:
        weights = _heuristic_weights(fmap)

    risky, reassuring = _rank_features(fmap, weights)
    bullets = _build_bullets(risk_level, risky, reassuring)

    anomaly_models = [name for name, vote in model_votes.items() if vote == -1]
    if risk_level == 'MEDIUM' and not risky and anomaly_models:
        bullets = [('ALERT', _model_consensus_note(anomaly_models))] + bullets

    if risk_level == 'LOW':
        header = 'LOGIN ALLOWED'
        summary = 'This login closely matches the trusted pattern for the account.'
    elif risk_level == 'MEDIUM':
        header = 'MEDIUM RISK - MFA REQUIRED'
        summary = _medium_summary(risky, anomaly_models)
    else:
        header = 'LOGIN BLOCKED'
        summary = _high_summary(risky)

    if anomaly_models:
        model_line = f"Models flagged: {', '.join(anomaly_models)}"
    else:
        model_line = 'Models flagged: none'

    analysis_lines = '\n'.join(f"  - {emoji} {text}" for emoji, text in bullets)
    if not analysis_lines:
        analysis_lines = '  - Login appears normal.'

    recommendation = "Contact support if this wasn't you." if risk_level == 'HIGH' else 'Review if unexpected.'

    return (
        f'{header}\n\n'
        f'Risk Score: {risk_score:.0f}/100\n\n'
        f'Summary: {summary}\n\n'
        f'Analysis:\n{analysis_lines}\n'
        f'{model_line}\n\n'
        f'Recommendation: {recommendation}'
    )


def _is_risky(feature: str, value: float) -> bool:
    rules = {
        'hour_of_day': lambda v: v < 6 or v > 22,
        'is_weekend': lambda v: v == 1,
        'is_business_hours': lambda v: v == 0,
        'time_since_last_login': lambda v: v > 96,
        'location_change': lambda v: v == 1,
        'device_change': lambda v: v == 1,
        'login_velocity': lambda v: v >= 5,
        'typing_speed': lambda v: v < 1.0 or v > 15.0,
        'ip_risk_score': lambda v: v > 0.5,
        'vpn_detected': lambda v: v == 1,
        'country_change': lambda v: v == 1,
        'failed_login_ratio': lambda v: v > 0.3,
        'account_age_days': lambda v: v < 7,
        'login_frequency_7d': lambda v: v > 30,
    }
    checker = rules.get(feature)
    return bool(checker(value)) if checker else False


def _heuristic_weights(fmap: dict) -> dict:
    return {feature: _feature_weight(feature, value) for feature, value in fmap.items()}


def _feature_weight(feature: str, value: float) -> float:
    if feature in {'location_change', 'device_change', 'country_change'}:
        return 1.0 if value == 1 else 0.45
    if feature == 'failed_login_ratio':
        return min(1.0, 0.2 + value * 1.5)
    if feature == 'ip_risk_score':
        return min(1.0, max(0.2, value))
    if feature == 'vpn_detected':
        return 0.85 if value == 1 else 0.3
    if feature == 'time_since_last_login':
        return 0.85 if value > 96 else (0.55 if value > 48 else 0.3)
    if feature == 'login_velocity':
        return 0.9 if value >= 5 else (0.45 if value >= 3 else 0.25)
    if feature == 'account_age_days':
        if value < 7:
            return 0.8
        if value < 30:
            return 0.5
        return 0.35
    if feature == 'login_frequency_7d':
        return 0.8 if value > 30 else 0.25
    if feature in {'hour_of_day', 'is_weekend', 'is_business_hours', 'typing_speed'}:
        return 0.55 if _is_risky(feature, value) else 0.25
    return 0.2


def _rank_features(fmap: dict, weights: dict):
    risky = []
    reassuring = []

    for feature, weight in weights.items():
        template = _FEATURE_TEMPLATES.get(feature)
        if template is None or weight < 0.2:
            continue

        value = fmap.get(feature, 0)
        risky_flag = _is_risky(feature, value)
        key = 'high' if risky_flag else 'low'
        text = template[key].format(val=value)

        if risky_flag:
            risky.append((weight, 'ALERT', text))
        else:
            reassuring.append((weight, 'OK', text))

    risky.sort(key=lambda item: item[0], reverse=True)
    reassuring.sort(key=lambda item: item[0], reverse=True)
    return risky, reassuring


def _build_bullets(risk_level: str, risky: list, reassuring: list):
    if risk_level == 'LOW':
        selected = reassuring[:4]
        if not selected:
            selected = risky[:2]
    elif risk_level == 'MEDIUM':
        selected = risky[:3] + reassuring[:1]
        if not risky:
            selected = reassuring[:3]
    else:
        selected = risky[:4] + reassuring[:1]

    return [(marker, text) for _, marker, text in selected]


def _medium_summary(risky: list, anomaly_models: list) -> str:
    if risky:
        reasons = ', '.join(text.lower().rstrip('.') for _, _, text in risky[:2])
        return f'Additional verification is required because we detected {reasons}.'
    if anomaly_models:
        return 'The login looks mostly consistent, but multiple anomaly models still requested extra verification.'
    return 'Some unusual patterns were detected, so extra verification is required.'


def _high_summary(risky: list) -> str:
    if risky:
        reasons = ', '.join(text.lower().rstrip('.') for _, _, text in risky[:2])
        return f'This attempt was blocked because we detected {reasons}.'
    return 'Multiple high-risk indicators were detected, so the attempt was blocked.'


def _model_consensus_note(anomaly_models: list) -> str:
    count = len(anomaly_models)
    if count == 1:
        return f'{anomaly_models[0]} flagged the overall pattern as unusual, so extra verification is required'
    return f'{count} anomaly models flagged the overall pattern as unusual, so extra verification is required'
