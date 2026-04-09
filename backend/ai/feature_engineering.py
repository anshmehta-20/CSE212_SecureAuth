"""
ai/feature_engineering.py – Extract 15+ features from login context.
"""

import hashlib
import logging
import math
import random
from datetime import datetime, timedelta
from typing import Optional
import numpy as np

logger = logging.getLogger(__name__)

# Mock IP risk DB (high-risk CIDR prefixes)
_HIGH_RISK_PREFIXES = ['185.', '5.188.', '194.', '45.33.', '198.', '89.248.']
_VPN_PREFIXES       = ['10.', '172.16.', '172.17.', '172.18.', '172.19.',
                        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                        '172.25.']

# Feature column names (order matters for model)
FEATURE_NAMES = [
    'hour_of_day',          # 0 – temporal
    'day_of_week',          # 1
    'is_weekend',           # 2
    'is_business_hours',    # 3
    'time_since_last_login',# 4 (hours, capped at 168)
    'location_change',      # 5 – behavioral
    'device_change',        # 6
    'login_velocity',       # 7 (logins last hour)
    'typing_speed',         # 8 (chars/sec, simulated)
    'ip_risk_score',        # 9 – network
    'vpn_detected',         # 10
    'country_change',       # 11
    'failed_login_ratio',   # 12 – statistical
    'account_age_days',     # 13
    'login_frequency_7d',   # 14 (logins last 7 days)
    # bonus
    'hour_sin',             # 15 (cyclic)
    'hour_cos',             # 16 (cyclic)
    'day_sin',              # 17
    'day_cos',              # 18
]


def _cyclic(val, max_val):
    """Encode cyclic feature as (sin, cos) pair."""
    angle = 2 * math.pi * val / max_val
    return math.sin(angle), math.cos(angle)


def _hash_device(user_agent: str, ip: str) -> str:
    return hashlib.md5(f"{user_agent}|{ip}".encode()).hexdigest()[:8]


def _ip_risk(ip: str) -> float:
    """Deterministic heuristic IP risk score 0-1 based on IP hash."""
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    for prefix in _HIGH_RISK_PREFIXES:
        if ip.startswith(prefix):
            return 0.60 + (h % 35) / 100          # 0.60 – 0.95
    if ip.startswith('192.168.') or ip.startswith('127.') or ip.startswith('10.'):
        return (h % 15) / 100                      # 0.00 – 0.14
    return 0.05 + (h % 35) / 100                   # 0.05 – 0.40


def _vpn_detected(ip: str) -> int:
    for prefix in _VPN_PREFIXES:
        if ip.startswith(prefix):
            return 1
    # Randomly flag some external IPs (mock)
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16) % 100
    return 1 if h < 8 else 0          # ~8% of external IPs flagged


def extract_features(
    user,                               # User model instance
    ip: str,
    user_agent: str,
    location: str,
    typing_speed: Optional[float],
    login_history: list,               # List of recent logins (dicts)
    now: Optional[datetime] = None,
) -> np.ndarray:
    """
    Build the 19-element feature vector for the AI models.
    Returns a numpy array shaped (1, 19).
    """
    if now is None:
        now = datetime.utcnow()

    hour      = now.hour
    dow       = now.weekday()           # Mon=0 … Sun=6
    is_we     = int(dow >= 5)
    is_biz    = int(9 <= hour <= 18 and not is_we)

    # --- time since last login (hours) ---
    last_ts = None
    for h in login_history:
        try:
            last_ts = datetime.strptime(h['timestamp'], '%Y-%m-%d %H:%M:%S')
            break
        except (ValueError, KeyError, TypeError):
            continue
    if last_ts:
        delta_h = (now - last_ts).total_seconds() / 3600
    else:
        delta_h = 168.0                 # New account → max gap
    delta_h = min(delta_h, 168.0)

    # --- behavioral ---
    current_device = _hash_device(user_agent, ip)
    last_device    = login_history[0].get('device_hash', '') if login_history else ''
    device_change  = int(current_device != last_device and last_device != '')

    last_location  = login_history[0].get('location', '') if login_history else ''
    location_change = int(location != last_location and last_location != '')

    # Login velocity: logins in last hour from history
    one_hr_ago = now - timedelta(hours=1)
    velocity   = sum(
        1 for h in login_history
        if _parse_ts(h.get('timestamp', ''), now) > one_hr_ago
    )
    velocity = min(velocity, 20)

    if typing_speed is None:
        # Simulate: normal ~3-6 chars/sec; bots very fast or 0
        typing_speed = random.uniform(2.5, 6.5)

    # --- network ---
    ip_risk   = _ip_risk(ip)
    vpn       = _vpn_detected(ip)
    country_ch = location_change          # Simplified: use location change as proxy

    # --- statistical ---
    total_logins  = len(login_history)
    failed        = sum(1 for h in login_history if h.get('status') == 'blocked')
    fail_ratio    = failed / total_logins if total_logins > 0 else 0.0

    try:
        created_at  = datetime.strptime(str(user.created_at)[:19], '%Y-%m-%d %H:%M:%S')
        acct_age    = (now - created_at).days
    except Exception:
        acct_age = 365

    seven_ago = now - timedelta(days=7)
    freq_7d   = sum(
        1 for h in login_history
        if _parse_ts(h.get('timestamp', ''), now) > seven_ago
    )

    # --- cyclic ----
    h_sin, h_cos = _cyclic(hour, 24)
    d_sin, d_cos = _cyclic(dow,  7)

    vector = np.array([
        hour,
        dow,
        is_we,
        is_biz,
        delta_h,
        location_change,
        device_change,
        velocity,
        typing_speed,
        ip_risk,
        vpn,
        country_ch,
        fail_ratio,
        acct_age,
        freq_7d,
        h_sin,
        h_cos,
        d_sin,
        d_cos,
    ], dtype=float)

    return vector.reshape(1, -1)


def _parse_ts(ts_str: str, fallback: datetime) -> datetime:
    """Safe timestamp parser."""
    try:
        return datetime.strptime(ts_str[:19], '%Y-%m-%d %H:%M:%S')
    except Exception:
        return fallback - timedelta(days=999)
