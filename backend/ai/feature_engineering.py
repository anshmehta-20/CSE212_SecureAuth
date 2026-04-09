"""
ai/feature_engineering.py - Extract risk features from login context.
"""

import hashlib
import logging
import math
import random
from datetime import datetime, timedelta
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

_HIGH_RISK_PREFIXES = ['185.', '5.188.', '194.', '45.33.', '198.', '89.248.']
_VPN_PREFIXES = [
    '10.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
    '172.25.',
]
_PRIVATE_PREFIXES = [
    '127.', '10.', '192.168.',
    '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.',
    '172.24.', '172.25.', '172.26.', '172.27.',
    '172.28.', '172.29.', '172.30.', '172.31.',
]

FEATURE_NAMES = [
    'hour_of_day',
    'day_of_week',
    'is_weekend',
    'is_business_hours',
    'time_since_last_login',
    'location_change',
    'device_change',
    'login_velocity',
    'typing_speed',
    'ip_risk_score',
    'vpn_detected',
    'country_change',
    'failed_login_ratio',
    'account_age_days',
    'login_frequency_7d',
    'hour_sin',
    'hour_cos',
    'day_sin',
    'day_cos',
]


def _cyclic(val, max_val):
    angle = 2 * math.pi * val / max_val
    return math.sin(angle), math.cos(angle)


def _hash_device(user_agent: str, ip: str) -> str:
    return hashlib.md5(f"{user_agent}|{ip}".encode()).hexdigest()[:8]


def _is_private_ip(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in _PRIVATE_PREFIXES)


def _ip_risk(ip: str) -> float:
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    for prefix in _HIGH_RISK_PREFIXES:
        if ip.startswith(prefix):
            return 0.60 + (h % 35) / 100
    if _is_private_ip(ip):
        return (h % 15) / 100
    return 0.05 + (h % 35) / 100


def _vpn_detected(ip: str) -> int:
    if _is_private_ip(ip):
        return 0
    for prefix in _VPN_PREFIXES:
        if ip.startswith(prefix):
            return 1
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16) % 100
    return 1 if h < 8 else 0


def extract_features(
    user,
    ip: str,
    user_agent: str,
    location: str,
    typing_speed: Optional[float],
    login_history: list,
    now: Optional[datetime] = None,
) -> np.ndarray:
    if now is None:
        now = datetime.utcnow()

    hour = now.hour
    dow = now.weekday()
    is_we = int(dow >= 5)
    is_biz = int(9 <= hour <= 18 and not is_we)

    last_ts = None
    for item in login_history:
        try:
            last_ts = datetime.strptime(item['timestamp'], '%Y-%m-%d %H:%M:%S')
            break
        except (ValueError, KeyError, TypeError):
            continue

    delta_h = 168.0
    if last_ts:
        delta_h = min((now - last_ts).total_seconds() / 3600, 168.0)

    current_device = _hash_device(user_agent, ip)
    last_device = login_history[0].get('device_hash', '') if login_history else ''
    device_change = int(current_device != last_device and last_device != '')

    last_location = login_history[0].get('location', '') if login_history else ''
    location_change = int(location != last_location and last_location != '')

    one_hr_ago = now - timedelta(hours=1)
    velocity = sum(1 for item in login_history if _parse_ts(item.get('timestamp', ''), now) > one_hr_ago)
    velocity = min(velocity, 20)

    if typing_speed is None:
        typing_speed = random.uniform(2.5, 6.5)

    ip_risk = _ip_risk(ip)
    vpn = _vpn_detected(ip)
    country_ch = location_change

    total_logins = len(login_history)
    blocked = sum(1 for item in login_history if item.get('status') == 'blocked')
    fail_ratio = blocked / total_logins if total_logins > 0 else 0.0

    try:
        created_at = datetime.strptime(str(user.created_at)[:19], '%Y-%m-%d %H:%M:%S')
        acct_age = (now - created_at).days
    except Exception:
        acct_age = 365

    seven_ago = now - timedelta(days=7)
    freq_7d = sum(1 for item in login_history if _parse_ts(item.get('timestamp', ''), now) > seven_ago)

    h_sin, h_cos = _cyclic(hour, 24)
    d_sin, d_cos = _cyclic(dow, 7)

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
    try:
        return datetime.strptime(ts_str[:19], '%Y-%m-%d %H:%M:%S')
    except Exception:
        return fallback - timedelta(days=999)
