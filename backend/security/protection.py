"""
security/protection.py – Rate limiting, brute force, credential stuffing detection.

Implemented as an in-memory + DB backed tracker (no Redis needed for MVP).
"""

import os
import time
import logging
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify

logger = logging.getLogger(__name__)

RATE_LIMIT_WINDOW  = 60        # seconds
RATE_LIMIT_MAX_REQ = int(os.getenv('RATE_LIMIT_MAX', 20))
MAX_ATTEMPTS       = int(os.getenv('MAX_LOGIN_ATTEMPTS', 5))
LOCKOUT_SECS       = int(os.getenv('LOCKOUT_MINUTES', 15)) * 60

# ── In-memory stores (thread-safe) ───────────────────────────────
_rate_lock  = threading.Lock()
_brute_lock = threading.Lock()

# ip -> list of timestamps
_ip_requests: dict[str, list] = defaultdict(list)

# ip -> {count, first_attempt}
_brute_force: dict[str, dict] = {}

# credential stuffing: { (ip, username_set_hash) -> attempt count }
_stuffing: dict[tuple, int] = defaultdict(int)


# ─────────────────────────────────────────────────────────────────
# Rate Limiting
# ─────────────────────────────────────────────────────────────────

def check_rate_limit(ip: str) -> tuple[bool, str]:
    """
    Returns (is_blocked, message).
    Sliding-window rate limiter: max RATE_LIMIT_MAX_REQ per 60 sec.
    """
    now = time.time()
    with _rate_lock:
        timestamps = _ip_requests[ip]
        # Prune old
        timestamps[:] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
        timestamps.append(now)

        if len(timestamps) > RATE_LIMIT_MAX_REQ:
            wait = int(RATE_LIMIT_WINDOW - (now - timestamps[0]))
            logger.warning("Rate limit hit: IP=%s, count=%d", ip, len(timestamps))
            return True, f"Too many requests. Try again in {wait}s."
    return False, ""


# ─────────────────────────────────────────────────────────────────
# Brute Force Tracker (IP-level, separate from User model account lock)
# ─────────────────────────────────────────────────────────────────

def record_failed_ip(ip: str):
    """Track failed logins at the IP level."""
    with _brute_lock:
        if ip not in _brute_force:
            _brute_force[ip] = {'count': 0, 'since': time.time()}
        entry = _brute_force[ip]

        # Reset if window expired
        if time.time() - entry['since'] > LOCKOUT_SECS:
            _brute_force[ip] = {'count': 0, 'since': time.time()}
            entry = _brute_force[ip]

        entry['count'] += 1
        logger.info("Brute force counter IP=%s count=%d", ip, entry['count'])


def is_ip_brute_forced(ip: str) -> bool:
    with _brute_lock:
        entry = _brute_force.get(ip)
        if not entry:
            return False
        if time.time() - entry['since'] > LOCKOUT_SECS:
            _brute_force.pop(ip, None)
            return False
        return entry['count'] >= MAX_ATTEMPTS


def reset_ip_brute(ip: str):
    with _brute_lock:
        _brute_force.pop(ip, None)


# ─────────────────────────────────────────────────────────────────
# Credential Stuffing Detection
# ─────────────────────────────────────────────────────────────────

_stuffing_window   = 30     # seconds
_stuffing_max_users = 4     # distinct usernames from one IP in window

# ip -> list of (timestamp, username)
_stuffing_attempts: dict[str, list] = defaultdict(list)


def detect_credential_stuffing(ip: str, username: str) -> bool:
    """
    Flag if a single IP is trying many different usernames rapidly.
    Classic credential stuffing signature.
    """
    now = time.time()
    with _brute_lock:
        entries = _stuffing_attempts[ip]
        entries[:] = [(t, u) for t, u in entries if now - t < _stuffing_window]
        entries.append((now, username))

        distinct = len({u for _, u in entries})
        if distinct >= _stuffing_max_users:
            logger.warning("Credential stuffing detected: IP=%s distinct_users=%d", ip, distinct)
            return True
    return False


# ─────────────────────────────────────────────────────────────────
# Flask decorator
# ─────────────────────────────────────────────────────────────────

def rate_limited(f):
    """Decorator: apply rate limiting to a Flask route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        ip      = _get_client_ip()
        blocked, msg = check_rate_limit(ip)
        if blocked:
            return jsonify({'error': msg, 'retry_after': RATE_LIMIT_WINDOW}), 429
        return f(*args, **kwargs)
    return decorated


def security_headers(response):
    """Add security headers to every response."""
    response.headers['X-Content-Type-Options']  = 'nosniff'
    response.headers['X-Frame-Options']          = 'DENY'
    response.headers['X-XSS-Protection']         = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy']  = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "connect-src 'self' http://localhost:* http://127.0.0.1:*"
    )
    return response


def _get_client_ip() -> str:
    """Best-effort client IP extraction (handles proxies)."""
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'


# Export the helper so routes can use it
get_client_ip = _get_client_ip
