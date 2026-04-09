"""
routes/auth.py – Authentication blueprint: login, MFA, refresh, logout.
"""

import os
import sys
import json
import logging
import hashlib
from datetime import datetime

from flask import Blueprint, request, jsonify, g

# Fix import paths
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database          import get_connection, dict_from_row, execute
from models.user       import User
from jwt_handler.jwt_manager import (
    JWTManager, store_refresh_token,
    revoke_refresh_token, is_refresh_token_valid,
)
from security.protection import (
    check_rate_limit, record_failed_ip, is_ip_brute_forced,
    reset_ip_brute, detect_credential_stuffing, get_client_ip,
)
from mfa.otp_manager   import create_mfa_session, verify_otp, send_otp_email
from ai.feature_engineering import extract_features
from ai.ensemble_model import get_ensemble
from ai.explainable_ai import generate_explanation

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__, url_prefix='/api')


# ─────────────────────────────────────────────────────────────────
# POST /api/login
# ─────────────────────────────────────────────────────────────────

@auth_bp.route('/login', methods=['POST'])
def login():
    ip   = get_client_ip()
    data = request.get_json(silent=True) or {}

    # 1. Input validation
    username = str(data.get('username', '')).strip()
    password = str(data.get('password', ''))
    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400

    # 2. Rate limit check
    blocked, msg = check_rate_limit(ip)
    if blocked:
        return jsonify({'error': msg}), 429

    # 3. IP-level brute force
    if is_ip_brute_forced(ip):
        return jsonify({
            'error': 'Too many failed attempts from your IP. Try again later.',
            'locked': True,
        }), 403

    # 4. Credential stuffing detection
    if detect_credential_stuffing(ip, username):
        return jsonify({
            'error': 'Suspicious activity: multiple usernames tried from your IP.',
        }), 403

    # 5. Find user
    user = User.find_by_username(username)
    if not user:
        record_failed_ip(ip)
        # Return same message to prevent username enumeration
        return jsonify({'error': 'Invalid credentials.'}), 401

    # 6. Account lock check
    if user.is_account_locked():
        return jsonify({
            'error': f'Account locked. Try again after {user.locked_until}.',
            'locked': True,
        }), 403

    # 7. Password verification (bcrypt)
    if not user.check_password(password):
        user.record_failed_attempt()
        record_failed_ip(ip)
        remaining = max(0, 5 - user.failed_attempts)
        return jsonify({
            'error': f'Invalid credentials. {remaining} attempt(s) remaining before lockout.',
        }), 401

    # ─ Password correct ─────────────────────────────────────────
    user.reset_failed_attempts()
    reset_ip_brute(ip)

    # 8. Pull login history for feature extraction
    history = user.get_login_history(limit=50)

    # 9. Extract features
    user_agent   = request.headers.get('User-Agent', 'unknown')
    location     = data.get('location', 'Unknown, IN')   # frontend may send geolocation hint
    typing_speed = data.get('typing_speed', None)
    if typing_speed is not None:
        try:
            typing_speed = float(typing_speed)
        except (TypeError, ValueError):
            typing_speed = None

    feature_vec = extract_features(
        user        = user,
        ip          = ip,
        user_agent  = user_agent,
        location    = location,
        typing_speed = typing_speed,
        login_history = history,
    )

    # 10. AI ensemble risk scoring
    ensemble = get_ensemble()
    result   = ensemble.predict(feature_vec)

    risk_score  = result['risk_score']
    risk_level  = result['risk_level']
    confidence  = result['confidence']
    model_votes = result['model_votes']

    # 11. SHAP explanation
    explanation = generate_explanation(
        risk_score  = risk_score,
        risk_level  = risk_level,
        feature_vector = feature_vec,
        model_votes = model_votes,
    )

    # 12. Persist AI metrics
    _save_ai_metrics(user.id, feature_vec, result, risk_score, risk_level, confidence, explanation)

    # 13. Decision
    device_hash = hashlib.md5(f"{user_agent}|{ip}".encode()).hexdigest()[:8]

    if risk_level == 'HIGH':
        # Block
        user.record_login(ip, device_hash, location, risk_score, risk_level, 'blocked', explanation)
        logger.warning("Login BLOCKED for user=%s score=%.1f", username, risk_score)
        return jsonify({
            'status':      'blocked',
            'error':       'Login blocked for security reasons.',
            'risk_score':  risk_score,
            'risk_level':  risk_level,
            'confidence':  confidence,
            'explanation': explanation,
        }), 403

    elif risk_level == 'MEDIUM':
        # Require MFA
        mfa_token, otp = create_mfa_session(user.id, result)
        send_otp_email(user.email, user.username, otp)
        user.record_login(ip, device_hash, location, risk_score, risk_level, 'mfa_required', explanation)
        logger.info("MFA required for user=%s score=%.1f", username, risk_score)
        return jsonify({
            'status':     'mfa_required',
            'message':    'Multi-factor authentication required.',
            'mfa_token':  mfa_token,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'confidence': confidence,
            'explanation': explanation,
        }), 200

    else:
        # Allow – issue tokens
        access_token            = JWTManager.create_access_token(user.id, user.username, user.role)
        refresh_token, exp      = JWTManager.create_refresh_token(user.id)
        store_refresh_token(user.id, refresh_token, exp)
        user.record_login(ip, device_hash, location, risk_score, risk_level, 'allowed', explanation)
        logger.info("Login ALLOWED for user=%s score=%.1f", username, risk_score)
        return jsonify({
            'status':        'success',
            'access_token':  access_token,
            'refresh_token': refresh_token,
            'risk_score':    risk_score,
            'risk_level':    risk_level,
            'confidence':    confidence,
            'explanation':   explanation,
            'user':          user.to_dict(),
        }), 200


# ─────────────────────────────────────────────────────────────────
# POST /api/verify-mfa
# ─────────────────────────────────────────────────────────────────

@auth_bp.route('/verify-mfa', methods=['POST'])
def verify_mfa():
    data      = request.get_json(silent=True) or {}
    mfa_token = str(data.get('mfa_token', '')).strip()
    otp_input = str(data.get('otp', '')).strip()

    if not mfa_token or not otp_input:
        return jsonify({'error': 'mfa_token and otp are required.'}), 400

    valid, reason, user_id = verify_otp(mfa_token, otp_input)

    if not valid:
        return jsonify({'error': reason}), 401

    user = User.find_by_id(user_id)
    if not user:
        return jsonify({'error': 'User not found.'}), 404

    access_token            = JWTManager.create_access_token(user.id, user.username, user.role)
    refresh_token, exp      = JWTManager.create_refresh_token(user.id)
    store_refresh_token(user.id, refresh_token, exp)

    logger.info("MFA verified for user=%s", user.username)
    return jsonify({
        'status':        'success',
        'access_token':  access_token,
        'refresh_token': refresh_token,
        'user':          user.to_dict(),
    }), 200


# ─────────────────────────────────────────────────────────────────
# POST /api/refresh
# ─────────────────────────────────────────────────────────────────

@auth_bp.route('/refresh', methods=['POST'])
def refresh():
    data          = request.get_json(silent=True) or {}
    refresh_token = str(data.get('refresh_token', '')).strip()

    if not refresh_token:
        return jsonify({'error': 'refresh_token is required.'}), 400

    if not is_refresh_token_valid(refresh_token):
        return jsonify({'error': 'Refresh token is invalid or expired.'}), 401

    payload = JWTManager.verify_refresh_token(refresh_token)
    if not payload:
        return jsonify({'error': 'Invalid refresh token.'}), 401

    user = User.find_by_id(int(payload['sub']))
    if not user:
        return jsonify({'error': 'User not found.'}), 404

    # Rotate: revoke old, issue new access token (keep refresh)
    new_access = JWTManager.create_access_token(user.id, user.username, user.role)
    return jsonify({
        'status':       'success',
        'access_token': new_access,
    }), 200


# ─────────────────────────────────────────────────────────────────
# POST /api/logout
# ─────────────────────────────────────────────────────────────────

@auth_bp.route('/logout', methods=['POST'])
def logout():
    data          = request.get_json(silent=True) or {}
    refresh_token = data.get('refresh_token', '')
    if refresh_token:
        revoke_refresh_token(refresh_token)
    return jsonify({'status': 'success', 'message': 'Logged out.'}), 200


# ─────────────────────────────────────────────────────────────────
# POST /api/resend-otp
# ─────────────────────────────────────────────────────────────────

@auth_bp.route('/resend-otp', methods=['POST'])
def resend_otp():
    data      = request.get_json(silent=True) or {}
    mfa_token = str(data.get('mfa_token', '')).strip()
    if not mfa_token:
        return jsonify({'error': 'mfa_token required.'}), 400

    ip = get_client_ip()
    blocked, msg = check_rate_limit(ip)
    if blocked:
        return jsonify({'error': msg}), 429

    # Find user from existing (unused) MFA session
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT user_id FROM mfa_tokens WHERE mfa_token=?",
            (mfa_token,)
        )
        row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        return jsonify({'error': 'Invalid MFA session.'}), 400

    user_id = row[0]
    user    = User.find_by_id(user_id)
    if not user:
        return jsonify({'error': 'User not found.'}), 404

    new_mfa_token, otp = create_mfa_session(user.id, {})
    send_otp_email(user.email, user.username, otp)

    return jsonify({
        'status':    'success',
        'mfa_token': new_mfa_token,
        'message':   'New OTP sent.',
    }), 200


# ─────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────

def _save_ai_metrics(user_id, feature_vec, result, risk_score, risk_level, confidence, explanation):
    import json as _json
    conn = get_connection()
    try:
        execute(conn,
            """INSERT INTO ai_metrics
               (user_id, feature_vector, model_votes, risk_score, risk_level, confidence, explanation)
               VALUES (?,?,?,?,?,?,?)""",
            (user_id,
             _json.dumps(feature_vec.tolist()),
             _json.dumps({k: int(v) for k, v in result['model_votes'].items()}),
             risk_score,
             risk_level,
             confidence,
             explanation))
        conn.commit()
    except Exception as exc:
        logger.warning("AI metrics save failed: %s", exc)
    finally:
        conn.close()
