"""
routes/dashboard.py – MySQL-compatible dashboard & admin routes.
"""

import os, sys, logging
from datetime import datetime, timedelta
from functools import wraps
from flask import Blueprint, request, jsonify

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database          import get_connection, dict_from_row, execute
from models.user       import User
from jwt_handler.jwt_manager import JWTManager

logger  = logging.getLogger(__name__)
dash_bp = Blueprint('dashboard', __name__, url_prefix='/api')


# ── Auth guards ───────────────────────────────────────────────────

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Authorization header missing.'}), 401
        payload = JWTManager.verify_access_token(auth[7:])
        if not payload:
            return jsonify({'error': 'Token expired or invalid.'}), 401
        request.user_id   = int(payload['sub'])
        request.username  = payload.get('username')
        request.user_role = payload.get('role', 'user')
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    @wraps(f)
    @require_auth
    def decorated(*args, **kwargs):
        if getattr(request, 'user_role', 'user') != 'admin':
            return jsonify({'error': 'Admin access required.'}), 403
        return f(*args, **kwargs)
    return decorated


# ── Endpoints ─────────────────────────────────────────────────────

@dash_bp.route('/me', methods=['GET'])
@require_auth
def me():
    user = User.find_by_id(request.user_id)
    if not user:
        return jsonify({'error': 'User not found.'}), 404
    return jsonify({'status': 'success', 'user': user.to_dict()}), 200


@dash_bp.route('/history', methods=['GET'])
@require_auth
def history():
    user = User.find_by_id(request.user_id)
    if not user:
        return jsonify({'error': 'User not found.'}), 404
    limit   = min(int(request.args.get('limit', 20)), 100)
    entries = user.get_login_history(limit=limit)
    return jsonify({'status': 'success', 'history': entries, 'count': len(entries)}), 200


@dash_bp.route('/risk-summary', methods=['GET'])
@require_auth
def risk_summary():
    conn = get_connection()
    try:
        cur = execute(conn,
            """SELECT risk_score, risk_level, confidence, explanation, timestamp
               FROM ai_metrics WHERE user_id=?
               ORDER BY timestamp DESC LIMIT 1""",
            (request.user_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({'status': 'success', 'data': None}), 200
        return jsonify({'status': 'success', 'data': dict_from_row(row)}), 200
    finally:
        conn.close()


@dash_bp.route('/analytics', methods=['GET'])
@require_admin
def analytics():
    conn = get_connection()
    try:
        since_7d = (datetime.utcnow() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')

        cur = execute(conn, "SELECT COUNT(*) AS cnt FROM login_history WHERE timestamp >= ?", (since_7d,))
        total_7d = dict_from_row(cur.fetchone()).get('cnt', 0)

        cur = execute(conn,
            "SELECT status, COUNT(*) AS cnt FROM login_history WHERE timestamp >= ? GROUP BY status",
            (since_7d,))
        status_breakdown = {r['status'] if isinstance(r, dict) else dict_from_row(r)['status']:
                            r['cnt'] if isinstance(r, dict) else dict_from_row(r)['cnt']
                            for r in cur.fetchall()}

        cur = execute(conn,
            "SELECT risk_level, COUNT(*) AS cnt FROM login_history WHERE timestamp >= ? GROUP BY risk_level",
            (since_7d,))
        risk_dist = {dict_from_row(r).get('risk_level', ''): dict_from_row(r).get('cnt', 0)
                     for r in cur.fetchall()}

        cur = execute(conn,
            """SELECT DATE(timestamp) AS day, COUNT(*) AS cnt
               FROM login_history WHERE timestamp >= ?
               GROUP BY DATE(timestamp) ORDER BY day""",
            (since_7d,))
        daily = [{'date': str(dict_from_row(r)['day']), 'count': dict_from_row(r)['cnt']}
                 for r in cur.fetchall()]

        cur = execute(conn,
            """SELECT u.username, AVG(lh.risk_score) AS avg_risk
               FROM login_history lh JOIN users u ON lh.user_id=u.id
               WHERE lh.timestamp >= ? GROUP BY u.username ORDER BY avg_risk DESC LIMIT 10""",
            (since_7d,))
        user_risks = [{'username': dict_from_row(r)['username'],
                       'avg_risk': round(float(dict_from_row(r)['avg_risk'] or 0), 1)}
                      for r in cur.fetchall()]

        cur = execute(conn, "SELECT COUNT(*) AS cnt FROM users")
        total_users = dict_from_row(cur.fetchone()).get('cnt', 0)

        return jsonify({
            'status': 'success',
            'total_logins_7d':   total_7d,
            'status_breakdown':  status_breakdown,
            'risk_distribution': risk_dist,
            'daily_logins':      daily,
            'user_risks':        user_risks,
            'total_users':       total_users,
        }), 200
    finally:
        conn.close()


@dash_bp.route('/users', methods=['GET'])
@require_admin
def list_users():
    conn = get_connection()
    try:
        cur = execute(conn,
            "SELECT id, username, email, role, is_locked, failed_attempts, created_at FROM users")
        users = [dict_from_row(r) for r in cur.fetchall()]
        # Normalise datetime fields
        for u in users:
            for k in ('created_at', 'locked_until'):
                if k in u and u[k] is not None:
                    u[k] = str(u[k])
        return jsonify({'status': 'success', 'users': users}), 200
    finally:
        conn.close()
