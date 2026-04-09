"""
jwt_handler/jwt_manager.py – Access & refresh token management.
Uses database.execute() for MySQL/SQLite compatibility.
"""

import os
import jwt
import uuid
import logging
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '..', 'config', '.env'))

logger    = logging.getLogger(__name__)
SECRET    = os.getenv('JWT_SECRET_KEY', 'change-me-in-production-min-32-chars')
ACCESS_M  = int(os.getenv('JWT_ACCESS_EXPIRES_MINUTES', 15))
REFRESH_D = int(os.getenv('JWT_REFRESH_EXPIRES_DAYS', 7))
ALGORITHM = 'HS256'


class JWTManager:

    @staticmethod
    def create_access_token(user_id: int, username: str, role: str) -> str:
        now = datetime.now(tz=timezone.utc)
        payload = {
            'sub': str(user_id), 'username': username, 'role': role,
            'type': 'access', 'jti': str(uuid.uuid4()),
            'iat': now, 'exp': now + timedelta(minutes=ACCESS_M),
        }
        return jwt.encode(payload, SECRET, algorithm=ALGORITHM)

    @staticmethod
    def create_refresh_token(user_id: int) -> tuple:
        now = datetime.now(tz=timezone.utc)
        exp = now + timedelta(days=REFRESH_D)
        payload = {
            'sub': str(user_id), 'type': 'refresh',
            'jti': str(uuid.uuid4()), 'iat': now, 'exp': exp,
        }
        return jwt.encode(payload, SECRET, algorithm=ALGORITHM), exp

    @staticmethod
    def decode_token(token: str) -> dict | None:
        try:
            return jwt.decode(token, SECRET, algorithms=[ALGORITHM])
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    @staticmethod
    def verify_access_token(token: str) -> dict | None:
        p = JWTManager.decode_token(token)
        return p if p and p.get('type') == 'access' else None

    @staticmethod
    def verify_refresh_token(token: str) -> dict | None:
        p = JWTManager.decode_token(token)
        return p if p and p.get('type') == 'refresh' else None


# ── DB helpers ────────────────────────────────────────────────────

def _db():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from database import get_connection, hash_token, execute
    return get_connection, hash_token, execute


def store_refresh_token(user_id: int, token: str, expires_at: datetime):
    get_connection, hash_token, execute = _db()
    conn = get_connection()
    try:
        execute(conn,
            "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?,?,?)",
            (user_id, hash_token(token), expires_at.strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
    finally:
        conn.close()


def revoke_refresh_token(token: str):
    get_connection, hash_token, execute = _db()
    conn = get_connection()
    try:
        execute(conn,
            "UPDATE refresh_tokens SET revoked=1 WHERE token_hash=?",
            (hash_token(token),))
        conn.commit()
    finally:
        conn.close()


def is_refresh_token_valid(token: str) -> bool:
    get_connection, hash_token, execute = _db()
    conn = get_connection()
    try:
        from database import dict_from_row
        cur = execute(conn,
            "SELECT revoked, expires_at FROM refresh_tokens WHERE token_hash=?",
            (hash_token(token),))
        row = cur.fetchone()
        if not row:
            return False
        d = dict_from_row(row) if not isinstance(row, dict) else row
        if d.get('revoked'):
            return False
        exp_str = str(d.get('expires_at', ''))[:19]
        exp = datetime.strptime(exp_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
        return datetime.now(tz=timezone.utc) < exp
    finally:
        conn.close()
