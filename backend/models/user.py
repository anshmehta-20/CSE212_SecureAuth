"""
models/user.py – User model with bcrypt password management.
Uses database.execute() for DB-agnostic queries (MySQL / SQLite).
"""

import bcrypt
import logging
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import get_connection, dict_from_row, execute

logger = logging.getLogger(__name__)

MAX_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', 5))
LOCKOUT_MINS = int(os.getenv('LOCKOUT_MINUTES', 15))


class User:
    """Business-logic wrapper around the users table."""

    def __init__(self, row: dict):
        self.id              = row['id']
        self.username        = row['username']
        self.email           = row['email']
        self.password_hash   = row['password_hash']
        self.role            = row['role']
        self.is_locked       = bool(row['is_locked'])
        self.failed_attempts = row['failed_attempts']
        self.locked_until    = row.get('locked_until')
        self.created_at      = row['created_at']

    # ── Finders ──────────────────────────────────────────────────

    @staticmethod
    def find_by_username(username: str) -> 'User | None':
        conn = get_connection()
        try:
            cur = execute(conn, "SELECT * FROM users WHERE username = ?", (username,))
            row = cur.fetchone()
            return User(dict_from_row(row)) if row else None
        finally:
            conn.close()

    @staticmethod
    def find_by_id(user_id: int) -> 'User | None':
        conn = get_connection()
        try:
            cur = execute(conn, "SELECT * FROM users WHERE id = ?", (user_id,))
            row = cur.fetchone()
            return User(dict_from_row(row)) if row else None
        finally:
            conn.close()

    # ── Password ─────────────────────────────────────────────────

    def check_password(self, plain: str) -> bool:
        try:
            return bcrypt.checkpw(plain.encode(), self.password_hash.encode())
        except Exception:
            return False

    # ── Account locking ──────────────────────────────────────────

    def is_account_locked(self) -> bool:
        if not self.is_locked:
            return False
        if self.locked_until:
            try:
                until_str = str(self.locked_until)[:19]
                until = datetime.strptime(until_str, '%Y-%m-%d %H:%M:%S')
                if datetime.utcnow() > until:
                    self._unlock()
                    return False
            except (ValueError, TypeError):
                pass
        return True

    def record_failed_attempt(self):
        self.failed_attempts += 1
        conn = get_connection()
        try:
            if self.failed_attempts >= MAX_ATTEMPTS:
                until = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINS)) \
                            .strftime('%Y-%m-%d %H:%M:%S')
                execute(conn,
                    "UPDATE users SET failed_attempts=?, is_locked=1, locked_until=? WHERE id=?",
                    (self.failed_attempts, until, self.id))
                self.is_locked    = True
                self.locked_until = until
                logger.warning("User '%s' locked until %s", self.username, until)
            else:
                execute(conn,
                    "UPDATE users SET failed_attempts=? WHERE id=?",
                    (self.failed_attempts, self.id))
            conn.commit()
        finally:
            conn.close()

    def reset_failed_attempts(self):
        conn = get_connection()
        try:
            execute(conn,
                "UPDATE users SET failed_attempts=0, is_locked=0, locked_until=NULL WHERE id=?",
                (self.id,))
            conn.commit()
            self.failed_attempts = 0
            self.is_locked       = False
        finally:
            conn.close()

    def _unlock(self):
        conn = get_connection()
        try:
            execute(conn,
                "UPDATE users SET is_locked=0, locked_until=NULL, failed_attempts=0 WHERE id=?",
                (self.id,))
            conn.commit()
            self.is_locked = False
        finally:
            conn.close()

    # ── Login history ─────────────────────────────────────────────

    def record_login(self, ip, device_hash, location, risk_score, risk_level, status, explanation=''):
        conn = get_connection()
        try:
            execute(conn,
                """INSERT INTO login_history
                   (user_id, ip_address, device_hash, location,
                    risk_score, risk_level, status, explanation)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (self.id, ip, device_hash, location,
                 round(risk_score, 2), risk_level, status, explanation))
            conn.commit()
        finally:
            conn.close()

    def get_login_history(self, limit=20) -> list:
        conn = get_connection()
        try:
            cur = execute(conn,
                "SELECT * FROM login_history WHERE user_id=? ORDER BY timestamp DESC LIMIT ?",
                (self.id, limit))
            return [dict_from_row(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def to_dict(self) -> dict:
        return {
            'id':         self.id,
            'username':   self.username,
            'email':      self.email,
            'role':       self.role,
            'created_at': str(self.created_at),
        }
