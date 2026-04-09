"""
database.py – MySQL connection manager & schema initializer.
Primary: MySQL via PyMySQL (pure-Python, no C extensions needed).
Fallback: SQLite for local dev when DB_TYPE=sqlite.
"""

import os
import sqlite3
import logging
import hashlib
from datetime import datetime
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', 'config', '.env'))

logger = logging.getLogger(__name__)

DB_TYPE = os.getenv('DB_TYPE', 'sqlite')      # 'mysql' | 'sqlite'
DB_PATH = os.getenv('DB_PATH', 'secureauth.db')

_backend_dir = os.path.dirname(os.path.abspath(__file__))
if not os.path.isabs(DB_PATH):
    DB_PATH = os.path.join(_backend_dir, DB_PATH)


# ─────────────────────────────────────────────────────────────────
# Connection
# ─────────────────────────────────────────────────────────────────

def get_connection():
    """Return a database connection.
    DB_TYPE=mysql  → PyMySQL (requires MySQL server)
    DB_TYPE=sqlite → SQLite (default, no server needed)
    """
    if DB_TYPE == 'mysql':
        return _mysql_connection()
    return _sqlite_connection()


def _mysql_connection():
    """Open a PyMySQL connection with DictCursor for dict-style row access."""
    try:
        import pymysql
        import pymysql.cursors
        conn = pymysql.connect(
            host     = os.getenv('DB_HOST', 'localhost'),
            port     = int(os.getenv('DB_PORT', 3306)),
            database = os.getenv('DB_NAME', 'secureauth_db'),
            user     = os.getenv('DB_USER', 'secureauth_user'),
            password = os.getenv('DB_PASSWORD', ''),
            charset  = 'utf8mb4',
            autocommit = False,
            cursorclass = pymysql.cursors.DictCursor,
            connect_timeout = 10,
        )
        logger.debug("MySQL connection established.")
        return conn
    except ImportError:
        logger.error("PyMySQL not installed. Run: pip install PyMySQL")
        raise
    except Exception as exc:
        logger.error("MySQL connection failed: %s", exc)
        raise


def _sqlite_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ─────────────────────────────────────────────────────────────────
# Schema – MySQL dialect (also valid for SQLite with minor notes)
# ─────────────────────────────────────────────────────────────────

# MySQL DDL statements (executed one at a time)
MYSQL_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id              INT             NOT NULL AUTO_INCREMENT PRIMARY KEY,
        username        VARCHAR(80)     NOT NULL UNIQUE,
        email           VARCHAR(255)    NOT NULL UNIQUE,
        password_hash   VARCHAR(255)    NOT NULL,
        role            VARCHAR(20)     NOT NULL DEFAULT 'user',
        is_locked       TINYINT(1)      NOT NULL DEFAULT 0,
        failed_attempts INT             NOT NULL DEFAULT 0,
        locked_until    DATETIME        NULL,
        created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS login_history (
        id          INT             NOT NULL AUTO_INCREMENT PRIMARY KEY,
        user_id     INT             NOT NULL,
        ip_address  VARCHAR(45)     NULL,
        device_hash VARCHAR(64)     NULL,
        location    VARCHAR(255)    NULL,
        risk_score  FLOAT           NULL,
        risk_level  VARCHAR(10)     NULL,
        status      VARCHAR(20)     NULL,
        explanation TEXT            NULL,
        timestamp   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS mfa_tokens (
        id          INT             NOT NULL AUTO_INCREMENT PRIMARY KEY,
        user_id     INT             NOT NULL,
        otp_hash    VARCHAR(255)    NOT NULL,
        mfa_token   VARCHAR(64)     NOT NULL UNIQUE,
        expires_at  DATETIME        NOT NULL,
        used        TINYINT(1)      NOT NULL DEFAULT 0,
        created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS refresh_tokens (
        id          INT             NOT NULL AUTO_INCREMENT PRIMARY KEY,
        user_id     INT             NOT NULL,
        token_hash  VARCHAR(64)     NOT NULL UNIQUE,
        expires_at  DATETIME        NOT NULL,
        revoked     TINYINT(1)      NOT NULL DEFAULT 0,
        created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS ai_metrics (
        id              INT             NOT NULL AUTO_INCREMENT PRIMARY KEY,
        user_id         INT             NOT NULL,
        feature_vector  MEDIUMTEXT      NULL,
        model_votes     TEXT            NULL,
        risk_score      FLOAT           NULL,
        risk_level      VARCHAR(10)     NULL,
        confidence      FLOAT           NULL,
        explanation     TEXT            NULL,
        timestamp       DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS rate_limit_log (
        id          INT             NOT NULL AUTO_INCREMENT PRIMARY KEY,
        ip_address  VARCHAR(45)     NOT NULL,
        endpoint    VARCHAR(100)    NULL,
        timestamp   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
]

# SQLite fallback schema (single executescript call)
SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    email           TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL DEFAULT 'user',
    is_locked       INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS login_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    ip_address  TEXT,
    device_hash TEXT,
    location    TEXT,
    risk_score  REAL,
    risk_level  TEXT,
    status      TEXT,
    explanation TEXT,
    timestamp   TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS mfa_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    otp_hash    TEXT    NOT NULL,
    mfa_token   TEXT    NOT NULL UNIQUE,
    expires_at  TEXT    NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    token_hash  TEXT    NOT NULL UNIQUE,
    expires_at  TEXT    NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS ai_metrics (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id),
    feature_vector  TEXT,
    model_votes     TEXT,
    risk_score      REAL,
    risk_level      TEXT,
    confidence      REAL,
    explanation     TEXT,
    timestamp       TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS rate_limit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address  TEXT    NOT NULL,
    endpoint    TEXT,
    timestamp   TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""


# ─────────────────────────────────────────────────────────────────
# init_db
# ─────────────────────────────────────────────────────────────────

def init_db():
    """Create all tables if they don't exist."""
    conn = get_connection()
    try:
        if DB_TYPE == 'mysql':
            cur = conn.cursor()
            for stmt in MYSQL_SCHEMA:
                stmt = stmt.strip()
                if stmt:
                    cur.execute(stmt)
            conn.commit()
            logger.info("MySQL schema initialised.")
        else:
            conn.executescript(SQLITE_SCHEMA)
            conn.commit()
            logger.info("SQLite database initialised at %s", DB_PATH)
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────
# Placeholder / query helpers
# ─────────────────────────────────────────────────────────────────

def ph():
    """Return the correct placeholder for the active DB driver.
    MySQL uses %s, SQLite uses ?.
    """
    return '%s' if DB_TYPE == 'mysql' else '?'


def execute(conn, sql: str, params=()):
    """Execute a single statement with correct placeholders."""
    sql = _adapt_sql(sql)
    cur = conn.cursor()
    cur.execute(sql, params)
    return cur


def _adapt_sql(sql: str) -> str:
    """Convert ? placeholders to %s for MySQL."""
    if DB_TYPE == 'mysql':
        return sql.replace('?', '%s')
    return sql


# ─────────────────────────────────────────────────────────────────
# Row → dict helper
# ─────────────────────────────────────────────────────────────────

def dict_from_row(row) -> dict | None:
    """Normalise a row to a plain dict regardless of driver."""
    if row is None:
        return None
    if isinstance(row, dict):
        return row
    if isinstance(row, sqlite3.Row):
        return dict(row)
    # Fallback (e.g. tuple): shouldn't happen with DictCursor
    return dict(row)


def hash_token(token: str) -> str:
    """SHA-256 hash for token storage."""
    return hashlib.sha256(token.encode()).hexdigest()


# ─────────────────────────────────────────────────────────────────
# Seed demo data
# ─────────────────────────────────────────────────────────────────

def seed_demo_data():
    """Insert demo users + calibrated per-user login history if the DB is empty."""
    import bcrypt
    import random
    import hashlib as _hl
    from datetime import timedelta

    conn = get_connection()
    try:
        cur = execute(conn, "SELECT COUNT(*) AS cnt FROM users")
        row = cur.fetchone()
        count = dict_from_row(row).get('cnt', 0) if row else 0
        if count > 0:
            logger.info("Demo data already present – skipping seed.")
            return

        users = [
            ('alice',   'alice@demo.com',   'SecurePass123!', 'user'),
            ('bob',     'bob@demo.com',     'Pass@2024',       'user'),
            ('charlie', 'charlie@demo.com', 'Admin@999',       'user'),
            ('admin',   'admin@demo.com',   'AdminSecure1!',   'admin'),
        ]

        now = datetime.utcnow()
        for uname, email, pwd, role in users:
            pw_hash = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()
            execute(
                conn,
                "INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)",
                (uname, email, pw_hash, role)
            )
        conn.commit()

        cur = execute(conn, "SELECT id, username FROM users")
        db_users = cur.fetchall()

        # ── Per-user seed profiles ────────────────────────────────────────────
        #
        # device_hash:
        #   LOW users  → '' (empty) so device_change = 0 on any real login
        #              (condition: current != last AND last != '' → False when last == '')
        #   HIGH user  → random 8-char hex so device_change = 1 (always new device)
        #
        # location:
        #   LOW users  → 'Unknown, IN' matches the frontend default
        #              → location_change = 0 on login
        #   HIGH user  → foreign cities → location_change = 1
        #
        # status / scores calibrated so fail_ratio drives differentiation:
        #   alice  → all 'allowed' (fail_ratio ≈ 0.00) → LOW
        #   bob    → mix of mfa/allowed (fail_ratio ≈ 0.0–0.10) → MEDIUM context
        #   charlie→ mostly 'blocked' (fail_ratio ≈ 0.65+) → HIGH
        #   admin  → all 'allowed' like alice → LOW

        def _rnd_hex8():
            return _hl.md5(str(random.random()).encode()).hexdigest()[:8]

        _profiles = {
            'alice': {
                'location_pool': ['Unknown, IN'],           # consistent → no location change
                'device_pool':   [''],                       # empty → no device change
                'score_lo': 5, 'score_hi': 28,
                'recent_hours': (1, 12),                    # logged in recently
            },
            'bob': {
                'location_pool': ['Unknown, IN', 'Mumbai, IN'],  # sometimes changes
                'device_pool':   ['', _rnd_hex8()],              # sometimes new device
                'score_lo': 38, 'score_hi': 62,
                'recent_hours': (2, 48),
            },
            'charlie': {
                'location_pool': ['London, UK', 'Moscow, RU', 'Sao Paulo, BR',
                                   'Lagos, NG', 'Frankfurt, DE'],
                'device_pool':   [_rnd_hex8() for _ in range(6)],  # always different
                'score_lo': 65, 'score_hi': 94,
                'recent_hours': (24, 168),                  # hasn't logged in recently
            },
            'admin': {
                'location_pool': ['Unknown, IN'],
                'device_pool':   [''],
                'score_lo': 4, 'score_hi': 22,
                'recent_hours': (1, 8),
            },
        }

        local_ips = ['192.168.1.{}'.format(i) for i in range(10, 50)]

        for row in db_users:
            row_d = dict_from_row(row)
            uid   = row_d['id']
            uname = row_d['username']
            prof  = _profiles.get(uname, _profiles['alice'])

            lo = prof['score_lo']
            hi = prof['score_hi']

            # Seed 24 historical logins spread over the past 30 days
            for i in range(24):
                hours_ago = random.randint(8, 720)
                ts    = now - timedelta(hours=hours_ago)
                score = random.uniform(lo, hi)
                rlvl  = 'LOW' if score < 40 else ('MEDIUM' if score < 70 else 'HIGH')
                status = 'allowed' if score < 40 else ('mfa_required' if score < 70 else 'blocked')
                execute(
                    conn,
                    """INSERT INTO login_history
                       (user_id, ip_address, device_hash, location,
                        risk_score, risk_level, status, timestamp)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (uid,
                     random.choice(local_ips),
                     random.choice(prof['device_pool']),
                     random.choice(prof['location_pool']),
                     round(score, 1),
                     rlvl,
                     status,
                     ts.strftime('%Y-%m-%d %H:%M:%S'))
                )

            # Seed 1 very-recent login that will be history[0]
            # This is the critical entry compared against the live login
            recent_h_lo, recent_h_hi = prof['recent_hours']
            recent_ts = now - timedelta(hours=random.uniform(recent_h_lo, recent_h_hi))
            recent_score = random.uniform(lo, hi)
            recent_rlvl  = 'LOW' if recent_score < 40 else ('MEDIUM' if recent_score < 70 else 'HIGH')
            recent_status = 'allowed' if recent_score < 40 else ('mfa_required' if recent_score < 70 else 'blocked')
            execute(
                conn,
                """INSERT INTO login_history
                   (user_id, ip_address, device_hash, location,
                    risk_score, risk_level, status, timestamp)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (uid,
                 '127.0.0.1',
                 # LOW users: empty device_hash → device_change = 0 on any login
                 # HIGH/MED users: real hex → device_change = 1
                 '' if prof['device_pool'][0] == '' else _rnd_hex8(),
                 # LOW users: 'Unknown, IN' matches frontend default → location_change = 0
                 # HIGH users: foreign city → location_change = 1
                 prof['location_pool'][0],
                 round(recent_score, 1),
                 recent_rlvl,
                 recent_status,
                 recent_ts.strftime('%Y-%m-%d %H:%M:%S'))
            )

        conn.commit()
        logger.info("Demo data seeded successfully.")
    finally:
        conn.close()



if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    init_db()
    seed_demo_data()
    print("Database ready.")
