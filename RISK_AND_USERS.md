# SecureAuth — Risk Analysis & User Management Guide

This document covers two operational topics:

1. **How to analyse a login risk assessment** — what the scores mean, which signals drive them, and how to act on them.
2. **How to add a new user** — three methods (Python script, API call, direct database insert) with exact commands.

---

## Part A — Risk Analysis

### A.1 — The Three-Tier Risk System

Every login event is scored on a scale of **0 to 100** by a three-model AI ensemble. The score falls into one of three bands that determine the authentication outcome:

| Band | Score Range | Colour | Outcome |
|---|---|---|---|
| **LOW** | 0 – 39 | 🟢 Green | JWT tokens issued; login succeeds immediately |
| **MEDIUM** | 40 – 69 | 🟡 Yellow | MFA triggered; OTP sent to registered email |
| **HIGH** | 70 – 100 | 🔴 Red | Login blocked; SHAP explanation returned |

---

### A.2 — What Signals Drive the Score

The AI engine extracts 19 features from each login event and feeds them simultaneously into three models. Understanding which features carry the most weight helps you diagnose why a specific login was scored a certain way.

#### Group 1 — Temporal Signals

| Feature | What raises the score |
|---|---|
| `hour_of_day` | Login between 00:00–06:00 or 22:00–23:59 (off-hours) |
| `is_weekend` | Login on Saturday or Sunday (unusual for the account) |
| `is_business_hours` | Score goes **down** when login is 09:00–18:00 Mon–Fri |
| `time_since_last_login` | Gaps over 96 hours — account possibly dormant or compromised |

#### Group 2 — Behavioural Signals

| Feature | What raises the score |
|---|---|
| `location_change` | Login location differs from the most recent recorded login |
| `device_change` | The MD5 fingerprint of `User-Agent + IP` does not match the last login |
| `login_velocity` | More than 5 logins from this account in the last 60 minutes |
| `typing_speed` | Input speed < 1 char/sec (bot) or > 15 chars/sec (macro) |

#### Group 3 — Network Signals

| Feature | What raises the score |
|---|---|
| `ip_risk_score` | IP prefix matches known high-risk CIDR blocks (score > 0.5) |
| `vpn_detected` | IP belongs to a known VPN or proxy range |
| `country_change` | Derived from location change — country differs from last login |

#### Group 4 — Account Statistics

| Feature | What raises the score |
|---|---|
| `failed_login_ratio` | More than 30% of the account's history is blocked attempts |
| `account_age_days` | Account is fewer than 3 days old |
| `login_frequency_7d` | More than 30 logins in the past 7 days (unusual velocity) |

> **Important:** On a fresh installation, all four demo accounts have seeded login history recording private IP addresses (`192.168.x.x`) from Indian cities. Any login from a new IP or browser will trigger `location_change = 1` and `device_change = 1`, which reliably produces a HIGH score. This is intentional — it demonstrates that **a stolen password alone is insufficient for access**.

---

### A.3 — How the Three Models Vote

Each model independently evaluates the 19-feature vector and casts a binary vote:

| Model | Algorithm | Vote |
|---|---|---|
| **Isolation Forest** | Tree-based random partitioning | `+1` = normal, `-1` = anomaly |
| **One-Class SVM** | Kernel-based boundary (RBF) | `+1` = inside boundary, `-1` = outside |
| **Local Outlier Factor** | Density-based neighbourhood comparison | `+1` = normal density, `-1` = sparse outlier |

The individual raw anomaly scores are normalised to `[0, 1]` and combined with weights:

```
risk_raw = (0.45 × IsolationForest)
         + (0.30 × OneClassSVM)
         + (0.25 × LocalOutlierFactor)
```

**Consensus penalty** — when models agree, the score is amplified:

```
2 models flag anomaly → risk_raw += 0.10
3 models flag anomaly → risk_raw += 0.20
```

`risk_score = round(risk_raw × 100, 1)`

---

### A.3b — Feature Value → Score Contribution (Detailed)

This section explains **exactly which values each feature produces**, what the models consider "normal" vs "anomalous", and how much weight each feature realistically carries in the final score.

> The models (Isolation Forest, One-Class SVM, Local Outlier Factor) were trained on synthetic normal-login data. They learned a **boundary of normality**. A login falls outside that boundary when several features simultaneously land in unusual ranges. No single feature alone determines the outcome — it is always the combination.

---

#### Feature Reference Table

The table below lists all 19 features in vector order (index 0–18), their source, what the models see as normal, what triggers an anomaly signal, and their approximate relative influence.

| # | Feature | Normal Range | Anomalous Range | Relative Weight |
|---|---|---|---|---|
| 0 | `hour_of_day` | 7 – 22 | 0 – 6 or 23 | Medium |
| 1 | `day_of_week` | 0 – 4 (Mon–Fri) | 5 – 6 (Sat–Sun) | Low |
| 2 | `is_weekend` | 0 | 1 | Low |
| 3 | `is_business_hours` | 1 (09:00–18:00 weekday) | 0 | Low–Medium |
| 4 | `time_since_last_login` | 0 – 72 h | > 168 h (max cap) | Medium |
| 5 | `location_change` | 0 (same as last) | **1 (changed)** | **Very High** |
| 6 | `device_change` | 0 (same device hash) | **1 (changed)** | **Very High** |
| 7 | `login_velocity` | 0 – 2 per hour | > 5 per hour | High |
| 8 | `typing_speed` | 2.5 – 8 chars/sec | < 1 or > 15 | Low–Medium |
| 9 | `ip_risk_score` | 0.00 – 0.14 (private ranges) | > 0.60 | High |
| 10 | `vpn_detected` | 0 | 1 | Medium–High |
| 11 | `country_change` | 0 | 1 | **Very High** |
| 12 | `failed_login_ratio` | 0.00 – 0.10 | > 0.35 | **Very High** |
| 13 | `account_age_days` | > 30 days | 0 – 3 days | Medium |
| 14 | `login_frequency_7d` | 1 – 15 | > 30 | Medium |
| 15 | `hour_sin` | cyclic encoding | — | Low (context) |
| 16 | `hour_cos` | cyclic encoding | — | Low (context) |
| 17 | `day_sin` | cyclic encoding | — | Low (context) |
| 18 | `day_cos` | cyclic encoding | — | Low (context) |

---

#### Feature-by-Feature Breakdown

**`hour_of_day` (index 0)**

The models learn that most legitimate logins happen between 07:00 and 22:00. A login at 02:00 is rare in training data, placing it near the boundary.

```
03:00  →  high anomaly signal  (off-hours)
14:00  →  normal, no signal
20:00  →  acceptable, low signal
```

---

**`time_since_last_login` (index 4)**

Calculated as hours since the account's most recent recorded login. The cap is 168 h (7 days).

```
2 h    →  very normal — active user
48 h   →  low signal
96 h   →  medium signal
168 h  →  max signal (account dormant or brand new)
```

---

**`location_change` (index 5) — Binary: 0 or 1**

Comparison: `current_location != last_login_location AND last_login_location != ''`

```
Same city as last login       →  0  (no signal)
Different city or country     →  1  (strong anomaly)
No history (first login)      →  0  (no comparison possible, condition guards this)
```

This is one of the strongest single features. Together with `device_change`, a simultaneous `1` on both almost guarantees HIGH risk.

---

**`device_change` (index 6) — Binary: 0 or 1**

Comparison: `MD5(User-Agent + "|" + IP)[:8]  !=  stored_device_hash  AND  stored_hash != ''`

```
Same browser and IP as last login  →  0  (no signal)
Different browser or IP            →  1  (strong anomaly)
Stored hash is empty               →  0  (condition prevents false positives on new accounts)
```

---

**`login_velocity` (index 7)**

Count of logins made by this account in the last 60 minutes, from history.

```
0 – 2   →  normal
3 – 5   →  mild signal
> 5     →  possible credential stuffing
> 10    →  strong anomaly (capped at 20)
```

---

**`ip_risk_score` (index 9)**

Deterministic score derived from the IP prefix hash (same IP always returns the same score):

```
127.0.0.1 / 192.168.x.x / 10.x.x.x   →  0.00 – 0.14  (private, low risk)
Unknown external IPs                   →  0.05 – 0.40  (mild signal)
185.x / 45.33.x / 198.x               →  0.60 – 0.95  (known high-risk block)
```

---

**`vpn_detected` (index 10) — Binary: 0 or 1**

Based on known VPN IP prefixes (172.16–172.25) plus a deterministic 8% flag for unrecognised external IPs.

```
Localhost or private range  →  0
Known VPN prefix            →  1
~8% of external IPs         →  1  (flagged deterministically by IP hash)
```

---

**`failed_login_ratio` (index 12)**

`blocked_logins / total_login_history` across the last 50 recorded events.

```
0.00          →  account is considered clean
0.10 – 0.20   →  mild concern
0.35+         →  suspicious account pattern
0.65+         →  consistently targeted account (charlie's profile)
```

This is the feature that most strongly differentiates between accounts with otherwise identical network conditions (same IP, same hour). Alice (ratio ≈ 0.00) vs Charlie (ratio ≈ 0.65) produce very different ensemble responses even from the same machine.

---

**`account_age_days` (index 13)**

```
0 – 3 days     →  high signal (new account, no trust history)
4 – 30 days    →  medium signal
31 – 180 days  →  low signal
> 180 days     →  no signal (established account)
```

---

**Cyclic encoding: `hour_sin/cos`, `day_sin/cos` (indices 15–18)**

Raw hour (0–23) and day (0–6) are converted to sine/cosine pairs so that the model treats time continuously rather than as integers. This prevents an artificial numerical gap between 23:59 and 00:00.

```python
hour_sin = sin(2π × hour / 24)
hour_cos = cos(2π × hour / 24)
```

These add smooth temporal context alongside the raw `hour_of_day` value.

---

#### Worked Example — Alice (LOW) vs Charlie (HIGH)

Both users log in from localhost at 14:30 on a Tuesday. Here is how their feature vectors differ and why the scores diverge.

| Feature | Alice value | Charlie value | Note |
|---|---|---|---|
| `hour_of_day` | 14 | 14 | Same — neutral |
| `is_weekend` | 0 | 0 | Same — neutral |
| `is_business_hours` | 1 | 1 | Same — reduces both scores |
| `time_since_last_login` | **4 h** | **72 h** | Charlie is less active recently |
| `location_change` | **0** | **1** | Alice: "Unknown, IN" matches seeded history. Charlie: seeded history has foreign cities |
| `device_change` | **0** | **1** | Alice: empty stored hash — condition short-circuits. Charlie: stored different hex hash |
| `login_velocity` | 0 | 0 | Same — neutral |
| `ip_risk_score` | 0.04 | 0.04 | Same localhost IP — both low |
| `vpn_detected` | 0 | 0 | Same — neutral |
| `country_change` | **0** | **1** | Mirrors location_change |
| `failed_login_ratio` | **0.00** | **0.65** | Key differentiator — charlie has mostly blocked history |
| `account_age_days` | 0 | 0 | Both just seeded, equal |
| `login_frequency_7d` | 2 | 1 | Similar — neutral |

**Score outcome:**

```
Alice
  Features in anomalous range: 1 (account_age = 0)
  Model votes: all 3 → NORMAL
  Consensus penalty: none
  risk_score ≈ 15 – 30  →  LOW  ✅  (login succeeds)

Charlie
  Features in anomalous range: location_change, device_change,
                                country_change, failed_login_ratio, time_since_last_login
  Model votes: IsolationForest → ANOMALY
               One-Class SVM   → ANOMALY
               LocalOutlierFactor → ANOMALY
  Consensus penalty: all 3 agree → +0.20
  risk_score ≈ 75 – 90  →  HIGH  🚫  (login blocked)
```

The critical difference is five simultaneous anomalous features triggering unanimous model agreement. The `+0.20` consensus penalty then amplifies the already-high raw score into the HIGH band.

---

#### Why Unanimous Agreement Matters

The consensus penalty is designed to reflect a fundamental insight: three independently designed algorithms — one tree-based (Isolation Forest), one kernel-based (One-Class SVM), one density-based (Local Outlier Factor) — each view the data from a fundamentally different mathematical perspective. If all three simultaneously consider a login abnormal, the probability of a false positive drops significantly.

```
Only 1 model flags anomaly  →  moderate confidence  (no penalty)
2 models flag anomaly       →  high confidence      (+0.10 to raw score)
All 3 models flag anomaly   →  very high confidence (+0.20 to raw score)
```

This design makes the system **robust against individual algorithm quirks** while **decisive when all three converge** — which is exactly the condition under which a real attacker using stolen credentials from a foreign location would be detected.

---

### A.4 — Reading a SHAP Explanation

Every blocked or flagged login returns an explanation string in the API response and displays it in the UI. Example:

```
🚫 LOGIN BLOCKED

Risk Score: 88/100

Summary: Multiple high-risk indicators detected. For your security,
we've blocked this attempt.

Analysis:
  • ⚠️ New device detected – first time logging in from this device
  • ⚠️ Location is different from your usual locations – possible travel or attack
  • ⚠️ VPN or proxy detected – often used to hide true location
  • ⚠️ Login at 2:00 is very unusual (typically associated with attacks)
  • ✅ Login rate is normal
  • ✅ Low failed login ratio – normal

Models flagged: IsolationForest, OneClassSVM, LocalOutlierFactor

Recommendation: Contact support if this wasn't you.
```

**How to read it:**

| Symbol | Meaning |
|---|---|
| `⚠️` | This feature is in a risky range and contributed to the elevated score |
| `✅` | This feature is normal — it did not contribute to the risk |
| `Models flagged:` | Which of the three models voted `-1` (anomaly) |
| `Risk Score:` | The final weighted composite score out of 100 |

The top 6 features by SHAP magnitude are shown. Features not listed had near-zero contribution.

---

### A.5 — Checking a Login's Full AI Audit

Every login is recorded in the `ai_metrics` table with the full feature vector, model votes, score, and explanation.

**Using Python:**

```python
import sys
sys.path.insert(0, 'backend')
from database import get_connection, execute, dict_from_row
import json

conn = get_connection()

# Get the last 5 AI evaluations
cur = execute(conn, """
    SELECT am.timestamp, u.username, am.risk_score, am.risk_level,
           am.confidence, am.model_votes, am.explanation
    FROM ai_metrics am
    JOIN users u ON u.id = am.user_id
    ORDER BY am.timestamp DESC
    LIMIT 5
""")

for row in cur.fetchall():
    r = dict_from_row(row)
    votes = json.loads(r['model_votes'])
    print(f"[{r['timestamp']}] {r['username']:10s}  "
          f"score={r['risk_score']:5.1f}  level={r['risk_level']:6s}  "
          f"conf={r['confidence']:.2f}  votes={votes}")

conn.close()
```

**Using SQLite CLI:**

```bash
sqlite3 backend/secureauth.db

SELECT datetime(am.timestamp), u.username, am.risk_score, am.risk_level,
       am.confidence, am.model_votes
FROM ai_metrics am
JOIN users u ON u.id = am.user_id
ORDER BY am.timestamp DESC
LIMIT 10;
```

---

### A.6 — Adjusting Risk Thresholds

Risk thresholds are configurable without code changes. Edit `config/.env`:

```ini
# Number of failed logins before IP-level lockout (default: 5)
MAX_LOGIN_ATTEMPTS=5

# Lockout duration in minutes (default: 15)
LOCKOUT_MINUTES=15

# Requests per minute before rate-limit kicks in (default: 20)
RATE_LIMIT_MAX=20
```

To adjust the AI risk bands (LOW/MEDIUM/HIGH cutoffs), edit `backend/ai/ensemble_model.py`:

```python
# Lines 203–208 — adjust these thresholds
if risk_score < 40:       # ← raise to make LOW stricter (e.g. < 30)
    risk_level = 'LOW'
elif risk_score < 70:     # ← raise to make MEDIUM wider (e.g. < 80)
    risk_level = 'MEDIUM'
else:
    risk_level = 'HIGH'
```

After editing, delete the cached models and restart so they retrain on the new thresholds:

```bash
rm -rf config/models/
python backend/app.py
```

---

## Part B — Adding a New User

There are three supported methods. Choose the one appropriate to your context.

---

### Method 1 — Python Script (Recommended)

This is the safest and most reproducible method. It uses the same bcrypt hashing as the production login flow.

Create a file called `add_user.py` in the project root:

```python
"""
add_user.py — Add a new user to SecureAuth.
Run from the project root:
    python add_user.py
"""

import sys
import bcrypt

sys.path.insert(0, 'backend')
from database import get_connection, execute, dict_from_row

# ── Configure the new user here ──────────────────────────────────
USERNAME   = 'newuser'
EMAIL      = 'newuser@yourdomain.com'
PASSWORD   = 'StrongPassword1!'     # must be at least 8 chars
ROLE       = 'user'                 # 'user' or 'admin'
# ─────────────────────────────────────────────────────────────────

def add_user(username, email, password, role='user'):
    # Hash the password
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

    conn = get_connection()
    try:
        # Check for duplicate username
        cur = execute(conn, "SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone():
            print(f"ERROR: Username '{username}' already exists.")
            return

        # Check for duplicate email
        cur = execute(conn, "SELECT id FROM users WHERE email = ?", (email,))
        if cur.fetchone():
            print(f"ERROR: Email '{email}' is already registered.")
            return

        # Insert the user
        execute(conn,
            "INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)",
            (username, email, pw_hash, role)
        )
        conn.commit()

        # Confirm insertion
        cur = execute(conn, "SELECT id, username, email, role, created_at FROM users WHERE username = ?", (username,))
        row = dict_from_row(cur.fetchone())
        print(f"\nUser created successfully:")
        print(f"  ID       : {row['id']}")
        print(f"  Username : {row['username']}")
        print(f"  Email    : {row['email']}")
        print(f"  Role     : {row['role']}")
        print(f"  Created  : {row['created_at']}")
        print(f"\nThey can now log in at http://localhost:5000\n")

    except Exception as e:
        print(f"ERROR: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    add_user(USERNAME, EMAIL, PASSWORD, ROLE)
```

**Run it:**

```bash
python add_user.py
```

**Expected output:**

```
User created successfully:
  ID       : 5
  Username : newuser
  Email    : newuser@yourdomain.com
  Role     : user
  Created  : 2026-04-09 15:00:00

They can now log in at http://localhost:5000
```

---

### Method 2 — API Request (Programmatic / No Server Access)

If you are adding users without direct server file access, use the admin API endpoint via any HTTP client.

> **Prerequisite:** You must first log in as an `admin` account to obtain a valid `access_token`.

**Step 1 — Obtain an admin token:**

```bash
curl -s -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"AdminSecure1!"}' \
  | python -m json.tool
```

Copy the `access_token` from the response.

**Step 2 — Create the user** (requires an `/api/admin/create-user` endpoint — see note below):

```bash
curl -X POST http://localhost:5000/api/admin/create-user \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your_access_token>" \
  -d '{
    "username": "newuser",
    "email":    "newuser@yourdomain.com",
    "password": "StrongPassword1!",
    "role":     "user"
  }'
```

> **Note:** The `/api/admin/create-user` endpoint is not included in the default build. To add it, append the following route to `backend/routes/dashboard.py`:
>
> ```python
> @dash_bp.route('/admin/create-user', methods=['POST'])
> @require_admin
> def create_user_api():
>     import bcrypt
>     data     = request.get_json(silent=True) or {}
>     username = data.get('username', '').strip()
>     email    = data.get('email', '').strip()
>     password = data.get('password', '')
>     role     = data.get('role', 'user')
>
>     if not all([username, email, password]):
>         return jsonify({'error': 'username, email, password are required.'}), 400
>     if role not in ('user', 'admin'):
>         return jsonify({'error': 'role must be user or admin.'}), 400
>
>     pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
>     conn = get_connection()
>     try:
>         execute(conn,
>             "INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)",
>             (username, email, pw_hash, role))
>         conn.commit()
>         return jsonify({'status': 'success', 'message': f"User '{username}' created."}), 201
>     except Exception as e:
>         return jsonify({'error': str(e)}), 409
>     finally:
>         conn.close()
> ```

---

### Method 3 — Direct Database Insert

Use this only in development when you need to add a bulk set of users without running a script.

**Step 1 — Generate a bcrypt hash for the password:**

```python
python -c "import bcrypt; print(bcrypt.hashpw(b'YourPassword1!', bcrypt.gensalt(12)).decode())"
```

Copy the output hash (it will look like `$2b$12$...`).

**Step 2 — Insert the user (SQLite):**

```bash
sqlite3 backend/secureauth.db

INSERT INTO users (username, email, password_hash, role)
VALUES (
  'newuser',
  'newuser@yourdomain.com',
  '$2b$12$<paste_your_hash_here>',
  'user'
);

-- Verify
SELECT id, username, email, role, created_at FROM users;
.quit
```

**Step 2 (MySQL equivalent):**

```sql
INSERT INTO users (username, email, password_hash, role)
VALUES (
  'newuser',
  'newuser@yourdomain.com',
  '$2b$12$<paste_your_hash_here>',
  'user'
);

SELECT id, username, email, role, created_at FROM users;
```

> **Warning:** Never insert a plaintext password directly into the `password_hash` column. The login flow uses `bcrypt.checkpw()` — a plaintext value will never match and the account will be permanently inaccessible.

---

### B.2 — Creating an Admin User

The process is identical to creating a regular user. The only difference is setting `role = 'admin'`.

In the Python script method, change:

```python
ROLE = 'admin'
```

In the direct SQL method:

```sql
INSERT INTO users (username, email, password_hash, role)
VALUES ('superadmin', 'admin@corp.com', '$2b$12$...', 'admin');
```

Admin accounts gain access to:
- The "Admin" tab on the dashboard (login analytics, user table)
- The `GET /api/analytics` endpoint (7-day statistics, risk distribution chart)
- The `GET /api/users` endpoint (full user list)

---

### B.3 — Verifying the New User Exists

After adding a user by any method, verify with:

```bash
python -c "
import sys; sys.path.insert(0, 'backend')
from models.user import User
u = User.find_by_username('newuser')
print(u.to_dict() if u else 'User not found')
"
```

Expected output:

```python
{
  'id': 5,
  'username': 'newuser',
  'email': 'newuser@yourdomain.com',
  'role': 'user',
  'created_at': '2026-04-09 15:00:00'
}
```

---

### B.4 — Expected AI Behaviour for a New User

A newly created user has **no login history**. This affects the feature vector:

| Feature | Value for new user | Effect on score |
|---|---|---|
| `time_since_last_login` | 168.0 h (maximum cap) | Raises score |
| `login_frequency_7d` | 0 | Neutral |
| `failed_login_ratio` | 0.0 | Lowers score |
| `account_age_days` | 0 | Raises score significantly |
| `device_change` | 0 (no previous device to compare) | Neutral |
| `location_change` | 0 (no previous location to compare) | Neutral |

**Expected first login score:** 40–75 range — typically MEDIUM, triggering MFA on the first login.

After a few successful logins from the same device and location, the history builds up and subsequent logins will score in the LOW range.

---

## Quick Reference

```
Add user (fastest):
  python add_user.py

Inspect last risk decision:
  sqlite3 backend/secureauth.db
  > SELECT username, risk_score, risk_level, model_votes, timestamp
    FROM ai_metrics am JOIN users u ON u.id=am.user_id
    ORDER BY am.timestamp DESC LIMIT 1;

Unlock a locked account:
  sqlite3 backend/secureauth.db
  > UPDATE users SET is_locked=0, locked_until=NULL, failed_attempts=0
    WHERE username='alice';

Reset MFA tokens (clear stale):
  sqlite3 backend/secureauth.db
  > DELETE FROM mfa_tokens WHERE used=1 OR expires_at < datetime('now');

View all users:
  sqlite3 backend/secureauth.db
  > SELECT id, username, email, role, is_locked, failed_attempts FROM users;
```
