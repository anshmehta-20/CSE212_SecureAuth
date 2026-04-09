# SecureAuth: An AI-Augmented Enterprise Authentication System with Multi-Layer Security and Explainable Risk Analysis

---

## Abstract

This document presents **SecureAuth**, a production-grade authentication and access control system that integrates a three-model machine learning ensemble with conventional cryptographic security primitives to produce context-aware, risk-driven authentication decisions. The system addresses a fundamental limitation of credential-based authentication: the inability to distinguish a legitimate user from an adversary who has obtained valid credentials. SecureAuth resolves this by constructing a 19-dimensional behavioural feature vector for each authentication event and subjecting it to an ensemble of unsupervised anomaly detectors — Isolation Forest, One-Class Support Vector Machine, and Local Outlier Factor — whose outputs are combined via a weighted voting scheme to yield a normalised risk score on the interval [0, 100]. Authentication outcomes are determined by three discrete risk bands and are accompanied by SHAP-derived, human-readable explanations. The system further incorporates JSON Web Token (JWT) session management, bcrypt credential hashing, role-based access control (RBAC), time-limited multi-factor authentication (MFA) via one-time passwords, and a multi-layer security stack comprising rate limiting, IP-level brute-force tracking, credential-stuffing detection, account lockout, and HTTP security header enforcement. The backend is implemented in Python (Flask) with support for both MySQL and SQLite persistence layers; the frontend is a pure HTML/CSS/JavaScript single-page application adopting an enterprise SaaS aesthetic.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture](#2-architecture)
3. [AI Risk Engine](#3-ai-risk-engine)
   - 3.1 Feature Engineering
   - 3.2 Ensemble Models
   - 3.3 Voting and Score Computation
   - 3.4 Explainability (SHAP)
4. [Authentication Flow](#4-authentication-flow)
5. [Security Subsystems](#5-security-subsystems)
   - 5.1 Password Security
   - 5.2 JSON Web Token Session Management
   - 5.3 Multi-Factor Authentication
   - 5.4 Role-Based Access Control
   - 5.5 Rate Limiting
   - 5.6 Brute-Force Protection
   - 5.7 Credential-Stuffing Detection
   - 5.8 HTTP Security Headers
6. [Database Layer](#6-database-layer)
7. [API Reference](#7-api-reference)
8. [Frontend Interface](#8-frontend-interface)
9. [Project Structure](#9-project-structure)
10. [Installation and Configuration](#10-installation-and-configuration)
11. [Demo Accounts and Test Scenarios](#11-demo-accounts-and-test-scenarios)
12. [Dependencies](#12-dependencies)
13. [Security Considerations and Limitations](#13-security-considerations-and-limitations)

---

## 1. System Overview

Contemporary authentication systems operate on a binary principle: if supplied credentials match a stored record, access is granted. This model is structurally inadequate against threats such as credential stuffing, account takeover following a data breach, pass-the-hash attacks, and automated botnet logins — scenarios in which the attacker possesses the correct password.

SecureAuth proposes a contextual authentication model in which every login event is independently evaluated against a statistical model of the account holder's historical behaviour. The system characterises normal login patterns across temporal, behavioural, network, and statistical dimensions and treats deviations from those patterns as risk signals. The magnitude and breadth of detected deviation determines the authentication outcome:

| Risk Band | Score Range | Action |
|---|---|---|
| **LOW** | 0 – 39 | JWT tokens issued; access granted immediately |
| **MEDIUM** | 40 – 69 | MFA via email OTP required before token issuance |
| **HIGH** | 70 – 100 | Login blocked; SHAP explanation returned to client |

This architecture ensures that a stolen password alone is insufficient to gain access if the login context deviates significantly from established patterns — directly addressing the most prevalent credential-based attack vectors.

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CLIENT (Browser)                            │
│   index.html · mfa.html · dashboard.html · style.css · script.js   │
└────────────────────────────────┬────────────────────────────────────┘
                                 │ HTTP/JSON  (port 5000)
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Flask Application Server                        │
│                                                                     │
│  ┌─────────────────────┐     ┌──────────────────────────────────┐  │
│  │   Auth Blueprint    │     │      Dashboard Blueprint         │  │
│  │  POST /api/login    │     │  GET  /api/me                    │  │
│  │  POST /api/verify-  │     │  GET  /api/history               │  │
│  │       mfa           │     │  GET  /api/risk-summary          │  │
│  │  POST /api/refresh  │     │  GET  /api/analytics  (admin)    │  │
│  │  POST /api/logout   │     │  GET  /api/users      (admin)    │  │
│  │  POST /api/resend-  │     └──────────────────────────────────┘  │
│  │       otp           │                                            │
│  └──────────┬──────────┘                                            │
│             │                                                        │
│  ┌──────────▼──────────────────────────────────────────────────┐   │
│  │                    Security Subsystem                        │   │
│  │  Rate Limiter · Brute-Force Tracker · Credential Stuffer     │   │
│  │  bcrypt Verifier · JWT Manager · Security Headers           │   │
│  └──────────┬───────────────────────────────────────────────────┘  │
│             │                                                        │
│  ┌──────────▼───────────────────────────────────────────────────┐  │
│  │                      AI Risk Engine                          │  │
│  │                                                              │  │
│  │  Feature Engineering (19-dim vector)                         │  │
│  │        │                                                     │  │
│  │        ├──► Isolation Forest  (weight 0.45)  ──► vote +1/-1 │  │
│  │        ├──► One-Class SVM     (weight 0.30)  ──► vote +1/-1 │  │
│  │        └──► Local Outlier Factor (weight 0.25) ─► vote +1/-1│  │
│  │                                                              │  │
│  │  Weighted Score → Risk Level → SHAP Explanation             │  │
│  └──────────┬───────────────────────────────────────────────────┘  │
│             │                                                        │
│  ┌──────────▼───────────────────────────────────────────────────┐  │
│  │              Persistence Layer (MySQL / SQLite)              │  │
│  │  users · login_history · mfa_tokens · refresh_tokens        │  │
│  │  ai_metrics · rate_limit_log                                │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. AI Risk Engine

### 3.1 Feature Engineering

For each authentication event, a 19-dimensional feature vector is constructed from contextual signals. The feature set is partitioned into four semantic groups:

#### Temporal Features (indices 0–4)

| Index | Feature | Description |
|---|---|---|
| 0 | `hour_of_day` | UTC hour of the login attempt (0–23) |
| 1 | `day_of_week` | Day index Monday = 0, Sunday = 6 |
| 2 | `is_weekend` | Binary flag; 1 if Saturday or Sunday |
| 3 | `is_business_hours` | Binary flag; 1 if 09:00–18:00 on a weekday |
| 4 | `time_since_last_login` | Hours elapsed since the most recent recorded login, capped at 168 h (one week) |

#### Behavioural Features (indices 5–8)

| Index | Feature | Description |
|---|---|---|
| 5 | `location_change` | Binary; 1 if the reported location string differs from the most recent login record |
| 6 | `device_change` | Binary; 1 if the MD5 fingerprint of (User-Agent, IP) differs from the most recent record |
| 7 | `login_velocity` | Count of logins recorded in the preceding 60 minutes, capped at 20 |
| 8 | `typing_speed` | Estimated characters per second derived from client-side keydown event timing; simulated if unavailable |

#### Network Features (indices 9–11)

| Index | Feature | Description |
|---|---|---|
| 9 | `ip_risk_score` | Heuristic score in [0, 1] based on IP prefix affiliation with known high-risk CIDR blocks |
| 10 | `vpn_detected` | Binary; 1 if IP prefix matches known VPN/proxy ranges |
| 11 | `country_change` | Binary; used as a proxy for location change at the country level |

#### Statistical Features (indices 12–14)

| Index | Feature | Description |
|---|---|---|
| 12 | `failed_login_ratio` | Proportion of blocked logins in the account's full history |
| 13 | `account_age_days` | Days elapsed since account creation |
| 14 | `login_frequency_7d` | Count of logins in the preceding seven days |

#### Cyclic Encoding (indices 15–18)

To prevent discontinuities at period boundaries (e.g., hour 23 and hour 0 being numerically far despite being adjacent), cyclic features are encoded as sine–cosine pairs:

| Index | Feature |
|---|---|
| 15 | `hour_sin` = sin(2π × hour / 24) |
| 16 | `hour_cos` = cos(2π × hour / 24) |
| 17 | `day_sin`  = sin(2π × weekday / 7) |
| 18 | `day_cos`  = cos(2π × weekday / 7) |

---

### 3.2 Ensemble Models

Three unsupervised anomaly detection algorithms are employed. All models are trained once on a corpus of 1,000 synthetically generated "normal" login vectors and their parameters are serialised to disk via `joblib`; subsequent process instantiations load the cached artefacts without retraining.

#### 3.2.1 Isolation Forest

Isolation Forest (Liu et al., 2008) isolates anomalies by recursively partitioning the feature space with random split points. Anomalous observations require fewer partitions to isolate, yielding shorter path lengths. Configuration:

```
n_estimators = 200
contamination = 0.05
random_state  = 42
```

#### 3.2.2 One-Class Support Vector Machine

One-Class SVM (Schölkopf et al., 2001) learns a decision boundary enclosing the majority of the training distribution in a kernel-induced feature space. Observations falling outside the boundary are classified as anomalous. Configuration:

```
kernel = 'rbf'
nu     = 0.05
gamma  = 'scale'
```

#### 3.2.3 Local Outlier Factor (Novelty Mode)

LOF (Breunig et al., 2000) computes a local density estimate for each observation relative to its k-nearest neighbours. Observations with significantly lower density than their neighbours receive high outlier scores. The model is used in `novelty=True` mode, permitting inference on unseen data without retraining. Configuration:

```
n_neighbors   = 20
contamination = 0.05
novelty       = True
```

---

### 3.3 Voting and Score Computation

Each model independently predicts +1 (inlier / normal) or −1 (outlier / anomalous) for the input vector. Raw anomaly scores from each model are also extracted and normalised to [0, 1] using empirically derived clipping bounds specific to each model's score distribution.

The composite risk score is computed as a weighted average of the three normalised risk components:

```
risk_raw = 0.45 × r_IsolationForest
         + 0.30 × r_OneClassSVM
         + 0.25 × r_LOF
```

Consensus penalties are applied to amplify inter-model agreement:

```
if anomaly_count == 2: risk_raw += 0.10  (capped at 1.0)
if anomaly_count == 3: risk_raw += 0.20  (capped at 1.0)
```

The final risk score is:

```
risk_score = round(risk_raw × 100, 1)    ∈ [0, 100]
```

Confidence is estimated from the degree of model agreement:

```
confidence = 0.70 + (agreement / 3) × 0.25    ∈ [0.70, 0.95]
```

---

### 3.4 Explainability

To satisfy interpretability requirements, SecureAuth returns a human-readable AI analysis alongside each authentication decision.

- High-risk decisions emphasize the strongest anomaly drivers.
- Medium-risk decisions explain why step-up verification was required.
- Low-risk decisions highlight the signals that matched the trusted pattern.

These explanations are returned in the API response and rendered in the dashboard so the decision path is visible during demos and security review.

---

## 4. Authentication Flow

The following sequence describes a complete authentication event:

```
Client                          Server                        Database
  │                               │                               │
  │── POST /api/login ───────────►│                               │
  │   {username, password,        │                               │
  │    typing_speed}              │                               │
  │                               │── Rate limit check ──────────►│
  │                               │── IP brute-force check       │
  │                               │── Credential stuffing check  │
  │                               │── SELECT user ───────────────►│
  │                               │◄─ user row ──────────────────│
  │                               │── Account lock check         │
  │                               │── bcrypt.checkpw()           │
  │                               │── SELECT login_history ──────►│
  │                               │◄─ history rows ──────────────│
  │                               │── Extract 19-dim feature vec  │
  │                               │── IsolationForest.predict()  │
  │                               │── OneClassSVM.predict()       │
  │                               │── LOF.predict()              │
  │                               │── Weighted vote → risk_score │
  │                               │── SHAP explanation           │
  │                               │── INSERT ai_metrics ─────────►│
  │                               │                               │
  │                               │  if HIGH risk:               │
  │◄─ 403 {blocked, score, expl}─│── INSERT login_history ──────►│
  │                               │                               │
  │                               │  if MEDIUM risk:             │
  │                               │── INSERT mfa_tokens ─────────►│
  │                               │── Send OTP via Resend API    │
  │◄─ 200 {mfa_required, token} ─│                               │
  │                               │                               │
  │── POST /api/verify-mfa ──────►│                               │
  │   {mfa_token, otp}           │── SELECT mfa_token ──────────►│
  │                               │── bcrypt.checkpw(otp)        │
  │                               │── UPDATE mfa_token used=1 ───►│
  │                               │                               │
  │                               │  if LOW risk OR MFA verified: │
  │                               │── CREATE access_token (JWT)  │
  │                               │── CREATE refresh_token (JWT) │
  │                               │── INSERT refresh_tokens ─────►│
  │◄─ 200 {access_token,         │── INSERT login_history ──────►│
  │        refresh_token, user} ─│                               │
```

---

## 5. Security Subsystems

### 5.1 Password Security

Passwords are hashed using **bcrypt** with a randomly generated salt at an automatically determined work factor (default rounds ≥ 12). The plaintext password is never logged, stored, or returned in any API response. The system employs a uniform error message for both "username not found" and "incorrect password" to prevent username enumeration.

### 5.2 JSON Web Token Session Management

SecureAuth issues two classes of JWT tokens, both signed with the HS256 algorithm:

| Token Type | Lifetime | Purpose |
|---|---|---|
| **Access Token** | 15 minutes | Authorises API requests via `Authorization: Bearer` header |
| **Refresh Token** | 7 days | Exchanges for a new access token at `/api/refresh` |

Refresh tokens are persisted to the database in SHA-256-hashed form, allowing server-side revocation at logout. The SHA-256 hash prevents use of the database record to re-derive the token. Token rotation (issuing a new access token on each refresh) limits the exposure window of any compromised token.

### 5.3 Multi-Factor Authentication

When the AI engine classifies a login as MEDIUM risk, the following MFA protocol is executed:

1. A cryptographically secure 6-digit OTP is generated using `random.SystemRandom` (backed by the OS CSPRNG).
2. The OTP is hashed with bcrypt and stored in the `mfa_tokens` table alongside a UUID session token and a 5-minute expiry timestamp.
3. The OTP is dispatched to the account's registered email address via the Resend transactional email API.
4. The client submits the OTP and the session UUID to `/api/verify-mfa`; the server verifies the bcrypt hash and enforces the expiry constraint.
5. Upon successful verification, the MFA token is marked as consumed (`used = 1`) and standard JWT tokens are issued.

The OTP is never stored in plaintext; the bcrypt hash ensures that a database breach does not expose valid OTPs.

### 5.4 Role-Based Access Control

Each user record carries a `role` field (`user` or `admin`). The role is embedded in the JWT claims at token issuance and validated by server-side decorators on every protected route:

- `require_auth` — validates the access token and attaches the decoded payload to the request context.
- `require_admin` — extends `require_auth` with an additional check that `role == 'admin'`.

Admin-only endpoints (`/api/analytics`, `/api/users`) return HTTP 403 if a non-admin token is presented.

### 5.5 Rate Limiting

A sliding-window rate limiter tracks the timestamp of every request from each IP address in a thread-safe in-memory dictionary. Requests exceeding 20 per 60-second window are rejected with HTTP 429 and a `Retry-After` value.

### 5.6 Brute-Force Protection

Two independent brute-force countermeasures operate in parallel:

**IP-level tracker** (`security/protection.py`): A failed authentication from any account increments a per-IP counter. When the counter reaches 5 within a 15-minute window, all subsequent requests from that IP return HTTP 403.

**Account-level tracker** (`models/user.py`): Each failed password verification increments `users.failed_attempts`. Upon reaching 5 failures, the account is locked (`is_locked = 1`) and a `locked_until` timestamp is set 15 minutes in the future. The lock is automatically lifted on the next login attempt after the timestamp elapses.

### 5.7 Credential-Stuffing Detection

A secondary in-memory data structure records (timestamp, username) pairs per source IP. If a single IP submits authentication requests for 4 or more distinct usernames within any 30-second window, the request is rejected with HTTP 403 and the event is logged. This pattern is characteristic of automated credential-stuffing attacks that cycle through a password database across multiple accounts.

### 5.8 HTTP Security Headers

Every HTTP response includes the following headers, applied globally via a Flask `after_request` hook:

| Header | Value |
|---|---|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `X-XSS-Protection` | `1; mode=block` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `Content-Security-Policy` | Restricts script, style, font, and connection sources to known safe origins |

---

## 6. Database Layer

SecureAuth supports two database backends selected via the `DB_TYPE` environment variable:

| Value | Driver | Use Case |
|---|---|---|
| `mysql` | PyMySQL (pure Python) | Production — requires a running MySQL 8.x server |
| `sqlite` | stdlib `sqlite3` | Development — zero-configuration, file-based |

The abstraction layer (`database.py`) exposes a unified `execute(conn, sql, params)` helper that automatically translates `?` positional placeholders to `%s` for MySQL, ensuring that all query strings in the application are written once and remain compatible with both backends.

The schema comprises six tables:

| Table | Purpose |
|---|---|
| `users` | Account records with bcrypt password hash, role, lock state |
| `login_history` | Per-event audit log with IP, device, location, risk score, and status |
| `mfa_tokens` | bcrypt-hashed OTPs with UUID session tokens and expiry timestamps |
| `refresh_tokens` | SHA-256-hashed JWT refresh tokens with revocation flag |
| `ai_metrics` | Full AI audit trail: feature vectors, model votes, scores, explanations |
| `rate_limit_log` | Reserved for persistent rate-limit event archiving |

---

## 7. API Reference

All endpoints are prefixed with `/api`. Authenticated endpoints require the header `Authorization: Bearer <access_token>`.

### Authentication

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/login` | None | Submit credentials; returns risk analysis and token or MFA token |
| `POST` | `/api/verify-mfa` | None | Submit OTP and MFA session token; returns JWT tokens |
| `POST` | `/api/resend-otp` | None | Invalidate current OTP and issue a new one |
| `POST` | `/api/refresh` | None | Exchange refresh token for new access token |
| `POST` | `/api/logout` | None | Revoke refresh token |

### User

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/me` | User | Returns authenticated user's profile |
| `GET` | `/api/history` | User | Returns paginated login history |
| `GET` | `/api/risk-summary` | User | Returns most recent AI risk assessment |

### Administration

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/analytics` | Admin | Returns 7-day aggregated statistics, daily chart data, risk distribution |
| `GET` | `/api/users` | Admin | Returns full user table |

### Request / Response Examples

**POST /api/login**
```json
Request:
{
  "username": "alice",
  "password": "SecurePass123!",
  "typing_speed": 4.2
}

Response (LOW risk, 200):
{
  "status":        "success",
  "access_token":  "eyJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiJ9...",
  "risk_score":    22.5,
  "risk_level":    "LOW",
  "confidence":    0.92,
  "explanation":   "LOGIN ALLOWED\nRisk Score: 22/100\n\nSummary: ...",
  "user":          { "id": 1, "username": "alice", "role": "user" }
}

Response (HIGH risk, 403):
{
  "status":      "blocked",
  "error":       "Login blocked for security reasons.",
  "risk_score":  88.0,
  "risk_level":  "HIGH",
  "confidence":  0.95,
  "explanation": "LOGIN BLOCKED\n\nRisk Score: 88/100\n\nSummary: Multiple
                  high-risk indicators detected...\n\nAnalysis:\n  • New
                  device detected...\n  • Location differs from usual..."
}
```

---

## 8. Frontend Interface

The frontend is a three-page single-page application served directly by the Flask process from the `frontend/` directory. No Node.js runtime, build tool, or bundler is required.

| Page | File | Description |
|---|---|---|
| **Sign-in** | `index.html` | Credential form, demo account selector, result modal |
| **Verification** | `mfa.html` | 6-box OTP entry, countdown timer, resend control |
| **Dashboard** | `dashboard.html` | Risk overview, login history table, admin analytics |

**Design principles**: The interface follows an enterprise SaaS aesthetic modelled on Stripe, GitHub, and Linear — dark slate background (#0f172a), flat card surfaces (#111827), Inter typography, 8 px spacing grid, and subtle 200 ms fade-and-translate transitions. All status indicators use coloured dots and text badges rather than iconographic ornamentation.

**Client-side security**: Tokens are stored in `sessionStorage` (cleared on tab close) rather than `localStorage` or cookies, limiting both XSS exposure window and CSRF attack surface. All API calls include the `Authorization` header; no session cookies are set.

---

## 9. Project Structure

```
SecureAuth/
│
├── backend/
│   ├── app.py                    # Flask application factory and entry point
│   ├── database.py               # Connection manager, schema DDL, query helpers, data seeding
│   │
│   ├── ai/
│   │   ├── ensemble_model.py     # IsolationForest + OneClassSVM + LOF ensemble
│   │   ├── explainable_ai.py     # SHAP computation and natural-language explanation generation
│   │   ├── feature_engineering.py# 19-dimensional behavioural feature extractor
│   │   └── model_persistence.py  # joblib serialisation and deserialisation of trained models
│   │
│   ├── jwt_handler/
│   │   └── jwt_manager.py        # JWT creation, verification, refresh, and revocation
│   │
│   ├── mfa/
│   │   └── otp_manager.py        # OTP generation, bcrypt storage, Resend email dispatch
│   │
│   ├── models/
│   │   └── user.py               # User data model: password verification, locking, history
│   │
│   ├── routes/
│   │   ├── auth.py               # /login, /verify-mfa, /refresh, /logout, /resend-otp
│   │   └── dashboard.py          # /me, /history, /risk-summary, /analytics, /users
│   │
│   └── security/
│       └── protection.py         # Rate limiter, brute-force tracker, credential-stuffing detector,
│                                 # account locker, HTTP security header injector
│
├── frontend/
│   ├── index.html                # Authentication page
│   ├── mfa.html                  # OTP verification page
│   ├── dashboard.html            # Security overview and administration panel
│   ├── style.css                 # Enterprise design system (variables, components, layouts)
│   └── script.js                 # Page logic, API calls, JWT management, chart rendering
│
├── config/
│   ├── .env.example              # Annotated environment variable template
│   └── models/                   # Serialised AI model artefacts (auto-generated on first run)
│
├── requirements.txt              # Python package dependencies
└── SETUP.md                      # Operational guide
```

---

## 10. Installation and Configuration

### Prerequisites

- Python 3.9 or later
- pip
- A running MySQL 8.x instance (optional; SQLite requires no server)
- A Resend API key and verified sending domain (optional; OTPs are printed to stdout in development)

### Procedure

**Step 1 — Clone the repository**
```bash
git clone <repository-url>
cd SecureAuth
```

**Step 2 — Install Python dependencies**
```bash
pip install -r requirements.txt
```

**Step 3 — Configure environment**
```bash
cp config/.env.example config/.env
```

Edit `config/.env` and set the following variables at minimum:

```ini
SECRET_KEY=<random 32+ character string>
JWT_SECRET_KEY=<random 32+ character string>

# Database backend (choose one)
DB_TYPE=sqlite                # Development (default)
DB_TYPE=mysql                 # Production

# MySQL — required only when DB_TYPE=mysql
DB_HOST=localhost
DB_PORT=3306
DB_NAME=secureauth_db
DB_USER=secureauth_user
DB_PASSWORD=<password>

# MFA email delivery — omit to use console output in development
RESEND_API_KEY=re_<key>
MFA_FROM_EMAIL=noreply@yourdomain.com
```

**Step 4 — Provision MySQL (if applicable)**

```sql
CREATE DATABASE secureauth_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'secureauth_user'@'localhost' IDENTIFIED BY '<password>';
GRANT ALL PRIVILEGES ON secureauth_db.* TO 'secureauth_user'@'localhost';
FLUSH PRIVILEGES;
```

**Step 5 — Start the server**
```bash
python backend/app.py
```

On first startup, the server will:
1. Initialise the database schema (all six tables)
2. Seed four demo user accounts with 25 synthetic login history records each
3. Train the AI ensemble on 1,000 synthetic normal-behaviour vectors
4. Serialise the trained models to `config/models/`
5. Start serving on `http://localhost:5000`

Subsequent startups will load cached models directly, reducing startup time to under one second.

---

## 11. Demo Accounts and Test Scenarios

The following accounts are automatically seeded on first startup:

| Username | Password | Role | Seeded Risk Profile | Expected Behaviour (new session) |
|---|---|---|---|---|
| `alice` | `SecurePass123!` | User | LOW (scores 5–30) | HIGH block — new device/IP differs from seeded history |
| `bob` | `Pass@2024` | User | MEDIUM (scores 35–65) | HIGH or MFA — location and device flags |
| `charlie` | `Admin@999` | User | HIGH (scores 60–95) | HIGH block |
| `admin` | `AdminSecure1!` | Admin | LOW (scores 5–25) | HIGH block; admin panel accessible after history builds |

> **Note on expected behaviour**: The seeded login history records private IP addresses (192.168.x.x) and location strings matching Indian cities. A login from a fresh session with a different IP and User-Agent string will produce high location-change and device-change feature values, causing the ensemble to classify the attempt as HIGH risk. This is the correct and intended behaviour — it demonstrates that even with valid credentials, access is denied to an unrecognised context. The AI models will score sessions as lower risk once legitimate logins from a given environment accumulate in the history.

### Scenario: Stolen Credentials (Primary Demonstration)

> **Current demo note:** On a freshly seeded environment, the intended demo bands are `alice` = LOW, `bob` = MEDIUM, `charlie` = HIGH, and `admin` = LOW with dashboard access. If you are testing locally with an older database, reset `backend/secureauth.db` before rerunning the demo.

This scenario illustrates the core security guarantee of the system:

```
Precondition:  An attacker has obtained alice's correct password
               (e.g., via a phishing attack or data breach).

Attack:        Attacker attempts login from a different IP address
               and device than alice normally uses.

Feature vector (attacker session):
  location_change  = 1  (different from seeded location)
  device_change    = 1  (new User-Agent + IP hash)
  vpn_detected     = 1  (or IP risk score elevated)
  time_since_last  = 168 (no recent login from this context)
  country_change   = 1

AI Decision:
  IsolationForest  → -1 (anomaly)
  OneClassSVM      → -1 (anomaly)
  LocalOutlierFactor → -1 (anomaly)
  anomaly_count    = 3
  risk_score       = ~88/100
  risk_level       = HIGH

Outcome:  HTTP 403, access denied.
          Explanation returned to client identifying the anomalous signals.
          Login event recorded in audit log with status = 'blocked'.
```

---

## 12. Dependencies

> **Current note:** The deployed build uses the human-readable AI analysis path and does not require `shap` to be installed in production.

| Package | Version | Purpose |
|---|---|---|
| Flask | ≥ 3.0.0 | HTTP application framework |
| flask-cors | ≥ 4.0.0 | Cross-Origin Resource Sharing configuration |
| flask-limiter | ≥ 3.5.0 | Rate limiting middleware reference (custom implementation used) |
| PyJWT | ≥ 2.8.0 | JSON Web Token encoding and decoding |
| bcrypt | ≥ 4.1.0 | Password and OTP hashing |
| scikit-learn | ≥ 1.4.0 | IsolationForest, OneClassSVM, LocalOutlierFactor |
| shap | ≥ 0.44.0 | SHapley Additive exPlanations |
| joblib | ≥ 1.3.0 | Model serialisation |
| numpy | ≥ 1.26.0 | Numerical feature vector operations |
| scipy | ≥ 1.12.0 | Scientific computing (SHAP dependency) |
| python-dotenv | ≥ 1.0.0 | Environment variable loading |
| PyMySQL | ≥ 1.1.0 | Pure-Python MySQL driver |
| cryptography | ≥ 42.0.0 | PyMySQL SSL support |
| resend | ≥ 2.0.0 | Transactional email delivery |

**Frontend dependencies** (loaded from CDN, no local installation required):

| Library | Version | Purpose |
|---|---|---|
| Chart.js | 4.4.2 | Bar and doughnut chart rendering on the admin dashboard |
| Inter (Google Fonts) | — | Primary typeface |

---

## 13. Security Considerations and Limitations

### Production Deployment Requirements

The following configuration changes are mandatory before deploying SecureAuth in a production environment:

1. **SECRET_KEY and JWT_SECRET_KEY** must be set to randomly generated strings of at least 32 characters and must never be committed to version control.
2. **DB_TYPE=mysql** must be used; the SQLite backend does not provide adequate concurrency guarantees or access controls for multi-user production workloads.
3. The Flask development server (`app.run(debug=True)`) must be replaced with a production WSGI server (e.g., Gunicorn, uWSGI) behind an Nginx or Caddy reverse proxy.
4. **HTTPS** must be enforced at the reverse proxy level; the `Strict-Transport-Security` header has no effect over plain HTTP.
5. **RESEND_API_KEY** must be configured with a verified sending domain; the console-fallback OTP delivery mode is suitable only for development and testing.

### Known Limitations

- **In-memory rate-limit and brute-force state** is not shared across multiple Flask worker processes or server instances. A Redis-backed alternative is required for high-availability or load-balanced deployments.
- **IP geolocation** is approximated by the client-supplied `location` request parameter and the heuristic IP-risk and VPN-detection functions; a production system should integrate a reputable IP intelligence API (e.g., MaxMind GeoIP2, ipinfo.io).
- **AI model drift**: The synthetic training data encodes a specific definition of "normal" behaviour (business hours, Indian timezone context, low velocity). In a production deployment, models should be retrained periodically on real historical login data for the specific user population.
- **Typing speed** is measured at the client and submitted as a request parameter, making it susceptible to manipulation by a sophisticated attacker. It should be treated as a soft signal rather than a hard security control.
- **Feature vector dimensions** are fixed at 19 at training time. Adding or removing features requires full model retraining.

---

## References

- Breunig, M. M., Kriegel, H.-P., Ng, R. T., & Sander, J. (2000). LOF: Identifying density-based local outliers. *Proceedings of the 2000 ACM SIGMOD International Conference on Management of Data*, 93–104.
- Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008). Isolation forest. *Proceedings of the IEEE International Conference on Data Mining (ICDM 2008)*, 413–422.
- Lundberg, S. M., & Lee, S.-I. (2017). A unified approach to interpreting model predictions. *Advances in Neural Information Processing Systems*, 30.
- Provos, N., & Mazieres, D. (1999). A future-adaptable password scheme. *Proceedings of the 1999 USENIX Annual Technical Conference*, 81–92. (bcrypt)
- Schölkopf, B., Platt, J. C., Shawe-Taylor, J., Smola, A. J., & Williamson, R. C. (2001). Estimating the support of a high-dimensional distribution. *Neural Computation*, 13(7), 1443–1471.

---

*SecureAuth is developed as a demonstration of applied machine learning in cybersecurity. All AI risk thresholds, feature weights, and security policy parameters are configurable and should be calibrated to the specific threat model and user population of the target deployment environment.*
