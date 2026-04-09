# 🔐 SecureAuth – Setup & Run Guide

## Quick Start

### 1. Copy environment config
```bash
cp config/.env.example config/.env
```
Edit `config/.env` and set:
- `RESEND_API_KEY` – your Resend.com API key (for MFA emails)
- `MFA_FROM_EMAIL` – your verified sender email
- (Optional) MariaDB credentials if not using SQLite

### 2. Install Python dependencies
```bash
pip install -r requirements.txt
```
> Requires Python 3.9+. Tested on Python 3.13.

### 3. Start the server
```bash
python backend/app.py
```

On first launch this will:
- Create the SQLite database (`backend/secureauth.db`)
- Seed 4 demo users + 25 login history entries each
- Train the 3-model AI ensemble and save to `config/models/`
- Start Flask at **http://localhost:5000**

> Subsequent launches use cached models (instant startup).

---

## Demo Users

| Username | Password | Role | Behavior |
|---|---|---|---|
| `alice` | `SecurePass123!` | user | Normal pattern → LOW risk |
| `bob` | `Pass@2024` | user | Mixed location → MEDIUM risk (MFA) |
| `charlie` | `Admin@999` | user | Night/VPN/new device → HIGH risk (blocked) |
| `admin` | `AdminSecure1!` | admin | Admin role → analytics panel |

> **Note:** All users are flagged HIGH on first login from a genuinely new environment (new device, new IP, new location) – this is by design and demonstrates the AI working correctly. The risk will lower as login history builds.

---

> **Current demo note:** On a freshly seeded database, the intended demo bands are `alice` = LOW, `bob` = MEDIUM, and `charlie` = HIGH. If your local results drift from that, delete `backend/secureauth.db` and restart the app so the demo data reseeds.

## API Reference

### POST /api/login
```json
{ "username": "alice", "password": "SecurePass123!" }
```
**Low risk response (200):**
```json
{
  "status": "success",
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "risk_score": 22.5,
  "risk_level": "LOW",
  "confidence": 0.92,
  "explanation": "✅ LOGIN ALLOWED\n...",
  "user": { "id": 1, "username": "alice", "role": "user" }
}
```

**MFA required response (200):**
```json
{
  "status": "mfa_required",
  "mfa_token": "uuid-...",
  "risk_score": 55.0,
  "risk_level": "MEDIUM"
}
```

**Blocked response (403):**
```json
{
  "status": "blocked",
  "risk_score": 87.0,
  "risk_level": "HIGH",
  "explanation": "🚫 LOGIN BLOCKED\n\nAnalysis:\n  • VPN detected..."
}
```

### POST /api/verify-mfa
```json
{ "mfa_token": "uuid-...", "otp": "123456" }
```
Returns same success response as login.

### POST /api/refresh  
```json
{ "refresh_token": "eyJ..." }
```
Returns new `access_token`.

### GET /api/me  *(requires Bearer token)*
Returns current user info.

### GET /api/history  *(requires Bearer token)*
Returns login history for the current user.

### GET /api/analytics  *(admin only)*
Returns 7-day analytics, daily chart data, risk distribution.

### GET /api/users  *(admin only)*
Returns all users list.

---

## UI Pages

| Page | URL |
|---|---|
| Login | http://localhost:5000/ |
| MFA | http://localhost:5000/mfa.html |
| Dashboard | http://localhost:5000/dashboard.html |

---

## Security Features

| Feature | Implementation |
|---|---|
| Rate Limiting | 20 req/min per IP (sliding window) |
| Brute Force | 5 failed → IP lockout for 15 min |
| Credential Stuffing | 4+ distinct usernames from 1 IP in 30s |
| Account Lockout | 5 failed → account locked (per-user) |
| Password Hashing | bcrypt with random salt |
| JWT | Access: 15min, Refresh: 7 days, revokable |
| MFA | 6-digit OTP, bcrypt-hashed, 5-min expiry |
| Security Headers | X-Frame-Options, HSTS, XSS-Protection, CSP |

---

## AI Architecture

```
Feature Vector (19 dimensions)
 ├─ Temporal: hour, dow, is_weekend, is_business_hours, time_since_last
 ├─ Behavioral: location_change, device_change, velocity, typing_speed
 ├─ Network: ip_risk_score, vpn_detected, country_change
 ├─ Statistical: failed_login_ratio, account_age_days, login_frequency_7d
 └─ Cyclic: hour_sin, hour_cos, day_sin, day_cos
           │
     ┌─────▼──────┐
     │  Ensemble  │
     ├────────────┤
     │ IF (45%)   │  IsolationForest – tree-based outlier detection
     │ SVM (30%)  │  OneClassSVM – kernel-based boundary
     │ LOF (25%)  │  LocalOutlierFactor – density-based
     └─────┬──────┘
           │
    Risk Score 0–100
           │
    < 40 → ✅ ALLOW         → JWT tokens issued
   40–70 → ⚠️ MFA REQUIRED  → OTP email via Resend
    > 70 → 🚫 BLOCK          → SHAP explanation returned
```

---

## Project Structure

```
SecureAuth/
├── backend/
│   ├── app.py                    # Flask factory + startup
│   ├── database.py               # SQLite/MariaDB + schema + seeding
│   ├── models/
│   │   └── user.py               # User model (bcrypt, locking, history)
│   ├── routes/
│   │   ├── auth.py               # /login, /verify-mfa, /refresh, /logout
│   │   └── dashboard.py          # /me, /history, /analytics, /users
│   ├── ai/
│   │   ├── feature_engineering.py # 19-feature extractor
│   │   ├── ensemble_model.py     # IF + SVM + LOF ensemble
│   │   ├── explainable_ai.py     # SHAP + human-readable bullets
│   │   └── model_persistence.py  # joblib save/load
│   ├── security/
│   │   └── protection.py         # Rate limit, brute force, stuffing
│   ├── mfa/
│   │   └── otp_manager.py        # OTP gen, storage, Resend email
│   └── jwt_handler/
│       └── jwt_manager.py        # JWT create/verify/revoke
│
├── frontend/
│   ├── index.html                # Login page
│   ├── mfa.html                  # OTP verification
│   ├── dashboard.html            # Risk dashboard + admin panel
│   ├── style.css                 # Dark glassmorphism theme
│   └── script.js                 # Frontend logic
│
├── config/
│   ├── .env.example              # Environment template
│   └── models/                   # Saved AI models (auto-generated)
│
├── requirements.txt
└── SETUP.md                      # This file
```

---

## Configure MFA (Resend)

1. Sign up at [resend.com](https://resend.com)
2. Create an API key
3. Verify your sending domain
4. Set in `config/.env`:
   ```
   RESEND_API_KEY=re_your_actual_key
   MFA_FROM_EMAIL=noreply@yourdomain.com
   ```
5. Update demo user emails to real addresses in the DB:
   ```sql
   UPDATE users SET email='real@email.com' WHERE username='bob';
   ```

> **Dev mode:** If `RESEND_API_KEY` is not set or starts with `re_your_`, OTPs are printed to the server console instead of emailed.

---

## Force AI Retrain

Delete cached models to retrain from scratch:
```python
from ai.model_persistence import delete_models
delete_models()
# Then restart the server
```
