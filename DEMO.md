# SecureAuth — Verification & Demo Guide

This document provides step-by-step procedures to verify that every component of the SecureAuth system is functioning correctly. Execute each section in order on a fresh installation.

---

## Prerequisites

Ensure the server is running before proceeding:

```bash
cd SecureAuth
python backend/app.py
```

Expected startup output:
```
[INFO] Initializing database ...
[INFO] SQLite database initialised at .../secureauth.db
[INFO] Demo data already present – skipping seed.
[INFO] Loading AI ensemble ...
[INFO] Models loaded from disk.
[INFO] SecureAuth starting on http://localhost:5000
* Running on http://127.0.0.1:5000
```

Open your browser and navigate to: **http://localhost:5000**

---

## Section 1 — Health Check

Verify the API server is online.

**Method:** Open a new browser tab and visit:
```
http://localhost:5000/health
```

**Expected response:**
```json
{ "status": "ok", "service": "SecureAuth API" }
```

**Pass criteria:** HTTP 200, JSON body as shown above.

---

## Section 2 — Login Page (UI)

**Step 2.1 — Page renders correctly**

Navigate to `http://localhost:5000`

Verify:
- [ ] Glassmorphism card is visible against the dark gradient background
- [ ] Animated ambient orbs are visible (blue top-left, purple bottom-right)
- [ ] "SecureAuth" brand name appears with blue-purple gradient icon
- [ ] Username and Password input fields are present with labels
- [ ] "Sign in" button is visible with gradient fill
- [ ] "Demo accounts" panel is visible at the bottom with 4 entries
- [ ] Each demo row shows a coloured status dot (green, amber, red, blue)

**Step 2.2 — Demo credential auto-fill**

Click the "Low Risk" row (alice / SecurePass123!)

Verify:
- [ ] Username field populates with `alice`
- [ ] Password field populates with `SecurePass123!`

**Step 2.3 — Form validation**

Clear both fields and click "Sign in"

Verify:
- [ ] Username field border turns red
- [ ] "Username is required." error message appears below the field
- [ ] Password field border turns red
- [ ] "Password is required." error message appears below the field

**Step 2.4 — Password toggle**

With a password entered, click the eye icon

Verify:
- [ ] Password text is revealed (input type changes to text)
- [ ] Clicking again hides the password

---

## Section 3 — AI Risk Engine: HIGH Risk Block

This test verifies the primary security scenario: stolen credentials blocked by AI.

**Steps:**

1. Click the "High Risk (blocked)" demo row (charlie / Admin@999)
2. Click "Sign in"
3. Wait for the result (approximately 2 seconds while AI scores the login)

**Expected behaviour:**

- [ ] Loading spinner appears on the button during AI processing
- [ ] A modal overlay appears with blurred backdrop
- [ ] Modal header shows a **red dot** and the title "Login blocked"
- [ ] Subtitle reads: "Risk score X/100 — access denied by AI policy"
- [ ] Risk score is displayed as a large number (typically 70–95)
- [ ] Score is rendered with blue-purple gradient text
- [ ] The "HIGH" badge is visible in red
- [ ] Risk progress bar is red and filled to the score percentage
- [ ] "AI Analysis" section shows the SHAP explanation text block
- [ ] Explanation mentions factors such as "New device detected", "Location differs", etc.
- [ ] "Try again" and "Close" buttons are present
- [ ] HTTP 403 is returned (visible in browser devtools Network tab)

**Server log should show:**
```
[WARNING] routes.auth – Login BLOCKED for user=charlie score=XX.X
```

**Pass criteria:** Login is denied despite correct password — AI correctly identifies the unfamiliar login context.

---

## Section 4 — AI Risk Engine: MEDIUM Risk (MFA Flow)

**Steps:**

1. Click the "Medium Risk (MFA)" demo row (bob / Pass@2024)
2. Click "Sign in"

**Expected behaviour:**

- [ ] Modal appears with an **amber dot** and title "Verification required"
- [ ] Risk score is in the 40–69 range (MEDIUM band)
- [ ] Badge shows "MEDIUM" in amber
- [ ] Button "Enter verification code" is present
- [ ] HTTP 200 is returned with `status: mfa_required`

3. Click "Enter verification code"

**Expected behaviour:**

- [ ] Browser navigates to `mfa.html`
- [ ] Glassmorphism card renders with 6 OTP input boxes
- [ ] Countdown timer shows 5:00 and counts down
- [ ] Risk context bar is visible showing the score from step 2

4. Check the server console for the OTP:

```
==================================================
MFA OTP (dev mode)
  User:  bob
  Email: bob@demo.com
  OTP:   XXXXXX
  Expires in 5 minutes
==================================================
```

5. Type the 6-digit OTP into the boxes (one digit per box)
6. Click "Verify code"

**Expected behaviour:**

- [ ] Success alert appears: "Verified. Redirecting to dashboard..."
- [ ] Browser navigates to `dashboard.html` after ~1 second

**Pass criteria:** MFA challenge is issued on medium-risk login; OTP verification grants access.

---

## Section 5 — LOW Risk Login and Dashboard

**Steps:**

1. Return to `http://localhost:5000`
2. Click the "Low Risk" demo row (alice / SecurePass123!)
3. Click "Sign in"

> **Note:** Alice will likely score HIGH on a fresh session because the seeded login history uses different IPs and locations. If blocked, this is correct AI behaviour. To test the dashboard directly, proceed to step 4 using admin.

4. Use the "Admin account" row (admin / AdminSecure1!) instead and click "Sign in"

**Expected behaviour after a successful login (success modal):**

- [ ] Modal shows a **green dot** and title "Login successful"
- [ ] "Go to dashboard" button is present
- [ ] Clicking "Go to dashboard" navigates to `dashboard.html`

**Dashboard verification:**

- [ ] Sticky glassmorphism navbar is visible (blurred background)
- [ ] Username and initial avatar shown in top-right user pill
- [ ] "Admin" tag visible (purple badge) for the admin account
- [ ] "Overview", "History", and "Admin" tabs are available
- [ ] Three stat cards show: Last risk score, Risk level badge, Model confidence
- [ ] Risk assessment card shows large gradient score number
- [ ] Risk bar animates to the correct percentage over ~1 second
- [ ] SHAP explanation block shows the AI analysis text

5. Click the **History** tab

Verify:
- [ ] Login history table loads with entries
- [ ] Each row shows timestamp, IP, location, score, level badge, and status badge
- [ ] Status badges are colour-coded (green = Allowed, amber = MFA, red = Blocked)

6. Click the **Admin** tab (only visible for admin account)

Verify:
- [ ] Three admin stat cards load (Users, Logins 7d, Blocked)
- [ ] Daily login bar chart renders
- [ ] Risk distribution doughnut chart renders (green/amber/red segments)
- [ ] All Users table loads with 4 demo accounts

---

## Section 6 — Brute-Force Protection

**Steps:**

1. Navigate to `http://localhost:5000`
2. Enter username `alice` and password `wrongpassword`
3. Click "Sign in" — note the error message
4. Repeat with incorrect password 4 more times (5 total attempts)

**Expected behaviour:**

- [ ] After 5 failed attempts, the error changes to: "Too many failed attempts from your IP. Try again later."
- [ ] HTTP 403 is returned with `"locked": true`

**Server logs should show:**
```
[INFO] security.protection – Brute force counter IP=127.0.0.1 count=1
[INFO] security.protection – Brute force counter IP=127.0.0.1 count=2
...
```

**Pass criteria:** IP is blocked after 5 consecutive failures.

> **Reset:** Restart the server to clear in-memory brute-force state, or wait 15 minutes.

---

## Section 7 — Rate Limiting

**Steps:**

Using the browser's DevTools console (F12), run the following:

```javascript
let count = 0;
const interval = setInterval(async () => {
  const r = await fetch('http://localhost:5000/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'test', password: 'test' })
  });
  count++;
  console.log(`Request ${count}: HTTP ${r.status}`);
  if (count >= 25) clearInterval(interval);
}, 100);
```

**Expected behaviour:**

- [ ] First ~20 requests return HTTP 401 (invalid credentials)
- [ ] Requests 21+ return HTTP 429 with body: `"Too many requests. Try again in Xs."`

**Server logs should show:**
```
[WARNING] security.protection – Rate limit hit: IP=127.0.0.1, count=21
```

---

## Section 8 — MFA Resend and Expiry

**Steps:**

1. Trigger MFA by logging in as `bob`
2. On the MFA page, wait for the code to expire (5 minutes) OR verify the Resend button enables after ~30 seconds
3. Click "Resend code"

**Expected behaviour:**

- [ ] Success alert: "A new code has been sent to your email."
- [ ] New OTP is printed to the server console
- [ ] Previous OTP no longer works (marked as used)
- [ ] Countdown timer resets to 5:00

---

## Section 9 — Token Refresh and Session Persistence

**Steps:**

1. Log in successfully (admin account)
2. Open DevTools > Application > Session Storage
3. Verify keys: `sa_token`, `sa_refresh`, `sa_user`, `sa_risk`
4. Copy the value of `sa_token` — it is a JWT
5. Decode it at https://jwt.io and verify:
   - `sub` matches the user ID
   - `username` matches the login
   - `role` is `admin`
   - `exp` is ~15 minutes from now

6. Without refreshing the page, wait for the token to expire (or manually manipulate `exp` in `jwt_manager.py` to 10 seconds for testing)
7. The dashboard's `setInterval` auto-refresh calls `/api/refresh` every 12 minutes automatically

**Expected behaviour:**

- [ ] Access token is renewed silently in the background
- [ ] Dashboard remains functional without manual re-login

---

## Section 10 — Logout

**Steps:**

1. While logged in on the dashboard, click "Sign out"

**Expected behaviour:**

- [ ] Browser navigates to `index.html`
- [ ] `sessionStorage` is cleared (verify in DevTools)
- [ ] Navigating directly to `dashboard.html` redirects back to login
- [ ] The refresh token is marked as revoked in the database

**Verify revocation:**

Using a SQLite browser or `sqlite3` CLI:
```sql
.open backend/secureauth.db
SELECT token_hash, revoked FROM refresh_tokens ORDER BY created_at DESC LIMIT 5;
```

The most recent token should have `revoked = 1`.

---

## Section 11 — Database Integrity

```bash
cd SecureAuth
python -c "
from backend.database import get_connection, execute, dict_from_row
conn = get_connection()
for table in ['users','login_history','mfa_tokens','refresh_tokens','ai_metrics']:
    cur = execute(conn, f'SELECT COUNT(*) AS cnt FROM {table}')
    row = dict_from_row(cur.fetchone())
    print(f'{table:20s} : {row[\"cnt\"]} rows')
conn.close()
"
```

**Expected output (approximate after demo data seeding):**
```
users                : 4 rows
login_history        : 100+ rows
mfa_tokens           : 0-5 rows
refresh_tokens       : 1-5 rows
ai_metrics           : 1+ rows (populated after first login)
```

---

## Section 12 — AI Model Files

Verify that trained model artefacts exist:

```bash
ls config/models/
```

**Expected output:**
```
isolation_forest.pkl
one_class_svm.pkl
local_outlier_factor.pkl
```

**Force retraining** (if needed):
```bash
# Delete cached models to force retrain on next startup
rm -rf config/models/
python backend/app.py
# Startup will train and save new models
```

---

## Summary Checklist

| # | Component | Test Method |
|---|---|---|
| 1 | API health | GET /health |
| 2 | Login UI & validation | Manual browser |
| 3 | HIGH risk block (AI) | Login as charlie |
| 4 | MEDIUM risk + MFA flow | Login as bob |
| 5 | LOW risk + dashboard | Login as admin |
| 6 | Brute-force protection | 5 wrong passwords |
| 7 | Rate limiting | 25 rapid requests |
| 8 | MFA resend + expiry | Wait 30s on MFA page |
| 9 | JWT refresh + session | DevTools inspection |
| 10 | Logout + token revocation | Sign out + DB check |
| 11 | Database row counts | Python CLI |
| 12 | AI model persistence | File system check |

**All 12 checks passing** confirms that the SecureAuth system is fully operational.

---

## Troubleshooting

| Symptom | Likely Cause | Resolution |
|---|---|---|
| Server fails to start | Missing dependencies | `pip install -r requirements.txt` |
| `No module named 'shap'` | Incomplete install | `pip install shap` |
| All logins return HIGH risk | AI sees new IP/device | Expected behaviour — models trained on synthetic data |
| OTP not received by email | No Resend API key | Check server console — OTP is printed there |
| `DB_TYPE=mysql` fails to connect | MySQL server not running | Switch to `DB_TYPE=sqlite` for dev |
| Model files missing on startup | First run or deleted | Server auto-retrains — wait ~30 seconds |
| Dashboard shows "Loading..." | Token expired or missing | Sign out and sign in again |
