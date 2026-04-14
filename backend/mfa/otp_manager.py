"""
mfa/otp_manager.py – MySQL-compatible OTP management via Resend.
"""

import os, sys, uuid, bcrypt, logging, random, string
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '..', 'config', '.env'), override=True)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from database import get_connection, dict_from_row, execute

logger          = logging.getLogger(__name__)
RESEND_API_KEY  = os.getenv('RESEND_API_KEY', '')
MFA_FROM_EMAIL  = os.getenv('MFA_FROM_EMAIL', 'noreply@secureauth.dev')
OTP_EXPIRY_MINS = int(os.getenv('OTP_EXPIRY_MINUTES', 5))


def generate_otp(length: int = 6) -> str:
    return ''.join(random.SystemRandom().choices(string.digits, k=length))


def create_mfa_session(user_id: int, risk_info: dict) -> tuple:
    otp       = generate_otp()
    otp_hash  = bcrypt.hashpw(otp.encode(), bcrypt.gensalt()).decode()
    mfa_token = str(uuid.uuid4())
    expires   = (datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINS)) \
                    .strftime('%Y-%m-%d %H:%M:%S')
    conn = get_connection()
    try:
        execute(conn, "UPDATE mfa_tokens SET used=? WHERE user_id=? AND used=?", (True, user_id, False))
        execute(conn,
            "INSERT INTO mfa_tokens (user_id, otp_hash, mfa_token, expires_at) VALUES (?,?,?,?)",
            (user_id, otp_hash, mfa_token, expires))
        conn.commit()
    finally:
        conn.close()
    return mfa_token, otp


def verify_otp(mfa_token: str, otp_input: str) -> tuple:
    conn = get_connection()
    try:
        cur = execute(conn,
            "SELECT * FROM mfa_tokens WHERE mfa_token=? AND used=?", (mfa_token, False))
        row = cur.fetchone()
        if not row:
            return False, "Invalid or expired MFA session.", None
        data    = dict_from_row(row)
        expires = datetime.strptime(str(data['expires_at'])[:19], '%Y-%m-%d %H:%M:%S')
        if datetime.utcnow() > expires:
            execute(conn, "UPDATE mfa_tokens SET used=? WHERE id=?", (True, data['id'],))
            conn.commit()
            return False, "OTP has expired. Please request a new one.", None
        if not bcrypt.checkpw(otp_input.encode(), data['otp_hash'].encode()):
            return False, "Incorrect OTP.", None
        execute(conn, "UPDATE mfa_tokens SET used=? WHERE id=?", (True, data['id'],))
        conn.commit()
        return True, "OTP verified.", data['user_id']
    finally:
        conn.close()


def send_otp_email(to_email: str, username: str, otp: str) -> tuple:
    """Returns (delivered: bool, fallback_otp: str | None).
    fallback_otp is set when delivery failed and the OTP must be shown in-UI."""
    if not RESEND_API_KEY or RESEND_API_KEY.startswith('re_your_'):
        logger.warning("RESEND_API_KEY not set — OTP for %s: %s (console only)", username, otp)
        print(f"\n{'='*50}\nMFA OTP (dev mode)\n  User:  {username}\n  Email: {to_email}\n  OTP:   {otp}\n  Expires in {OTP_EXPIRY_MINS} minutes\n{'='*50}\n")
        return True, None  # Local dev — console log is fine, no in-UI fallback needed

    # 1. First, attempt standard SMTP protocol if credentials exist in .env
    smtp_user = os.getenv('SMTP_EMAIL')
    smtp_pass = os.getenv('SMTP_PASSWORD')

    if smtp_user and smtp_pass:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        try:
            msg = MIMEMultipart()
            msg['From'] = smtp_user
            msg['To'] = to_email
            msg['Subject'] = f"SecureAuth: Your verification code is {otp}"
            msg.attach(MIMEText(_email_html(username, otp), 'html'))

            server = smtplib.SMTP(os.getenv('SMTP_SERVER', 'smtp.gmail.com'), int(os.getenv('SMTP_PORT', 587)))
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
            server.quit()
            logger.info("OTP email sent via SMTP to %s", to_email)
            return True, None
        except Exception as exc:
            logger.error("SMTP delivery failed: %s", exc)

    # 2. Try Resend API (Domain limited)
    try:
        import resend
        resend.api_key = RESEND_API_KEY
        resend.Emails.send({
            "from":    MFA_FROM_EMAIL,
            "to":      [to_email],
            "subject": f"SecureAuth: Your verification code is {otp}",
            "html":    _email_html(username, otp),
        })
        logger.info("OTP email sent via Resend to %s", to_email)
        return True, None
    except Exception as exc:
        logger.error("Failed to send OTP via Resend: %s", exc)
        logger.warning(
            "\n" + "="*50 + "\n" +
            "  FALLBACK: Resend/SMTP rejected or missing configuration.\n" +
            "  Intercepted OTP for %s: >> %s <<\n" % (to_email, otp) +
            "=" * 50 + "\n"
        )
        # Return the OTP so the API can surface it in-UI (demo fallback)
        return False, otp


def _email_html(username: str, otp: str) -> str:
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0f172a;font-family:Inter,Arial,sans-serif">
<div style="max-width:480px;margin:40px auto;background:#111827;border-radius:12px;
            border:1px solid #1f2937;overflow:hidden">
  <div style="padding:24px 32px;border-bottom:1px solid #1f2937">
    <p style="color:#9ca3af;margin:0;font-size:12px;text-transform:uppercase;letter-spacing:.08em">SecureAuth</p>
    <h1 style="color:#e5e7eb;margin:8px 0 0;font-size:20px;font-weight:600">Verification Code</h1>
  </div>
  <div style="padding:32px">
    <p style="color:#9ca3af;margin:0 0 24px;font-size:14px">Hi {username}, use the code below to complete your sign-in.</p>
    <div style="background:#0f172a;border-radius:8px;padding:24px;text-align:center;border:1px solid #1f2937;margin:0 0 24px">
      <span style="font-size:36px;font-weight:700;letter-spacing:10px;color:#3b82f6;font-family:monospace">{otp}</span>
    </div>
    <p style="color:#6b7280;font-size:12px;margin:0">
      Code expires in {OTP_EXPIRY_MINS} minutes. Do not share this code.
    </p>
  </div>
</div></body></html>"""
