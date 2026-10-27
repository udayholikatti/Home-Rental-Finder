"""
HomeNest - mailer.py
====================
Sends OTP verification emails through SMTP.

All settings come from environment variables (loaded from the .env file by
python-dotenv in app.py) so that real credentials are NEVER written in code:

    SMTP_HOST         e.g. smtp.gmail.com
    SMTP_PORT         587 (STARTTLS) or 465 (SSL)
    SMTP_USER         your email address
    SMTP_PASSWORD     app password (NOT your normal login password)
    MAIL_FROM_NAME    display name, e.g. HomeNest

Failure policy (important):
    If the email cannot be delivered this module RAISES MailError.
    The app then shows an honest "could not send" message to the user and
    offers the resend button - it never pretends that an OTP was sent.
"""

import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr

PURPOSE_TEXT = {
    "register": "verify your new HomeNest account",
    "reset": "reset your HomeNest password",
}


class MailError(Exception):
    """Raised when an email could not be sent (configuration or network)."""


def is_placeholder(val):
    if not val:
        return True
    v = str(val).strip().lower()
    placeholders = [
        "your_email@gmail.com",
        "your_16_char_app_password",
        "example.com",
        "change-me",
        "changeme",
        "your_email",
        "your_app_password",
        "your_password",
    ]
    return any(p in v for p in placeholders) or v.startswith("<") or v.endswith(">")


def smtp_configured():
    """True when all required SMTP variables exist and are not placeholder values."""
    host = os.getenv("SMTP_HOST", "").strip()
    user = os.getenv("SMTP_USER", "").strip()
    password = os.getenv("SMTP_PASSWORD", "").strip()
    if not (host and user and password):
        return False
    if is_placeholder(user) or is_placeholder(password):
        return False
    return True


def _build_message(to_email, code, purpose):
    from_name = os.getenv("MAIL_FROM_NAME", "HomeNest")
    from_address = os.getenv("SMTP_USER", "noreply@homenest.local")

    msg = EmailMessage()
    msg["Subject"] = f"{code} is your HomeNest verification code"
    msg["From"] = formataddr((from_name, from_address))
    msg["To"] = to_email

    action_text = PURPOSE_TEXT.get(purpose, "verify your email")

    plain_body = (
        f"Hello from {from_name}!\n\n"
        f"Use the one-time code below to {action_text}:\n\n"
        f"    {code}\n\n"
        "This code expires soon and can be used only once. "
        "If you did not request it, you can safely ignore this email.\n\n"
        f"- The {from_name} Team\n"
    )
    html_body = f"""
    <div style="font-family:Arial,Helvetica,sans-serif;max-width:460px;
                margin:0 auto;padding:24px;border:1px solid #e2e8f0;
                border-radius:14px;">
      <h2 style="color:#0f766e;margin-top:0;">{from_name}</h2>
      <p>Use the one-time code below to {action_text}:</p>
      <p style="font-size:34px;font-weight:bold;letter-spacing:8px;
                color:#0f766e;background:#d9f0ed;padding:14px 10px;
                border-radius:10px;text-align:center;">{code}</p>
      <p style="color:#64748b;font-size:14px;">This code expires soon and can
         be used only once. If you did not request it, you can safely ignore
         this email.</p>
    </div>
    """
    msg.set_content(plain_body)
    msg.add_alternative(html_body, subtype="html")
    return msg


def send_otp_email(to_email, code, purpose):
    """Send one OTP email. Raises MailError on any failure.

    NOTE: the code is deliberately NOT printed/logged here. In development
    (without SMTP configured) app.py may print it to the console when the
    OTP_DEV_CONSOLE flag is enabled - never in production.
    """
    host = os.getenv("SMTP_HOST")
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASSWORD")
    try:
        port = int(os.getenv("SMTP_PORT", "587"))
    except ValueError:
        raise MailError("SMTP_PORT must be a number (587 or 465).")

    if not smtp_configured():
        raise MailError("SMTP is not configured (missing SMTP_HOST/USER/PASSWORD).")

    message = _build_message(to_email, code, purpose)

    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=20,
                                  context=ssl.create_default_context()) as server:
                server.login(user, password)
                server.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=20) as server:
                server.ehlo()
                server.starttls(context=ssl.create_default_context())
                server.login(user, password)
                server.send_message(message)
    except smtplib.SMTPAuthenticationError as exc:
        raise MailError(
            "The mail server rejected the login (check SMTP_USER / SMTP_PASSWORD)."
        ) from exc
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        raise MailError(
            f"Could not reach the mail server ({exc.__class__.__name__})."
        ) from exc
