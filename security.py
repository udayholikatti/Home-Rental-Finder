"""
HomeNest - security.py
======================
Security helper functions used by app.py:

    * Password hashing            (Werkzeug - never store plain text)
    * One-time password (OTP)     (generation + hashing)
    * Simple in-memory rate limiter
    * Input validation            (username, email, mobile, password)
    * Privacy helpers             (mask email / phone before displaying)

Everything here is plain Python so it is easy to read, explain in an
interview and unit-test.
"""

import hashlib
import re
import secrets
import time
from datetime import datetime, timedelta, timezone

from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# 1) PASSWORDS
# ---------------------------------------------------------------------------
def hash_password(plain_password):
    """Hash a password with Werkzeug (scrypt). A random salt is included
    inside the hash string, so the same password never hashes twice
    to the same value."""
    return generate_password_hash(plain_password)


def verify_password(password_hash, plain_password):
    """Constant-time comparison of a plain password against a stored hash."""
    if not password_hash:
        return False
    try:
        return check_password_hash(password_hash, plain_password)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# 2) ONE-TIME PASSWORDS (OTP)
# ---------------------------------------------------------------------------
def generate_otp():
    """Cryptographically random 6-digit code, e.g. '042917'."""
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(code, secret_key):
    """Store only a SHA-256 hash of the OTP (peppered with SECRET_KEY),
    exactly like a password. A leaked database row cannot be turned
    back into the code easily, and codes are single-use + short-lived."""
    pepper = (secret_key or "homenest-dev-pepper").encode()
    return hashlib.sha256(pepper + code.encode("utf-8")).hexdigest()


def otp_is_expired(expires_at_iso):
    """True when the OTP is past its expiry time (stored as ISO UTC)."""
    try:
        expires_at = datetime.fromisoformat(expires_at_iso)
    except (TypeError, ValueError):
        return True
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) >= expires_at


def utc_now_iso():
    """Current UTC time as an ISO-8601 string (used for all timestamps)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def seconds_since(iso_timestamp):
    """Seconds elapsed since an ISO timestamp (returns a big number if invalid)."""
    try:
        then = datetime.fromisoformat(iso_timestamp)
    except (TypeError, ValueError):
        return 10**9
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - then).total_seconds())


# ---------------------------------------------------------------------------
# 3) SIMPLE IN-MEMORY RATE LIMITER
#    Good enough for a learning project / single-process dev server.
#    For multi-server production you would use Redis instead.
# ---------------------------------------------------------------------------
_rate_buckets = {}


def rate_limit_hit(key, max_hits, window_seconds):
    """Record one hit for `key` and decide whether it is still allowed.

    Returns (allowed, retry_after_seconds).
    Example: allow 5 login attempts per 15 minutes:
        allowed, retry_in = rate_limit_hit(f"login:{u}:{ip}", 5, 900)
    """
    now = time.monotonic()
    hits = [t for t in _rate_buckets.get(key, []) if now - t < window_seconds]
    if len(hits) >= max_hits:
        _rate_buckets[key] = hits
        retry_after = int(window_seconds - (now - hits[0])) + 1
        return False, retry_after
    hits.append(now)
    _rate_buckets[key] = hits
    return True, 0


def rate_limit_reset(key):
    """Clear the counter (e.g. after a successful login)."""
    _rate_buckets.pop(key, None)


# ---------------------------------------------------------------------------
# 4) INPUT VALIDATION
# ---------------------------------------------------------------------------
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
DIGITS_RE = re.compile(r"\D")


def valid_username(username):
    """3-20 characters: letters, numbers, underscores."""
    return bool(USERNAME_RE.match(username or ""))


def valid_email(email):
    """Very small sanity check - the real test is the OTP email we send."""
    return bool(email) and len(email) <= 254 and bool(EMAIL_RE.match(email))


def normalize_mobile(raw_value):
    """Normalise an Indian mobile number to 10 digits.

    Accepts: 9876543210, +91 98765 43210, 91-9876543210, 098765 43210
    Returns the 10-digit string, or None when the number is not valid.
    """
    if not raw_value:
        return None
    digits = DIGITS_RE.sub("", str(raw_value))
    # Strip common country code / leading-zero prefixes.
    if len(digits) > 10 and digits.startswith("091"):
        digits = digits[3:]
    if len(digits) > 10 and digits.startswith("91"):
        digits = digits[2:]
    if len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]
    if len(digits) == 10 and digits[0] in "6789":
        return digits
    return None


def password_problem(password):
    """Return an error message, or None when the password is acceptable.

    Rules: at least 8 characters, at least one letter and one digit.
    """
    if not password or len(password) < 8:
        return "Password must be at least 8 characters long."
    if len(password) > 128:
        return "Password is too long (max 128 characters)."
    if not re.search(r"[A-Za-z]", password):
        return "Password must contain at least one letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one number."
    return None


# ---------------------------------------------------------------------------
# 5) PRIVACY HELPERS
# ---------------------------------------------------------------------------
def mask_email(email):
    """'priya.sharma@gmail.com' -> 'p*******@gmail.com' (safe to display)."""
    if not email or "@" not in email:
        return email or ""
    local, _, domain = email.partition("@")
    if len(local) <= 1:
        shown = local
    else:
        shown = local[0] + "*" * min(len(local) - 1, 7)
    return f"{shown}@{domain}"


def mask_phone(phone):
    """'9876543210' -> '98xxxxxx10' - only shown fully to logged-in users."""
    if not phone or len(phone) < 4:
        return phone or ""
    return phone[:2] + "x" * (len(phone) - 4) + phone[-2:]
