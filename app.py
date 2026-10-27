"""
HomeNest - House Rental Finder
==============================
A beginner-friendly full-stack web application, enhanced with:

    * Secure user accounts  - register, email OTP verification, login,
                              logout, forgot/reset password
    * OLX-style listings    - any verified user can publish, edit and
                              delete rental properties with photos
    * Search & filters      - city, locality, rent range, type, bedrooms,
                              furnishing, availability + sorting

    Backend  : Python Flask (routes + REST API)
    Database : SQLite (rentals.db, created and migrated automatically)
    Frontend : HTML5 + CSS3 + JavaScript (templates/ and static/)

PAGES (return HTML)
    /                          Home page: hero search, filters, cards
    /property/<id>             Property details page (gallery + contact)
    /favorites                 Saved homes (login required)
    /login                     Login page
    /register                  Create an account
    /verify-otp                Enter the 6-digit email code
    /forgot-password           Request a password-reset code
    /reset-password            Code + new password
    /add-property              Publish a new listing (login required)
    /my-listings               Dashboard of your own listings
    /property/<id>/edit        Edit your own listing + photos

REST API (return JSON)
    GET    /api/properties                    List/search/filter properties
    GET    /api/properties/<id>               One property (images + viewer info)
    GET    /api/cities                        Distinct cities (suggestions)
    GET    /api/property-types                Distinct property types
    GET    /api/health                        Health check
    GET    /api/favorites                     Your saved properties
    POST   /api/favorites                     Add favorite  {"property_id": 1}
    DELETE /api/favorites/<id>                Remove favorite

HOW TO RUN
    1. python -m venv venv && venv\\Scripts\\activate      (Windows)
    2. pip install -r requirements.txt
    3. copy .env.example to .env and edit it
    4. python app.py   ->  open http://127.0.0.1:5000
"""

import hmac
import os
import re
import sqlite3
import uuid
from datetime import date, datetime, timedelta, timezone
from functools import wraps
from io import BytesIO
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from PIL import Image
from werkzeug.utils import secure_filename

from mailer import MailError, send_otp_email, smtp_configured
from security import (
    generate_otp,
    hash_otp,
    hash_password,
    mask_email,
    mask_phone,
    normalize_mobile,
    otp_is_expired,
    password_problem,
    rate_limit_hit,
    rate_limit_reset,
    seconds_since,
    utc_now_iso,
    valid_email,
    valid_username,
    verify_password,
)

# ---------------------------------------------------------------------------
# 1) APPLICATION CONFIGURATION
#    Secrets and limits come from the .env file - never hardcoded.
# ---------------------------------------------------------------------------
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "rentals.db"
UPLOAD_DIR = BASE_DIR / "static" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

DEBUG = os.getenv("FLASK_DEBUG", "1") == "1"


def _env_int(name, default):
    """Read an integer from the environment, falling back to the default."""
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


app = Flask(__name__)

# The secret key signs the session cookie. In production ALWAYS set
# SECRET_KEY in the .env file (python -c "import secrets; print(secrets.token_hex(32))").
_secret_key = os.getenv("SECRET_KEY")
if not _secret_key:
    _secret_key = "dev-only-insecure-secret-change-me"
    if DEBUG:
        print("WARNING: SECRET_KEY missing - using an insecure development key.")
app.secret_key = _secret_key

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,                      # JS cannot read the cookie
    SESSION_COOKIE_SAMESITE="Lax",                     # basic CSRF hardening
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",  # enable on HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    MAX_CONTENT_LENGTH=32 * 1024 * 1024,               # 32 MB max request size
)

# --- OTP / login limits (all configurable through .env) ---
OTP_EXPIRES_MINUTES = _env_int("OTP_EXPIRES_MINUTES", 10)
OTP_RESEND_COOLDOWN_SECONDS = _env_int("OTP_RESEND_COOLDOWN_SECONDS", 60)
OTP_MAX_PER_15_MINUTES = _env_int("OTP_MAX_PER_15_MINUTES", 3)
OTP_MAX_VERIFY_ATTEMPTS = _env_int("OTP_MAX_VERIFY_ATTEMPTS", 5)
LOGIN_MAX_ATTEMPTS = _env_int("LOGIN_MAX_ATTEMPTS", 5)
LOGIN_WINDOW_SECONDS = 900               # 15 minutes
OTP_DEV_CONSOLE = os.getenv("OTP_DEV_CONSOLE", "0") == "1"

# --- Listing feature constants ---
PROPERTY_TYPES = [
    "House", "Apartment", "Flat", "PG", "Room", "Villa",
    "Studio", "Independent House",
]
FURNISHING_OPTIONS = ["Unfurnished", "Semi-Furnished", "Fully-Furnished"]
AMENITY_LABELS = {
    "parking": "Parking",
    "water_supply": "24x7 Water Supply",
    "wifi": "Wi-Fi",
    "power_backup": "Power Backup",
    "lift": "Lift",
    "gym": "Gym",
    "security": "24x7 Security",
    "balcony": "Balcony",
    "garden": "Garden",
    "ac": "Air Conditioning",
    "servant_room": "Servant Room",
    "pet_friendly": "Pet Friendly",
}
ALLOWED_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
ALLOWED_IMAGE_FORMATS = {"JPEG", "PNG", "WEBP"}
MAX_IMAGES_PER_PROPERTY = 8
MAX_IMAGE_SIZE_MB = 5
PAGE_SIZE = 9
SORT_OPTIONS = {
    "newest":    "ORDER BY COALESCE(p.created_at, '0000') DESC, p.id DESC",
    "rent_asc":  "ORDER BY p.rent ASC, p.id DESC",
    "rent_desc": "ORDER BY p.rent DESC, p.id DESC",
}

# ---------------------------------------------------------------------------
# 2) DATABASE SCHEMA (v2)
#    Fresh databases are created with the full schema below. Databases from
#    version 1 are upgraded IN PLACE by migrate_existing_database() - no
#    data is ever deleted.
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    mobile        TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    is_verified   INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL,
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS otp_codes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT    NOT NULL,
    purpose     TEXT    NOT NULL CHECK (purpose IN ('register', 'reset')),
    code_hash   TEXT    NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL,
    expires_at  TEXT    NOT NULL,
    consumed_at TEXT,
    request_ip  TEXT
);

CREATE TABLE IF NOT EXISTS properties (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    title          TEXT    NOT NULL,
    city           TEXT    NOT NULL,
    address        TEXT    NOT NULL,
    rent           INTEGER NOT NULL CHECK (rent > 0),
    bedrooms       INTEGER NOT NULL CHECK (bedrooms > 0),
    bathrooms      INTEGER NOT NULL CHECK (bathrooms > 0),
    property_type  TEXT    NOT NULL,
    image_url      TEXT    NOT NULL,
    description    TEXT    NOT NULL,
    amenities      TEXT    NOT NULL DEFAULT '',
    deposit        INTEGER NOT NULL DEFAULT 0,
    furnishing     TEXT    NOT NULL DEFAULT 'Unfurnished',
    area_sqft      INTEGER,
    locality       TEXT    NOT NULL DEFAULT '',
    district       TEXT    NOT NULL DEFAULT '',
    state          TEXT    NOT NULL DEFAULT '',
    available_from TEXT,
    contact_name   TEXT    NOT NULL DEFAULT '',
    contact_phone  TEXT    NOT NULL DEFAULT '',
    status         TEXT    NOT NULL DEFAULT 'available'
                          CHECK (status IN ('available', 'rented')),
    owner_id       INTEGER REFERENCES users (id) ON DELETE CASCADE,
    created_at     TEXT,
    updated_at     TEXT
);

CREATE TABLE IF NOT EXISTS property_images (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id INTEGER NOT NULL REFERENCES properties (id) ON DELETE CASCADE,
    filename    TEXT    NOT NULL,
    is_primary  INTEGER NOT NULL DEFAULT 0,
    sort_order  INTEGER NOT NULL DEFAULT 0,
    uploaded_at TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS favorites (
    user_id     INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    property_id INTEGER NOT NULL REFERENCES properties (id) ON DELETE CASCADE,
    added_on    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, property_id)
);
"""

# Indexes are created AFTER the column migration runs (they reference the
# new v2 columns such as owner_id, which old databases gain via ALTER TABLE).
INDEXES = """
CREATE INDEX IF NOT EXISTS idx_otp_lookup        ON otp_codes (email, purpose, created_at);
CREATE INDEX IF NOT EXISTS idx_images_property   ON property_images (property_id);
CREATE INDEX IF NOT EXISTS idx_properties_city   ON properties (city);
CREATE INDEX IF NOT EXISTS idx_properties_rent   ON properties (rent);
CREATE INDEX IF NOT EXISTS idx_properties_owner  ON properties (owner_id);
"""

# Columns added to `properties` in version 2. On old databases they are
# added one by one with ALTER TABLE (SQLite allows adding nullable columns
# and columns with constant defaults - existing rows keep their data).
V2_PROPERTY_COLUMNS = {
    "deposit":       "INTEGER NOT NULL DEFAULT 0",
    "furnishing":    "TEXT NOT NULL DEFAULT 'Unfurnished'",
    "area_sqft":     "INTEGER",
    "locality":      "TEXT NOT NULL DEFAULT ''",
    "district":      "TEXT NOT NULL DEFAULT ''",
    "state":         "TEXT NOT NULL DEFAULT ''",
    "available_from": "TEXT",
    "contact_name":  "TEXT NOT NULL DEFAULT ''",
    "contact_phone": "TEXT NOT NULL DEFAULT ''",
    "status":        "TEXT NOT NULL DEFAULT 'available'",
    "owner_id":      "INTEGER REFERENCES users (id) ON DELETE CASCADE",
    "created_at":    "TEXT",
    "updated_at":    "TEXT",
}


def get_db():
    """Open one SQLite connection per request and reuse it via flask.g."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row      # rows can then be read like dicts
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    """Close the database connection automatically when the request ends."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------------------------------------------------------------------------
# 3) SAMPLE DATA - inserted on the very first run only. The extra fields
#    (locality, deposit, furnishing...) power the new OLX-style features.
#    `demo_owned: True` marks listings that belong to the demo account so
#    the My Listings dashboard shows content immediately.
# ---------------------------------------------------------------------------
SAMPLE_PROPERTIES = [
    {
        "title": "Skyline Residency 2 BHK",
        "city": "Mumbai", "locality": "Andheri West",
        "district": "Mumbai Suburban", "state": "Maharashtra",
        "address": "B-1204, Skyline Residency, Andheri West, Mumbai 400058",
        "rent": 42000, "deposit": 126000, "bedrooms": 2, "bathrooms": 2,
        "property_type": "Apartment", "furnishing": "Semi-Furnished",
        "area_sqft": 950, "available_from": "2026-11-01",
        "contact_name": "Rohit Sharma", "contact_phone": "9820011223",
        "image_url": "/static/images/property-01.jpg",
        "description": ("Bright and airy 2 BHK on the 12th floor with a large balcony "
                        "overlooking Andheri West. Walking distance to the metro station, "
                        "malls and top-rated schools. Ideal for small families or "
                        "working professionals."),
        "amenities": "Gym, Swimming Pool, 24x7 Security, Power Backup, Covered Parking, Lift",
        "demo_owned": True,
    },
    {
        "title": "Palm Crest Luxury Villa",
        "city": "Bengaluru", "locality": "Whitefield",
        "district": "Bengaluru Urban", "state": "Karnataka",
        "address": "Villa 7, Palm Crest, Palm Meadows Road, Whitefield, Bengaluru 560066",
        "rent": 85000, "deposit": 340000, "bedrooms": 4, "bathrooms": 4,
        "property_type": "Villa", "furnishing": "Unfurnished",
        "area_sqft": 3200, "available_from": "2026-12-01",
        "contact_name": "Preeti Nair", "contact_phone": "9900112233",
        "image_url": "/static/images/property-03.jpg",
        "description": ("Spacious four-bedroom villa with a private garden and covered "
                        "parking for two cars. Located inside a gated community with "
                        "clubhouse access in Whitefield. Perfect for families looking "
                        "for premium, quiet living."),
        "amenities": "Private Garden, Clubhouse, Swimming Pool, 24x7 Security, Servant Room, 2 Car Parking",
        "demo_owned": False,
    },
    {
        "title": "Urban Nest Studio",
        "city": "Hyderabad", "locality": "Gachibowli",
        "district": "Rangareddy", "state": "Telangana",
        "address": "Flat 502, Urban Nest Apartments, Gachibowli, Hyderabad 500032",
        "rent": 16500, "deposit": 49500, "bedrooms": 1, "bathrooms": 1,
        "property_type": "Studio", "furnishing": "Fully-Furnished",
        "area_sqft": 480, "available_from": "2026-10-15",
        "contact_name": "Arvind Reddy", "contact_phone": "9848011223",
        "image_url": "/static/images/property-02.jpg",
        "description": ("Fully furnished studio apartment in the heart of Gachibowli, "
                        "minutes away from the IT hub. Comes with a modular kitchen, "
                        "wardrobe and high-speed internet readiness. Best suited for "
                        "working professionals."),
        "amenities": "Furnished, Modular Kitchen, Wi-Fi Ready, Power Backup, Lift, Biometric Entry",
        "demo_owned": False,
    },
    {
        "title": "Greenfield Family House",
        "city": "Pune", "locality": "Kharadi",
        "district": "Pune", "state": "Maharashtra",
        "address": "House 14, Greenfield Society, Kharadi, Pune 411014",
        "rent": 52000, "deposit": 156000, "bedrooms": 3, "bathrooms": 3,
        "property_type": "Independent House", "furnishing": "Semi-Furnished",
        "area_sqft": 1850, "available_from": "2026-11-15",
        "contact_name": "Sunita Kulkarni", "contact_phone": "9822011334",
        "image_url": "/static/images/property-04.jpg",
        "description": ("Independent house with a terrace garden and a dedicated study "
                        "room in Kharadi. Located in a quiet residential lane with easy "
                        "access to EON IT Park. Great for families who want space and "
                        "privacy."),
        "amenities": "Terrace Garden, Study Room, 2 Wheeler Parking, 24x7 Water Supply, Security",
        "demo_owned": True,
    },
    {
        "title": "Marina View Apartment",
        "city": "Chennai", "locality": "Besant Nagar",
        "district": "Chennai", "state": "Tamil Nadu",
        "address": "Flat 9A, Marina Heights, Besant Nagar, Chennai 600020",
        "rent": 33000, "deposit": 99000, "bedrooms": 2, "bathrooms": 2,
        "property_type": "Apartment", "furnishing": "Semi-Furnished",
        "area_sqft": 1050, "available_from": "2026-11-01",
        "contact_name": "Karthik Iyer", "contact_phone": "9840011225",
        "image_url": "/static/images/property-05.jpg",
        "description": ("Sea-facing 2 BHK apartment a short walk from Besant Nagar beach. "
                        "Wake up to ocean views and enjoy evening walks along the shore. "
                        "The building has round-the-clock security and covered parking."),
        "amenities": "Sea View, 24x7 Security, Covered Parking, Lift, Power Backup, Water Supply",
        "demo_owned": False,
    },
    {
        "title": "Central Park Serviced 2 BHK",
        "city": "New Delhi", "locality": "Saket",
        "district": "South Delhi", "state": "Delhi",
        "address": "C-9/12, Central Park Residency, Saket, New Delhi 110017",
        "rent": 48000, "deposit": 144000, "bedrooms": 2, "bathrooms": 2,
        "property_type": "Apartment", "furnishing": "Fully-Furnished",
        "area_sqft": 1100, "available_from": "2026-10-20",
        "contact_name": "Neha Gupta", "contact_phone": "9811011226",
        "image_url": "/static/images/property-06.jpg",
        "description": ("Serviced 2 BHK in a premium gated society in Saket with "
                        "housekeeping twice a week. Close to Select Citywalk mall and "
                        "Saket metro station. Fully furnished and move-in ready."),
        "amenities": "Fully Furnished, Housekeeping, Gym, Swimming Pool, Clubhouse, Metro Nearby",
        "demo_owned": False,
    },
    {
        "title": "Lakeside Serene Villa",
        "city": "Bengaluru", "locality": "Hebbal",
        "district": "Bengaluru Urban", "state": "Karnataka",
        "address": "Villa 22, Lakeside Enclave, Hebbal, Bengaluru 560024",
        "rent": 95000, "deposit": 475000, "bedrooms": 4, "bathrooms": 4,
        "property_type": "Villa", "furnishing": "Fully-Furnished",
        "area_sqft": 4100, "available_from": "2026-12-10",
        "contact_name": "Rakesh Hegde", "contact_phone": "9880011227",
        "image_url": "/static/images/property-08.jpg",
        "description": ("Luxury lakeside villa with floor-to-ceiling windows and a private "
                        "deck facing Hebbal Lake. The gated community offers a gym, pool "
                        "and landscaped walking trails. A premium home for those who want "
                        "the best."),
        "amenities": "Lake View, Private Deck, Swimming Pool, Gym, Smart Home Features, 3 Car Parking",
        "demo_owned": True,
    },
    {
        "title": "Anjuna Beach House",
        "city": "Goa", "locality": "Anjuna",
        "district": "North Goa", "state": "Goa",
        "address": "House 3, Sunset Lane, Ozran Beach Road, Anjuna, Goa 403509",
        "rent": 58000, "deposit": 116000, "bedrooms": 2, "bathrooms": 2,
        "property_type": "Independent House", "furnishing": "Semi-Furnished",
        "area_sqft": 1400, "available_from": "2026-11-05",
        "contact_name": "Maria D'Souza", "contact_phone": "9822011228",
        "image_url": "/static/images/property-11.jpg",
        "description": ("Charming beach house with a palm-shaded courtyard, ten minutes "
                        "from Anjuna beach. Includes a fully equipped kitchen and a "
                        "hammock-ready veranda. Popular with remote workers and "
                        "long-stay guests."),
        "amenities": "Courtyard, Equipped Kitchen, Veranda, Inverter Backup, Parking",
        "demo_owned": False,
    },
    {
        "title": "Heritage Court 3 BHK",
        "city": "Kolkata", "locality": "Salt Lake",
        "district": "North 24 Parganas", "state": "West Bengal",
        "address": "Flat 6B, Heritage Court, Salt Lake Sector 2, Kolkata 700091",
        "rent": 38000, "deposit": 114000, "bedrooms": 3, "bathrooms": 2,
        "property_type": "Apartment", "furnishing": "Semi-Furnished",
        "area_sqft": 1450, "available_from": "2026-11-20",
        "contact_name": "Arnab Sen", "contact_phone": "9830011229",
        "image_url": "/static/images/property-07.jpg",
        "description": ("Well-maintained 3 BHK in peaceful Salt Lake Sector 2 with park "
                        "views. Schools, hospitals and the stadium are all within walking "
                        "distance. Semi-furnished with wardrobes and light fittings."),
        "amenities": "Park View, Semi Furnished, Lift, 24x7 Security, Community Hall, Parking",
        "demo_owned": False,
    },
    {
        "title": "Golf Course Road Premium Flat",
        "city": "Gurugram", "locality": "Golf Course Road",
        "district": "Gurugram", "state": "Haryana",
        "address": "Tower C-1802, Golf Greens, Golf Course Road, Gurugram 122002",
        "rent": 65000, "deposit": 260000, "bedrooms": 3, "bathrooms": 3,
        "property_type": "Apartment", "furnishing": "Fully-Furnished",
        "area_sqft": 2100, "available_from": "2026-10-25",
        "contact_name": "Ishita Malhotra", "contact_phone": "9818011230",
        "image_url": "/static/images/property-10.jpg",
        "description": ("High-floor 3 BHK on Golf Course Road with panoramic city views "
                        "and premium finishes. Residents enjoy a clubhouse, pool and "
                        "concierge services. Ideal for executives working in Cyber City."),
        "amenities": "Clubhouse, Swimming Pool, Concierge, Gym, High Floor, Covered Parking",
        "demo_owned": False,
    },
    {
        "title": "Cozy Loft Studio",
        "city": "Pune", "locality": "Kothrud",
        "district": "Pune", "state": "Maharashtra",
        "address": "Unit 12, Cozy Loft Homes, Kothrud, Pune 411038",
        "rent": 14500, "deposit": 43500, "bedrooms": 1, "bathrooms": 1,
        "property_type": "Studio", "furnishing": "Furnished",
        "area_sqft": 420, "available_from": "2026-10-12",
        "contact_name": "Vikram Joshi", "contact_phone": "9822011231",
        "image_url": "/static/images/property-09.jpg",
        "description": ("Budget-friendly loft studio with a mezzanine sleeping area in "
                        "central Kothrud. Walking distance to cafes, grocery stores and "
                        "the bus stop. A smart choice for students and interns."),
        "amenities": "Loft Bed, Study Desk, Wardrobe, Wi-Fi Ready, 2 Wheeler Parking",
        "demo_owned": False,
    },
    {
        "title": "Tech Park Smart Studio",
        "city": "Bengaluru", "locality": "Electronic City",
        "district": "Bengaluru Urban", "state": "Karnataka",
        "address": "Flat 304, Smart Living Towers, Electronic City, Bengaluru 560100",
        "rent": 14900, "deposit": 44700, "bedrooms": 1, "bathrooms": 1,
        "property_type": "Studio", "furnishing": "Fully-Furnished",
        "area_sqft": 450, "available_from": "2026-10-18",
        "contact_name": "Divya Ramesh", "contact_phone": "9886011232",
        "image_url": "/static/images/property-12.jpg",
        "description": ("Compact smart studio with app-controlled lighting and locks, "
                        "inside Electronic City Phase 1. Tech parks, cafeterias and the "
                        "elevated expressway are minutes away. Designed for busy techies."),
        "amenities": "Smart Locks, App Controlled Lights, Furnished, Gym, Wi-Fi Ready",
        "demo_owned": False,
    },
]

# Demo account used for interviews/demos (documented in README.md):
#   username: demo_user   password: Demo@1234
DEMO_USER = {
    "username": "demo_user",
    "email": "demo@homenest.app",
    "mobile": "9876543210",
    "password": "Demo@1234",
}

# ---------------------------------------------------------------------------
# 4) DATABASE INITIALISATION + SAFE MIGRATION
# ---------------------------------------------------------------------------
def _table_columns(connection, table):
    """Return the set of column names of a table (empty if it doesn't exist)."""
    rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
    return {row[1] for row in rows}


def migrate_existing_database(connection):
    """Upgrade a version-1 database to the version-2 schema IN PLACE.

    Safe by design:
      * tables are created only when missing (CREATE TABLE IF NOT EXISTS)
      * new columns are added with ALTER TABLE - existing rows keep data
      * the old global favorites table (one shared list) is converted to
        per-user favorites: existing rows are moved to the demo account
      * nothing is ever dropped or overwritten
    """
    connection.executescript(SCHEMA)     # create any table still missing

    # --- 4a. add the new property columns one by one -----------------------
    columns = _table_columns(connection, "properties")
    for column_name, column_sql in V2_PROPERTY_COLUMNS.items():
        if column_name not in columns:
            connection.execute(
                f"ALTER TABLE properties ADD COLUMN {column_name} {column_sql}"
            )

    # --- 4b. migrate the legacy global favorites table ---------------------
    fav_columns = _table_columns(connection, "favorites")
    if fav_columns and "user_id" not in fav_columns:
        legacy_rows = connection.execute(
            "SELECT property_id, added_on FROM favorites"
        ).fetchall()
        connection.execute("ALTER TABLE favorites RENAME TO favorites_legacy")
        connection.execute(
            """CREATE TABLE favorites (
                   user_id     INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
                   property_id INTEGER NOT NULL REFERENCES properties (id) ON DELETE CASCADE,
                   added_on    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                   PRIMARY KEY (user_id, property_id)
               )"""
        )
        if legacy_rows:
            demo_id = _ensure_demo_user(connection)
            connection.executemany(
                """INSERT OR IGNORE INTO favorites (user_id, property_id, added_on)
                   VALUES (?, ?, ?)""",
                [(demo_id, row["property_id"], row["added_on"]) for row in legacy_rows],
            )
        connection.execute("DROP TABLE favorites_legacy")
        print("Migrated legacy favorites to per-user favorites.")

    # --- 4c. indexes last (some reference the newly added columns) ---------
    connection.executescript(INDEXES)

    connection.commit()


def _ensure_demo_user(connection):
    """Create the documented demo account (if needed) and return its id."""
    row = connection.execute(
        "SELECT id FROM users WHERE username = ?", (DEMO_USER["username"],)
    ).fetchone()
    if row:
        return row["id"]
    cursor = connection.execute(
        """INSERT INTO users (username, email, mobile, password_hash,
                               is_verified, created_at)
           VALUES (?, ?, ?, ?, 1, ?)""",
        (
            DEMO_USER["username"],
            DEMO_USER["email"],
            DEMO_USER["mobile"],
            hash_password(DEMO_USER["password"]),
            utc_now_iso(),
        ),
    )
    print("Created demo account 'demo_user' (see README for the password).")
    return cursor.lastrowid


def init_db():
    """Create/upgrade the schema and insert sample data when the database
    is empty. Safe to call on every start-up."""
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    migrate_existing_database(connection)

    property_count = connection.execute(
        "SELECT COUNT(*) FROM properties"
    ).fetchone()[0]
    if property_count == 0:
        demo_id = _ensure_demo_user(connection)
        now = datetime.now(timezone.utc)
        for index, sample in enumerate(SAMPLE_PROPERTIES):
            created_at = (now - timedelta(days=30 - index)).isoformat(timespec="seconds")
            cursor = connection.execute(
                """INSERT INTO properties
                   (title, city, locality, district, state, address,
                    rent, deposit, bedrooms, bathrooms, property_type,
                    furnishing, area_sqft, available_from,
                    contact_name, contact_phone, image_url, description,
                    amenities, status, owner_id, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'available', ?, ?, ?)""",
                (
                    sample["title"], sample["city"], sample["locality"],
                    sample["district"], sample["state"], sample["address"],
                    sample["rent"], sample["deposit"], sample["bedrooms"],
                    sample["bathrooms"], sample["property_type"],
                    sample["furnishing"], sample["area_sqft"],
                    sample["available_from"], sample["contact_name"],
                    sample["contact_phone"], sample["image_url"],
                    sample["description"], sample["amenities"],
                    demo_id if sample["demo_owned"] else None,
                    created_at, created_at,
                ),
            )
            if sample["demo_owned"]:
                connection.execute(
                    "INSERT OR IGNORE INTO favorites (user_id, property_id) VALUES (?, ?)",
                    (demo_id, cursor.lastrowid),
                )
        connection.commit()
        print(f"Database ready - inserted {len(SAMPLE_PROPERTIES)} sample properties.")
    else:
        # A database that already existed may pre-date the demo account.
        _ensure_demo_user(connection)
        connection.commit()

    connection.close()


# ---------------------------------------------------------------------------
# 5) SESSION / AUTH HELPERS
# ---------------------------------------------------------------------------
def load_current_user():
    """Load the logged-in user row once per request (or None for guests)."""
    if "user" in g:
        return g.user
    g.user = None
    user_id = session.get("user_id")
    if user_id is not None:
        row = get_db().execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        # The account must still exist AND be verified, otherwise the
        # session is stale - clear it instead of trusting the cookie.
        if row and row["is_verified"]:
            g.user = row
        elif row is None or not row["is_verified"]:
            session.clear()
    return g.user


@app.before_request
def csrf_protect():
    """CSRF protection: every state-changing request must carry the secret
    token that only pages rendered by this app could have embedded.

      * HTML forms  -> hidden input  <input name="csrf_token" ...>
      * JS fetch()  -> header        X-CSRF-Token (added by script.js)
    """
    load_current_user()   # resolve the user before every view runs
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
        expected = session.get("_csrf_token", "")
        if not expected or not sent or not hmac.compare_digest(sent, expected):
            message = ("Your session expired or the request was missing a "
                       "security token. Please refresh the page and try again.")
            if request.path.startswith("/api/"):
                return jsonify({"error": message}), 400
            flash(message, "error")
            return redirect(request.referrer or url_for("home_page"))


def csrf_token():
    """Return (creating if needed) the CSRF token for this session."""
    if "_csrf_token" not in session:
        import secrets as _secrets
        session["_csrf_token"] = _secrets.token_hex(32)
    return session["_csrf_token"]


def client_ip():
    """Best-effort client IP for rate limiting (works behind local proxies)."""
    return (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.remote_addr or "unknown")


def login_required(view):
    """Decorator for pages that need a logged-in, verified user."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = load_current_user()
        if user is None:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login_page", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def safe_next_url(default="/"):
    """Only allow internal redirect targets (prevents open redirects)."""
    candidate = request.values.get("next", default)
    if isinstance(candidate, str) and candidate.startswith("/") and not candidate.startswith("//"):
        return candidate
    return default


def start_logged_in_session(user_id):
    """Regenerate the session on login (prevents session fixation):
    wipe everything, then store ONLY the fresh user id."""
    session.clear()
    session["user_id"] = user_id
    session.permanent = True
    csrf_token()   # new token for the new session


# ---------------------------------------------------------------------------
# 6) OTP ISSUE + VERIFY (shared by register and password reset)
# ---------------------------------------------------------------------------
def issue_otp(email, purpose):
    """Create and (try to) deliver a one-time code.

    Returns (ok, message, retry_after_seconds). In development mode, the code
    is also remembered in session and printed to the console so registration/login
    can be tested without an SMTP server.
    """
    db = get_db()
    now = utc_now_iso()

    is_dev = DEBUG or OTP_DEV_CONSOLE
    cooldown_limit = 5 if is_dev else OTP_RESEND_COOLDOWN_SECONDS
    volume_limit = 100 if is_dev else OTP_MAX_PER_15_MINUTES

    # 1) Resend cooldown - check the most recent code for this email+purpose.
    last = db.execute(
        """SELECT created_at FROM otp_codes
           WHERE email = ? AND purpose = ? ORDER BY id DESC LIMIT 1""",
        (email, purpose),
    ).fetchone()
    if last:
        elapsed = seconds_since(last["created_at"])
        if elapsed < cooldown_limit:
            remaining = int(cooldown_limit - elapsed) + 1
            return False, f"Please wait {remaining}s before requesting a new code.", remaining

    # 2) Volume cap - at most N codes per 15 minutes (prevents mail bombing).
    recent = db.execute(
        """SELECT COUNT(*) FROM otp_codes
           WHERE email = ? AND purpose = ? AND created_at > ?""",
        (email, purpose,
         (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat(timespec="seconds")),
    ).fetchone()[0]
    if recent >= volume_limit:
        return False, "Too many codes requested. Please try again in 15 minutes.", 900

    # 3) Invalidate any previous unused codes for this email+purpose.
    db.execute(
        """UPDATE otp_codes SET consumed_at = ?
           WHERE email = ? AND purpose = ? AND consumed_at IS NULL""",
        (now, email, purpose),
    )

    # 4) Generate, store only the HASH of the code, then deliver it.
    code = generate_otp()
    db.execute(
        """INSERT INTO otp_codes
           (email, purpose, code_hash, attempts, created_at, expires_at, request_ip)
           VALUES (?, ?, ?, 0, ?, ?, ?)""",
        (email, purpose, hash_otp(code, app.secret_key), now,
         (datetime.now(timezone.utc)
          + timedelta(minutes=OTP_EXPIRES_MINUTES)).isoformat(timespec="seconds"),
         client_ip()),
    )
    db.commit()

    if smtp_configured():
        try:
            send_otp_email(email, code, purpose)
            return True, f"We emailed a 6-digit code to {mask_email(email)}.", 0
        except MailError as exc:
            print(f"OTP email delivery FAILED for {email}: {exc}")
            if is_dev:
                session["dev_otp"] = code
                print(f"[DEV FALLBACK] OTP for {email} ({purpose}): {code}")
                return True, (
                    f"Email sending failed ({exc}). "
                    f"Development mode verification code: {code}"
                ), 0
            # If not dev mode, delete the undelivered code so it doesn't count against volume cap
            db.execute(
                """DELETE FROM otp_codes
                   WHERE email = ? AND purpose = ? AND created_at = ?""",
                (email, purpose, now),
            )
            db.commit()
            return False, (
                "We created your code but the email could not be sent "
                f"({exc}). Please use the resend button in a moment."
            ), OTP_RESEND_COOLDOWN_SECONDS

    # Development mode without SMTP: store code in session and print to console
    if is_dev:
        session["dev_otp"] = code
        print(f"[DEV ONLY] OTP for {email} ({purpose}): {code}")
        return True, (
            f"Development mode: Your verification code is {code} (SMTP is not configured)."
        ), 0

    db.execute(
        """DELETE FROM otp_codes
           WHERE email = ? AND purpose = ? AND created_at = ?""",
        (email, purpose, now),
    )
    db.commit()
    return False, (
        "Email delivery is not configured. Set SMTP_HOST/USER/PASSWORD in "
        "the .env file (or enable OTP_DEV_CONSOLE=1 for local development)."
    ), 0


def verify_otp_record(email, purpose, code):
    """Check a submitted OTP. Returns (ok, error_message)."""
    db = get_db()
    allowed, _ = rate_limit_hit(f"otp-verify:{email}:{client_ip()}", 10, 900)
    if not allowed:
        return False, "Too many wrong attempts. Please wait a few minutes."

    row = db.execute(
        """SELECT * FROM otp_codes
           WHERE email = ? AND purpose = ? AND consumed_at IS NULL
           ORDER BY id DESC LIMIT 1""",
        (email, purpose),
    ).fetchone()
    if row is None:
        return False, "No active code found. Please request a new one."
    if otp_is_expired(row["expires_at"]):
        return False, "This code has expired. Please request a new one."
    if row["attempts"] >= OTP_MAX_VERIFY_ATTEMPTS:
        db.execute("UPDATE otp_codes SET consumed_at = ? WHERE id = ?",
                   (utc_now_iso(), row["id"]))
        db.commit()
        return False, "Too many wrong attempts for this code. Please request a new one."

    submitted_hash = hash_otp(code.strip(), app.secret_key)
    if not hmac.compare_digest(submitted_hash, row["code_hash"]):
        db.execute("UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?",
                   (row["id"],))
        db.commit()
        remaining = OTP_MAX_VERIFY_ATTEMPTS - row["attempts"] - 1
        if remaining <= 0:
            return False, "That code was wrong too many times. Please request a new one."
        return False, f"Incorrect code. {remaining} attempt(s) remaining."

    db.execute("UPDATE otp_codes SET consumed_at = ? WHERE id = ?",
               (utc_now_iso(), row["id"]))
    db.commit()
    rate_limit_reset(f"otp-verify:{email}:{client_ip()}")
    return True, ""


# ---------------------------------------------------------------------------
# 7) TEMPLATE CONTEXT (available in every template)
# ---------------------------------------------------------------------------
@app.template_filter("number_format")
def number_format(value):
    """1260000 -> '12,60,000' using Indian digit grouping (for templates)."""
    try:
        digits = str(int(value))
    except (TypeError, ValueError):
        return str(value)
    if len(digits) <= 3:
        return digits
    head, tail = digits[:-3], digits[-3:]
    parts = []
    while len(head) > 2:
        parts.insert(0, head[-2:])
        head = head[:-2]
    if head:
        parts.insert(0, head)
    return ",".join(parts + [tail])


@app.context_processor
def inject_template_globals():
    user = load_current_user()
    fav_count = 0
    if user is not None:
        fav_count = get_db().execute(
            "SELECT COUNT(*) FROM favorites WHERE user_id = ?", (user["id"],)
        ).fetchone()[0]
    return {
        "current_user": user,
        "fav_count": fav_count,
        "csrf_token": csrf_token,
        "property_types": PROPERTY_TYPES,
        "furnishing_options": FURNISHING_OPTIONS,
        "amenity_labels": AMENITY_LABELS,
    }


# ---------------------------------------------------------------------------
# 8) INPUT VALIDATION HELPERS
# ---------------------------------------------------------------------------
def try_parse_int(raw_value):
    """Safely convert a query-string value to an integer.

    Returns a tuple (value, error):
        "25"          -> (25, None)
        "" or None    -> (None, None)   meaning "not provided"
        "abc"         -> (None, "must be a whole number")
    """
    if raw_value is None or str(raw_value).strip() == "":
        return None, None
    try:
        return int(str(raw_value).strip()), None
    except ValueError:
        return None, "must be a whole number"


def clean_text(raw_value):
    """Return a trimmed string, or "" when the value is missing."""
    return raw_value.strip() if isinstance(raw_value, str) else ""


def validate_registration_form(form):
    """Validate the sign-up form. Returns (values, errors)."""
    values = {
        "username": clean_text(form.get("username")),
        "email": clean_text(form.get("email")).lower(),
        "mobile": clean_text(form.get("mobile")),
    }
    errors = {}
    db = get_db()

    username = values["username"]
    if not username:
        errors["username"] = "Username is required."
    elif not valid_username(username):
        errors["username"] = ("Use 3-20 characters: letters, numbers and "
                              "underscores only.")
    elif db.execute("SELECT 1 FROM users WHERE username = ?",
                    (username,)).fetchone():
        errors["username"] = "That username is already taken."

    email = values["email"]
    if not email:
        errors["email"] = "Email address is required."
    elif not valid_email(email):
        errors["email"] = "Enter a valid email address."
    elif db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
        errors["email"] = "That email is already registered."

    mobile = normalize_mobile(values["mobile"])
    if mobile is None:
        errors["mobile"] = "Enter a valid 10-digit Indian mobile number."
    elif db.execute("SELECT 1 FROM users WHERE mobile = ?", (mobile,)).fetchone():
        errors["mobile"] = "That mobile number is already registered."

    password = form.get("password", "")
    problem = password_problem(password)
    if problem:
        errors["password"] = problem
    elif password != form.get("confirm_password", ""):
        errors["confirm_password"] = "Passwords do not match."

    return values, errors


def validate_property_form(form, require_phone=True):
    """Validate the add/edit listing form. Returns (values, errors)."""
    values = {key: clean_text(form.get(key, "")) for key in (
        "title", "property_type", "description", "rent", "deposit",
        "bedrooms", "bathrooms", "furnishing", "area_sqft", "address",
        "locality", "city", "district", "state", "available_from",
        "contact_name", "contact_phone",
    )}
    errors = {}

    if not values["title"]:
        errors["title"] = "Property title is required."
    elif len(values["title"]) > 120:
        errors["title"] = "Keep the title under 120 characters."

    if values["property_type"] not in PROPERTY_TYPES:
        errors["property_type"] = "Choose a property type."

    description = values["description"]
    if len(description) < 30:
        errors["description"] = "Describe the property in at least 30 characters."
    elif len(description) > 3000:
        errors["description"] = "Keep the description under 3000 characters."

    rent, rent_error = try_parse_int(values["rent"])
    if rent is None or rent_error:
        errors["rent"] = "Monthly rent must be a whole number."
    elif rent < 1000 or rent > 10_000_000:
        errors["rent"] = "Monthly rent must be between 1,000 and 1,00,00,000."
    values["rent"] = rent

    deposit, deposit_error = try_parse_int(values["deposit"])
    if deposit_error:
        errors["deposit"] = "Deposit must be a whole number."
    elif deposit is not None and deposit < 0:
        errors["deposit"] = "Deposit cannot be negative."
    values["deposit"] = deposit

    bedrooms, bedrooms_error = try_parse_int(values["bedrooms"])
    if bedrooms is None or bedrooms_error:
        errors["bedrooms"] = "Bedrooms must be a whole number."
    elif bedrooms < 1 or bedrooms > 10:
        errors["bedrooms"] = "Bedrooms must be between 1 and 10."
    values["bedrooms"] = bedrooms

    bathrooms, bathrooms_error = try_parse_int(values["bathrooms"])
    if bathrooms is None or bathrooms_error:
        errors["bathrooms"] = "Bathrooms must be a whole number."
    elif bathrooms < 1 or bathrooms > 10:
        errors["bathrooms"] = "Bathrooms must be between 1 and 10."
    values["bathrooms"] = bathrooms

    if values["furnishing"] not in FURNISHING_OPTIONS:
        errors["furnishing"] = "Choose a furnishing status."

    area, area_error = try_parse_int(values["area_sqft"])
    if area_error:
        errors["area_sqft"] = "Area must be a whole number."
    elif area is not None and (area < 50 or area > 1_000_000):
        errors["area_sqft"] = "Area must be between 50 and 1,00,000 sq.ft."
    values["area_sqft"] = area

    if not values["address"]:
        errors["address"] = "Full address is required."
    elif len(values["address"]) > 250:
        errors["address"] = "Keep the address under 250 characters."

    if not values["city"]:
        errors["city"] = "City is required."
    elif len(values["city"]) > 80:
        errors["city"] = "Keep the city name under 80 characters."

    for optional_field, max_len in (("locality", 100), ("district", 80), ("state", 80)):
        if len(values[optional_field]) > max_len:
            errors[optional_field] = f"Keep this under {max_len} characters."

    if values["available_from"]:
        try:
            parsed_date = date.fromisoformat(values["available_from"])
            if parsed_date < date.today() - timedelta(days=1):
                errors["available_from"] = "The available-from date cannot be in the past."
        except ValueError:
            errors["available_from"] = "Enter a valid date (YYYY-MM-DD)."
    else:
        values["available_from"] = date.today().isoformat()

    if not values["contact_name"]:
        errors["contact_name"] = "Contact name is required."
    elif len(values["contact_name"]) > 80:
        errors["contact_name"] = "Keep the contact name under 80 characters."

    phone = normalize_mobile(values["contact_phone"])
    if phone is None:
        errors["contact_phone"] = "Enter a valid 10-digit mobile number."
    values["contact_phone"] = phone

    # Amenities arrive as several checkboxes named "amenities".
    chosen = form.getlist("amenities")
    amenities = [a for a in chosen if a in AMENITY_LABELS]
    values["amenities"] = ",".join(amenities)

    return values, errors


# ---------------------------------------------------------------------------
# 9) IMAGE UPLOAD HELPERS
# ---------------------------------------------------------------------------
def validate_uploaded_images(files):
    """Validate a list of uploaded files. Returns (images, error_message).

    Each accepted image is a dict with the raw bytes + original filename.
    Defence layers:
      1. extension whitelist (jpg/jpeg/png/webp)
      2. size limit (5 MB each)
      3. real image check with Pillow (blocks executables renamed to .jpg)
      4. decoded format must be JPEG/PNG/WEBP
    """
    images = []
    for storage in files:
        if storage is None or not storage.filename:
            continue
        original_name = storage.filename
        extension = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else ""
        if extension not in ALLOWED_IMAGE_EXTENSIONS:
            return None, (f"'{original_name}' is not a supported image. "
                          "Please upload JPG, PNG or WEBP files.")
        data = storage.read()
        if len(data) == 0:
            return None, f"'{original_name}' is empty."
        if len(data) > MAX_IMAGE_SIZE_MB * 1024 * 1024:
            return None, (f"'{original_name}' is larger than "
                          f"{MAX_IMAGE_SIZE_MB} MB. Please choose a smaller photo.")
        try:
            with Image.open(BytesIO(data)) as probe:
                probe.verify()          # detects corrupt/fake images
            with Image.open(BytesIO(data)) as decoded:
                image_format = (decoded.format or "").upper()
        except Exception:
            return None, (f"'{original_name}' is not a valid image file.")
        if image_format not in ALLOWED_IMAGE_FORMATS:
            return None, (f"'{original_name}' has an unsupported image format.")
        images.append({"data": data, "original_name": original_name})
    return images, None


def save_image_file(image_data, original_name):
    """Write image bytes to static/uploads/ under a safe unique name.

    uuid4 + secure_filename means: no path traversal, no collisions, and
    even hostile names ('../../evil.exe') cannot do anything.
    """
    safe_name = secure_filename(original_name) or "photo"
    if len(safe_name) > 60:
        extension = safe_name.rsplit(".", 1)[-1][:5]
        safe_name = f"photo.{extension}"
    filename = f"{uuid.uuid4().hex[:16]}_{safe_name}"
    (UPLOAD_DIR / filename).write_bytes(image_data)
    return filename


def delete_image_file(filename):
    """Remove an uploaded file from disk (ignore errors on missing files)."""
    if not filename:
        return
    try:
        (UPLOAD_DIR / Path(filename).name).unlink(missing_ok=True)
    except OSError:
        pass


def property_image_urls(db, property_row):
    """Ordered gallery URLs for a property: uploaded images first (primary
    on top), then the legacy image_url as fallback for sample data."""
    rows = db.execute(
        """SELECT filename FROM property_images
           WHERE property_id = ?
           ORDER BY is_primary DESC, sort_order ASC, id ASC""",
        (property_row["id"],),
    ).fetchall()
    urls = ["/static/uploads/" + row["filename"] for row in rows]
    if not urls and property_row["image_url"]:
        urls = [property_row["image_url"]]
    return urls


def property_main_image(db, property_row):
    """The single image used on cards: primary upload or legacy image_url."""
    row = db.execute(
        """SELECT filename FROM property_images
           WHERE property_id = ?
           ORDER BY is_primary DESC, sort_order ASC, id ASC
           LIMIT 1""",
        (property_row["id"],),
    ).fetchone()
    if row:
        return "/static/uploads/" + row["filename"]
    return property_row["image_url"]


def delete_property_and_files(db, property_id):
    """Delete one property together with its image rows AND image files."""
    files = db.execute(
        "SELECT filename FROM property_images WHERE property_id = ?",
        (property_id,),
    ).fetchall()
    db.execute("DELETE FROM property_images WHERE property_id = ?", (property_id,))
    db.execute("DELETE FROM favorites WHERE property_id = ?", (property_id,))
    db.execute("DELETE FROM properties WHERE id = ?", (property_id,))
    db.commit()
    for row in files:
        delete_image_file(row["filename"])


def serialize_property(db, row, with_viewer=False):
    """Convert a properties row into the JSON used by the frontend."""
    data = dict(row)
    data["image_url"] = property_main_image(db, row)
    data["image_count"] = db.execute(
        "SELECT COUNT(*) FROM property_images WHERE property_id = ?",
        (row["id"],),
    ).fetchone()[0]
    owner = db.execute("SELECT username, created_at FROM users WHERE id = ?",
                       (row["owner_id"],)).fetchone()
    data["owner_name"] = owner["username"] if owner else "HomeNest"
    if with_viewer:
        viewer = load_current_user()
        viewer_data = {"logged_in": viewer is not None, "is_owner": False,
                       "favorited": False}
        if viewer is not None:
            viewer_data["is_owner"] = (row["owner_id"] == viewer["id"])
            viewer_data["favorited"] = bool(db.execute(
                "SELECT 1 FROM favorites WHERE user_id = ? AND property_id = ?",
                (viewer["id"], row["id"]),
            ).fetchone())
        # Contact details: the phone number stays masked until login.
        revealed = viewer is not None
        data["contact"] = {
            "name": row["contact_name"] or data["owner_name"],
            "phone": row["contact_phone"] if revealed else mask_phone(row["contact_phone"]),
            "revealed": revealed,
        }
        data["viewer"] = viewer_data
        # Amenity ids -> readable labels ('parking' -> 'Parking').
        data["amenity_list"] = [
            AMENITY_LABELS.get(a.strip(), a.strip())
            for a in (row["amenities"] or "").split(",") if a.strip()
        ]
        data["gallery"] = property_image_urls(db, row)
    return data


# ---------------------------------------------------------------------------
# 10) PAGE ROUTES - CORE BROWSING
# ---------------------------------------------------------------------------
@app.route("/")
def home_page():
    """Home page with hero search, filters and the property grid.
    The page shell renders here; property data loads via the REST API."""
    return render_template("index.html")


@app.route("/property/<int:property_id>")
def property_details_page(property_id):
    """Property details page shell; data is fetched from the API by JS."""
    return render_template("property_details.html", property_id=property_id)


@app.route("/favorites")
@login_required
def favorites_page():
    """Saved homes of the logged-in user."""
    return render_template("favorites.html")


# ---------------------------------------------------------------------------
# 11) PAGE ROUTES - REGISTRATION, LOGIN, OTP
# ---------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "POST":
        # Anti-spam: max 10 sign-up attempts per IP per hour.
        allowed, _ = rate_limit_hit(f"register:{client_ip()}", 10, 3600)
        if not allowed:
            flash("Too many sign-up attempts. Please try again later.", "error")
            return redirect(url_for("register_page"))

        values, errors = validate_registration_form(request.form)
        if errors:
            return render_template("register.html", values=values,
                                   errors=errors), 400

        db = get_db()
        cursor = db.execute(
            """INSERT INTO users (username, email, mobile, password_hash,
                                  is_verified, created_at)
               VALUES (?, ?, ?, ?, 0, ?)""",
            (values["username"], values["email"],
             normalize_mobile(values["mobile"]),
             hash_password(request.form.get("password", "")),
             utc_now_iso()),
        )
        db.commit()

        session.clear()                     # fresh session for the OTP step
        session["pending_user_id"] = cursor.lastrowid
        session["pending_email"] = values["email"]
        session["pending_name"] = values["username"]
        csrf_token()

        ok, message, _ = issue_otp(values["email"], "register")
        flash(message, "success" if ok else "error")
        return redirect(url_for("verify_otp_page"))

    return render_template("register.html", values={}, errors={})


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp_page():
    pending_user_id = session.get("pending_user_id")
    if pending_user_id is None:
        flash("Start by registering or logging in first.", "error")
        return redirect(url_for("login_page"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?",
                      (pending_user_id,)).fetchone()
    if user is None:
        session.clear()
        flash("Account not found. Please register again.", "error")
        return redirect(url_for("register_page"))
    if user["is_verified"]:
        session.clear()
        flash("This account is already verified - please log in.", "success")
        return redirect(url_for("login_page"))

    dev_code = session.get("dev_otp") if (DEBUG or OTP_DEV_CONSOLE) else None

    if request.method == "POST":
        code = "".join(request.form.get(f"otp_digit{i}", "") for i in range(1, 7))
        if not code.isdigit() or len(code) != 6:
            error = "Enter the 6-digit code from your email."
        else:
            ok, error = verify_otp_record(user["email"], "register", code)
            if ok:
                db.execute(
                    "UPDATE users SET is_verified = 1 WHERE id = ?",
                    (user["id"],),
                )
                db.commit()
                session.pop("dev_otp", None)
                start_logged_in_session(user["id"])
                flash(f"Welcome to HomeNest, {user['username']}! "
                      "Your account is verified.", "success")
                return redirect(safe_next_url(url_for("home_page")))
        return render_template("verify_otp.html",
                               masked_email=mask_email(user["email"]),
                               dev_otp=dev_code,
                               error=error), 400

    return render_template("verify_otp.html",
                           masked_email=mask_email(user["email"]),
                           dev_otp=dev_code,
                           error=None)


@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    """Re-send the verification code (used by the button on the OTP page)."""
    pending_user_id = session.get("pending_user_id")
    target_email = session.get("pending_email")
    if pending_user_id is None or not target_email:
        return jsonify({"ok": False,
                        "error": "Your session expired. Please log in again.",
                        "message": "Your session expired. Please log in again."}), 400

    ok, message, retry_after = issue_otp(target_email, "register")
    return jsonify({"ok": ok, "message": message,
                    "error": None if ok else message,
                    "retry_after": retry_after,
                    "dev_otp": session.get("dev_otp") if (DEBUG or OTP_DEV_CONSOLE) else None}), (200 if ok else 429)


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        username = clean_text(request.form.get("username"))
        password = request.form.get("password", "")

        # Rate limit per username+IP: 5 attempts / 15 minutes.
        limiter_key = f"login:{username.lower()}:{client_ip()}"
        allowed, retry_after = rate_limit_hit(limiter_key, LOGIN_MAX_ATTEMPTS,
                                              LOGIN_WINDOW_SECONDS)
        if not allowed:
            minutes = max(1, retry_after // 60)
            return render_template(
                "login.html",
                values={"username": username},
                errors={"username": f"Too many failed attempts. Try again in "
                                    f"{minutes} minute(s)."},
            ), 429

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?",
                          (username,)).fetchone()

        if user is None or not verify_password(user["password_hash"], password):
            # Same message for both cases -> never reveal which part was wrong.
            return render_template(
                "login.html",
                values={"username": username},
                errors={"password": "Invalid username or password."},
            ), 401

        rate_limit_reset(limiter_key)

        if not user["is_verified"]:
            # Unverified accounts must complete OTP verification first.
            session.clear()
            session["pending_user_id"] = user["id"]
            session["pending_email"] = user["email"]
            session["pending_name"] = user["username"]
            csrf_token()

            # Check if there is already an active unexpired OTP
            active_otp = db.execute(
                """SELECT * FROM otp_codes
                   WHERE email = ? AND purpose = 'register' AND consumed_at IS NULL
                   ORDER BY id DESC LIMIT 1""",
                (user["email"],),
            ).fetchone()

            if active_otp and not otp_is_expired(active_otp["expires_at"]):
                flash("Please enter your verification code to activate your account.", "info")
            else:
                ok, message, _ = issue_otp(user["email"], "register")
                flash(message, "success" if ok else "error")
            return redirect(url_for("verify_otp_page"))

        start_logged_in_session(user["id"])
        db.execute("UPDATE users SET last_login_at = ? WHERE id = ?",
                   (utc_now_iso(), user["id"]))
        db.commit()
        flash(f"Welcome back, {user['username']}!", "success")
        return redirect(safe_next_url())

    return render_template("login.html", values={}, errors={})


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home_page"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password_page():
    if request.method == "POST":
        allowed, _ = rate_limit_hit(f"forgot:{client_ip()}", 10, 3600)
        if not allowed:
            flash("Too many attempts. Please try again later.", "error")
            return redirect(url_for("forgot_password_page"))

        email = clean_text(request.form.get("email")).lower()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?",
                          (email,)).fetchone()
        if user is not None:
            session.clear()
            session["reset_user_id"] = user["id"]
            session["reset_email"] = user["email"]
            csrf_token()
            ok, message, _ = issue_otp(user["email"], "reset")
            flash(message, "success" if ok else "error")
            return redirect(url_for("reset_password_page"))

        # Same response either way, so nobody can probe which emails exist.
        flash("If that email is registered, a reset code has been sent.",
              "success")
        return redirect(url_for("forgot_password_page"))

    return render_template("forgot_password.html", values={}, errors={})


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password_page():
    reset_user_id = session.get("reset_user_id")
    reset_email = session.get("reset_email")
    if reset_user_id is None or not reset_email:
        flash("Start by requesting a reset code first.", "error")
        return redirect(url_for("forgot_password_page"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ? AND email = ?",
                      (reset_user_id, reset_email)).fetchone()
    if user is None:
        session.clear()
        flash("Account not found. Please try again.", "error")
        return redirect(url_for("forgot_password_page"))

    dev_code = session.get("dev_otp") if (DEBUG or OTP_DEV_CONSOLE) else None

    if request.method == "POST":
        code = "".join(request.form.get(f"otp_digit{i}", "") for i in range(1, 7))
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        errors = {}

        if not code.isdigit() or len(code) != 6:
            errors["otp"] = "Enter the 6-digit code from your email."
        problem = password_problem(password)
        if problem:
            errors["password"] = problem
        elif password != confirm:
            errors["confirm_password"] = "Passwords do not match."

        if not errors:
            ok, error = verify_otp_record(user["email"], "reset", code)
            if not ok:
                errors["otp"] = error
            else:
                db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                           (hash_password(password), user["id"]))
                db.commit()
                session.clear()
                flash("Password updated. Please log in with your new password.",
                      "success")
                return redirect(url_for("login_page"))

        return render_template("reset_password.html",
                               masked_email=mask_email(user["email"]),
                               dev_otp=dev_code,
                               errors=errors), 400

    return render_template("reset_password.html",
                           masked_email=mask_email(user["email"]),
                           dev_otp=dev_code,
                           errors={})


# ---------------------------------------------------------------------------
# 12) PAGE ROUTES - OLX-STYLE LISTINGS (owner dashboard, add, edit)
# ---------------------------------------------------------------------------
ADD_FORM_PHOTO_ERROR = "Add at least one photo (JPG/PNG/WEBP, max 5 MB each)."


@app.route("/my-listings")
@login_required
def my_listings_page():
    """Dashboard: every listing posted by the logged-in user."""
    db = get_db()
    rows = db.execute(
        """SELECT p.*, u.username AS owner_username
           FROM properties p LEFT JOIN users u ON u.id = p.owner_id
           WHERE p.owner_id = ?
           ORDER BY COALESCE(p.created_at, '0000') DESC, p.id DESC""",
        (g.user["id"],),
    ).fetchall()
    listings = []
    for row in rows:
        item = dict(row)
        item["image_url"] = property_main_image(db, row)
        item["image_count"] = db.execute(
            "SELECT COUNT(*) FROM property_images WHERE property_id = ?",
            (row["id"],),
        ).fetchone()[0]
        listings.append(item)
    return render_template("my_listings.html", listings=listings)


def _property_form_context(values=None, errors=None, property_row=None,
                            images=None):
    """Shared template data for the add/edit listing form."""
    values = values or {}
    errors = errors or {}
    return {
        "values": values,
        "errors": errors,
        "property": property_row,
        "images": images or [],
        "today": date.today().isoformat(),
    }


@app.route("/add-property", methods=["GET", "POST"])
@login_required
def add_property_page():
    db = get_db()

    if request.method == "GET":
        defaults = {
            "contact_name": g.user["username"],
            "contact_phone": g.user["mobile"],
            "available_from": date.today().isoformat(),
            "furnishing": "Semi-Furnished",
            "property_type": "Apartment",
        }
        return render_template("property_form.html",
                               **_property_form_context(values=defaults))

    values, errors = validate_property_form(request.form)

    # --- photo validation (1 to MAX images) --------------------------------
    uploads = request.files.getlist("photos")
    chosen = [f for f in uploads if f and f.filename]
    images = []
    if not chosen:
        errors["photos"] = ADD_FORM_PHOTO_ERROR
    elif len(chosen) > MAX_IMAGES_PER_PROPERTY:
        errors["photos"] = (f"You can upload at most {MAX_IMAGES_PER_PROPERTY} "
                            "photos.")
    else:
        images, photo_error = validate_uploaded_images(chosen)
        if photo_error:
            errors["photos"] = photo_error

    if errors:
        return render_template(
            "property_form.html",
            **_property_form_context(values=values, errors=errors)), 400

    # --- save everything ----------------------------------------------------
    now = utc_now_iso()
    cursor = db.execute(
        """INSERT INTO properties
           (title, property_type, description, rent, deposit, bedrooms,
            bathrooms, furnishing, area_sqft, address, locality, city,
            district, state, available_from, contact_name, contact_phone,
            amenities, status, image_url, owner_id, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                   'available', '', ?, ?, ?)""",
        (values["title"], values["property_type"], values["description"],
         values["rent"], values["deposit"] or 0, values["bedrooms"],
         values["bathrooms"], values["furnishing"], values["area_sqft"],
         values["address"], values["locality"], values["city"],
         values["district"], values["state"], values["available_from"],
         values["contact_name"], values["contact_phone"],
         values["amenities"], g.user["id"], now, now),
    )
    property_id = cursor.lastrowid

    saved_filenames = []
    try:
        for order, image in enumerate(images):
            filename = save_image_file(image["data"], image["original_name"])
            saved_filenames.append(filename)
            db.execute(
                """INSERT INTO property_images
                   (property_id, filename, is_primary, sort_order, uploaded_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (property_id, filename, 1 if order == 0 else 0, order, now),
            )
        # Keep the legacy column in sync (used as card/detail fallback).
        db.execute("UPDATE properties SET image_url = ? WHERE id = ?",
                   ("/static/uploads/" + saved_filenames[0], property_id))
        db.commit()
    except Exception:
        db.rollback()
        for filename in saved_filenames:
            delete_image_file(filename)
        raise

    flash("Your property has been published!", "success")
    return redirect(url_for("my_listings_page"))


def _get_owned_property(db, property_id):
    """Fetch a property owned by the logged-in user, or None.
    THE SERVER decides ownership (session user id) - the browser is never
    trusted. This protects edit/delete/photo operations."""
    return db.execute(
        "SELECT * FROM properties WHERE id = ? AND owner_id = ?",
        (property_id, g.user["id"]),
    ).fetchone()


@app.route("/property/<int:property_id>/edit", methods=["GET", "POST"])
@login_required
def edit_property_page(property_id):
    db = get_db()
    row = _get_owned_property(db, property_id)
    if row is None:
        return render_template("403.html"), 403

    images = db.execute(
        """SELECT * FROM property_images WHERE property_id = ?
           ORDER BY is_primary DESC, sort_order ASC, id ASC""",
        (property_id,),
    ).fetchall()

    if request.method == "GET":
        values = dict(row)
        return render_template(
            "property_form.html",
            **_property_form_context(values=values, property_row=row,
                                     images=images))

    values, errors = validate_property_form(request.form)

    # Optional new photos - total (existing + new) must stay within limits.
    uploads = request.files.getlist("photos")
    chosen = [f for f in uploads if f and f.filename]
    new_images = []
    if len(images) + len(chosen) > MAX_IMAGES_PER_PROPERTY:
        errors["photos"] = (f"A listing can hold at most {MAX_IMAGES_PER_PROPERTY} "
                            "photos in total.")
    elif chosen:
        new_images, photo_error = validate_uploaded_images(chosen)
        if photo_error:
            errors["photos"] = photo_error

    if errors:
        return render_template(
            "property_form.html",
            **_property_form_context(values=values, errors=errors,
                                     property_row=row, images=images)), 400

    now = utc_now_iso()
    db.execute(
        """UPDATE properties SET
               title = ?, property_type = ?, description = ?, rent = ?,
               deposit = ?, bedrooms = ?, bathrooms = ?, furnishing = ?,
               area_sqft = ?, address = ?, locality = ?, city = ?,
               district = ?, state = ?, available_from = ?,
               contact_name = ?, contact_phone = ?, amenities = ?,
               updated_at = ?
           WHERE id = ? AND owner_id = ?""",
        (values["title"], values["property_type"], values["description"],
         values["rent"], values["deposit"] or 0, values["bedrooms"],
         values["bathrooms"], values["furnishing"], values["area_sqft"],
         values["address"], values["locality"], values["city"],
         values["district"], values["state"], values["available_from"],
         values["contact_name"], values["contact_phone"],
         values["amenities"], now, property_id, g.user["id"]),
    )

    if new_images:
        current_count = db.execute(
            "SELECT COUNT(*) FROM property_images WHERE property_id = ?",
            (property_id,),
        ).fetchone()[0]
        has_primary = db.execute(
            "SELECT 1 FROM property_images WHERE property_id = ? AND is_primary = 1",
            (property_id,),
        ).fetchone()
        for order, image in enumerate(new_images):
            filename = save_image_file(image["data"], image["original_name"])
            db.execute(
                """INSERT INTO property_images
                   (property_id, filename, is_primary, sort_order, uploaded_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (property_id, filename,
                 1 if (not has_primary and order == 0) else 0,
                 current_count + order, now),
            )
    # Keep the fallback column pointing at the primary image.
    main_row = db.execute(
        """SELECT filename FROM property_images WHERE property_id = ?
           ORDER BY is_primary DESC, sort_order ASC, id ASC LIMIT 1""",
        (property_id,),
    ).fetchone()
    db.execute("UPDATE properties SET image_url = ? WHERE id = ?",
               (("/static/uploads/" + main_row["filename"]) if main_row else "",
                property_id))
    db.commit()

    flash("Listing updated.", "success")
    return redirect(url_for("property_details_page", property_id=property_id))


@app.route("/property/<int:property_id>/delete", methods=["POST"])
@login_required
def delete_property(property_id):
    db = get_db()
    if _get_owned_property(db, property_id) is None:
        return render_template("403.html"), 403
    delete_property_and_files(db, property_id)
    flash("Your listing has been deleted.", "success")
    return redirect(url_for("my_listings_page"))


@app.route("/property/<int:property_id>/status", methods=["POST"])
@login_required
def toggle_property_status(property_id):
    db = get_db()
    row = _get_owned_property(db, property_id)
    if row is None:
        return render_template("403.html"), 403
    new_status = "rented" if row["status"] == "available" else "available"
    db.execute(
        "UPDATE properties SET status = ?, updated_at = ? WHERE id = ?",
        (new_status, utc_now_iso(), property_id),
    )
    db.commit()
    flash(f"Listing marked as {new_status}.", "success")
    return redirect(request.referrer or url_for("my_listings_page"))


@app.route("/property/<int:property_id>/photos/<int:image_id>/delete",
           methods=["POST"])
@login_required
def delete_property_photo(property_id, image_id):
    db = get_db()
    if _get_owned_property(db, property_id) is None:
        return render_template("403.html"), 403
    image = db.execute(
        "SELECT * FROM property_images WHERE id = ? AND property_id = ?",
        (image_id, property_id),
    ).fetchone()
    if image is None:
        flash("Photo not found.", "error")
        return redirect(url_for("edit_property_page", property_id=property_id))

    remaining = db.execute(
        "SELECT COUNT(*) FROM property_images WHERE property_id = ?",
        (property_id,),
    ).fetchone()[0]
    if remaining <= 1:
        flash("A listing needs at least one photo.", "error")
        return redirect(url_for("edit_property_page", property_id=property_id))

    db.execute("DELETE FROM property_images WHERE id = ?", (image_id,))
    # If we removed the primary image, promote the first remaining one.
    if image["is_primary"]:
        next_image = db.execute(
            """SELECT id FROM property_images WHERE property_id = ?
               ORDER BY sort_order ASC, id ASC LIMIT 1""",
            (property_id,),
        ).fetchone()
        if next_image:
            db.execute("UPDATE property_images SET is_primary = 1 WHERE id = ?",
                       (next_image["id"],))
    main_row = db.execute(
        """SELECT filename FROM property_images WHERE property_id = ?
           ORDER BY is_primary DESC, sort_order ASC, id ASC LIMIT 1""",
        (property_id,),
    ).fetchone()
    db.execute("UPDATE properties SET image_url = ? WHERE id = ?",
               (("/static/uploads/" + main_row["filename"]) if main_row else "",
                property_id))
    db.commit()
    delete_image_file(image["filename"])
    flash("Photo removed.", "success")
    return redirect(url_for("edit_property_page", property_id=property_id))


@app.route("/property/<int:property_id>/photos/<int:image_id>/primary",
           methods=["POST"])
@login_required
def set_primary_photo(property_id, image_id):
    db = get_db()
    if _get_owned_property(db, property_id) is None:
        return render_template("403.html"), 403
    image = db.execute(
        "SELECT id FROM property_images WHERE id = ? AND property_id = ?",
        (image_id, property_id),
    ).fetchone()
    if image is None:
        flash("Photo not found.", "error")
        return redirect(url_for("edit_property_page", property_id=property_id))

    db.execute("UPDATE property_images SET is_primary = 0 WHERE property_id = ?",
               (property_id,))
    db.execute("UPDATE property_images SET is_primary = 1 WHERE id = ?",
               (image_id,))
    main_row = db.execute(
        "SELECT filename FROM property_images WHERE id = ?", (image_id,)
    ).fetchone()
    db.execute("UPDATE properties SET image_url = ? WHERE id = ?",
               ("/static/uploads/" + main_row["filename"], property_id))
    db.commit()
    flash("Main photo updated.", "success")
    return redirect(url_for("edit_property_page", property_id=property_id))


# ---------------------------------------------------------------------------
# 13) REST API - PROPERTIES (search, filters, sorting, pagination)
# ---------------------------------------------------------------------------
@app.route("/api/properties", methods=["GET"])
def api_get_properties():
    """Return properties as JSON with optional search and filters.

    Supported query parameters:
        q          (str) - free text: title / locality / city / address
        city       (str) - matches city OR address, partial, case-insensitive
        locality   (str) - matches locality, partial
        min_rent   (int) - rent >= value
        max_rent   (int) - rent <= value
        bedrooms   (int) - bedrooms >= value (so 3 means "3 or more")
        type       (str) - exact property type, e.g. Apartment
        furnishing (str) - exact furnishing status
        status     (str) - 'available' or 'rented'
        sort       (str) - newest (default) | rent_asc | rent_desc
        page       (int) - 1-based page number (9 results per page)
    """
    db = get_db()

    query_parts = [
        "q", "city", "locality", "min_rent", "max_rent", "bedrooms",
        "type", "furnishing", "status", "sort", "page",
    ]
    args = {key: request.args.get(key) for key in query_parts}

    errors = {}
    min_rent, min_error = try_parse_int(args["min_rent"])
    max_rent, max_error = try_parse_int(args["max_rent"])
    bedrooms, bedrooms_error = try_parse_int(args["bedrooms"])
    page, page_error = try_parse_int(args["page"])
    if page is not None and page < 1:
        page_error = "must be 1 or greater"
    if min_error:
        errors["min_rent"] = "min_rent " + min_error
    if max_error:
        errors["max_rent"] = "max_rent " + max_error
    if bedrooms_error:
        errors["bedrooms"] = "bedrooms " + bedrooms_error
    if page_error:
        errors["page"] = "page " + page_error
    if min_rent is not None and max_rent is not None and min_rent > max_rent:
        errors["rent_range"] = "min_rent cannot be greater than max_rent."
    if args["status"] and args["status"] not in ("available", "rented"):
        errors["status"] = "status must be 'available' or 'rented'."
    if args["sort"] and args["sort"] not in SORT_OPTIONS:
        errors["sort"] = "sort must be newest, rent_asc or rent_desc."
    if errors:
        return jsonify({"error": "Invalid input.", "details": errors}), 400

    # Build the SQL query safely: EVERY value goes through a "?" placeholder,
    # which prevents SQL injection. Never join user input directly into SQL.
    where = ["1 = 1"]
    params = []

    def add_like(column, value):
        """Case-insensitive partial match with escaped wildcards."""
        where.append(f"{column} LIKE ? ESCAPE '\\'")
        escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        params.append("%" + escaped + "%")

    free_text = clean_text(args["q"])
    if free_text:
        where.append("(title LIKE ? ESCAPE '\\' OR locality LIKE ? ESCAPE '\\'"
                     " OR city LIKE ? ESCAPE '\\' OR address LIKE ? ESCAPE '\\')")
        escaped = (free_text.replace("\\", "\\\\")
                   .replace("%", "\\%").replace("_", "\\_"))
        params.extend(["%" + escaped + "%"] * 4)

    city = clean_text(args["city"])
    if city:
        # Same behaviour as version 1: match the city OR the address.
        escaped = (city.replace("\\", "\\\\")
                   .replace("%", "\\%").replace("_", "\\_"))
        where.append("(city LIKE ? ESCAPE '\\' OR address LIKE ? ESCAPE '\\')")
        params.extend(["%" + escaped + "%", "%" + escaped + "%"])

    locality = clean_text(args["locality"])
    if locality:
        add_like("locality", locality)

    if min_rent is not None:
        where.append("rent >= ?")
        params.append(min_rent)
    if max_rent is not None:
        where.append("rent <= ?")
        params.append(max_rent)
    if bedrooms is not None:
        where.append("bedrooms >= ?")
        params.append(bedrooms)
    if clean_text(args["type"]):
        where.append("property_type = ?")
        params.append(clean_text(args["type"]))
    if clean_text(args["furnishing"]):
        where.append("furnishing = ?")
        params.append(clean_text(args["furnishing"]))
    if clean_text(args["status"]):
        where.append("status = ?")
        params.append(clean_text(args["status"]))

    where_sql = " AND ".join(where)
    order_sql = SORT_OPTIONS[args["sort"] or "newest"]
    current_page = page or 1

    total = db.execute(
        f"SELECT COUNT(*) FROM properties p WHERE {where_sql}", params
    ).fetchone()[0]

    rows = db.execute(
        f"""SELECT p.*, u.username AS owner_username
            FROM properties p LEFT JOIN users u ON u.id = p.owner_id
            WHERE {where_sql}
            {order_sql}
            LIMIT ? OFFSET ?""",
        params + [PAGE_SIZE, (current_page - 1) * PAGE_SIZE],
    ).fetchall()

    properties = [serialize_property(db, row) for row in rows]
    total_pages = max(1, -(-total // PAGE_SIZE))   # ceiling division
    return jsonify({
        "count": len(properties),
        "total": total,
        "page": current_page,
        "pages": total_pages,
        "properties": properties,
    }), 200


@app.route("/api/properties/<int:property_id>", methods=["GET"])
def api_get_property(property_id):
    """One property with gallery, contact and viewer context, or 404."""
    db = get_db()
    row = db.execute(
        """SELECT p.*, u.username AS owner_username
           FROM properties p LEFT JOIN users u ON u.id = p.owner_id
           WHERE p.id = ?""",
        (property_id,),
    ).fetchone()
    if row is None:
        return jsonify({
            "error": f"Property with id {property_id} was not found."
        }), 404
    return jsonify({"property": serialize_property(db, row, with_viewer=True)}), 200


@app.route("/api/cities", methods=["GET"])
def api_get_cities():
    """Distinct city names - used for the search suggestion list."""
    rows = get_db().execute(
        "SELECT DISTINCT city FROM properties ORDER BY city"
    ).fetchall()
    return jsonify({"cities": [row["city"] for row in rows]}), 200


@app.route("/api/property-types", methods=["GET"])
def api_get_property_types():
    """Distinct property types - used to fill the filter dropdown."""
    rows = get_db().execute(
        "SELECT DISTINCT property_type FROM properties ORDER BY property_type"
    ).fetchall()
    return jsonify({"types": [row["property_type"] for row in rows]}), 200


@app.route("/api/health", methods=["GET"])
def api_health():
    """Simple health check - useful for demos and interviews."""
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM properties").fetchone()[0]
    users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    return jsonify({
        "status": "ok", "database": "connected",
        "total_properties": total, "total_users": users,
    }), 200


# ---------------------------------------------------------------------------
# 14) REST API - FAVORITES (per user, login required)
# ---------------------------------------------------------------------------
@app.route("/api/favorites", methods=["GET"])
def api_get_favorites():
    """All favorite properties of the logged-in user (401 for guests)."""
    user = load_current_user()
    if user is None:
        return jsonify({"error": "Please log in to see your favorites."}), 401
    rows = get_db().execute(
        """SELECT p.* FROM favorites AS f
           JOIN properties AS p ON p.id = f.property_id
           WHERE f.user_id = ?
           ORDER BY f.added_on DESC, p.id DESC""",
        (user["id"],),
    ).fetchall()
    favorites = [serialize_property(get_db(), row) for row in rows]
    return jsonify({"count": len(favorites), "favorites": favorites}), 200


@app.route("/api/favorites", methods=["POST"])
def api_add_favorite():
    """Add a property to the logged-in user's favorites.
    Body: {"property_id": 1}"""
    user = load_current_user()
    if user is None:
        return jsonify({"error": "Please log in to save favorites."}), 401

    data = request.get_json(silent=True)   # silent=True -> None instead of crash
    if not isinstance(data, dict) or "property_id" not in data:
        return jsonify({"error": 'Request body must be JSON like {"property_id": 1}.'}), 400

    property_id, error = try_parse_int(data.get("property_id"))
    if error or property_id is None:
        return jsonify({"error": "property_id must be a whole number."}), 400

    db = get_db()
    property_row = db.execute(
        "SELECT id FROM properties WHERE id = ?", (property_id,)
    ).fetchone()
    if property_row is None:
        return jsonify({"error": f"Property with id {property_id} was not found."}), 404

    already_saved = db.execute(
        "SELECT 1 FROM favorites WHERE user_id = ? AND property_id = ?",
        (user["id"], property_id),
    ).fetchone()
    if already_saved:
        return jsonify({"error": f"Property {property_id} is already in favorites."}), 409

    db.execute(
        "INSERT INTO favorites (user_id, property_id) VALUES (?, ?)",
        (user["id"], property_id),
    )
    db.commit()
    return jsonify({"message": "Property added to favorites.",
                    "property_id": property_id}), 201


@app.route("/api/favorites/<int:property_id>", methods=["DELETE"])
def api_remove_favorite(property_id):
    """Remove a property from the logged-in user's favorites."""
    user = load_current_user()
    if user is None:
        return jsonify({"error": "Please log in to manage favorites."}), 401

    db = get_db()
    saved = db.execute(
        "SELECT 1 FROM favorites WHERE user_id = ? AND property_id = ?",
        (user["id"], property_id),
    ).fetchone()
    if saved is None:
        return jsonify({"error": f"Property {property_id} is not in favorites."}), 404

    db.execute(
        "DELETE FROM favorites WHERE user_id = ? AND property_id = ?",
        (user["id"], property_id),
    )
    db.commit()
    return jsonify({"message": "Property removed from favorites.",
                    "property_id": property_id}), 200


# ---------------------------------------------------------------------------
# 15) ERROR HANDLERS (JSON for API calls, friendly HTML for pages)
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def handle_404(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "API endpoint not found."}), 404
    return render_template("404.html"), 404


@app.errorhandler(403)
def handle_403(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "You are not allowed to do that."}), 403
    return render_template("403.html"), 403


@app.errorhandler(413)
def handle_413(error):
    message = "Upload too large. Photos must be 5 MB or smaller each."
    if request.path.startswith("/api/"):
        return jsonify({"error": message}), 413
    flash(message, "error")
    return redirect(request.referrer or url_for("home_page"))


@app.errorhandler(500)
def handle_500(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Something went wrong on the server."}), 500
    return "<h1>500 - Server error</h1><p>Please try again.</p>", 500


# ---------------------------------------------------------------------------
# 16) START THE DEVELOPMENT SERVER
# ---------------------------------------------------------------------------
init_db()   # creates / upgrades the schema, seeds sample data once

if __name__ == "__main__":
    # debug=True gives auto-reload and clear error pages. Never use it in
    # production (a real deployment uses a WSGI server such as Gunicorn).
    app.run(debug=DEBUG,
            host=os.getenv("HOST", "127.0.0.1"),
            port=_env_int("PORT", 5000))



