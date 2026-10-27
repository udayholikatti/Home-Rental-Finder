# 🏠 HomeNest — House Rental Finder (v2, OLX-style)

A beginner-friendly **full-stack web application** for finding and posting
rental homes, built with **Python Flask**, **SQLite**, and
**HTML5 / CSS3 / JavaScript**.

**Version 2 adds:** secure user accounts with **email OTP verification**, an
**OLX-style "post your property" system** with multiple photo uploads, a
**My Listings dashboard**, richer **search / filters / sorting**, and
per-user favorites — while keeping every version-1 feature working.

> All 12 built-in listings are clearly identified **sample data**.
> Images are AI-generated for illustration.

## ✨ Features

### Browsing (existing, improved)
- Home page with hero city search, filter card and responsive property grid
- Filters: **city/locality, min & max rent, bedrooms, property type,
  furnishing, availability**, free-text search (`q`)
- **Sorting**: newest first, rent low→high, rent high→low
- **Pagination** (9 listings per page) and shareable filter URLs
- Property details page: **multi-image gallery**, deposit, area, furnishing,
  availability, amenities, status badge
- **Owner contact card** — phone number is masked for guests, revealed to
  logged-in users
- Friendly loading / empty / error states, toasts, mobile-first responsive

### Accounts & security (new)
- Register with username, email, mobile + password
- **Email OTP verification**: 6-digit code, expiry, resend cooldown, request
  caps, wrong-attempt limits; account activates only after verification
- Login with **rate limiting** (5 attempts / 15 min), logout, session
  management (**session fixation** protection, 7-day cookie, HttpOnly +
  SameSite)
- **Forgot password → OTP → reset password** workflow
- **CSRF protection** on every POST (forms and fetch calls)
- **Password hashing** with Werkzeug (scrypt) — plain passwords never stored;
  OTP codes are stored **hashed** too
- In-memory **rate limiting** for login / register / OTP endpoints
- All secrets and limits configured through a **`.env` file**

### OLX-style listings (new)
- Any verified user can **publish a property**: title, type, description,
  rent, deposit, bedrooms/bathrooms, furnishing, area, full address
  (address / locality / city / district / state), available-from date,
  contact name & phone, amenities
- **Multiple photo uploads** (up to 8, max 5 MB each, JPG/PNG/WEBP) with:
  - extension whitelist + **Pillow content verification** (blocks executables
    renamed to .jpg)
  - safe unique filenames (`uuid + secure_filename`)
- **My Listings dashboard**: edit, delete (with confirm), mark
  **available / rented**, manage photos (upload more, set main, remove)
- **Ownership enforced on the server** for every edit/delete/photo action —
  the browser is never trusted
- Listing cards show main photo, rent, location, beds/baths, furnishing,
  short description and owner name

### REST API
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET  | `/api/properties` | Search/filter/sort/paginate (see params in `app.py`) |
| GET  | `/api/properties/<id>` | One property + gallery + viewer context |
| GET  | `/api/cities` | Distinct cities (search suggestions) |
| GET  | `/api/property-types` | Distinct property types |
| GET  | `/api/favorites` | Your saved properties (401 for guests) |
| POST | `/api/favorites` | Add favorite `{"property_id": 1}` |
| DELETE | `/api/favorites/<id>` | Remove favorite |
| GET  | `/api/health` | Health check |

## 🧰 Tech stack

| Layer    | Technology |
|----------|------------|
| Frontend | HTML5, CSS3, vanilla JavaScript (fetch API) |
| Backend  | Python 3, Flask 3 |
| Database | SQLite 3 (file: `rentals.db`, auto-created & auto-migrated) |
| Email    | SMTP (any provider; Gmail example below) |
| Images   | Pillow (upload validation) |

## 📁 Project structure

```
house_rental_finder/
├── app.py                      # Flask backend: routes, REST API, schema, migration
├── security.py                 # Password/OTP hashing, rate limiter, validators
├── mailer.py                   # SMTP OTP email delivery
├── requirements.txt            # Flask, python-dotenv, Pillow
├── .env.example                # Copy to .env and edit (never commit .env)
├── README.md
├── rentals.db                  # SQLite DB (auto-created on first run)
├── templates/
│   ├── base.html               # Shared navbar / footer / flash messages
│   ├── index.html              # Home: hero, filters, cards, pagination
│   ├── property_details.html   # Gallery, amenities, owner contact
│   ├── favorites.html          # Saved homes (login required)
│   ├── login.html  register.html  verify_otp.html
│   ├── forgot_password.html  reset_password.html
│   ├── add/edit shared: property_form.html
│   ├── my_listings.html        # Owner dashboard
│   ├── 404.html  403.html
└── static/
    ├── style.css               # Design system (teal/amber) + v2 components
    ├── script.js               # Cards, filters, gallery, OTP UI, previews
    ├── favicon.svg
    ├── images/                 # Sample property photos (AI-generated)
    └── uploads/                # User-uploaded photos (created automatically)
```

## 🚀 Getting started (Windows PowerShell + VS Code)

1. **Install Python 3.10+** from python.org — tick **"Add python.exe to PATH"**.
2. Open the project folder in VS Code (`File → Open Folder`), then open a
   terminal (`Ctrl + ~`) and run:

```powershell
# 1) create and activate a virtual environment
python -m venv venv
venv\Scripts\activate
# (if PowerShell blocks activation, run once:
#   Set-ExecutionPolicy -Scope CurrentUser RemoteSigned  )

# 2) install dependencies
pip install -r requirements.txt

# 3) create your .env file
copy .env.example .env
notepad .env        # edit SECRET_KEY at minimum (see below)

# 4) run the app - the database creates/migrates itself on first start
python app.py
```

3. Open **http://127.0.0.1:5000** in your browser.

Linux / macOS: replace `venv\Scripts\activate` with `source venv/bin/activate`
and `copy` with `cp`.

> **No database step is needed.** On start-up the app creates missing tables,
> adds the v2 columns to an old v1 database with `ALTER TABLE` (existing rows
> are preserved), and seeds the 12 sample listings only when the DB is empty.

## 🔐 Configure email OTP (SMTP)

The OTP email is delivered through any standard SMTP provider. For Gmail:

1. Enable **2-Step Verification** on your Google account.
2. Create an **App Password**: https://myaccount.google.com/apppasswords
   (select "Mail" — you get a 16-character password).
3. Put it in `.env`:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=abcdabcdabcdabcd     # the 16-char app password
```

**Development without SMTP:** keep `OTP_DEV_CONSOLE=1` in `.env`. While SMTP
is not configured, the OTP is printed in the server console (never faked in
the UI) so you can test the full flow locally. Remove that flag for any
real deployment.

**Never** commit your `.env` — it is already in `.gitignore`.

## 👤 Demo account (for quick demos/interviews)

| Field | Value |
|-------|-------|
| Username | `demo_user` |
| Password | `Demo@1234` |
| Email | `demo@homenest.app` (already verified) |

The demo account owns 3 of the sample listings, so the **My Listings**
dashboard, editing and photo management can be demoed instantly. New users
you register yourself will need OTP verification (console or SMTP).

## 🗄️ Database & migration notes

- Tables: `users`, `otp_codes`, `properties`, `property_images`, `favorites`
- The v1 database had a *global* favorites table; the migration converts it
  to per-user favorites and moves old rows to the demo account.
- Migration runs automatically on every start-up (`init_db()` in `app.py`);
  it only adds — it never drops or rewrites existing data.

## ✅ What is tested

`scripts/test_homenest_v2.py` (kept outside the app folder) runs **103
automated checks**: pages, every filter/sort, pagination, validation errors,
registration + OTP (wrong code, cooldown, resend), unverified-login block,
guest 401s, CSRF rejection, photo upload & malicious-file rejection, 403
ownership checks, edit/status/photo management, favorites, login rate
limiting, and the full forgot/reset-password flow. All pass on a clean run.

*SMTP delivery itself is implemented against the standard library but could
not be live-tested without real credentials — the honest-failure path
(wrong credentials → visible error message + resend) is what the tests cover.*


## 🔭 Future improvements

User profile pages & avatars, landlord verification badge, booking/appointment
requests, image thumbnails & CDN, Redis-backed rate limiting, password reset
via SMS, WebSocket notifications, and deployment behind Gunicorn + Nginx.
