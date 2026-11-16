# Swap Couple — development package

A Flask-based, adult-only personal dating/social connection prototype. It is not a general classifieds platform and does not include paid sexual-service booking or payment flows.

## Local development

1. Use Python 3.11+.
2. Create and activate a virtual environment.
3. Install dependencies: `pip install -r requirements.txt`.
4. Copy `.env.example` to `.env` and set a private `SECRET_KEY` and local `ADMIN_EMAIL` / `ADMIN_PASSWORD` (admin password must be at least 12 characters).
5. Run `python app.py` and open `http://127.0.0.1:5000`.

Local development can use SQLite and local private image storage. Never use those fallbacks in production.

## Render production configuration

Set the following as private Render environment variables (never commit secrets):

- `SECRET_KEY` — random secret, at least 32 characters.
- `DATABASE_URL` — Render PostgreSQL Internal Database URL. The app selects psycopg v3 explicitly.
- `PUBLIC_BASE_URL` — deployed HTTPS URL.
- `ADMIN_EMAIL`, `ADMIN_PASSWORD` — private owner login; password at least 12 characters.
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM` — working email delivery.
- `SMS_WEBHOOK_URL` (HTTPS), `SMS_WEBHOOK_TOKEN` — an owner-controlled SMS gateway adapter that accepts JSON `{\"to\": \"...\", \"message\": \"...\"}` and returns HTTP 2xx. Ensure India DLT/provider compliance.
- `S3_ENDPOINT_URL`, `S3_BUCKET`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, optional `S3_REGION` — private S3-compatible object storage.

Production startup deliberately fails if critical settings are absent. Production image storage never falls back to local disk. Render runs `flask --app app init-db` before Gunicorn. This is an idempotent first-install table creation step only; it does not alter existing tables and is NOT a substitute for versioned migrations when the schema changes.

## Release status

See `RELEASE_STATUS.txt`. Runtime, integration, and security tests have not yet passed. Do not treat this as production-ready.


## Security and release notes (2026-11-14)
- Registration age is calculated by calendar birthday, not an approximate day-count.
- OTP resend is limited to one request per 60 seconds and five issued codes per hour per user and channel. Issuing a new code invalidates the previous code.
- Production requires `SMS_WEBHOOK_TOKEN`; SMS webhook calls fail closed if it is missing.
- Do not expose `.env`, database URLs, SMTP credentials, SMS tokens, or S3 keys in GitHub.

This package is still a development build, not a production release. It still calls `db.create_all()` during startup and does not yet include a reviewed database migration chain or persistent login brute-force throttling. Runtime tests against PostgreSQL, SMTP, the SMS provider, and S3 have not been performed. Do not deploy it publicly until those items are completed and tested.
