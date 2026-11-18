# Swap Couple — Permanent No-S3 Package

Private visitor selfies and owner profile photos are stored as binary data in PostgreSQL (`user_media` table). No S3/R2 account or ephemeral local disk is used. Images are validated JPEG, PNG, or WEBP, maximum 5 MB. Selfies are owner/admin-only; owner photos require login and approved membership.

## Required production configuration
`DATABASE_URL`, `ADMIN_EMAIL`, `ADMIN_PASSWORD` (12+ characters), `SECRET_KEY` (32+ random characters), `PUBLIC_BASE_URL` (HTTPS), Brevo SMTP variables (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`), and MSG91 (`MSG91_WIDGET_ID`, `MSG91_WIDGET_TOKEN`, `MSG91_AUTHKEY`). Never commit real secrets to GitHub.

## Database initialization
The Render start command runs `flask --app app init-db` before Gunicorn. This creates missing tables, including `user_media`, and bootstraps the first admin if configured. It does not modify existing tables or perform general schema migrations.

## Permanent operation
Use a non-expiring persistent PostgreSQL plan and keep regular backups. Image blobs consume database storage and increase backup/restore size. The previously created Render Free database expires and must be upgraded or replaced for permanent use. Free web hosting may sleep; choose an always-on plan if continuous availability is required.

## Verification status
Live Render, PostgreSQL, Brevo SMTP, MSG91 OTP, browser end-to-end, backup/restore and production security tests have not been performed. Treat this as a deployment candidate pending those tests, not as production-certified software.
