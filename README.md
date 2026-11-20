# Swap Couple — Brevo Email OTP release

Private visitor selfies and owner profile photos are stored as binary data in PostgreSQL (`user_media`). No S3/R2 account or ephemeral local disk is used. Images are validated JPEG, PNG, or WEBP, maximum 5 MB. Selfies are visible only to the owner/admin. Owner photos require login and approved membership.

## Required production configuration
`DATABASE_URL`, `ADMIN_EMAIL`, `ADMIN_PASSWORD` (12+ characters), `SECRET_KEY` (32+ random characters), `PUBLIC_BASE_URL` (HTTPS), `BREVO_API_KEY`, and `BREVO_SENDER_EMAIL`. Optional: `BREVO_SENDER_NAME` (defaults to Swap Couple). The sender address must be verified in Brevo. Email is sent using Brevo's HTTPS transactional email API; no SMTP ports or MSG91 credentials are used. Never commit real secrets to GitHub.

## Verification and approval
Visitors register with their mobile number, but mobile OTP verification is not used. Email OTP is required. After email verification, the visitor submits a private selfie. Admin approval requires verified email, a submitted selfie, and an unblocked account. Selfie submission is for owner review only and is not proof of age or legal identity. The 18+ date-of-birth check remains.

## Database initialization
The Render start command runs `flask --app app init-db` before Gunicorn. This creates missing tables and bootstraps the first admin if configured. It does not alter existing tables or perform general schema migrations. Existing `phone_ok` database columns are retained for compatibility but are no longer used for access, approval, or messaging decisions.

## Permanent operation
Use a non-expiring persistent PostgreSQL plan and keep regular backups. Image blobs consume database storage and increase backup/restore size. Free web hosting may sleep; choose an always-on plan if continuous availability is required.

## Deployment checks
Before deployment, configure the Brevo API key and verified sender in Render environment variables. Then run automated tests and perform real email OTP, selfie upload, admin approval, profile, chat, meeting, and backup/restore checks. A successful build alone is not production certification.
