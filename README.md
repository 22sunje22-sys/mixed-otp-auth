# Email OTP Authentication

Minimal OTP authentication for internal dashboards. Users log in via **Email OTP** — backed by Supabase Auth. No passwords, no tokens stored in the app.

## How It Works

1. User enters their corporate email (`@platinumlist.net` only)
2. Backend calls Supabase Auth `POST /auth/v1/otp` — Supabase sends a 6-digit code via custom SMTP
3. User enters code → backend verifies via `POST /auth/v1/verify`
4. Signed `somauth` HttpOnly cookie set (24h TTL)

## Security

Cookies are HMAC-SHA256 signed with `OTP_SIGNING_SECRET`:
```
base64url(JSON_payload).hex(hmac-sha256(payload, OTP_SIGNING_SECRET))
```

| Cookie  | Payload              | TTL    | Purpose          |
|---------|----------------------|--------|------------------|
| `soreq` | `{ iat, rid, p, email }` | 15 min | Request context  |
| `somauth` | `{ e, x }`         | 24h    | Auth session     |

Properties: HttpOnly + Secure + SameSite=Lax, timing-safe HMAC comparison, single-use time-limited OTP codes.

## File Structure

```
mixed-otp-auth/
├── login.html               # Login page (email OTP only)
├── vercel.json              # Routes config
└── api/otp/
    ├── email-request.js     # Send OTP via Supabase Auth
    ├── email-verify.js      # Verify code, set auth cookie
    ├── session.js           # GET: check auth from somauth cookie
    └── logout.js            # POST: clear all cookies
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SUPABASE_URL` | Yes | Supabase project URL (must have Auth + email OTP configured) |
| `SUPABASE_SERVICE_ROLE_KEY` | Yes | Supabase **service role** key — server-side only, never exposed to client. Get from Supabase dashboard → Project Settings → API → `service_role` |
| `OTP_SIGNING_SECRET` | Yes | Random string ≥ 16 chars for HMAC cookie signing. Generate with: `openssl rand -hex 32` |
| `OTP_ALLOWED_DOMAIN` | No | Email domain restriction (default: `platinumlist.net`) |

> **Important:** `SUPABASE_SERVICE_ROLE_KEY` has full database access. Never commit it or expose it client-side. Set it as an encrypted environment variable in Vercel (Settings → Environment Variables).

## Supabase Setup

1. Enable **Email** auth provider (Auth → Providers → Email)
2. Set `OTP` mode: Auth → Settings → disable "Confirm email" / enable magic links, or use the email OTP flow
3. Configure **Custom SMTP** (Auth → Settings → SMTP) so emails come from your domain

## Protect Your Dashboard

Add this at the top of your main page `<script>`:

```javascript
fetch('/api/otp/session')
  .then(r => r.json())
  .then(d => { if (!d.authenticated) location.replace('/login'); })
  .catch(() => {});
```

Logout button:
```javascript
fetch('/api/otp/logout', { method: 'POST' })
  .then(() => location.replace('/login'));
```

## Error Reference

| Error | Meaning |
|---|---|
| `otp_request_required` | `soreq` cookie missing — click "Send Code" first |
| `otp_request_expired` | Request expired (>15 min) — request new code |
| `otp_incorrect` | Wrong code or already used |
| `email_domain_not_allowed` | Email not in allowed domain |
| `supabase_otp_failed` | Supabase Auth unreachable or returned error |
| `supabase_verify_failed` | Verification call failed |
