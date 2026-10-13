# Email OTP Authentication

Minimal OTP authentication for internal dashboards. Users log in via **Email OTP** — backed by Supabase Auth. No passwords, no tokens stored in the app.

## How It Works

1. User enters their corporate email (`@platinumlist.net` only)
2. Backend calls the shared Supabase edge function **`otp-send`** with its `service_role` key. The function mints a 6-digit code (`auth/v1/admin/generate_link`, which sends nothing) and emails it through **pl-mailer** from `e-notifications@platinumlist.net`. The code is never returned to the app.
3. User enters code → backend verifies via `POST /auth/v1/verify` (`type: "email"`)
4. Signed `somauth` HttpOnly cookie set (24h TTL)

> **Do not call `POST /auth/v1/otp` / `signInWithOtp`.** On our Supabase project that makes Supabase Auth send the code through a shared Gmail box (~500 emails/day for everyone; a password change on it broke every login on 11.10.2026). Use `otp-send`.

## `otp-send` — the shared sender

Deployed on Supabase project `kwftlkfvtglnugxsyjci`; source in [`supabase/functions/otp-send`](supabase/functions/otp-send/index.ts).

```
POST https://<project>.supabase.co/functions/v1/otp-send
Authorization: Bearer <SUPABASE_SERVICE_ROLE_KEY>
{ "email": "name@platinumlist.net", "app": "My Dashboard", "allow": ["platinumlist.net"] }
→ 200 { "ok": true }
```

| Field | Notes |
|---|---|
| `email` | Recipient. |
| `app` | Shown in the email ("Sign in to My Dashboard") and in the send log. Letters, digits, spaces and `.&'()-`, up to 60 chars. |
| `allow` | Who may receive codes: domains or exact addresses. Default `["platinumlist.net"]`. Pass `["*"]` only if your app checks its own whitelist *before* calling. |
| `redirect_to` | Optional `https://` URL, only if you also use the magic link. |

Errors: `403 service_role_required` (anon key used), `403 email_not_allowed`, `400 email_invalid` / `app_invalid` / `allow_invalid`, `429 too_many_requests` (5 codes per address per 10 min), `429 daily_cap_reached`, `502 mint_failed` / `send_failed`, `504 send_timeout`.

**No email key in your app.** The pl-mailer key is stored only in Supabase Vault and read by the function. You need nothing beyond the Supabase `service_role` key your backend already has.

**Security:** the gateway verifies the JWT signature (`verify_jwt = true`) and the function additionally requires `role = service_role`, so the public anon key can't trigger emails. Every call is logged in `public.otp_send_log` (RLS on, service_role only) — that table is also the per-app volume report. Failures alert the team Telegram channel.

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
    ├── email-request.js     # Ask otp-send to email a code
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
| `OTP_APP_NAME` | No | Name shown in the email ("Sign in to …"). Default `Dashboard` |

> **Important:** `SUPABASE_SERVICE_ROLE_KEY` has full database access. Never commit it or expose it client-side. Set it as an encrypted environment variable in Vercel (Settings → Environment Variables).

## Supabase Setup

1. Enable **Email** auth provider (Auth → Providers → Email)
2. Set `OTP` mode: Auth → Settings → disable "Confirm email" / enable magic links, or use the email OTP flow
3. No SMTP setup needed — `otp-send` delivers the email. (The project's Custom SMTP is the old Gmail path; don't rely on it.)

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
