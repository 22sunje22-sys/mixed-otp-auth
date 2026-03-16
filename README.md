# Mixed Email + Slack OTP Authentication

A dual-channel OTP authentication method for internal dashboards. Users can log in via **Email OTP** or **Slack OTP (Gatey)** — both backed by the same Supabase Auth engine. No passwords, no tokens stored in the app.

## How It Works

```
┌─────────────────────────────────────────────┐
│                  Login Page                   │
│         [Email OTP]    [Slack OTP]           │
└──────┬──────────────────────┬────────────────┘
       │                      │
       ▼                      ▼
  email-request            request
  (Supabase Auth           (Gatey Edge Function
   signInWithOtp)           returns email)
       │                      │
       │                      ▼
       │               User DMs @gatey: "otp <project>"
       │               Gatey generates OTP via
       │               sb.auth.admin.generateLink()
       │               and sends code to Slack DM
       │                      │
       ▼                      ▼
  User gets code         User gets code
  in email inbox         in Slack DM
       │                      │
       ▼                      ▼
  email-verify              verify
  (Supabase Auth          (Supabase Auth
   /auth/v1/verify          /auth/v1/verify
   type: "email")           type: "magiclink")
       │                      │
       └──────────┬───────────┘
                  ▼
          Set signed auth cookie
          (somauth, 24h TTL)
```

**Key idea:** The app never touches `SLACK_BOT_TOKEN`. Slack is just a delivery channel — all verification goes through Supabase Auth.

## Email OTP Flow

1. User enters their corporate email (domain-restricted)
2. Backend calls Supabase Auth `POST /auth/v1/otp` with `{ email, create_user: true }`
3. Supabase sends a 6-digit code via custom SMTP
4. User enters code → backend verifies via `POST /auth/v1/verify` with `{ email, token, type: "email" }`
5. Signed `somauth` cookie set (24h)

## Slack OTP Flow (Gatey)

1. User clicks "Login via Slack"
2. Backend calls Gatey Edge Function with `{ project }` → gets email
3. User DMs `@gatey` in Slack: `otp <project>`
4. Gatey generates OTP via `sb.auth.admin.generateLink({ type: "magiclink" })` and sends code in Slack DM
5. User enters code → backend reads email from `soreq` cookie, verifies via `POST /auth/v1/verify` with `{ email, token, type: "magiclink" }`
6. Signed `somauth` cookie set (24h)

## Security

### Signed Cookies
```
base64url(JSON_payload).hex(hmac-sha256(payload, OTP_SIGNING_SECRET))
```

| Cookie | Payload | TTL | Purpose |
|--------|---------|-----|---------|
| `soreq` | `{ iat, rid, p, email }` | 15 min | Request context |
| `somauth` | `{ e, x }` | 24h | Auth session |

### Token Isolation
- `SLACK_BOT_TOKEN` — Supabase secrets only, never in the app
- `OTP_SIGNING_SECRET` — app env var, cookie signing
- `SUPABASE_ANON_KEY` — safe to embed (RLS applies)

### Properties
- HttpOnly + Secure + SameSite=Lax cookies (no XSS/CSRF)
- HMAC with timing-safe comparison (no signature forgery)
- Single-use, time-limited OTP codes (Supabase Auth)
- Email domain restriction (organization-only access)

## File Structure

```
mixed-otp-auth/
├── login.html                 # Login page with dual OTP UI
├── vercel.json                # Routes config
├── api/
│   └── otp/
│       ├── email-request.js   # Email OTP: send code via Supabase Auth
│       ├── email-verify.js    # Email OTP: verify code via Supabase Auth
│       ├── request.js         # Slack OTP: call Gatey, set soreq cookie
│       ├── verify.js          # Slack OTP: verify code via Supabase Auth
│       ├── session.js         # GET: check auth status from somauth cookie
│       └── logout.js          # POST: clear all auth cookies
```

## Setup

### Prerequisites
- Supabase project with Auth enabled
- Custom SMTP configured in Supabase (for email delivery)
- Gatey Edge Function deployed (for Slack OTP)
- Vercel project

### 1. Configure Supabase Auth
- Enable email auth with OTP
- Set up custom SMTP (e.g. Gmail App Password with your corporate sender)

### 2. Register your project in Gatey
In `b2b-slack-otp-v2/index.ts`, add:
- Project ID to `ProjectId` type
- Keywords, title, redirect URL to default maps
- Deploy to Supabase

### 3. Set Vercel Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `OTP_SIGNING_SECRET` | Yes | HMAC secret for cookie signing (min 16 chars) |
| `SUPABASE_ANON_KEY` | No | Fallback hardcoded, but recommended |

**NOT needed:** `SLACK_BOT_TOKEN` (lives in Supabase Function secrets only)

### 4. Customize for your project
- `email-request.js`: change `ALLOWED_DOMAIN` to your corporate domain
- `request.js` / `verify.js`: change `PROJECT` to your project ID
- `login.html`: update branding, hints, Slack DM instructions

### 5. Protect your dashboard
On page load:
```javascript
fetch('/api/otp/session')
  .then(r => r.json())
  .then(d => { if (!d.authenticated) location.href = '/login.html'; });
```

Logout:
```javascript
fetch('/api/otp/logout', { method: 'POST' })
  .then(() => location.href = '/login.html');
```

## Infrastructure

| Component | Role |
|-----------|------|
| **Supabase Auth** | OTP generation + verification (both channels) |
| **Supabase Custom SMTP** | Email delivery |
| **Gatey Edge Function** | Multi-project Slack OTP hub |
| **Vercel Serverless Functions** | API routes |
| **Signed HttpOnly Cookies** | Session management |

## Error Reference

| Error | Meaning |
|-------|---------|
| `otp_request_required` | `soreq` cookie missing — click "Send Code" first |
| `otp_request_expired` | Request expired (>15 min) — request new code |
| `otp_incorrect` | Wrong code or already used |
| `email_domain_not_allowed` | Email not in allowed domain |
| `email_missing_from_request` | Gatey didn't return email |
| `supabase_verify_failed` | Supabase Auth unreachable |
| `project_mismatch` | Cookie has wrong project ID |

## Projects Using This Method

- [Selly Dashboard](https://github.com/22sunje22-sys/selly-dashboard) (`selly`)
- B2B Marketing Dashboard (`b2b`)
- State of the Market (`state`)
- Paid Marketing Dashboard (`paid`)
- Hello Gracey (`gracey`)

## Documentation

Full method description: [Notion — Mixed Email + Slack OTP Authentication Method](https://www.notion.so/325349fa080381fe8634edc5d1b0da0d)
