// otp-send — shared sign-in code sender for every site on Supabase project
// kwftlkfvtglnugxsyjci. A site calls it with its service_role key and an email; this
// function mints the 6-digit code with auth/v1/admin/generate_link (which sends nothing)
// and mails it through pl-mailer from e-notifications@platinumlist.net. The code is never
// returned to the caller. The site verifies it as before: POST /auth/v1/verify, type "email".
//
// Why it exists: the pl-mailer key lives only in Supabase Vault (pl_mailer_api_key), so no
// site has to hold it. Before 13.10.2026 sites called /auth/v1/otp and Supabase Auth sent
// the code over a shared Gmail box (marketing@platinumlist.net, ~500/day cap) whose password
// change broke every login on 11.10.2026.
//
// Security:
// - verify_jwt=true: the gateway checks the signature; we additionally require role=service_role.
//   The anon key (public in every browser) can not call this.
// - Recipients default to platinumlist.net; a caller must pass allow:["*"] explicitly to email
//   outsiders, and should only do so after its own whitelist check.
// - Per-address limit 5 codes / 10 min, global daily cap; every call is logged in
//   public.otp_send_log (RLS on, service_role only). Failures alert Telegram.
//
// Request:  POST { email, app, allow?: string[], redirect_to?: string }
// Response: 200 { ok: true } | 4xx/5xx { error }
// Selftest: POST ?selftest=1 (same auth) sends one line to the alert chat and exits.

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const TG_TOKEN = Deno.env.get("TELEGRAM_ALERT_BOT_TOKEN") ?? "";
const TG_CHAT = Deno.env.get("TELEGRAM_ALERT_CHAT_ID") ?? "";

const PER_EMAIL_LIMIT = 5;
const PER_EMAIL_WINDOW_MIN = 10;
const DAILY_CAP = 3000;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const APP_RE = /^[A-Za-z0-9][A-Za-z0-9 .&'()-]{0,59}$/;
const ALLOW_RE = /^(\*|[a-z0-9.-]+\.[a-z]{2,}|[^\s@]+@[a-z0-9.-]+\.[a-z]{2,})$/;

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function jwtRole(req: Request): string | null {
  const auth = req.headers.get("Authorization") ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const part = token.split(".")[1];
  if (!part) return null;
  try {
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(part.length / 4) * 4, "=");
    return JSON.parse(atob(b64)).role ?? null;
  } catch {
    return null;
  }
}

async function rest(path: string, init: RequestInit = {}) {
  const r = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    ...init,
    headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}`, "Content-Type": "application/json", ...(init.headers || {}) },
  });
  if (!r.ok) throw new Error(`rest ${path.split("?")[0]} ${r.status}`);
  const text = await r.text();
  return text ? JSON.parse(text) : null;
}

async function alert(text: string) {
  if (!TG_TOKEN || !TG_CHAT) return;
  await fetch(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: TG_CHAT, text: `otp-send: ${text}` }),
  }).catch(() => {});
}

async function log(app: string, email: string, status: string, detail?: string) {
  await rest("otp_send_log", {
    method: "POST",
    headers: { Prefer: "return=minimal" },
    body: JSON.stringify({ app, email, status, detail: detail ?? null }),
  }).catch(() => {});
}

async function count(filter: string): Promise<number> {
  const r = await fetch(`${SUPABASE_URL}/rest/v1/otp_send_log?select=id&${filter}`, {
    method: "HEAD",
    headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}`, Prefer: "count=exact" },
  });
  return Number((r.headers.get("content-range") ?? "*/0").split("/")[1] || 0);
}

function allowed(email: string, allow: string[]) {
  if (allow.includes("*")) return true;
  const domain = email.split("@")[1];
  return allow.some((a) => a === email || a === domain);
}

function body(app: string, otp: string) {
  const html = `<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;color:#0a1628;">
  <h2 style="font-size:22px;margin:0 0 8px;">Sign in to ${app}</h2>
  <p style="color:#555;font-size:15px;margin:0 0 24px;">Enter the code below on the sign-in page to continue.</p>
  <p style="font-family:monospace;font-size:32px;font-weight:700;letter-spacing:8px;margin:0 0 24px;">${otp}</p>
  <p style="color:#bbb;font-size:12px;border-top:1px solid #eee;padding-top:16px;margin:0;">This code expires in 60 minutes. If you did not request this, you can ignore this email.</p>
</div>`;
  const text = `Sign in to ${app}\n\nYour code: ${otp}\n\nThis code expires in 60 minutes. If you did not request this, you can ignore this email.`;
  return { subject: `Your ${app} sign-in code`, html, text };
}

Deno.serve(async (req) => {
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });
  if (jwtRole(req) !== "service_role") return json(403, { error: "service_role_required" });

  if (new URL(req.url).searchParams.get("selftest") === "1") {
    await alert("selftest ok — alert channel works");
    return json(200, { ok: true, selftest: true });
  }

  let input: { email?: unknown; app?: unknown; allow?: unknown; redirect_to?: unknown };
  try { input = await req.json(); } catch { return json(400, { error: "invalid_json" }); }

  const email = String(input.email ?? "").trim().toLowerCase();
  const app = String(input.app ?? "").trim();
  const allow = Array.isArray(input.allow) && input.allow.length
    ? input.allow.map((a) => String(a).trim().toLowerCase())
    : ["platinumlist.net"];
  const redirectTo = typeof input.redirect_to === "string" && /^https:\/\//.test(input.redirect_to) ? input.redirect_to : undefined;

  if (!EMAIL_RE.test(email) || email.length > 254) return json(400, { error: "email_invalid" });
  if (!APP_RE.test(app)) return json(400, { error: "app_invalid" });
  if (allow.length > 20 || !allow.every((a) => ALLOW_RE.test(a))) return json(400, { error: "allow_invalid" });
  if (!allowed(email, allow)) { await log(app, email, "rejected", "outside allow"); return json(403, { error: "email_not_allowed" }); }

  try {
    const since = new Date(Date.now() - PER_EMAIL_WINDOW_MIN * 60_000).toISOString();
    if (await count(`email=eq.${encodeURIComponent(email)}&status=eq.sent&created_at=gte.${encodeURIComponent(since)}`) >= PER_EMAIL_LIMIT) {
      await log(app, email, "rate_limited");
      return json(429, { error: "too_many_requests" });
    }
    const today = new Date(); today.setUTCHours(0, 0, 0, 0);
    const sentToday = await count(`status=eq.sent&created_at=gte.${encodeURIComponent(today.toISOString())}`);
    if (sentToday >= DAILY_CAP) {
      await log(app, email, "daily_cap");
      if (sentToday === DAILY_CAP) await alert(`daily cap ${DAILY_CAP} reached — sends refused until 00:00 UTC (last app: ${app})`);
      return json(429, { error: "daily_cap_reached" });
    }
  } catch (e) {
    await alert(`otp_send_log unreadable: ${(e as Error).message}`);
    return json(503, { error: "temporarily_unavailable" });
  }

  const g = await fetch(`${SUPABASE_URL}/auth/v1/admin/generate_link`, {
    method: "POST",
    headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ type: "magiclink", email, ...(redirectTo ? { redirect_to: redirectTo } : {}) }),
  });
  const otp = g.ok ? String((await g.json()).email_otp ?? "") : "";
  if (!otp) {
    await log(app, email, "mint_failed", `generate_link ${g.status}`);
    await alert(`generate_link failed ${g.status} (app: ${app})`);
    return json(502, { error: "mint_failed" });
  }

  let cfg: { url: string; key: string } | null = null;
  try {
    const rows = await rest("rpc/otp_send_mailer_config", { method: "POST", body: "{}" });
    cfg = rows?.[0]?.url && rows?.[0]?.key ? rows[0] : null;
  } catch { /* handled below */ }
  if (!cfg) {
    await log(app, email, "send_failed", "vault config missing");
    await alert("pl-mailer config missing in Vault (pl_mailer_url / pl_mailer_api_key)");
    return json(500, { error: "mailer_not_configured" });
  }

  const msg = body(app, otp);
  try {
    const r = await fetch(cfg.url, {
      method: "POST",
      headers: { Authorization: `Bearer ${cfg.key}`, "Content-Type": "application/json" },
      body: JSON.stringify({ to: email, subject: msg.subject, html: msg.html, text: msg.text, fromName: `Platinumlist ${app}`.slice(0, 80), allow }),
      signal: AbortSignal.timeout(15000),
    });
    if (!r.ok) {
      const b = await r.json().catch(() => ({}));
      await log(app, email, "send_failed", `pl-mailer ${r.status} ${b?.error ?? ""}`.trim());
      if (r.status !== 403) await alert(`pl-mailer ${r.status} ${b?.error ?? ""} (app: ${app})`);
      return json(r.status === 403 ? 403 : 502, { error: r.status === 403 ? "email_not_allowed" : "send_failed" });
    }
  } catch (e) {
    await log(app, email, "send_failed", (e as Error).name);
    await alert(`pl-mailer unreachable: ${(e as Error).name} (app: ${app})`);
    return json(504, { error: "send_timeout" });
  }

  await log(app, email, "sent");
  return json(200, { ok: true });
});
