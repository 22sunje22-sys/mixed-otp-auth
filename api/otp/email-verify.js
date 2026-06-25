const crypto = require('crypto');

const SUPABASE_URL = process.env.SUPABASE_URL || '';

const AUTH_COOKIE = 'somauth';
const AUTH_TTL_SECONDS = 24 * 60 * 60;
const REQ_COOKIE = 'soreq';
const REQ_TTL_MS = 15 * 60 * 1000;

function json(res, status, body, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(JSON.stringify(body));
}

function b64url(input) { return Buffer.from(input).toString('base64url'); }

function parseCookie(req, key) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === key) return v.join('=');
  }
  return '';
}

function safeEqualHex(a, b) {
  const ab = Buffer.from(a || '', 'hex');
  const bb = Buffer.from(b || '', 'hex');
  if (!ab.length || !bb.length || ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function decodeSignedPayload(raw, secret) {
  const [payloadEncoded, sig] = String(raw || '').split('.');
  if (!payloadEncoded || !sig) return null;
  const expectedSig = crypto.createHmac('sha256', secret).update(payloadEncoded).digest('hex');
  if (!safeEqualHex(sig, expectedSig)) return null;
  try { return JSON.parse(Buffer.from(payloadEncoded, 'base64url').toString('utf8')); }
  catch { return null; }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 32 * 1024) { reject(new Error('payload_too_large')); req.destroy(); }
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try { resolve(JSON.parse(data)); } catch { reject(new Error('invalid_json')); }
    });
    req.on('error', reject);
  });
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { error: 'method_not_allowed' });

  const secret = process.env.OTP_SIGNING_SECRET;
  if (!secret || secret.length < 16) return json(res, 500, { error: 'OTP_SIGNING_SECRET missing or too short' });
  if (!SUPABASE_URL) return json(res, 500, { error: 'SUPABASE_URL missing' });

  let body;
  try { body = await readBody(req); }
  catch (err) { return json(res, err.message === 'payload_too_large' ? 413 : 400, { error: err.message }); }

  const code = String(body.code || '').trim();
  if (!/^\d{6}$/.test(code)) return json(res, 400, { error: 'invalid_code' });

  const reqCookieRaw = parseCookie(req, REQ_COOKIE);
  const reqPayload = decodeSignedPayload(reqCookieRaw, secret);
  if (!reqPayload?.iat) return json(res, 401, { error: 'otp_request_required' });
  if (Date.now() - Number(reqPayload.iat) > REQ_TTL_MS) return json(res, 401, { error: 'otp_request_expired' });
  if (reqPayload.p !== 'selly-email') return json(res, 401, { error: 'project_mismatch' });

  const email = reqPayload.email;
  if (!email) return json(res, 401, { error: 'email_missing_from_request' });

  try {
    const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
    if (!supabaseKey) return json(res, 500, { error: 'SUPABASE_SERVICE_ROLE_KEY missing' });

    const verifyResp = await fetch(`${SUPABASE_URL}/auth/v1/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'apikey': supabaseKey },
      body: JSON.stringify({ email, token: code, type: 'email' }),
    });

    if (!verifyResp.ok) {
      const errBody = await verifyResp.json().catch(() => ({}));
      const detail = errBody.msg || errBody.error_description || `HTTP ${verifyResp.status}`;
      return json(res, 401, { error: 'otp_incorrect', detail });
    }
  } catch (e) {
    return json(res, 502, { error: 'supabase_verify_failed', detail: String(e?.message || e) });
  }

  const authExpiresAt = Date.now() + AUTH_TTL_SECONDS * 1000;
  const authPayload = b64url(JSON.stringify({ e: email, x: authExpiresAt }));
  const authSig = crypto.createHmac('sha256', secret).update(authPayload).digest('hex');
  const authCookie = `${AUTH_COOKIE}=${authPayload}.${authSig}; Max-Age=${AUTH_TTL_SECONDS}; Path=/; HttpOnly; Secure; SameSite=Lax`;
  const clearReq = `${REQ_COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`;

  return json(res, 200, { ok: true, email, expires_at: authExpiresAt }, { 'Set-Cookie': [authCookie, clearReq] });
};
