const crypto = require('crypto');

const SUPABASE_URL = 'https://kwftlkfvtglnugxsyjci.supabase.co';
const ALLOWED_DOMAIN = 'platinumlist.net';

const REQ_COOKIE = 'soreq';
const REQ_TTL_SECONDS = 15 * 60;

function json(res, status, body, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 32 * 1024) {
        reject(new Error('payload_too_large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new Error('invalid_json'));
      }
    });
    req.on('error', reject);
  });
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { error: 'method_not_allowed' });

  const secret = process.env.OTP_SIGNING_SECRET;
  if (!secret || secret.length < 16) {
    return json(res, 500, { error: 'OTP_SIGNING_SECRET is missing or too short' });
  }

  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    const status = err.message === 'payload_too_large' ? 413 : 400;
    return json(res, status, { error: err.message });
  }

  const email = String(body.email || '').trim().toLowerCase();
  if (!email || !email.includes('@')) {
    return json(res, 400, { error: 'email_required' });
  }

  // Only allow @platinumlist.net emails
  const domain = email.split('@')[1];
  if (domain !== ALLOWED_DOMAIN) {
    return json(res, 403, { error: 'email_domain_not_allowed', message: `Only @${ALLOWED_DOMAIN} emails are allowed` });
  }

  // Call Supabase Auth signInWithOtp
  try {
    const supabaseKey = process.env.SUPABASE_ANON_KEY || '';
    if (!supabaseKey) return json(res, 500, { error: 'SUPABASE_ANON_KEY missing' });

    const otpResp = await fetch(`${SUPABASE_URL}/auth/v1/otp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': supabaseKey,
      },
      body: JSON.stringify({
        email,
        create_user: true,
      }),
    });

    if (!otpResp.ok) {
      const errBody = await otpResp.json().catch(() => ({}));
      return json(res, 502, { error: 'supabase_otp_failed', detail: errBody.msg || errBody.error_description || `HTTP ${otpResp.status}` });
    }
  } catch (e) {
    return json(res, 502, { error: 'supabase_otp_failed', detail: String(e?.message || e) });
  }

  // Set soreq cookie with email info
  const issuedAt = Date.now();
  const requestId = crypto.randomBytes(12).toString('hex');
  const payloadEncoded = Buffer.from(JSON.stringify({ iat: issuedAt, rid: requestId, p: 'selly-email', email })).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(payloadEncoded).digest('hex');
  const cookie = `${REQ_COOKIE}=${payloadEncoded}.${sig}; Max-Age=${REQ_TTL_SECONDS}; Path=/; HttpOnly; Secure; SameSite=Lax`;

  return json(
    res,
    200,
    {
      ok: true,
      email,
      message: `OTP code sent to ${email}. Check your inbox.`,
    },
    { 'Set-Cookie': cookie },
  );
};
