const crypto = require('crypto');

const AUTH_COOKIE = 'somauth';

function json(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(JSON.stringify(body));
}

function parseCookie(req, key) {
  const raw = req.headers.cookie || '';
  if (!raw) return '';
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
  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadEncoded, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!payload?.e || !payload?.x) return null;
  if (Date.now() > Number(payload.x)) return null;
  return payload;
}

module.exports = async (req, res) => {
  if (req.method !== 'GET') return json(res, 405, { error: 'method_not_allowed' });

  const secret = process.env.OTP_SIGNING_SECRET;
  if (!secret || secret.length < 16) {
    return json(res, 500, { error: 'OTP_SIGNING_SECRET is missing or too short' });
  }

  const cookieValue = parseCookie(req, AUTH_COOKIE);
  const payload = decodeSignedPayload(cookieValue, secret);
  if (!payload) return json(res, 200, { authenticated: false });

  return json(res, 200, { authenticated: true, ok: true, email: payload.e, expires_at: payload.x });
};
