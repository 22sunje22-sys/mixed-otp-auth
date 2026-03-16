const crypto = require('crypto');

const PROJECT = 'selly';

const REQ_COOKIE = 'soreq';
const REQ_TTL_SECONDS = 15 * 60;
const DEFAULT_GATEY_OTP_URL = 'https://kwftlkfvtglnugxsyjci.supabase.co/functions/v1/b2b-slack-otp-v2';

function json(res, status, body, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(JSON.stringify(body));
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { error: 'method_not_allowed' });

  const secret = process.env.OTP_SIGNING_SECRET;
  if (!secret || secret.length < 16) {
    return json(res, 500, { error: 'OTP_SIGNING_SECRET is missing or too short' });
  }

  // Call Gatey Edge Function — it returns email + tells user to DM @gatey
  const gateyUrl = process.env.SLACK_OTP_FUNCTION_URL || DEFAULT_GATEY_OTP_URL;
  let gateyEmail = '';
  let gateyStatus = 'ok';
  let gateyError = '';
  try {
    const otpResp = await fetch(gateyUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
      body: JSON.stringify({ project: PROJECT }),
    });
    const otpJson = await otpResp.json().catch(() => ({}));
    if (!otpResp.ok || otpJson?.error) {
      gateyStatus = 'degraded';
      gateyError = String(otpJson?.error || `HTTP ${otpResp.status}`);
    } else {
      gateyEmail = otpJson?.email || '';
    }
  } catch (e) {
    gateyStatus = 'degraded';
    gateyError = String(e?.message || e || 'unknown_error');
  }

  // Store email in soreq cookie so verify can use it with Supabase Auth
  const issuedAt = Date.now();
  const requestId = crypto.randomBytes(12).toString('hex');
  const payloadEncoded = Buffer.from(JSON.stringify({
    iat: issuedAt,
    rid: requestId,
    p: PROJECT,
    email: gateyEmail,
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(payloadEncoded).digest('hex');
  const cookie = `${REQ_COOKIE}=${payloadEncoded}.${sig}; Max-Age=${REQ_TTL_SECONDS}; Path=/; HttpOnly; Secure; SameSite=Lax`;

  return json(
    res,
    200,
    {
      ok: true,
      project: PROJECT,
      request_id: requestId,
      issued_at: issuedAt,
      gatey_status: gateyStatus,
      gatey_error: gateyError,
      message: `Open @gatey in Slack, send "otp ${PROJECT}", then paste the code here.`,
    },
    { 'Set-Cookie': cookie },
  );
};
