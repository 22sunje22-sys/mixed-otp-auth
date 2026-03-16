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

  const clearAuth = 'somauth=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax';
  const clearOtp = 'sotp=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax';
  const clearReq = 'soreq=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax';

  return json(res, 200, { ok: true }, { 'Set-Cookie': [clearAuth, clearOtp, clearReq] });
};
