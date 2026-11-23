// lib/netlify-adapter.js
//
// Runs the existing Vercel-style handlers in api/ (req, res) on Netlify
// Functions, so the scanner, report, estate scan and rate limit code is
// identical on both platforms. Netlify passes an "event"; this builds the
// req/res objects those handlers expect and turns the result back into a
// Netlify response.

function lowerHeaders(h) {
  const out = {};
  for (const [k, v] of Object.entries(h || {})) out[k.toLowerCase()] = v;
  return out;
}

function makeReq(event) {
  const headers = lowerHeaders(event.headers);
  // Netlify's own record of the visitor's address. Use it in preference to
  // X-Forwarded-For, which a client could pad with fake entries.
  const nfIp = headers["x-nf-client-connection-ip"];
  if (nfIp) { headers["x-forwarded-for"] = nfIp; headers["x-real-ip"] = nfIp; }

  let body = event.body || "";
  if (body && event.isBase64Encoded) body = Buffer.from(body, "base64").toString("utf8");
  if (body && /application\/json/i.test(headers["content-type"] || "")) {
    try { body = JSON.parse(body); } catch { /* handlers cope with a raw string */ }
  }
  return {
    method: (event.httpMethod || "GET").toUpperCase(),
    query: event.queryStringParameters || {},
    headers,
    body,
    socket: {},
  };
}

function makeRes() {
  const res = {
    statusCode: 200, headers: {}, body: "",
    setHeader(k, v) { this.headers[k] = String(v); },
    status(code) { this.statusCode = code; return this; },
    json(obj) { this.headers["Content-Type"] = "application/json"; this.body = JSON.stringify(obj); return this; },
    end(text) { if (text != null) this.body = String(text); return this; },
  };
  return res;
}

module.exports = function adapt(handler, prepare) {
  return async (event) => {
    const req = makeReq(event);
    if (prepare) prepare(req, event);
    const res = makeRes();
    await handler(req, res);
    return { statusCode: res.statusCode, headers: res.headers, body: res.body };
  };
};
