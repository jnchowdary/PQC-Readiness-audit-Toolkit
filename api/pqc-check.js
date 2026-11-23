// api/pqc-check.js  (Vercel serverless function, Node runtime)
//
// Instant quick check: performs real TLS handshakes to <domain>:443 and
// returns the quantum-relevant facts. The scanning logic lives in
// lib/scan.js so api/report.js runs exactly the same checks.
//
// Rate limit (so the endpoint can't be used as a free scanning proxy), per
// visitor IP, counted in Supabase (table scan_events, function allow_scan):
//   - 10 checks per 10 minutes
//   - 30 checks per day
//   - 300 checks per hour across all visitors (caps distributed abuse)
// If the database can't be reached, checks are ALLOWED and the failure is
// logged, so a database outage never takes the quick check down.
//
// Endpoint: https://<your-project>.vercel.app/api/pqc-check?domain=example.com
// No dependencies. Node 24.x, pinned in package.json.

const scan = require("../lib/scan");
const supabase = require("../lib/supabase");
const { applyCors, clientIp, hashIp } = require("../lib/http");

const LIMITS = { perTenMinutes: 10, perDay: 30, globalPerHour: 300 };
const CONTACT_EMAIL = process.env.CONTACT_EMAIL || "nageshj@diarkaquantum.co.uk";

const REFUSALS = {
  IP_BURST: { retry: 600, error: "Too many checks in a short time. Please wait 10 minutes and try again." },
  IP_DAILY: { retry: 3600, error: "You've reached today's limit for quick checks. To check more domains, contact us." },
  GLOBAL:   { retry: 300, error: "The checker is busy right now. Please try again in a few minutes." },
};

async function checkLimit(req, domain) {
  if (!supabase.configured()) return "OK";
  try {
    return await supabase.rpc("allow_scan", {
      p_ip: hashIp(clientIp(req)), p_domain: domain,
      p_per_10min: LIMITS.perTenMinutes, p_per_day: LIMITS.perDay, p_global_hour: LIMITS.globalPerHour,
    });
  } catch (e) {
    console.error("rate limit check failed, allowing scan:", e.message);
    return "OK";
  }
}

module.exports = async (req, res) => {
  applyCors(req, res, "GET, OPTIONS");
  if (req.method === "OPTIONS") { res.status(204).end(); return; }

  const domain = scan.cleanDomain((req.query && req.query.domain) || "");
  if (!scan.validHost(domain)) { res.status(400).json({ error: "Enter a valid public domain" }); return; }

  const verdict = await checkLimit(req, domain);
  if (verdict !== "OK") {
    const r = REFUSALS[verdict] || REFUSALS.GLOBAL;
    res.setHeader("Retry-After", String(r.retry));
    res.status(429).json({ code: verdict, error: r.error, contact: CONTACT_EMAIL });
    return;
  }

  const result = await scan.inspect(domain);
  res.status(result.error ? 502 : 200).json(result);
};

// Exposed for local testing only.
module.exports._internal = {
  handshake: scan.handshake, read: scan.read, cleanDomain: scan.cleanDomain, validHost: scan.validHost,
  isPrivateAddress: scan.isPrivateAddress, resolvePublic: scan.resolvePublic, inspect: scan.inspect, LIMITS,
};
