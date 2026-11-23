// api/pqc-check.js  (Vercel serverless function, Node runtime)
//
// Instant quick check: performs real TLS handshakes to <domain>:443 and
// returns the quantum-relevant facts. The scanning logic lives in
// lib/scan.js so api/report.js runs exactly the same checks.
//
// Endpoint: https://<your-project>.vercel.app/api/pqc-check?domain=example.com
// No dependencies. Node 24.x, pinned in package.json.

const { inspect, cleanDomain, validHost, handshake, read, isPrivateAddress, resolvePublic } = require("../lib/scan");
const { applyCors } = require("../lib/http");

module.exports = async (req, res) => {
  applyCors(req, res, "GET, OPTIONS");
  if (req.method === "OPTIONS") { res.status(204).end(); return; }

  const domain = cleanDomain((req.query && req.query.domain) || "");
  if (!validHost(domain)) { res.status(400).json({ error: "Enter a valid public domain" }); return; }

  const result = await inspect(domain);
  res.status(result.error ? 502 : 200).json(result);
};

// Exposed for local testing only.
module.exports._internal = { handshake, read, cleanDomain, validHost, isPrivateAddress, resolvePublic, inspect };
