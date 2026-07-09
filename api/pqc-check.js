// api/pqc-check.js  —  Vercel serverless function (Node runtime)
//
// Performs a real TLS handshake to <domain>:443 and returns the quantum-relevant
// facts the quick-check needs. Runs server-side because browsers (and GitHub
// Pages, which is static-only) cannot read a third-party site's certificate or
// negotiated cipher.
//
// Deploy: put this file at `api/pqc-check.js` in a repo connected to Vercel.
// It becomes https://<your-project>.vercel.app/api/pqc-check?domain=example.com
// No dependencies. Node 18+.

const tls = require("tls");
const crypto = require("crypto");

const CURVE_MAP = {
  prime256v1: "P-256", secp256r1: "P-256",
  secp384r1: "P-384", secp521r1: "P-521",
};

function cleanDomain(v) {
  return (v || "").trim().toLowerCase()
    .replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "");
}

function validHost(h) {
  if (!h || h.length > 253 || !h.includes(".")) return false;
  if (!/^[a-z0-9.-]+$/.test(h)) return false;
  if (/^(localhost|127\.|10\.|192\.168\.|0\.|169\.254\.)/.test(h)) return false;
  if (/\.(local|internal|lan)$/.test(h)) return false;
  return true;
}

function inspect(domain) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (obj) => { if (!done) { done = true; try { socket.destroy(); } catch {} resolve(obj); } };

    const socket = tls.connect({
      host: domain, port: 443, servername: domain,
      rejectUnauthorized: false,
      ALPNProtocols: ["h2", "http/1.1"],
      timeout: 8000,
    }, () => {
      try {
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher() || {};
        const peer = socket.getPeerCertificate(true) || {};

        let keyType = null, keySize = null;
        try {
          if (peer.raw) {
            const x = new crypto.X509Certificate(peer.raw);
            const t = (x.publicKey.asymmetricKeyType || "").toUpperCase();
            const det = x.publicKey.asymmetricKeyDetails || {};
            keyType = t || null;
            if (t === "RSA") keySize = det.modulusLength || peer.bits || null;
            else if (t === "EC") keySize = CURVE_MAP[det.namedCurve] || det.namedCurve || null;
          }
        } catch {}
        if (!keyType) {
          if (peer.nistCurve || peer.asn1Curve) { keyType = "EC"; keySize = CURVE_MAP[peer.nistCurve] || peer.nistCurve || null; }
          else if (peer.modulus) { keyType = "RSA"; keySize = peer.bits || null; }
        }

        const sigAlg = keyType === "RSA" ? "RSA" : keyType === "EC" ? "ECDSA" : (keyType || "unknown");

        let kxFamily;
        const cname = (cipher.name || cipher.standardName || "").toUpperCase();
        if (protocol === "TLSv1.3") kxFamily = "ECDHE (TLS 1.3)";
        else if (cname.includes("ECDHE")) kxFamily = "ECDHE";
        else if (cname.includes("DHE")) kxFamily = "DHE";
        else if (cname.includes("RSA")) kxFamily = "RSA key transport";
        else kxFamily = cipher.name || "unknown";

        let issuer = null;
        if (peer.issuer && (peer.issuer.O || peer.issuer.CN)) issuer = peer.issuer.O || peer.issuer.CN;

        finish({
          domain,
          tlsVersion: protocol,
          cert: { keyType, keySize, sigAlg, issuer, validFrom: peer.valid_from || null, validTo: peer.valid_to || null },
          cipher: { name: cipher.name || cipher.standardName || null, kxFamily },
          pqcKeyExchange: false, // Node TLS does not expose the negotiated group; full audit only.
          note: "Quick check: certificate + protocol + cipher family only.",
        });
      } catch (e) {
        finish({ error: "Inspection failed: " + e.message });
      }
    });

    socket.on("timeout", () => finish({ error: "Connection timed out" }));
    socket.on("error", (e) => finish({ error: e.code || e.message || "Connection failed" }));
  });
}

module.exports = async (req, res) => {
  // Tighten this to your GitHub Pages origin in production
  // e.g. "https://diarkaquantum.co.uk" or "https://<user>.github.io"
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Cache-Control", "no-store");
  if (req.method === "OPTIONS") { res.status(204).end(); return; }

  const domain = cleanDomain((req.query && req.query.domain) || "");
  if (!validHost(domain)) { res.status(400).json({ error: "Enter a valid public domain" }); return; }

  const result = await inspect(domain);
  res.status(result.error ? 502 : 200).json(result);
};
