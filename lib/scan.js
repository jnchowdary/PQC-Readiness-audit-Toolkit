// lib/scan.js
//
// Shared TLS scanner used by api/pqc-check.js (instant result) and
// api/report.js (emailed report), so both run exactly the same checks.
// Moved here unchanged from api/pqc-check.js, plus ISO certificate dates.
// Files outside api/ are bundled into the functions, not deployed as endpoints.
//
// Performs real TLS handshakes to <domain>:443 and returns the quantum-relevant
// facts the quick check needs. Runs server-side because browsers cannot read a
// third-party site's certificate or negotiated key exchange.
//
// Two handshakes run in parallel:
//   1. Classical probe: offers the normal groups and reads TLS version,
//      certificate, cipher and the negotiated key-exchange group.
//   2. Post-quantum probe: offers ONLY the hybrid group X25519MLKEM768.
//      If the handshake completes, the server supports post-quantum key
//      exchange. If the server rejects it, it does not.
//   If this Node build's OpenSSL lacks ML-KEM (needs OpenSSL 3.5+, i.e. a
//   recent Node 22.x or Node 24), the PQ result is reported as null
//   ("not tested") instead of a false "vulnerable".
//
// Deploy: this file lives at api/pqc-check.js in a repo connected to Vercel.
// Endpoint: https://<your-project>.vercel.app/api/pqc-check?domain=example.com
// No dependencies. Node 22.x (recent) or 24.x; pinned in package.json.

const tls = require("tls");
const crypto = require("crypto");
const dns = require("dns").promises;
const net = require("net");

const PQ_GROUP = "X25519MLKEM768";
const CLASSICAL_GROUPS = "X25519:P-256:P-384";
const TIMEOUT_MS = 6000;

const CURVE_MAP = {
  prime256v1: "P-256", secp256r1: "P-256",
  secp384r1: "P-384", secp521r1: "P-521",
};

function cleanDomain(v) {
  return (v || "").trim().toLowerCase()
    .replace(/^https?:\/\//, "").replace(/[/?#].*$/, "").replace(/:\d+$/, "")
    .replace(/\.$/, "");
}

function validHost(h) {
  if (!h || h.length > 253 || !h.includes(".")) return false;
  if (!/^[a-z0-9.-]+$/.test(h)) return false;
  if (net.isIP(h)) return false; // domains only
  if (/\.(local|internal|lan|localhost)$/.test(h) || h === "localhost") return false;
  return true;
}

// Block private / loopback / link-local targets after DNS resolution,
// so a public-looking domain pointing at an internal address is refused.
function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const v = ip.toLowerCase();
  if (v.startsWith("::ffff:")) return isPrivateAddress(v.slice(7));
  return v === "::" || v === "::1" || v.startsWith("fe80") ||
    v.startsWith("fc") || v.startsWith("fd") || v.startsWith("ff");
}

const NOT_FOUND_CODES = ["ENOTFOUND", "ENODATA", "ENONAME", "NXDOMAIN"];

function friendlyError(message, code) {
  const e = new Error(message); e.code = code; e.friendly = true; return e;
}

// Resolve via the system resolver first; if it fails transiently (e.g. EBUSY,
// EAI_AGAIN on serverless runtimes), fall back to querying DNS directly.
async function resolveAll(host) {
  try {
    return (await dns.lookup(host, { all: true })).map(a => a.address);
  } catch (e) {
    if (NOT_FOUND_CODES.includes(e.code)) throw e;
    const results = await Promise.allSettled([dns.resolve4(host), dns.resolve6(host)]);
    const addrs = results.filter(r => r.status === "fulfilled").flatMap(r => r.value);
    if (addrs.length) return addrs;
    const codes = results.map(r => r.reason && r.reason.code);
    const err = new Error("DNS lookup failed");
    err.code = codes.every(c => NOT_FOUND_CODES.includes(c)) ? "ENOTFOUND" : "EDNS";
    throw err;
  }
}

async function resolvePublic(host) {
  let addrs;
  try { addrs = await resolveAll(host); }
  catch (e) {
    if (NOT_FOUND_CODES.includes(e.code)) throw friendlyError("Domain not found", "ENOTFOUND");
    throw friendlyError("Couldn't look up this domain right now", "EDNS");
  }
  if (!addrs.length) throw friendlyError("Domain not found", "ENOTFOUND");
  if (addrs.some(isPrivateAddress)) {
    throw friendlyError("That domain points to a private address, so it can't be checked", "EPRIVATE");
  }
  // Prefer IPv4: serverless runtimes often lack IPv6 egress.
  return addrs.find(a => net.isIPv4(a)) || addrs[0];
}

// One TLS handshake. Resolves {ok:true, socketInfo} or {ok:false, code}.
function handshake(ip, servername, opts) {
  return new Promise((resolve) => {
    let socket, done = false;
    const finish = (obj) => {
      if (done) return;
      done = true;
      try { socket && socket.destroy(); } catch {}
      resolve(obj);
    };
    try {
      socket = tls.connect({
        host: ip, port: 443, servername,
        rejectUnauthorized: false,
        ALPNProtocols: ["h2", "http/1.1"],
        timeout: TIMEOUT_MS,
        ...opts,
      }, () => {
        try { finish({ ok: true, info: read(socket) }); }
        catch (e) { finish({ ok: false, code: "INSPECT_FAILED", message: e.message }); }
      });
    } catch (e) {
      // Thrown synchronously when this OpenSSL build does not know the group.
      finish({ ok: false, code: "UNSUPPORTED_LOCALLY", message: e.message });
      return;
    }
    socket.on("timeout", () => finish({ ok: false, code: "ETIMEDOUT" }));
    socket.on("error", (e) => finish({ ok: false, code: e.code || "ECONNFAILED", message: e.message }));
  });
}

function toISO(v) {
  if (!v) return null;
  const d = new Date(v);
  return isNaN(d) ? null : d.toISOString();
}

function read(socket) {
  const protocol = socket.getProtocol();
  const cipher = socket.getCipher() || {};
  const eph = (socket.getEphemeralKeyInfo && socket.getEphemeralKeyInfo()) || {};
  const peer = socket.getPeerCertificate(true) || {};

  let keyType = null, keySize = null;
  try {
    if (peer.raw) {
      const x = new crypto.X509Certificate(peer.raw);
      const t = (x.publicKey.asymmetricKeyType || "").toUpperCase();
      const det = x.publicKey.asymmetricKeyDetails || {};
      keyType = t || null;
      if (t === "RSA" || t === "RSA-PSS") keySize = det.modulusLength || peer.bits || null;
      else if (t === "EC") keySize = CURVE_MAP[det.namedCurve] || det.namedCurve || null;
    }
  } catch {}
  if (!keyType) {
    if (peer.nistCurve || peer.asn1Curve) { keyType = "EC"; keySize = CURVE_MAP[peer.nistCurve] || peer.nistCurve || null; }
    else if (peer.modulus) { keyType = "RSA"; keySize = peer.bits || null; }
  }
  const sigAlg = /^RSA/.test(keyType || "") ? "RSA" : keyType === "EC" ? "ECDSA" : (keyType || null);

  // Key exchange: prefer the actual negotiated group when Node reports it.
  const cname = (cipher.name || cipher.standardName || "").toUpperCase();
  let kxFamily;
  if (eph.name) kxFamily = eph.name;                       // e.g. X25519, prime256v1
  else if (protocol === "TLSv1.3") kxFamily = "ECDHE (TLS 1.3)";
  else if (cname.includes("ECDHE")) kxFamily = "ECDHE";
  else if (cname.includes("DHE")) kxFamily = "DHE";
  else if (cname.includes("RSA")) kxFamily = "RSA key transport";
  else kxFamily = cipher.name || null;
  if (CURVE_MAP[kxFamily]) kxFamily = "ECDHE " + CURVE_MAP[kxFamily];

  let issuer = null;
  if (peer.issuer && (peer.issuer.O || peer.issuer.CN)) issuer = peer.issuer.O || peer.issuer.CN;

  return {
    tlsVersion: protocol,
    cert: {
      keyType, keySize, sigAlg, issuer,
      validFrom: peer.valid_from || null, validTo: peer.valid_to || null,
      // ISO versions so the report page can do date maths in any browser.
      validFromISO: toISO(peer.valid_from), validToISO: toISO(peer.valid_to),
    },
    cipher: { name: cipher.name || cipher.standardName || null, kxFamily },
  };
}

const FRIENDLY = {
  ENOTFOUND: "Domain not found",
  EPRIVATE: "That domain points to a private address, so it can't be checked",
  ECONNREFUSED: "Nothing is listening on port 443 for this domain",
  ETIMEDOUT: "Connection timed out",
  ECONNRESET: "The server closed the connection",
};

async function inspectHost(host) {
  const ip = await resolvePublic(host);
  const [classical, pq] = await Promise.all([
    handshake(ip, host, { ecdhCurve: CLASSICAL_GROUPS, minVersion: "TLSv1" }),
    handshake(ip, host, { ecdhCurve: PQ_GROUP, minVersion: "TLSv1.3" }),
  ]);

  if (!classical.ok) {
    throw friendlyError(FRIENDLY[classical.code] || "This domain didn't complete a secure connection on port 443", classical.code);
  }

  // true = server accepted ML-KEM hybrid; false = server refused it;
  // null = couldn't test (this runtime lacks ML-KEM, or a network fault).
  let pqcKeyExchange, pqcNote;
  if (pq.ok) { pqcKeyExchange = true; pqcNote = "Server accepted " + PQ_GROUP; }
  else if (pq.code === "UNSUPPORTED_LOCALLY") { pqcKeyExchange = null; pqcNote = "Scanner runtime lacks ML-KEM (needs OpenSSL 3.5+)"; }
  else if (/HANDSHAKE_FAILURE|NO_SHARED|ILLEGAL_PARAMETER|PROTOCOL_VERSION|UNSUPPORTED_PROTOCOL|ALERT/i.test(pq.code + " " + (pq.message || ""))) {
    pqcKeyExchange = false; pqcNote = "Server refused " + PQ_GROUP;
  } else { pqcKeyExchange = null; pqcNote = "Post-quantum probe inconclusive (" + pq.code + ")"; }

  const info = classical.info;
  if (pqcKeyExchange) info.cipher.kxFamily = PQ_GROUP + " (hybrid)";
  return { domain: host, ...info, pqcKeyExchange, pqcNote };
}

async function inspect(domain) {
  try {
    return await inspectHost(domain);
  } catch (e) {
    // Some organisations only serve TLS on www. Try it once before giving up.
    if (!domain.startsWith("www.") && ["ENOTFOUND", "ECONNREFUSED", "ETIMEDOUT", "ECONNRESET", "EDNS"].includes(e.code)) {
      try { return await inspectHost("www." + domain); } catch {}
    }
    // Never show raw Node error text to visitors.
    return { error: e.friendly ? e.message : "Couldn't connect to this domain" };
  }
}

module.exports = { inspect, inspectHost, handshake, read, cleanDomain, validHost, isPrivateAddress, resolvePublic, PQ_GROUP };
