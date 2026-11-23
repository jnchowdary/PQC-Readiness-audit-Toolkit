// lib/estate.js — external estate scan.
//
// Given an organisation's domain (always taken from the requester's verified
// work email, never typed in freely), finds its public hostnames and runs the
// same TLS / post-quantum check as the quick check on each one.
//
//  1. Discovery: Certificate Transparency logs (crt.sh) list every hostname
//     that has had a public TLS certificate. If crt.sh is slow or down, a list
//     of common hostnames (www, mail, vpn, portal...) is tried instead.
//  2. Names that no longer resolve in DNS are dropped (CT logs keep old names).
//  3. Up to MAX_HOSTS hosts are scanned in one parallel round, so the whole
//     scan fits inside one serverless call. Worst case is about 26 seconds
//     (crt.sh 8s + DNS 12s + one 6s TLS round), under Netlify's 30-second
//     function limit. Typical scans take a few seconds.
//  4. Mail servers (MX) are listed but not checked: Vercel blocks outbound
//     port 25, so their STARTTLS can't be tested from here.

const dnsp = require("dns").promises;
const scan = require("./scan");

const MAX_HOSTS = 24;
const MAX_PARALLEL = 24;        // all hosts in one round of TLS checks
const MAX_CANDIDATES = 160;     // names checked in DNS (CT logs can list thousands)
const DNS_PARALLEL = 40;        // 160 / 40 = at most 4 rounds of 3s
const CT_TIMEOUT_MS = 8000;
const DNS_TIMEOUT_MS = 3000;

const FALLBACK_NAMES = ["", "www", "mail", "webmail", "owa", "autodiscover", "remote", "vpn", "portal",
  "login", "sso", "secure", "app", "api", "intranet", "extranet", "citrix", "gateway", "shop",
  "blog", "support", "help", "my", "admin", "dev", "staging", "test"];

// Second-level suffixes where the organisation's domain has three labels
// (firm.co.uk, camden.gov.uk). Not a full public-suffix list, but covers the
// UK and the main markets Diarka sells into.
const TWO_LEVEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk", "nhs.uk", "police.uk", "sch.uk", "mod.uk",
  "com.au", "net.au", "org.au", "gov.au", "edu.au", "co.nz", "org.nz", "govt.nz",
  "co.in", "net.in", "org.in", "gov.in", "ac.in", "com.sg", "gov.sg", "co.za", "org.za", "com.br", "co.jp", "co.ie",
]);

function orgDomain(host) {
  const p = String(host || "").toLowerCase().replace(/\.$/, "").split(".");
  if (p.length <= 2) return p.join(".");
  const last2 = p.slice(-2).join(".");
  return (TWO_LEVEL_SUFFIXES.has(last2) ? p.slice(-3) : p.slice(-2)).join(".");
}

function withTimeout(promise, ms, code) {
  let t;
  return Promise.race([
    promise,
    new Promise((_, rej) => { t = setTimeout(() => rej(Object.assign(new Error(code), { code })), ms); }),
  ]).finally(() => clearTimeout(t));
}

// Run fn over items with at most `limit` in flight. Keeps input order.
async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  const worker = async () => { while (next < items.length) { const i = next++; out[i] = await fn(items[i], i); } };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

// Hostnames from Certificate Transparency. Returns a de-duplicated array.
async function ctHostnames(domain, fetchImpl = fetch) {
  const url = "https://crt.sh/?q=" + encodeURIComponent("%." + domain) + "&output=json&exclude=expired";
  const r = await fetchImpl(url, { signal: AbortSignal.timeout(CT_TIMEOUT_MS), headers: { "User-Agent": "DiarkaQuantum-PQC-Check/1.0" } });
  if (!r.ok) throw Object.assign(new Error("crt.sh returned " + r.status), { code: "CT_HTTP" });
  const rows = await r.json();
  const names = new Set();
  for (const row of Array.isArray(rows) ? rows : []) {
    for (let n of String(row.name_value || "").split(/\s+/)) {
      n = n.trim().toLowerCase().replace(/\.$/, "");
      if (n.startsWith("*.")) n = n.slice(2);          // wildcard cert covers the parent name
      if (!n || n.includes("@")) continue;               // skip email-address SANs
      if (n !== domain && !n.endsWith("." + domain)) continue;
      if (!scan.validHost(n)) continue;
      names.add(n);
    }
  }
  return [...names];
}

// Order: apex, www, then shorter names first (usually the important ones).
function prioritise(domain, names) {
  const rank = (n) => (n === domain ? 0 : n === "www." + domain ? 1 : 2);
  return [...new Set(names)].sort((a, b) => rank(a) - rank(b) || a.split(".").length - b.split(".").length || a.localeCompare(b));
}

async function resolves(host, lookup) {
  try { const a = await withTimeout(lookup(host, { all: true }), DNS_TIMEOUT_MS, "DNS_TIMEOUT"); return a.length > 0; }
  catch { return false; }
}

const ISSUE_TEXT = {
  PQ_NO: "Classical key exchange only",
  PQ_UNKNOWN: "Post-quantum support not confirmed",
  TLS_OLD: "Deprecated TLS version",
  TLS_12: "TLS 1.2 (post-quantum needs TLS 1.3)",
  RSA_WEAK: "RSA key below 2048 bits",
  CERT_EXPIRED: "Certificate expired",
  CERT_SOON: "Certificate expires within 30 days",
};

function hostIssues(r, now) {
  const issues = [];
  if (r.pqcKeyExchange === false) issues.push("PQ_NO");
  if (r.pqcKeyExchange == null) issues.push("PQ_UNKNOWN");
  if (/^TLSv1(\.0|\.1)?$/.test(r.tlsVersion || "")) issues.push("TLS_OLD");
  else if (r.tlsVersion === "TLSv1.2") issues.push("TLS_12");
  const c = r.cert || {};
  if (/^RSA/.test(c.keyType || "") && c.keySize && c.keySize < 2048) issues.push("RSA_WEAK");
  const exp = c.validToISO ? Date.parse(c.validToISO) : NaN;
  if (!isNaN(exp)) {
    if (exp < now) issues.push("CERT_EXPIRED");
    else if (exp - now < 30 * 86400000) issues.push("CERT_SOON");
  }
  return issues;
}

async function scanOne(host, inspectHost, now) {
  try {
    const r = await inspectHost(host);
    return {
      host, status: "ok",
      tlsVersion: r.tlsVersion || null,
      kx: (r.cipher && (r.cipher.kxFamily || r.cipher.name)) || null,
      pq: r.pqcKeyExchange,
      certKey: r.cert && r.cert.keyType ? r.cert.keyType + (r.cert.keySize ? "-" + r.cert.keySize : "") : null,
      issuer: (r.cert && r.cert.issuer) || null,
      certExpiry: (r.cert && r.cert.validToISO) || null,
      issues: hostIssues(r, now),
    };
  } catch (e) {
    if (e.code === "EPRIVATE") return { host, status: "private" };
    return { host, status: "no_https", reason: e.friendly ? e.message : "No secure connection on port 443" };
  }
}

async function runEstateScan(domain, deps = {}) {
  const d = {
    fetch: deps.fetch || fetch,
    lookup: deps.lookup || dnsp.lookup,
    resolveMx: deps.resolveMx || dnsp.resolveMx,
    inspectHost: deps.inspectHost || scan.inspectHost,
    now: deps.now || Date.now,
  };
  const started = d.now();

  // 1. Discover
  let source = "ct", ctError = null, names;
  try {
    names = await ctHostnames(domain, d.fetch);
  } catch (e) {
    source = "fallback"; ctError = e.code || e.name || "CT_FAILED"; names = [];
  }
  const candidates = prioritise(domain, [domain, "www." + domain, ...names,
    ...(source === "fallback" ? FALLBACK_NAMES.map(n => (n ? n + "." + domain : domain)) : [])]);

  // 2. Keep names that still exist in DNS
  const checked = candidates.slice(0, MAX_CANDIDATES);
  const alive = await mapLimit(checked, DNS_PARALLEL, async (h) => ((await resolves(h, d.lookup)) ? h : null));
  const live = alive.filter(Boolean);
  const toScan = live.slice(0, MAX_HOSTS);
  // Not scanned: live names over the host cap, plus names never DNS-checked
  // because the CT list was longer than MAX_CANDIDATES.
  const overCap = [...live.slice(MAX_HOSTS), ...candidates.slice(MAX_CANDIDATES)];

  // 3. Scan + mail servers (in parallel)
  const now = d.now();
  const [hosts, mx] = await Promise.all([
    mapLimit(toScan, MAX_PARALLEL, (h) => scanOne(h, d.inspectHost, now)),
    withTimeout(d.resolveMx(domain), DNS_TIMEOUT_MS, "DNS_TIMEOUT")
      .then(list => list.sort((a, b) => a.priority - b.priority).map(m => m.exchange.toLowerCase()))
      .catch(() => []),
  ]);

  // 4. Summarise
  const ok = hosts.filter(h => h.status === "ok");
  const has = (code) => ok.filter(h => h.issues.includes(code)).length;
  const summary = {
    discovered: candidates.length,
    live: live.length,
    scanned: toScan.length,
    https: ok.length,
    pqYes: ok.filter(h => h.pq === true).length,
    pqNo: has("PQ_NO"),
    pqUnknown: has("PQ_UNKNOWN"),
    tlsOld: has("TLS_OLD"),
    tls12: has("TLS_12"),
    rsaWeak: has("RSA_WEAK"),
    certExpired: has("CERT_EXPIRED"),
    certSoon: has("CERT_SOON"),
    noHttps: hosts.filter(h => h.status === "no_https").length,
    privateAddr: hosts.filter(h => h.status === "private").length,
    overCap: overCap.length,
    mailServers: mx.length,
  };

  return {
    domain, source, ctError, summary,
    hosts, overCapSample: overCap.slice(0, 25), mx,
    durationMs: d.now() - started,
    limits: { maxHosts: MAX_HOSTS },
  };
}

module.exports = { MAX_CANDIDATES, runEstateScan, orgDomain, ctHostnames, prioritise, hostIssues, mapLimit, ISSUE_TEXT, MAX_HOSTS };
