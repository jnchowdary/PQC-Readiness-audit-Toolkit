// lib/http.js — small helpers shared by the API functions.

// Origins allowed to call the API cross-origin. Same-origin calls
// (pages served by this Vercel project) don't need to be listed.
const ALLOWED_ORIGINS = ["https://diarkaquantum.co.uk", "https://pqc.diarkaquantum.co.uk"];

function applyCors(req, res, methods) {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", methods);
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }
  res.setHeader("Vary", "Origin");
  res.setHeader("Cache-Control", "no-store");
}

// Vercel puts the real client IP first in x-forwarded-for, and also in x-real-ip.
function clientIp(req) {
  const xff = (req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return xff || req.headers["x-real-ip"] || (req.socket && req.socket.remoteAddress) || "unknown";
}

// Vercel parses JSON bodies into req.body. Handle a raw string too.
function jsonBody(req) {
  const b = req.body;
  if (!b) return {};
  if (typeof b === "string") { try { return JSON.parse(b); } catch { return {}; } }
  return b;
}

module.exports = { ALLOWED_ORIGINS, applyCors, clientIp, jsonBody };
