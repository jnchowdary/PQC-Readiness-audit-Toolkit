// api/estate.js  (Vercel serverless function, Node runtime)
//
// POST /api/estate   body: {"email":"jane@firm.co.uk"}
//   Whole-estate scan of the organisation behind a WORK email address.
//   The domain is always taken from the email (jane@mail.firm.co.uk ->
//   firm.co.uk), never typed in, and the report goes only to that inbox. So
//   nobody can use this to map someone else's estate: typing a stranger's
//   address just sends the stranger their own report.
//
//   Rules:
//   - Work emails only (same rules as the single-domain report).
//   - One estate scan per email. Asking again resends the same report link
//     (max 2 resends, 10 minutes apart), without rescanning.
//   - Max 2 new estate scans per IP per day, and 20 per hour overall: each
//     scan probes up to 40 hosts, so this is the expensive endpoint.
//   - The scan runs inside this request (up to about a minute; maxDuration is
//     set in vercel.json). A failed scan or email saves nothing.
//
// GET /api/estate?t=<token>
//   Returns the stored result for estate.html.

const crypto = require("crypto");
const scan = require("../lib/scan");
const estate = require("../lib/estate");
const rules = require("../lib/lead-rules");
const supabase = require("../lib/supabase");
const mailer = require("../lib/mailer");
const { applyCors, clientIp, jsonBody, hashIp } = require("../lib/http");

const IP_DAILY_LIMIT = 2;
const GLOBAL_HOURLY_LIMIT = 20;
const MAX_RESENDS = 2;
const RESEND_COOLDOWN_MS = 10 * 60 * 1000;
const TOKEN_RE = /^[A-Za-z0-9_-]{20,64}$/;

function makeHandler(deps = {}) {
  const d = {
    runEstateScan: estate.runEstateScan,
    checkWorkEmail: rules.checkWorkEmail,
    estates: supabase.estates,
    send: mailer.send,
    now: () => Date.now(),
    newToken: () => crypto.randomBytes(24).toString("base64url"),
    ...deps,
  };

  const contactEmail = () => process.env.CONTACT_EMAIL || "nageshj@diarkaquantum.co.uk";
  const baseUrl = (req) => (process.env.PUBLIC_BASE_URL || ("https://" + req.headers.host)).replace(/\/$/, "");
  const reportUrl = (req, token) => baseUrl(req) + "/estate.html?t=" + token;
  const fail = (res, status, code, error, extra = {}) => res.status(status).json({ code, error, ...extra });

  async function notifyOwner(args) {
    const to = process.env.NOTIFY_EMAIL;
    if (!to) return;
    try { await d.send({ to, ...mailer.ownerEstateEmail(args) }); }
    catch (e) { console.error("owner notify failed:", e.message); }
  }

  async function sendReport(req, { email, domain, result, token }) {
    const url = reportUrl(req, token);
    const msg = mailer.estateEmail({ domain, result, reportUrl: url, contactEmail: contactEmail() });
    await d.send({ to: email, replyTo: process.env.NOTIFY_EMAIL || contactEmail(), ...msg });
    return url;
  }

  async function getReport(req, res) {
    const token = String((req.query && req.query.t) || "");
    if (!TOKEN_RE.test(token)) return fail(res, 400, "BAD_TOKEN", "This report link isn't valid");
    const row = await d.estates.findByToken(token);
    if (!row) return fail(res, 404, "NOT_FOUND", "We couldn't find this report");
    try {
      await d.estates.update(row.id, {
        report_views: (row.report_views || 0) + 1,
        ...(row.first_viewed_at ? {} : { first_viewed_at: new Date(d.now()).toISOString() }),
      });
    } catch (e) { console.error("view count failed:", e.message); }
    res.status(200).json({
      domain: row.domain, result: row.result, createdAt: row.created_at,
      reference: "DQE-" + token.slice(0, 8).toUpperCase(),
    });
  }

  async function postReport(req, res) {
    const body = jsonBody(req);
    if (body.website) return res.status(200).json({ status: "sent" }); // honeypot

    const em = await d.checkWorkEmail(body.email);
    if (!em.ok) return fail(res, 422, em.code, em.error);
    const { email, emailDomain } = em;
    const domain = estate.orgDomain(emailDomain);
    if (!scan.validHost(domain)) return fail(res, 400, "BAD_DOMAIN", "We couldn't work out your organisation's domain from that email");

    const contact = contactEmail();
    const existing = await d.estates.findByEmail(email);
    if (existing) {
      const last = existing.last_sent_at ? Date.parse(existing.last_sent_at) : 0;
      if (d.now() - last < RESEND_COOLDOWN_MS) {
        return fail(res, 429, "RECENTLY_SENT", "We sent your estate report a few minutes ago. Check your inbox and spam folder.", { contact });
      }
      if ((existing.resend_count || 0) >= MAX_RESENDS) {
        return fail(res, 429, "RESEND_LIMIT", "We've already sent this report several times. Contact us and we'll send it directly.", { contact });
      }
      try {
        const url = await sendReport(req, { email, domain: existing.domain, result: existing.result, token: existing.report_token });
        await d.estates.update(existing.id, { resend_count: (existing.resend_count || 0) + 1, last_sent_at: new Date(d.now()).toISOString() });
        await notifyOwner({ email, domain: existing.domain, result: existing.result, reportUrl: url, kind: "resent" });
      } catch (e) {
        console.error("estate resend failed:", e.message);
        return fail(res, 502, "EMAIL_FAILED", "We couldn't send the email just now. Please try again shortly.");
      }
      return res.status(200).json({ status: "resent", email, domain: existing.domain });
    }

    const ipHash = hashIp(clientIp(req));
    const dayAgo = new Date(d.now() - 24 * 3600 * 1000).toISOString();
    const hourAgo = new Date(d.now() - 3600 * 1000).toISOString();
    if ((await d.estates.countRecentByIp(ipHash, dayAgo)) >= IP_DAILY_LIMIT) {
      return fail(res, 429, "RATE_LIMIT", "Too many estate scans from your network today. Contact us instead.", { contact });
    }
    if ((await d.estates.countSince(hourAgo)) >= GLOBAL_HOURLY_LIMIT) {
      return fail(res, 429, "BUSY", "The estate scanner is busy right now. Please try again in an hour, or contact us.", { contact });
    }

    let result;
    try { result = await d.runEstateScan(domain); }
    catch (e) {
      console.error("estate scan failed:", e.message);
      return fail(res, 502, "SCAN_FAILED", "The scan couldn't complete. Please try again shortly.");
    }

    const token = d.newToken();
    let row;
    try {
      row = await d.estates.insert({
        email, email_domain: emailDomain, domain, report_token: token, result,
        endpoints: result.summary.https, pq_ready: result.summary.pqYes, classical_only: result.summary.pqNo,
        ip_hash: ipHash, last_sent_at: new Date(d.now()).toISOString(),
      });
    } catch (e) {
      if (e.pgCode === "23505") return fail(res, 409, "ALREADY_USED", "An estate report for this email is already on its way. Check your inbox.", { contact });
      throw e;
    }

    try {
      const url = await sendReport(req, { email, domain, result, token });
      await notifyOwner({ email, domain, result, reportUrl: url, kind: "new" });
    } catch (e) {
      console.error("estate email failed:", e.message);
      try { await d.estates.remove(row.id); } catch (e2) { console.error("cleanup failed:", e2.message); }
      return fail(res, 502, "EMAIL_FAILED", "We couldn't send the email just now. Please try again shortly.");
    }

    return res.status(200).json({ status: "sent", email, domain });
  }

  return async function handler(req, res) {
    applyCors(req, res, "GET, POST, OPTIONS");
    if (req.method === "OPTIONS") { res.status(204).end(); return; }
    try {
      if (req.method === "GET") return await getReport(req, res);
      if (req.method === "POST") return await postReport(req, res);
      res.setHeader("Allow", "GET, POST, OPTIONS");
      return fail(res, 405, "METHOD", "Method not allowed");
    } catch (e) {
      console.error("estate error:", e.message);
      if (e.code === "NOT_CONFIGURED") return fail(res, 503, "NOT_CONFIGURED", "The estate scanner isn't set up yet.");
      return fail(res, 500, "SERVER_ERROR", "Something went wrong on our side. Please try again shortly.");
    }
  };
}

module.exports = makeHandler();
module.exports.makeHandler = makeHandler;
