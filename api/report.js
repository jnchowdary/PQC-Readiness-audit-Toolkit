// api/report.js  (Vercel serverless function, Node runtime)
//
// POST /api/report   body: {"email":"jane@firm.co.uk","domain":"firm.co.uk"}
//   Lead capture. Checks the email is a work address, rescans the domain
//   SERVER-SIDE (never trusts results sent from the browser), stores the lead
//   in Supabase and emails a private report link via Resend. Also emails you.
//
//   Rules:
//   - Work emails only (no free webmail, no throwaway inboxes, must have MX).
//   - One report per email address. Asking again for the SAME domain resends
//     the same report link (max 2 resends, 10 minutes apart), so a report lost
//     in spam doesn't lose the lead. Asking for a DIFFERENT domain is refused
//     with "contact us".
//   - Max 3 new reports per IP address per 24 hours.
//
// GET /api/report?t=<token>
//   Returns the stored result for the report page. The token is a long random
//   value only sent to the requester's inbox.
//
// Environment variables (Vercel > Project > Settings > Environment Variables):
//   SUPABASE_URL, SUPABASE_SECRET_KEY, RESEND_API_KEY, REPORT_FROM,
//   NOTIFY_EMAIL, PUBLIC_BASE_URL, IP_HASH_SALT, CONTACT_EMAIL (optional)

const crypto = require("crypto");
const scan = require("../lib/scan");
const rules = require("../lib/lead-rules");
const supabase = require("../lib/supabase");
const mailer = require("../lib/mailer");
const { applyCors, clientIp, jsonBody } = require("../lib/http");

const IP_DAILY_LIMIT = 3;
const MAX_RESENDS = 2;
const RESEND_COOLDOWN_MS = 10 * 60 * 1000;
const TOKEN_RE = /^[A-Za-z0-9_-]{20,64}$/;

function makeHandler(deps = {}) {
  const d = {
    inspect: scan.inspect,
    checkWorkEmail: rules.checkWorkEmail,
    leads: supabase.leads,
    send: mailer.send,
    now: () => Date.now(),
    newToken: () => crypto.randomBytes(24).toString("base64url"),
    ...deps,
  };

  const contactEmail = () => process.env.CONTACT_EMAIL || "nageshj@diarkaquantum.co.uk";
  const baseUrl = (req) => (process.env.PUBLIC_BASE_URL || ("https://" + req.headers.host)).replace(/\/$/, "");
  const reportUrl = (req, token) => baseUrl(req) + "/report.html?t=" + token;
  const hashIp = (ip) => crypto.createHash("sha256").update((process.env.IP_HASH_SALT || "diarka-pqc") + "|" + ip).digest("hex").slice(0, 32);

  const fail = (res, status, code, error, extra = {}) => res.status(status).json({ code, error, ...extra });

  async function notifyOwner(args) {
    const to = process.env.NOTIFY_EMAIL;
    if (!to) return;
    try { await d.send({ to, ...mailer.ownerEmail(args) }); }
    catch (e) { console.error("owner notify failed:", e.message); } // never block the visitor on this
  }

  async function sendReport(req, { email, domain, result, token }) {
    const url = reportUrl(req, token);
    const msg = mailer.reportEmail({ domain, result, reportUrl: url, contactEmail: contactEmail() });
    await d.send({ to: email, replyTo: process.env.NOTIFY_EMAIL || contactEmail(), ...msg });
    return url;
  }

  // ---------- GET: serve a stored report ----------
  async function getReport(req, res) {
    const token = String((req.query && req.query.t) || "");
    if (!TOKEN_RE.test(token)) return fail(res, 400, "BAD_TOKEN", "This report link isn't valid");
    const row = await d.leads.findByToken(token);
    if (!row) return fail(res, 404, "NOT_FOUND", "We couldn't find this report");
    // Record that the lead opened it: a useful follow-up signal. Best effort.
    try {
      await d.leads.update(row.id, {
        report_views: (row.report_views || 0) + 1,
        ...(row.first_viewed_at ? {} : { first_viewed_at: new Date(d.now()).toISOString() }),
      });
    } catch (e) { console.error("view count failed:", e.message); }
    res.status(200).json({
      domain: row.domain,
      result: row.result,
      createdAt: row.created_at,
      reference: "DQ-" + token.slice(0, 8).toUpperCase(),
    });
  }

  // ---------- POST: request a report ----------
  async function postReport(req, res) {
    const body = jsonBody(req);

    // Honeypot: a hidden field real people never fill in. Bots do.
    if (body.website) return res.status(200).json({ status: "sent" });

    const domain = scan.cleanDomain(body.domain || "");
    if (!scan.validHost(domain)) return fail(res, 400, "BAD_DOMAIN", "Enter a valid public domain");

    const em = await d.checkWorkEmail(body.email);
    if (!em.ok) return fail(res, 422, em.code, em.error);
    const { email, emailDomain } = em;

    const contact = contactEmail();
    const existing = await d.leads.findByEmail(email);

    if (existing) {
      if (existing.domain !== domain) {
        return fail(res, 409, "ALREADY_USED",
          "This email address has already received its free report. To check another domain, contact us.",
          { contact });
      }
      // Same email, same domain: they probably didn't get the first email.
      const last = existing.last_sent_at ? Date.parse(existing.last_sent_at) : 0;
      if (d.now() - last < RESEND_COOLDOWN_MS) {
        return fail(res, 429, "RECENTLY_SENT",
          "We sent your report a few minutes ago. Check your inbox and spam folder.", { contact });
      }
      if ((existing.resend_count || 0) >= MAX_RESENDS) {
        return fail(res, 429, "RESEND_LIMIT",
          "We've already sent this report several times. Contact us and we'll send it directly.", { contact });
      }
      const row = existing;
      try {
        const url = await sendReport(req, { email, domain, result: row.result, token: existing.report_token });
        await d.leads.update(existing.id, {
          resend_count: (existing.resend_count || 0) + 1,
          last_sent_at: new Date(d.now()).toISOString(),
        });
        await notifyOwner({ email, emailDomain, domain, result: row.result, reportUrl: url, kind: "resent" });
      } catch (e) {
        console.error("resend failed:", e.message);
        return fail(res, 502, "EMAIL_FAILED", "We couldn't send the email just now. Please try again shortly.");
      }
      return res.status(200).json({ status: "resent", email });
    }

    // New lead: per-IP cap on new reports.
    const ipHash = hashIp(clientIp(req));
    const since = new Date(d.now() - 24 * 3600 * 1000).toISOString();
    if ((await d.leads.countRecentByIp(ipHash, since)) >= IP_DAILY_LIMIT) {
      return fail(res, 429, "RATE_LIMIT", "Too many report requests from your network today. Contact us instead.", { contact });
    }

    // Rescan server-side. A failed scan doesn't use up their one report.
    const result = await d.inspect(domain);
    if (result.error) {
      return fail(res, 502, "SCAN_FAILED", result.error + ". Check the domain serves HTTPS, then try again.");
    }

    const token = d.newToken();
    let row;
    try {
      row = await d.leads.insert({
        email, email_domain: emailDomain, domain: result.domain || domain,
        report_token: token, result,
        pqc_key_exchange: result.pqcKeyExchange,
        ip_hash: ipHash,
        last_sent_at: new Date(d.now()).toISOString(),
      });
    } catch (e) {
      if (e.pgCode === "23505") { // two requests raced with the same email
        return fail(res, 409, "ALREADY_USED", "A report for this email address is already on its way. Check your inbox.", { contact });
      }
      throw e;
    }

    try {
      const url = await sendReport(req, { email, domain: row.domain, result, token });
      await notifyOwner({ email, emailDomain, domain: row.domain, result, reportUrl: url, kind: "new" });
    } catch (e) {
      // Email didn't go: remove the lead so their one report isn't used up.
      console.error("report email failed:", e.message);
      try { await d.leads.remove(row.id); } catch (e2) { console.error("cleanup failed:", e2.message); }
      return fail(res, 502, "EMAIL_FAILED", "We couldn't send the email just now. Please try again shortly.");
    }

    return res.status(200).json({ status: "sent", email });
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
      console.error("report error:", e.message);
      if (e.code === "NOT_CONFIGURED") return fail(res, 503, "NOT_CONFIGURED", "The report service isn't set up yet.");
      return fail(res, 500, "SERVER_ERROR", "Something went wrong on our side. Please try again shortly.");
    }
  };
}

module.exports = makeHandler();
module.exports.makeHandler = makeHandler;
