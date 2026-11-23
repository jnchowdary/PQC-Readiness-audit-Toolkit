// lib/mailer.js — sends email through Resend's REST API, no dependencies.

function esc(v) {
  return String(v == null ? "" : v).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// One-line verdict, matching the wording on the page.
function headline(result) {
  if (result.pqcKeyExchange === true) return "Post-quantum key exchange in place";
  if (result.pqcKeyExchange === false) return "Not yet quantum-safe";
  return "Post-quantum support not confirmed";
}

async function send({ to, subject, html, text, replyTo }) {
  const key = process.env.RESEND_API_KEY;
  const from = process.env.REPORT_FROM;
  if (!key || !from) throw Object.assign(new Error("Resend not configured"), { code: "NOT_CONFIGURED" });
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: "Bearer " + key, "Content-Type": "application/json" },
    body: JSON.stringify({ from, to: [to], subject, html, text, ...(replyTo ? { reply_to: replyTo } : {}) }),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error("Resend failed: " + r.status + " " + (data.message || "")), { status: r.status });
  return data; // { id }
}

function reportEmail({ domain, result, reportUrl, contactEmail }) {
  const h = headline(result);
  const subject = `Your PQC Quick Check report: ${domain}`;
  const text =
`Your PQC Quick Check report for ${domain} is ready.

Result: ${h}

Open the full report (you can save it as a PDF from the page):
${reportUrl}

The report covers one public endpoint. For other domains, or a full
cryptographic inventory mapped to the NCSC 2028 to 2035 timeline,
reply to this email or write to ${contactEmail}.

Diarka Quantum Ltd, United Kingdom
You received this because you requested this report at our PQC Quick Check.
If you don't want follow-up from us, reply with "unsubscribe".`;

  const html = `<!DOCTYPE html><html><body style="margin:0;background:#f3f5fb;font-family:Helvetica,Arial,sans-serif;color:#0B1230">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f5fb;padding:28px 12px"><tr><td align="center">
<table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border-radius:12px;border:1px solid #dfe4f2">
<tr><td style="background:#0B1230;border-radius:12px 12px 0 0;padding:20px 26px">
  <img src="https://diarkaquantum.co.uk/diarka-logo-header-180w.png" alt="Diarka Quantum" height="34" style="display:block;height:34px">
</td></tr>
<tr><td style="padding:26px">
  <p style="margin:0 0 6px;font-size:12px;letter-spacing:2px;color:#1FB6C9;font-weight:bold;text-transform:uppercase">PQC Quick Check report</p>
  <h1 style="margin:0 0 14px;font-size:21px;line-height:1.3">${esc(domain)}</h1>
  <p style="margin:0 0 18px;font-size:15px;line-height:1.5">Result: <b>${esc(h)}</b></p>
  <p style="margin:0 0 22px;font-size:14px;line-height:1.55;color:#3a4566">Your full report explains each finding, where this endpoint sits against the NCSC 2028, 2031 and 2035 milestones, and the first actions to take. You can save it as a PDF from the page.</p>
  <a href="${esc(reportUrl)}" style="display:inline-block;background:#1FB6C9;color:#0B1230;text-decoration:none;font-weight:bold;padding:12px 22px;border-radius:8px;font-size:15px">Open your report</a>
  <p style="margin:26px 0 0;font-size:13px;line-height:1.55;color:#3a4566">This report covers one public endpoint. For other domains, or a full cryptographic inventory and migration roadmap, reply to this email or write to <a href="mailto:${esc(contactEmail)}" style="color:#3D6FF5">${esc(contactEmail)}</a>.</p>
</td></tr>
<tr><td style="padding:16px 26px;border-top:1px solid #eef1f8;font-size:11.5px;color:#7a86a8;line-height:1.5">
  Diarka Quantum Ltd, United Kingdom. You received this because you requested this report at our PQC Quick Check.
  If you don't want follow-up from us, reply with "unsubscribe".
</td></tr>
</table></td></tr></table></body></html>`;
  return { subject, text, html };
}

function ownerEmail({ email, emailDomain, domain, result, reportUrl, kind }) {
  const h = headline(result);
  const match = domain === emailDomain || domain.endsWith("." + emailDomain) || emailDomain.endsWith("." + domain);
  const subject = `${kind === "resent" ? "Report resent" : "New PQC lead"}: ${email} checked ${domain}`;
  const lines = [
    `Email: ${email}`,
    `Domain checked: ${domain}`,
    `Email matches domain: ${match ? "yes (likely checking their own organisation)" : "no (consultant, supplier, or checking someone else)"}`,
    `Result: ${h}`,
    `TLS: ${result.tlsVersion || "n/a"}`,
    `Key exchange: ${(result.cipher && result.cipher.kxFamily) || "n/a"}`,
    `Certificate: ${result.cert ? (result.cert.keyType || "n/a") + (result.cert.keySize ? "-" + result.cert.keySize : "") : "n/a"}`,
    `Report: ${reportUrl}`,
  ];
  const text = lines.join("\n");
  const html = "<pre style=\"font:13px/1.5 Menlo,Consolas,monospace\">" + esc(text) + "</pre>";
  return { subject, text, html };
}

module.exports = { send, reportEmail, ownerEmail, headline };
