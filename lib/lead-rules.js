// lib/lead-rules.js — who may request a report.
//
// Work emails only: free webmail and throwaway inboxes are refused, and the
// email's domain must have mail servers (MX records), so made-up company
// domains are refused too.

const dns = require("dns").promises;

// Free consumer webmail. Add to this list if you see others getting through.
const FREE_PROVIDERS = new Set([
  "gmail.com", "googlemail.com", "outlook.com", "outlook.co.uk", "hotmail.com", "hotmail.co.uk",
  "live.com", "live.co.uk", "msn.com", "yahoo.com", "yahoo.co.uk", "ymail.com", "rocketmail.com",
  "icloud.com", "me.com", "mac.com", "aol.com", "aol.co.uk", "proton.me", "protonmail.com", "pm.me",
  "gmx.com", "gmx.co.uk", "gmx.net", "mail.com", "zoho.com", "zohomail.eu", "yandex.com", "yandex.ru",
  "tutanota.com", "tuta.io", "fastmail.com", "hey.com", "qq.com", "163.com", "rediffmail.com",
  // UK ISP consumer mail
  "btinternet.com", "btopenworld.com", "sky.com", "virginmedia.com", "ntlworld.com", "blueyonder.co.uk",
  "talktalk.net", "tiscali.co.uk", "plus.com", "o2.co.uk",
]);

// Disposable / temporary inboxes.
const DISPOSABLE = new Set([
  "mailinator.com", "guerrillamail.com", "guerrillamail.info", "sharklasers.com", "10minutemail.com",
  "temp-mail.org", "tempmail.com", "tempmail.dev", "yopmail.com", "trashmail.com", "getnada.com",
  "dispostable.com", "maildrop.cc", "throwawaymail.com", "fakeinbox.com", "mintemail.com", "emailondeck.com",
]);

const EMAIL_RE = /^[a-z0-9._%+'-]+@([a-z0-9-]+\.)+[a-z]{2,}$/;

function normaliseEmail(v) {
  return String(v || "").trim().toLowerCase();
}

function withTimeout(p, ms) {
  return Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(Object.assign(new Error("timeout"), { code: "ETIMEOUT" })), ms))]);
}

// Returns {ok:true, email, emailDomain} or {ok:false, code, error}.
async function checkWorkEmail(raw, { resolveMx = dns.resolveMx } = {}) {
  const email = normaliseEmail(raw);
  if (!email || email.length > 254 || !EMAIL_RE.test(email)) {
    return { ok: false, code: "BAD_EMAIL", error: "Enter a valid email address" };
  }
  const emailDomain = email.split("@")[1];
  if (FREE_PROVIDERS.has(emailDomain)) {
    return { ok: false, code: "FREE_EMAIL", error: "Please use your work email address, not a personal one" };
  }
  if (DISPOSABLE.has(emailDomain)) {
    return { ok: false, code: "DISPOSABLE_EMAIL", error: "Please use your work email address" };
  }
  try {
    const mx = await withTimeout(resolveMx(emailDomain), 4000);
    if (!mx || !mx.length) throw Object.assign(new Error("no mx"), { code: "ENODATA" });
  } catch (e) {
    if (e.code === "ETIMEOUT") return { ok: true, email, emailDomain, mxUnchecked: true }; // don't punish slow DNS
    return { ok: false, code: "NO_MAIL_DOMAIN", error: "That email domain doesn't receive email. Check the address" };
  }
  return { ok: true, email, emailDomain };
}

module.exports = { checkWorkEmail, normaliseEmail, FREE_PROVIDERS, DISPOSABLE };
