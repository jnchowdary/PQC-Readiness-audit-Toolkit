// lib/supabase.js — minimal Supabase REST (PostgREST) client, no dependencies.
//
// Uses the project's SECRET key (sb_secret_...). Supabase requires the new
// keys on the `apikey` header only; they are not JWTs, so they must not go in
// `Authorization: Bearer`. Server-side only: never put this key in a page.

function config() {
  const url = (process.env.SUPABASE_URL || "").replace(/\/$/, "");
  const key = process.env.SUPABASE_SECRET_KEY || "";
  if (!url || !key) throw Object.assign(new Error("Supabase not configured"), { code: "NOT_CONFIGURED" });
  return { url, key };
}

async function call(method, path, { body, prefer } = {}) {
  const { url, key } = config();
  const headers = { apikey: key, "Content-Type": "application/json" };
  if (prefer) headers.Prefer = prefer;
  const r = await fetch(url + "/rest/v1/" + path, {
    method, headers, body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!r.ok) {
    const e = new Error("Supabase " + method + " " + path.split("?")[0] + " failed: " + r.status + " " + (data && data.message || text));
    e.status = r.status;
    e.pgCode = data && data.code; // e.g. "23505" = unique violation
    throw e;
  }
  return data;
}

const q = encodeURIComponent;

const leads = {
  async findByEmail(email) {
    const rows = await call("GET", `leads?email=eq.${q(email)}&select=id,domain,report_token,result,resend_count,last_sent_at&limit=1`);
    return rows[0] || null;
  },
  async findByToken(token) {
    const rows = await call("GET", `leads?report_token=eq.${q(token)}&select=id,domain,result,created_at,report_views,first_viewed_at&limit=1`);
    return rows[0] || null;
  },
  async countRecentByIp(ipHash, sinceISO) {
    const rows = await call("GET", `leads?ip_hash=eq.${q(ipHash)}&created_at=gte.${q(sinceISO)}&select=id&limit=50`);
    return rows.length;
  },
  async insert(row) {
    const rows = await call("POST", "leads", { body: row, prefer: "return=representation" });
    return rows[0];
  },
  async update(id, patch) {
    await call("PATCH", `leads?id=eq.${q(id)}`, { body: patch, prefer: "return=minimal" });
  },
  async remove(id) {
    await call("DELETE", `leads?id=eq.${q(id)}`, { prefer: "return=minimal" });
  },
};

module.exports = { leads, call };
