// api/keepalive.js
// Runs once a day via Vercel Cron (see vercel.json). Two jobs:
//  1. Keeps the free Supabase project awake: free projects are paused after a
//     period of inactivity, which would silently break the report form.
//  2. Deletes quick-check records (scan_events) older than 30 days, so the
//     rate-limit table stays small and nothing is kept longer than needed.
// Returns nothing about the data.

const { call } = require("../lib/supabase");

module.exports = async (req, res) => {
  // If CRON_SECRET is set in Vercel, only Vercel Cron can trigger this.
  const secret = process.env.CRON_SECRET;
  if (secret && req.headers.authorization !== "Bearer " + secret) { res.status(401).json({ ok: false }); return; }
  try {
    await call("GET", "leads?select=id&limit=1");
    const cutoff = new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString();
    try {
      await call("DELETE", "scan_events?created_at=lt." + encodeURIComponent(cutoff), { prefer: "return=minimal" });
    } catch (e) {
      console.error("scan_events cleanup failed:", e.message); // table missing until rate-limit.sql is run
    }
    res.status(200).json({ ok: true });
  } catch (e) {
    console.error("keepalive failed:", e.message);
    res.status(500).json({ ok: false });
  }
};
