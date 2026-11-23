// api/keepalive.js
// Free Supabase projects are paused after a period of inactivity. Vercel Cron
// (see vercel.json) calls this once a day so the lead database stays awake
// even in quiet weeks. Returns nothing about the data.

const { call } = require("../lib/supabase");

module.exports = async (req, res) => {
  // If CRON_SECRET is set in Vercel, only Vercel Cron can trigger this.
  const secret = process.env.CRON_SECRET;
  if (secret && req.headers.authorization !== "Bearer " + secret) { res.status(401).json({ ok: false }); return; }
  try {
    await call("GET", "leads?select=id&limit=1");
    res.status(200).json({ ok: true });
  } catch (e) {
    console.error("keepalive failed:", e.message);
    res.status(500).json({ ok: false });
  }
};
