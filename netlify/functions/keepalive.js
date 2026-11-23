// Netlify scheduled function (schedule in netlify.toml): runs api/keepalive.js
// once a day to keep the free Supabase project awake and delete quick-check
// records older than 30 days. Scheduled functions can't be called from the
// public web on Netlify, so the scheduler is the only caller; the CRON_SECRET
// header the shared code checks is supplied here.
const adapt = require("../../lib/netlify-adapter");
exports.handler = adapt(require("../../api/keepalive"), (req) => {
  if (process.env.CRON_SECRET) req.headers.authorization = "Bearer " + process.env.CRON_SECRET;
});
