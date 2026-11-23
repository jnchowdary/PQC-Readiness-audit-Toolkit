# Moving the PQC Quick Check from Vercel to Netlify (free plan)

Why: Vercel's free Hobby plan forbids commercial use; Netlify's Free plan allows it.

What runs where:
- `netlify/functions/*.js` are thin wrappers. They run the SAME handlers in
  `api/` through `lib/netlify-adapter.js`, so the scanner, reports, estate
  scan and rate limit are identical on both platforms.
- `netlify.toml` publishes only `pqc-check.html`, `report.html` and
  `estate.html` (from `dist/`), routes `/api/*` to the functions, serves the
  quick check at `/`, and runs the keep-alive daily at 06:17 UTC.
- Estate scans are sized for Netlify's 30-second function limit: up to 24
  hosts, worst case about 26 seconds.

Credits (Free plan: 300 a month, hard limit):
- Each production deploy (every push to `main`) costs 15 credits.
  Batch changes and push once.
- Function time, requests and bandwidth for this tool cost very little.

Environment variables to set in Netlify (Project configuration > Environment
variables), same names and values as on Vercel:
- Secret: SUPABASE_SECRET_KEY, RESEND_API_KEY, IP_HASH_SALT, CRON_SECRET
- Plain: SUPABASE_URL, REPORT_FROM, NOTIFY_EMAIL, CONTACT_EMAIL, PUBLIC_BASE_URL
