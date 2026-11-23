// Netlify entry point for api/report.js (same code as on Vercel). See lib/netlify-adapter.js.
const adapt = require("../../lib/netlify-adapter");
exports.handler = adapt(require("../../api/report"));
