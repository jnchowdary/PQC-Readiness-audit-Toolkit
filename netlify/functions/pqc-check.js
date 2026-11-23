// Netlify entry point for api/pqc-check.js (same code as on Vercel). See lib/netlify-adapter.js.
const adapt = require("../../lib/netlify-adapter");
exports.handler = adapt(require("../../api/pqc-check"));
