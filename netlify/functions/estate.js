// Netlify entry point for api/estate.js (same code as on Vercel). See lib/netlify-adapter.js.
const adapt = require("../../lib/netlify-adapter");
exports.handler = adapt(require("../../api/estate"));
