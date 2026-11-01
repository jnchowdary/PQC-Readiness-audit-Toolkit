# Diarka PQC Quick Check — deploy notes (GitHub Pages + Vercel)

GitHub Pages is **static-only** and cannot run the scanner. So:
- **Frontend** `pqc-check.html` → stays on your GitHub Pages site (static).
- **Function** `api/pqc-check.js` → deploys to a free Vercel project that does
  the real TLS handshake. The frontend calls it cross-origin.

(If you'd rather use Netlify for the function instead of Vercel, the equivalent
file is `netlify/functions/pqc-check.js`, also included — same logic.)

## One-time setup (~10 min)
1. Create a repo (or reuse one) containing `api/pqc-check.js` at that exact path.
2. Go to vercel.com → New Project → import that GitHub repo → Deploy.
   No build settings needed; no environment variables; no dependencies.
3. You'll get a URL like `https://your-project.vercel.app`.
   Your endpoint is `https://your-project.vercel.app/api/pqc-check`.
4. Test it directly in a browser:
   `https://your-project.vercel.app/api/pqc-check?domain=diarkaquantum.co.uk`
   You should see JSON with tlsVersion, cert, cipher.

## Wire the frontend
In `pqc-check.html`, set the full cross-origin URL:
```js
const FUNCTION_URL = "https://your-project.vercel.app/api/pqc-check";
```
Commit `pqc-check.html` to your GitHub Pages site. Done — the widget is live.
(Until FUNCTION_URL is set, it runs in clearly-labelled SAMPLE mode.)

## Before promoting it publicly
- **CORS:** in `api/pqc-check.js`, change `Access-Control-Allow-Origin: "*"`
  to your Pages origin (e.g. `https://diarkaquantum.co.uk`).
- **Rate-limit:** add a simple per-IP cap so the endpoint can't be used as a
  free scanning proxy. Vercel has middleware / you can use a KV counter.

## What it reads (and what it doesn't)
Two TLS handshakes run in parallel against `<domain>:443`:

1. **Classical probe**: TLS version, the leaf certificate's public-key type and
   size, its signature family, and the negotiated key-exchange group.
2. **Post-quantum probe**: offers only the hybrid group `X25519MLKEM768`.
   If the server completes the handshake, it supports post-quantum key
   exchange (`pqcKeyExchange: true`). If it refuses, `false`.

If the runtime's OpenSSL lacks ML-KEM (needs OpenSSL 3.5+; `package.json` pins
Node 24.x), or the probe fails for a network reason, `pqcKeyExchange` is `null`
and the page says "not confirmed" instead of claiming the site is vulnerable.

Node does not report the hybrid group after a normal handshake, which is why
the separate probe is needed.

## After each deploy, check
- `?domain=cloudflare.com` should return `pqcKeyExchange: true`.
  If it returns `null`, the Vercel project is on an older Node; set 24.x.
- A typical UK council or law-firm domain should return `false`.
- A made-up domain should return a clean `error`.
