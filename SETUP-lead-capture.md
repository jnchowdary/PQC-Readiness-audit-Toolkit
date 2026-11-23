# Lead capture setup: Supabase + Resend + report page

About 30 to 40 minutes, most of it waiting for DNS. Nothing here costs money on the free tiers.

## What changed in the repo

```
api/pqc-check.js      now a thin wrapper; behaviour unchanged
api/report.js         NEW  POST = request report, GET = load report
api/keepalive.js      NEW  daily ping so the free Supabase project isn't paused
lib/scan.js           the scanner, moved out of api/pqc-check.js (same logic, plus ISO cert dates)
lib/lead-rules.js     NEW  work-email rules (free webmail, throwaway inboxes, MX check)
lib/supabase.js       NEW  database calls, no npm packages
lib/mailer.js         NEW  Resend calls and both email templates
lib/http.js           NEW  CORS, client IP, body parsing
pqc-check.html        lead box added under the result; "nothing stored" wording fixed
report.html           NEW  the emailed report, with Save as PDF
supabase/schema.sql   NEW  run once in Supabase
vercel.json           NEW  the daily keep-alive cron (merge it if you already have a vercel.json)
package.json          unchanged
```

Copy all of these into the repo that Vercel deploys, keeping the folders exactly as shown.

---

## 1. Supabase (the lead database)

1. Go to supabase.com and create a new project. Choose the **London (eu-west-2)** region so UK leads' data stays in the UK.
2. Open **SQL Editor > New query**, paste in everything from `supabase/schema.sql`, and click **Run**. You should see "Success".
3. Open **Table Editor**. A `leads` table now exists, with RLS enabled.
4. Go to **Project Settings > API Keys**:
   - Copy the **Project URL** (`https://xxxx.supabase.co`). This is `SUPABASE_URL`.
   - Create or copy a **secret key** (`sb_secret_...`). This is `SUPABASE_SECRET_KEY`.
     Never put this key in an HTML page or commit it to GitHub. It only goes into Vercel.

## 2. Resend (sending the email)

1. Sign up at resend.com.
2. Go to **Domains > Add domain**, enter `diarkaquantum.co.uk`, and pick the **Ireland (eu-west-1)** region.
3. Resend now shows a list of DNS records, usually a DKIM TXT record at `resend._domainkey` plus an MX and a TXT record on a `send` subdomain. **Copy them exactly as Resend shows them.**
   These records only use `send.` and `resend._domainkey`, so they don't affect the mailbox you already use at nageshj@diarkaquantum.co.uk.
4. In **IONOS**, go to **Domains & SSL > diarkaquantum.co.uk > DNS > Add record**, and add each record.
   IONOS wants only the host part in the name field (`resend._domainkey`, `send`), not the full domain.
5. Back in Resend, click **Verify**. It can take anywhere from a few minutes to a few hours.
6. Go to **API Keys > Create API key**, choose "Sending access" for this domain, and copy the key (`re_...`). This is `RESEND_API_KEY`.

## 3. Vercel environment variables

Go to **Project > Settings > Environment Variables** and add each of these for Production:

| Name | Value |
|---|---|
| `SUPABASE_URL` | `https://xxxx.supabase.co` |
| `SUPABASE_SECRET_KEY` | `sb_secret_...` |
| `RESEND_API_KEY` | `re_...` |
| `REPORT_FROM` | `Diarka Quantum <reports@diarkaquantum.co.uk>` |
| `NOTIFY_EMAIL` | `nageshj@diarkaquantum.co.uk` (gets a copy of every lead; replies to reports go here) |
| `CONTACT_EMAIL` | `nageshj@diarkaquantum.co.uk` |
| `PUBLIC_BASE_URL` | the address that serves `report.html`, e.g. `https://pqc.diarkaquantum.co.uk` |
| `IP_HASH_SALT` | any long random string (it salts the IP hashes) |
| `CRON_SECRET` | any long random string (only Vercel Cron can call the keep-alive) |

Then **redeploy**. New environment variables only apply to new deployments.

## 4. Privacy notice (before you promote it)

The form links to `https://diarkaquantum.co.uk/privacy`. That page has to exist. It needs to say:

- what you collect: email address, the domain checked and its scan result, and a hashed IP address
- why: to send the report, to follow up about it, and to prevent abuse
- your lawful basis: legitimate interests
- who processes the data: Supabase (database) and Resend (email)
- how long you keep it: for example, 24 months, or until they opt out
- how to opt out or ask for deletion: email nageshj@diarkaquantum.co.uk

If the page lives somewhere else, change `PRIVACY_URL` near the top of `pqc-check.html`.

## 5. Test after deploying

1. Check a domain, then request the report with a **Gmail** address. It should be refused: "use your work email".
2. Request it with a **work email** you control. You should get the report email, and a lead notification should arrive at NOTIFY_EMAIL.
3. Open the report link. The report loads. Click **Save as PDF**: the print dialog opens with a light, A4 layout.
4. In Supabase, open **Table Editor > leads**. Your row is there, and `report_views` is 1.
5. Request again with the **same email and the same domain** within 10 minutes. You should see "we sent it a few minutes ago".
6. Request with the **same email and a different domain**. You should be refused with your contact email.
7. Delete your test row in Supabase so that email address can be used again.

## Rules, and where to change them

All of these live in `api/report.js` (the free-provider list is in `lib/lead-rules.js`):

- one report per email address; the same domain can be resent twice, at least 10 minutes apart (`MAX_RESENDS`, `RESEND_COOLDOWN_MS`)
- at most 3 new reports per IP address per 24 hours (`IP_DAILY_LIMIT`)
- the report is always rescanned on the server, so nobody can send in fake results
- if the scan or the email fails, nothing is stored and the person can try again
- the hidden "website" field catches simple bots

## Working your leads

Use Supabase's **Table Editor > leads**, sorted by `created_at`. The most useful columns are:

- `pqc_key_exchange`: `false` means they have a clear gap
- `report_views` and `first_viewed_at`: whether they actually read the report
- `status` and `notes`: yours to fill in by hand (new, contacted, call booked, proposal, won, lost, not a fit)
- `opted_out`: tick it when someone replies "unsubscribe"
