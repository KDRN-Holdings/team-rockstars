# Team Rockstars

Members-only networking chapter portal.

- **Front end** — Cloudflare Pages (`index.html`)
- **API + auth** — Cloudflare Worker (`worker/src/index.js`)
- **Database** — Cloudflare D1 (`worker/schema.sql`)
- **Email** — Resend (password reset / member invites)

```
index.html          the app — Pages serves this at /
config.js           ← the ONE file you edit: paste your Worker URL here
support.js          front-end runtime, do not edit
worker/
  src/index.js      API + authentication
  schema.sql        D1 schema, clean beta state
  wrangler.toml     Worker + D1 config (CLI deploys only)
README.md
```

## The one place you paste the Worker URL

`config.js`, line 13:

```js
window.TR_CONFIG = {
  API_BASE: 'https://tr-api.YOUR-SUBDOMAIN.workers.dev'
};
```

No trailing slash. Leave it empty and the app shows **“Not connected to the
server”** and refuses to sign anyone in — it will never fall back to local or
simulated authentication.

---

## Deployment, in order

### 1. Create the D1 database

Dashboard → **Storage & Databases → D1 SQL Database → Create database**.
Name it `team-rockstars`.

CLI equivalent: `npx wrangler d1 create team-rockstars`

### 2. Put the database ID into the Worker config

Only needed for CLI deploys: copy the `database_id` into `worker/wrangler.toml`.
If you deploy from the dashboard, skip this — you bind D1 in step 7 instead.

### 3. Apply `schema.sql`

Open the `team-rockstars` database → **Console** tab → paste all of
`worker/schema.sql` → **Execute**. If it rejects the whole file, paste it in
blocks, top to bottom.

CLI: `npx wrangler d1 execute team-rockstars --file=./worker/schema.sql --remote`

Verify:

```sql
SELECT email, role, status FROM members;
```

One row: `admin@sculpt-rx.net | admin | active`, with no password set.

### 4. Configure Resend

1. [resend.com](https://resend.com) → sign up.
2. **Domains → Add Domain** → `sculpt-rx.net`.
3. Add the DKIM and SPF records to Cloudflare DNS. Set them to **DNS only**
   (grey cloud), not proxied.
4. Wait for **Verified**. Skipping this means reset emails bounce or land in spam.
5. **API Keys → Create API Key** with sending permission. Copy it now — it is
   shown once.

### 5. Add the Resend key as a Worker secret

After creating the Worker (step 7): **Settings → Variables and Secrets → Add**,
type **Secret**, name `RESEND_API_KEY`.

CLI: `npx wrangler secret put RESEND_API_KEY`

### 6. Set `APP_ORIGIN`

Same panel, type **Text**:

| Name | Value |
| --- | --- |
| `APP_ORIGIN` | your Pages URL, e.g. `https://team-rockstars.pages.dev` — no trailing slash |
| `MAIL_FROM` | `Team Rockstars <noreply@sculpt-rx.net>` — must be on the verified domain |
| `COOKIE_SAMESITE` | `None` |

`APP_ORIGIN` does double duty: it is the CORS allow-list **and** the base for
password-reset links. Getting it wrong is the most common cause of a login that
appears to succeed and then immediately signs out.

### 7. Deploy the Worker

**Dashboard route:** Compute (Workers) → **Workers & Pages → Create → Workers**
→ Hello World → name it `tr-api` → Deploy → **Edit code** → delete the
placeholder → paste all of `worker/src/index.js` → **Deploy**.

Then bind the database: **Settings → Bindings → Add binding → D1 database**.
Variable name **`DB`** (exactly, uppercase), database `team-rockstars`. Deploy.

**CLI route:** `cd worker && npx wrangler deploy`

### 8. Copy the workers.dev URL

On the Worker's overview page, directly under the name **tr-api**, as a
clickable link:

```
https://tr-api.YOUR-SUBDOMAIN.workers.dev
```

Also at **Settings → Domains & Routes**. If it reads **Disabled**, enable it.

Confirm it is alive — paste in a browser:

```
https://tr-api.YOUR-SUBDOMAIN.workers.dev/api/auth/me
```

Expected: `{"ok":false,"error":"Not signed in"}`. That 401 is success.

### 9. Put that URL into `config.js`

Edit `config.js` and set `API_BASE`. This is the only front-end change required.

### 10. Push to GitHub

Commit everything and push.

### 11. Deploy Cloudflare Pages

**Workers & Pages → Create → Pages → Connect to Git** → pick the repo.

- Framework preset: **None**
- Build command: *empty*
- Build output directory: `/`

Deploy. Pages serves `index.html` from the root; every push redeploys.

If your Pages URL differs from what you set in step 6, update `APP_ORIGIN` on the
Worker and redeploy it.

### 12. Test `admin@sculpt-rx.net`

Open the live site. You should see the login form with no error banner. If it
says “Not connected to the server”, step 9 did not deploy.

### 13. Send the first password email

On the live site: **Forgot password** → `admin@sculpt-rx.net` → **Send password
link**.

The “Check your email” panel only appears if the Worker accepted the request. If
nothing arrives, look at **Resend → Logs** first — that shows whether the send
succeeded.

Click the link, choose a password of at least 10 characters.

### 14. Verify login, logout, reset

| Check | Expected |
| --- | --- |
| Correct password | Signs in, lands on Home |
| Wrong password | “That email and password do not match an account.” |
| Logout | Signed out; reload stays signed out |
| Same reset link twice | “This reset link has already been used.” |
| Link after 60 minutes | “This reset link has expired.” |
| Admin dashboard toggle | Visible for the admin only |

Confirm the admin gate is real, not UI-level — sign in as a member, open the
browser console on the live site and run:

```js
fetch(TR_CONFIG.API_BASE + '/api/admin/members', {
  method: 'POST', credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: 'x@y.com', fullName: 'Test' })
}).then(r => r.status)
```

Expected: `403`.

### 15. Verify shared data across two devices

1. As admin, **Admin Dashboard → Members → Add** with a real second email.
2. That member sets a password from their invite email.
3. On phone A submit an opportunity; on phone B it appears in Opportunities.
4. Complete a tag on B; the leaderboard updates on A.
5. Publish an announcement as admin; it appears on both.

Nothing is device-local. The app refetches on window focus, so switching back to
a tab picks up other members' activity.

---

## Security notes

- **Passwords** — PBKDF2-HMAC-SHA256, 100,000 iterations (the maximum Cloudflare
  Workers' WebCrypto allows), fresh 16-byte random salt per password, verified
  server-side with a constant-time compare against the iteration count stored
  with that account. Never stored, logged, or sent anywhere but the Worker.
- **Sessions** — opaque 32-byte token in an `HttpOnly; Secure` cookie,
  unreadable from JavaScript. Only its SHA-256 is stored, so a database leak
  cannot be replayed as a login. Revoked on reset and on deactivation.
- **Reset tokens** — 32 random bytes, SHA-256 stored, 60-minute expiry, single
  use; issuing a new one invalidates outstanding ones. Capped at 4 requests per
  address per hour.
- **Enumeration** — login gives one generic failure message; forgot-password
  responds identically whether or not the address exists.
- **Admin authorisation** — every `/api/admin/*` route re-reads the caller's role
  from D1 per request. The last active admin cannot be demoted or
  self-deactivated.
- **localStorage** — used only for device-local UI preferences via `uiPref()`.
  No application data, no credentials, no session token.

## Optional hardening

The session cookie needs `SameSite=None` while Pages and the Worker are on
different domains. Putting both on your own domain lets it tighten to `Lax`:

1. Pages → **Custom domains** → `app.sculpt-rx.net`
2. Worker → **Settings → Domains & Routes** → `api.sculpt-rx.net`
3. Set `COOKIE_SAMESITE = Lax`, add `COOKIE_DOMAIN = .sculpt-rx.net`, update
   `APP_ORIGIN`, redeploy both.
