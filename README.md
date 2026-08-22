# Survival / Ops Site

A small, passcode-gated static site for sharing survival reference info and team
operations content with a few people. No backend, no database, no accounts --
just a static site you deploy to GitHub Pages or Vercel.

## How access works

There are three tiers of passcode:

1. **Per-page codes.** Each page (Survival Basics, Medical/First Aid, Team Roster
   & Comms, Ops Plans & Checklists) has its own code. Someone with only that code
   can see only that page.
2. **Admin code.** One code that unlocks every page.
3. **Rotating code.** A 6-digit code that changes every 30 minutes, generated the
   same way a 2FA app generates codes (TOTP, RFC 6238). It unlocks every page,
   but only for as long as it's valid.

This isn't done with a login form that just hides content with JavaScript --
each page's actual content is AES-256-GCM encrypted, and the encryption key is
only recoverable if you supply a passcode that correctly unwraps it. Someone who
opens dev tools and reads the page source, or downloads the raw files, gets
ciphertext, not your content. See **Security model and its limits** below for
what this does and doesn't protect against.

## Quick start

```bash
npm install
node build.js
```

The first run has no `secrets.json`, so it **bootstraps one for you**: random
per-page passcodes, a random admin passcode, and a random TOTP secret for the
rotating code. It prints nothing sensitive to the terminal -- instead it writes
two files (both gitignored, never commit them):

- `secrets.json` -- machine-readable, used by `build.js` on every future run.
- `CREDENTIALS.txt` -- human-readable, lists every passcode so you can hand them
  out. Also generates `totp-qr.png`, a QR code you can scan into an authenticator
  app (Google Authenticator, Authy, 1Password, etc.) to get the rotating code.

Open `CREDENTIALS.txt` to see what was generated, distribute the relevant codes
to each person, then **delete or secure `CREDENTIALS.txt`** once you've done
that -- it's the one file that lists everything in plaintext.

To preview locally:

```bash
npm run serve
# then open http://localhost:8080
```

## Editing content

Content currently lives directly in `secrets.json` (each page's `content` field
is placeholder HTML -- see `DEFAULT_PAGES` in `build.js` for what it looked like
originally). To change a page's content:

1. Open `secrets.json`.
2. Find the page under `"pages"` and edit its `"content"` field (this is raw
   HTML that gets rendered on the page -- keep it to simple tags like
   `<h2>`, `<p>`, `<ul>`/`<li>`, `<strong>`, etc.).
3. Run `node build.js` again to re-encrypt and rebuild `dist/`.
4. Redeploy (see below).

To add a page or rename one, edit the `pages` array in `secrets.json` (each
entry needs a unique `id`, a `title`, `content`, and a `passcode`), then rebuild.
Since editing is just you, occasionally, there's no in-browser editor -- you (or
you working with Claude) edit `secrets.json` and rebuild.

## Changing passcodes

Edit the relevant `passcode` field in `secrets.json` (a page's own passcode, or
`admin.passcode`), then run `node build.js`. To rotate the TOTP secret, delete
`totp.base32Secret` and let a fresh one bootstrap, or generate your own 20-byte
random value and base32-encode it.

## Deploying

### GitHub Pages (recommended, included)

A workflow at `.github/workflows/rebuild.yml` rebuilds and redeploys the site
automatically every 15 minutes, and on every push to `main`. This is what keeps
the rotating code in sync -- **without periodic rebuilds, the rotating code will
go stale** (the site only ever has the current/adjacent 30-minute window baked
into it at build time).

To use it:

1. Push this repo to GitHub.
2. In **Settings -> Pages**, set the source to "GitHub Actions".
3. In **Settings -> Secrets and variables -> Actions**, add these repository
   secrets (copy the values from your local `CREDENTIALS.txt` / `secrets.json`):
   - `SITE_ADMIN_PASSCODE`
   - `SITE_TOTP_SECRET_BASE32`
   - `SITE_TOTP_PERIOD_SECONDS` (e.g. `1800`)
   - `SITE_TOTP_DIGITS` (e.g. `6`)
   - `SITE_PAGE_SURVIVAL_BASICS_PASSCODE`
   - `SITE_PAGE_MEDICAL_FIRST_AID_PASSCODE`
   - `SITE_PAGE_TEAM_ROSTER_COMMS_PASSCODE`
   - `SITE_PAGE_OPS_PLANS_CHECKLISTS_PASSCODE`
4. **Do not commit `secrets.json`.** In CI, `build.js` reads these environment
   variables directly instead (see the "CI mode" branch in `build.js`).
   If you added/renamed pages, update both the workflow's `env:` block and the
   secret names to match (`SITE_PAGE_<ID-IN-CAPS-WITH-UNDERSCORES>_PASSCODE`).
5. Run the workflow once manually (Actions tab -> "Rebuild and deploy site" ->
   "Run workflow") to do the first deploy.

### Vercel

Vercel doesn't have a free built-in cron, so the simplest approach is to keep
using the GitHub Action above but have it also deploy to Vercel:

1. Create a Vercel project pointed at this repo, with build command
   `node build.js`, output directory `dist`, and install command `npm install`.
2. Add the same environment variables listed above in Vercel's project settings.
3. In Vercel's project settings, create a **Deploy Hook** and copy its URL.
4. Add a step at the end of `.github/workflows/rebuild.yml` that does
   `curl -X POST "$VERCEL_DEPLOY_HOOK_URL"` (store the URL as another repo
   secret). Vercel will then rebuild using its own copy of `build.js` and the
   env vars you set there.

If you don't need the rotating code to stay fresh automatically, you can skip
all of this and just deploy `dist/` as a one-off (`vercel --prod` after running
`node build.js` locally) -- the per-page and admin codes work fine forever;
only the rotating code depends on periodic rebuilds.

### Just a file

If you don't want to deploy anywhere, `node build.js` still produces a working
`dist/` folder. Zip it up, or open `dist/index.html` directly in a browser
(some browsers restrict `fetch()` on `file://` URLs -- if the page seems stuck,
run `npm run serve` and use `http://localhost:8080` instead).

## Security model and its limits

**What this protects against:** someone who has the URL/files but not a valid
passcode cannot read page content, because it's actually encrypted, not just
hidden. Different codes reveal different subsets of pages, as configured.

**What this does NOT protect against:**

- **Passcode strength.** The generated passcodes are reasonably strong by
  default, but this is client-side crypto running entirely in the browser --
  there's no server to rate-limit guesses. Someone who downloads your `dist/`
  files could attempt offline brute-force guessing against the wrapped keys.
  Longer, random passcodes (which is what gets generated by default) make this
  impractical; short/memorable passcodes you pick yourself would not.
- **Anyone who has a valid code can screenshot, copy, print, or otherwise save
  what they see.** This system controls initial access, not what someone does
  with content after they've unlocked it. Don't rely on it for anything where
  that distinction matters.
- **Server-side access logging/revocation.** There's no server, so there's no
  way to see who accessed what, or to instantly revoke one person's code without
  rebuilding and redeploying with a new passcode for them.
- **The rotating code's freshness depends entirely on the periodic rebuild
  running.** If the GitHub Action stops running (disabled, repo archived, quota
  exhausted), the rotating code will eventually stop working until the next
  successful build.

For a small trusted group sharing reference material, this is a reasonable
level of protection. It is not a substitute for a real authentication backend
if your threat model includes a sophisticated or well-resourced attacker.

## Project structure

```
build.js                    Node build script (encrypts content, writes dist/)
lib/
  crypto-node.js             PBKDF2 + AES-GCM helpers (build-time)
  totp.js                    RFC 6238 TOTP implementation (build-time only)
  base32.js                  Base32 encode/decode for the TOTP secret
public/
  index.html, app.js, style.css   The static frontend (copied as-is into dist/)
secrets.json                 Your real passcodes + content (gitignored, bootstrapped)
CREDENTIALS.txt              Human-readable dump of generated codes (gitignored)
totp-qr.png                  QR code for the rotating-code secret (gitignored)
dist/                        Build output -- this is what gets deployed
.github/workflows/rebuild.yml   Periodic rebuild + GitHub Pages deploy
```
