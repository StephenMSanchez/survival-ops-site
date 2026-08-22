# Survival / Ops Site

A small, passcode-gated static site for sharing survival reference info and team
operations content with a few people. No backend, no database, no accounts --
just a static site you deploy to GitHub Pages or Vercel.

## How access works

There are two ways in:

1. **Username + passcode.** Each person has their own login, and their own
   list of pages they're cleared for (`pages: ["survival"]`), or full access
   (`allPages: true`). Both the username and passcode must be exactly right --
   the decryption key is derived from the two together, not the passcode alone.
   Someone with a valid login always sees every page in the menu, but a page
   they're not cleared for shows an "Access Denied" prompt instead of its
   content when they try to open it.
2. **Rotating code.** A 6-digit code that changes every 30 minutes, generated the
   same way a 2FA app generates codes (TOTP, RFC 6238). Leave the username field
   blank and enter it in the passcode field. It unlocks every page, but only for
   as long as it's valid -- useful as an admin/emergency fallback that isn't
   tied to a specific person's login.

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

The first run has no `secrets.json`, so it **bootstraps one for you**: a random
passcode per default page (username = that page's id), an `admin` user with
`allPages: true`, and a random TOTP secret for the rotating code. It prints
nothing sensitive to the terminal -- instead it writes two files (both
gitignored, never commit them):

- `secrets.json` -- machine-readable, used by `build.js` on every future run.
- `CREDENTIALS.txt` -- human-readable, lists every username/passcode so you can
  hand them out. Also generates `totp-qr.png`, a QR code you can scan into an
  authenticator app (Google Authenticator, Authy, 1Password, etc.) to get the
  rotating code.

Open `CREDENTIALS.txt` to see what was generated, distribute the relevant
logins to each person, then **delete or secure `CREDENTIALS.txt`** once you've
done that -- it's the one file that lists everything in plaintext.

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
entry needs a unique `id`, a `title`, and `subpages`), then rebuild. A page's
`subpages` array is what the tabs at the top of that page are built from --
each needs a unique `id`, `title`, and `content` (raw HTML). Since editing is
just you, occasionally, there's no in-browser editor -- you (or you working
with Claude) edit `secrets.json` and rebuild.

## Managing logins and access

Each entry in the `users` array in `secrets.json` is one login:

```json
{ "username": "alice", "passcode": "...", "pages": ["survival", "tactical"] }
```

- `pages` is the list of page `id`s that user can see the content of. Everyone
  sees every page in the menu regardless; pages outside their `pages` list show
  an "Access Denied" message instead of content.
- Use `"allPages": true` instead of `pages` for a login that should see
  everything (like the bootstrapped `admin` user) -- this way you don't have to
  update every admin-level login when you add a new page.
- To add a person, add a new entry with a new `username` and a random
  `passcode`. To revoke someone, delete their entry (or change their
  `passcode`) and rebuild -- their old login stops working immediately on the
  next deploy.
- To change what an existing person can see, edit their `pages` array and
  rebuild.

To rotate the TOTP secret, delete `totp.base32Secret` and let a fresh one
bootstrap, or generate your own 20-byte random value and base32-encode it.

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
   secrets:
   - `SITE_USERS_JSON` -- the whole `users` array from your local
     `secrets.json`, as a single-line JSON string, e.g.
     `[{"username":"admin","passcode":"...","allPages":true},{"username":"survival","passcode":"...","pages":["survival"]}]`
   - `SITE_TOTP_SECRET_BASE32`
   - `SITE_TOTP_PERIOD_SECONDS` (e.g. `1800`)
   - `SITE_TOTP_DIGITS` (e.g. `6`)
4. **Do not commit `secrets.json`.** In CI, `build.js` reads these environment
   variables directly instead (see the "CI mode" branch in `build.js`); page
   content in CI mode always comes from `DEFAULT_PAGES` in `build.js` itself
   (not `secrets.json`, which isn't in the repo), so if you edit page content
   or add/rename pages, update `DEFAULT_PAGES` in `build.js` too and commit it.
   Whenever you add, remove, or change a user's access, update
   `SITE_USERS_JSON` to match.
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
username+passcode (or a currently-valid rotating code) cannot read page
content, because it's actually encrypted, not just hidden. Different logins
unlock different subsets of pages, as configured per user.

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
- **Server-side access logging.** There's no server, so there's no way to see
  who accessed what, or when. Revoking one person is easier than before, though
  -- delete their entry from `users` (or change their passcode) and rebuild;
  nobody else's login is affected.
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
