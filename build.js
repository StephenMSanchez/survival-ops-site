#!/usr/bin/env node
// Builds dist/ from secrets.json (or bootstraps secrets.json on first run).
//
// Usage:
//   node build.js
//
// In CI, provide secrets via environment variables instead of committing secrets.json
// (see .github/workflows/rebuild.yml) -- this script will assemble secrets.json from
// env vars automatically when SITE_ADMIN_PASSCODE is set.
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { base32Encode, base32Decode } = require('./lib/base32');
const { totpForCounter, counterForTime } = require('./lib/totp');
const {
  contextSalt,
  deriveKey,
  aesGcmEncrypt,
  randomKey,
  randomSalt,
} = require('./lib/crypto-node');

const ROOT = __dirname;
const SECRETS_PATH = path.join(ROOT, 'secrets.json');
const CREDENTIALS_PATH = path.join(ROOT, 'CREDENTIALS.txt');
const PUBLIC_DIR = path.join(ROOT, 'public');
const DIST_DIR = path.join(ROOT, 'dist');

const DEFAULT_PAGES = [
  {
    id: 'survival',
    title: 'Survival',
    subpages: [
      {
        id: 'overview',
        title: 'Overview',
        content:
          '<p><em>Placeholder page. Replace this with your own reference material.</em></p>\n' +
          '<ul>\n' +
          '  <li>Water: sourcing, purification methods, storage</li>\n' +
          '  <li>Shelter: site selection, construction basics</li>\n' +
          '  <li>Fire: methods, safety, materials</li>\n' +
          '  <li>Food: foraging cautions, storage, rationing</li>\n' +
          '  <li>Navigation: map/compass, landmarks, routes</li>\n' +
          '</ul>',
      },
      {
        id: 'medical',
        title: 'Medical',
        content:
          '<ul>\n' +
          '  <li>Trauma basics: bleeding control, splinting</li>\n' +
          '  <li>Common environmental injuries: heat, cold, dehydration</li>\n' +
          '</ul>',
      },
    ],
  },
  {
    id: 'technical',
    title: 'Technical',
    subpages: [
      {
        id: 'comms',
        title: 'Comms',
        content:
          '<p><em>Placeholder page. Replace this with your own reference material.</em></p>\n' +
          '<ul>\n' +
          '  <li>Communication plan: primary/backup channels, check-in schedule</li>\n' +
          '  <li>Code words / call signs (if used)</li>\n' +
          '</ul>',
      },
    ],
  },
  {
    id: 'tactical',
    title: 'Tactical',
    subpages: [
      {
        id: 'team-roster',
        title: 'Team Roster',
        content:
          '<p><em>Placeholder page. Replace this with your own reference material.</em></p>\n' +
          '<ul>\n' +
          '  <li>Roster: names, roles, contact info</li>\n' +
          '  <li>Emergency contacts</li>\n' +
          '</ul>',
      },
      {
        id: 'ops-plans',
        title: 'Ops Plans',
        content:
          '<ul>\n' +
          '  <li>Standing operating procedures</li>\n' +
          '  <li>Rally points and routes</li>\n' +
          '  <li>After-action review notes</li>\n' +
          '</ul>',
      },
      {
        id: 'medical',
        title: 'Medical',
        content:
          '<ul>\n' +
          '  <li>Medical kit contents and locations</li>\n' +
          '  <li>Team member medical info / allergies (sensitive -- keep minimal)</li>\n' +
          '  <li>Evacuation criteria and contacts</li>\n' +
          '</ul>',
      },
    ],
  },
];

function log(...args) {
  console.log('[build]', ...args);
}

function randomPasscode(bytes = 9) {
  // URL-safe, easy to read aloud-ish, ~12 base64url chars from 9 random bytes.
  return crypto.randomBytes(bytes).toString('base64url');
}

function loadOrBootstrapSecrets() {
  // CI path: assemble secrets.json from environment variables if present.
  if (process.env.SITE_USERS_JSON) {
    log('Assembling secrets from environment variables (CI mode).');
    return {
      users: JSON.parse(process.env.SITE_USERS_JSON),
      totp: {
        base32Secret: process.env.SITE_TOTP_SECRET_BASE32,
        periodSeconds: Number(process.env.SITE_TOTP_PERIOD_SECONDS || 1800),
        digits: Number(process.env.SITE_TOTP_DIGITS || 6),
        accessAllPages: true,
      },
      pages: DEFAULT_PAGES,
    };
  }

  if (fs.existsSync(SECRETS_PATH)) {
    log('Loading existing secrets.json');
    return JSON.parse(fs.readFileSync(SECRETS_PATH, 'utf8'));
  }

  log('No secrets.json found -- bootstrapping new random credentials.');
  const totpSecretBytes = crypto.randomBytes(20); // 160-bit, standard TOTP secret size
  const secrets = {
    users: [
      { username: 'admin', passcode: randomPasscode(12), allPages: true },
      ...DEFAULT_PAGES.map((p) => ({
        username: p.id,
        passcode: randomPasscode(9),
        pages: [p.id],
      })),
    ],
    totp: {
      base32Secret: base32Encode(totpSecretBytes),
      periodSeconds: 1800, // 30 minutes
      digits: 6,
      accessAllPages: true,
    },
    pages: DEFAULT_PAGES,
  };

  fs.writeFileSync(SECRETS_PATH, JSON.stringify(secrets, null, 2));
  log('Wrote secrets.json (keep this file private -- it is gitignored).');
  writeCredentialsFile(secrets);
  return secrets;
}

function writeCredentialsFile(secrets) {
  const otpauthUri =
    'otpauth://totp/SurvivalOps:rotating-access?secret=' +
    secrets.totp.base32Secret +
    '&issuer=SurvivalOps&period=' +
    secrets.totp.periodSeconds +
    '&digits=' +
    secrets.totp.digits;

  const lines = [];
  lines.push('SURVIVAL/OPS SITE -- ACCESS CREDENTIALS');
  lines.push('Generated: ' + new Date().toISOString());
  lines.push('');
  lines.push('KEEP THIS FILE PRIVATE. Distribute individual logins to team members');
  lines.push('over a secure channel (not email/SMS in plaintext if you can avoid it).');
  lines.push('');
  lines.push('USER LOGINS (username + passcode, each with its own page access):');
  for (const u of secrets.users) {
    const access = u.allPages ? 'ALL PAGES' : (u.pages || []).join(', ') || '(none)';
    lines.push('  ' + u.username + ' / ' + u.passcode + '  -- access: ' + access);
  }
  lines.push('');
  lines.push('To change what a user can see, edit their "pages" array (or "allPages": true');
  lines.push('for full access) in secrets.json, under "users", then rebuild.');
  lines.push('');
  lines.push('ROTATING ACCESS CODE (TOTP, changes every ' + secrets.totp.periodSeconds / 60 + ' minutes, unlocks all pages, no username needed):');
  lines.push('  Add this to an authenticator app (Google Authenticator, Authy, 1Password, etc.)');
  lines.push('  Either scan totp-qr.png (in this same folder after build) or enter manually:');
  lines.push('    Secret (base32): ' + secrets.totp.base32Secret);
  lines.push('    Type: Time-based, Digits: ' + secrets.totp.digits + ', Period: ' + secrets.totp.periodSeconds + 's');
  lines.push('  otpauth URI: ' + otpauthUri);
  lines.push('');
  lines.push('Remember: the rotating code only stays in sync if the site is rebuilt');
  lines.push('periodically (see .github/workflows/rebuild.yml). A stale build will reject');
  lines.push('otherwise-correct rotating codes once enough time has passed.');

  fs.writeFileSync(CREDENTIALS_PATH, lines.join('\n') + '\n');
  log('Wrote CREDENTIALS.txt (private, gitignored) with all generated codes.');
}

function encryptPageContent(pageKey, page) {
  const payload = JSON.stringify({ title: page.title, subpages: page.subpages });
  const { iv, ct } = aesGcmEncrypt(pageKey, Buffer.from(payload, 'utf8'));
  return { iv, ct };
}

function wrapKeyForPasscode(pageKey, passcode, baseSalt, context) {
  const salt = contextSalt(baseSalt, context);
  const kek = deriveKey(passcode, salt);
  const { iv, ct } = aesGcmEncrypt(kek, pageKey);
  return { context, iv, ct };
}

// Users authenticate with a username + passcode pair. Both must be exactly
// right: the derivation key is "username:passcode", not just the passcode,
// so knowing one user's passcode (or seeing another user's username in a
// page's wrapped-entry list) doesn't help unlock a different user's login.
function wrapKeyForUser(pageKey, user, baseSalt) {
  return wrapKeyForPasscode(pageKey, user.username + ':' + user.passcode, baseSalt, 'user:' + user.username);
}

function userGrantsPage(user, pageId) {
  return user.allPages === true || (Array.isArray(user.pages) && user.pages.includes(pageId));
}

function buildTotpWrappedEntries(pageKey, baseSalt, totpConfig) {
  if (!totpConfig || !totpConfig.base32Secret) return [];
  const secretBuf = base32Decode(totpConfig.base32Secret);
  const nowSec = Math.floor(Date.now() / 1000);
  const period = totpConfig.periodSeconds || 1800;
  const digits = totpConfig.digits || 6;
  const currentCounter = counterForTime(nowSec, period);

  const entries = [];
  // Accept previous, current, and next window to tolerate clock skew / rebuild timing.
  for (const offset of [-1, 0, 1]) {
    const counter = currentCounter + offset;
    const code = totpForCounter(secretBuf, counter, digits);
    const salt = contextSalt(baseSalt, 'totp:' + counter);
    const kek = deriveKey(code, salt);
    const { iv, ct } = aesGcmEncrypt(kek, pageKey);
    entries.push({ context: 'totp:' + counter, iv, ct });
  }
  return entries;
}

function main() {
  const secrets = loadOrBootstrapSecrets();

  if (fs.existsSync(DIST_DIR)) {
    fs.rmSync(DIST_DIR, { recursive: true, force: true });
  }
  fs.mkdirSync(DIST_DIR, { recursive: true });
  fs.mkdirSync(path.join(DIST_DIR, 'pages'), { recursive: true });

  // Copy static frontend assets as-is.
  for (const file of fs.readdirSync(PUBLIC_DIR)) {
    fs.copyFileSync(path.join(PUBLIC_DIR, file), path.join(DIST_DIR, file));
  }

  const manifest = [];

  for (const page of secrets.pages) {
    const baseSalt = randomSalt(16);
    const pageKey = randomKey();

    const content = encryptPageContent(pageKey, page);

    const wrapped = [];
    for (const user of secrets.users || []) {
      if (userGrantsPage(user, page.id)) {
        wrapped.push(wrapKeyForUser(pageKey, user, baseSalt));
      }
    }

    const totpGrantsThisPage =
      secrets.totp &&
      secrets.totp.base32Secret &&
      (secrets.totp.accessAllPages !== false) &&
      (!secrets.totp.pages || secrets.totp.pages.includes(page.id));
    if (totpGrantsThisPage) {
      wrapped.push(...buildTotpWrappedEntries(pageKey, baseSalt, secrets.totp));
    }

    const pageOut = {
      id: page.id,
      title: page.title,
      salt: baseSalt.toString('base64'),
      content,
      wrapped,
    };

    fs.writeFileSync(
      path.join(DIST_DIR, 'pages', page.id + '.json'),
      JSON.stringify(pageOut)
    );

    manifest.push({ id: page.id, title: page.title });
  }

  fs.writeFileSync(path.join(DIST_DIR, 'pages', 'manifest.json'), JSON.stringify(manifest));

  log('Built ' + manifest.length + ' page(s) into dist/.');

  // Generate a QR code for the TOTP secret if the qrcode package is available.
  if (secrets.totp && secrets.totp.base32Secret) {
    try {
      const QRCode = require('qrcode');
      const otpauthUri =
        'otpauth://totp/SurvivalOps:rotating-access?secret=' +
        secrets.totp.base32Secret +
        '&issuer=SurvivalOps&period=' +
        secrets.totp.periodSeconds +
        '&digits=' +
        secrets.totp.digits;
      QRCode.toFile(path.join(ROOT, 'totp-qr.png'), otpauthUri, { width: 300 }, (err) => {
        if (err) {
          log('Could not generate totp-qr.png:', err.message);
        } else {
          log('Wrote totp-qr.png -- scan with an authenticator app.');
        }
      });
    } catch (e) {
      log('qrcode package not installed; skipping QR generation (npm install to enable).');
    }
  }

  if (!fs.existsSync(CREDENTIALS_PATH) && !process.env.SITE_USERS_JSON) {
    writeCredentialsFile(secrets);
  }
}

main();
