// Build-time (Node) crypto helpers. Must stay byte-for-byte compatible with the
// browser-side implementation in dist assets (see app.js): PBKDF2-HMAC-SHA256,
// AES-256-GCM with a 12-byte IV and the auth tag appended to the ciphertext.
'use strict';

const crypto = require('crypto');

const PBKDF2_ITERATIONS = 200000;
const KEY_LENGTH = 32; // 256 bits

// salt for a given (page, context) pair: base salt bytes + ":" + context label.
// Keeping this identical between build.js and app.js is what makes unwrap work.
function contextSalt(baseSaltBuf, context) {
  return Buffer.concat([baseSaltBuf, Buffer.from(':' + context, 'utf8')]);
}

function deriveKey(passcode, saltBuf) {
  return crypto.pbkdf2Sync(String(passcode), saltBuf, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
}

// Encrypts `plaintextBuf` with `keyBuf` (32 bytes) using AES-256-GCM.
// Returns { iv, ct } both base64, with the 16-byte auth tag appended to ct so
// that Web Crypto's subtle.decrypt (which expects tag-appended ciphertext) works directly.
function aesGcmEncrypt(keyBuf, plaintextBuf) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuf, iv);
  const ct = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    ct: Buffer.concat([ct, tag]).toString('base64'),
  };
}

function randomKey() {
  return crypto.randomBytes(KEY_LENGTH);
}

function randomSalt(len = 16) {
  return crypto.randomBytes(len);
}

module.exports = {
  PBKDF2_ITERATIONS,
  KEY_LENGTH,
  contextSalt,
  deriveKey,
  aesGcmEncrypt,
  randomKey,
  randomSalt,
};
