// RFC 6238 TOTP / RFC 4226 HOTP implementation (HMAC-SHA1), build-time only (Node).
// This is the same algorithm used by Google Authenticator, Authy, 1Password, etc.
// The secret NEVER ships to the browser -- only the site builder (Node) ever sees it,
// so the site itself has no way to compute future codes; it can only check whether a
// code a person typed in happens to unwrap content that was pre-wrapped for the
// current time window at build time.
'use strict';

const crypto = require('crypto');

function hotp(secretBuf, counter, digits = 6) {
  const counterBuf = Buffer.alloc(8);
  // Write a 64-bit big-endian counter (counter is always small enough for Number here).
  counterBuf.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
  counterBuf.writeUInt32BE(counter >>> 0, 4);

  const hmac = crypto.createHmac('sha1', secretBuf).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const code = (binCode % 10 ** digits).toString().padStart(digits, '0');
  return code;
}

function totpForCounter(secretBuf, counter, digits = 6) {
  return hotp(secretBuf, counter, digits);
}

function counterForTime(unixSeconds, periodSeconds) {
  return Math.floor(unixSeconds / periodSeconds);
}

module.exports = { hotp, totpForCounter, counterForTime };
