/**
 * VaultScan - JWT Utilities
 * Base64URL decode, structure inspection, expiration checks, weak secret verification
 */

const jwt = require('jsonwebtoken');
const { WEAK_SECRETS } = require('./config');

/**
 * Decodes base64url encoded string to UTF-8
 */
function base64UrlDecode(str) {
  if (!str) return '';
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf8');
}

/**
 * Decodes a JWT token without verifying signature
 * Handles malformed tokens gracefully
 */
function decodeJwt(token) {
  if (!token || typeof token !== 'string') {
    return { error: 'Empty or non-string token provided' };
  }

  const trimmed = token.trim();
  const parts = trimmed.split('.');

  if (parts.length < 2 || parts.length > 3) {
    return { error: 'Invalid JWT structure: must have header, payload, and optional signature separated by dots (.)' };
  }

  try {
    const headerJson = base64UrlDecode(parts[0]);
    const payloadJson = base64UrlDecode(parts[1]);

    const header = JSON.parse(headerJson);
    const payload = JSON.parse(payloadJson);
    const signature = parts[2] || '';

    return {
      header,
      payload,
      signature,
      raw: trimmed
    };
  } catch (err) {
    return {
      error: 'Malformed JWT: failed to decode base64 or parse JSON header/payload (' + err.message + ')'
    };
  }
}

/**
 * Checks if token payload exp claim is in the past
 */
function isExpired(payload) {
  if (!payload || !payload.exp) return false;
  const expSeconds = Number(payload.exp);
  if (isNaN(expSeconds)) return false;
  const nowSeconds = Math.floor(Date.now() / 1000);
  return expSeconds < nowSeconds;
}

/**
 * Tests HMAC signed tokens against the weak secret dictionary
 * Returns the cracked secret string if found, otherwise null
 */
function tryWeakSecrets(token, header) {
  if (!token || !header || !header.alg) return null;
  const alg = String(header.alg).toUpperCase();

  // Weak secret dictionary verification applies to symmetric HMAC algorithms
  if (!['HS256', 'HS384', 'HS512'].includes(alg)) {
    return null;
  }

  for (const secret of WEAK_SECRETS) {
    try {
      jwt.verify(token, secret, { algorithms: [header.alg] });
      return secret; // Found matching weak secret
    } catch (e) {
      // Continue to next candidate
    }
  }

  return null;
}

module.exports = {
  base64UrlDecode,
  decodeJwt,
  isExpired,
  tryWeakSecrets
};
