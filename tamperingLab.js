/**
 * VaultScan - JWT Tampering Simulator (tamperingLab.js)
 * Local educational simulator illustrating how altering claims breaks signature validity
 * and why secure servers reject modified, un-signed JWT tokens.
 */

const { decodeJwt, base64UrlDecode } = require('./jwtUtils');

function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Simulates tampering on a JWT payload
 * @param {string} originalTokenStr - Raw original JWT
 * @param {object|string} newPayloadClaims - Modified payload claims
 * @param {string} mode - 'preserve_signature' | 'strip_signature' | 'invalid_signature'
 */
function simulateTampering(originalTokenStr, newPayloadClaims, mode = 'preserve_signature') {
  const decoded = decodeJwt(originalTokenStr);
  if (decoded.error) {
    return { error: 'Failed to parse original token: ' + decoded.error };
  }

  let modifiedPayload = {};
  if (typeof newPayloadClaims === 'string') {
    try {
      modifiedPayload = JSON.parse(newPayloadClaims);
    } catch (e) {
      return { error: 'Modified payload must be valid JSON: ' + e.message };
    }
  } else if (typeof newPayloadClaims === 'object' && newPayloadClaims !== null) {
    modifiedPayload = { ...decoded.payload, ...newPayloadClaims };
  } else {
    return { error: 'Invalid modified payload format' };
  }

  // Detect specific field changes
  const changes = [];
  const allKeys = new Set([...Object.keys(decoded.payload), ...Object.keys(modifiedPayload)]);

  for (const key of allKeys) {
    const origVal = decoded.payload[key];
    const modVal = modifiedPayload[key];

    if (!(key in decoded.payload)) {
      changes.push({
        claim: key,
        type: 'ADDED',
        before: '(none)',
        after: JSON.stringify(modVal)
      });
    } else if (!(key in modifiedPayload)) {
      changes.push({
        claim: key,
        type: 'REMOVED',
        before: JSON.stringify(origVal),
        after: '(removed)'
      });
    } else if (JSON.stringify(origVal) !== JSON.stringify(modVal)) {
      changes.push({
        claim: key,
        type: 'MODIFIED',
        before: JSON.stringify(origVal),
        after: JSON.stringify(modVal)
      });
    }
  }

  // Re-encode modified token
  const headerB64 = base64UrlEncode(JSON.stringify(decoded.header));
  const payloadB64 = base64UrlEncode(JSON.stringify(modifiedPayload));

  let finalSignature = decoded.signature || '';
  let signatureState = 'MISMATCH_INVALID';

  if (mode === 'strip_signature') {
    finalSignature = '';
    signatureState = 'STRIPPED_UNSIGNED';
  } else if (mode === 'invalid_signature') {
    finalSignature = 'invalid_tampered_signature_' + Date.now();
    signatureState = 'FORGED_INVALID';
  }

  const tamperedToken = headerB64 + '.' + payloadB64 + '.' + finalSignature;

  return {
    original: {
      token: decoded.raw,
      header: decoded.header,
      payload: decoded.payload,
      signature: decoded.signature
    },
    tampered: {
      token: tamperedToken,
      header: decoded.header,
      payload: modifiedPayload,
      signature: finalSignature
    },
    changes,
    changesCount: changes.length,
    signatureStatus: 'SIGNATURE INVALID / NOT VERIFIED',
    signatureExplanation: 'The token payload was altered. The cryptographic signature was calculated over the original header and payload. Any alteration to the payload produces a different hash, rendering the signature invalid.',
    serverVerificationVerdict: 'SECURE SERVER WILL REJECT (HTTP 401 Unauthorized / JsonWebTokenError: invalid signature)',
    visualFlow: [
      { step: 1, title: 'ORIGINAL TOKEN', status: 'VALID_OR_ISSUED', detail: 'Token created by authenticating authority' },
      { step: 2, title: 'PAYLOAD MODIFIED', status: 'MODIFIED', detail: 'Claims tampered in transit (' + changes.length + ' fields changed)' },
      { step: 3, title: 'SIGNATURE INVALID', status: 'VERIFICATION_FAILED', detail: 'Signature HMAC/RSA digest no longer matches payload' },
      { step: 4, title: 'SERVER REJECTION', status: 'REJECTED', detail: 'Properly implemented JWT verifiers abort request immediately' }
    ]
  };
}

module.exports = {
  simulateTampering
};
