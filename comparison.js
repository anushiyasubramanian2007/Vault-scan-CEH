/**
 * VaultScan - JWT Comparison Engine (comparison.js)
 * Compares two JSON Web Tokens (Token A and Token B) across headers,
 * algorithms, payload claims, role/privilege escalations, expiry, and token sizes.
 */

const { decodeJwt } = require('./jwtUtils');

/**
 * Deep comparison of two JWT tokens
 * Returns structural differences, claim modifications, and change summary
 */
function compareTokens(tokenAStr, tokenBStr) {
  const decodedA = decodeJwt(tokenAStr);
  const decodedB = decodeJwt(tokenBStr);

  if (decodedA.error) {
    return { error: 'Token A Error: ' + decodedA.error };
  }
  if (decodedB.error) {
    return { error: 'Token B Error: ' + decodedB.error };
  }

  const headerA = decodedA.header || {};
  const headerB = decodedB.header || {};
  const payloadA = decodedA.payload || {};
  const payloadB = decodedB.payload || {};

  const differences = [];

  // 1. Header & Algorithm Comparison
  if (headerA.alg !== headerB.alg) {
    differences.push({
      category: 'Header / Algorithm',
      type: 'ALGORITHM_CHANGED',
      severity: 'HIGH',
      field: 'header.alg',
      oldValue: headerA.alg || 'undefined',
      newValue: headerB.alg || 'undefined',
      description: 'Algorithm changed from "' + (headerA.alg || 'none') + '" to "' + (headerB.alg || 'none') + '"'
    });
  }

  if (headerA.typ !== headerB.typ) {
    differences.push({
      category: 'Header / Type',
      type: 'TYPE_CHANGED',
      severity: 'INFO',
      field: 'header.typ',
      oldValue: headerA.typ || 'undefined',
      newValue: headerB.typ || 'undefined',
      description: 'Token type header changed from "' + (headerA.typ || 'none') + '" to "' + (headerB.typ || 'none') + '"'
    });
  }

  if (headerA.kid !== headerB.kid) {
    differences.push({
      category: 'Header / Key ID',
      type: 'KID_CHANGED',
      severity: 'MEDIUM',
      field: 'header.kid',
      oldValue: headerA.kid || 'undefined',
      newValue: headerB.kid || 'undefined',
      description: 'Key ID (kid) parameter changed'
    });
  }

  // 2. Identity Claims Comparison (sub, user, username, email)
  const identityFields = ['sub', 'user', 'username', 'email', 'userId', 'id'];
  for (const field of identityFields) {
    if (payloadA[field] !== undefined || payloadB[field] !== undefined) {
      if (payloadA[field] !== payloadB[field]) {
        differences.push({
          category: 'Identity',
          type: 'IDENTITY_CHANGED',
          severity: 'HIGH',
          field,
          oldValue: payloadA[field] !== undefined ? String(payloadA[field]) : '(not set)',
          newValue: payloadB[field] !== undefined ? String(payloadB[field]) : '(not set)',
          description: 'User identity claim "' + field + '" changed from "' + payloadA[field] + '" to "' + payloadB[field] + '"'
        });
      }
    }
  }

  // 3. Privilege & Role Escalation Detection
  const roleFields = ['role', 'roles', 'admin', 'isAdmin', 'group', 'groups', 'scope', 'scopes', 'permissions'];
  for (const field of roleFields) {
    const valA = payloadA[field];
    const valB = payloadB[field];
    const strA = JSON.stringify(valA !== undefined ? valA : null);
    const strB = JSON.stringify(valB !== undefined ? valB : null);

    if (strA !== strB) {
      // Check if privilege escalation indicator
      const isEscalation = /admin|root|superuser|manage|write/i.test(strB) && !/admin|root|superuser/i.test(strA);
      differences.push({
        category: 'Privileges & Roles',
        type: isEscalation ? 'PRIVILEGE_ESCALATION' : 'ROLE_CHANGED',
        severity: isEscalation ? 'CRITICAL' : 'HIGH',
        field,
        oldValue: valA !== undefined ? valA : '(not set)',
        newValue: valB !== undefined ? valB : '(not set)',
        description: isEscalation
          ? 'CRITICAL PRIVILEGE ESCALATION: Role elevated to administrative level (' + strA + ' → ' + strB + ')'
          : 'Role/Permissions claim "' + field + '" was modified (' + strA + ' → ' + strB + ')'
      });
    }
  }

  // 4. Standard Metadata Claims: Issuer, Audience, Expiry, IAT
  if (payloadA.iss !== payloadB.iss) {
    differences.push({
      category: 'Issuer (iss)',
      type: 'ISSUER_CHANGED',
      severity: 'MEDIUM',
      field: 'iss',
      oldValue: payloadA.iss || '(not set)',
      newValue: payloadB.iss || '(not set)',
      description: 'Issuer claim changed from "' + (payloadA.iss || 'none') + '" to "' + (payloadB.iss || 'none') + '"'
    });
  }

  if (payloadA.aud !== payloadB.aud) {
    differences.push({
      category: 'Audience (aud)',
      type: 'AUDIENCE_CHANGED',
      severity: 'MEDIUM',
      field: 'aud',
      oldValue: payloadA.aud || '(not set)',
      newValue: payloadB.aud || '(not set)',
      description: 'Audience claim changed from "' + (payloadA.aud || 'none') + '" to "' + (payloadB.aud || 'none') + '"'
    });
  }

  if (payloadA.exp !== payloadB.exp) {
    const timeA = payloadA.exp ? new Date(payloadA.exp * 1000).toISOString() : '(no expiry)';
    const timeB = payloadB.exp ? new Date(payloadB.exp * 1000).toISOString() : '(no expiry)';
    differences.push({
      category: 'Expiration (exp)',
      type: 'EXPIRY_CHANGED',
      severity: 'MEDIUM',
      field: 'exp',
      oldValue: timeA,
      newValue: timeB,
      description: 'Expiration changed from ' + timeA + ' to ' + timeB
    });
  }

  // 5. Detect Newly Added, Removed, and Modified Arbitrary Claims
  const allKeys = new Set([...Object.keys(payloadA), ...Object.keys(payloadB)]);
  const skipStandard = new Set([...identityFields, ...roleFields, 'iss', 'aud', 'exp', 'iat', 'nbf']);

  for (const key of allKeys) {
    if (skipStandard.has(key)) continue;

    if (!(key in payloadA) && (key in payloadB)) {
      differences.push({
        category: 'Payload Claims',
        type: 'CLAIM_ADDED',
        severity: 'LOW',
        field: key,
        oldValue: '(not present)',
        newValue: JSON.stringify(payloadB[key]),
        description: 'New claim "' + key + '" added to Token B'
      });
    } else if ((key in payloadA) && !(key in payloadB)) {
      differences.push({
        category: 'Payload Claims',
        type: 'CLAIM_REMOVED',
        severity: 'LOW',
        field: key,
        oldValue: JSON.stringify(payloadA[key]),
        newValue: '(removed)',
        description: 'Claim "' + key + '" removed from Token B'
      });
    } else if (JSON.stringify(payloadA[key]) !== JSON.stringify(payloadB[key])) {
      differences.push({
        category: 'Payload Claims',
        type: 'CLAIM_MODIFIED',
        severity: 'MEDIUM',
        field: key,
        oldValue: JSON.stringify(payloadA[key]),
        newValue: JSON.stringify(payloadB[key]),
        description: 'Claim "' + key + '" value was altered'
      });
    }
  }

  // 6. Token Size Comparison
  const sizeA = (tokenAStr || '').trim().length;
  const sizeB = (tokenBStr || '').trim().length;
  const sizeDiff = sizeB - sizeA;

  return {
    tokenA: {
      header: headerA,
      payload: payloadA,
      size: sizeA,
      signatureLength: (decodedA.signature || '').length
    },
    tokenB: {
      header: headerB,
      payload: payloadB,
      size: sizeB,
      signatureLength: (decodedB.signature || '').length
    },
    sizeDifference: {
      bytesA: sizeA,
      bytesB: sizeB,
      delta: sizeDiff,
      summary: sizeDiff === 0 ? 'Identical length' : (sizeDiff > 0 ? ('Token B is ' + sizeDiff + ' bytes larger') : ('Token B is ' + Math.abs(sizeDiff) + ' bytes smaller'))
    },
    changesCount: differences.length,
    differences,
    securityNote: 'Note: Differences in cryptographic signatures reflect differing headers or payloads; signature comparison alone does not indicate whether either token is authentic or valid.'
  };
}

module.exports = {
  compareTokens
};
