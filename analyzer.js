/**
 * VaultScan - Security Analyzer Engine
 * Implements 12 comprehensive security checks, score computation, and remediation guidelines
 */

const { SEVERITY_WEIGHTS, SENSITIVE_PATTERNS, MITRE_MAP } = require('./config');
const { decodeJwt, isExpired, tryWeakSecrets } = require('./jwtUtils');

/**
 * Searches an object recursively for sensitive patterns
 */
function scanSensitiveData(obj, path = '') {
  const matches = [];
  if (!obj || typeof obj !== 'object') return matches;

  for (const [key, val] of Object.entries(obj)) {
    const currentPath = path ? (path + '.' + key) : key;
    const strVal = String(val);

    for (const [patternType, regex] of Object.entries(SENSITIVE_PATTERNS)) {
      if (regex.test(key) || regex.test(strVal)) {
        matches.push({
          type: patternType,
          key: currentPath,
          evidence: currentPath + ': "' + (strVal.length > 25 ? strVal.slice(0, 22) + '...' : strVal) + '"'
        });
      }
    }

    if (val && typeof val === 'object' && !Array.isArray(val)) {
      matches.push(...scanSensitiveData(val, currentPath));
    }
  }

  const uniqueTypes = new Map();
  for (const m of matches) {
    if (!uniqueTypes.has(m.type)) {
      uniqueTypes.set(m.type, m);
    }
  }

  return Array.from(uniqueTypes.values());
}

/**
 * Analyzes a JWT token and returns findings, score, and grade
 */
function analyzeToken(token) {
  const decoded = decodeJwt(token);

  if (decoded.error) {
    return {
      error: decoded.error,
      score: 0,
      grade: 'F',
      header: {},
      payload: {},
      findings: [
        {
          id: 'malformed_jwt',
          severity: 'CRITICAL',
          title: 'Malformed or Invalid Token Structure',
          description: decoded.error,
          fix: 'Verify the token format conforms to RFC 7519 (header.payload.signature encoded with base64url).',
          mitre_id: '—',
          evidence: token ? token.slice(0, 40) + '...' : 'empty string'
        }
      ]
    };
  }

  const { header, payload, raw } = decoded;
  const findings = [];
  const nowSeconds = Math.floor(Date.now() / 1000);

  // 1. Check alg: none
  const algStr = String(header.alg || '').trim().toLowerCase();
  if (algStr === 'none') {
    findings.push({
      id: 'alg_none',
      severity: 'CRITICAL',
      title: 'Algorithm Set to "none"',
      description: 'The token explicitly disables cryptographic signature verification. Anyone can forge arbitrary identity and admin claims without needing any secret key.',
      fix: 'Reject alg: "none" on the authentication server. Enforce an explicit whitelist of allowed signature algorithms (e.g. HS256, RS256).',
      mitre_id: MITRE_MAP.alg_none,
      evidence: 'header.alg = "' + header.alg + '"'
    });
  }

  // 2. Check weak HMAC secret via dictionary attack
  const weakSecretMatch = tryWeakSecrets(raw, header);
  if (weakSecretMatch) {
    findings.push({
      id: 'weak_secret',
      severity: 'CRITICAL',
      title: 'Weak HS256 Secret Detected',
      description: 'The token was signed with a guessable secret key ("' + weakSecretMatch + '") found in our common dictionary. Attackers can crack this offline in seconds.',
      fix: 'Rotate to a cryptographically random 256-bit secret (at least 32 random characters). Never use plain dictionary words or default template keys.',
      mitre_id: MITRE_MAP.weak_secret,
      evidence: 'Cracked secret key: "' + weakSecretMatch + '" (algorithm: ' + header.alg + ')'
    });
  }

  // 3. Check algorithm confusion (RS256 / ES256)
  const algUpper = String(header.alg || '').toUpperCase();
  if (algUpper.startsWith('RS') || algUpper.startsWith('ES')) {
    findings.push({
      id: 'alg_confusion',
      severity: 'HIGH',
      title: 'Algorithm Confusion Risk (Asymmetric to Symmetric)',
      description: 'Token specifies an asymmetric algorithm (' + header.alg + '). If your server verifies signatures with a library that does not pin expected algorithms, an attacker can re-sign the token using the server public key as an HMAC secret.',
      fix: 'Explicitly specify allowed algorithms during verification (e.g., jwt.verify(token, pubKey, { algorithms: ["' + header.alg + '"] })).',
      mitre_id: MITRE_MAP.alg_confusion,
      evidence: 'header.alg = "' + header.alg + '"'
    });
  }

  // 4. Missing expiration claim (exp)
  if (payload.exp === undefined || payload.exp === null) {
    findings.push({
      id: 'missing_exp',
      severity: 'HIGH',
      title: 'Missing "exp" (Expiration) Claim',
      description: 'The token never expires. If an attacker intercepts or steals this token, it remains valid forever.',
      fix: 'Always add an "exp" claim when signing tokens. Use a short validity window (15 minutes to 1 hour for access tokens).',
      mitre_id: '—',
      evidence: 'payload.exp claim is not present'
    });
  }

  // 5. Expired token
  if (payload.exp !== undefined && payload.exp !== null && isExpired(payload)) {
    const expiredAgoSec = nowSeconds - Number(payload.exp);
    const expiredAgoMin = Math.round(expiredAgoSec / 60);
    findings.push({
      id: 'expired',
      severity: 'MEDIUM',
      title: 'Token Already Expired',
      description: 'The token expired ' + (expiredAgoMin > 0 ? expiredAgoMin + ' minutes ago' : 'recently') + '. The server should reject requests presenting this token.',
      fix: 'Re-authenticate user or exchange a valid refresh token for a fresh unexpired access token.',
      mitre_id: '—',
      evidence: 'exp: ' + payload.exp + ' (' + new Date(Number(payload.exp) * 1000).toISOString() + ')'
    });
  }

  // 6. Excessive expiry (> 24 hours)
  if (payload.exp && payload.iat) {
    const lifetimeSec = Number(payload.exp) - Number(payload.iat);
    if (lifetimeSec > 86400) {
      const hours = Math.round(lifetimeSec / 3600);
      findings.push({
        id: 'excessive_expiry',
        severity: 'MEDIUM',
        title: 'Excessive Expiration Duration (> 24 Hours)',
        description: 'The token lifetime is ' + hours + ' hours. Excessively long lifespans give attackers an extended window of opportunity if the token is stolen.',
        fix: 'Reduce access token lifetime to 1 hour or less. Pair with short-lived tokens and secure refresh token rotation.',
        mitre_id: '—',
        evidence: 'Lifetime: ' + hours + ' hours (iat: ' + payload.iat + ', exp: ' + payload.exp + ')'
      });
    }
  }

  // 7. Sensitive data in payload
  const sensitiveMatches = scanSensitiveData(payload);
  for (const match of sensitiveMatches) {
    findings.push({
      id: 'sensitive_payload_' + match.type,
      severity: 'HIGH',
      title: 'Sensitive Data Exposed in Payload (' + match.type + ')',
      description: 'Payload contains sensitive data matching ' + match.type + '. JWT payloads are only Base64 encoded—not encrypted—making them readable by anyone with access to the token.',
      fix: 'Remove sensitive information from the token payload. Use opaque identifiers (e.g. user_id) and retrieve details from database server-side.',
      mitre_id: MITRE_MAP.sensitive_payload,
      evidence: match.evidence
    });
  }

  // 8. Missing issuer (iss)
  if (!payload.iss) {
    findings.push({
      id: 'missing_iss',
      severity: 'LOW',
      title: 'Missing "iss" (Issuer) Claim',
      description: 'The token does not specify which authentication server or authority issued it.',
      fix: 'Include an "iss" claim (e.g., "iss": "https://auth.example.com") and verify it in your backend middleware.',
      mitre_id: '—',
      evidence: 'payload.iss claim is missing'
    });
  }

  // 9. Missing audience (aud)
  if (!payload.aud) {
    findings.push({
      id: 'missing_aud',
      severity: 'LOW',
      title: 'Missing "aud" (Audience) Claim',
      description: 'The token does not declare its intended recipient or API service.',
      fix: 'Include an "aud" claim specifying the target service (e.g., "aud": "api.example.com") to prevent token reuse across services.',
      mitre_id: '—',
      evidence: 'payload.aud claim is missing'
    });
  }

  // 10. Key ID (kid) path traversal
  if (header.kid) {
    const kidStr = String(header.kid);
    if (kidStr.includes('../') || kidStr.includes('..\\') || kidStr.includes('/') || kidStr.includes('\\')) {
      findings.push({
        id: 'kid_traversal',
        severity: 'HIGH',
        title: 'Key ID (kid) Path Traversal Indicator',
        description: 'The "kid" header parameter contains path traversal characters (../ or slashes). An attacker could exploit file-based key lookups to force verification with local files.',
        fix: 'Sanitize "kid" input or look up cryptographic keys using a whitelist dictionary/database rather than constructing direct filesystem paths.',
        mitre_id: MITRE_MAP.kid_traversal,
        evidence: 'header.kid = "' + header.kid + '"'
      });
    }
  }

  // 11. Large payload size (> 4096 bytes)
  if (raw && raw.length > 4096) {
    findings.push({
      id: 'large_payload',
      severity: 'LOW',
      title: 'Large Token Size (> 4KB)',
      description: 'The token is ' + raw.length + ' bytes. Excessively large tokens sent in Authorization headers can cause HTTP 431 errors and consume unnecessary network bandwidth.',
      fix: 'Store only minimal identity claims in the JWT. Keep the token under 4KB for optimal HTTP header transmission.',
      mitre_id: '—',
      evidence: 'Token length: ' + raw.length + ' bytes (threshold: 4096 bytes)'
    });
  }

  // 12. External JKU or X5U URLs
  const jku = header.jku || header.x5u;
  if (jku && String(jku).toLowerCase().startsWith('http')) {
    findings.push({
      id: 'jku_external',
      severity: 'HIGH',
      title: 'External JWKS / Certificate URL (jku / x5u)',
      description: 'Token points to an external key server (' + jku + '). If untrusted URLs are fetched by the server, attackers can host their own keys and forge signatures (SSRF / Key Injection).',
      fix: 'Enforce a strict whitelist of allowed domains for "jku"/"x5u" endpoints, or configure key sets statically on the server.',
      mitre_id: MITRE_MAP.jku_external,
      evidence: 'header.jku/x5u = "' + jku + '"'
    });
  }

  // Calculate score and grade
  let score = 100;
  for (const f of findings) {
    score -= (SEVERITY_WEIGHTS[f.severity] || 0);
  }
  score = Math.max(0, score);

  let grade = 'F';
  if (score >= 90) grade = 'A';
  else if (score >= 75) grade = 'B';
  else if (score >= 60) grade = 'C';
  else if (score >= 40) grade = 'D';
  else grade = 'F';

  const severityRank = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4 };
  findings.sort((a, b) => (severityRank[a.severity] || 5) - (severityRank[b.severity] || 5));

  return {
    score,
    grade,
    header,
    payload,
    findings
  };
}

module.exports = {
  analyzeToken
};
