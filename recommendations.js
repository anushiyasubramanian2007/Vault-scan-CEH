/**
 * VaultScan - Security Recommendation & Score Improvement Engine (recommendations.js)
 * Implements:
 * 1. "Improve My Score" recommendation simulator & checklist
 * 2. Secure demonstration JWT generator
 * 3. Rule-based offline remediation advice engine with code snippets
 */

const jwt = require('./node_modules/jsonwebtoken');
const { SEVERITY_WEIGHTS } = require('./config');

const RULE_RECOMMENDATIONS = {
  alg_none: {
    problem: 'Algorithm set to "none" (Unsigned / Spoofed Token)',
    whyItMatters: 'Anyone can forge claims, elevate themselves to administrator, or alter identity without needing any cryptographic secret.',
    recommendedAction: 'Enforce algorithm whitelisting in your server verification middleware. Explicitly reject "none" or unapproved ciphers.',
    priority: 'CRITICAL',
    codeSnippet: '// Server-side verification fix (Node.js / Express):\njwt.verify(token, process.env.JWT_SECRET, {\n  algorithms: ["HS256"] // Whitelist only approved algorithms\n});'
  },
  weak_secret: {
    problem: 'Weak HS256 Secret Key (Dictionary / Brute-Force Vulnerability)',
    whyItMatters: 'Attackers can crack the secret key offline in seconds using standard password lists (e.g. rockyou.txt) and forge legitimate-looking tokens.',
    recommendedAction: 'Rotate to a cryptographically strong 256-bit random secret. Store it securely in environment variables or a secrets manager.',
    priority: 'CRITICAL',
    codeSnippet: '// Generate a strong 256-bit secret via terminal:\n// openssl rand -hex 32\n\n// In .env:\n// JWT_SECRET=8e9b4c2a1f0d3e5b7a9c1e3f5d7b9a1c3e5d7f9a0b2c4d6e8f1a3b5c7e9d0f1a'
  },
  alg_confusion: {
    problem: 'Algorithm Confusion Risk (Public Key as HMAC Secret)',
    whyItMatters: 'If the server verifies tokens without pinning the algorithm to asymmetric RS256, an attacker can re-sign the token using HMAC-SHA256 with the server public key.',
    recommendedAction: 'Pin algorithms explicitly in the jwt.verify options and strictly distinguish symmetric vs asymmetric verification routines.',
    priority: 'HIGH',
    codeSnippet: 'jwt.verify(token, publicKey, {\n  algorithms: ["RS256"] // Explicitly prevent fallback to HMAC\n});'
  },
  missing_exp: {
    problem: 'Missing Expiration ("exp") Claim',
    whyItMatters: 'Tokens without an expiration date remain valid perpetually. If leaked from browser storage or logs, attackers maintain permanent access.',
    recommendedAction: 'Always configure an exp claim. For access tokens, use 15 minutes to 1 hour; pair with rotating refresh tokens.',
    priority: 'HIGH',
    codeSnippet: 'jwt.sign(payload, secret, {\n  expiresIn: "1h" // Sets "exp" claim automatically\n});'
  },
  expired: {
    problem: 'Token Already Expired',
    whyItMatters: 'Requests presenting expired credentials should be blocked to prevent replay attacks and stale session utilization.',
    recommendedAction: 'Prompt the user to re-authenticate or trigger a secure refresh token rotation flow.',
    priority: 'MEDIUM',
    codeSnippet: '// Middleware error handling:\ntry {\n  const decoded = jwt.verify(token, secret);\n} catch (err) {\n  if (err.name === "TokenExpiredError") {\n    return res.status(401).json({ error: "Session expired. Please refresh token." });\n  }\n}'
  },
  excessive_expiry: {
    problem: 'Excessive Expiration Duration (> 24 Hours)',
    whyItMatters: 'Long validity periods expand the window of opportunity for attackers if a token is intercepted in logs, proxies, or XSS attacks.',
    recommendedAction: 'Shorten access token lifespan to 1 hour or less. Use secure HTTP-only refresh cookies for session continuity.',
    priority: 'MEDIUM',
    codeSnippet: 'jwt.sign(payload, secret, {\n  expiresIn: "30m" // Keep access token lifetime concise\n});'
  },
  missing_iss: {
    problem: 'Missing Issuer ("iss") Claim',
    whyItMatters: 'Without an issuer claim, services cannot verify which authentication authority or domain generated the token.',
    recommendedAction: 'Add an "iss" claim pointing to your identity provider domain and verify it in API gateways.',
    priority: 'LOW',
    codeSnippet: 'jwt.sign(payload, secret, {\n  issuer: "https://auth.mycompany.com"\n});\n\n// Verifier:\njwt.verify(token, secret, {\n  issuer: "https://auth.mycompany.com"\n});'
  },
  missing_aud: {
    problem: 'Missing Audience ("aud") Claim',
    whyItMatters: 'Without an audience claim, a token issued for one microservice could be replayed against other internal APIs.',
    recommendedAction: 'Include an "aud" claim specifying the targeted resource or API endpoint.',
    priority: 'LOW',
    codeSnippet: 'jwt.sign(payload, secret, {\n  audience: "https://api.mycompany.com"\n});\n\n// Verifier:\njwt.verify(token, secret, {\n  audience: "https://api.mycompany.com"\n});'
  },
  kid_traversal: {
    problem: 'Key ID ("kid") Path Traversal Vulnerability',
    whyItMatters: 'Attackers manipulate the kid header to force filesystem lookup into predictable files (e.g. /dev/null or static files) with known contents.',
    recommendedAction: 'Never pass kid directly to filesystem paths. Look up keys from an in-memory dictionary or database with strict sanitization.',
    priority: 'HIGH',
    codeSnippet: 'const keyMap = { "key-2026-v1": process.env.KEY_V1 };\nconst safeKey = keyMap[header.kid];\nif (!safeKey) throw new Error("Unknown Key ID");'
  },
  large_payload: {
    problem: 'Excessive Token Size (> 4KB)',
    whyItMatters: 'Bloated tokens degrade HTTP performance and can trigger HTTP 431 Request Header Fields Too Large errors in reverse proxies.',
    recommendedAction: 'Store only minimal identity claims (sub, roles). Fetch verbose profile data from cache/database on the server.',
    priority: 'LOW',
    codeSnippet: '// Bad: storing full user profile, address, and shopping cart in JWT\n// Good: storing only minimal identifiers\nconst payload = { sub: user.id, role: user.role };'
  },
  jku_external: {
    problem: 'External JKU / X5U Key Server Reference',
    whyItMatters: 'If your server fetches public keys from unverified external URLs, attackers can host malicious keys and sign forged tokens (SSRF / Key Spoofing).',
    recommendedAction: 'Strictly whitelist allowed domains for jku/x5u, or pre-configure trust stores and local JWKS sets.',
    priority: 'HIGH',
    codeSnippet: 'const ALLOWED_JWKS = ["https://auth.mycompany.com/.well-known/jwks.json"];\nif (!ALLOWED_JWKS.includes(header.jku)) {\n  throw new Error("Untrusted JWKS endpoint");\n}'
  }
};

/**
 * Generates an improvement plan and potential score recalculation
 */
function buildImprovementPlan(analysisResult) {
  const { score, grade, findings } = analysisResult;
  const checklist = [];
  let potentialScore = score;

  for (const f of findings || []) {
    let fixTitle = '';
    let pointRecovery = SEVERITY_WEIGHTS[f.severity] || 0;

    if (f.id === 'alg_none') {
      fixTitle = 'Enforce signed algorithm (reject alg:none)';
    } else if (f.id === 'weak_secret') {
      fixTitle = 'Rotate to a 256-bit cryptographically random secret';
    } else if (f.id === 'alg_confusion') {
      fixTitle = 'Pin allowed algorithms explicitly during verification';
    } else if (f.id === 'missing_exp') {
      fixTitle = 'Add "exp" expiration claim (e.g. 15m to 1h)';
    } else if (f.id === 'expired') {
      fixTitle = 'Refresh expired session with unexpired access token';
    } else if (f.id === 'excessive_expiry') {
      fixTitle = 'Reduce access token lifetime to ≤ 1 hour';
    } else if (f.id.startsWith('sensitive_payload')) {
      fixTitle = 'Remove sensitive plaintext credentials/PII from payload';
    } else if (f.id === 'missing_iss') {
      fixTitle = 'Add "iss" (issuer) authority claim';
    } else if (f.id === 'missing_aud') {
      fixTitle = 'Add "aud" (audience) destination service claim';
    } else if (f.id === 'kid_traversal') {
      fixTitle = 'Sanitize "kid" header and use whitelist lookup';
    } else if (f.id === 'large_payload') {
      fixTitle = 'Prune unnecessary payload claims to keep size < 4KB';
    } else if (f.id === 'jku_external') {
      fixTitle = 'Whitelist or pre-configure trusted JWKS endpoints';
    } else {
      fixTitle = f.title;
    }

    potentialScore += pointRecovery;

    checklist.push({
      findingId: f.id,
      severity: f.severity,
      fixTitle,
      pointRecovery,
      resolved: false
    });
  }

  potentialScore = Math.min(100, potentialScore);

  let potentialGrade = 'A';
  if (potentialScore < 40) potentialGrade = 'F';
  else if (potentialScore < 60) potentialGrade = 'D';
  else if (potentialScore < 75) potentialGrade = 'C';
  else if (potentialScore < 90) potentialGrade = 'B';

  return {
    currentScore: score,
    currentGrade: grade,
    potentialScore,
    potentialGrade,
    checklist,
    recommendationsNotice: 'This is an educational recommendation simulation. Changes must be implemented in your backend token issuance configuration.'
  };
}

/**
 * Returns prioritized rule-based recommendations for all findings
 */
function getDetailedRecommendations(findings) {
  const recommendations = [];

  for (const f of findings || []) {
    let key = f.id;
    if (key.startsWith('sensitive_payload')) {
      key = 'sensitive_payload';
    }

    if (RULE_RECOMMENDATIONS[key]) {
      recommendations.push({
        findingId: f.id,
        severity: f.severity,
        ...RULE_RECOMMENDATIONS[key]
      });
    } else if (key === 'sensitive_payload') {
      recommendations.push({
        findingId: f.id,
        severity: 'HIGH',
        problem: 'Sensitive Information Stored in Plaintext Payload',
        whyItMatters: 'JWT payloads are only Base64URL encoded, not encrypted. Anyone who inspects the token can read passwords, SSNs, or keys in plaintext.',
        recommendedAction: 'Strip sensitive credentials from the token. Store only user IDs and fetch sensitive state server-side.',
        priority: 'HIGH',
        codeSnippet: '// Bad: jwt.sign({ password: user.password }, secret)\n// Good: jwt.sign({ sub: user.id }, secret)'
      });
    }
  }

  return recommendations;
}

/**
 * Generates a hardened, secure demonstration token
 */
function generateSecureExampleToken() {
  const strongSecret = '9f7c4e2b8a1d5e6f3a7c9b0e2d4f6a8b1c3e5d7f9a0b2c4d6e8f1a3b5c7e9d0f';
  const now = Math.floor(Date.now() / 1000);

  const payload = {
    sub: 'usr_sec_demo_2026',
    role: 'auditor',
    department: 'CyberSecurity',
    iss: 'https://vaultscan.security.internal',
    aud: 'https://api.vaultscan.security.internal',
    iat: now,
    exp: now + 1800 // 30 minutes
  };

  const token = jwt.sign(payload, strongSecret, {
    algorithm: 'HS256'
  });

  return {
    token,
    header: { alg: 'HS256', typ: 'JWT' },
    payload,
    score: 100,
    grade: 'A',
    description: 'This is a hardened, production-ready JWT configuration using HS256 with a 256-bit random secret, 30-minute expiration, authentic issuer, audience claim, and zero sensitive data.'
  };
}

module.exports = {
  buildImprovementPlan,
  getDetailedRecommendations,
  generateSecureExampleToken,
  RULE_RECOMMENDATIONS
};
