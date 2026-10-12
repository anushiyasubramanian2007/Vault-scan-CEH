/**
 * VaultScan - Security Learning Mode & Attack Scenario Lab (learningData.js)
 * Implements:
 * 1. 12 Educational Flashcards (What is it, Why is it dangerous, Detection, Prevention)
 * 2. 8 Predefined Attack Scenarios with test token generators & validation specs
 */

const jwt = require('./node_modules/jsonwebtoken');

const LEARNING_CARDS = [
  {
    id: 'alg_none',
    title: 'Insecure Algorithm "none"',
    severity: 'CRITICAL',
    mitre: 'T1550.001 (Use Alternate Authentication Material)',
    whatIsIt: 'The "none" algorithm indicates that the JWT is intentionally unsigned. In RFC 7519, this was designed for environments where signature verification occurs through another channel, but in web applications, it means anyone can forge the token.',
    whyDangerous: 'If a backend accepts alg:none, an attacker can modify any claim (such as elevating role from "user" to "admin" or changing the user ID) and submit the token without a signature. The server treats the fabricated claims as authentic.',
    detectionMethod: 'VaultScan inspects the JWT header. If header.alg is equal to "none" (case-insensitive), it triggers an immediate critical alert.',
    howToPrevent: 'Explicitly whitelist approved cryptographic algorithms (e.g. HS256, RS256) in your backend verification library. Never let incoming tokens dictate the verification algorithm.',
    exampleCode: 'jwt.verify(token, secret, { algorithms: ["HS256"] }); // Rejects alg:none automatically'
  },
  {
    id: 'weak_secret',
    title: 'Weak HMAC Secret Key',
    severity: 'CRITICAL',
    mitre: 'T1110.002 (Brute Force: Password Cracking)',
    whatIsIt: 'HMAC algorithms (HS256, HS384, HS512) rely on a symmetric shared secret. A weak secret is a common word, short phrase, or default template key (e.g. "secret123", "password", "jwt").',
    whyDangerous: 'Because JWTs are self-contained and public, an attacker can capture one valid token and run offline dictionary or brute-force attacks at billions of guesses per second with tools like hashcat or John the Ripper. Once cracked, the attacker has the secret and can sign arbitrary tokens.',
    detectionMethod: 'VaultScan tests the token signature against an internal dictionary of common weak passwords and default development keys using local verification.',
    howToPrevent: 'Use a cryptographically generated 256-bit random secret (at least 32 characters or 64 hex characters) and load it exclusively from secure environment variables.',
    exampleCode: '// Terminal: openssl rand -hex 32\nconst secret = process.env.JWT_SECRET_KEY;'
  },
  {
    id: 'alg_confusion',
    title: 'Algorithm Confusion (RS256 → HS256)',
    severity: 'HIGH',
    mitre: 'T1550.001 (Use Alternate Authentication Material)',
    whatIsIt: 'Asymmetric algorithms (RS256) use a private key to sign and a public key to verify. Algorithm confusion occurs when a server accepts both RS256 and HS256 using the same verification function.',
    whyDangerous: 'Because the server public key is public, an attacker can take that public key, treat it as a symmetric HMAC secret, and sign an altered token using HS256. If the server does not enforce RS256, it verifies the HMAC signature using its own public key string and accepts the forged token.',
    detectionMethod: 'VaultScan flags tokens configured with RS/ES asymmetric algorithms if verification controls are missing or if unverified public keys can be leveraged.',
    howToPrevent: 'Never share the same verification handler for symmetric and asymmetric algorithms. Explicitly configure { algorithms: ["RS256"] } on the server.',
    exampleCode: 'jwt.verify(token, publicKey, { algorithms: ["RS256"] });'
  },
  {
    id: 'missing_exp',
    title: 'Missing "exp" (Expiration) Claim',
    severity: 'HIGH',
    mitre: 'N/A (CWE-613: Insufficient Session Expiration)',
    whatIsIt: 'The "exp" claim defines the UNIX timestamp after which the token must not be accepted for processing.',
    whyDangerous: 'A token without an expiration claim never expires. If the token is logged in proxy logs, stored in browser local storage, or intercepted via network sniffing, the compromised token grants permanent access indefinitely.',
    detectionMethod: 'VaultScan checks if the payload contains a valid numerical "exp" property.',
    howToPrevent: 'Always include an "exp" claim when creating tokens. Restrict access token lifespans to 15–60 minutes and implement refresh token rotation.',
    exampleCode: 'jwt.sign(payload, secret, { expiresIn: "1h" });'
  },
  {
    id: 'expired',
    title: 'Expired Token Accepted / In Use',
    severity: 'MEDIUM',
    mitre: 'N/A (Replay Attack Risk)',
    whatIsIt: 'The token contains an "exp" claim with a timestamp in the past.',
    whyDangerous: 'If client applications or servers continue processing expired tokens without error, session termination is ineffective and revoked or stale sessions can be replayed.',
    detectionMethod: 'VaultScan compares payload.exp against Math.floor(Date.now() / 1000).',
    howToPrevent: 'Enable strict clock verification in server middleware and handle TokenExpiredError gracefully by initiating a refresh cycle.',
    exampleCode: 'try { jwt.verify(token, secret); } catch (err) { if (err.name === "TokenExpiredError") { /* refresh */ } }'
  },
  {
    id: 'excessive_expiry',
    title: 'Excessive Expiration Duration (> 24 Hours)',
    severity: 'MEDIUM',
    mitre: 'N/A (Excessive Trust Window)',
    whatIsIt: 'The validity lifespan (exp - iat) exceeds 24 hours (86,400 seconds).',
    whyDangerous: 'Stateless JWTs cannot be easily revoked before they expire without stateful blacklisting. A 30-day or 1-year access token gives attackers an unacceptably wide window of opportunity if the client device or token is stolen.',
    detectionMethod: 'VaultScan calculates the difference between payload.exp and payload.iat and flags durations exceeding 86,400 seconds.',
    howToPrevent: 'Issue short-lived access tokens (15–60 minutes) combined with secure HTTP-only refresh tokens stored in a revocable database store.',
    exampleCode: 'jwt.sign(claims, secret, { expiresIn: "30m" });'
  },
  {
    id: 'sensitive_payload',
    title: 'Sensitive Plaintext Data in Payload',
    severity: 'HIGH',
    mitre: 'T1552.001 (Credentials in Files/Payloads)',
    whatIsIt: 'The payload contains passwords, Social Security Numbers, credit cards, or API secrets.',
    whyDangerous: 'A common misconception is that JWTs encrypt data. JWT payloads are only Base64URL-encoded JSON. Anyone who can see the token (users, browser extensions, proxy logs, CDN logs) can decode and view the sensitive data instantly without the secret.',
    detectionMethod: 'VaultScan scans payload keys and values against regex patterns for passwords, SSNs, credit cards, emails, phone numbers, and API tokens.',
    howToPrevent: 'Never place confidential credentials or sensitive PII in JWT payloads. Store only opaque user identifiers (e.g. sub: "usr_9410") and retrieve profile details from the database server-side.',
    exampleCode: '// Store only identity references:\nconst payload = { sub: user.id, role: user.role };'
  },
  {
    id: 'missing_iss',
    title: 'Missing "iss" (Issuer) Claim',
    severity: 'LOW',
    mitre: 'N/A (CWE-287: Improper Authentication)',
    whatIsIt: 'The "iss" claim identifies the principal or authorization server that issued the JWT.',
    whyDangerous: 'In multi-service or microservice architectures, an API cannot confirm which authority generated the credential, increasing the risk of unauthorized token reuse across disparate environments.',
    detectionMethod: 'VaultScan verifies whether payload.iss exists and is non-empty.',
    howToPrevent: 'Include a standard issuer URI when signing, and validate it in API gateway middleware.',
    exampleCode: 'jwt.sign(payload, secret, { issuer: "https://auth.example.com" });'
  },
  {
    id: 'missing_aud',
    title: 'Missing "aud" (Audience) Claim',
    severity: 'LOW',
    mitre: 'N/A (Confused Deputy Risk)',
    whatIsIt: 'The "aud" claim identifies the recipients or target API endpoints for which the JWT is intended.',
    whyDangerous: 'Without audience restrictions, a token issued for a low-privilege service (e.g. public comments API) could be replayed against a high-privilege billing or admin API if both use the same signing authority.',
    detectionMethod: 'VaultScan checks for the presence of payload.aud.',
    howToPrevent: 'Include the specific API identifier in "aud" and reject tokens targeted to other microservices.',
    exampleCode: 'jwt.verify(token, secret, { audience: "https://api.example.com/billing" });'
  },
  {
    id: 'kid_traversal',
    title: 'Key ID ("kid") Path Traversal',
    severity: 'HIGH',
    mitre: 'T1083 (File and Directory Discovery)',
    whatIsIt: 'The "kid" (Key ID) header parameter indicates which key in a key store should be used for signature verification.',
    whyDangerous: 'If backend code retrieves keys by concatenating the "kid" value into a filesystem path (e.g. /etc/keys/ + kid), an attacker can supply "../../../../dev/null" or a known static file. This forces the server to verify the signature against an empty string or known content, allowing trivial signature forgery.',
    detectionMethod: 'VaultScan inspects header.kid for directory traversal sequences ("../", "..\\", "/", "\\").',
    howToPrevent: 'Sanitize the "kid" input strictly or look up keys using a pre-populated Map/database rather than constructing direct filesystem file paths.',
    exampleCode: 'const key = KEY_MAP[header.kid]; if (!key) throw new Error("Invalid key ID");'
  },
  {
    id: 'large_payload',
    title: 'Excessive Token Size (> 4KB)',
    severity: 'LOW',
    mitre: 'N/A (Performance / Denial of Service)',
    whatIsIt: 'The raw encoded JWT string exceeds 4,096 bytes.',
    whyDangerous: 'Because JWTs are transmitted with every HTTP request in the "Authorization: Bearer <token>" header or cookies, excessive size wastes network bandwidth, degrades mobile performance, and triggers HTTP 431 "Request Header Fields Too Large" errors in proxies like Nginx or AWS CloudFront.',
    detectionMethod: 'VaultScan checks raw token length against a 4,096-byte threshold.',
    howToPrevent: 'Store only minimal authentication claims in the JWT. Keep the total token size below 1–2KB.',
    exampleCode: '// Minimize token payload; fetch large datasets via separate API calls'
  },
  {
    id: 'jku_external',
    title: 'External JKU / X5U Key Endpoint',
    severity: 'HIGH',
    mitre: 'T1195 (Supply Chain Compromise: Remote Key Injection)',
    whatIsIt: 'The "jku" (JWK Set URL) or "x5u" (X.509 URL) header parameter specifies a URL where the public key for verifying the token is hosted.',
    whyDangerous: 'If an application fetches the verification key from arbitrary external URLs without whitelisting, an attacker can generate their own public/private key pair, host the public key on their own server, and point jku to that URL. The target server fetches the attacker key, verifies the forged token, and grants access.',
    detectionMethod: 'VaultScan checks if header.jku or header.x5u points to an external HTTP/HTTPS address.',
    howToPrevent: 'Enforce a strict domain whitelist for all JWKS endpoints, or pre-configure key sets statically on the server.',
    exampleCode: 'const ALLOWED_HOSTS = ["auth.mycompany.com"];\nconst url = new URL(header.jku);\nif (!ALLOWED_HOSTS.includes(url.hostname)) throw new Error("Untrusted JWKS host");'
  }
];

/**
 * Returns 8 Predefined Attack Scenarios with test tokens and verification specs
 */
function getAttackScenarios() {
  const strongSecret = '9f7c4e2b8a1d5e6f3a7c9b0e2d4f6a8b1c3e5d7f9a0b2c4d6e8f1a3b5c7e9d0f';
  const now = Math.floor(Date.now() / 1000);

  const b64 = (s) => Buffer.from(s).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  // 1. Weak Secret
  const tokenWeak = jwt.sign(
    { sub: 'usr_dev_33', role: 'developer', iat: now, exp: now + 3600, iss: 'auth', aud: 'api' },
    'secret123',
    { algorithm: 'HS256' }
  );

  // 2. alg:none
  const noneH = b64(JSON.stringify({ alg: 'none', typ: 'JWT' }));
  const noneP = b64(JSON.stringify({ sub: 'admin_usr', role: 'admin', iss: 'auth', aud: 'api', iat: now, exp: now + 3600 }));
  const tokenNone = noneH + '.' + noneP + '.';

  // 3. Missing exp
  const tokenNoExp = jwt.sign(
    { sub: 'usr_service_cron', role: 'daemon', iat: now, iss: 'auth', aud: 'api' },
    strongSecret,
    { algorithm: 'HS256' }
  );

  // 4. Expired token
  const tokenExpired = jwt.sign(
    { sub: 'usr_session_old', role: 'customer', iat: now - 7200, exp: now - 3600, iss: 'auth', aud: 'api' },
    strongSecret,
    { algorithm: 'HS256' }
  );

  // 5. Sensitive data
  const tokenSensitive = jwt.sign(
    {
      sub: 'usr_patient_99',
      role: 'patient',
      password: 'MyPlainTextPassword2026',
      ssn: '987-65-4321',
      iat: now,
      exp: now + 1800,
      iss: 'auth',
      aud: 'api'
    },
    strongSecret,
    { algorithm: 'HS256' }
  );

  // 6. Alg confusion
  const rsH = b64(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const rsP = b64(JSON.stringify({ sub: 'usr_confused', role: 'user', iss: 'auth', aud: 'api', iat: now, exp: now + 1800 }));
  const tokenConfusion = rsH + '.' + rsP + '.dummy_asymmetric_signature';

  // 7. kid traversal
  const kidH = b64(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: '../../../../dev/null' }));
  const kidP = b64(JSON.stringify({ sub: 'attacker_root', role: 'root', iss: 'auth', aud: 'api', iat: now, exp: now + 1800 }));
  const tokenKid = kidH + '.' + kidP + '.forged_signature';

  // 8. External JKU
  const jkuH = b64(JSON.stringify({ alg: 'RS256', typ: 'JWT', jku: 'http://malicious-keys.attacker.net/jwks.json' }));
  const jkuP = b64(JSON.stringify({ sub: 'target_account', role: 'admin', iss: 'auth', aud: 'api', iat: now, exp: now + 1800 }));
  const tokenJku = jkuH + '.' + jkuP + '.forged_sig';

  return [
    {
      id: 'scenario_weak_secret',
      title: 'Scenario 1: Weak Secret Dictionary Attack',
      description: 'Developer used a common passphrase ("secret123") to sign the token. Attackers can brute-force the key offline in seconds.',
      token: tokenWeak,
      expectedVulnerability: 'weak_secret (CRITICAL)',
      expectedScore: 60,
      expectedGrade: 'C',
      mitre: 'T1110.002',
      fix: 'Use a random 256-bit secret generated via crypto.randomBytes(32).'
    },
    {
      id: 'scenario_alg_none',
      title: 'Scenario 2: Signature Bypass via alg:none',
      description: 'An attacker tampers with the header, sets "alg": "none", elevates their role to "admin", and drops the signature.',
      token: tokenNone,
      expectedVulnerability: 'alg_none (CRITICAL)',
      expectedScore: 60,
      expectedGrade: 'C',
      mitre: 'T1550.001',
      fix: 'Reject alg:none unconditionally and whitelist allowed algorithms on the server.'
    },
    {
      id: 'scenario_missing_exp',
      title: 'Scenario 3: Replay Risk via Missing Expiration',
      description: 'The authentication server omitted the "exp" claim. The token is perpetually valid, enabling unlimited replay if stolen.',
      token: tokenNoExp,
      expectedVulnerability: 'missing_exp (HIGH)',
      expectedScore: 75,
      expectedGrade: 'B',
      mitre: 'CWE-613',
      fix: 'Always specify an expiration claim (15–60 minutes recommended).'
    },
    {
      id: 'scenario_expired',
      title: 'Scenario 4: Stale Session / Expired Token',
      description: 'Token expired 1 hour ago. Simulates a request presenting an expired credential.',
      token: tokenExpired,
      expectedVulnerability: 'expired (MEDIUM)',
      expectedScore: 90,
      expectedGrade: 'A',
      mitre: 'CWE-613',
      fix: 'Require re-authentication or refresh token exchange.'
    },
    {
      id: 'scenario_sensitive_payload',
      title: 'Scenario 5: Plaintext Credential Exposure',
      description: 'Developers stored plaintext passwords and SSN inside the JWT payload, exposing private credentials to anyone who reads the token.',
      token: tokenSensitive,
      expectedVulnerability: 'sensitive_payload (HIGH)',
      expectedScore: 50,
      expectedGrade: 'D',
      mitre: 'T1552.001',
      fix: 'Store only opaque user identifiers; never store secrets in JWT payloads.'
    },
    {
      id: 'scenario_alg_confusion',
      title: 'Scenario 6: Key Confusion (RS256 → HS256)',
      description: 'Token specifies asymmetric RS256 algorithm. Vulnerable verifiers might verify HMAC signatures using the public key string.',
      token: tokenConfusion,
      expectedVulnerability: 'alg_confusion (HIGH)',
      expectedScore: 75,
      expectedGrade: 'B',
      mitre: 'T1550.001',
      fix: 'Pin { algorithms: ["RS256"] } explicitly in verification options.'
    },
    {
      id: 'scenario_kid_traversal',
      title: 'Scenario 7: Key ID (kid) Directory Traversal',
      description: 'Token header injects "../../../../dev/null" into the kid parameter, attempting to trick file-based key lookup routines.',
      token: tokenKid,
      expectedVulnerability: 'kid_traversal (HIGH)',
      expectedScore: 75,
      expectedGrade: 'B',
      mitre: 'T1083',
      fix: 'Sanitize kid values and look up keys from a key map dictionary rather than filesystem paths.'
    },
    {
      id: 'scenario_jku_external',
      title: 'Scenario 8: Remote Key Injection via External JKU',
      description: 'Token points to an attacker-controlled external JWKS endpoint (http://malicious-keys.attacker.net/jwks.json).',
      token: tokenJku,
      expectedVulnerability: 'jku_external (HIGH) + alg_confusion (HIGH)',
      expectedScore: 50,
      expectedGrade: 'D',
      mitre: 'T1195',
      fix: 'Enforce domain whitelisting on all remote key retrieval endpoints.'
    }
  ];
}

module.exports = {
  LEARNING_CARDS,
  getAttackScenarios
};
