/**
 * VaultScan - Security Profiling & Secret Strength Analyzer (scoring.js)
 * Implements:
 * 1. Secret Strength Analyzer (entropy, diversity, dictionary match, pattern checks)
 * 2. Token Security Profile (4 Security Pillars: Authentication, Claims, Cryptography, Lifetime)
 */

const { WEAK_SECRETS } = require('./config');

/**
 * Calculates Shannon entropy of a string (bits per character)
 */
function calculateEntropy(str) {
  if (!str) return 0;
  const len = str.length;
  const freq = {};
  for (let i = 0; i < len; i++) {
    const ch = str[i];
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * len * 10) / 10; // Total entropy in bits
}

/**
 * Evaluates the cryptographic strength of an HMAC secret key
 * @param {string} secret - Secret passphrase or key
 */
function analyzeSecretStrength(secret) {
  if (!secret || typeof secret !== 'string') {
    return {
      strength: 'VERY WEAK',
      score: 0,
      reasons: ['No secret key provided or empty string.'],
      recommendation: 'Use a cryptographically generated 256-bit key (at least 32 random ASCII/hex characters).'
    };
  }

  const reasons = [];
  let score = 0;

  // 1. Dictionary Check
  const lower = secret.toLowerCase().trim();
  const isDictionary = WEAK_SECRETS.includes(lower);
  if (isDictionary) {
    reasons.push('Dictionary Match: Passphrase matches a widely known dictionary attack entry ("' + secret + '").');
  }

  // 2. Length Check
  if (secret.length < 8) {
    reasons.push('Critically short length (' + secret.length + ' chars). Keys under 8 characters can be brute-forced in milliseconds.');
    score += 5;
  } else if (secret.length < 16) {
    reasons.push('Short key length (' + secret.length + ' chars). Recommended minimum for HS256 is 32 characters (256 bits).');
    score += 20;
  } else if (secret.length < 32) {
    reasons.push('Moderate length (' + secret.length + ' chars). Sufficient for non-critical services, but recommended 32+ characters for high security.');
    score += 45;
  } else {
    score += 65;
  }

  // 3. Character Diversity
  const hasLower = /[a-z]/.test(secret);
  const hasUpper = /[A-Z]/.test(secret);
  const hasDigits = /[0-9]/.test(secret);
  const hasSpecial = /[^a-zA-Z0-9]/.test(secret);

  let diversityCount = 0;
  if (hasLower) diversityCount++;
  if (hasUpper) diversityCount++;
  if (hasDigits) diversityCount++;
  if (hasSpecial) diversityCount++;

  if (diversityCount === 1) {
    reasons.push('Poor character diversity: only uses one character set (e.g. only lowercase or only numbers).');
  } else if (diversityCount >= 3) {
    score += 20;
  }

  // 4. Repeated Characters & Predictable Sequences
  if (/(.)\1{2,}/.test(secret)) {
    reasons.push('Contains repetitive character sequences (e.g. "aaa", "111").');
    score -= 10;
  }
  if (/1234|abcd|qwerty|admin|pass/i.test(secret)) {
    reasons.push('Contains predictable keyboard or alphabet sequence.');
    score -= 15;
  }

  const entropyBits = calculateEntropy(secret);
  if (entropyBits < 40) {
    reasons.push('Low Shannon entropy (' + entropyBits + ' bits). Lacks randomness.');
  } else if (entropyBits >= 120) {
    score += 15;
  }

  score = Math.max(0, Math.min(100, score));

  // If in dictionary, cap strength at WEAK
  let strength = 'STRONG';
  if (isDictionary || score < 30) {
    strength = 'VERY WEAK';
  } else if (score < 55) {
    strength = 'WEAK';
  } else if (score < 80) {
    strength = 'MEDIUM';
  } else {
    strength = 'STRONG';
  }

  if (reasons.length === 0) {
    reasons.push('High entropy, adequate length (32+ chars), diverse character space.');
  }

  return {
    secret: secret.length > 20 ? secret.slice(0, 8) + '...' + secret.slice(-4) : secret,
    length: secret.length,
    entropyBits,
    score,
    strength,
    reasons,
    recommendation: strength === 'STRONG'
      ? 'Secret is sufficiently strong and resistant to offline dictionary and brute-force attacks.'
      : 'Generate an unguessable 256-bit secret using OpenSSL (e.g. openssl rand -hex 32).'
  };
}

/**
 * Builds the 4-Pillar Token Security Profile (0-100 each)
 * 1. Authentication Security
 * 2. Claim Security
 * 3. Cryptographic Security
 * 4. Token Lifetime Security
 */
function buildSecurityProfile(analysisResult) {
  const { header, payload, findings, score } = analysisResult;
  const findingIds = new Set((findings || []).map(f => f.id));

  // Pillar 1: Authentication Security (identity bound, not alg none, authentic issuer/audience)
  let authScore = 100;
  if (findingIds.has('alg_none')) authScore -= 60;
  if (findingIds.has('missing_iss')) authScore -= 20;
  if (findingIds.has('missing_aud')) authScore -= 20;
  authScore = Math.max(0, authScore);

  // Pillar 2: Claim Security (sensitive data exposure, excessive size)
  let claimScore = 100;
  for (const f of findings || []) {
    if (f.id.startsWith('sensitive_payload')) claimScore -= 35;
  }
  if (findingIds.has('large_payload')) claimScore -= 20;
  claimScore = Math.max(0, claimScore);

  // Pillar 3: Cryptographic Security (alg strength, weak secret, kid traversal, jku external)
  let cryptoScore = 100;
  if (findingIds.has('alg_none')) cryptoScore -= 70;
  if (findingIds.has('weak_secret')) cryptoScore -= 60;
  if (findingIds.has('alg_confusion')) cryptoScore -= 25;
  if (findingIds.has('kid_traversal')) cryptoScore -= 25;
  if (findingIds.has('jku_external')) cryptoScore -= 25;
  cryptoScore = Math.max(0, cryptoScore);

  // Pillar 4: Token Lifetime Security (exp claim, expired status, excessive duration)
  let lifetimeScore = 100;
  if (findingIds.has('missing_exp')) lifetimeScore -= 50;
  if (findingIds.has('expired')) lifetimeScore -= 30;
  if (findingIds.has('excessive_expiry')) lifetimeScore -= 20;
  lifetimeScore = Math.max(0, lifetimeScore);

  // Overall Risk Rating
  let overallRisk = 'LOW RISK';
  if (score < 40) overallRisk = 'CRITICAL RISK';
  else if (score < 60) overallRisk = 'HIGH RISK';
  else if (score < 80) overallRisk = 'MEDIUM RISK';

  return {
    overallRisk,
    pillars: {
      authentication: {
        score: authScore,
        label: 'Authentication Security',
        status: authScore >= 75 ? 'SECURE' : (authScore >= 50 ? 'WARNING' : 'COMPROMISED'),
        description: 'Identity attribution, issuer authority, and audience restriction'
      },
      claims: {
        score: claimScore,
        label: 'Claim Security',
        status: claimScore >= 75 ? 'SECURE' : (claimScore >= 50 ? 'WARNING' : 'COMPROMISED'),
        description: 'Protection of sensitive personal data and payload boundary management'
      },
      cryptography: {
        score: cryptoScore,
        label: 'Cryptographic Security',
        status: cryptoScore >= 75 ? 'SECURE' : (cryptoScore >= 50 ? 'WARNING' : 'COMPROMISED'),
        description: 'Signature algorithm integrity, secret entropy, and key locator security'
      },
      lifetime: {
        score: lifetimeScore,
        label: 'Token Lifetime Security',
        status: lifetimeScore >= 75 ? 'SECURE' : (lifetimeScore >= 50 ? 'WARNING' : 'COMPROMISED'),
        description: 'Session expiration boundaries and replay attack prevention window'
      }
    }
  };
}

module.exports = {
  analyzeSecretStrength,
  buildSecurityProfile,
  calculateEntropy
};
