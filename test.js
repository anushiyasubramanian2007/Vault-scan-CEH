/**
 * VaultScan - Comprehensive Automated Test Suite
 * Validates:
 * 1. Valid Hardened JWT
 * 2. Invalid / Malformed JWTs
 * 3. alg:none check
 * 4. Weak Secret Dictionary Attack
 * 5. Missing exp claim
 * 6. Expired token
 * 7. Excessive expiry (> 24 hours)
 * 8. Sensitive information in payload
 * 9. Missing issuer (iss)
 * 10. Missing audience (aud)
 * 11. Key ID (kid) path traversal
 * 12. External JKU / X5U
 * 13. Large token size (> 4KB)
 * 14. JWT Comparison Engine (Claims, Roles, Diff count)
 * 15. Tampering Simulator & Visual Flow
 * 16. Secret Strength Analyzer (Entropy, Dictionary, Diversity)
 * 17. 4-Pillar Security Profile Builder
 * 18. Recommendation & Score Improvement Engine
 * 19. Attack Scenario Lab
 * 20. Report Generator
 * 21. Edge Cases (Malformed Base64, Special Unicode, Empty inputs)
 */

const assert = require('assert');
const path = require('path');
const jwt = require('./node_modules/jsonwebtoken');

const { analyzeToken } = require('./analyzer');
const { decodeJwt, base64UrlDecode, isExpired, tryWeakSecrets } = require('./jwtUtils');
const { SEVERITY_WEIGHTS, WEAK_SECRETS } = require('./config');
const { compareTokens } = require('./comparison');
const { simulateTampering } = require('./tamperingLab');
const { analyzeSecretStrength, buildSecurityProfile } = require('./scoring');
const { buildImprovementPlan, getDetailedRecommendations, generateSecureExampleToken } = require('./recommendations');
const { LEARNING_CARDS, getAttackScenarios } = require('./learningData');
const { generateHtmlReport } = require('./reportGenerator');

const strongSecret = '9f7c4e2b8a1d5e6f3a7c9b0e2d4f6a8b1c3e5d7f9a0b2c4d6e8f1a3b5c7e9d0f';
let testsPassed = 0;
let testsFailed = 0;

function runTest(name, fn) {
  try {
    fn();
    console.log('  ✔ PASS: ' + name);
    testsPassed++;
  } catch (err) {
    console.error('  ✖ FAIL: ' + name);
    console.error('    ' + err.message);
    testsFailed++;
  }
}

console.log('========================================================');
console.log('🛡️  VAULTSCAN COMPREHENSIVE AUTOMATED TEST SUITE');
console.log('========================================================\n');

// 1. Valid Hardened JWT Test
runTest('1. Valid Hardened JWT (Score 100, Grade A)', () => {
  const token = jwt.sign(
    { sub: 'user_123', role: 'member' },
    strongSecret,
    {
      algorithm: 'HS256',
      expiresIn: '30m',
      issuer: 'https://auth.vaultscan.local',
      audience: 'https://api.vaultscan.local'
    }
  );
  const res = analyzeToken(token);
  assert.strictEqual(res.score, 100);
  assert.strictEqual(res.grade, 'A');
  assert.strictEqual(res.findings.length, 0);
});

// 2. Invalid & Malformed JWT Handling
runTest('2. Invalid & Malformed JWT (Graceful Error Handling)', () => {
  const invalidTokens = ['', 'not_a_jwt', 'header.payload', 'a.b.c.d', '!!!.@@@.###'];
  for (const t of invalidTokens) {
    const res = analyzeToken(t);
    assert.ok(res.error, 'Must report error object for invalid input');
    assert.strictEqual(res.score, 0);
    assert.strictEqual(res.grade, 'F');
    assert.ok(res.findings.some(f => f.id === 'malformed_jwt'));
  }
});

// 3. Check 1: alg:none
runTest('3. Check 1: alg:none Detection (CRITICAL)', () => {
  const b64 = (s) => Buffer.from(s).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const h = b64(JSON.stringify({ alg: 'none', typ: 'JWT' }));
  const p = b64(JSON.stringify({ sub: 'admin', iss: 'auth', aud: 'api', exp: Math.floor(Date.now()/1000) + 3600, iat: Math.floor(Date.now()/1000) }));
  const token = h + '.' + p + '.';

  const res = analyzeToken(token);
  const finding = res.findings.find(f => f.id === 'alg_none');
  assert.ok(finding);
  assert.strictEqual(finding.severity, 'CRITICAL');
  assert.strictEqual(finding.mitre_id, 'T1550.001');
});

// 4. Check 2: Weak HS256 Secret (Dictionary Attack)
runTest('4. Check 2: Weak HS256 Secret (CRITICAL, MITRE T1110.002)', () => {
  const token = jwt.sign({ sub: 'user_456', iss: 'auth', aud: 'api', exp: Math.floor(Date.now()/1000) + 1800, iat: Math.floor(Date.now()/1000) }, 'secret123');
  const res = analyzeToken(token);
  const finding = res.findings.find(f => f.id === 'weak_secret');
  assert.ok(finding);
  assert.strictEqual(finding.severity, 'CRITICAL');
});

// 5. Check 3: Algorithm Confusion
runTest('5. Check 3: Algorithm Confusion Warning (HIGH, MITRE T1550.001)', () => {
  const b64 = (s) => Buffer.from(s).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const h = b64(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const p = b64(JSON.stringify({ sub: 'user_rs', iss: 'auth', aud: 'api', exp: Math.floor(Date.now()/1000) + 1800, iat: Math.floor(Date.now()/1000) }));
  const token = h + '.' + p + '.fakesig';

  const res = analyzeToken(token);
  const finding = res.findings.find(f => f.id === 'alg_confusion');
  assert.ok(finding);
  assert.strictEqual(finding.severity, 'HIGH');
});

// 6. Check 4: Missing Expiration (exp)
runTest('6. Check 4: Missing exp Claim (HIGH)', () => {
  const token = jwt.sign({ sub: 'daemon', iss: 'auth', aud: 'api' }, strongSecret);
  const res = analyzeToken(token);
  const finding = res.findings.find(f => f.id === 'missing_exp');
  assert.ok(finding);
  assert.strictEqual(finding.severity, 'HIGH');
});

// 7. Check 5: Expired Token
runTest('7. Check 5: Expired Token Detection (MEDIUM)', () => {
  const pastTime = Math.floor(Date.now() / 1000) - 3600;
  const token = jwt.sign({ sub: 'usr_exp', iss: 'auth', aud: 'api', exp: pastTime, iat: pastTime - 1800 }, strongSecret);
  const res = analyzeToken(token);
  const finding = res.findings.find(f => f.id === 'expired');
  assert.ok(finding);
  assert.strictEqual(finding.severity, 'MEDIUM');
});

// 8. Check 6: Excessive Expiry (> 24 Hours)
runTest('8. Check 6: Excessive Expiration > 24 Hours (MEDIUM)', () => {
  const now = Math.floor(Date.now() / 1000);
  const token = jwt.sign({ sub: 'usr_long', iss: 'auth', aud: 'api', iat: now, exp: now + (86400 * 30) }, strongSecret);
  const res = analyzeToken(token);
  const finding = res.findings.find(f => f.id === 'excessive_expiry');
  assert.ok(finding);
  assert.strictEqual(finding.severity, 'MEDIUM');
});

// 9. Check 7: Sensitive Data in Payload
runTest('9. Check 7: Sensitive Data in Payload (HIGH, MITRE T1552.001)', () => {
  const token = jwt.sign(
    { sub: 'usr_sec', password: 'SecretPassword#1', ssn: '123-45-6789', iss: 'auth', aud: 'api', exp: Math.floor(Date.now()/1000) + 1800, iat: Math.floor(Date.now()/1000) },
    strongSecret
  );
  const res = analyzeToken(token);
  const pwdFinding = res.findings.find(f => f.id === 'sensitive_payload_password');
  const ssnFinding = res.findings.find(f => f.id === 'sensitive_payload_ssn');
  assert.ok(pwdFinding);
  assert.ok(ssnFinding);
});

// 10. Check 8 & 9: Missing Issuer and Audience
runTest('10. Check 8 & 9: Missing iss and aud Claims (LOW)', () => {
  const now = Math.floor(Date.now() / 1000);
  const token = jwt.sign({ sub: 'user_minimal', exp: now + 1800, iat: now }, strongSecret);
  const res = analyzeToken(token);
  assert.ok(res.findings.some(f => f.id === 'missing_iss'));
  assert.ok(res.findings.some(f => f.id === 'missing_aud'));
});

// 11. Check 10: Key ID (kid) Path Traversal
runTest('11. Check 10: kid Path Traversal (HIGH, MITRE T1083)', () => {
  const b64 = (s) => Buffer.from(s).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const h = b64(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: '../../../../etc/passwd' }));
  const p = b64(JSON.stringify({ sub: 'admin', iss: 'auth', aud: 'api', exp: Math.floor(Date.now()/1000) + 1800, iat: Math.floor(Date.now()/1000) }));
  const token = h + '.' + p + '.fakesig';
  const res = analyzeToken(token);
  assert.ok(res.findings.some(f => f.id === 'kid_traversal'));
});

// 12. Check 11: Large Payload Size (> 4KB)
runTest('12. Check 11: Large Token Size > 4KB (LOW)', () => {
  const hugeData = 'X'.repeat(4500);
  const token = jwt.sign({ sub: 'blob', data: hugeData, iss: 'auth', aud: 'api', exp: Math.floor(Date.now()/1000) + 1800, iat: Math.floor(Date.now()/1000) }, strongSecret);
  const res = analyzeToken(token);
  assert.ok(res.findings.some(f => f.id === 'large_payload'));
});

// 13. Check 12: External jku / x5u URLs
runTest('13. Check 12: External jku URL (HIGH, MITRE T1195)', () => {
  const b64 = (s) => Buffer.from(s).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const h = b64(JSON.stringify({ alg: 'RS256', typ: 'JWT', jku: 'http://evil.com/keys.json' }));
  const p = b64(JSON.stringify({ sub: 'target', iss: 'auth', aud: 'api', exp: Math.floor(Date.now()/1000) + 1800, iat: Math.floor(Date.now()/1000) }));
  const token = h + '.' + p + '.fakesig';
  const res = analyzeToken(token);
  assert.ok(res.findings.some(f => f.id === 'jku_external'));
});

// 14. JWT Comparison Engine
runTest('14. JWT Comparison Engine (Detect Role Escalation & Claim Diffs)', () => {
  const tokenA = jwt.sign({ sub: 'user_1', role: 'user', dept: 'HR' }, strongSecret);
  const tokenB = jwt.sign({ sub: 'user_1', role: 'admin', dept: 'Engineering', newClaim: 'added' }, strongSecret);
  const diff = compareTokens(tokenA, tokenB);

  assert.strictEqual(diff.changesCount >= 2, true);
  const roleDiff = diff.differences.find(d => d.type === 'PRIVILEGE_ESCALATION' || d.type === 'ROLE_CHANGED');
  assert.ok(roleDiff, 'Must detect role modification or privilege escalation');
  assert.strictEqual(diff.sizeDifference.delta !== undefined, true);
});

// 15. JWT Tampering Simulator
runTest('15. JWT Tampering Simulator (Payload Alteration & Rejection Flow)', () => {
  const original = jwt.sign({ sub: 'student_99', role: 'student' }, strongSecret);
  const tampered = simulateTampering(original, { role: 'admin' });

  assert.strictEqual(tampered.changes.length, 1);
  assert.strictEqual(tampered.changes[0].claim, 'role');
  assert.strictEqual(tampered.signatureStatus, 'SIGNATURE INVALID / NOT VERIFIED');
  assert.strictEqual(tampered.visualFlow.length, 4);
});

// 16. Secret Strength Analyzer
runTest('16. Secret Strength Analyzer (Entropy & Dictionary Match)', () => {
  const weakAnalysis = analyzeSecretStrength('secret123');
  assert.strictEqual(weakAnalysis.strength, 'VERY WEAK');
  assert.ok(weakAnalysis.reasons.some(r => r.includes('Dictionary Match')));

  const strongAnalysis = analyzeSecretStrength('X9#mK$2vL@pQ8!zW5^tR1*yU7&cB3(eN');
  assert.strictEqual(strongAnalysis.strength, 'STRONG');
  assert.ok(strongAnalysis.entropyBits > 100);
});

// 17. 4-Pillar Security Profile Builder
runTest('17. 4-Pillar Token Security Profile Builder', () => {
  const token = jwt.sign({ sub: 'usr_test', password: '123' }, 'secret123');
  const analysis = analyzeToken(token);
  const profile = buildSecurityProfile(analysis);

  assert.ok(profile.pillars.authentication);
  assert.ok(profile.pillars.claims);
  assert.ok(profile.pillars.cryptography);
  assert.ok(profile.pillars.lifetime);
  assert.ok(profile.pillars.cryptography.score < 50, 'Crypto pillar must reflect weak secret');
});

// 18. Recommendation & Score Improvement Engine
runTest('18. Recommendation & Score Improvement Engine', () => {
  const token = jwt.sign({ sub: 'usr_test' }, 'secret123');
  const analysis = analyzeToken(token);
  const plan = buildImprovementPlan(analysis);

  assert.ok(plan.potentialScore > plan.currentScore);
  assert.ok(plan.checklist.length > 0);

  const secureExample = generateSecureExampleToken();
  assert.strictEqual(secureExample.score, 100);
  assert.strictEqual(secureExample.grade, 'A');
});

// 19. Attack Scenario Lab
runTest('19. Attack Scenario Lab (Predefined Scenarios & Validation)', () => {
  const scenarios = getAttackScenarios();
  assert.strictEqual(scenarios.length >= 8, true);
  for (const s of scenarios) {
    assert.ok(s.id);
    assert.ok(s.token);
    const analysis = analyzeToken(s.token);
    assert.ok(analysis.findings.length > 0, 'Scenario ' + s.id + ' must trigger findings');
  }
});

// 20. Report Generator
runTest('20. Security Report Generator (HTML/PDF Structure)', () => {
  const token = jwt.sign({ sub: 'audit_target', role: 'admin' }, strongSecret);
  const analysis = analyzeToken(token);
  const html = generateHtmlReport(analysis, { rawToken: token });

  assert.ok(html.includes('VAULTSCAN'));
  assert.ok(html.includes('Executive Security Assessment'));
  assert.ok(html.includes('Security Profile Pillars'));
  assert.ok(html.includes('Detailed Security Findings'));
});

// 21. Edge Cases (Malformed Base64, Special Unicode, Empty inputs)
runTest('21. Edge Cases (Malformed Base64, Special Unicode, Empty inputs)', () => {
  const tokenUnicode = jwt.sign({ name: 'அனுஷியா', role: 'admin' }, strongSecret);
  const resUnicode = analyzeToken(tokenUnicode);
  assert.strictEqual(resUnicode.payload.name, 'அனுஷியா');

  const resEmpty = analyzeToken('');
  assert.strictEqual(resEmpty.grade, 'F');
});

console.log('\n========================================================');
console.log('RESULTS: ' + testsPassed + ' PASSED, ' + testsFailed + ' FAILED');
console.log('========================================================\n');

if (testsFailed > 0) {
  process.exit(1);
} else {
  console.log('✅ ALL COMPREHENSIVE VAULTSCAN TESTS PASSED SUCCESSFULLY.');
}
