/**
 * VaultScan - Advanced JWT Security Analysis & Learning Platform
 * Express Server and REST API Architecture
 */

const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');

// Core Modules
const { analyzeToken } = require('./analyzer');
const { base64UrlDecode } = require('./jwtUtils');
const { compareTokens } = require('./comparison');
const { simulateTampering } = require('./tamperingLab');
const { analyzeSecretStrength, buildSecurityProfile } = require('./scoring');
const { buildImprovementPlan, getDetailedRecommendations, generateSecureExampleToken } = require('./recommendations');
const { LEARNING_CARDS, getAttackScenarios } = require('./learningData');
const { generateHtmlReport } = require('./reportGenerator');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/static', express.static(path.join(__dirname, 'static')));
app.use(express.static(path.join(__dirname, 'static')));

// In-Memory Storage (Preserved for safe local session)
let history = [];
let dashboardStats = {
  totalAnalyzed: 0,
  scoreSum: 0,
  highestScore: 0,
  lowestScore: 100,
  criticalCount: 0,
  highCount: 0,
  mediumCount: 0,
  lowCount: 0,
  grades: { A: 0, B: 0, C: 0, D: 0, F: 0 }
};

function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Update aggregate dashboard statistics
 */
function recordAnalysisStats(result) {
  const score = result.score || 0;
  dashboardStats.totalAnalyzed++;
  dashboardStats.scoreSum += score;
  if (score > dashboardStats.highestScore) dashboardStats.highestScore = score;
  if (score < dashboardStats.lowestScore) dashboardStats.lowestScore = score;

  const grade = result.grade || 'F';
  if (dashboardStats.grades[grade] !== undefined) {
    dashboardStats.grades[grade]++;
  }

  for (const f of result.findings || []) {
    if (f.severity === 'CRITICAL') dashboardStats.criticalCount++;
    else if (f.severity === 'HIGH') dashboardStats.highCount++;
    else if (f.severity === 'MEDIUM') dashboardStats.mediumCount++;
    else if (f.severity === 'LOW') dashboardStats.lowCount++;
  }
}

// ==========================================
// 1. Core Endpoints (Preserved)
// ==========================================

/**
 * Root route - Serve Web UI
 */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'templates', 'index.html'));
});

/**
 * POST /api/analyze - Single token security audit
 */
app.post('/api/analyze', (req, res) => {
  const { token } = req.body;
  if (!token || typeof token !== 'string') {
    return res.status(400).json({ error: 'Please provide a valid token string in { token }' });
  }

  const trimmedToken = token.trim();
  const result = analyzeToken(trimmedToken);

  // Enrich with advanced modules
  const profile = buildSecurityProfile(result);
  const improvement = buildImprovementPlan(result);
  const detailedRecommendations = getDetailedRecommendations(result.findings);

  const enrichedResult = {
    ...result,
    profile,
    improvement,
    recommendations: detailedRecommendations
  };

  // Record into history
  const historyItem = {
    id: Date.now().toString(),
    timestamp: new Date().toLocaleTimeString(),
    tokenTruncated: trimmedToken.slice(0, 30) + '...',
    score: result.score,
    grade: result.grade,
    findingsCount: result.findings ? result.findings.length : 0,
    overallRisk: profile.overallRisk
  };

  history.unshift(historyItem);
  if (history.length > 20) {
    history = history.slice(0, 20);
  }

  recordAnalysisStats(result);

  return res.json(enrichedResult);
});

/**
 * POST /api/analyze-bulk - Analyze multiple tokens simultaneously
 */
app.post('/api/analyze-bulk', (req, res) => {
  const { tokens } = req.body;
  if (!Array.isArray(tokens)) {
    return res.status(400).json({ error: 'Please provide an array of tokens in { tokens: [] }' });
  }

  const results = tokens.map((t, idx) => {
    const analysis = analyzeToken(String(t).trim());
    const profile = buildSecurityProfile(analysis);
    recordAnalysisStats(analysis);
    return {
      index: idx,
      tokenTruncated: String(t).trim().slice(0, 25) + '...',
      score: analysis.score,
      grade: analysis.grade,
      findingsCount: analysis.findings ? analysis.findings.length : 0,
      overallRisk: profile.overallRisk,
      analysis
    };
  });

  return res.json({
    total: results.length,
    results
  });
});

/**
 * GET /api/history - Retrieve last 20 analysis entries
 */
app.get('/api/history', (req, res) => {
  return res.json({
    count: history.length,
    history
  });
});

/**
 * DELETE /api/history - Reset analysis history
 */
app.delete('/api/history', (req, res) => {
  history = [];
  return res.json({ success: true, message: 'Audit history cleared successfully' });
});

/**
 * GET /api/generate-test - Generate sample demonstration tokens
 */
app.get('/api/generate-test', (req, res) => {
  const strongSecret = '9f7c4e2b8a1d5e6f3a7c9b0e2d4f6a8b1c3e5d7f9a0b2c4d6e8f1a3b5c7e9d0f';
  const now = Math.floor(Date.now() / 1000);

  // 1. Perfect token
  const perfectToken = jwt.sign(
    { sub: 'usr_secure_9841', role: 'auditor', department: 'Infosec' },
    strongSecret,
    {
      algorithm: 'HS256',
      expiresIn: '45m',
      issuer: 'https://vaultscan.security.internal',
      audience: 'https://api.vaultscan.security.internal'
    }
  );

  // 2. alg:none token
  const noneHeader = base64UrlEncode(JSON.stringify({ alg: 'none', typ: 'JWT' }));
  const nonePayload = base64UrlEncode(
    JSON.stringify({
      sub: 'admin_root',
      user: 'admin',
      role: 'superuser',
      iss: 'https://vaultscan.security.internal',
      aud: 'https://api.vaultscan.security.internal',
      exp: now + 3600,
      iat: now
    })
  );
  const algNoneToken = noneHeader + '.' + nonePayload + '.';

  // 3. Weak secret token (HS256 with dictionary key 'secret123')
  const weakSecretToken = jwt.sign(
    { sub: 'dev_analyst_2', role: 'developer' },
    'secret123',
    { algorithm: 'HS256', expiresIn: '2h', issuer: 'auth-service', audience: 'dev-api' }
  );

  // 4. No expiry token
  const noExpiryToken = jwt.sign(
    { sub: 'service_worker_cron', role: 'daemon', iat: now },
    strongSecret,
    { algorithm: 'HS256', noTimestamp: false, issuer: 'auth-service', audience: 'worker-api' }
  );

  // 5. Sensitive data in payload (password + SSN)
  const sensitiveToken = jwt.sign(
    {
      sub: 'usr_patient_552',
      password: 'PlainPassword#2026',
      ssn: '458-12-9904',
      email: 'alex.security@targetcorp.com'
    },
    strongSecret,
    { algorithm: 'HS256', expiresIn: '30m', issuer: 'portal', audience: 'user-service' }
  );

  // 6. Multiple Vulnerabilities Token
  const multiVulnToken = jwt.sign(
    {
      sub: 'usr_bad_99',
      password: 'hunter2',
      ssn: '000-11-2222',
      role: 'admin'
    },
    'password', // weak secret
    { algorithm: 'HS256' } // no expiry, no iss, no aud
  );

  const samples = [
    {
      label: 'Perfect Token (Hardened)',
      token: perfectToken,
      expected_grade: 'A',
      notes: 'Strong 256-bit secret, exp within 1h, proper iss and aud claims.'
    },
    {
      label: 'Critical: Insecure alg:none',
      token: algNoneToken,
      expected_grade: 'F',
      notes: 'Signature verification completely omitted (alg: none).'
    },
    {
      label: 'Critical: Weak Secret Key',
      token: weakSecretToken,
      expected_grade: 'F',
      notes: 'Signed using common dictionary passphrase "secret123".'
    },
    {
      label: 'High: Missing Expiry (exp)',
      token: noExpiryToken,
      expected_grade: 'D',
      notes: 'Never expires, permanently reusable if intercepted.'
    },
    {
      label: 'High: Plaintext Sensitive Data',
      token: sensitiveToken,
      expected_grade: 'D',
      notes: 'Contains exposed password and SSN in Base64-readable payload.'
    },
    {
      label: 'Critical: Multiple Flaws Combined',
      token: multiVulnToken,
      expected_grade: 'F',
      notes: 'Weak secret + sensitive password/SSN + no expiration + no issuer/aud.'
    }
  ];

  return res.json(samples);
});

// ==========================================
// 2. Advanced Feature Endpoints
// ==========================================

/**
 * POST /api/compare - JWT Comparison Engine (Feature 1)
 */
app.post('/api/compare', (req, res) => {
  const { tokenA, tokenB } = req.body;
  if (!tokenA || !tokenB) {
    return res.status(400).json({ error: 'Please provide both tokenA and tokenB in request body.' });
  }

  const comparison = compareTokens(String(tokenA).trim(), String(tokenB).trim());
  return res.json(comparison);
});

/**
 * POST /api/tamper - JWT Tampering Simulator (Feature 2)
 */
app.post('/api/tamper', (req, res) => {
  const { originalToken, modifiedClaims, mode } = req.body;
  if (!originalToken) {
    return res.status(400).json({ error: 'Please provide originalToken in request body.' });
  }

  const result = simulateTampering(String(originalToken).trim(), modifiedClaims || {}, mode || 'preserve_signature');
  return res.json(result);
});

/**
 * GET /api/dashboard - Security Dashboard Metrics & Trend (Feature 4 & 5)
 */
app.get('/api/dashboard', (req, res) => {
  const total = dashboardStats.totalAnalyzed;
  const avgScore = total > 0 ? Math.round(dashboardStats.scoreSum / total) : 0;

  // Trend analysis based on history
  const trendScores = history.map(h => h.score).reverse(); // chronological order
  let trendDirection = 'Stable';
  if (trendScores.length >= 2) {
    const firstHalf = trendScores.slice(0, Math.floor(trendScores.length / 2));
    const secondHalf = trendScores.slice(Math.floor(trendScores.length / 2));
    const avg1 = firstHalf.reduce((a, b) => a + b, 0) / firstHalf.length;
    const avg2 = secondHalf.reduce((a, b) => a + b, 0) / secondHalf.length;
    if (avg2 - avg1 > 5) trendDirection = 'Improving';
    else if (avg1 - avg2 > 5) trendDirection = 'Declining';
  }

  return res.json({
    metrics: {
      totalAnalyzed: total,
      averageScore: avgScore,
      highestScore: total > 0 ? dashboardStats.highestScore : 0,
      lowestScore: total > 0 ? dashboardStats.lowestScore : 0,
      criticalFindings: dashboardStats.criticalCount,
      highFindings: dashboardStats.highCount,
      mediumFindings: dashboardStats.mediumCount,
      lowFindings: dashboardStats.lowCount,
      grades: dashboardStats.grades
    },
    trend: {
      direction: trendDirection,
      recentScores: trendScores,
      historyCount: history.length
    }
  });
});

/**
 * POST /api/secret-strength - Secret Strength Analyzer (Feature 3)
 */
app.post('/api/secret-strength', (req, res) => {
  const { secret } = req.body;
  const analysis = analyzeSecretStrength(secret || '');
  return res.json(analysis);
});

/**
 * GET /api/learning - Security Learning Cards (Feature 8)
 */
app.get('/api/learning', (req, res) => {
  return res.json({
    count: LEARNING_CARDS.length,
    cards: LEARNING_CARDS
  });
});

/**
 * GET /api/scenarios - Attack Scenario Lab (Feature 9)
 */
app.get('/api/scenarios', (req, res) => {
  const scenarios = getAttackScenarios();
  return res.json({
    count: scenarios.length,
    scenarios
  });
});

/**
 * POST /api/scenarios/run - Run pre-configured Attack Scenario
 */
app.post('/api/scenarios/run', (req, res) => {
  const { scenarioId } = req.body;
  const scenarios = getAttackScenarios();
  const scenario = scenarios.find(s => s.id === scenarioId);
  if (!scenario) {
    return res.status(404).json({ error: 'Scenario not found: ' + scenarioId });
  }

  const analysis = analyzeToken(scenario.token);
  const profile = buildSecurityProfile(analysis);
  const improvement = buildImprovementPlan(analysis);

  return res.json({
    scenario,
    analysis,
    profile,
    improvement
  });
});

/**
 * GET /api/secure-example - Show Secure Example (Feature 6)
 */
app.get('/api/secure-example', (req, res) => {
  const example = generateSecureExampleToken();
  return res.json(example);
});

/**
 * POST /api/report - Generate Standalone Printable HTML Security Report (Feature 7)
 */
app.post('/api/report', (req, res) => {
  const { token, analysisResult } = req.body;
  let analysis = analysisResult;

  if (!analysis && token) {
    analysis = analyzeToken(String(token).trim());
  }

  if (!analysis) {
    return res.status(400).json({ error: 'Please supply a token or analysisResult to generate report.' });
  }

  const htmlReport = generateHtmlReport(analysis, { rawToken: token });

  // If query format=html, render directly as webpage, else return JSON with html string
  if (req.query.format === 'html' || req.headers.accept?.includes('text/html')) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.send(htmlReport);
  }

  return res.json({
    success: true,
    html: htmlReport
  });
});

/**
 * POST /api/clear-all - Privacy / Safe Analysis Mode (Feature 12)
 * Clears current token, history, dashboard statistics, and caches
 */
app.post('/api/clear-all', (req, res) => {
  history = [];
  dashboardStats = {
    totalAnalyzed: 0,
    scoreSum: 0,
    highestScore: 0,
    lowestScore: 100,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    grades: { A: 0, B: 0, C: 0, D: 0, F: 0 }
  };

  return res.json({
    success: true,
    message: 'All local session data, history, and dashboard counters cleared successfully.'
  });
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
  console.log('====================================================');
  console.log('🛡️  VAULTSCAN — Advanced JWT Security Platform');
  console.log('📡  Server is running at: http://localhost:' + PORT);
  console.log('⚡  Active Modules: Analyzer | Compare | Tamper | Dashboard');
  console.log('📚  Learning Lab | Reports | Secret Strength | Privacy Mode');
  console.log('====================================================');
});
