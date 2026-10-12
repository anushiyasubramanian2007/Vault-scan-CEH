/**
 * VaultScan - Security Report Generator (reportGenerator.js)
 * Generates an executive-grade, printable HTML/PDF audit report
 * containing token metadata, decoded inspection, security profile,
 * findings matrix, MITRE ATT&CK mappings, and remediation checklist.
 */

const { buildSecurityProfile } = require('./scoring');
const { buildImprovementPlan } = require('./recommendations');

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Generates standalone printable HTML report
 */
function generateHtmlReport(analysisResult, options = {}) {
  const { score, grade, header, payload, findings, error } = analysisResult;
  const analysisId = 'VS-' + Date.now().toString(36).toUpperCase() + '-' + Math.floor(Math.random() * 1000);
  const reportDate = new Date().toUTCString();

  const profile = buildSecurityProfile(analysisResult);
  const improvement = buildImprovementPlan(analysisResult);

  const gradeColorMap = {
    A: '#4caf50',
    B: '#8bc34a',
    C: '#ffd700',
    D: '#ff8c00',
    F: '#ff2d2d'
  };
  const gradeColor = gradeColorMap[grade] || '#00d4ff';

  const severityColorMap = {
    CRITICAL: '#ff2d2d',
    HIGH: '#ff8c00',
    MEDIUM: '#ffd700',
    LOW: '#4caf50'
  };

  const rawToken = options.rawToken || '';
  const tokenTruncated = rawToken.length > 50
    ? rawToken.slice(0, 30) + '...' + rawToken.slice(-15)
    : (rawToken || '(omitted for confidentiality)');

  let findingsHtml = '';
  if (!findings || findings.length === 0) {
    findingsHtml = '<div class="no-findings">✅ No security vulnerabilities identified. Token satisfies standard hardening criteria.</div>';
  } else {
    findingsHtml = findings.map((f, i) => {
      const sevColor = severityColorMap[f.severity] || '#888';
      return `
      <div class="finding-card">
        <div class="finding-header">
          <span class="severity-badge" style="background-color: ${sevColor};">${escapeHtml(f.severity)}</span>
          <span class="finding-title">${escapeHtml(f.title)}</span>
          <span class="mitre-tag">${escapeHtml(f.mitre_id && f.mitre_id !== '—' ? 'MITRE ' + f.mitre_id : 'CWE / Hygiene')}</span>
        </div>
        <div class="finding-body">
          <p><strong>Description:</strong> ${escapeHtml(f.description)}</p>
          <p class="evidence-line"><strong>Evidence:</strong> <code>${escapeHtml(f.evidence)}</code></p>
          <div class="fix-box">
            <strong>🔧 Remediation:</strong> ${escapeHtml(f.fix)}
          </div>
        </div>
      </div>
      `;
    }).join('\n');
  }

  const checklistHtml = (improvement.checklist || []).map(item => {
    return `
    <li class="checklist-item">
      <span class="check-box">◽</span>
      <span class="check-title">${escapeHtml(item.fixTitle)}</span>
      <span class="point-badge">+${item.pointRecovery} pts</span>
    </li>
    `;
  }).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>VaultScan Security Audit Report - ${analysisId}</title>
  <style>
    @page { margin: 15mm; size: A4 portrait; }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: #1a202c;
      background: #f7fafc;
      line-height: 1.5;
      margin: 0;
      padding: 24px;
    }
    .report-container {
      max-width: 900px;
      margin: 0 auto;
      background: #ffffff;
      padding: 40px;
      border-radius: 8px;
      box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
      border-top: 6px solid #00d4ff;
    }
    .header-banner {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 2px solid #edf2f7;
      padding-bottom: 20px;
      margin-bottom: 30px;
    }
    .logo-area h1 { margin: 0; font-size: 26px; color: #0d1117; font-family: monospace; letter-spacing: 1px; }
    .logo-area p { margin: 4px 0 0; color: #718096; font-size: 13px; }
    .meta-box { text-align: right; font-size: 13px; color: #4a5568; }
    .meta-box strong { color: #2d3748; }

    .exec-summary {
      display: grid;
      grid-template-columns: 200px 1fr;
      gap: 24px;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 24px;
      margin-bottom: 30px;
    }
    .score-circle {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      border-right: 1px solid #e2e8f0;
      padding-right: 20px;
    }
    .grade-display { font-size: 56px; font-weight: 800; line-height: 1; color: ${gradeColor}; }
    .score-number { font-size: 20px; font-weight: 700; color: #2d3748; margin-top: 4px; }
    .risk-badge {
      display: inline-block;
      margin-top: 8px;
      padding: 4px 12px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 700;
      background: ${gradeColor}22;
      color: ${gradeColor};
      border: 1px solid ${gradeColor};
    }
    .summary-text h3 { margin: 0 0 10px; font-size: 18px; color: #2d3748; }
    .summary-text p { margin: 0 0 8px; font-size: 14px; color: #4a5568; }

    .pillars-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-bottom: 30px;
    }
    .pillar-card {
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      padding: 12px;
      text-align: center;
    }
    .pillar-title { font-size: 12px; font-weight: 700; color: #718096; margin-bottom: 4px; }
    .pillar-score { font-size: 22px; font-weight: 800; color: #2b6cb0; }
    .pillar-status { font-size: 11px; font-weight: 700; padding: 2px 6px; border-radius: 4px; display: inline-block; margin-top: 4px; }
    .status-SECURE { background: #c6f6d5; color: #22543d; }
    .status-WARNING { background: #fefcbf; color: #744210; }
    .status-COMPROMISED { background: #fed7d7; color: #742a2a; }

    .section-title {
      font-size: 18px;
      font-weight: 700;
      color: #2d3748;
      border-bottom: 2px solid #e2e8f0;
      padding-bottom: 8px;
      margin: 30px 0 16px;
    }

    .metadata-table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 24px;
      font-size: 13px;
    }
    .metadata-table th, .metadata-table td {
      border: 1px solid #e2e8f0;
      padding: 8px 12px;
      text-align: left;
    }
    .metadata-table th { background: #f7fafc; color: #4a5568; font-weight: 600; width: 25%; }
    .metadata-table td code { font-family: monospace; background: #edf2f7; padding: 2px 4px; border-radius: 3px; }

    .code-block {
      background: #0d1117;
      color: #c9d1d9;
      padding: 14px;
      border-radius: 6px;
      font-family: monospace;
      font-size: 12px;
      overflow-x: auto;
      margin-bottom: 20px;
    }

    .finding-card {
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      margin-bottom: 16px;
      overflow: hidden;
    }
    .finding-header {
      background: #f8fafc;
      padding: 10px 14px;
      display: flex;
      align-items: center;
      gap: 10px;
      border-bottom: 1px solid #e2e8f0;
    }
    .severity-badge {
      color: #ffffff;
      font-size: 11px;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 4px;
      text-transform: uppercase;
    }
    .finding-title { font-weight: 700; font-size: 14px; color: #2d3748; flex-grow: 1; }
    .mitre-tag { font-size: 11px; font-family: monospace; color: #4a5568; background: #edf2f7; padding: 2px 6px; border-radius: 4px; }
    .finding-body { padding: 14px; font-size: 13px; color: #4a5568; }
    .finding-body p { margin: 0 0 8px; }
    .evidence-line code { background: #edf2f7; color: #c53030; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
    .fix-box {
      background: #f0fff4;
      border: 1px solid #c6f6d5;
      color: #22543d;
      padding: 10px 12px;
      border-radius: 4px;
      margin-top: 10px;
    }

    .checklist-list { list-style: none; padding: 0; margin: 0; }
    .checklist-item {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 8px 12px;
      border-bottom: 1px solid #edf2f7;
      font-size: 13px;
    }
    .check-box { color: #a0aec0; font-size: 16px; }
    .check-title { flex-grow: 1; color: #2d3748; font-weight: 500; }
    .point-badge { background: #ebf8ff; color: #2b6cb0; font-weight: 700; font-size: 11px; padding: 2px 8px; border-radius: 4px; }

    .print-actions {
      margin-top: 30px;
      padding-top: 20px;
      border-top: 2px solid #edf2f7;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .print-btn {
      background: #00d4ff;
      color: #0d1117;
      border: none;
      font-weight: 700;
      padding: 10px 20px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 14px;
    }
    .print-btn:hover { background: #00b0d4; }
    .disclaimer { font-size: 11px; color: #a0aec0; }

    @media print {
      body { background: #ffffff; padding: 0; }
      .report-container { box-shadow: none; border-top: none; padding: 0; }
      .print-actions { display: none; }
    }
  </style>
</head>
<body>
  <div class="report-container">
    <div class="header-banner">
      <div class="logo-area">
        <h1>🛡️ VAULTSCAN</h1>
        <p>Advanced JWT Security Analysis & Compliance Audit</p>
      </div>
      <div class="meta-box">
        <div><strong>Report ID:</strong> ${analysisId}</div>
        <div><strong>Generated:</strong> ${reportDate}</div>
        <div><strong>Environment:</strong> Local Safe Analysis Mode</div>
      </div>
    </div>

    <div class="exec-summary">
      <div class="score-circle">
        <div class="grade-display">${grade}</div>
        <div class="score-number">${score} / 100</div>
        <div class="risk-badge">${profile.overallRisk}</div>
      </div>
      <div class="summary-text">
        <h3>Executive Security Assessment</h3>
        <p>VaultScan performed an offline cryptographic inspection and evaluated the target token against 12 RFC 7519 compliance checks, MITRE ATT&CK vectors, and dictionary attacks.</p>
        <p><strong>Findings Summary:</strong> ${findings ? findings.length : 0} issue(s) identified (${(findings || []).filter(f => f.severity === 'CRITICAL').length} Critical, ${(findings || []).filter(f => f.severity === 'HIGH').length} High, ${(findings || []).filter(f => f.severity === 'MEDIUM').length} Medium, ${(findings || []).filter(f => f.severity === 'LOW').length} Low).</p>
        <p><strong>Potential Score:</strong> Implementing recommended remediation can elevate this token's security score to <strong>${improvement.potentialScore} / 100 (Grade ${improvement.potentialGrade})</strong>.</p>
      </div>
    </div>

    <div class="section-title">Security Profile Pillars</div>
    <div class="pillars-grid">
      <div class="pillar-card">
        <div class="pillar-title">Authentication</div>
        <div class="pillar-score">${profile.pillars.authentication.score}</div>
        <div class="pillar-status status-${profile.pillars.authentication.status}">${profile.pillars.authentication.status}</div>
      </div>
      <div class="pillar-card">
        <div class="pillar-title">Claims & Data</div>
        <div class="pillar-score">${profile.pillars.claims.score}</div>
        <div class="pillar-status status-${profile.pillars.claims.status}">${profile.pillars.claims.status}</div>
      </div>
      <div class="pillar-card">
        <div class="pillar-title">Cryptography</div>
        <div class="pillar-score">${profile.pillars.cryptography.score}</div>
        <div class="pillar-status status-${profile.pillars.cryptography.status}">${profile.pillars.cryptography.status}</div>
      </div>
      <div class="pillar-card">
        <div class="pillar-title">Token Lifetime</div>
        <div class="pillar-score">${profile.pillars.lifetime.score}</div>
        <div class="pillar-status status-${profile.pillars.lifetime.status}">${profile.pillars.lifetime.status}</div>
      </div>
    </div>

    <div class="section-title">Token Metadata</div>
    <table class="metadata-table">
      <tr>
        <th>Algorithm (alg)</th>
        <td><code>${escapeHtml(header ? header.alg : 'none')}</code></td>
        <th>Type (typ)</th>
        <td><code>${escapeHtml(header ? header.typ : 'JWT')}</code></td>
      </tr>
      <tr>
        <th>Subject (sub)</th>
        <td>${escapeHtml(payload && payload.sub ? payload.sub : '(not present)')}</td>
        <th>Issuer (iss)</th>
        <td>${escapeHtml(payload && payload.iss ? payload.iss : '(missing)')}</td>
      </tr>
      <tr>
        <th>Audience (aud)</th>
        <td>${escapeHtml(payload && payload.aud ? payload.aud : '(missing)')}</td>
        <th>Expiration (exp)</th>
        <td>${payload && payload.exp ? new Date(payload.exp * 1000).toUTCString() : '<strong>Missing (Token never expires)</strong>'}</td>
      </tr>
      <tr>
        <th>Token Size</th>
        <td>${rawToken ? rawToken.length + ' bytes' : '(not provided)'}</td>
        <th>Signature Status</th>
        <td><strong style="color: #d69e2e;">NOT VERIFIED (Pure Inspection)</strong></td>
      </tr>
    </table>

    <div class="section-title">Decoded Header & Payload</div>
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
      <div>
        <h4 style="margin: 0 0 6px; font-size: 13px; color: #4a5568;">Header</h4>
        <div class="code-block">${escapeHtml(JSON.stringify(header || {}, null, 2))}</div>
      </div>
      <div>
        <h4 style="margin: 0 0 6px; font-size: 13px; color: #4a5568;">Payload</h4>
        <div class="code-block">${escapeHtml(JSON.stringify(payload || {}, null, 2))}</div>
      </div>
    </div>

    <div class="section-title">Detailed Security Findings</div>
    ${findingsHtml}

    <div class="section-title">Security Improvement Checklist</div>
    <ul class="checklist-list">
      ${checklistHtml}
    </ul>

    <div class="print-actions">
      <div class="disclaimer">
        🔒 VaultScan Local Analysis Mode: No secrets or raw tokens are stored externally. All calculations conducted offline.
      </div>
      <button class="print-btn" onclick="window.print()">🖨️ Print or Save as PDF</button>
    </div>
  </div>
</body>
</html>`;
}

module.exports = {
  generateHtmlReport
};
