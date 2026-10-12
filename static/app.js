/**
 * VaultScan - Core Application Controller (static/app.js)
 * Manages Tabbed Navigation, JWT Security Auditing, Conic Gauge Rendering,
 * Security Profile Pillars, Score Improvement Checklist, and Privacy Mode.
 */

window.AppModule = (() => {
  // DOM References
  let jwtInput, charCounter, btnAnalyze, btnLoadTest, sampleDropdown, btnClear;
  let riskPanel, scoreGauge, scoreValue, letterGrade, summaryLine, riskHeadline;
  let findingsPanel, findingsCountBadge, findingsList;
  let decodedPanel, headerJson, payloadJson, sigStatusBar;
  let profilePanel, pillarAuth, pillarClaims, pillarCrypto, pillarLifetime;
  let improvementPanel, potentialScoreBadge, improvementChecklist;
  let historyTableBody, btnClearHistory, btnClearAllData;
  let toastEl;

  document.addEventListener('DOMContentLoaded', () => {
    initDOMElements();
    initTabNavigation();
    initCoreAnalyzer();
    initHistory();
    initPrivacyMode();

    // Initialize Submodules
    if (window.ComparisonModule) window.ComparisonModule.init();
    if (window.TamperingModule) window.TamperingModule.init();
    if (window.LearningModule) window.LearningModule.init();
    if (window.ReportsModule) window.ReportsModule.init();
    if (window.DashboardModule) window.DashboardModule.refresh();
  });

  function initDOMElements() {
    jwtInput = document.getElementById('jwtInput');
    charCounter = document.getElementById('charCounter');
    btnAnalyze = document.getElementById('btnAnalyze');
    btnLoadTest = document.getElementById('btnLoadTest');
    sampleDropdown = document.getElementById('sampleDropdown');
    btnClear = document.getElementById('btnClear');

    riskPanel = document.getElementById('riskPanel');
    scoreGauge = document.getElementById('scoreGauge');
    scoreValue = document.getElementById('scoreValue');
    letterGrade = document.getElementById('letterGrade');
    summaryLine = document.getElementById('summaryLine');
    riskHeadline = document.getElementById('riskHeadline');

    findingsPanel = document.getElementById('findingsPanel');
    findingsCountBadge = document.getElementById('findingsCountBadge');
    findingsList = document.getElementById('findingsList');

    decodedPanel = document.getElementById('decodedPanel');
    headerJson = document.getElementById('headerJson');
    payloadJson = document.getElementById('payloadJson');
    sigStatusBar = document.getElementById('sigStatusBar');

    profilePanel = document.getElementById('profilePanel');
    pillarAuth = document.getElementById('pillarAuth');
    pillarClaims = document.getElementById('pillarClaims');
    pillarCrypto = document.getElementById('pillarCrypto');
    pillarLifetime = document.getElementById('pillarLifetime');

    improvementPanel = document.getElementById('improvementPanel');
    potentialScoreBadge = document.getElementById('potentialScoreBadge');
    improvementChecklist = document.getElementById('improvementChecklist');

    historyTableBody = document.getElementById('historyTableBody');
    btnClearHistory = document.getElementById('btnClearHistory');
    btnClearAllData = document.getElementById('btnClearAllData');
    toastEl = document.getElementById('toast');
  }

  // Tab Navigation Controller
  function initTabNavigation() {
    const tabBtns = document.querySelectorAll('.nav-tab');
    tabBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-tab');
        switchTab(targetId);
      });
    });

    // Quick Action shortcuts from dashboard
    document.querySelectorAll('[data-goto-tab]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const target = btn.getAttribute('data-goto-tab');
        switchTab(target);
      });
    });
  }

  function switchTab(tabId) {
    document.querySelectorAll('.nav-tab').forEach(b => {
      b.classList.toggle('active', b.getAttribute('data-tab') === tabId);
    });

    document.querySelectorAll('.tab-content-section').forEach(sec => {
      sec.classList.toggle('hidden', sec.id !== tabId);
    });

    window.scrollTo({ top: 0, behavior: 'smooth' });

    if (tabId === 'tab-dashboard' && window.DashboardModule) {
      window.DashboardModule.refresh();
    } else if (tabId === 'tab-history') {
      fetchHistory();
    }
  }

  // Core JWT Analyzer
  function initCoreAnalyzer() {
    if (jwtInput) {
      jwtInput.addEventListener('input', () => {
        const count = jwtInput.value.length;
        if (charCounter) charCounter.textContent = `${count} characters`;
      });
    }

    if (btnAnalyze) {
      btnAnalyze.addEventListener('click', () => runAnalysis());
    }

    if (btnClear) {
      btnClear.addEventListener('click', () => {
        if (jwtInput) {
          jwtInput.value = '';
          jwtInput.dispatchEvent(new Event('input'));
        }
        hideResults();
      });
    }

    if (btnLoadTest) {
      btnLoadTest.addEventListener('click', (e) => {
        e.stopPropagation();
        toggleSampleDropdown();
      });
    }

    document.addEventListener('click', () => {
      if (sampleDropdown && !sampleDropdown.classList.contains('hidden')) {
        sampleDropdown.classList.add('hidden');
      }
    });

    const btnShowSecureEx = document.getElementById('btnShowSecureEx');
    if (btnShowSecureEx) {
      btnShowSecureEx.addEventListener('click', loadSecureExample);
    }
  }

  async function toggleSampleDropdown() {
    if (!sampleDropdown) return;
    if (!sampleDropdown.classList.contains('hidden')) {
      sampleDropdown.classList.add('hidden');
      return;
    }

    sampleDropdown.innerHTML = '<div class="sample-item text-muted">Generating fresh test tokens...</div>';
    sampleDropdown.classList.remove('hidden');

    try {
      const res = await fetch('/api/generate-test');
      const samples = await res.json();

      sampleDropdown.innerHTML = '';
      samples.forEach(s => {
        const item = document.createElement('div');
        item.className = 'sample-item';
        item.innerHTML = `
          <div class="sample-label">${escapeHtml(s.label)}</div>
          <div class="sample-notes">${escapeHtml(s.notes)} (Exp: Grade ${s.expected_grade})</div>
        `;
        item.addEventListener('click', () => {
          if (jwtInput) {
            jwtInput.value = s.token;
            jwtInput.dispatchEvent(new Event('input'));
          }
          sampleDropdown.classList.add('hidden');
          runAnalysis();
        });
        sampleDropdown.appendChild(item);
      });
    } catch (e) {
      sampleDropdown.innerHTML = '<div class="sample-item text-muted">Error generating test samples</div>';
    }
  }

  async function runAnalysis() {
    if (!jwtInput) return;
    const token = jwtInput.value.trim();
    if (!token) {
      showToast('Please paste a JWT string into the input area.');
      jwtInput.focus();
      return;
    }

    try {
      btnAnalyze.disabled = true;
      btnAnalyze.textContent = 'Auditing Token...';

      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });

      const data = await res.json();
      displayResults(data);
      fetchHistory();
      if (window.DashboardModule) window.DashboardModule.refresh();
    } catch (err) {
      alert('Error communicating with security analyzer engine: ' + err.message);
    } finally {
      btnAnalyze.disabled = false;
      btnAnalyze.textContent = 'Analyze Token';
    }
  }

  function displayResults(data) {
    if (data.error && (!data.findings || data.findings.length === 0)) {
      alert('Malformed Token Error: ' + data.error);
      return;
    }

    // 1. Reveal panels
    if (riskPanel) riskPanel.classList.remove('hidden');
    if (findingsPanel) findingsPanel.classList.remove('hidden');
    if (decodedPanel) decodedPanel.classList.remove('hidden');
    if (profilePanel) profilePanel.classList.remove('hidden');
    if (improvementPanel) improvementPanel.classList.remove('hidden');

    // 2. Risk Score & Gauge
    animateScoreGauge(data.score, data.grade);
    if (summaryLine) {
      const f = data.findings || [];
      const crit = f.filter(x => x.severity === 'CRITICAL').length;
      const high = f.filter(x => x.severity === 'HIGH').length;
      const med = f.filter(x => x.severity === 'MEDIUM').length;
      const low = f.filter(x => x.severity === 'LOW').length;
      summaryLine.textContent = `Identified ${f.length} issue(s): ${crit} CRITICAL, ${high} HIGH, ${med} MEDIUM, ${low} LOW`;
    }

    // 3. Security Profile 4 Pillars
    if (data.profile) {
      renderSecurityProfile(data.profile);
    }

    // 4. Render Findings Cards
    renderFindings(data.findings || []);

    // 5. Improvement Checklist
    if (data.improvement) {
      renderImprovementPlan(data.improvement);
    }

    // 6. Decoded JSON Header & Payload
    if (headerJson) headerJson.innerHTML = syntaxHighlightJson(data.header || {});
    if (payloadJson) payloadJson.innerHTML = syntaxHighlightJson(data.payload || {});
    if (sigStatusBar) {
      sigStatusBar.innerHTML = `<span class="sig-warning">⚠️ Signature: NOT VERIFIED (Pure offline inspection without server secret)</span>`;
    }

    riskPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function renderSecurityProfile(profile) {
    const { overallRisk, pillars } = profile;
    if (riskHeadline) {
      riskHeadline.textContent = `Security Assessment: ${overallRisk}`;
    }

    const updatePillar = (elem, pillar) => {
      if (!elem || !pillar) return;
      const val = elem.querySelector('.pillar-score-val');
      const bar = elem.querySelector('.pillar-progress-fill');
      const tag = elem.querySelector('.pillar-status-tag');
      if (val) val.textContent = pillar.score;
      if (bar) bar.style.width = pillar.score + '%';
      if (tag) {
        tag.textContent = pillar.status;
        tag.className = 'pillar-status-tag tag-' + pillar.status.toLowerCase();
      }
    };

    updatePillar(pillarAuth, pillars.authentication);
    updatePillar(pillarClaims, pillars.claims);
    updatePillar(pillarCrypto, pillars.cryptography);
    updatePillar(pillarLifetime, pillars.lifetime);
  }

  function renderImprovementPlan(plan) {
    if (!potentialScoreBadge || !improvementChecklist) return;
    potentialScoreBadge.textContent = `Current: ${plan.currentScore} / 100 → Potential: ${plan.potentialScore} / 100 (Grade ${plan.potentialGrade})`;

    if (!plan.checklist || plan.checklist.length === 0) {
      improvementChecklist.innerHTML = '<li class="checklist-row text-success">✅ Token satisfies hardening requirements. No action needed!</li>';
      return;
    }

    improvementChecklist.innerHTML = plan.checklist.map(item => `
      <li class="checklist-row">
        <label class="check-box-wrapper">
          <input type="checkbox" onchange="AppModule.toggleCheckItem(this, ${item.pointRecovery}, ${plan.currentScore})">
          <span class="custom-check"></span>
          <span class="check-text">${escapeHtml(item.fixTitle)}</span>
        </label>
        <span class="recov-pill">+${item.pointRecovery} pts</span>
      </li>
    `).join('');
  }

  function toggleCheckItem(chk, recovery, current) {
    const checkboxes = document.querySelectorAll('.checklist-row input[type="checkbox"]');
    let simulatedGain = 0;
    checkboxes.forEach(c => {
      if (c.checked) {
        const pill = c.closest('.checklist-row').querySelector('.recov-pill');
        if (pill) {
          const pts = parseInt(pill.textContent.replace(/[^0-9]/g, '')) || 0;
          simulatedGain += pts;
        }
      }
    });

    const newSimScore = Math.min(100, current + simulatedGain);
    if (potentialScoreBadge) {
      potentialScoreBadge.textContent = `Current: ${current} / 100 → Simulated: ${newSimScore} / 100`;
    }
  }

  function renderFindings(findings) {
    if (!findingsList) return;
    if (findingsCountBadge) {
      findingsCountBadge.textContent = `${findings.length} Issue${findings.length === 1 ? '' : 's'} Found`;
    }

    if (findings.length === 0) {
      findingsList.innerHTML = `
        <div class="empty-findings-box">
          <div class="check-icon">🛡️</div>
          <h3>Zero Vulnerabilities Detected</h3>
          <p>This token adheres to secure JWT configuration standards: strong algorithm, expiration bounded, and identity claims bound.</p>
        </div>
      `;
      return;
    }

    findingsList.innerHTML = findings.map((f, i) => {
      const isCritical = f.severity === 'CRITICAL';
      const sevClass = 'sev-' + f.severity.toLowerCase();
      const openClass = isCritical ? 'open' : '';
      const mitreBadge = f.mitre_id && f.mitre_id !== '—'
        ? `<span class="mitre-tag">MITRE ${escapeHtml(f.mitre_id)}</span>`
        : '';

      return `
        <div class="finding-card ${sevClass} ${openClass}" id="finding_${i}">
          <div class="finding-card-header" onclick="AppModule.toggleFindingCard('${i}')">
            <span class="sev-badge badge-${f.severity.toLowerCase()}">${escapeHtml(f.severity)}</span>
            <span class="finding-card-title">${escapeHtml(f.title)}</span>
            ${mitreBadge}
            <span class="chevron-icon">▼</span>
          </div>
          <div class="finding-card-content">
            <p class="finding-description">${escapeHtml(f.description)}</p>
            <div class="evidence-box">
              <span class="box-label">EVIDENCE:</span>
              <code>${escapeHtml(f.evidence)}</code>
            </div>
            <div class="fix-box">
              <div class="fix-header">
                <span class="box-label">🔧 RECOMMENDED FIX:</span>
                <button class="btn-copy-fix" onclick="AppModule.copyFixText('${i}')">Copy Fix</button>
              </div>
              <p class="fix-text" id="fixText_${i}">${escapeHtml(f.fix)}</p>
            </div>
          </div>
        </div>
      `;
    }).join('');
  }

  function toggleFindingCard(idx) {
    const card = document.getElementById('finding_' + idx);
    if (card) card.classList.toggle('open');
  }

  function copyFixText(idx) {
    const fixEl = document.getElementById('fixText_' + idx);
    if (!fixEl) return;
    navigator.clipboard.writeText(fixEl.textContent).then(() => {
      showToast('Fix instructions copied to clipboard!');
    });
  }

  async function loadSecureExample() {
    try {
      const res = await fetch('/api/secure-example');
      const data = await res.json();
      if (jwtInput) {
        jwtInput.value = data.token;
        jwtInput.dispatchEvent(new Event('input'));
      }
      runAnalysis();
    } catch (e) {
      alert('Could not fetch secure example: ' + e.message);
    }
  }

  function animateScoreGauge(score, grade) {
    if (!scoreGauge || !scoreValue || !letterGrade) return;

    let gradeColor = '#00d4ff';
    if (grade === 'A') gradeColor = '#4caf50';
    else if (grade === 'B') gradeColor = '#8bc34a';
    else if (grade === 'C') gradeColor = '#ffd700';
    else if (grade === 'D') gradeColor = '#ff8c00';
    else if (grade === 'F') gradeColor = '#ff2d2d';

    letterGrade.textContent = grade;
    letterGrade.style.color = gradeColor;

    let current = 0;
    const duration = 800;
    const stepTime = 16;
    const steps = duration / stepTime;
    const increment = score / steps;

    const timer = setInterval(() => {
      current += increment;
      if (current >= score) {
        current = score;
        clearInterval(timer);
      }
      scoreValue.textContent = Math.round(current);
      const angle = (current / 100) * 360;
      scoreGauge.style.background = `conic-gradient(${gradeColor} 0deg ${angle}deg, #1c212c ${angle}deg 360deg)`;
    }, stepTime);
  }

  function hideResults() {
    if (riskPanel) riskPanel.classList.add('hidden');
    if (findingsPanel) findingsPanel.classList.add('hidden');
    if (decodedPanel) decodedPanel.classList.add('hidden');
    if (profilePanel) profilePanel.classList.add('hidden');
    if (improvementPanel) improvementPanel.classList.add('hidden');
  }

  // History Module
  function initHistory() {
    if (btnClearHistory) {
      btnClearHistory.addEventListener('click', async () => {
        if (!confirm('Clear recent token analysis history?')) return;
        await fetch('/api/history', { method: 'DELETE' });
        fetchHistory();
        if (window.DashboardModule) window.DashboardModule.refresh();
      });
    }
  }

  async function fetchHistory() {
    if (!historyTableBody) return;
    try {
      const res = await fetch('/api/history');
      const data = await res.json();
      const list = data.history || [];

      if (list.length === 0) {
        historyTableBody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No analysis records in current session.</td></tr>';
        return;
      }

      historyTableBody.innerHTML = list.map(item => `
        <tr>
          <td>${item.timestamp}</td>
          <td><code class="tok-preview">${escapeHtml(item.tokenTruncated)}</code></td>
          <td><span class="badge-grade grade-${item.grade.toLowerCase()}">${item.grade}</span></td>
          <td><strong>${item.score}/100</strong></td>
          <td><span class="risk-pill">${item.overallRisk || 'N/A'}</span></td>
        </tr>
      `).join('');
    } catch (e) {
      console.warn('History fetch error:', e);
    }
  }

  // Privacy Mode / Clear All Data (Feature 12)
  function initPrivacyMode() {
    if (btnClearAllData) {
      btnClearAllData.addEventListener('click', async () => {
        if (!confirm('Execute Privacy Wipe? This resets all history, clear inputs, and wipes dashboard metrics.')) return;
        try {
          await fetch('/api/clear-all', { method: 'POST' });
          if (jwtInput) {
            jwtInput.value = '';
            jwtInput.dispatchEvent(new Event('input'));
          }
          hideResults();
          fetchHistory();
          if (window.ComparisonModule) window.ComparisonModule.clearInputs();
          if (window.DashboardModule) window.DashboardModule.refresh();
          showToast('Local session data and metrics successfully wiped.');
        } catch (e) {
          alert('Error clearing session: ' + e.message);
        }
      });
    }
  }

  function showToast(msg) {
    if (!toastEl) return;
    toastEl.textContent = msg;
    toastEl.classList.remove('hidden');
    setTimeout(() => { toastEl.classList.add('hidden'); }, 3000);
  }

  function syntaxHighlightJson(jsonObj) {
    const str = JSON.stringify(jsonObj, null, 2);
    return str.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, match => {
      let cls = 'number';
      if (/^"/.test(match)) {
        if (/:$/.test(match)) {
          cls = 'key';
        } else {
          cls = 'string';
        }
      } else if (/true|false/.test(match)) {
        cls = 'boolean';
      } else if (/null/.test(match)) {
        cls = 'null';
      }
      return `<span class="json-${cls}">${match}</span>`;
    });
  }

  function escapeHtml(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  return {
    switchTab,
    toggleFindingCard,
    copyFixText,
    toggleCheckItem,
    loadSecureExample
  };
})();
