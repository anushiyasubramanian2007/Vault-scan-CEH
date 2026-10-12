/**
 * VaultScan - Learning Mode & Security Lab Controller (static/learning.js)
 * Manages:
 * 1. 12 Educational Vulnerability Flashcards
 * 2. Predefined Attack Scenario Lab Runner
 * 3. Secret Strength & Entropy Analyzer
 */

window.LearningModule = (() => {
  let cachedCards = [];
  let cachedScenarios = [];

  function init() {
    loadLearningCards();
    loadAttackScenarios();

    const searchInput = document.getElementById('learningSearchInput');
    if (searchInput) {
      searchInput.addEventListener('input', () => {
        filterCards(searchInput.value.trim().toLowerCase());
      });
    }

    const btnTestSecret = document.getElementById('btnTestSecret');
    if (btnTestSecret) {
      btnTestSecret.addEventListener('click', runSecretStrengthTest);
    }

    const testSecretInput = document.getElementById('testSecretInput');
    if (testSecretInput) {
      testSecretInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') runSecretStrengthTest();
      });
    }
  }

  // 1. Learning Cards
  async function loadLearningCards() {
    const container = document.getElementById('learningCardsGrid');
    if (!container) return;

    try {
      const res = await fetch('/api/learning');
      const data = await res.json();
      cachedCards = data.cards || [];
      renderCards(cachedCards);
    } catch (err) {
      container.innerHTML = '<div class="error-banner">Failed to load learning resources.</div>';
    }
  }

  function renderCards(cards) {
    const container = document.getElementById('learningCardsGrid');
    if (!container) return;

    if (!cards || cards.length === 0) {
      container.innerHTML = '<div class="empty-hint">No matching security topics found.</div>';
      return;
    }

    const html = cards.map(c => {
      const sevClass = 'badge-' + c.severity.toLowerCase();
      return `
        <div class="learning-card" id="card-${c.id}">
          <div class="learning-card-header">
            <span class="severity-pill ${sevClass}">${c.severity}</span>
            <span class="learning-mitre">${c.mitre}</span>
          </div>
          <h3 class="learning-card-title">${c.title}</h3>
          
          <div class="learning-section">
            <div class="learning-label">💡 What is it?</div>
            <p>${c.whatIsIt}</p>
          </div>

          <div class="learning-section">
            <div class="learning-label">⚠️ Why is it dangerous?</div>
            <p>${c.whyDangerous}</p>
          </div>

          <div class="learning-section">
            <div class="learning-label">🔍 How VaultScan detects it:</div>
            <p>${c.detectionMethod}</p>
          </div>

          <div class="learning-section">
            <div class="learning-label">🛡️ How to prevent it:</div>
            <p>${c.howToPrevent}</p>
            <pre class="learning-code"><code>${escapeHtml(c.exampleCode)}</code></pre>
          </div>
        </div>
      `;
    }).join('');

    container.innerHTML = html;
  }

  function filterCards(query) {
    if (!query) {
      renderCards(cachedCards);
      return;
    }
    const filtered = cachedCards.filter(c => {
      return c.title.toLowerCase().includes(query) ||
             c.whatIsIt.toLowerCase().includes(query) ||
             c.whyDangerous.toLowerCase().includes(query) ||
             c.mitre.toLowerCase().includes(query) ||
             c.id.toLowerCase().includes(query);
    });
    renderCards(filtered);
  }

  // 2. Attack Scenarios Lab
  async function loadAttackScenarios() {
    const container = document.getElementById('scenariosList');
    if (!container) return;

    try {
      const res = await fetch('/api/scenarios');
      const data = await res.json();
      cachedScenarios = data.scenarios || [];
      renderScenarios(cachedScenarios);
    } catch (err) {
      container.innerHTML = '<div class="error-banner">Failed to load scenarios.</div>';
    }
  }

  function renderScenarios(scenarios) {
    const container = document.getElementById('scenariosList');
    if (!container) return;

    const html = scenarios.map((s, idx) => {
      return `
        <div class="scenario-card">
          <div class="scenario-header">
            <h4>${s.title}</h4>
            <span class="scenario-vuln-tag">${s.expectedVulnerability}</span>
          </div>
          <p class="scenario-desc">${s.description}</p>
          <div class="scenario-meta">
            <span>Expected Score: <strong>${s.expectedScore}/100 (${s.expectedGrade})</strong></span>
            <span>MITRE: <strong>${s.mitre}</strong></span>
          </div>
          <div class="scenario-actions">
            <button class="btn btn-sm btn-primary" onclick="LearningModule.runScenario('${s.id}')">
              ▶ Run Scenario
            </button>
            <button class="btn btn-sm btn-ghost" onclick="LearningModule.loadScenarioIntoAnalyzer('${s.id}')">
              Open in Analyzer
            </button>
          </div>
          <div class="scenario-result-box hidden" id="scenarioResult_${s.id}"></div>
        </div>
      `;
    }).join('');

    container.innerHTML = html;
  }

  async function runScenario(scenarioId) {
    const resultBox = document.getElementById('scenarioResult_' + scenarioId);
    if (!resultBox) return;

    resultBox.classList.remove('hidden');
    resultBox.innerHTML = '<p class="text-muted">Analyzing scenario token locally...</p>';

    try {
      const res = await fetch('/api/scenarios/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenarioId })
      });
      const data = await res.json();
      const { scenario, analysis, profile } = data;

      const findingsList = (analysis.findings || []).map(f => `
        <div class="scen-finding">
          <span class="pill-sev ${f.severity.toLowerCase()}">${f.severity}</span>
          <strong>${f.title}</strong> — <code>${escapeHtml(f.evidence)}</code>
        </div>
      `).join('');

      resultBox.innerHTML = `
        <div class="scenario-evaluation">
          <div class="scen-score-badge">
            Score: <strong>${analysis.score} / 100</strong> (Grade ${analysis.grade}) | Risk: <strong>${profile.overallRisk}</strong>
          </div>
          <div class="scen-findings-list">
            ${findingsList}
          </div>
          <div class="scen-fix-box">
            🔧 <strong>Recommended Mitigation:</strong> ${scenario.fix}
          </div>
        </div>
      `;
    } catch (err) {
      resultBox.innerHTML = `<div class="error-banner">Execution failed: ${err.message}</div>`;
    }
  }

  function loadScenarioIntoAnalyzer(scenarioId) {
    const scenario = cachedScenarios.find(s => s.id === scenarioId);
    if (!scenario) return;

    const jwtInput = document.getElementById('jwtInput');
    if (jwtInput) {
      jwtInput.value = scenario.token;
      if (window.AppModule && window.AppModule.switchTab) {
        window.AppModule.switchTab('tab-analyze');
        const btnAnalyze = document.getElementById('btnAnalyze');
        if (btnAnalyze) btnAnalyze.click();
      }
    }
  }

  // 3. Secret Strength Analyzer
  async function runSecretStrengthTest() {
    const input = document.getElementById('testSecretInput');
    const resultContainer = document.getElementById('secretStrengthResult');
    if (!input || !resultContainer) return;

    const secret = input.value.trim();
    if (!secret) {
      alert('Please enter a test passphrase or secret.');
      return;
    }

    try {
      const res = await fetch('/api/secret-strength', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret })
      });
      const data = await res.json();

      resultContainer.classList.remove('hidden');

      const strengthClass = 'str-' + data.strength.toLowerCase().replace(/\s+/g, '-');
      const reasonsList = (data.reasons || []).map(r => `<li>${r}</li>`).join('');

      resultContainer.innerHTML = `
        <div class="strength-card">
          <div class="strength-top">
            <div class="strength-pill ${strengthClass}">Strength: ${data.strength}</div>
            <div class="strength-score">Rating: <strong>${data.score}/100</strong></div>
            <div class="strength-entropy">Entropy: <strong>${data.entropyBits} bits</strong></div>
          </div>
          <div class="strength-meter-bar">
            <div class="strength-meter-fill" style="width: ${data.score}%;"></div>
          </div>
          <ul class="strength-reasons-list">
            ${reasonsList}
          </ul>
          <div class="strength-advice">
            💡 <strong>Advice:</strong> ${data.recommendation}
          </div>
        </div>
      `;
    } catch (err) {
      resultContainer.classList.remove('hidden');
      resultContainer.innerHTML = `<div class="error-banner">Test failed: ${err.message}</div>`;
    }
  }

  function escapeHtml(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  return {
    init,
    runScenario,
    loadScenarioIntoAnalyzer
  };
})();
