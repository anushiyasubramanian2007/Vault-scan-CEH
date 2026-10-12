/**
 * VaultScan - JWT Comparison Controller (static/comparison.js)
 * Compares two tokens, renders claim diffs, detects privilege escalations,
 * and highlights size/metadata variations.
 */

window.ComparisonModule = (() => {
  function init() {
    const btnRunCompare = document.getElementById('btnRunCompare');
    const btnLoadCompareSample = document.getElementById('btnLoadCompareSample');
    const btnClearCompare = document.getElementById('btnClearCompare');

    if (btnRunCompare) btnRunCompare.addEventListener('click', runComparison);
    if (btnLoadCompareSample) btnLoadCompareSample.addEventListener('click', loadSamplePair);
    if (btnClearCompare) btnClearCompare.addEventListener('click', clearInputs);
  }

  async function runComparison() {
    const inputA = document.getElementById('compareTokenA');
    const inputB = document.getElementById('compareTokenB');
    const resultsContainer = document.getElementById('compareResults');
    const btn = document.getElementById('btnRunCompare');

    if (!inputA || !inputB || !resultsContainer) return;
    const tokenA = inputA.value.trim();
    const tokenB = inputB.value.trim();

    if (!tokenA || !tokenB) {
      alert('Please enter both Token A and Token B to execute comparison.');
      return;
    }

    try {
      btn.disabled = true;
      btn.textContent = 'Comparing Tokens...';

      const res = await fetch('/api/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tokenA, tokenB })
      });

      const data = await res.json();
      if (data.error) {
        resultsContainer.classList.remove('hidden');
        resultsContainer.innerHTML = `<div class="error-banner">❌ ${data.error}</div>`;
        return;
      }

      renderComparison(data);
    } catch (err) {
      resultsContainer.classList.remove('hidden');
      resultsContainer.innerHTML = `<div class="error-banner">❌ Network or comparison error: ${err.message}</div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = 'Compare Tokens';
    }
  }

  function renderComparison(data) {
    const resultsContainer = document.getElementById('compareResults');
    if (!resultsContainer) return;
    resultsContainer.classList.remove('hidden');

    const { changesCount, differences, sizeDifference, tokenA, tokenB, securityNote } = data;

    let diffItemsHtml = '';
    if (!differences || differences.length === 0) {
      diffItemsHtml = '<div class="no-diff-msg">✅ Both tokens have identical decoded claims and headers.</div>';
    } else {
      diffItemsHtml = differences.map(d => {
        const isEscalation = d.type === 'PRIVILEGE_ESCALATION';
        const cardClass = isEscalation ? 'diff-card escalation-card' : 'diff-card';
        return `
          <div class="${cardClass}">
            <div class="diff-header">
              <span class="diff-tag tag-${d.severity.toLowerCase()}">${d.severity}</span>
              <span class="diff-category">${d.category}</span>
              <span class="diff-type">${d.type.replace(/_/g, ' ')}</span>
            </div>
            <div class="diff-body">
              <p class="diff-desc">${d.description}</p>
              <div class="diff-values-grid">
                <div class="val-box val-old">
                  <span class="val-label">TOKEN A:</span>
                  <code>${escapeHtml(String(d.oldValue))}</code>
                </div>
                <div class="val-arrow">➔</div>
                <div class="val-box val-new">
                  <span class="val-label">TOKEN B:</span>
                  <code>${escapeHtml(String(d.newValue))}</code>
                </div>
              </div>
            </div>
          </div>
        `;
      }).join('');
    }

    resultsContainer.innerHTML = `
      <div class="compare-summary-banner">
        <div class="summary-stat">
          <span class="stat-number">${changesCount}</span>
          <span class="stat-label">Differences Identified</span>
        </div>
        <div class="summary-stat">
          <span class="stat-number">${sizeDifference ? sizeDifference.summary : 'N/A'}</span>
          <span class="stat-label">Size Variance (${sizeDifference.bytesA}B vs ${sizeDifference.bytesB}B)</span>
        </div>
      </div>

      <div class="diff-list">
        ${diffItemsHtml}
      </div>

      <div class="compare-footer-note">
        🔒 ${securityNote}
      </div>
    `;
  }

  function loadSamplePair() {
    const inputA = document.getElementById('compareTokenA');
    const inputB = document.getElementById('compareTokenB');
    if (!inputA || !inputB) return;

    // Generated demo pair: Token A (regular user) vs Token B (role elevated to admin, department changed)
    const b64 = (s) => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const now = Math.floor(Date.now() / 1000);

    const hA = b64(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const pA = b64(JSON.stringify({
      sub: 'usr_student_882',
      user: 'alex',
      role: 'student',
      permissions: ['read_catalog'],
      department: 'Computer Science',
      iss: 'https://auth.university.edu',
      aud: 'https://portal.university.edu',
      iat: now,
      exp: now + 3600
    }));
    const tokA = hA + '.' + pA + '.demo_signature_hash_a';

    const hB = b64(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const pB = b64(JSON.stringify({
      sub: 'usr_student_882',
      user: 'alex',
      role: 'admin', // Escalated!
      permissions: ['read_catalog', 'write_grades', 'modify_system'], // Escalated!
      department: 'University Administration',
      iss: 'https://auth.university.edu',
      aud: 'https://portal.university.edu',
      iat: now,
      exp: now + 86400 // Extended!
    }));
    const tokB = hB + '.' + pB + '.demo_signature_hash_b';

    inputA.value = tokA;
    inputB.value = tokB;

    runComparison();
  }

  function clearInputs() {
    const inputA = document.getElementById('compareTokenA');
    const inputB = document.getElementById('compareTokenB');
    const resultsContainer = document.getElementById('compareResults');
    if (inputA) inputA.value = '';
    if (inputB) inputB.value = '';
    if (resultsContainer) {
      resultsContainer.classList.add('hidden');
      resultsContainer.innerHTML = '';
    }
  }

  function escapeHtml(s) {
    if (!s) return '';
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  return { init, runComparison, loadSamplePair, clearInputs };
})();
