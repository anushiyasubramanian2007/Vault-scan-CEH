/**
 * VaultScan - JWT Tampering Simulator Controller (static/tampering.js)
 * Educational lab demonstrating payload manipulation, signature mismatch,
 * and the visual security flow of server-side token rejection.
 */

window.TamperingModule = (() => {
  let loadedOriginalToken = '';

  function init() {
    const btnLoadTamperSample = document.getElementById('btnLoadTamperSample');
    const btnRunTamper = document.getElementById('btnRunTamper');
    const tamperTokenInput = document.getElementById('tamperTokenInput');

    if (btnLoadTamperSample) btnLoadTamperSample.addEventListener('click', loadTamperSample);
    if (btnRunTamper) btnRunTamper.addEventListener('click', runTampering);
    if (tamperTokenInput) {
      tamperTokenInput.addEventListener('input', () => {
        populateClaimsFromToken(tamperTokenInput.value.trim());
      });
    }
  }

  function loadTamperSample() {
    const input = document.getElementById('tamperTokenInput');
    if (!input) return;

    const b64 = (s) => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const now = Math.floor(Date.now() / 1000);

    const h = b64(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const p = b64(JSON.stringify({
      sub: 'usr_student_441',
      user: 'alice_student',
      role: 'user',
      department: 'Library',
      iat: now,
      exp: now + 3600
    }));

    const sample = h + '.' + p + '.sample_cryptographic_signature_base64';
    input.value = sample;
    populateClaimsFromToken(sample);
  }

  function populateClaimsFromToken(tokenStr) {
    loadedOriginalToken = tokenStr;
    const claimsEditor = document.getElementById('tamperPayloadEditor');
    if (!claimsEditor) return;

    if (!tokenStr) {
      claimsEditor.value = '{\n  "user": "student",\n  "role": "admin"\n}';
      return;
    }

    const parts = tokenStr.split('.');
    if (parts.length >= 2) {
      try {
        let b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4 !== 0) b64 += '=';
        const json = JSON.parse(atob(b64));
        claimsEditor.value = JSON.stringify(json, null, 2);
      } catch (e) {
        claimsEditor.value = '{\n  "user": "student",\n  "role": "admin"\n}';
      }
    }
  }

  async function runTampering() {
    const tokenInput = document.getElementById('tamperTokenInput');
    const claimsEditor = document.getElementById('tamperPayloadEditor');
    const resultsContainer = document.getElementById('tamperResults');
    const btn = document.getElementById('btnRunTamper');

    if (!tokenInput || !claimsEditor || !resultsContainer) return;

    const originalToken = tokenInput.value.trim() || loadedOriginalToken;
    if (!originalToken) {
      alert('Please paste or load an original token first.');
      return;
    }

    let modifiedPayload = {};
    try {
      modifiedPayload = JSON.parse(claimsEditor.value);
    } catch (err) {
      alert('Invalid JSON in Claims Editor: ' + err.message);
      return;
    }

    try {
      btn.disabled = true;
      btn.textContent = 'Simulating Attack...';

      const res = await fetch('/api/tamper', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          originalToken,
          modifiedClaims: modifiedPayload,
          mode: 'preserve_signature'
        })
      });

      const data = await res.json();
      if (data.error) {
        resultsContainer.classList.remove('hidden');
        resultsContainer.innerHTML = `<div class="error-banner">❌ ${data.error}</div>`;
        return;
      }

      renderTamperResults(data);
    } catch (err) {
      resultsContainer.classList.remove('hidden');
      resultsContainer.innerHTML = `<div class="error-banner">❌ Error running simulation: ${err.message}</div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = 'Simulate Tampering';
    }
  }

  function renderTamperResults(data) {
    const container = document.getElementById('tamperResults');
    if (!container) return;
    container.classList.remove('hidden');

    const { original, tampered, changes, signatureStatus, signatureExplanation, serverVerificationVerdict, visualFlow } = data;

    // Visual Flow Steps HTML
    const flowHtml = (visualFlow || []).map((step, idx) => {
      const isLast = idx === visualFlow.length - 1;
      return `
        <div class="flow-step-node node-step-${step.step}">
          <div class="node-badge">STEP ${step.step}</div>
          <div class="node-title">${step.title}</div>
          <div class="node-detail">${step.detail}</div>
        </div>
        ${!isLast ? '<div class="flow-arrow-down">↓</div>' : ''}
      `;
    }).join('');

    // Changes List
    let changesHtml = '';
    if (!changes || changes.length === 0) {
      changesHtml = '<p class="text-muted">No specific field modifications detected.</p>';
    } else {
      changesHtml = changes.map(c => `
        <div class="tamper-change-row">
          <span class="change-claim"><strong>${escapeHtml(c.claim)}</strong></span>
          <span class="change-pill pill-${c.type.toLowerCase()}">${c.type}</span>
          <span class="change-vals">${escapeHtml(c.before)} ➔ <strong style="color: #ff8c00;">${escapeHtml(c.after)}</strong></span>
        </div>
      `).join('');
    }

    container.innerHTML = `
      <!-- Visual Flow Diagram -->
      <div class="card subcard-flow">
        <h3 class="subcard-title">🎯 Tampering Visual Flow</h3>
        <div class="visual-flow-column">
          ${flowHtml}
        </div>
      </div>

      <!-- Verdict Banner -->
      <div class="verdict-banner-reject">
        <div class="verdict-icon">⛔</div>
        <div class="verdict-content">
          <h4>${serverVerificationVerdict}</h4>
          <p>${signatureExplanation}</p>
          <div class="status-tag status-invalid">${signatureStatus}</div>
        </div>
      </div>

      <!-- Side by Side Tokens -->
      <div class="tokens-comparison-grid">
        <div class="token-box">
          <div class="token-box-header">
            <span>Original Valid Token</span>
            <span class="badge-valid">Issued by Server</span>
          </div>
          <textarea class="token-readonly" readonly>${original.token}</textarea>
        </div>
        <div class="token-box">
          <div class="token-box-header">
            <span>Modified / Tampered Token</span>
            <span class="badge-invalid">Unsigned Alteration</span>
          </div>
          <textarea class="token-readonly" readonly>${tampered.token}</textarea>
        </div>
      </div>

      <!-- Detected Changes -->
      <div class="card subcard-changes">
        <h3 class="subcard-title">🔍 Detected Payload Alterations (${changes.length})</h3>
        <div class="tamper-changes-list">
          ${changesHtml}
        </div>
      </div>
    `;
  }

  function escapeHtml(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  return { init, loadTamperSample, runTampering };
})();
