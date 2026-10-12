/**
 * VaultScan - Security Report Generator Controller (static/reports.js)
 * Generates audit documentation, renders print-optimized HTML previews,
 * and provides one-click PDF printing and file download.
 */

window.ReportsModule = (() => {
  let latestReportHtml = '';

  function init() {
    const btnGenerateReport = document.getElementById('btnGenerateReport');
    const btnUseCurrentToken = document.getElementById('btnUseCurrentToken');
    const btnPrintReport = document.getElementById('btnPrintReport');
    const btnDownloadHtml = document.getElementById('btnDownloadHtml');

    if (btnGenerateReport) btnGenerateReport.addEventListener('click', generateReport);
    if (btnUseCurrentToken) btnUseCurrentToken.addEventListener('click', loadCurrentToken);
    if (btnPrintReport) btnPrintReport.addEventListener('click', printReport);
    if (btnDownloadHtml) btnDownloadHtml.addEventListener('click', downloadHtml);
  }

  function loadCurrentToken() {
    const mainInput = document.getElementById('jwtInput');
    const reportInput = document.getElementById('reportTokenInput');
    if (mainInput && reportInput && mainInput.value.trim()) {
      reportInput.value = mainInput.value.trim();
    } else {
      alert('No active token in analyzer. Please paste a token or analyze one first.');
    }
  }

  async function generateReport() {
    const reportInput = document.getElementById('reportTokenInput');
    const previewContainer = document.getElementById('reportPreviewContainer');
    const previewActions = document.getElementById('reportActionsBar');
    const btn = document.getElementById('btnGenerateReport');

    if (!reportInput || !previewContainer) return;
    const token = reportInput.value.trim();

    if (!token) {
      alert('Please paste or load a token to generate an audit report.');
      return;
    }

    try {
      btn.disabled = true;
      btn.textContent = 'Compiling Report...';

      const res = await fetch('/api/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });

      const data = await res.json();
      if (data.error) {
        previewContainer.innerHTML = `<div class="error-banner">❌ ${data.error}</div>`;
        return;
      }

      latestReportHtml = data.html;
      previewContainer.innerHTML = `
        <iframe id="reportFrame" class="report-iframe" srcdoc="${escapeAttr(latestReportHtml)}" style="width: 100%; height: 750px; border: 1px solid var(--border-color); border-radius: 8px; background: #ffffff;"></iframe>
      `;

      if (previewActions) previewActions.classList.remove('hidden');
    } catch (err) {
      previewContainer.innerHTML = `<div class="error-banner">❌ Failed to generate report: ${err.message}</div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = 'Generate Security Report';
    }
  }

  function printReport() {
    const frame = document.getElementById('reportFrame');
    if (frame && frame.contentWindow) {
      frame.contentWindow.print();
    } else if (latestReportHtml) {
      const win = window.open('', '_blank');
      win.document.write(latestReportHtml);
      win.document.close();
      win.print();
    }
  }

  function downloadHtml() {
    if (!latestReportHtml) return;
    const blob = new Blob([latestReportHtml], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'VaultScan-Security-Audit-Report-' + Date.now() + '.html';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function escapeAttr(s) {
    if (!s) return '';
    return s.replace(/"/g, '&quot;');
  }

  return { init, generateReport, printReport, downloadHtml };
})();
