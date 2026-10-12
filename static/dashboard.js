/**
 * VaultScan - Security Dashboard Controller (static/dashboard.js)
 * Manages aggregated statistics, grade distributions, vulnerability counters,
 * and historical security score trends.
 */

window.DashboardModule = (() => {
  async function refreshDashboard() {
    try {
      const res = await fetch('/api/dashboard');
      if (!res.ok) return;
      const data = await res.json();
      renderDashboard(data);
    } catch (err) {
      console.warn('Dashboard fetch error:', err);
    }
  }

  function renderDashboard(data) {
    const { metrics, trend } = data;
    if (!metrics) return;

    // Stat cards
    const elTotal = document.getElementById('dashTotalAnalyzed');
    const elAvg = document.getElementById('dashAvgScore');
    const elCrit = document.getElementById('dashCriticalIssues');
    const elGradeA = document.getElementById('dashGradeACount');
    const elTrendDirection = document.getElementById('dashTrendDirection');

    if (elTotal) elTotal.textContent = metrics.totalAnalyzed || 0;
    if (elAvg) {
      elAvg.textContent = (metrics.averageScore || 0) + ' / 100';
      elAvg.style.color = metrics.averageScore >= 75 ? 'var(--color-a)' : (metrics.averageScore >= 50 ? 'var(--color-c)' : 'var(--color-f)');
    }
    if (elCrit) elCrit.textContent = metrics.criticalFindings || 0;
    if (elGradeA) elGradeA.textContent = (metrics.grades ? metrics.grades.A : 0) + ' tokens';

    if (elTrendDirection && trend) {
      elTrendDirection.textContent = trend.direction || 'Stable';
      elTrendDirection.className = 'trend-badge trend-' + (trend.direction ? trend.direction.toLowerCase() : 'stable');
    }

    // Severity Breakdown
    const elSevCrit = document.getElementById('sevCountCrit');
    const elSevHigh = document.getElementById('sevCountHigh');
    const elSevMed = document.getElementById('sevCountMed');
    const elSevLow = document.getElementById('sevCountLow');

    if (elSevCrit) elSevCrit.textContent = metrics.criticalFindings || 0;
    if (elSevHigh) elSevHigh.textContent = metrics.highFindings || 0;
    if (elSevMed) elSevMed.textContent = metrics.mediumFindings || 0;
    if (elSevLow) elSevLow.textContent = metrics.lowFindings || 0;

    // Grades Breakdown
    if (metrics.grades) {
      const gA = document.getElementById('gradeCountA');
      const gB = document.getElementById('gradeCountB');
      const gC = document.getElementById('gradeCountC');
      const gD = document.getElementById('gradeCountD');
      const gF = document.getElementById('gradeCountF');

      if (gA) gA.textContent = metrics.grades.A || 0;
      if (gB) gB.textContent = metrics.grades.B || 0;
      if (gC) gC.textContent = metrics.grades.C || 0;
      if (gD) gD.textContent = metrics.grades.D || 0;
      if (gF) gF.textContent = metrics.grades.F || 0;
    }

    // Historical Trend Graph
    renderTrendGraph(trend ? trend.recentScores : []);
  }

  function renderTrendGraph(scores) {
    const container = document.getElementById('trendGraphContainer');
    if (!container) return;

    if (!scores || scores.length === 0) {
      container.innerHTML = '<div class="empty-hint">Analyze tokens to visualize your historical score trajectory.</div>';
      return;
    }

    let barsHtml = scores.map((sc, idx) => {
      let color = sc >= 75 ? 'var(--color-a)' : (sc >= 50 ? 'var(--color-c)' : 'var(--color-f)');
      let height = Math.max(10, sc);
      return `
        <div class="trend-bar-wrapper" title="Analysis #${idx + 1}: ${sc}/100">
          <div class="trend-bar" style="height: ${height}%; background: ${color};"></div>
          <span class="trend-val">${sc}</span>
        </div>
      `;
    }).join('');

    container.innerHTML = `<div class="trend-bars-flex">${barsHtml}</div>`;
  }

  return {
    refresh: refreshDashboard
  };
})();
