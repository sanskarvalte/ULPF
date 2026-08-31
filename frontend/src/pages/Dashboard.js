import { renderMetricCards } from '../components/metrics.js';

export function renderDashboardPage(stats = {}, anomalyData = {}, recentEvents = []) {
  const metricsHtml = renderMetricCards(stats, anomalyData);

  const catRows = (stats.by_category || []).map(c => {
    const pct = stats.total_normalized_events > 0 ? ((c.count / stats.total_normalized_events) * 100).toFixed(1) : 0;
    return `
      <div class="stat-row">
        <div class="stat-header">
          <span>${c.category}</span>
          <span class="stat-count">${c.count.toLocaleString()} (${pct}%)</span>
        </div>
        <div class="progress-bar-bg"><div class="progress-bar-fill" style="width:${pct}%; background:#38bdf8;"></div></div>
      </div>
    `;
  }).join('') || '<div style="color:var(--text-muted); font-size:13px;">No events ingested yet.</div>';

  const sevColors = { critical:'#dc2626', high:'#ef4444', medium:'#f59e0b', low:'#3b82f6', informational:'#64748b', unknown:'#475569' };
  const sevRows = (stats.by_severity || []).map(s => {
    const color = sevColors[(s.severity || 'unknown').toLowerCase()] || '#64748b';
    const pct = stats.total_normalized_events > 0 ? ((s.count / stats.total_normalized_events) * 100).toFixed(1) : 0;
    return `
      <div class="stat-row">
        <div class="stat-header">
          <span style="text-transform:capitalize;">${s.severity}</span>
          <span class="stat-count">${s.count.toLocaleString()} (${pct}%)</span>
        </div>
        <div class="progress-bar-bg"><div class="progress-bar-fill" style="width:${pct}%; background:${color};"></div></div>
      </div>
    `;
  }).join('') || '<div style="color:var(--text-muted); font-size:13px;">No severity data.</div>';

  const anomaliesHtml = (anomalyData.anomalies || []).map(a => `
    <div class="anomaly-card">
      <div>
        <div style="display:flex; align-items:center; gap:8px;">
          <span class="anomaly-window">⏱ Window: ${a.time_window}</span>
          <span class="sev-badge sev-high">${a.high_severity_events} ERRORS</span>
        </div>
        <div style="font-size:13px; color:var(--text); margin-top:4px;">${a.description}</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">Volume: ${a.total_events} events • Source: ${a.vendors} (${a.categories})</div>
      </div>
      <div style="text-align:right;">
        <div class="anomaly-score-badge">Score: ${(a.anomaly_score * 100).toFixed(0)}%</div>
      </div>
    </div>
  `).join('') || `
    <div class="anomaly-card clean">
      <div>
        <div class="anomaly-window">✅ Statistical Baseline Normal</div>
        <div style="font-size:12px; color:var(--text-muted); margin-top:3px;">No abnormal spike or intrusion patterns detected by Isolation Forest.</div>
      </div>
      <span class="badge-offline">Normal</span>
    </div>
  `;

  return `
    ${metricsHtml}
    
    <div class="panel" style="border-color: rgba(239, 68, 68, 0.4); margin-bottom: 24px;">
      <div class="panel-title">
        <span>🚨 AI/ML Anomaly Detection (Isolation Forest)</span>
        <span style="font-size:12px; color:var(--text-muted);">${anomalyData.anomalies_detected || 0} flagged window(s) of ${anomalyData.total_windows_analyzed || 0} evaluated</span>
      </div>
      <div style="max-height: 280px; overflow-y: auto;">${anomaliesHtml}</div>
    </div>

    <div class="grid-2">
      <div class="panel">
        <div class="panel-title"><span>Event Categories (DuckDB SQL)</span></div>
        ${catRows}
      </div>
      <div class="panel">
        <div class="panel-title"><span>Severity Distribution</span></div>
        ${sevRows}
      </div>
    </div>
  `;
}
