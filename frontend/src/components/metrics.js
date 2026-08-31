export function renderMetricCards(stats = {}, anomalyData = {}) {
  const totalEvents = (stats.total_normalized_events || 0).toLocaleString();
  const totalRaw = (stats.total_raw_events || 0).toLocaleString();
  const anomaliesCount = anomalyData.anomalies_detected || 0;

  return `
    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-title">Total Normalized Events</div>
        <div class="metric-value">${totalEvents}</div>
        <div class="metric-sub">Stored in normalized_events</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Deduplicated Raw Logs</div>
        <div class="metric-value">${totalRaw}</div>
        <div class="metric-sub">SHA-256 indexed in raw_events</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Anomalies Flagged</div>
        <div class="metric-value" style="color: ${anomaliesCount > 0 ? 'var(--danger)' : 'var(--success)'};">${anomaliesCount}</div>
        <div class="metric-sub">Isolation Forest Machine Learning</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Engine & Analytics</div>
        <div class="metric-value" style="font-size: 22px; color: var(--accent); padding-top: 4px;">DuckDB + Parquet</div>
        <div class="metric-sub">In-Database SQL Aggregations</div>
      </div>
    </div>
  `;
}
