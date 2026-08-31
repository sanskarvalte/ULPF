export function renderMappingReviewPage(mappingsData = {}) {
  const mappingEntries = Object.entries(mappingsData.mappings || {}).map(([key, val]) => {
    const fields = Object.entries(val.field_maps || {}).map(([src, tgt]) => `
      <div style="display:flex; justify-content:space-between; padding:4px 0; border-bottom:1px solid rgba(255,255,255,0.05); font-size:12px;">
        <span style="font-family:monospace; color:#38bdf8;">${src}</span>
        <span style="color:var(--text-muted);">→</span>
        <span style="font-family:monospace; color:#4ade80;">${tgt}</span>
      </div>
    `).join('');

    return `
      <div class="panel" style="margin-bottom:16px;">
        <div class="panel-title">
          <span>${val.vendor} • ${val.product} (${key})</span>
          <span class="fmt-pill">${val.format.toUpperCase()}</span>
        </div>
        <div style="margin-top:10px;">${fields}</div>
      </div>
    `;
  }).join('');

  return `
    <div class="panel">
      <div class="panel-title">
        <span>🗺️ OCSF Schema Mappings & AI Assistant</span>
      </div>
      <p style="font-size:13px; color:var(--text-muted); margin-bottom:16px;">
        ULPF maps heterogeneous vendor fields directly into the Open Cybersecurity Schema Framework (OCSF) taxonomy.
      </p>

      <!-- AI Suggestion Box -->
      <div style="background:rgba(56,189,248,0.08); border:1px solid rgba(56,189,248,0.3); border-radius:8px; padding:16px; margin-bottom:20px;">
        <div style="font-size:14px; font-weight:600; color:#38bdf8; margin-bottom:8px;">🤖 AI Schema Mapping Suggester</div>
        <p style="font-size:12px; color:var(--text-muted); margin-bottom:10px;">Enter comma-separated raw keys from any proprietary log to generate automated OCSF mappings with confidence scores:</p>
        <div style="display:flex; gap:10px;">
          <input type="text" id="ai-sample-keys" class="search-input" style="flex:1; margin:0;" placeholder="e.g. client_ip, sport, login_user, timestamp, status_code">
          <button class="btn btn-primary" onclick="app.suggestMapping()">Run AI Inference</button>
        </div>
        <div id="ai-mapping-result" style="margin-top:12px;"></div>
      </div>

      <h3 style="font-size:15px; margin-bottom:12px;">Active Built-in Vendor Normalization Rules</h3>
      <div class="grid-2">${mappingEntries}</div>
    </div>
  `;
}
