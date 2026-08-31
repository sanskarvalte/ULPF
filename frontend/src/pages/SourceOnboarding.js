export function renderSourceOnboardingPage(sources = []) {
  const sourceRows = sources.map(s => `
    <tr>
      <td style="font-weight:600; color:#38bdf8;">${s.source_name}</td>
      <td><span class="fmt-pill">${s.format.toUpperCase()}</span></td>
      <td>${s.vendor || '—'} / ${s.product || '—'}</td>
      <td style="font-family:monospace; font-size:11px;">${s.source_id.slice(0, 8)}...</td>
      <td style="font-size:12px; color:var(--text-muted);">${s.created_at ? s.created_at.slice(0, 19) : '—'}</td>
    </tr>
  `).join('') || '<tr><td colspan="5" style="text-align:center; color:var(--text-muted);">No custom sources registered. Standard parsers auto-detect logs.</td></tr>';

  return `
    <div class="grid-2">
      <!-- Live Ingestion Box -->
      <div class="panel">
        <div class="panel-title">⚡ Live Ingest Log Stream</div>
        <div class="upload-box">
          <textarea id="raw-log-input" placeholder="Paste raw log lines here (JSON, Syslog, CEF, LEEF, XML, or unstructured text)..."></textarea>
          <div style="display:flex; gap:12px; justify-content:space-between; align-items:center; flex-wrap:wrap;">
            <input type="file" id="log-file-input" style="font-size:13px; color:var(--text-muted);">
            <button class="btn btn-primary" id="ingest-btn" onclick="app.handleUpload()">Ingest & Normalize</button>
          </div>
          <div id="upload-status" class="upload-status"></div>
        </div>
      </div>

      <!-- Register New Source Definition -->
      <div class="panel">
        <div class="panel-title">➕ Register Custom Log Source</div>
        <form onsubmit="event.preventDefault(); app.registerSource();" style="display:grid; gap:10px;">
          <input type="text" id="new-src-name" class="search-input" placeholder="Source Name (e.g. Cisco_ASA_FW_01)" required>
          <div style="display:flex; gap:10px;">
            <select id="new-src-format" class="search-input" style="flex:1;">
              <option value="syslog">Syslog (RFC 3164 / 5424)</option>
              <option value="json">JSON</option>
              <option value="cef">CEF (ArcSight)</option>
              <option value="leef">LEEF (QRadar)</option>
              <option value="csv">CSV / Excel</option>
              <option value="xml">XML (Windows/Sysmon)</option>
              <option value="generic">Generic Unstructured</option>
            </select>
            <input type="text" id="new-src-vendor" class="search-input" placeholder="Vendor" style="flex:1;">
          </div>
          <input type="text" id="new-src-product" class="search-input" placeholder="Product Name">
          <button type="submit" class="btn btn-primary" style="justify-self:start;">Register Source</button>
        </form>
      </div>
    </div>

    <!-- Active Registered Sources Table -->
    <div class="panel" style="margin-top:20px;">
      <div class="panel-title"><span>📡 Active Onboarded Sources</span></div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Source Name</th>
              <th>Format</th>
              <th>Vendor / Product</th>
              <th>Source UUID</th>
              <th>Registered At</th>
            </tr>
          </thead>
          <tbody>${sourceRows}</tbody>
        </table>
      </div>
    </div>
  `;
}
