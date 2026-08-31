export function renderLogExplorerPage(events = []) {
  const rows = events.map(e => {
    const sevClass = 'sev-' + (e.severity || 'unknown').toLowerCase();
    const ts = e.timestamp ? e.timestamp.replace('T', ' ').slice(0, 19) : (e.created_at ? e.created_at.slice(0, 19) : '—');
    const msg = e.message ? (e.message.slice(0, 50) + (e.message.length > 50 ? '...' : '')) : (e.raw_event ? (e.raw_event.slice(0, 50) + '...') : '—');
    const vendorProd = [e.vendor, e.product].filter(Boolean).join(' / ') || '—';

    return `
      <tr>
        <td style="font-family: monospace; font-size: 12px; white-space: nowrap;">${ts}</td>
        <td>${e.category_name || '—'}</td>
        <td><span class="sev-badge ${sevClass}">${e.severity || 'UNKNOWN'}</span></td>
        <td><span class="fmt-pill">${e.log_format || 'GENERIC'}</span></td>
        <td style="font-family: monospace; font-size: 12px;">${e.src_ip || '—'}</td>
        <td>${e.user || '—'}</td>
        <td>${vendorProd}</td>
        <td style="font-size: 12px;">${msg}</td>
        <td><button class="btn btn-sm" onclick="app.inspectEvent('${e.event_id}')">🔍 Trace</button></td>
      </tr>
    `;
  }).join('') || '<tr><td colspan="9" style="text-align:center; color:var(--text-muted);">No events found in DuckDB.</td></tr>';

  return `
    <div class="panel">
      <div class="panel-title">
        <span>📋 Normalized Events Explorer</span>
        <div style="display:flex; gap:10px;">
          <input type="text" id="explorer-search" class="search-input" style="width:300px; margin:0;" placeholder="Search IP, user, vendor, message..." oninput="app.filterExplorer()">
        </div>
      </div>
      <div class="table-container" style="max-height: 65vh; overflow-y: auto;">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Category</th>
              <th>Severity</th>
              <th>Format</th>
              <th>Source IP</th>
              <th>User</th>
              <th>Vendor / Product</th>
              <th>Message</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="explorer-table-body">${rows}</tbody>
        </table>
      </div>
    </div>
  `;
}
