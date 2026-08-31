export function renderNavbar(activePage = 'dashboard') {
  return `
    <header class="topbar">
      <div class="brand">
        <div class="eyebrow">National Technical Research Organisation (NTRO) • ULPF</div>
        <h1>Universal Log Pre-processing Framework</h1>
        <p class="subtitle">Lossless Normalization • OCSF Taxonomy • Isolation Forest ML • DuckDB Storage</p>
      </div>
      <div class="header-actions">
        <span class="badge-offline">● 100% Offline Air-Gapped</span>
        <button class="btn btn-primary" onclick="app.refreshCurrentPage()">🔄 Refresh</button>
      </div>
    </header>
    <nav class="main-nav">
      <button class="nav-tab ${activePage === 'dashboard' ? 'active' : ''}" onclick="app.navigate('dashboard')">📊 Dashboard</button>
      <button class="nav-tab ${activePage === 'explorer' ? 'active' : ''}" onclick="app.navigate('explorer')">🔍 Log Explorer</button>
      <button class="nav-tab ${activePage === 'onboarding' ? 'active' : ''}" onclick="app.navigate('onboarding')">⚡ Source Onboarding</button>
      <button class="nav-tab ${activePage === 'mappings' ? 'active' : ''}" onclick="app.navigate('mappings')">🗺️ Mapping Review</button>
      <div style="flex:1;"></div>
      <a href="/export/json" class="btn btn-sm" download="events.json">📥 JSON</a>
      <a href="/export/csv" class="btn btn-sm" download="events.csv">📊 CSV</a>
      <a href="/export/parquet" class="btn btn-sm" download="events.parquet">📦 Parquet</a>
      <a href="/docs" target="_blank" class="btn btn-sm">📖 OpenAPI Docs</a>
    </nav>
  `;
}
