function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function renderSeverityBadge(sev) {
  const s = String(sev || 'UNKNOWN').toUpperCase();
  if (s === 'CRITICAL') {
    return `<span class="px-2 py-0.5 rounded bg-error/15 text-error border border-outline-variant text-[10px] font-bold">CRITICAL</span>`;
  } else if (s === 'HIGH') {
    return `<span class="px-2 py-0.5 rounded bg-tertiary-container/20 text-tertiary text-[10px] font-bold">HIGH</span>`;
  } else if (s === 'MEDIUM') {
    return `<span class="px-2 py-0.5 rounded bg-tertiary/15 text-tertiary text-[10px] font-bold">MEDIUM</span>`;
  } else if (s === 'LOW') {
    return `<span class="px-2 py-0.5 rounded bg-primary/15 text-primary text-[10px] font-bold">LOW</span>`;
  } else {
    return `<span class="px-2 py-0.5 rounded bg-secondary-container/30 text-on-surface-variant text-[10px] font-bold">INFO</span>`;
  }
}

export function renderIntegrityBadge(status) {
  const st = String(status || 'PENDING').toUpperCase();
  if (st === 'VERIFIED') {
    return `
      <div class="flex items-center gap-1.5 cursor-pointer hover:opacity-80 transition-opacity" title="Cryptographic SHA-256 verified against immutable blockchain proof. Click for details.">
        <span class="material-symbols-outlined text-[15px] text-[#22c55e]">check_circle</span>
        <span class="font-code-xs text-[11px] text-[#86efac] font-medium">Verified</span>
      </div>
    `;
  } else if (st === 'FAILED' || st === 'TAMPERED') {
    return `
      <div class="flex items-center gap-1.5 text-error bg-error/15 px-2 py-0.5 rounded w-fit border border-outline-variant/30 cursor-pointer hover:bg-error/25 transition-colors" title="Cryptographic hash mismatch! Evidence altered after blockchain commitment.">
        <span class="material-symbols-outlined text-[14px]">warning</span>
        <span class="font-code-xs text-[10px] font-bold">FAILED</span>
      </div>
    `;
  } else {
    return `
      <div class="flex items-center gap-1.5 text-outline bg-secondary-container/20 px-2 py-0.5 rounded w-fit border border-outline-variant/20 cursor-pointer hover:bg-secondary-container/30 transition-colors" title="Recorded in DuckDB; pending ledger commitment.">
        <span class="material-symbols-outlined text-[14px] text-outline">schedule</span>
        <span class="font-code-xs text-[10px] font-medium text-outline">PENDING</span>
      </div>
    `;
  }
}

export function renderLogExplorerPage(events = [], total = 0, page = 1, pageSize = 50, state = {}) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const activeDropdown = state.activeDropdown || null;
  const searchVal = state.searchVal || '';
  const timeRange = state.timeRange || '24h';
  const sourceFilter = state.sourceFilter || 'all';
  const severityFilter = state.severityFilter || 'all';
  const integrityFilter = state.integrityFilter || 'all';
  const ocsfFilter = state.ocsfFilter || 'all';
  const eventTypeFilter = state.eventTypeFilter || 'all';
  const formatFilter = state.formatFilter || 'all';
  const filterOptions = state.filterOptions || {};

  const timeMap = {
    '15m': 'Last 15 Minutes',
    '1h': 'Last 1 Hour',
    '24h': 'Last 24 Hours',
    '7d': 'Last 7 Days',
    'all': 'All Time'
  };
  const timeLabel = timeMap[timeRange] || 'Last 24 Hours';
  const sourceLabel = sourceFilter === 'all' ? 'All' : (sourceFilter.length > 18 ? sourceFilter.slice(0, 16) + '...' : sourceFilter);

  const severityMap = {
    'all': 'All',
    'high+': 'High+',
    'critical': 'Critical',
    'high': 'High',
    'medium': 'Medium',
    'low': 'Low',
    'info': 'Info'
  };
  const severityLabel = severityMap[severityFilter.toLowerCase()] || severityFilter;

  const integrityMap = {
    'all': 'All',
    'verified': 'Verified',
    'failed': 'Failed',
    'pending': 'Pending'
  };
  const integrityLabel = integrityMap[integrityFilter.toLowerCase()] || integrityFilter;

  let availableSources = filterOptions.sources || [];
  if (!availableSources.length && events && events.length) {
    availableSources = [...new Set(events.map(e => e.source_display || e.src_hostname || e.source_file || e.product).filter(Boolean))].sort();
  }
  if (!availableSources.length && window.app && window.app.state && window.app.state.sources && window.app.state.sources.length) {
    availableSources = window.app.state.sources.map(s => s.source_name).filter(Boolean).sort();
  }
  const sourceOptionsHtml = availableSources.length > 0 ? availableSources.slice(0, 50).map(s => {
    const isSel = sourceFilter === s;
    return `
      <button onclick="event.stopPropagation(); app.setFilter('sourceFilter', '${escapeHtml(s)}')" class="w-full text-left px-3 py-2 flex items-center justify-between hover:bg-primary/10 hover:text-primary transition-colors font-code-xs text-code-xs ${isSel ? 'text-primary font-bold bg-primary/15' : 'text-on-surface'} truncate" title="${escapeHtml(s)}">
        <span class="truncate flex items-center gap-2">
          <span class="material-symbols-outlined text-[15px] text-outline">description</span>
          ${escapeHtml(s)}
        </span>
        ${isSel ? '<span class="text-primary font-bold ml-2">✓</span>' : ''}
      </button>
    `;
  }).join('') : '<div class="px-3 py-2 text-on-surface-variant text-[11px] italic">No sources detected yet</div>';

  const activeChips = [];
  if (ocsfFilter && ocsfFilter !== 'all') {
    activeChips.push(`<span class="inline-flex items-center gap-1.5 px-2 py-0.5 bg-primary/10 border border-primary/30 text-primary rounded font-code-xs text-[10px]">OCSF: ${escapeHtml(ocsfFilter)} <button onclick="app.setFilter('ocsfFilter', 'all')" class="hover:text-error cursor-pointer">✕</button></span>`);
  }
  if (eventTypeFilter && eventTypeFilter !== 'all') {
    activeChips.push(`<span class="inline-flex items-center gap-1.5 px-2 py-0.5 bg-primary/10 border border-primary/30 text-primary rounded font-code-xs text-[10px]">Type: ${escapeHtml(eventTypeFilter)} <button onclick="app.setFilter('eventTypeFilter', 'all')" class="hover:text-error cursor-pointer">✕</button></span>`);
  }
  if (formatFilter && formatFilter !== 'all') {
    activeChips.push(`<span class="inline-flex items-center gap-1.5 px-2 py-0.5 bg-primary/10 border border-primary/30 text-primary rounded font-code-xs text-[10px]">Format: ${escapeHtml(formatFilter.toUpperCase())} <button onclick="app.setFilter('formatFilter', 'all')" class="hover:text-error cursor-pointer">✕</button></span>`);
  }

  const hasActiveFilters = Boolean(searchVal || timeRange !== 'all' || sourceFilter !== 'all' || severityFilter !== 'all' || integrityFilter !== 'all' || activeChips.length > 0);

  let contentBody = '';
  if (state.loading) {
    contentBody = `
      <div class="p-16 flex flex-col items-center justify-center gap-3 text-on-surface-variant">
        <div class="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin"></div>
        <div class="font-code-sm text-code-sm text-primary font-bold tracking-wider animate-pulse">QUERYING EVENT STORE...</div>
        <div class="font-code-xs text-code-xs text-outline">Searching DuckDB normalized store & blockchain ledger proofs</div>
      </div>
    `;
  } else if (state.error) {
    contentBody = `
      <div class="p-16 flex flex-col items-center justify-center gap-3 text-center">
        <span class="material-symbols-outlined text-[40px] text-error">dns</span>
        <div class="font-headline-md text-body-md font-bold text-error">EVENT STORE UNAVAILABLE</div>
        <div class="font-code-xs text-code-xs text-on-surface-variant max-w-md">${escapeHtml(state.error)}</div>
        <button onclick="app.loadExplorerEvents()" class="mt-2 px-4 py-1.5 bg-secondary-container hover:bg-secondary-container/80 text-on-surface rounded font-label-caps text-label-caps border border-outline-variant transition-colors cursor-pointer">RETRY</button>
      </div>
    `;
  } else if (!events || events.length === 0) {
    contentBody = `
      <div class="p-16 flex flex-col items-center justify-center gap-2 text-center">
        <span class="material-symbols-outlined text-[36px] text-outline opacity-60">search_off</span>
        <div class="font-label-caps text-label-caps text-on-surface font-bold text-sm tracking-wider">NO EVENTS FOUND</div>
        <div class="font-code-xs text-code-xs text-on-surface-variant">Try adjusting your query or filters.</div>
        ${hasActiveFilters ? `<button onclick="app.resetExplorerFilters()" class="mt-3 px-3 py-1 bg-primary/10 text-primary hover:bg-primary/20 rounded font-code-xs text-code-xs border border-primary/20 transition-colors cursor-pointer">Reset All Filters</button>` : ''}
      </div>
    `;
  } else {
    const rowsHtml = events.map((e, idx) => {
      const bgClass = idx % 2 === 0 ? 'bg-surface-container-lowest' : 'bg-surface-container';
      const ts = e.timestamp || e.created_at || '—';
      const rawId = e.event_id || 'EVT-UNKNOWN';
      const displayId = rawId.length > 14 ? rawId.slice(0, 13) + '…' : rawId;
      const sourceName = e.source_display || e.src_hostname || e.source_file || e.product || 'unknown-source';
      const eventType = e.event_type_display || e.activity_name || e.type_name || e.category_name || 'Event';
      const ocsfName = e.ocsf_display || e.class_name || e.category_name || 'Security Finding';
      const severityBadge = renderSeverityBadge(e.severity_clean || e.severity);
      const integrityBadge = renderIntegrityBadge(e.integrity_status || (e.blockchain_proof && e.blockchain_proof.status));

      return `
        <tr class="${bgClass} hover:bg-surface-container-high transition-colors group cursor-pointer border-b border-outline-variant/30" onclick="app.inspectEvent('${escapeHtml(e.event_id)}')">
          <td class="px-4 py-2.5 text-on-surface-variant font-code-sm whitespace-nowrap">${escapeHtml(ts)}</td>
          <td class="px-4 py-2.5 text-primary font-bold font-code-sm whitespace-nowrap" title="${escapeHtml(e.event_id)}">${escapeHtml(displayId)}</td>
          <td class="px-4 py-2.5 text-on-surface font-code-sm whitespace-nowrap">${escapeHtml(sourceName)}</td>
          <td class="px-4 py-2.5 text-on-surface whitespace-nowrap">${escapeHtml(eventType)}</td>
          <td class="px-4 py-2.5 whitespace-nowrap">${severityBadge}</td>
          <td class="px-4 py-2.5 text-on-surface-variant whitespace-nowrap">${escapeHtml(ocsfName)}</td>
          <td class="px-4 py-2.5 whitespace-nowrap" onclick="event.stopPropagation(); app.showIntegrityDetails('${escapeHtml(e.event_id)}')">
            ${integrityBadge}
          </td>
          <td class="px-4 py-2.5 text-right whitespace-nowrap">
            <button onclick="event.stopPropagation(); app.inspectEvent('${escapeHtml(e.event_id)}')" class="text-primary hover:text-primary-container p-1 rounded transition-colors cursor-pointer" title="View details & raw trace">
              <span class="material-symbols-outlined text-[18px]">read_more</span>
            </button>
          </td>
        </tr>
      `;
    }).join('');

    contentBody = `
      <div class="flex-1 overflow-auto">
        <table class="w-full text-left border-collapse whitespace-nowrap">
          <thead class="sticky top-0 bg-surface-container-highest shadow-sm z-20">
            <tr>
              <th class="px-4 py-3 font-label-caps text-label-caps text-on-surface-variant font-normal">TIME</th>
              <th class="px-4 py-3 font-label-caps text-label-caps text-on-surface-variant font-normal">EVENT ID</th>
              <th class="px-4 py-3 font-label-caps text-label-caps text-on-surface-variant font-normal">SOURCE</th>
              <th class="px-4 py-3 font-label-caps text-label-caps text-on-surface-variant font-normal">EVENT TYPE</th>
              <th class="px-4 py-3 font-label-caps text-label-caps text-on-surface-variant font-normal">SEVERITY</th>
              <th class="px-4 py-3 font-label-caps text-label-caps text-on-surface-variant font-normal">OCSF</th>
              <th class="px-4 py-3 font-label-caps text-label-caps text-on-surface-variant font-normal">INTEGRITY</th>
              <th class="px-4 py-3 font-label-caps text-label-caps text-on-surface-variant font-normal text-right">ACTION</th>
            </tr>
          </thead>
          <tbody class="font-code-sm text-code-sm">
            ${rowsHtml}
          </tbody>
        </table>
      </div>
    `;
  }

  return `
    <div class="flex flex-col w-full h-full p-gutter gap-stack-md" onclick="app.closeDropdowns()">
      <!-- TOP SEARCH & FILTER PANEL (overflow-visible ensures dropdowns are never clipped) -->
      <div class="flex flex-col bg-surface-container rounded shadow-sm relative overflow-visible z-30">
        <div class="p-container-padding flex flex-col gap-stack-md relative overflow-visible">
          <!-- LOG EXPLORER TITLE & ACTION BUTTONS -->
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-3">
              <h1 class="font-headline-md text-headline-md text-on-surface">Log Explorer</h1>
              ${state.customLoadedFileName ? `<span class="px-2 py-0.5 rounded font-code-xs text-[10px] font-bold bg-primary/15 text-primary border border-primary/30">LOCAL FILE: ${escapeHtml(state.customLoadedFileName)}</span>` : `<span class="px-2 py-0.5 rounded font-code-xs text-[10px] font-bold bg-[#10b981]/15 text-[#86efac] border border-[#10b981]/30">LOCAL DUCKDB (${total.toLocaleString()} EVENTS)</span>`}
            </div>
            <div class="flex items-center gap-stack-sm">
              <input type="file" id="explorer-local-file-input" class="hidden" accept=".json,.log,.txt" onchange="app.importLocalLogFile(event)" style="display:none;">
              <button onclick="document.getElementById('explorer-local-file-input').click()" class="flex items-center gap-2 px-3 py-1.5 bg-surface-container-highest text-on-surface rounded border border-outline-variant hover:bg-surface-container-high transition-colors cursor-pointer" title="Load your local normalized_events.json or log file directly into offline explorer">
                <span class="material-symbols-outlined text-[18px]">folder_open</span>
                <span class="font-label-caps text-label-caps">LOAD LOCAL LOGS</span>
              </button>
              <button onclick="app.exportExplorerCSV()" class="flex items-center gap-2 px-3 py-1.5 bg-primary/10 text-primary rounded border border-primary/20 hover:bg-primary/20 transition-colors cursor-pointer" title="Export filtered events as CSV">
                <span class="material-symbols-outlined text-[18px]">download</span>
                <span class="font-label-caps text-label-caps">EXPORT CSV</span>
              </button>
              <button onclick="app.shareExplorerQuery()" class="flex items-center gap-2 px-3 py-1.5 bg-secondary-container text-on-secondary-container rounded hover:bg-secondary-container/80 transition-colors cursor-pointer" title="Copy active query & filter parameters to clipboard">
                <span class="material-symbols-outlined text-[18px]">share</span>
                <span class="font-label-caps text-label-caps">SHARE QUERY</span>
              </button>
            </div>
          </div>

          <!-- QUERY INPUT SEARCH BAR -->
          <div class="relative flex items-center w-full">
            <span class="material-symbols-outlined absolute left-4 text-on-surface-variant text-[24px]">manage_search</span>
            <input id="explorer-query-input" class="w-full bg-[#080A0E] border border-outline-variant rounded py-4 pl-12 pr-28 font-code-sm text-code-sm text-on-surface focus:outline-none focus:border-primary transition-all shadow-inner placeholder:text-outline" placeholder="Enter Lucene query or raw text (e.g. source.ip:192.168.1.* AND event.action:login)" type="text" value="${escapeHtml(searchVal)}" onkeydown="if(event.key==='Enter') app.onSearchSubmit()" oninput="app.onSearchInput(this.value)">
            <div class="absolute right-4 flex items-center gap-2">
              ${searchVal ? `<button onclick="app.clearSearch()" class="text-on-surface-variant hover:text-on-surface p-1 cursor-pointer" title="Clear query"><span class="material-symbols-outlined text-[16px]">close</span></button>` : ''}
              <span class="font-code-xs text-code-xs text-on-surface-variant bg-surface-container-high px-2 py-1 rounded border border-outline-variant/30 select-none">Ctrl + K</span>
            </div>
          </div>

          <!-- FILTER BAR (relative z-40 overflow-visible allows dropdowns to freely float over table) -->
          <div class="flex flex-wrap gap-x-stack-md gap-y-stack-sm items-center relative z-40 overflow-visible">
            <span class="font-label-caps text-label-caps text-outline">FILTERS:</span>

            <!-- TIME RANGE DROPDOWN -->
            <div class="relative">
              <button onclick="event.stopPropagation(); app.toggleFilterDropdown('time')" class="flex items-center gap-2 px-3 py-1.5 bg-[#080A0E] border ${timeRange !== 'all' ? 'border-primary/60 text-primary' : 'border-outline-variant text-on-surface'} rounded hover:border-primary/50 transition-colors cursor-pointer text-left">
                <span class="material-symbols-outlined text-[16px] text-on-surface-variant">schedule</span>
                <span class="font-code-xs text-code-xs">${escapeHtml(timeLabel)}</span>
                <span class="material-symbols-outlined text-[16px] text-on-surface-variant">arrow_drop_down</span>
              </button>
              ${activeDropdown === 'time' ? `
                <div class="absolute left-0 top-full mt-2 w-52 bg-[#181c26] border border-[#3b4354] rounded-lg shadow-2xl z-50 py-1.5 font-code-xs text-code-xs ring-1 ring-black/50 backdrop-blur-md">
                  <div class="px-3 py-1 text-[10px] font-label-caps uppercase text-outline border-b border-[#2b3342] mb-1">Time Range</div>
                  <button onclick="event.stopPropagation(); app.setFilter('timeRange', 'all')" class="w-full text-left px-3 py-2 flex items-center justify-between hover:bg-primary/10 hover:text-primary cursor-pointer ${timeRange === 'all' ? 'text-primary font-bold bg-primary/15' : 'text-on-surface'}"><span>All Time</span>${timeRange === 'all' ? '<span class="text-primary font-bold">✓</span>' : ''}</button>
                  <button onclick="event.stopPropagation(); app.setFilter('timeRange', '15m')" class="w-full text-left px-3 py-2 flex items-center justify-between hover:bg-primary/10 hover:text-primary cursor-pointer ${timeRange === '15m' ? 'text-primary font-bold bg-primary/15' : 'text-on-surface'}"><span>Last 15 Minutes</span>${timeRange === '15m' ? '<span class="text-primary font-bold">✓</span>' : ''}</button>
                  <button onclick="event.stopPropagation(); app.setFilter('timeRange', '1h')" class="w-full text-left px-3 py-2 flex items-center justify-between hover:bg-primary/10 hover:text-primary cursor-pointer ${timeRange === '1h' ? 'text-primary font-bold bg-primary/15' : 'text-on-surface'}"><span>Last 1 Hour</span>${timeRange === '1h' ? '<span class="text-primary font-bold">✓</span>' : ''}</button>
                  <button onclick="event.stopPropagation(); app.setFilter('timeRange', '24h')" class="w-full text-left px-3 py-2 flex items-center justify-between hover:bg-primary/10 hover:text-primary cursor-pointer ${timeRange === '24h' ? 'text-primary font-bold bg-primary/15' : 'text-on-surface'}"><span>Last 24 Hours</span>${timeRange === '24h' ? '<span class="text-primary font-bold">✓</span>' : ''}</button>
                  <button onclick="event.stopPropagation(); app.setFilter('timeRange', '7d')" class="w-full text-left px-3 py-2 flex items-center justify-between hover:bg-primary/10 hover:text-primary cursor-pointer ${timeRange === '7d' ? 'text-primary font-bold bg-primary/15' : 'text-on-surface'}"><span>Last 7 Days</span>${timeRange === '7d' ? '<span class="text-primary font-bold">✓</span>' : ''}</button>
                </div>
              ` : ''}
            </div>

            <!-- SOURCE DROPDOWN -->
            <div class="relative">
              <button onclick="event.stopPropagation(); app.toggleFilterDropdown('source')" class="flex items-center gap-2 px-3 py-1.5 bg-[#080A0E] border ${sourceFilter !== 'all' ? 'border-primary/60 text-primary' : 'border-outline-variant text-on-surface'} rounded hover:border-primary/50 transition-colors cursor-pointer text-left">
                <span class="font-code-xs text-code-xs text-on-surface-variant">Source:</span>
                <span class="font-code-xs text-code-xs text-on-surface font-semibold">${escapeHtml(sourceLabel)}</span>
                <span class="material-symbols-outlined text-[16px] text-on-surface-variant">arrow_drop_down</span>
              </button>
              ${activeDropdown === 'source' ? `
                <div class="absolute left-0 top-full mt-2 w-72 max-h-80 overflow-y-auto bg-[#181c26] border border-[#3b4354] rounded-lg shadow-2xl z-50 py-1.5 font-code-xs text-code-xs ring-1 ring-black/50 backdrop-blur-md">
                  <div class="px-3 py-1.5 text-[10px] font-label-caps uppercase text-outline border-b border-[#2b3342] mb-1 flex items-center justify-between">
                    <span>Log Sources</span>
                    <span class="text-primary font-bold">${availableSources.length} detected</span>
                  </div>
                  <button onclick="event.stopPropagation(); app.setFilter('sourceFilter', 'all')" class="w-full text-left px-3 py-2 flex items-center justify-between hover:bg-primary/10 hover:text-primary cursor-pointer ${sourceFilter === 'all' ? 'text-primary font-bold bg-primary/15' : 'text-on-surface'}">
                    <span>📁 All Sources</span>
                    ${sourceFilter === 'all' ? '<span class="text-primary font-bold">✓</span>' : ''}
                  </button>
                  ${sourceOptionsHtml}
                </div>
              ` : ''}
            </div>

            <!-- SEVERITY DROPDOWN -->
            <div class="relative">
              <button onclick="event.stopPropagation(); app.toggleFilterDropdown('severity')" class="flex items-center gap-2 px-3 py-1.5 bg-[#080A0E] border ${severityFilter !== 'all' ? 'border-error/60' : 'border-outline-variant'} rounded hover:border-primary/50 transition-colors cursor-pointer text-left">
                <span class="font-code-xs text-code-xs text-on-surface-variant">Severity:</span>
                <span class="font-code-xs text-code-xs ${severityFilter === 'all' ? 'text-on-surface' : (severityFilter === 'high+' || severityFilter === 'critical' ? 'text-error font-bold' : 'text-tertiary')}">${escapeHtml(severityLabel)}</span>
                <span class="material-symbols-outlined text-[16px] text-on-surface-variant">arrow_drop_down</span>
              </button>
              ${activeDropdown === 'severity' ? `
                <div class="absolute left-0 top-full mt-2 w-56 bg-[#181c26] border border-[#3b4354] rounded-lg shadow-2xl z-50 py-1.5 font-code-xs text-code-xs ring-1 ring-black/50 backdrop-blur-md">
                  <div class="px-3 py-1 text-[10px] font-label-caps uppercase text-outline border-b border-[#2b3342] mb-1">Severity Level</div>
                  <button onclick="event.stopPropagation(); app.setFilter('severityFilter', 'all')" class="w-full text-left px-3 py-2 flex items-center justify-between hover:bg-primary/10 hover:text-primary cursor-pointer ${severityFilter === 'all' ? 'text-primary font-bold bg-primary/15' : 'text-on-surface'}"><span>All Severities</span>${severityFilter === 'all' ? '<span class="text-primary font-bold">✓</span>' : ''}</button>
                  <button onclick="event.stopPropagation(); app.setFilter('severityFilter', 'high+')" class="w-full text-left px-3 py-2 flex items-center justify-between hover:bg-primary/10 hover:text-primary cursor-pointer text-error font-bold ${severityFilter === 'high+' ? 'bg-primary/15' : ''}"><span>High+ (Critical & High)</span>${severityFilter === 'high+' ? '<span>✓</span>' : ''}</button>
                  <button onclick="event.stopPropagation(); app.setFilter('severityFilter', 'critical')" class="w-full text-left px-3 py-2 flex items-center justify-between hover:bg-primary/10 hover:text-primary cursor-pointer text-error ${severityFilter === 'critical' ? 'font-bold bg-primary/15' : ''}"><span>Critical</span>${severityFilter === 'critical' ? '<span>✓</span>' : ''}</button>
                  <button onclick="event.stopPropagation(); app.setFilter('severityFilter', 'high')" class="w-full text-left px-3 py-2 flex items-center justify-between hover:bg-primary/10 hover:text-primary cursor-pointer text-tertiary ${severityFilter === 'high' ? 'font-bold bg-primary/15' : ''}"><span>High</span>${severityFilter === 'high' ? '<span>✓</span>' : ''}</button>
                  <button onclick="event.stopPropagation(); app.setFilter('severityFilter', 'medium')" class="w-full text-left px-3 py-2 flex items-center justify-between hover:bg-primary/10 hover:text-primary cursor-pointer text-tertiary ${severityFilter === 'medium' ? 'font-bold bg-primary/15' : ''}"><span>Medium</span>${severityFilter === 'medium' ? '<span>✓</span>' : ''}</button>
                  <button onclick="event.stopPropagation(); app.setFilter('severityFilter', 'low')" class="w-full text-left px-3 py-2 flex items-center justify-between hover:bg-primary/10 hover:text-primary cursor-pointer text-primary ${severityFilter === 'low' ? 'font-bold bg-primary/15' : ''}"><span>Low</span>${severityFilter === 'low' ? '<span>✓</span>' : ''}</button>
                  <button onclick="event.stopPropagation(); app.setFilter('severityFilter', 'info')" class="w-full text-left px-3 py-2 flex items-center justify-between hover:bg-primary/10 hover:text-primary cursor-pointer text-on-surface-variant ${severityFilter === 'info' ? 'font-bold bg-primary/15' : ''}"><span>Info</span>${severityFilter === 'info' ? '<span>✓</span>' : ''}</button>
                </div>
              ` : ''}
            </div>

            <!-- INTEGRITY DROPDOWN -->
            <div class="relative">
              <button onclick="event.stopPropagation(); app.toggleFilterDropdown('integrity')" class="flex items-center gap-2 px-3 py-1.5 bg-[#080A0E] border ${integrityFilter !== 'all' ? 'border-[#10b981]/60 text-[#34d399]' : 'border-outline-variant text-on-surface'} rounded hover:border-primary/50 transition-colors cursor-pointer text-left">
                <span class="font-code-xs text-code-xs text-on-surface-variant">Integrity:</span>
                <span class="font-code-xs text-code-xs ${integrityFilter === 'verified' ? 'text-[#86efac] font-bold' : (integrityFilter === 'failed' ? 'text-error font-bold' : 'text-on-surface')}">${escapeHtml(integrityLabel)}</span>
                <span class="material-symbols-outlined text-[16px] text-on-surface-variant">arrow_drop_down</span>
              </button>
              ${activeDropdown === 'integrity' ? `
                <div class="absolute left-0 top-full mt-2 w-52 bg-[#181c26] border border-[#3b4354] rounded-lg shadow-2xl z-50 py-1.5 font-code-xs text-code-xs ring-1 ring-black/50 backdrop-blur-md">
                  <div class="px-3 py-1 text-[10px] font-label-caps uppercase text-outline border-b border-[#2b3342] mb-1">Blockchain Proof</div>
                  <button onclick="event.stopPropagation(); app.setFilter('integrityFilter', 'all')" class="w-full text-left px-3 py-2 flex items-center justify-between hover:bg-primary/10 hover:text-primary cursor-pointer ${integrityFilter === 'all' ? 'text-primary font-bold bg-primary/15' : 'text-on-surface'}"><span>All Statuses</span>${integrityFilter === 'all' ? '<span class="text-primary font-bold">✓</span>' : ''}</button>
                  <button onclick="event.stopPropagation(); app.setFilter('integrityFilter', 'verified')" class="w-full text-left px-3 py-2 flex items-center justify-between hover:bg-primary/10 hover:text-primary cursor-pointer text-[#86efac] ${integrityFilter === 'verified' ? 'font-bold bg-primary/15' : ''}"><span>✓ Verified Only</span>${integrityFilter === 'verified' ? '<span>✓</span>' : ''}</button>
                  <button onclick="event.stopPropagation(); app.setFilter('integrityFilter', 'failed')" class="w-full text-left px-3 py-2 flex items-center justify-between hover:bg-primary/10 hover:text-primary cursor-pointer text-error ${integrityFilter === 'failed' ? 'font-bold bg-primary/15' : ''}"><span>⚠ Failed / Tampered</span>${integrityFilter === 'failed' ? '<span>✓</span>' : ''}</button>
                  <button onclick="event.stopPropagation(); app.setFilter('integrityFilter', 'pending')" class="w-full text-left px-3 py-2 flex items-center justify-between hover:bg-primary/10 hover:text-primary cursor-pointer text-outline ${integrityFilter === 'pending' ? 'font-bold bg-primary/15' : ''}"><span>○ Pending Proof</span>${integrityFilter === 'pending' ? '<span>✓</span>' : ''}</button>
                </div>
              ` : ''}
            </div>

            <!-- ACTIVE CUSTOM CHIPS -->
            ${activeChips.join('')}

            <!-- RIGHT ACTION BUTTONS -->
            <div class="ml-auto flex items-center gap-3">
              ${hasActiveFilters ? `
                <button onclick="app.resetExplorerFilters()" class="font-label-caps text-label-caps text-on-surface-variant hover:text-error transition-colors cursor-pointer">
                  CLEAR FILTERS
                </button>
              ` : ''}
              <button onclick="app.toggleAddFilterModal(true)" class="font-label-caps text-label-caps text-primary hover:text-primary/80 transition-colors cursor-pointer">
                + ADD FILTER
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- BOTTOM RESULTS PANEL -->
      <div class="flex-1 bg-surface-container rounded shadow-md overflow-hidden flex flex-col relative min-h-[420px]">
        <!-- RESULTS SUMMARY & PAGINATION STRIP -->
        <div class="px-container-padding py-stack-sm bg-surface-container-high border-b border-outline-variant flex items-center justify-between">
          <div class="flex items-center gap-3">
            <span class="font-code-sm text-code-sm text-on-surface font-bold">${total.toLocaleString()}</span>
            <span class="font-label-caps text-label-caps text-on-surface-variant">EVENTS FOUND</span>
          </div>
          <div class="flex items-center gap-3">
            <span class="font-code-xs text-code-xs text-on-surface-variant">Page ${page} of ${totalPages}</span>
            <div class="flex items-center gap-1">
              <button onclick="app.changePage(${page - 1})" class="w-6 h-6 flex items-center justify-center bg-surface-container-highest rounded text-on-surface-variant hover:text-on-surface transition-colors cursor-pointer ${page <= 1 ? 'opacity-30 pointer-events-none' : ''}">
                <span class="material-symbols-outlined text-[16px]">chevron_left</span>
              </button>
              <button onclick="app.changePage(${page + 1})" class="w-6 h-6 flex items-center justify-center bg-surface-container-highest rounded text-on-surface-variant hover:text-on-surface transition-colors cursor-pointer ${page >= totalPages ? 'opacity-30 pointer-events-none' : ''}">
                <span class="material-symbols-outlined text-[16px]">chevron_right</span>
              </button>
            </div>
            <select onchange="app.changePageSize(Number(this.value))" class="bg-surface-container-lowest border border-outline-variant rounded px-2 py-0.5 font-code-xs text-code-xs text-on-surface focus:outline-none">
              <option value="25" ${pageSize === 25 ? 'selected' : ''}>25 / page</option>
              <option value="50" ${pageSize === 50 ? 'selected' : ''}>50 / page</option>
              <option value="100" ${pageSize === 100 ? 'selected' : ''}>100 / page</option>
            </select>
          </div>
        </div>

        <!-- TABLE CONTENT -->
        ${contentBody}
      </div>
    </div>
  `;
}
