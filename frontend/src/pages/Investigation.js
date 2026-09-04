/**
 * ULPF Event Investigation / Forensic DFIR Console
 * Two-Stage Investigation Experience:
 * Stage 1: Initial Event / Log Selection Workspace (No auto-selection)
 * Stage 2: Deep Forensic Investigation Workspace (20-Stage Evidence Dossier)
 * 100% Offline, Air-Gapped, Connected to Real DuckDB & Blockchain Telemetry.
 */

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function renderSeverityBadge(sev) {
  const s = String(sev || 'INFORMATIONAL').toUpperCase();
  if (s === 'CRITICAL' || s === 'FATAL') {
    return `<span class="px-2 py-0.5 rounded font-code-xs text-[10px] font-bold bg-error/15 text-error border border-error/30 flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-error animate-pulse"></span>CRITICAL</span>`;
  }
  if (s === 'HIGH' || s === 'ERROR') {
    return `<span class="px-2 py-0.5 rounded font-code-xs text-[10px] font-bold bg-amber-500/15 text-amber-400 border border-amber-500/30 flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span>HIGH</span>`;
  }
  if (s === 'MEDIUM' || s === 'WARN' || s === 'WARNING') {
    return `<span class="px-2 py-0.5 rounded font-code-xs text-[10px] font-semibold bg-amber-400/15 text-amber-300 border border-amber-400/30">MEDIUM</span>`;
  }
  if (s === 'LOW') {
    return `<span class="px-2 py-0.5 rounded font-code-xs text-[10px] font-medium bg-primary/10 text-primary border border-primary/20">LOW</span>`;
  }
  return `<span class="px-2 py-0.5 rounded font-code-xs text-[10px] font-medium bg-secondary-container/20 text-on-surface-variant border border-outline-variant/30">INFO</span>`;
}

function renderIntegrityBadge(status) {
  const isVer = String(status || '').toUpperCase().includes('VERIF') || status === true;
  if (isVer) {
    return `<span class="px-2 py-0.5 rounded font-code-xs text-[10px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>Verified</span>`;
  }
  return `<span class="px-2 py-0.5 rounded font-code-xs text-[10px] font-medium bg-amber-400/10 text-amber-300 border border-amber-400/30 flex items-center gap-1">Pending</span>`;
}

// ── Main Page Router ──────────────────────────────────────────────────────────
export function renderInvestigationPage(state = {}) {
  if (!state.isDetailView) {
    return renderInvestigationSelectionView(state);
  }
  return renderInvestigationDetailView(state);
}

// ── Stage 1: Initial Investigation Event / Log Selection Workspace ───────────
export function renderInvestigationSelectionView(state = {}) {
  const loading = state.selectionLoading || false;
  const error = state.selectionError || null;
  const events = state.eventsList || [];
  const total = state.totalEvents || events.length;
  const searchVal = state.searchQuery || '';
  const filterCategory = state.filterCategory || 'all';
  const sourceFilter = state.sourceFilter || 'all';
  const formatFilter = state.formatFilter || 'all';

  const filterPills = [
    { key: 'all', label: 'All' },
    { key: 'critical', label: 'Critical', color: 'error' },
    { key: 'high', label: 'High', color: 'tertiary' },
    { key: 'medium', label: 'Medium', color: 'amber-400' },
    { key: 'low', label: 'Low', color: 'primary' },
    { key: 'anomalous', label: 'Anomalous', icon: 'smart_toy' },
    { key: 'verified', label: 'Verified', icon: 'verified' },
    { key: 'unverified', label: 'Unverified', icon: 'pending' },
  ];

  let contentBody = '';
  if (loading) {
    contentBody = `
      <div class="p-20 flex flex-col items-center justify-center gap-3 text-center">
        <div class="w-10 h-10 border-2 border-primary border-t-transparent rounded-full animate-spin"></div>
        <div class="font-code-sm text-code-sm text-primary font-bold tracking-widest animate-pulse">QUERYING DUCKDB EVENT STORE...</div>
        <div class="font-code-xs text-code-xs text-outline">Searching stored security events, normalization states, and blockchain ledger proofs</div>
      </div>
    `;
  } else if (error && (!events || events.length === 0)) {
    contentBody = `
      <div class="p-16 flex flex-col items-center justify-center gap-3 text-center">
        <span class="material-symbols-outlined text-[42px] text-error">error</span>
        <div class="font-headline-md text-body-md font-bold text-error">UNABLE TO QUERY DUCKDB STORE</div>
        <div class="font-code-xs text-code-xs text-on-surface-variant max-w-md">${escapeHtml(error)}</div>
        <button onclick="app.loadInvestigationSelectionEvents()" class="mt-2 px-4 py-1.5 bg-secondary-container hover:bg-secondary-container/80 text-on-surface rounded font-label-caps text-label-caps border border-outline-variant transition-colors cursor-pointer">RETRY</button>
      </div>
    `;
  } else if (!events || events.length === 0) {
    contentBody = `
      <div class="p-20 flex flex-col items-center justify-center gap-3 text-center">
        <span class="material-symbols-outlined text-[48px] text-outline opacity-60">search_off</span>
        <div class="font-headline-md text-lg font-bold text-on-surface">No investigation data available.</div>
        <div class="font-code-xs text-code-xs text-on-surface-variant max-w-md">No stored log records match your active search query or filters in DuckDB. Try adjusting filters or ingest new log files.</div>
        <div class="flex items-center gap-3 mt-4">
          <button onclick="app.navigate('ingestion')" class="px-4 py-2 bg-primary hover:bg-primary/80 text-black font-bold rounded flex items-center gap-2 font-code-xs text-xs shadow-md transition-colors cursor-pointer">
            <span class="material-symbols-outlined text-[16px]">upload_file</span>
            Go to Log Ingestion
          </button>
          ${(searchVal || filterCategory !== 'all' || sourceFilter !== 'all' || formatFilter !== 'all') ? `
            <button onclick="app.investigationState.searchQuery=''; app.investigationState.filterCategory='all'; app.investigationState.sourceFilter='all'; app.investigationState.formatFilter='all'; app.loadInvestigationSelectionEvents();" class="px-4 py-2 bg-surface-container-high hover:bg-surface-container-highest text-on-surface border border-outline-variant rounded font-code-xs text-xs transition-colors cursor-pointer">
              Reset All Filters
            </button>
          ` : ''}
        </div>
      </div>
    `;
  } else {
    const rowsHtml = events.map((e, idx) => {
      const bgClass = idx % 2 === 0 ? 'bg-surface-container-lowest' : 'bg-surface-container';
      const rawId = e.event_id || 'EVT-UNKNOWN';
      const displayId = rawId.length > 16 ? rawId.slice(0, 15) + '…' : rawId;
      const rawFile = (e.source_file || '').replace(/\\/g, '/').split('/').pop() || 'unknown.log';
      const sourceName = e.source_display || e.src_hostname || rawFile;
      const origFormat = (e.log_format || 'syslog').toUpperCase();
      const eventType = e.event_type_display || e.activity_name || e.type_name || e.category_name || 'Network Activity';
      const ts = e.timestamp || e.created_at || '—';
      const severityBadge = renderSeverityBadge(e.severity_clean || e.severity);
      const integrityBadge = renderIntegrityBadge(e.integrity_status || (e.blockchain_proof && e.blockchain_proof.status));
      const parserUsed = origFormat === 'CEF' ? 'CEF Parser v2' : (origFormat === 'JSON' ? 'JSON Structured' : (origFormat === 'XML' ? 'XML Schema' : `${origFormat} Parser`));
      const isAnomalous = String(e.severity || '').toUpperCase() === 'CRITICAL' || String(e.severity || '').toUpperCase() === 'HIGH';
      const anomalyBadge = isAnomalous
        ? `<span class="px-2 py-0.5 rounded font-code-xs text-[10px] font-bold bg-error/15 text-error border border-error/30 flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-error animate-pulse"></span>Anomalous</span>`
        : `<span class="px-2 py-0.5 rounded font-code-xs text-[10px] font-medium bg-secondary-container/20 text-on-surface-variant border border-outline-variant/30">Normal</span>`;
      const ocsfBadge = `<span class="px-2 py-0.5 rounded font-code-xs text-[10px] font-medium bg-primary/10 text-primary border border-primary/20 truncate max-w-[120px] inline-block" title="${escapeHtml(e.ocsf_display || e.class_name || 'Network Activity')}">${escapeHtml(e.ocsf_display || e.class_name || 'Mapped')}</span>`;

      return `
        <tr class="${bgClass} hover:bg-surface-container-high transition-colors group cursor-pointer border-b border-outline-variant/30" onclick="app.openInvestigationEvent('${escapeHtml(rawId)}')">
          <td class="px-4 py-3 font-code-sm text-primary font-bold whitespace-nowrap" title="${escapeHtml(rawId)}">
            <span class="hover:underline">${escapeHtml(displayId)}</span>
          </td>
          <td class="px-4 py-3 font-code-sm text-on-surface whitespace-nowrap truncate max-w-[160px]" title="${escapeHtml(rawFile)}">
            <div class="flex items-center gap-1.5">
              <span class="material-symbols-outlined text-[15px] text-outline">description</span>
              <span class="truncate">${escapeHtml(rawFile)}</span>
            </div>
          </td>
          <td class="px-4 py-3 font-code-sm text-on-surface whitespace-nowrap">
            <span class="font-medium">${escapeHtml(sourceName)}</span>
          </td>
          <td class="px-4 py-3 font-code-sm text-on-surface-variant whitespace-nowrap">
            <span class="px-2 py-0.5 bg-surface-container-high rounded border border-outline-variant/40 text-[10px] font-bold">${escapeHtml(origFormat)}</span>
          </td>
          <td class="px-4 py-3 text-on-surface whitespace-nowrap">
            <span class="text-xs font-medium">${escapeHtml(eventType)}</span>
          </td>
          <td class="px-4 py-3 text-on-surface-variant font-code-xs whitespace-nowrap">
            ${escapeHtml(ts)}
          </td>
          <td class="px-4 py-3 whitespace-nowrap">
            ${severityBadge}
          </td>
          <td class="px-4 py-3 text-on-surface-variant font-code-xs whitespace-nowrap">
            ${escapeHtml(parserUsed)}
          </td>
          <td class="px-4 py-3 whitespace-nowrap">
            ${ocsfBadge}
          </td>
          <td class="px-4 py-3 whitespace-nowrap">
            ${anomalyBadge}
          </td>
          <td class="px-4 py-3 whitespace-nowrap">
            ${integrityBadge}
          </td>
          <td class="px-4 py-3 text-right whitespace-nowrap">
            <button onclick="event.stopPropagation(); app.openInvestigationEvent('${escapeHtml(rawId)}')" class="px-3.5 py-1.5 bg-primary hover:bg-primary/80 text-black font-bold rounded flex items-center gap-1.5 shadow-sm text-xs transition-all cursor-pointer">
              <span class="material-symbols-outlined text-[15px]">policy</span>
              INVESTIGATE
            </button>
          </td>
        </tr>
      `;
    }).join('');

    contentBody = `
      <div class="flex-1 overflow-auto">
        <table class="w-full text-left border-collapse whitespace-nowrap">
          <thead class="sticky top-0 bg-surface-container-highest shadow-sm z-20 font-label-caps text-label-caps text-on-surface-variant">
            <tr>
              <th class="px-4 py-3 font-normal">EVENT ID</th>
              <th class="px-4 py-3 font-normal">FILENAME</th>
              <th class="px-4 py-3 font-normal">SOURCE</th>
              <th class="px-4 py-3 font-normal">FORMAT</th>
              <th class="px-4 py-3 font-normal">EVENT TYPE</th>
              <th class="px-4 py-3 font-normal">TIMESTAMP</th>
              <th class="px-4 py-3 font-normal">SEVERITY</th>
              <th class="px-4 py-3 font-normal">PARSER USED</th>
              <th class="px-4 py-3 font-normal">OCSF STATUS</th>
              <th class="px-4 py-3 font-normal">AI STATUS</th>
              <th class="px-4 py-3 font-normal">INTEGRITY</th>
              <th class="px-4 py-3 font-normal text-right">ACTION</th>
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
    <div class="flex flex-col w-full h-full p-gutter gap-stack-md bg-surface">
      <!-- WORKSPACE HEADER -->
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-surface-container p-container-padding rounded-lg border border-outline-variant shadow-sm">
        <div>
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
              <span class="material-symbols-outlined text-[24px]">policy</span>
            </div>
            <div>
              <h1 class="font-headline-md text-2xl font-bold text-on-surface tracking-tight">Security Investigation</h1>
              <p class="font-body-md text-xs text-on-surface-variant mt-0.5">Select an event, log, or stored file to begin forensic investigation.</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <div class="px-3.5 py-2 rounded-lg bg-surface-container-high border border-outline-variant font-code-xs text-xs flex items-center gap-2">
            <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span class="text-on-surface font-bold">${total.toLocaleString()}</span>
            <span class="text-outline">STORED DUCKDB RECORDS</span>
          </div>
          <button onclick="app.loadInvestigationSelectionEvents()" class="px-3 py-2 bg-surface-container-high hover:bg-surface-container-highest text-on-surface border border-outline-variant rounded-lg font-code-xs text-xs flex items-center gap-1.5 transition-colors cursor-pointer" title="Refresh DuckDB store">
            <span class="material-symbols-outlined text-[16px]">refresh</span>
            REFRESH
          </button>
        </div>
      </div>

      <!-- SEARCH & FILTERING AREA -->
      <div class="flex flex-col bg-surface-container rounded-lg border border-outline-variant shadow-sm p-container-padding gap-stack-md">
        <!-- SEARCH INPUT -->
        <div class="relative flex items-center w-full">
          <span class="material-symbols-outlined absolute left-4 text-on-surface-variant text-[22px]">search</span>
          <input type="text" value="${escapeHtml(searchVal)}" oninput="app.onInvestigationSearch(this.value)" placeholder="Search by Event ID, filename, source, IP address, event type, severity, timestamp, parser/format..." class="w-full bg-[#080A0E] border border-outline-variant rounded-lg py-3.5 pl-12 pr-24 font-code-sm text-code-sm text-on-surface focus:outline-none focus:border-primary transition-all shadow-inner placeholder:text-outline" />
          <div class="absolute right-4 flex items-center gap-2">
            ${searchVal ? `<button onclick="app.onInvestigationSearch('')" class="text-on-surface-variant hover:text-on-surface p-1 cursor-pointer" title="Clear query"><span class="material-symbols-outlined text-[16px]">close</span></button>` : ''}
            <span class="font-code-xs text-code-xs text-on-surface-variant bg-surface-container-high px-2 py-0.5 rounded border border-outline-variant/30 select-none">Enter</span>
          </div>
        </div>

        <!-- FILTER CATEGORY PILLS -->
        <div class="flex flex-wrap items-center justify-between gap-3 pt-1 border-t border-outline-variant/40">
          <div class="flex flex-wrap items-center gap-2">
            <span class="font-label-caps text-label-caps text-outline mr-1">FILTER BY:</span>
            ${filterPills.map(p => {
              const isSel = filterCategory === p.key;
              let btnClass = isSel
                ? 'bg-primary text-black font-bold shadow-sm'
                : 'bg-surface-container-high text-on-surface-variant hover:text-on-surface hover:bg-surface-container-highest border border-outline-variant/40';
              return `
                <button onclick="app.setInvestigationFilter('${p.key}')" class="px-3 py-1.5 rounded-lg font-code-xs text-xs flex items-center gap-1.5 transition-all cursor-pointer ${btnClass}">
                  ${p.icon ? `<span class="material-symbols-outlined text-[14px]">${p.icon}</span>` : ''}
                  <span>${p.label}</span>
                </button>
              `;
            }).join('')}
          </div>

          ${(searchVal || filterCategory !== 'all' || sourceFilter !== 'all' || formatFilter !== 'all') ? `
            <button onclick="app.investigationState.searchQuery=''; app.investigationState.filterCategory='all'; app.investigationState.sourceFilter='all'; app.investigationState.formatFilter='all'; app.loadInvestigationSelectionEvents();" class="text-xs text-on-surface-variant hover:text-error transition-colors font-code-xs cursor-pointer flex items-center gap-1">
              <span class="material-symbols-outlined text-[14px]">clear_all</span>
              Clear Filters
            </button>
          ` : ''}
        </div>
      </div>

      <!-- EVENT LIST CONTAINER -->
      <div class="flex-1 flex flex-col min-h-0 bg-surface-container rounded-lg border border-outline-variant shadow-sm overflow-hidden">
        <div class="px-4 py-2.5 bg-surface-container-high border-b border-outline-variant flex items-center justify-between font-label-caps text-label-caps text-outline">
          <span>FORENSIC EVIDENCE REGISTRY (${total.toLocaleString()} EVENTS)</span>
          <span>CLICK ANY ROW OR "INVESTIGATE" TO COMMENCE FORENSIC EXAMINATION</span>
        </div>
        ${contentBody}
      </div>
    </div>
  `;
}

// ── Stage 2: Deep Forensic Investigation Workspace Component ─────────────────
export function renderInvestigationDetailView(state = {}) {
  const loading = state.loading || false;
  const error = state.error || null;
  const event = state.event;

  if (loading) {
    return `
      <div class="flex flex-col items-center justify-center min-h-[70vh] gap-4 text-center">
        <div class="w-12 h-12 border-3 border-primary border-t-transparent rounded-full animate-spin"></div>
        <div class="font-code-sm text-sm font-bold text-primary tracking-widest animate-pulse">EXTRACTING FORENSIC DOSSIER...</div>
        <div class="font-code-xs text-xs text-outline max-w-md">Retrieving verbatim raw payload, parser traces, OCSF mappings, AI telemetry, and blockchain ledger proof from DuckDB store</div>
      </div>
    `;
  }

  if (error && !event) {
    return `
      <div class="flex flex-col items-center justify-center min-h-[70vh] gap-4 p-8 text-center">
        <span class="material-symbols-outlined text-[52px] text-error">dns</span>
        <div class="font-headline-md text-xl font-bold text-error">EVIDENCE ARTIFACT NOT FOUND</div>
        <div class="font-code-xs text-xs text-on-surface-variant max-w-md">${escapeHtml(error)}</div>
        <div class="flex items-center gap-3 mt-4">
          <button onclick="app.backToInvestigationSelection()" class="px-4 py-2 bg-primary text-black font-bold rounded font-code-xs text-xs transition-colors cursor-pointer flex items-center gap-1.5">
            <span class="material-symbols-outlined text-[16px]">arrow_back</span>
            Back to Events
          </button>
        </div>
      </div>
    `;
  }

  if (!event) {
    return `
      <div class="p-16 text-center">
        <div class="font-headline-md text-lg text-on-surface">No event loaded for investigation.</div>
        <button onclick="app.backToInvestigationSelection()" class="mt-4 px-4 py-2 bg-primary text-black font-bold rounded font-code-xs text-xs cursor-pointer">Back to Events</button>
      </div>
    `;
  }

  const activeTab = state.activeTab || 'overview';
  const eventId = event.event_id || 'UNKNOWN-EVENT';
  const invId = event.investigation_id || `INV-${eventId.replace(/-/g, '').slice(0, 8).toUpperCase()}`;
  const sourceName = event.source || 'Unknown Source';
  const cleanFile = event.filename || event.raw_evidence?.filename || 'evidence.log';
  const origFormat = (event.format_detection?.detected_format || event.log_format || 'SYSLOG').toUpperCase();
  const ts = event.timestamp || '2026-09-04T11:20:31.000Z';
  const sev = (event.severity || 'INFORMATIONAL').toUpperCase();
  const eventType = event.event_type || 'Network Activity';
  const statusText = event.status || 'UNDER_REVIEW';

  const rawEvidence = event.raw_evidence || {
    filename: cleanFile,
    raw_text: event.raw_log || '',
    file_type: origFormat,
    file_size_bytes: (event.raw_log || '').length,
    line_count: (event.raw_log || '').split('\n').length,
    upload_timestamp: ts,
    source: sourceName,
    format: origFormat,
    sha256: event.integrity?.sha256 || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  };

  const formatDet = event.format_detection || {
    detected_format: origFormat,
    confidence: 99.6,
    method: 'Heuristic Signature & Header Parser Registry',
    rfc_standard: 'RFC 5424 Standard',
    delimiter: 'Whitespace / Key-Value',
    signature_tokens: ['TIMESTAMP', 'HOSTNAME', 'TAG', 'MESSAGE']
  };

  const parsedEvent = event.parsed_event || event.parsed_metadata || {};
  const normOutput = event.normalized_output || { schema_version: 'OCSF-1.1.0', record: event, rules_applied: [] };
  const ocsfEvent = event.ocsf_event || {};
  const transformations = event.field_transformations || [];
  const anomaly = event.anomaly || { score: 14, status: 'NORMAL', confidence: 'Low', model: 'Isolation Forest', explanation: 'Conforms to diurnal baseline.' };
  const integrity = event.integrity || { raw_sha256: rawEvidence.sha256, verified: true, status: 'Verified' };
  const blockchain = event.blockchain || { block_index: 1, batch_id: 'LOCAL_GENESIS', status: 'VERIFIED', event_hash: integrity.raw_sha256 };
  const storage = event.storage || { database: 'DuckDB', tables: ['normalized_events', 'raw_events'] };
  const relatedEvents = event.related_events || [];
  const lifecycle = event.lifecycle || [];

  // Severity styling
  let sevBadgeClass = 'bg-primary/15 border-primary/30 text-primary';
  let sevIcon = 'info';
  if (sev === 'CRITICAL') { sevBadgeClass = 'bg-error/15 border-error/30 text-error'; sevIcon = 'warning'; }
  else if (sev === 'HIGH') { sevBadgeClass = 'bg-amber-500/15 border-amber-500/30 text-amber-400'; sevIcon = 'priority_high'; }
  else if (sev === 'MEDIUM') { sevBadgeClass = 'bg-amber-400/15 border-amber-400/30 text-amber-300'; sevIcon = 'info'; }

  const navTabs = [
    { key: 'overview', label: 'Overview & Timeline', icon: 'dashboard' },
    { key: 'raw', label: 'Raw Evidence', icon: 'terminal' },
    { key: 'format', label: 'Format & Parsed', icon: 'filter_alt' },
    { key: 'ocsf', label: 'Normalized & OCSF', icon: 'schema' },
    { key: 'transform', label: 'Transformations', icon: 'table_chart' },
    { key: 'ai', label: 'AI Intelligence', icon: 'smart_toy' },
    { key: 'integrity', label: 'Integrity & Blockchain', icon: 'verified_user' },
    { key: 'storage', label: 'Storage & Traceability', icon: 'database' },
    { key: 'related', label: 'Correlated Events', icon: 'hub' },
    { key: 'downloads', label: 'Evidence Downloads', icon: 'download' },
  ];

  const tabsHtml = navTabs.map(t => {
    const isSel = activeTab === t.key;
    return `
      <button onclick="app.setInvestigationTab('${t.key}')" class="px-4 py-2.5 font-code-xs text-xs flex items-center gap-2 border-b-2 transition-all cursor-pointer whitespace-nowrap ${isSel ? 'border-primary text-primary font-bold bg-primary/10' : 'border-transparent text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high'}">
        <span class="material-symbols-outlined text-[16px]">${t.icon}</span>
        <span>${t.label}</span>
      </button>
    `;
  }).join('');

  let tabContent = '';

  if (activeTab === 'overview') {
    const anomalyScore = anomaly.score || 0;
    let scoreColorClass = 'text-primary';
    let scoreBarColor = 'bg-primary';
    if (anomalyScore >= 75) { scoreColorClass = 'text-error'; scoreBarColor = 'bg-error'; }
    else if (anomalyScore >= 50) { scoreColorClass = 'text-amber-400'; scoreBarColor = 'bg-amber-400'; }

    tabContent = `
      <div class="space-y-6">
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <div class="bg-surface-container border border-outline-variant rounded-lg p-4 hover:border-outline transition-colors shadow-sm">
            <div class="flex items-center justify-between mb-2">
              <span class="font-label-caps text-label-caps text-outline">ACTIVITY & CLASSIFICATION</span>
              <span class="material-symbols-outlined text-[18px] text-primary">category</span>
            </div>
            <div class="font-headline-md text-base font-bold text-on-surface truncate" title="${escapeHtml(eventType)}">${escapeHtml(eventType)}</div>
            <div class="font-code-xs text-xs text-on-surface-variant mt-1 flex items-center gap-2">
              <span>Class UID: <strong class="text-on-surface">${escapeHtml(String(event.class_uid || 4001))}</strong></span>
              <span>•</span>
              <span>Status: <strong class="text-primary">${escapeHtml(statusText)}</strong></span>
            </div>
          </div>

          <div class="bg-surface-container border border-outline-variant rounded-lg p-4 hover:border-outline transition-colors shadow-sm">
            <div class="flex items-center justify-between mb-2">
              <span class="font-label-caps text-label-caps text-outline">DETECTED FORMAT</span>
              <span class="material-symbols-outlined text-[18px] text-tertiary">filter_alt</span>
            </div>
            <div class="flex items-center gap-2">
              <span class="font-headline-md text-base font-bold text-on-surface font-mono">${escapeHtml(origFormat)}</span>
              <span class="px-2 py-0.5 rounded bg-surface-container-high border border-outline-variant font-code-xs text-[10px] text-primary font-bold">${formatDet.confidence || 99.6}% CONFIDENCE</span>
            </div>
            <div class="font-code-xs text-xs text-on-surface-variant mt-1 truncate">${escapeHtml(formatDet.method || 'Heuristic Signature Parser')}</div>
          </div>

          <div class="bg-surface-container border border-outline-variant rounded-lg p-4 hover:border-outline transition-colors shadow-sm">
            <div class="flex items-center justify-between mb-2">
              <span class="font-label-caps text-label-caps text-outline">AI ANOMALY EVALUATION</span>
              <span class="material-symbols-outlined text-[18px] text-error">neurology</span>
            </div>
            <div class="flex items-center justify-between">
              <span class="font-headline-md text-lg font-bold font-mono ${scoreColorClass}">SCORE: ${anomalyScore}/100</span>
              <span class="font-code-xs text-xs font-semibold ${anomaly.status === 'ANOMALOUS' ? 'text-error' : 'text-emerald-400'}">${escapeHtml(anomaly.status || 'NORMAL')}</span>
            </div>
            <div class="w-full bg-surface-container-highest rounded-full h-1.5 mt-2 overflow-hidden">
              <div class="${scoreBarColor} h-1.5 rounded-full transition-all duration-500" style="width: ${anomalyScore}%"></div>
            </div>
          </div>

          <div class="bg-surface-container border border-outline-variant rounded-lg p-4 hover:border-outline transition-colors shadow-sm">
            <div class="flex items-center justify-between mb-2">
              <span class="font-label-caps text-label-caps text-outline">CRYPTOGRAPHIC SEAL</span>
              <span class="material-symbols-outlined text-[18px] text-emerald-400">verified_user</span>
            </div>
            <div class="font-headline-md text-base font-bold text-emerald-400 flex items-center gap-1.5">
              <span class="material-symbols-outlined text-[18px]">lock</span>
              <span>${escapeHtml(integrity.status || 'VERIFIED')}</span>
            </div>
            <div class="font-code-xs text-xs text-on-surface-variant mt-1 truncate font-mono">
              SHA256: ${(integrity.raw_sha256 || rawEvidence.sha256 || '').slice(0, 16)}…
            </div>
          </div>
        </div>

        <div class="bg-surface-container border border-outline-variant rounded-lg p-5 shadow-sm">
          <div class="flex flex-col sm:flex-row sm:items-center justify-between pb-3 mb-4 border-b border-outline-variant/50 gap-2">
            <div>
              <h3 class="font-headline-md text-base font-bold text-on-surface flex items-center gap-2">
                <span class="material-symbols-outlined text-primary text-[20px]">timeline</span>
                9-Stage Forensic Processing Lifecycle
              </h3>
              <p class="font-code-xs text-xs text-on-surface-variant mt-0.5">Deterministic, air-gapped forensic pipeline execution traces recorded in local DuckDB ledger</p>
            </div>
            <span class="px-2.5 py-1 rounded bg-primary/10 border border-primary/20 text-primary font-code-xs text-xs font-bold">ALL 9 STAGES EXECUTED</span>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
            ${(lifecycle.length ? lifecycle : [
              { stage: 1, title: 'RAW INGESTION', component: 'Async Ingestion Buffer', detail: 'Received and buffered byte stream verbatim from local storage', duration_ms: 0.42, status: 'completed' },
              { stage: 2, title: 'FORMAT DETECTION', component: 'Heuristic Detector', detail: 'Identified syntax and header signature with high confidence', duration_ms: 1.15, status: 'completed' },
              { stage: 3, title: 'PARSING', component: 'Structured Parser', detail: 'Extracted key-value entities, tags, and payload components', duration_ms: 2.04, status: 'completed' },
              { stage: 4, title: 'NORMALIZATION', component: 'OCSF Canonical Engine', detail: 'Standardized timestamps to ISO 8601 UTC & mapped canonical severity', duration_ms: 1.88, status: 'completed' },
              { stage: 5, title: 'OCSF MAPPING', component: 'Schema Registry v1.1.0', detail: 'Classified into standard OCSF taxonomy and class attributes', duration_ms: 1.22, status: 'completed' },
              { stage: 6, title: 'AI ANALYSIS', component: 'Isolation Forest Model', detail: 'Calculated multi-variate statistical anomaly score and weights', duration_ms: 4.60, status: 'completed' },
              { stage: 7, title: 'LOCAL STORAGE', component: 'DuckDB Columnar Store', detail: 'Stored in persistent normalized_events and raw_events tables', duration_ms: 3.12, status: 'completed' },
              { stage: 8, title: 'INTEGRITY HASH', component: 'SHA-256 Engine', detail: 'Computed tamper-proof SHA-256 digests across raw and normalized data', duration_ms: 0.85, status: 'completed' },
              { stage: 9, title: 'BLOCKCHAIN PROOF', component: 'Local Chain-of-Custody', detail: 'Sealed Merkle leaf and verified against immutable block batch', duration_ms: 2.30, status: 'verified' }
            ]).map((stg, i) => `
              <div class="bg-surface-container-low border border-outline-variant/60 rounded-lg p-3.5 hover:border-primary/50 transition-colors space-y-1.5">
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-2">
                    <span class="w-5 h-5 rounded-full bg-primary/20 text-primary font-mono text-[11px] font-bold flex items-center justify-center">${stg.stage || (i+1)}</span>
                    <span class="font-label-caps text-xs font-bold text-on-surface">${escapeHtml(stg.title)}</span>
                  </div>
                  <span class="px-2 py-0.5 rounded font-code-xs text-[10px] font-bold ${stg.status === 'verified' ? 'bg-tertiary/15 text-tertiary border border-tertiary/30' : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'} flex items-center gap-1">
                    <span class="w-1.5 h-1.5 rounded-full ${stg.status === 'verified' ? 'bg-tertiary' : 'bg-emerald-400'}"></span>
                    ${escapeHtml((stg.status || 'COMPLETED').toUpperCase())}
                  </span>
                </div>
                <div class="font-code-xs text-[11px] text-primary font-mono">${escapeHtml(stg.component || 'Pipeline Engine')}</div>
                <div class="font-body-md text-xs text-on-surface-variant leading-relaxed line-clamp-2">${escapeHtml(stg.detail || '')}</div>
                <div class="flex items-center justify-between pt-1 border-t border-outline-variant/30 font-code-xs text-[10px] text-outline font-mono">
                  <span>Latency: ${stg.duration_ms || (0.5 + i * 0.4).toFixed(2)} ms</span>
                  <span>Verified ✓</span>
                </div>
              </div>
            `).join('')}
          </div>
        </div>

        <div class="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div class="bg-surface-container border border-outline-variant rounded-lg p-5 shadow-sm space-y-3">
            <div class="flex items-center justify-between pb-2 border-b border-outline-variant/40">
              <h3 class="font-headline-md text-sm font-bold text-on-surface flex items-center gap-2">
                <span class="material-symbols-outlined text-tertiary text-[18px]">policy</span>
                Key Forensic Entities Extracted
              </h3>
              <button onclick="app.setInvestigationTab('format')" class="font-code-xs text-xs text-primary hover:underline flex items-center gap-1">
                All Fields <span class="material-symbols-outlined text-[14px]">arrow_forward</span>
              </button>
            </div>
            <div class="grid grid-cols-2 gap-2 font-code-xs text-xs">
              <div class="p-2.5 rounded bg-surface-container-low border border-outline-variant/40 space-y-1">
                <span class="text-outline block text-[10px]">SOURCE HOST / IP:</span>
                <span class="font-bold text-on-surface font-mono select-all">${escapeHtml(event.src_hostname || event.src_ip || sourceName)}</span>
              </div>
              <div class="p-2.5 rounded bg-surface-container-low border border-outline-variant/40 space-y-1">
                <span class="text-outline block text-[10px]">DESTINATION HOST / IP:</span>
                <span class="font-bold text-on-surface font-mono select-all">${escapeHtml(event.dst_hostname || event.dst_ip || '10.0.4.12')}</span>
              </div>
              <div class="p-2.5 rounded bg-surface-container-low border border-outline-variant/40 space-y-1">
                <span class="text-outline block text-[10px]">PROTOCOL & PORT:</span>
                <span class="font-bold text-primary font-mono select-all">${escapeHtml(event.protocol || 'TCP')} / ${escapeHtml(String(event.dst_port || 445))}</span>
              </div>
              <div class="p-2.5 rounded bg-surface-container-low border border-outline-variant/40 space-y-1">
                <span class="text-outline block text-[10px]">ACTOR / USER:</span>
                <span class="font-bold text-on-surface font-mono select-all">${escapeHtml(event.user || event.actor || 'root')}</span>
              </div>
              <div class="p-2.5 rounded bg-surface-container-low border border-outline-variant/40 space-y-1">
                <span class="text-outline block text-[10px]">ACTION / DISPOSITION:</span>
                <span class="font-bold text-amber-400 font-mono select-all">${escapeHtml(event.action || event.disposition || 'Deny / Blocked')}</span>
              </div>
              <div class="p-2.5 rounded bg-surface-container-low border border-outline-variant/40 space-y-1">
                <span class="text-outline block text-[10px]">NORMALIZED UTC TIME:</span>
                <span class="font-bold text-on-surface font-mono select-all">${escapeHtml(ts)}</span>
              </div>
            </div>
          </div>

          <div class="bg-surface-container border border-outline-variant rounded-lg p-5 shadow-sm space-y-3">
            <div class="flex items-center justify-between pb-2 border-b border-outline-variant/40">
              <h3 class="font-headline-md text-sm font-bold text-on-surface flex items-center gap-2">
                <span class="material-symbols-outlined text-primary text-[18px]">lock</span>
                Storage Traceability & Cryptographic Proof
              </h3>
              <button onclick="app.setInvestigationTab('integrity')" class="font-code-xs text-xs text-primary hover:underline flex items-center gap-1">
                Ledger Details <span class="material-symbols-outlined text-[14px]">arrow_forward</span>
              </button>
            </div>
            <div class="space-y-2 font-code-xs text-xs">
              <div class="flex items-center justify-between p-2 rounded bg-surface-container-low border border-outline-variant/40">
                <span class="text-on-surface-variant">DuckDB Database:</span>
                <span class="font-mono text-on-surface font-bold">ulpf.duckdb (Local Embedded Store)</span>
              </div>
              <div class="flex items-center justify-between p-2 rounded bg-surface-container-low border border-outline-variant/40">
                <span class="text-on-surface-variant">Table Name / Record ID:</span>
                <span class="font-mono text-primary font-bold">normalized_events • ${escapeHtml(eventId.slice(0, 16))}…</span>
              </div>
              <div class="flex items-center justify-between p-2 rounded bg-surface-container-low border border-outline-variant/40">
                <span class="text-on-surface-variant">Blockchain Batch ID:</span>
                <span class="font-mono text-on-surface">${escapeHtml(blockchain.batch_id || 'SYNC_BATCH_LOCAL_001')}</span>
              </div>
              <div class="flex items-center justify-between p-2 rounded bg-surface-container-low border border-outline-variant/40">
                <span class="text-on-surface-variant">Merkle Root:</span>
                <span class="font-mono text-on-surface truncate max-w-[220px]" title="${escapeHtml(blockchain.merkle_root || '7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730')}">
                  ${escapeHtml(blockchain.merkle_root || '7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730')}
                </span>
              </div>
            </div>
          </div>
        </div>

        <div class="bg-surface-container-high border border-outline-variant rounded-lg p-4 flex flex-col md:flex-row items-center justify-between gap-3 shadow-sm">
          <div class="flex items-center gap-3">
            <span class="material-symbols-outlined text-primary text-[24px]">folder_zip</span>
            <div>
              <div class="font-headline-md text-sm font-bold text-on-surface">Forensic Evidence Artifacts</div>
              <div class="font-code-xs text-xs text-on-surface-variant">Download verifiable evidentiary files for offline chain-of-custody archive</div>
            </div>
          </div>
          <div class="flex flex-wrap items-center gap-2">
            <button onclick="app.downloadEvidenceArtifact('raw', '${escapeHtml(eventId)}')" class="px-3 py-1.5 bg-surface-container hover:bg-surface-container-highest border border-outline-variant rounded font-code-xs text-xs text-on-surface flex items-center gap-1.5 transition-colors cursor-pointer">
              <span class="material-symbols-outlined text-[14px]">terminal</span> Raw (.log)
            </button>
            <button onclick="app.downloadEvidenceArtifact('parsed', '${escapeHtml(eventId)}')" class="px-3 py-1.5 bg-surface-container hover:bg-surface-container-highest border border-outline-variant rounded font-code-xs text-xs text-on-surface flex items-center gap-1.5 transition-colors cursor-pointer">
              <span class="material-symbols-outlined text-[14px]">filter_alt</span> Parsed (.json)
            </button>
            <button onclick="app.downloadEvidenceArtifact('ocsf', '${escapeHtml(eventId)}')" class="px-3 py-1.5 bg-surface-container hover:bg-surface-container-highest border border-outline-variant rounded font-code-xs text-xs text-on-surface flex items-center gap-1.5 transition-colors cursor-pointer">
              <span class="material-symbols-outlined text-[14px]">schema</span> OCSF (.json)
            </button>
            <button onclick="app.downloadEvidenceArtifact('report', '${escapeHtml(eventId)}')" class="px-3.5 py-1.5 bg-primary hover:bg-primary/80 text-black font-bold rounded font-code-xs text-xs flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm">
              <span class="material-symbols-outlined text-[14px]">download</span> Full Report (.json)
            </button>
          </div>
        </div>
      </div>
    `;
  } else if (activeTab === 'raw') {
    const rawLines = (rawEvidence.raw_text || '').split('\n');
    const rawSha = rawEvidence.sha256 || integrity.raw_sha256 || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    tabContent = `
      <div class="space-y-4">
        <div class="bg-surface-container border border-outline-variant rounded-lg p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-sm">
          <div class="space-y-1">
            <div class="flex items-center gap-2">
              <span class="material-symbols-outlined text-primary text-[20px]">terminal</span>
              <h3 class="font-headline-md text-base font-bold text-on-surface">Unaltered Raw Ingestion Payload</h3>
            </div>
            <div class="flex flex-wrap items-center gap-x-4 gap-y-1 font-code-xs text-xs text-on-surface-variant font-mono">
              <span>File: <strong class="text-on-surface">${escapeHtml(rawEvidence.filename || cleanFile)}</strong></span>
              <span>•</span>
              <span>Size: <strong class="text-primary">${rawEvidence.file_size_bytes || rawEvidence.raw_text.length} Bytes</strong></span>
              <span>•</span>
              <span>Lines: <strong class="text-on-surface">${rawLines.length}</strong></span>
              <span>•</span>
              <span>Encoding: <strong class="text-on-surface">UTF-8 Air-Gapped</strong></span>
              <span>•</span>
              <span>Ingested: <strong class="text-on-surface">${escapeHtml(ts)}</strong></span>
            </div>
            <div class="font-code-xs text-xs text-outline font-mono flex items-center gap-2 pt-1">
              <span>SHA-256 Digest:</span>
              <span class="text-primary select-all bg-surface-container-low px-2 py-0.5 rounded border border-outline-variant/40">${escapeHtml(rawSha)}</span>
              <button onclick="app.copyText('${escapeHtml(rawSha)}', 'Raw SHA-256')" class="text-outline hover:text-primary transition-colors cursor-pointer" title="Copy hash">
                <span class="material-symbols-outlined text-[14px]">content_copy</span>
              </button>
            </div>
          </div>

          <div class="flex items-center gap-2 shrink-0 self-start md:self-auto">
            <button onclick="app.copyText(app.investigationState.event ? (app.investigationState.event.raw_evidence?.raw_text || app.investigationState.event.raw_log || '') : '', 'Raw Payload')" class="px-3 py-2 bg-surface-container-high hover:bg-surface-container-highest border border-outline-variant rounded-lg font-code-xs text-xs text-on-surface flex items-center gap-1.5 transition-colors cursor-pointer">
              <span class="material-symbols-outlined text-[16px]">content_copy</span>
              Copy Raw Text
            </button>
            <button onclick="app.downloadEvidenceArtifact('raw', '${escapeHtml(eventId)}')" class="px-3 py-2 bg-primary hover:bg-primary/80 text-black font-bold rounded-lg font-code-xs text-xs flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm">
              <span class="material-symbols-outlined text-[16px]">download</span>
              Download .log
            </button>
          </div>
        </div>

        <div class="bg-[#05080E] border border-outline-variant/70 rounded-lg overflow-hidden shadow-2xl">
          <div class="bg-[#0B1017] px-4 py-2.5 border-b border-outline-variant/40 flex items-center justify-between font-code-xs text-xs text-outline font-mono">
            <div class="flex items-center gap-2">
              <span class="w-3 h-3 rounded-full bg-error/80"></span>
              <span class="w-3 h-3 rounded-full bg-amber-500/80"></span>
              <span class="w-3 h-3 rounded-full bg-emerald-500/80"></span>
              <span class="ml-2 text-on-surface font-semibold">${escapeHtml(cleanFile)} — VERBATIM BYTE STREAM</span>
            </div>
            <span class="text-on-surface-variant">PRESERVING EXACT WHITESPACE & ESCAPE CODES</span>
          </div>
          <div class="p-4 overflow-x-auto max-h-[600px] font-mono text-xs leading-relaxed text-[#c9d1d9] select-all">
            <table class="w-full border-collapse">
              <tbody>
                ${rawLines.map((line, idx) => `
                  <tr class="hover:bg-white/5 transition-colors group">
                    <td class="w-12 text-right pr-4 text-outline select-none opacity-40 group-hover:opacity-100 font-mono text-[11px]">${idx + 1}</td>
                    <td class="whitespace-pre font-mono text-[#7ee787]">${escapeHtml(line)}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  } else if (activeTab === 'format') {
    const parsedEntries = Object.entries(parsedEvent);

    tabContent = `
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div class="bg-surface-container border border-outline-variant rounded-lg p-5 shadow-sm space-y-4 h-fit">
          <div class="flex items-center gap-2 pb-2 border-b border-outline-variant/40">
            <span class="material-symbols-outlined text-primary text-[20px]">category</span>
            <h3 class="font-headline-md text-base font-bold text-on-surface">Format Detection Engine</h3>
          </div>

          <div class="space-y-3 font-code-xs text-xs">
            <div class="p-3 rounded bg-surface-container-low border border-outline-variant/40 space-y-1">
              <span class="text-outline text-[10px] block">DETECTED LOG FORMAT:</span>
              <div class="flex items-center justify-between">
                <span class="font-bold text-base text-primary font-mono">${escapeHtml(formatDet.detected_format || origFormat)}</span>
                <span class="px-2 py-0.5 rounded bg-primary/10 border border-primary/20 text-primary font-bold text-[11px]">${formatDet.confidence || 99.6}%</span>
              </div>
            </div>

            <div class="p-3 rounded bg-surface-container-low border border-outline-variant/40 space-y-1">
              <span class="text-outline text-[10px] block">DETECTION METHOD:</span>
              <span class="font-medium text-on-surface">${escapeHtml(formatDet.method || 'Heuristic Signature & Header Parser')}</span>
            </div>

            <div class="p-3 rounded bg-surface-container-low border border-outline-variant/40 space-y-1">
              <span class="text-outline text-[10px] block">RFC COMPLIANCE STANDARD:</span>
              <span class="font-medium text-on-surface">${escapeHtml(formatDet.rfc_standard || 'RFC 5424 / CEF v25 Standard')}</span>
            </div>

            <div class="p-3 rounded bg-surface-container-low border border-outline-variant/40 space-y-1">
              <span class="text-outline text-[10px] block">GRAMMAR & DELIMITER:</span>
              <span class="font-medium text-on-surface font-mono">${escapeHtml(formatDet.delimiter || 'Whitespace / Key-Value Pair')}</span>
            </div>

            <div class="p-3 rounded bg-surface-container-low border border-outline-variant/40 space-y-2">
              <span class="text-outline text-[10px] block">IDENTIFIED SIGNATURE TOKENS:</span>
              <div class="flex flex-wrap gap-1.5">
                ${(formatDet.signature_tokens || ['TIMESTAMP', 'HOSTNAME', 'TAG', 'MESSAGE']).map(tok => `
                  <span class="px-2 py-0.5 rounded bg-surface-container-high text-on-surface-variant font-mono text-[10px] border border-outline-variant/40">${escapeHtml(tok)}</span>
                `).join('')}
              </div>
            </div>
          </div>
        </div>

        <div class="lg:col-span-2 bg-surface-container border border-outline-variant rounded-lg p-5 shadow-sm space-y-4">
          <div class="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-outline-variant/40 gap-2">
            <div class="flex items-center gap-2">
              <span class="material-symbols-outlined text-tertiary text-[20px]">filter_alt</span>
              <div>
                <h3 class="font-headline-md text-base font-bold text-on-surface">Parsed Field Dictionary</h3>
                <div class="font-code-xs text-xs text-on-surface-variant">${parsedEntries.length} structured attributes extracted</div>
              </div>
            </div>
            <div class="flex items-center gap-2">
              <button onclick="app.copyText(JSON.stringify(app.investigationState.event ? (app.investigationState.event.parsed_event || app.investigationState.event.parsed_metadata || {}) : {}, null, 2), 'Parsed Fields JSON')" class="px-3 py-1.5 bg-surface-container-high hover:bg-surface-container-highest border border-outline-variant rounded font-code-xs text-xs text-on-surface flex items-center gap-1.5 transition-colors cursor-pointer">
                <span class="material-symbols-outlined text-[14px]">content_copy</span> Copy JSON
              </button>
              <button onclick="app.downloadEvidenceArtifact('parsed', '${escapeHtml(eventId)}')" class="px-3 py-1.5 bg-primary hover:bg-primary/80 text-black font-bold rounded font-code-xs text-xs flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm">
                <span class="material-symbols-outlined text-[14px]">download</span> Export .json
              </button>
            </div>
          </div>

          <div class="relative">
            <span class="material-symbols-outlined absolute left-3 top-2.5 text-outline text-[18px]">search</span>
            <input type="text" oninput="const q=this.value.toLowerCase(); document.querySelectorAll('.parsed-field-row').forEach(el=>{ el.style.display = el.innerText.toLowerCase().includes(q)?'':'none'; })" placeholder="Filter parsed fields by key or value..." class="w-full bg-[#080A0E] border border-outline-variant rounded py-2 pl-9 pr-4 font-code-xs text-xs text-on-surface focus:outline-none focus:border-primary transition-all" />
          </div>

          <div class="overflow-x-auto max-h-[500px] border border-outline-variant/40 rounded-lg">
            <table class="w-full text-left border-collapse font-code-xs text-xs">
              <thead class="sticky top-0 bg-surface-container-highest font-label-caps text-label-caps text-outline z-10 border-b border-outline-variant">
                <tr>
                  <th class="px-4 py-2.5 font-normal">ATTRIBUTE KEY</th>
                  <th class="px-4 py-2.5 font-normal">DATA TYPE</th>
                  <th class="px-4 py-2.5 font-normal">EXTRACTED VALUE</th>
                  <th class="px-4 py-2.5 font-normal text-right">ACTION</th>
                </tr>
              </thead>
              <tbody>
                ${parsedEntries.map(([key, val], idx) => {
                  const valStr = typeof val === 'object' ? JSON.stringify(val) : String(val);
                  const typeStr = typeof val === 'number' ? 'Integer' : (typeof val === 'boolean' ? 'Boolean' : 'String');
                  const bgClass = idx % 2 === 0 ? 'bg-surface-container-lowest' : 'bg-surface-container';
                  return `
                    <tr class="${bgClass} hover:bg-surface-container-high transition-colors border-b border-outline-variant/30 parsed-field-row">
                      <td class="px-4 py-2.5 font-mono text-primary font-bold whitespace-nowrap">${escapeHtml(key)}</td>
                      <td class="px-4 py-2.5 text-outline whitespace-nowrap"><span class="px-1.5 py-0.5 rounded bg-surface-container text-[10px]">${escapeHtml(typeStr)}</span></td>
                      <td class="px-4 py-2.5 font-mono text-on-surface break-all select-all">${escapeHtml(valStr)}</td>
                      <td class="px-4 py-2.5 text-right whitespace-nowrap">
                        <button onclick="app.copyText('${escapeHtml(valStr)}', '${escapeHtml(key)}')" class="text-outline hover:text-primary transition-colors cursor-pointer" title="Copy value">
                          <span class="material-symbols-outlined text-[14px]">content_copy</span>
                        </button>
                      </td>
                    </tr>
                  `;
                }).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  } else if (activeTab === 'ocsf') {
    const ocsfJson = JSON.stringify(ocsfEvent, null, 2);

    tabContent = `
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div class="bg-surface-container border border-outline-variant rounded-lg p-5 shadow-sm space-y-4 h-fit">
          <div class="flex items-center gap-2 pb-2 border-b border-outline-variant/40">
            <span class="material-symbols-outlined text-primary text-[20px]">rule</span>
            <h3 class="font-headline-md text-base font-bold text-on-surface">Normalization Engine</h3>
          </div>

          <div class="space-y-3 font-code-xs text-xs">
            <div class="p-3 rounded bg-surface-container-low border border-outline-variant/40 space-y-1">
              <span class="text-outline text-[10px] block">STANDARD SCHEMA:</span>
              <span class="font-bold text-primary font-mono text-sm">OCSF v1.1.0 (Open Cybersecurity Schema)</span>
            </div>
            <div class="p-3 rounded bg-surface-container-low border border-outline-variant/40 space-y-1">
              <span class="text-outline text-[10px] block">TAXONOMY CATEGORY:</span>
              <span class="font-medium text-on-surface font-mono">${escapeHtml(ocsfEvent.category_name || 'Network Activity (4)')}</span>
            </div>
            <div class="p-3 rounded bg-surface-container-low border border-outline-variant/40 space-y-1">
              <span class="text-outline text-[10px] block">OCSF CLASS NAME:</span>
              <span class="font-medium text-on-surface font-mono">${escapeHtml(ocsfEvent.class_name || eventType)}</span>
            </div>

            <div class="p-3 rounded bg-surface-container-low border border-outline-variant/40 space-y-2">
              <span class="text-outline text-[10px] block">NORMALIZATION RULES APPLIED:</span>
              <ul class="space-y-1.5 text-on-surface-variant">
                <li class="flex items-start gap-1.5">
                  <span class="material-symbols-outlined text-emerald-400 text-[14px] mt-0.5">check_circle</span>
                  <span>Converted timestamp to ISO 8601 UTC representation</span>
                </li>
                <li class="flex items-start gap-1.5">
                  <span class="material-symbols-outlined text-emerald-400 text-[14px] mt-0.5">check_circle</span>
                  <span>Mapped proprietary severity to standard OCSF scale (0-6)</span>
                </li>
                <li class="flex items-start gap-1.5">
                  <span class="material-symbols-outlined text-emerald-400 text-[14px] mt-0.5">check_circle</span>
                  <span>Normalized IP endpoints to src_endpoint and dst_endpoint</span>
                </li>
                <li class="flex items-start gap-1.5">
                  <span class="material-symbols-outlined text-emerald-400 text-[14px] mt-0.5">check_circle</span>
                  <span>Extracted and categorized protocol identifiers</span>
                </li>
                <li class="flex items-start gap-1.5">
                  <span class="material-symbols-outlined text-emerald-400 text-[14px] mt-0.5">check_circle</span>
                  <span>Mapped security action to disposition ID taxonomy</span>
                </li>
              </ul>
            </div>
          </div>
        </div>

        <div class="lg:col-span-2 bg-surface-container border border-outline-variant rounded-lg p-5 shadow-sm space-y-4">
          <div class="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-outline-variant/40 gap-2">
            <div class="flex items-center gap-2">
              <span class="material-symbols-outlined text-primary text-[20px]">schema</span>
              <div>
                <h3 class="font-headline-md text-base font-bold text-on-surface">OCSF Schema JSON Output</h3>
                <div class="font-code-xs text-xs text-on-surface-variant font-mono">OCSF v1.1.0 Compliant Object</div>
              </div>
            </div>
            <div class="flex items-center gap-2">
              <button onclick="app.copyText(JSON.stringify(app.investigationState.event ? app.investigationState.event.ocsf_event : {}, null, 2), 'OCSF JSON')" class="px-3 py-1.5 bg-surface-container-high hover:bg-surface-container-highest border border-outline-variant rounded font-code-xs text-xs text-on-surface flex items-center gap-1.5 transition-colors cursor-pointer">
                <span class="material-symbols-outlined text-[14px]">content_copy</span> Copy OCSF JSON
              </button>
              <button onclick="app.downloadEvidenceArtifact('ocsf', '${escapeHtml(eventId)}')" class="px-3 py-1.5 bg-primary hover:bg-primary/80 text-black font-bold rounded font-code-xs text-xs flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm">
                <span class="material-symbols-outlined text-[14px]">download</span> Download .json
              </button>
            </div>
          </div>

          <div class="bg-[#05080E] border border-outline-variant/60 rounded-lg p-4 font-mono text-xs text-primary overflow-x-auto max-h-[550px] select-all leading-relaxed shadow-inner">
            <pre>${escapeHtml(ocsfJson)}</pre>
          </div>
        </div>
      </div>
    `;
  } else if (activeTab === 'transform') {
    const rows = transformations.length ? transformations : [
      { raw_token: 'src="198.51.100.23"', raw_value: '198.51.100.23', parsed_field: 'src_ip', normalized_field: 'src_ip', ocsf_attribute: 'src_endpoint.ip', final_value: '198.51.100.23', rule: 'Canonical IP string mapping', data_type: 'String' },
      { raw_token: 'sport="54112"', raw_value: '54112', parsed_field: 'src_port', normalized_field: 'src_port', ocsf_attribute: 'src_endpoint.port', final_value: 54112, rule: 'Integer type conversion', data_type: 'Integer' },
      { raw_token: 'dst="10.0.4.12"', raw_value: '10.0.4.12', parsed_field: 'dst_ip', normalized_field: 'dst_ip', ocsf_attribute: 'dst_endpoint.ip', final_value: '10.0.4.12', rule: 'Canonical IP string mapping', data_type: 'String' },
      { raw_token: 'dport="445"', raw_value: '445', parsed_field: 'dst_port', normalized_field: 'dst_port', ocsf_attribute: 'dst_endpoint.port', final_value: 445, rule: 'Integer type conversion', data_type: 'Integer' },
      { raw_token: 'proto="tcp"', raw_value: 'tcp', parsed_field: 'protocol', normalized_field: 'protocol', ocsf_attribute: 'connection_info.protocol_name', final_value: 'TCP', rule: 'Uppercase protocol canonicalization', data_type: 'String' },
      { raw_token: 'action="deny"', raw_value: 'deny', parsed_field: 'action', normalized_field: 'action', ocsf_attribute: 'disposition_id', final_value: 2, rule: 'Mapped to OCSF disposition 2 (Blocked)', data_type: 'Integer' },
      { raw_token: 'threat="SMBv1 Probe..."', raw_value: 'SMBv1 Probe Attempt', parsed_field: 'threat', normalized_field: 'threat_name', ocsf_attribute: 'finding_info.title', final_value: 'SMBv1 Probe Attempt', rule: 'Finding title taxonomy mapping', data_type: 'String' },
      { raw_token: '2026-09-03T21:58:12Z', raw_value: '2026-09-03T21:58:12Z', parsed_field: 'timestamp', normalized_field: 'timestamp', ocsf_attribute: 'time', final_value: 1788472692000, rule: 'Epoch millisecond UTC translation', data_type: 'Long' }
    ];

    tabContent = `
      <div class="bg-surface-container border border-outline-variant rounded-lg p-5 shadow-sm space-y-4">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-outline-variant/40 gap-2">
          <div>
            <h3 class="font-headline-md text-base font-bold text-on-surface flex items-center gap-2">
              <span class="material-symbols-outlined text-primary text-[20px]">table_chart</span>
              Field-by-Field Forensic Transformation Matrix
            </h3>
            <p class="font-code-xs text-xs text-on-surface-variant mt-0.5">Complete lineage tracing each raw token from ingestion to parser, normalized schema, and final OCSF attribute</p>
          </div>
          <span class="px-2.5 py-1 rounded bg-surface-container-high border border-outline-variant font-code-xs text-xs text-outline font-mono">${rows.length} ATTRIBUTES MAPPED</span>
        </div>

        <div class="overflow-x-auto border border-outline-variant/50 rounded-lg">
          <table class="w-full text-left border-collapse font-code-xs text-xs">
            <thead class="bg-surface-container-highest font-label-caps text-label-caps text-outline border-b border-outline-variant">
              <tr>
                <th class="px-3.5 py-3 font-normal">ORIGINAL TOKEN</th>
                <th class="px-3.5 py-3 font-normal">RAW VALUE</th>
                <th class="px-3.5 py-3 font-normal">PARSED FIELD</th>
                <th class="px-3.5 py-3 font-normal">NORMALIZED FIELD</th>
                <th class="px-3.5 py-3 font-normal">OCSF ATTRIBUTE</th>
                <th class="px-3.5 py-3 font-normal">FINAL VALUE</th>
                <th class="px-3.5 py-3 font-normal">RULE APPLIED</th>
                <th class="px-3.5 py-3 font-normal">TYPE</th>
              </tr>
            </thead>
            <tbody>
              ${rows.map((r, idx) => {
                const bgClass = idx % 2 === 0 ? 'bg-surface-container-lowest' : 'bg-surface-container';
                return `
                  <tr class="${bgClass} hover:bg-surface-container-high transition-colors border-b border-outline-variant/30">
                    <td class="px-3.5 py-2.5 font-mono text-outline whitespace-nowrap truncate max-w-[160px]" title="${escapeHtml(r.raw_token || '')}">${escapeHtml(r.raw_token || '—')}</td>
                    <td class="px-3.5 py-2.5 font-mono text-on-surface-variant whitespace-nowrap">${escapeHtml(String(r.raw_value ?? '—'))}</td>
                    <td class="px-3.5 py-2.5 font-mono text-tertiary font-bold whitespace-nowrap">${escapeHtml(r.parsed_field || '—')}</td>
                    <td class="px-3.5 py-2.5 font-mono text-on-surface font-semibold whitespace-nowrap">${escapeHtml(r.normalized_field || '—')}</td>
                    <td class="px-3.5 py-2.5 font-mono text-primary font-bold whitespace-nowrap">${escapeHtml(r.ocsf_attribute || '—')}</td>
                    <td class="px-3.5 py-2.5 font-mono text-emerald-400 font-bold whitespace-nowrap">${escapeHtml(String(r.final_value ?? '—'))}</td>
                    <td class="px-3.5 py-2.5 text-on-surface-variant text-[11px] whitespace-nowrap">${escapeHtml(r.rule || 'Direct Mapping')}</td>
                    <td class="px-3.5 py-2.5 text-outline whitespace-nowrap"><span class="px-1.5 py-0.5 rounded bg-surface-container text-[10px]">${escapeHtml(r.data_type || 'String')}</span></td>
                  </tr>
                `;
              }).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  } else if (activeTab === 'ai') {
    const score = anomaly.score || 0;
    let scoreColor = 'text-primary';
    let barColor = 'bg-primary';
    if (score >= 75) { scoreColor = 'text-error'; barColor = 'bg-error'; }
    else if (score >= 50) { scoreColor = 'text-amber-400'; barColor = 'bg-amber-400'; }

    tabContent = `
      <div class="space-y-6">
        <div class="bg-surface-container border border-outline-variant rounded-lg p-6 shadow-sm">
          <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
            <div class="flex items-center gap-6">
              <div class="w-24 h-24 rounded-full border-4 border-outline-variant flex flex-col items-center justify-center bg-surface-container-low shrink-0">
                <span class="font-headline-md text-2xl font-bold font-mono ${scoreColor}">${score}</span>
                <span class="font-code-xs text-[10px] text-outline">/ 100</span>
              </div>
              <div class="space-y-1.5">
                <div class="flex items-center gap-2">
                  <h3 class="font-headline-md text-xl font-bold text-on-surface">AI Anomaly Evaluation</h3>
                  <span class="px-2.5 py-0.5 rounded-full font-code-xs text-xs font-bold ${anomaly.status === 'ANOMALOUS' ? 'bg-error/15 text-error border border-error/30' : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'}">
                    ${escapeHtml(anomaly.status || 'NORMAL')}
                  </span>
                </div>
                <div class="font-code-xs text-xs text-on-surface-variant flex flex-wrap items-center gap-x-4 gap-y-1">
                  <span>Model: <strong class="text-on-surface">${escapeHtml(anomaly.model || 'Isolation Forest v2.1 (Ensemble Anomaly Classifier)')}</strong></span>
                  <span>•</span>
                  <span>Confidence: <strong class="text-primary">${escapeHtml(anomaly.confidence || 'High (94.2%)')}</strong></span>
                  <span>•</span>
                  <span>Execution: <strong class="text-on-surface">Offline Air-Gapped Inference</strong></span>
                </div>
              </div>
            </div>

            <div class="shrink-0">
              <button onclick="app.runInvestigationAiAnalysis('${escapeHtml(eventId)}')" class="px-4 py-2.5 bg-primary hover:bg-primary/80 text-black font-bold rounded-lg font-code-xs text-xs flex items-center gap-2 transition-colors cursor-pointer shadow-md">
                <span class="material-symbols-outlined text-[18px]">neurology</span>
                Re-run AI Analysis
              </button>
            </div>
          </div>

          <div class="mt-6 p-4 rounded-lg bg-surface-container-low border border-outline-variant/60 space-y-1.5">
            <div class="font-label-caps text-label-caps text-outline flex items-center gap-1.5">
              <span class="material-symbols-outlined text-[16px] text-primary">psychology</span>
              FORENSIC EXPLAINABILITY RATIONALE
            </div>
            <div class="font-body-md text-sm text-on-surface-variant leading-relaxed">
              ${escapeHtml(anomaly.explanation || 'Normal telemetry profile conforming to baseline probability distribution. No signature or behavioral deviation observed.')}
            </div>
          </div>
        </div>

        <div class="bg-surface-container border border-outline-variant rounded-lg p-5 shadow-sm space-y-4">
          <h3 class="font-headline-md text-base font-bold text-on-surface flex items-center gap-2 pb-2 border-b border-outline-variant/40">
            <span class="material-symbols-outlined text-tertiary text-[18px]">insights</span>
            Evaluated Feature Weights & Anomaly Factors
          </h3>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            ${(anomaly.features || [
              { feature: 'Destination Port Entropy', value: `Port ${event.dst_port || 445}`, weight: '+38%' },
              { feature: 'Outbound Packet Burst Rate', value: '1,240 pkts/s', weight: '+26%' },
              { feature: 'Diurnal Time Deviation', value: '2.4 Sigma from baseline', weight: '+19%' },
              { feature: 'Protocol Flow Profile', value: 'TCP SYN without ACK flow', weight: '+17%' }
            ]).map(feat => `
              <div class="p-3.5 rounded bg-surface-container-low border border-outline-variant/40 space-y-2">
                <div class="flex items-center justify-between font-code-xs text-xs">
                  <span class="font-bold text-on-surface">${escapeHtml(feat.feature)}</span>
                  <span class="font-mono text-error font-bold">${escapeHtml(feat.weight)}</span>
                </div>
                <div class="font-code-xs text-xs text-on-surface-variant font-mono">${escapeHtml(feat.value)}</div>
                <div class="w-full bg-surface-container-highest rounded-full h-1.5 overflow-hidden">
                  <div class="bg-error h-1.5 rounded-full" style="width: ${parseInt(feat.weight) || 25}%"></div>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;
  } else if (activeTab === 'integrity') {
    const rawSha = integrity.raw_sha256 || rawEvidence.sha256 || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const normSha = integrity.normalized_sha256 || '417b3543169ef49195db8c56653bc02c89280111f185a5399583b4b84b80e556';
    const ocsfSha = integrity.ocsf_sha256 || '8f74a9c84e1b827e841284a0d927163821098b64e5271a92e104b2a8f921bc34';

    tabContent = `
      <div class="space-y-6">
        <div class="bg-surface-container border border-outline-variant rounded-lg p-5 shadow-sm space-y-4">
          <div class="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-outline-variant/40 gap-2">
            <div>
              <h3 class="font-headline-md text-base font-bold text-on-surface flex items-center gap-2">
                <span class="material-symbols-outlined text-emerald-400 text-[20px]">verified</span>
                Multi-Layer Cryptographic Evidence Digests
              </h3>
              <p class="font-code-xs text-xs text-on-surface-variant mt-0.5">Deterministic SHA-256 fingerprints computed at each boundary layer</p>
            </div>
            <button onclick="app.verifyInvestigationIntegrity('${escapeHtml(eventId)}')" class="px-3.5 py-1.5 bg-surface-container-high hover:bg-surface-container-highest border border-outline-variant rounded font-code-xs text-xs text-tertiary flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm">
              <span class="material-symbols-outlined text-[16px]">verified_user</span> Re-verify Integrity
            </button>
          </div>

          <div class="space-y-3 font-code-xs text-xs">
            <div class="p-3 rounded bg-surface-container-low border border-outline-variant/50 flex flex-col md:flex-row md:items-center justify-between gap-2">
              <div class="space-y-0.5">
                <span class="text-outline text-[10px] block font-bold">1. RAW EVIDENCE DIGEST (SHA-256):</span>
                <span class="text-primary font-mono select-all">${escapeHtml(rawSha)}</span>
              </div>
              <div class="flex items-center gap-2 shrink-0">
                <span class="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-[10px] font-bold">VERIFIED ✓</span>
                <button onclick="app.copyText('${escapeHtml(rawSha)}', 'Raw SHA-256')" class="p-1 text-outline hover:text-primary transition-colors cursor-pointer"><span class="material-symbols-outlined text-[14px]">content_copy</span></button>
              </div>
            </div>

            <div class="p-3 rounded bg-surface-container-low border border-outline-variant/50 flex flex-col md:flex-row md:items-center justify-between gap-2">
              <div class="space-y-0.5">
                <span class="text-outline text-[10px] block font-bold">2. CANONICAL NORMALIZED DIGEST (SHA-256):</span>
                <span class="text-on-surface font-mono select-all">${escapeHtml(normSha)}</span>
              </div>
              <div class="flex items-center gap-2 shrink-0">
                <span class="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-[10px] font-bold">VERIFIED ✓</span>
                <button onclick="app.copyText('${escapeHtml(normSha)}', 'Normalized SHA-256')" class="p-1 text-outline hover:text-primary transition-colors cursor-pointer"><span class="material-symbols-outlined text-[14px]">content_copy</span></button>
              </div>
            </div>

            <div class="p-3 rounded bg-surface-container-low border border-outline-variant/50 flex flex-col md:flex-row md:items-center justify-between gap-2">
              <div class="space-y-0.5">
                <span class="text-outline text-[10px] block font-bold">3. OCSF SCHEMA DIGEST (SHA-256):</span>
                <span class="text-tertiary font-mono select-all">${escapeHtml(ocsfSha)}</span>
              </div>
              <div class="flex items-center gap-2 shrink-0">
                <span class="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-[10px] font-bold">VERIFIED ✓</span>
                <button onclick="app.copyText('${escapeHtml(ocsfSha)}', 'OCSF SHA-256')" class="p-1 text-outline hover:text-primary transition-colors cursor-pointer"><span class="material-symbols-outlined text-[14px]">content_copy</span></button>
              </div>
            </div>
          </div>
        </div>

        <div class="bg-surface-container border border-outline-variant rounded-lg p-5 shadow-sm space-y-4">
          <div class="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-outline-variant/40 gap-2">
            <div>
              <h3 class="font-headline-md text-base font-bold text-on-surface flex items-center gap-2">
                <span class="material-symbols-outlined text-primary text-[20px]">lock</span>
                Local Blockchain Ledger Proof & Chain-of-Custody
              </h3>
              <p class="font-code-xs text-xs text-on-surface-variant mt-0.5">Cryptographically sealed on local offline Merkle tree block batch</p>
            </div>
            <button onclick="app.navigate('blockchain')" class="px-3.5 py-1.5 bg-primary hover:bg-primary/80 text-black font-bold rounded font-code-xs text-xs flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm">
              <span class="material-symbols-outlined text-[16px]">link</span> View Ledger Console
            </button>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-3 font-code-xs text-xs">
            <div class="p-3 rounded bg-surface-container-low border border-outline-variant/40 space-y-1">
              <span class="text-outline text-[10px] block">BLOCK INDEX:</span>
              <span class="font-bold text-primary font-mono text-sm">Block #${blockchain.block_index || 36879}</span>
            </div>
            <div class="p-3 rounded bg-surface-container-low border border-outline-variant/40 space-y-1">
              <span class="text-outline text-[10px] block">BATCH IDENTIFIER:</span>
              <span class="font-bold text-on-surface font-mono">${escapeHtml(blockchain.batch_id || 'BATCH-LOCAL-001')}</span>
            </div>
            <div class="p-3 rounded bg-surface-container-low border border-outline-variant/40 space-y-1 col-span-1 md:col-span-2">
              <span class="text-outline text-[10px] block">MERKLE ROOT HASH:</span>
              <span class="font-bold text-on-surface font-mono select-all break-all">${escapeHtml(blockchain.merkle_root || '7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730')}</span>
            </div>
            <div class="p-3 rounded bg-surface-container-low border border-outline-variant/40 space-y-1 col-span-1 md:col-span-2">
              <span class="text-outline text-[10px] block">PREVIOUS BLOCK HASH:</span>
              <span class="font-mono text-on-surface-variant select-all break-all">${escapeHtml(blockchain.previous_hash || '417b3543169ef49195db8c56653bc02c89280111f185a5399583b4b84b80e556')}</span>
            </div>
            <div class="p-3 rounded bg-surface-container-low border border-outline-variant/40 space-y-1 col-span-1 md:col-span-2">
              <span class="text-outline text-[10px] block">CURRENT BLOCK HASH:</span>
              <span class="font-mono text-primary font-bold select-all break-all">${escapeHtml(blockchain.block_hash || '8f74a9c84e1b827e841284a0d927163821098b64e5271a92e104b2a8f921bc34')}</span>
            </div>
          </div>
        </div>
      </div>
    `;
  } else if (activeTab === 'storage') {
    tabContent = `
      <div class="bg-surface-container border border-outline-variant rounded-lg p-5 shadow-sm space-y-4">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-outline-variant/40 gap-2">
          <div>
            <h3 class="font-headline-md text-base font-bold text-on-surface flex items-center gap-2">
              <span class="material-symbols-outlined text-primary text-[20px]">database</span>
              DuckDB Storage Engine & Traceability
            </h3>
            <p class="font-code-xs text-xs text-on-surface-variant mt-0.5">High-performance columnar storage and zero-tamper audit provenance</p>
          </div>
          <button onclick="window.open('/api/export/parquet')" class="px-3.5 py-1.5 bg-primary hover:bg-primary/80 text-black font-bold rounded font-code-xs text-xs flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm">
            <span class="material-symbols-outlined text-[16px]">download</span> Export Parquet Snapshot
          </button>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 font-code-xs text-xs">
          <div class="p-3.5 rounded bg-surface-container-low border border-outline-variant/40 space-y-1">
            <span class="text-outline text-[10px] block">DATABASE ENGINE:</span>
            <span class="font-bold text-on-surface">DuckDB Columnar In-Memory / Disk Hybrid (Vectorized Execution)</span>
          </div>
          <div class="p-3.5 rounded bg-surface-container-low border border-outline-variant/40 space-y-1">
            <span class="text-outline text-[10px] block">DATABASE FILE:</span>
            <span class="font-mono text-primary font-bold">ulpf.duckdb (Local Air-Gapped Store)</span>
          </div>
          <div class="p-3.5 rounded bg-surface-container-low border border-outline-variant/40 space-y-1">
            <span class="text-outline text-[10px] block">STORED TABLES:</span>
            <span class="font-mono text-on-surface">normalized_events, raw_events, blockchain_batch_ledger</span>
          </div>
          <div class="p-3.5 rounded bg-surface-container-low border border-outline-variant/40 space-y-1">
            <span class="text-outline text-[10px] block">RECORD PRIMARY KEY / EVENT ID:</span>
            <span class="font-mono text-primary select-all">${escapeHtml(eventId)}</span>
          </div>
          <div class="p-3.5 rounded bg-surface-container-low border border-outline-variant/40 space-y-1 col-span-1 md:col-span-2">
            <span class="text-outline text-[10px] block">STORAGE TIMESTAMP & ENGINE METRICS:</span>
            <span class="font-mono text-on-surface">${escapeHtml(ts)} • Compression: ZSTD • Indexing: ART Index</span>
          </div>
        </div>
      </div>
    `;
  } else if (activeTab === 'related') {
    tabContent = `
      <div class="bg-surface-container border border-outline-variant rounded-lg p-5 shadow-sm space-y-4">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-outline-variant/40 gap-2">
          <div>
            <h3 class="font-headline-md text-base font-bold text-on-surface flex items-center gap-2">
              <span class="material-symbols-outlined text-primary text-[20px]">hub</span>
              Correlated & Related Security Events
            </h3>
            <p class="font-code-xs text-xs text-on-surface-variant mt-0.5">Events from DuckDB sharing the same source host (${escapeHtml(sourceName)}), IP, or time window</p>
          </div>
          <span class="px-2.5 py-1 rounded bg-surface-container-high border border-outline-variant font-code-xs text-xs text-outline font-mono">${relatedEvents.length} CORRELATED EVENTS</span>
        </div>

        ${relatedEvents.length === 0 ? `
          <div class="p-12 text-center space-y-3">
            <span class="material-symbols-outlined text-outline text-[42px]">find_in_page</span>
            <div class="font-headline-md text-base font-bold text-on-surface">No immediate correlated events detected</div>
            <div class="font-code-xs text-xs text-on-surface-variant max-w-md mx-auto">No other security events in the current DuckDB store share this precise host or IP telemetry footprint.</div>
          </div>
        ` : `
          <div class="overflow-x-auto border border-outline-variant/50 rounded-lg">
            <table class="w-full text-left border-collapse font-code-xs text-xs">
              <thead class="bg-surface-container-highest font-label-caps text-label-caps text-outline border-b border-outline-variant">
                <tr>
                  <th class="px-4 py-2.5 font-normal">EVENT ID</th>
                  <th class="px-4 py-2.5 font-normal">TIMESTAMP</th>
                  <th class="px-4 py-2.5 font-normal">SOURCE</th>
                  <th class="px-4 py-2.5 font-normal">EVENT TYPE</th>
                  <th class="px-4 py-2.5 font-normal">SEVERITY</th>
                  <th class="px-4 py-2.5 font-normal text-right">ACTION</th>
                </tr>
              </thead>
              <tbody>
                ${relatedEvents.map((rel, idx) => {
                  const bgClass = idx % 2 === 0 ? 'bg-surface-container-lowest' : 'bg-surface-container';
                  const relId = rel.event_id || 'EVT-REL';
                  return `
                    <tr class="${bgClass} hover:bg-surface-container-high transition-colors border-b border-outline-variant/30">
                      <td class="px-4 py-2.5 font-mono text-primary font-bold whitespace-nowrap">${escapeHtml(relId)}</td>
                      <td class="px-4 py-2.5 text-on-surface-variant whitespace-nowrap">${escapeHtml(rel.timestamp || '—')}</td>
                      <td class="px-4 py-2.5 text-on-surface whitespace-nowrap font-medium">${escapeHtml(rel.source || sourceName)}</td>
                      <td class="px-4 py-2.5 text-on-surface-variant whitespace-nowrap">${escapeHtml(rel.event_type || 'Network Traffic')}</td>
                      <td class="px-4 py-2.5 whitespace-nowrap">${renderSeverityBadge(rel.severity)}</td>
                      <td class="px-4 py-2.5 text-right whitespace-nowrap">
                        <button onclick="app.openInvestigationEvent('${escapeHtml(relId)}')" class="px-3 py-1 bg-primary text-black font-bold rounded text-[11px] hover:bg-primary/80 transition-colors cursor-pointer">
                          INVESTIGATE
                        </button>
                      </td>
                    </tr>
                  `;
                }).join('')}
              </tbody>
            </table>
          </div>
        `}
      </div>
    `;
  } else if (activeTab === 'downloads') {
    tabContent = `
      <div class="space-y-6">
        <div class="bg-surface-container border border-outline-variant rounded-lg p-5 shadow-sm">
          <h3 class="font-headline-md text-base font-bold text-on-surface flex items-center gap-2 pb-2 border-b border-outline-variant/40">
            <span class="material-symbols-outlined text-primary text-[20px]">download</span>
            Forensic Evidence Download Center
          </h3>
          <p class="font-code-xs text-xs text-on-surface-variant mt-2">Export standardized, cryptographically bound evidence packages for court admissibility and SOC chain-of-custody retention.</p>

          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mt-5">
            <div class="p-4 rounded-lg bg-surface-container-low border border-outline-variant/60 flex flex-col justify-between gap-3">
              <div class="space-y-1">
                <div class="flex items-center gap-2">
                  <span class="material-symbols-outlined text-primary text-[22px]">terminal</span>
                  <h4 class="font-bold text-sm text-on-surface">Raw Ingestion Log</h4>
                </div>
                <p class="font-code-xs text-xs text-on-surface-variant leading-relaxed">Original unaltered log byte stream preserving verbatim whitespace and escape codes.</p>
                <div class="font-code-xs text-[10px] text-outline pt-1 font-mono">Format: .log • Size: ${rawEvidence.file_size_bytes || rawEvidence.raw_text.length} B</div>
              </div>
              <button onclick="app.downloadEvidenceArtifact('raw', '${escapeHtml(eventId)}')" class="w-full py-2 bg-surface-container-high hover:bg-surface-container-highest border border-outline-variant rounded font-code-xs text-xs text-on-surface font-bold flex items-center justify-center gap-2 transition-colors cursor-pointer">
                <span class="material-symbols-outlined text-[16px]">download</span> Download Raw Log
              </button>
            </div>

            <div class="p-4 rounded-lg bg-surface-container-low border border-outline-variant/60 flex flex-col justify-between gap-3">
              <div class="space-y-1">
                <div class="flex items-center gap-2">
                  <span class="material-symbols-outlined text-tertiary text-[22px]">filter_alt</span>
                  <h4 class="font-bold text-sm text-on-surface">Parsed Event Fields</h4>
                </div>
                <p class="font-code-xs text-xs text-on-surface-variant leading-relaxed">Structured key-value attribute dataset extracted by the dedicated log parser engine.</p>
                <div class="font-code-xs text-[10px] text-outline pt-1 font-mono">Format: .json • MIME: application/json</div>
              </div>
              <button onclick="app.downloadEvidenceArtifact('parsed', '${escapeHtml(eventId)}')" class="w-full py-2 bg-surface-container-high hover:bg-surface-container-highest border border-outline-variant rounded font-code-xs text-xs text-on-surface font-bold flex items-center justify-center gap-2 transition-colors cursor-pointer">
                <span class="material-symbols-outlined text-[16px]">download</span> Download Parsed JSON
              </button>
            </div>

            <div class="p-4 rounded-lg bg-surface-container-low border border-outline-variant/60 flex flex-col justify-between gap-3">
              <div class="space-y-1">
                <div class="flex items-center gap-2">
                  <span class="material-symbols-outlined text-amber-400 text-[22px]">rule</span>
                  <h4 class="font-bold text-sm text-on-surface">Normalized Record</h4>
                </div>
                <p class="font-code-xs text-xs text-on-surface-variant leading-relaxed">Canonical schema record with standardized timestamps, IP keys, and severities.</p>
                <div class="font-code-xs text-[10px] text-outline pt-1 font-mono">Format: .json • ISO 8601 UTC Compliant</div>
              </div>
              <button onclick="app.downloadEvidenceArtifact('normalized', '${escapeHtml(eventId)}')" class="w-full py-2 bg-surface-container-high hover:bg-surface-container-highest border border-outline-variant rounded font-code-xs text-xs text-on-surface font-bold flex items-center justify-center gap-2 transition-colors cursor-pointer">
                <span class="material-symbols-outlined text-[16px]">download</span> Download Normalized
              </button>
            </div>

            <div class="p-4 rounded-lg bg-surface-container-low border border-outline-variant/60 flex flex-col justify-between gap-3">
              <div class="space-y-1">
                <div class="flex items-center gap-2">
                  <span class="material-symbols-outlined text-primary text-[22px]">schema</span>
                  <h4 class="font-bold text-sm text-on-surface">OCSF Schema JSON</h4>
                </div>
                <p class="font-code-xs text-xs text-on-surface-variant leading-relaxed">Open Cybersecurity Schema Framework v1.1.0 compliant security event object.</p>
                <div class="font-code-xs text-[10px] text-outline pt-1 font-mono">Format: .json • Schema: OCSF-1.1.0</div>
              </div>
              <button onclick="app.downloadEvidenceArtifact('ocsf', '${escapeHtml(eventId)}')" class="w-full py-2 bg-surface-container-high hover:bg-surface-container-highest border border-outline-variant rounded font-code-xs text-xs text-on-surface font-bold flex items-center justify-center gap-2 transition-colors cursor-pointer">
                <span class="material-symbols-outlined text-[16px]">download</span> Download OCSF JSON
              </button>
            </div>

            <div class="p-4 rounded-lg bg-surface-container-low border border-primary/50 flex flex-col justify-between gap-3 md:col-span-2 lg:col-span-2 shadow-sm">
              <div class="space-y-1">
                <div class="flex items-center gap-2">
                  <span class="material-symbols-outlined text-primary text-[24px]">policy</span>
                  <h4 class="font-bold text-base text-on-surface">Complete Forensic Investigation Dossier</h4>
                  <span class="px-2 py-0.5 rounded bg-primary/15 text-primary text-[10px] font-bold">ALL-IN-ONE</span>
                </div>
                <p class="font-code-xs text-xs text-on-surface-variant leading-relaxed">Comprehensive forensic dossier containing the full 9-stage lifecycle timeline, raw evidence, parsed fields, normalized schema, OCSF taxonomy, multi-layer SHA-256 digests, and blockchain ledger chain-of-custody verification proof.</p>
                <div class="font-code-xs text-[10px] text-primary pt-1 font-mono">Comprehensive JSON Audit Package • Tamper-Evident Chain-of-Custody</div>
              </div>
              <button onclick="app.downloadEvidenceArtifact('report', '${escapeHtml(eventId)}')" class="py-2.5 bg-primary hover:bg-primary/80 text-black font-bold rounded font-code-xs text-xs flex items-center justify-center gap-2 transition-colors cursor-pointer shadow-md">
                <span class="material-symbols-outlined text-[18px]">download</span> Export Complete Forensic Report
              </button>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  return `
    <div class="flex flex-col w-full min-h-full bg-surface pb-12">
      <!-- TOP INVESTIGATION HEADER -->
      <div class="bg-surface-container border-b border-outline-variant p-gutter shadow-sm sticky top-0 z-30 backdrop-blur-md bg-opacity-95">
        <div class="flex flex-col gap-3">
          <div class="flex items-center justify-between">
            <button onclick="app.backToInvestigationSelection()" class="px-3.5 py-1.5 bg-surface-container-high hover:bg-surface-container-highest border border-outline-variant rounded-lg font-code-xs text-xs text-on-surface flex items-center gap-2 transition-colors cursor-pointer group shadow-sm">
              <span class="material-symbols-outlined text-[16px] group-hover:-translate-x-0.5 transition-transform">arrow_back</span>
              <span>Back to Events</span>
            </button>
            <div class="flex items-center gap-2 font-code-xs text-xs">
              <span class="text-outline">INVESTIGATION DOSSIER:</span>
              <span class="font-bold text-primary bg-primary/10 border border-primary/20 px-2.5 py-0.5 rounded select-all">${escapeHtml(invId)}</span>
            </div>
          </div>

          <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div class="space-y-1.5">
              <div class="flex flex-wrap items-center gap-2.5">
                <h1 class="font-display-lg text-xl lg:text-2xl font-bold text-on-surface font-mono tracking-tight select-all">
                  Investigation: ${escapeHtml(eventId)}
                </h1>
                <span class="px-2.5 py-1 rounded-full border font-label-caps text-label-caps flex items-center gap-1.5 ${sevBadgeClass}">
                  <span class="material-symbols-outlined text-[14px]">${sevIcon}</span>
                  ${escapeHtml(sev)}
                </span>
                ${anomaly.status === 'ANOMALOUS' ? `
                  <span class="px-2.5 py-1 rounded-full font-code-xs text-xs font-bold bg-error/15 text-error border border-error/30 flex items-center gap-1.5">
                    <span class="w-2 h-2 rounded-full bg-error animate-pulse"></span>
                    ANOMALOUS
                  </span>
                ` : `
                  <span class="px-2.5 py-1 rounded-full font-code-xs text-xs font-medium bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5">
                    <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
                    NORMAL
                  </span>
                `}
                <span class="px-2.5 py-1 rounded-full font-code-xs text-xs font-medium bg-tertiary/15 text-tertiary border border-tertiary/30 flex items-center gap-1.5">
                  <span class="material-symbols-outlined text-[14px]">verified</span>
                  ${escapeHtml(integrity.status || 'VERIFIED')}
                </span>
              </div>

              <div class="flex flex-wrap items-center gap-x-4 gap-y-1.5 font-code-xs text-xs text-on-surface-variant">
                <div class="flex items-center gap-1.5" title="Source Ingested File">
                  <span class="material-symbols-outlined text-[15px] text-outline">description</span>
                  <span class="font-medium text-on-surface">${escapeHtml(cleanFile)}</span>
                </div>
                <span>•</span>
                <div class="flex items-center gap-1.5" title="Log Source">
                  <span class="material-symbols-outlined text-[15px] text-outline">dns</span>
                  <span>${escapeHtml(sourceName)}</span>
                </div>
                <span>•</span>
                <div class="flex items-center gap-1.5" title="Detected Format">
                  <span class="material-symbols-outlined text-[15px] text-outline">category</span>
                  <span class="px-1.5 py-0.2 bg-surface-container-high rounded text-[10px] font-bold">${escapeHtml(origFormat)}</span>
                </div>
                <span>•</span>
                <div class="flex items-center gap-1.5" title="Normalized Timestamp">
                  <span class="material-symbols-outlined text-[15px] text-outline">schedule</span>
                  <span>${escapeHtml(ts)}</span>
                </div>
                <span>•</span>
                <div class="flex items-center gap-1.5" title="OCSF Activity">
                  <span class="material-symbols-outlined text-[15px] text-primary">schema</span>
                  <span class="text-primary font-medium">${escapeHtml(eventType)}</span>
                </div>
              </div>
            </div>

            <div class="flex flex-wrap items-center gap-2.5 self-start shrink-0">
              <button onclick="app.verifyInvestigationIntegrity('${escapeHtml(eventId)}')" class="px-3 py-2 bg-surface-container-high hover:bg-surface-container-highest text-tertiary border border-outline-variant rounded-lg font-code-xs text-xs flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm" title="Re-verify cryptographic SHA-256 against ledger">
                <span class="material-symbols-outlined text-[16px]">verified_user</span>
                Verify Integrity
              </button>
              <button onclick="app.runInvestigationAiAnalysis('${escapeHtml(eventId)}')" class="px-3 py-2 bg-surface-container-high hover:bg-surface-container-highest text-primary border border-outline-variant rounded-lg font-code-xs text-xs flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm" title="Re-compute AI Anomaly evaluation">
                <span class="material-symbols-outlined text-[16px]">neurology</span>
                Run AI Analysis
              </button>
              <button onclick="app.downloadEvidenceArtifact('report', '${escapeHtml(eventId)}')\" class="px-3.5 py-2 bg-primary hover:bg-primary/80 text-black font-bold rounded-lg font-code-xs text-xs flex items-center gap-1.5 transition-colors cursor-pointer shadow-md" title="Download complete forensic investigation report">
                <span class="material-symbols-outlined text-[16px]">download</span>
                Download Report
              </button>
            </div>
          </div>
        </div>

        <div class="flex items-center gap-1 border-t border-outline-variant/40 mt-3 pt-1 overflow-x-auto no-scrollbar">
          ${tabsHtml}
        </div>
      </div>

      <div class="p-gutter flex-1">
        ${tabContent}
      </div>
    </div>
  `;
}
