/**
 * ULPF Dashboard Component
 * Security Operations Overview with processing pipeline overview,
 * event volume bar charts, and source distribution donut graphs.
 */

function formatKpiNumber(num) {
  if (num === null || num === undefined) return '0';
  const n = Number(num);
  if (isNaN(n)) return '0';
  if (n >= 1000000) return (n / 1000000).toFixed(1).replace(/\.0$/, '') + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1).replace(/\.0$/, '') + 'K';
  return n.toLocaleString();
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function renderAiResolutionsTableRows(aiResolutions = []) {
  if (!aiResolutions || aiResolutions.length === 0) {
    return `
      <tr>
        <td colspan="8" class="p-6 text-center text-on-surface-variant font-code-xs">
          No unknown format resolutions recorded yet. Known formats and learned parsers execute with 0 Ollama calls.
        </td>
      </tr>
    `;
  }
  return aiResolutions.map(r => {
    let aiUsedBadge = '';
    if (r.ai_used === true) {
      aiUsedBadge = `<span class="px-2 py-0.5 rounded bg-primary/15 text-primary border border-primary/30 font-mono text-[10px] font-bold">YES (${escapeHtml(r.model || 'qwen3:4b')})</span>`;
    } else if (r.resolution_status === 'cached' || r.parser_type === 'learned_cache') {
      aiUsedBadge = `<span class="px-2 py-0.5 rounded bg-[#34d399]/15 text-[#34d399] border border-[#34d399]/30 font-mono text-[10px] font-medium">NO (Learned Reuse)</span>`;
    } else {
      aiUsedBadge = `<span class="px-2 py-0.5 rounded bg-outline-variant/30 text-on-surface-variant border border-outline-variant font-mono text-[10px]">NO (Rule-Based)</span>`;
    }

    let resBadge = '';
    const stLower = (r.resolution_status || '').toLowerCase();
    if (stLower === 'promoted') {
      resBadge = `<span class="px-2 py-0.5 rounded bg-[#10b981]/15 text-[#34d399] border border-[#10b981]/30 font-mono text-[10px] font-bold">PROMOTED</span>`;
    } else if (stLower === 'cached') {
      resBadge = `<span class="px-2 py-0.5 rounded bg-tertiary/15 text-tertiary border border-tertiary/30 font-mono text-[10px]">CACHED</span>`;
    } else if (stLower === 'pending_review' || stLower === 'review' || stLower === 'rejected') {
      resBadge = `<span class="px-2 py-0.5 rounded bg-[#f59e0b]/15 text-[#fbbf24] border border-[#f59e0b]/30 font-mono text-[10px]">REVIEW</span>`;
    } else {
      resBadge = `<span class="px-2 py-0.5 rounded bg-outline-variant/30 text-on-surface-variant border border-outline-variant font-mono text-[10px]">${escapeHtml(r.resolution_status || 'UNKNOWN')}</span>`;
    }

    const latStr = r.latency_ms > 0 ? (r.latency_ms >= 1000 ? (r.latency_ms / 1000).toFixed(1) + 's' : Math.round(r.latency_ms) + 'ms') : '0.0ms';
    const accStr = r.accuracy != null ? `${r.accuracy}%` : (r.confidence != null ? `${Math.round(r.confidence * 100)}% conf` : '-');
    const shortFp = (r.fingerprint && r.fingerprint.length > 12) ? r.fingerprint.slice(0, 10) + '...' : (r.fingerprint || '-');

    return `
      <tr class="border-b border-outline-variant/40 hover:bg-surface-container-high/40 transition-colors">
        <td class="p-2.5 pl-3 text-on-surface-variant whitespace-nowrap text-[11px]">${r.timestamp || '—'}</td>
        <td class="p-2.5 text-on-surface font-mono text-[11px]">${escapeHtml(r.source || '—')}</td>
        <td class="p-2.5 font-mono text-[11px] text-primary" title="${escapeHtml(r.fingerprint || '')}">${escapeHtml(shortFp)}</td>
        <td class="p-2.5 text-on-surface-variant font-mono text-[11px]">${escapeHtml(r.format || r.parser_type || '—')}</td>
        <td class="p-2.5 text-center">${aiUsedBadge}</td>
        <td class="p-2.5 text-center">${resBadge}</td>
        <td class="p-2.5 text-right font-mono text-on-surface text-[11px]">${accStr}</td>
        <td class="p-2.5 pr-3 text-right font-mono text-on-surface-variant text-[11px]">${latStr}</td>
      </tr>
    `;
  }).join('');
}

export function renderDashboardPage(dashboardState = {}) {
  const summary = dashboardState.summary || {};
  const volume = dashboardState.volume || { buckets: [], max_eps: 0 };
  const sources = dashboardState.sources || { distribution: [], total_events: 0 };
  const recentEvents = dashboardState.recentEvents || [];
  const aiStatus = dashboardState.aiStatus || {};
  const aiMetrics = dashboardState.aiMetrics || {};
  const aiResolutions = dashboardState.aiResolutions || [];
  const loading = dashboardState.loading || false;
  const error = dashboardState.error || null;

  // Pipeline stage throughput indicator if EPS metric is available
  const stageEpsHtml = (volume && typeof volume.max_eps === 'number') ? `
    <div class="mt-2 pt-2 border-t border-outline-variant/60 flex items-center justify-between font-mono text-[10px]">
      <span class="text-on-surface-variant font-sans">Throughput</span>
      <span class="text-primary font-semibold">${volume.max_eps} EPS</span>
    </div>
  ` : '';

  // Loading skeleton if no data has arrived yet
  if (loading && !summary.events_processed) {
    return `
      <div class="flex flex-col w-full p-gutter space-y-stack-md">
        <div class="grid grid-cols-6 gap-gutter">
          ${[1,2,3,4,5,6].map(() => `
            <div class="col-span-1 bg-surface-container p-4 rounded-xl border border-outline-variant h-24 animate-pulse flex flex-col justify-between">
              <div class="h-3 w-20 bg-surface-container-highest rounded"></div>
              <div class="h-8 w-14 bg-surface-container-highest rounded"></div>
            </div>
          `).join('')}
        </div>
        <div class="bg-surface-container p-6 rounded-xl border border-outline-variant h-32 animate-pulse"></div>
        <div class="grid grid-cols-2 gap-gutter">
          <div class="bg-surface-container p-6 rounded-xl border border-outline-variant h-64 animate-pulse"></div>
          <div class="bg-surface-container p-6 rounded-xl border border-outline-variant h-64 animate-pulse"></div>
        </div>
        <div class="bg-surface-container rounded-xl border border-outline-variant h-64 animate-pulse"></div>
      </div>
    `;
  }

  // Event Volume Bar Chart generation
  const buckets = volume.buckets || [];
  const maxCount = volume.max_hourly_count || 1;
  const barsHtml = buckets.length > 0 ? buckets.map((b, i) => {
    const isPeak = b.count > 0 && b.count === maxCount;
    const heightPct = maxCount > 0 ? Math.max(4, Math.round((b.count / maxCount) * 100)) : 4;
    return `
      <div class="volume-bar w-full ${isPeak ? 'bg-primary/40 hover:bg-primary/60' : 'bg-primary/20 hover:bg-primary/40'} transition-all duration-700 ease-out rounded-t-sm border-t border-primary relative group cursor-pointer" style="height: ${heightPct}%;" id="vol-bar-${i}" data-hour="${b.hour}" data-count="${b.count}">
        <div class="peak-dot ${isPeak ? '' : 'hidden'} absolute -top-1 w-2 h-2 rounded-full bg-primary left-1/2 -translate-x-1/2 shadow-[0_0_8px_rgba(152,203,255,0.8)]"></div>
        <div class="vol-tooltip hidden group-hover:block absolute -top-8 left-1/2 -translate-x-1/2 bg-surface-container-highest px-2 py-1 rounded text-code-xs font-code-xs text-on-surface z-20 whitespace-nowrap border border-outline-variant shadow-lg pointer-events-none">
          ${b.label} — ${b.count.toLocaleString()}
        </div>
      </div>
    `;
  }).join('') : `
    <div class="w-full h-full flex items-center justify-center text-on-surface-variant text-code-xs">
      No events available in 24h window
    </div>
  `;

  // Source Distribution Donut Chart calculation
  const dist = sources.distribution || [];
  const totalSrcEvents = sources.total_events || 0;
  const C = 289.026; // 2 * pi * 46

  let currentOffset = 0;
  const svgCircles = dist.map((item, idx) => {
    const strokeLen = (item.pct / 100.0) * C;
    const dashArray = `${strokeLen.toFixed(1)} ${(C - strokeLen).toFixed(1)}`;
    const rotation = (currentOffset / C) * 360;
    currentOffset += strokeLen;
    return `
      <circle id="donut-segment-${idx}" class="donut-segment" cx="50" cy="50" r="46" fill="none" stroke="${item.color}" stroke-width="8"
        stroke-dasharray="${dashArray}" stroke-dashoffset="0"
        transform="rotate(${rotation - 90} 50 50)" style="transition: stroke-dasharray 0.75s cubic-bezier(0.4, 0, 0.2, 1), transform 0.75s cubic-bezier(0.4, 0, 0.2, 1);" />
    `;
  }).join('');

  const legendHtml = dist.length > 0 ? dist.map(item => `
    <div class="flex items-center justify-between font-code-xs text-code-xs">
      <div class="flex items-center gap-2">
        <div class="w-2 h-2 rounded-full" style="background-color: ${item.color};"></div>
        <span class="text-on-surface-variant">${item.source}</span>
      </div>
      <span class="text-on-surface font-medium">${item.pct}%</span>
    </div>
  `).join('') : `
    <div class="text-on-surface-variant text-code-xs">No source data available</div>
  `;

  // Recent Security Events Table Rows
  const eventRows = recentEvents.length > 0 ? recentEvents.map(e => {
    let sevBadge = '';
    const sevUpper = (e.severity || 'INFO').toUpperCase();
    if (sevUpper === 'CRITICAL' || sevUpper === 'HIGH') {
      sevBadge = `<span class="px-2 py-0.5 rounded-sm bg-error-container/10 text-error font-label-caps text-label-caps border border-error-container">${sevUpper}</span>`;
    } else if (sevUpper === 'MEDIUM' || sevUpper === 'WARN' || sevUpper === 'WARNING') {
      sevBadge = `<span class="px-2 py-0.5 rounded-sm bg-tertiary/10 text-tertiary font-label-caps text-label-caps border border-tertiary/20">MEDIUM</span>`;
    } else if (sevUpper === 'LOW') {
      sevBadge = `<span class="px-2 py-0.5 rounded-sm bg-primary/10 text-primary font-label-caps text-label-caps border border-primary/20">LOW</span>`;
    } else {
      sevBadge = `<span class="px-2 py-0.5 rounded-sm bg-outline-variant/30 text-on-surface-variant font-label-caps text-label-caps border border-outline-variant">INFO</span>`;
    }

    const anmIcon = e.is_anomaly
      ? '<span class="material-symbols-outlined text-[16px] text-error" title="Anomaly Detected by Isolation Forest">warning</span>'
      : '<span class="material-symbols-outlined text-[16px] text-outline-variant">remove</span>';

    const intIcon = e.is_verified
      ? '<span class="material-symbols-outlined text-[16px] text-primary" title="Cryptographically Verified in Blockchain Ledger">verified</span>'
      : '<span class="material-symbols-outlined text-[16px] text-outline-variant animate-pulse" title="Integrity Check Pending">sync</span>';

    const shortId = e.event_id.length > 12 ? e.event_id.slice(0, 10) + '...' : e.event_id;

    return `
      <tr class="border-b border-outline-variant/50 hover:bg-surface-container-high/40 transition-colors cursor-pointer" onclick="app.inspectEvent('${e.event_id}')" title="Click to inspect raw forensic payload & blockchain proof">
        <td class="p-2 pl-4 text-on-surface-variant whitespace-nowrap text-code-xs">${e.time}</td>
        <td class="p-2 font-code-xs text-code-xs text-primary font-medium hover:underline">${shortId}</td>
        <td class="p-2 text-on-surface font-code-xs">${escapeHtml(e.source)}</td>
        <td class="p-2 text-on-surface-variant text-code-xs">${escapeHtml(e.format)}</td>
        <td class="p-2 text-on-surface text-code-xs">${escapeHtml(e.type)}</td>
        <td class="p-2">${sevBadge}</td>
        <td class="p-2 text-on-surface-variant text-code-xs">${escapeHtml(e.ocsf)}</td>
        <td class="p-2 text-center">${anmIcon}</td>
        <td class="p-2 pr-4 text-center">${intIcon}</td>
      </tr>
    `;
  }).join('') : `
    <tr>
      <td colspan="9" class="p-8 text-center text-on-surface-variant font-code-sm">
        No events available. Ingest logs via CLI or Log Ingestion to see live events.
      </td>
    </tr>
  `;

  return `
    <div class="flex flex-col w-full p-gutter space-y-stack-md">
      ${error ? `
        <div class="p-3 rounded-lg bg-error-container/20 border border-error-container text-error text-code-sm flex items-center justify-between">
          <div class="flex items-center gap-2">
            <span class="material-symbols-outlined text-[18px]">warning</span>
            <span>Dashboard Data Warning: ${error}</span>
          </div>
          <button onclick="app.refreshCurrentPage()" class="btn btn-sm" style="border-color: #93000a; color: #ffb4ab;">Retry</button>
        </div>
      ` : ''}

      <!-- 1. ROW OF 6 KPI METRIC CARDS (STITCH DESIGN) -->
      <div class="grid grid-cols-6 gap-gutter">
        <!-- 1. EVENTS PROCESSED -->
        <div class="col-span-1 bg-surface-container shadow-sm p-4 rounded-xl flex flex-col gap-2 border border-outline-variant" title="Total processed raw events in store: ${summary.raw_events_count?.toLocaleString() || '0'}">
          <span class="font-label-caps text-label-caps text-on-surface-variant">EVENTS PROCESSED</span>
          <span class="font-display-lg text-display-lg text-primary tracking-tighter" id="kpi-events-processed">${formatKpiNumber(summary.events_processed)}</span>
        </div>
        <!-- 2. NORMALIZED -->
        <div class="col-span-1 bg-surface-container shadow-sm p-4 rounded-xl flex flex-col gap-2 border border-outline-variant" title="Normalized: ${summary.normalized_count?.toLocaleString() || '0'}">
          <span class="font-label-caps text-label-caps text-on-surface-variant">NORMALIZED</span>
          <span class="font-display-lg text-display-lg text-on-surface tracking-tighter" id="kpi-normalized-pct">${summary.normalized_pct ?? 0}%</span>
        </div>
        <!-- 3. OCSF EVENTS -->
        <div class="col-span-1 bg-surface-container shadow-sm p-4 rounded-xl flex flex-col gap-2 border border-outline-variant" title="Conforming OCSF Events (${summary.ocsf_pct ?? 0}%)">
          <span class="font-label-caps text-label-caps text-on-surface-variant">OCSF EVENTS</span>
          <span class="font-display-lg text-display-lg text-on-surface tracking-tighter" id="kpi-ocsf-events">${formatKpiNumber(summary.ocsf_events_count)}</span>
        </div>
        <!-- 4. UNKNOWN FORMATS -->
        <div onclick="app.navigate('mappings')" class="col-span-1 bg-surface-container shadow-sm p-4 rounded-xl flex flex-col gap-2 border border-error-container bg-error-container/10 cursor-pointer hover:bg-error-container/20 transition-colors" title="Click to inspect unparsed format review queue">
          <span class="font-label-caps text-label-caps text-error">UNKNOWN FORMATS</span>
          <span class="font-display-lg text-display-lg text-error tracking-tighter" id="kpi-unknown-formats">${formatKpiNumber(summary.unknown_formats_count)}</span>
        </div>
        <!-- 5. ANOMALIES -->
        <div class="col-span-1 bg-surface-container shadow-sm p-4 rounded-xl flex flex-col gap-2 border border-error-container bg-error-container/10" title="Isolation Forest Machine Learning detections">
          <span class="font-label-caps text-label-caps text-error">ANOMALIES</span>
          <span class="font-display-lg text-display-lg text-error tracking-tighter" id="kpi-anomalies">${formatKpiNumber(summary.anomalies_count)}</span>
        </div>
        <!-- 6. BLOCKCHAIN VERIFIED -->
        <div class="col-span-1 bg-surface-container shadow-sm p-4 rounded-xl flex flex-col gap-2 border border-outline-variant" title="Immutable blockchain records verified">
          <span class="font-label-caps text-label-caps text-on-surface-variant">BLOCKCHAIN VERIFIED</span>
          <span class="font-display-lg text-display-lg text-primary tracking-tighter" id="kpi-blockchain-verified">${formatKpiNumber(summary.blockchain_verified_count)}</span>
        </div>
      </div>

      <!-- 2. PROCESSING PIPELINE (STITCH DESIGN) -->
      <div class="bg-surface-container shadow-sm p-6 rounded-xl border border-outline-variant flex flex-col gap-stack-md" id="dashboard-pipeline-card">
        <div class="flex items-center justify-between">
          <span class="font-title-sm text-title-sm text-on-surface">PROCESSING PIPELINE</span>
          <span class="font-label-caps text-label-caps text-primary bg-primary/10 px-2 py-1 rounded-full border border-primary/20 flex items-center gap-1.5">
            <span class="w-1.5 h-1.5 rounded-full bg-primary animate-pulse"></span>LIVE FLOW
          </span>
        </div>
        <div class="w-full bg-surface-container-highest rounded-lg h-24 relative flex items-center justify-between px-8 border border-outline-variant">
          <div class="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGNpcmNsZSBjeD0iMjAiIGN5PSIyMCIgcj0iMSIgZmlsbD0iIzI4MmMzNCIvPjwvc3ZnPg==')] opacity-50 rounded-lg overflow-hidden pointer-events-none"></div>
          <div class="flex items-center gap-2 relative z-10 w-full justify-between">
            <!-- 1. SRC: Sources -->
            <div class="pipeline-stage-item">
              <div class="pipeline-tooltip absolute bottom-[calc(100%+12px)] left-0 w-60 p-3 bg-[#0b0e14]/95 border border-outline-variant rounded-lg shadow-2xl backdrop-blur-md text-left">
                <div class="flex items-center justify-between gap-2 mb-1">
                  <span class="font-label-caps text-label-caps text-on-surface font-bold">SOURCE</span>
                  <span class="font-code-xs text-[10px] text-primary/80 font-normal">STAGE 1</span>
                </div>
                <p class="font-body-sm text-[11px] leading-relaxed text-on-surface-variant font-normal">
                  Collects incoming logs and telemetry from connected systems and security sources.
                </p>
                ${stageEpsHtml}
                <div class="absolute -bottom-1 left-3.5 w-2 h-2 bg-[#0b0e14] border-r border-b border-outline-variant rotate-45"></div>
              </div>
              <div class="w-8 h-8 rounded-full bg-surface-container-high border border-outline flex items-center justify-center text-on-surface-variant pipeline-stage-circle">
                <span class="material-symbols-outlined text-[16px]">hub</span>
              </div>
              <span class="font-code-xs text-code-xs text-on-surface-variant pipeline-stage-label">SRC</span>
            </div>
            <div class="h-[2px] bg-outline-variant/60 flex-1 mx-2 relative overflow-hidden rounded-full">
              <div class="pipeline-pulse-particle" style="animation-delay: -0.00s;"></div>
              <div class="pipeline-pulse-particle" style="animation-delay: -1.00s;"></div>
            </div>

            <!-- 2. ING: Ingestion -->
            <div class="pipeline-stage-item">
              <div class="pipeline-tooltip absolute bottom-[calc(100%+12px)] left-1/2 -translate-x-1/2 w-60 p-3 bg-[#0b0e14]/95 border border-outline-variant rounded-lg shadow-2xl backdrop-blur-md text-left">
                <div class="flex items-center justify-between gap-2 mb-1">
                  <span class="font-label-caps text-label-caps text-on-surface font-bold">INGEST</span>
                  <span class="font-code-xs text-[10px] text-primary/80 font-normal">STAGE 2</span>
                </div>
                <p class="font-body-sm text-[11px] leading-relaxed text-on-surface-variant font-normal">
                  Receives and accepts incoming log data into ULPF for processing.
                </p>
                ${stageEpsHtml}
                <div class="absolute -bottom-1 left-1/2 -translate-x-1/2 w-2 h-2 bg-[#0b0e14] border-r border-b border-outline-variant rotate-45"></div>
              </div>
              <div class="w-8 h-8 rounded-full bg-surface-container-high border border-outline flex items-center justify-center text-on-surface-variant pipeline-stage-circle">
                <span class="material-symbols-outlined text-[16px]">input</span>
              </div>
              <span class="font-code-xs text-code-xs text-on-surface-variant pipeline-stage-label">ING</span>
            </div>
            <div class="h-[2px] bg-outline-variant/60 flex-1 mx-2 relative overflow-hidden rounded-full">
              <div class="pipeline-pulse-particle" style="animation-delay: -0.22s;"></div>
              <div class="pipeline-pulse-particle" style="animation-delay: -1.22s;"></div>
            </div>

            <!-- 3. DET: Detection -->
            <div class="pipeline-stage-item">
              <div class="pipeline-tooltip absolute bottom-[calc(100%+12px)] left-1/2 -translate-x-1/2 w-60 p-3 bg-[#0b0e14]/95 border border-outline-variant rounded-lg shadow-2xl backdrop-blur-md text-left">
                <div class="flex items-center justify-between gap-2 mb-1">
                  <span class="font-label-caps text-label-caps text-on-surface font-bold">DETECT</span>
                  <span class="font-code-xs text-[10px] text-primary/80 font-normal">STAGE 3</span>
                </div>
                <p class="font-body-sm text-[11px] leading-relaxed text-on-surface-variant font-normal">
                  Identifies the incoming log format and determines the appropriate processing path.
                </p>
                ${stageEpsHtml}
                <div class="absolute -bottom-1 left-1/2 -translate-x-1/2 w-2 h-2 bg-[#0b0e14] border-r border-b border-outline-variant rotate-45"></div>
              </div>
              <div class="w-8 h-8 rounded-full bg-surface-container-high border border-outline flex items-center justify-center text-on-surface-variant pipeline-stage-circle">
                <span class="material-symbols-outlined text-[16px]">radar</span>
              </div>
              <span class="font-code-xs text-code-xs text-on-surface-variant pipeline-stage-label">DET</span>
            </div>
            <div class="h-[2px] bg-outline-variant/60 flex-1 mx-2 relative overflow-hidden rounded-full">
              <div class="pipeline-pulse-particle" style="animation-delay: -0.44s;"></div>
              <div class="pipeline-pulse-particle" style="animation-delay: -1.44s;"></div>
            </div>

            <!-- 4. PRS: Parsing -->
            <div class="pipeline-stage-item">
              <div class="pipeline-tooltip absolute bottom-[calc(100%+12px)] left-1/2 -translate-x-1/2 w-60 p-3 bg-[#0b0e14]/95 border border-outline-variant rounded-lg shadow-2xl backdrop-blur-md text-left">
                <div class="flex items-center justify-between gap-2 mb-1">
                  <span class="font-label-caps text-label-caps text-on-surface font-bold">PARSE</span>
                  <span class="font-code-xs text-[10px] text-primary/80 font-normal">STAGE 4</span>
                </div>
                <p class="font-body-sm text-[11px] leading-relaxed text-on-surface-variant font-normal">
                  Extracts structured fields and information from raw log messages.
                </p>
                ${stageEpsHtml}
                <div class="absolute -bottom-1 left-1/2 -translate-x-1/2 w-2 h-2 bg-[#0b0e14] border-r border-b border-outline-variant rotate-45"></div>
              </div>
              <div class="w-8 h-8 rounded-full bg-surface-container-high border border-outline flex items-center justify-center text-on-surface-variant pipeline-stage-circle">
                <span class="material-symbols-outlined text-[16px]">code</span>
              </div>
              <span class="font-code-xs text-code-xs text-on-surface-variant pipeline-stage-label">PRS</span>
            </div>
            <div class="h-[2px] bg-outline-variant/60 flex-1 mx-2 relative overflow-hidden rounded-full">
              <div class="pipeline-pulse-particle" style="animation-delay: -0.66s;"></div>
              <div class="pipeline-pulse-particle" style="animation-delay: -1.66s;"></div>
            </div>

            <!-- 5. NRM: Normalization -->
            <div class="pipeline-stage-item">
              <div class="pipeline-tooltip absolute bottom-[calc(100%+12px)] left-1/2 -translate-x-1/2 w-60 p-3 bg-[#0b0e14]/95 border border-outline-variant rounded-lg shadow-2xl backdrop-blur-md text-left">
                <div class="flex items-center justify-between gap-2 mb-1">
                  <span class="font-label-caps text-label-caps text-on-surface font-bold">NORMALIZE</span>
                  <span class="font-code-xs text-[10px] text-primary/80 font-normal">STAGE 5</span>
                </div>
                <p class="font-body-sm text-[11px] leading-relaxed text-on-surface-variant font-normal">
                  Converts parsed events into a unified internal structure.
                </p>
                ${stageEpsHtml}
                <div class="absolute -bottom-1 left-1/2 -translate-x-1/2 w-2 h-2 bg-[#0b0e14] border-r border-b border-outline-variant rotate-45"></div>
              </div>
              <div class="w-8 h-8 rounded-full bg-surface-container-high border border-outline flex items-center justify-center text-on-surface-variant pipeline-stage-circle">
                <span class="material-symbols-outlined text-[16px]">transform</span>
              </div>
              <span class="font-code-xs text-code-xs text-on-surface-variant pipeline-stage-label">NRM</span>
            </div>
            <div class="h-[2px] bg-outline-variant/60 flex-1 mx-2 relative overflow-hidden rounded-full">
              <div class="pipeline-pulse-particle" style="animation-delay: -0.88s;"></div>
              <div class="pipeline-pulse-particle" style="animation-delay: -1.88s;"></div>
            </div>

            <!-- 6. OCSF: OCSF Mapping -->
            <div class="pipeline-stage-item">
              <div class="pipeline-tooltip absolute bottom-[calc(100%+12px)] left-1/2 -translate-x-1/2 w-60 p-3 bg-[#0b0e14]/95 border border-outline-variant rounded-lg shadow-2xl backdrop-blur-md text-left">
                <div class="flex items-center justify-between gap-2 mb-1">
                  <span class="font-label-caps text-label-caps text-on-surface font-bold">OCSF</span>
                  <span class="font-code-xs text-[10px] text-primary/80 font-normal">STAGE 6</span>
                </div>
                <p class="font-body-sm text-[11px] leading-relaxed text-on-surface-variant font-normal">
                  Maps normalized events to OCSF event classes and attributes.
                </p>
                ${stageEpsHtml}
                <div class="absolute -bottom-1 left-1/2 -translate-x-1/2 w-2 h-2 bg-[#0b0e14] border-r border-b border-outline-variant rotate-45"></div>
              </div>
              <div class="w-8 h-8 rounded-full bg-surface-container-high border border-outline flex items-center justify-center text-on-surface-variant font-label-caps text-[10px] font-bold pipeline-stage-circle">OCSF</div>
            </div>
            <div class="h-[2px] bg-outline-variant/60 flex-1 mx-2 relative overflow-hidden rounded-full">
              <div class="pipeline-pulse-particle" style="animation-delay: -1.10s;"></div>
              <div class="pipeline-pulse-particle" style="animation-delay: -0.10s;"></div>
            </div>

            <!-- 7. VAL: Validation -->
            <div class="pipeline-stage-item">
              <div class="pipeline-tooltip absolute bottom-[calc(100%+12px)] left-1/2 -translate-x-1/2 w-60 p-3 bg-[#0b0e14]/95 border border-outline-variant rounded-lg shadow-2xl backdrop-blur-md text-left">
                <div class="flex items-center justify-between gap-2 mb-1">
                  <span class="font-label-caps text-label-caps text-on-surface font-bold">VALIDATE</span>
                  <span class="font-code-xs text-[10px] text-primary/80 font-normal">STAGE 7</span>
                </div>
                <p class="font-body-sm text-[11px] leading-relaxed text-on-surface-variant font-normal">
                  Checks the processed event for schema, field, and data integrity.
                </p>
                ${stageEpsHtml}
                <div class="absolute -bottom-1 left-1/2 -translate-x-1/2 w-2 h-2 bg-[#0b0e14] border-r border-b border-outline-variant rotate-45"></div>
              </div>
              <div class="w-8 h-8 rounded-full bg-surface-container-high border border-outline flex items-center justify-center text-on-surface-variant pipeline-stage-circle">
                <span class="material-symbols-outlined text-[16px]">fact_check</span>
              </div>
              <span class="font-code-xs text-code-xs text-on-surface-variant pipeline-stage-label">VAL</span>
            </div>
            <div class="h-[2px] bg-outline-variant/60 flex-1 mx-2 relative overflow-hidden rounded-full">
              <div class="pipeline-pulse-particle" style="animation-delay: -1.32s;"></div>
              <div class="pipeline-pulse-particle" style="animation-delay: -0.32s;"></div>
            </div>

            <!-- 8. STR: Storage -->
            <div class="pipeline-stage-item">
              <div class="pipeline-tooltip absolute bottom-[calc(100%+12px)] left-1/2 -translate-x-1/2 w-60 p-3 bg-[#0b0e14]/95 border border-outline-variant rounded-lg shadow-2xl backdrop-blur-md text-left">
                <div class="flex items-center justify-between gap-2 mb-1">
                  <span class="font-label-caps text-label-caps text-on-surface font-bold">STORE</span>
                  <span class="font-code-xs text-[10px] text-primary/80 font-normal">STAGE 8</span>
                </div>
                <p class="font-body-sm text-[11px] leading-relaxed text-on-surface-variant font-normal">
                  Persists processed and normalized event data for querying, analysis, and traceability.
                </p>
                ${stageEpsHtml}
                <div class="absolute -bottom-1 left-1/2 -translate-x-1/2 w-2 h-2 bg-[#0b0e14] border-r border-b border-outline-variant rotate-45"></div>
              </div>
              <div class="w-8 h-8 rounded-full bg-surface-container-high border border-outline flex items-center justify-center text-on-surface-variant pipeline-stage-circle">
                <span class="material-symbols-outlined text-[16px]">database</span>
              </div>
              <span class="font-code-xs text-code-xs text-on-surface-variant pipeline-stage-label">STR</span>
            </div>
            <div class="h-[2px] bg-outline-variant/60 flex-1 mx-2 relative overflow-hidden rounded-full">
              <div class="pipeline-pulse-particle" style="animation-delay: -1.54s;"></div>
              <div class="pipeline-pulse-particle" style="animation-delay: -0.54s;"></div>
            </div>

            <!-- 9. BC: Blockchain -->
            <div class="pipeline-stage-item">
              <div class="pipeline-tooltip absolute bottom-[calc(100%+12px)] right-0 w-60 p-3 bg-[#0b0e14]/95 border border-outline-variant rounded-lg shadow-2xl backdrop-blur-md text-left">
                <div class="flex items-center justify-between gap-2 mb-1">
                  <span class="font-label-caps text-label-caps text-on-surface font-bold">BLOCKCHAIN</span>
                  <span class="font-code-xs text-[10px] text-primary/80 font-normal">STAGE 9</span>
                </div>
                <p class="font-body-sm text-[11px] leading-relaxed text-on-surface-variant font-normal">
                  Anchors integrity metadata so processed data can later be verified.
                </p>
                ${stageEpsHtml}
                <div class="absolute -bottom-1 right-3.5 w-2 h-2 bg-[#0b0e14] border-r border-b border-outline-variant rotate-45"></div>
              </div>
              <div class="w-8 h-8 rounded-full bg-surface-container-high border border-outline flex items-center justify-center text-on-surface-variant pipeline-stage-circle">
                <span class="material-symbols-outlined text-[16px]">link</span>
              </div>
              <span class="font-code-xs text-code-xs text-on-surface-variant pipeline-stage-label">BC</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 2.5 REAL ULPF AI ENGINE & TELEMETRY -->
      <div class="bg-surface-container shadow-sm p-6 rounded-xl border border-outline-variant flex flex-col gap-stack-md" id="dashboard-ai-engine-card">
        <!-- Header -->
        <div class="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-outline-variant">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
              <span class="material-symbols-outlined text-[24px]">psychology</span>
            </div>
            <div>
              <div class="flex items-center gap-2">
                <span class="font-title-sm text-title-sm text-on-surface font-bold tracking-tight">ULPF AI ENGINE</span>
                <span id="ai-engine-status-badge" class="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold tracking-wide border flex items-center gap-1.5 ${aiStatus.status === 'UNAVAILABLE' ? 'bg-[#ef4444]/15 text-[#f87171] border-[#ef4444]/30' : (aiStatus.status === 'TIMEOUT' ? 'bg-[#f59e0b]/15 text-[#fbbf24] border-[#f59e0b]/30' : (aiStatus.status === 'MODEL_NOT_FOUND' ? 'bg-[#ef4444]/15 text-[#f87171] border-[#ef4444]/30' : (aiStatus.status === 'CONNECTED' ? 'bg-[#10b981]/15 text-[#34d399] border-[#10b981]/30' : 'bg-outline-variant/30 text-on-surface-variant border-outline-variant')))}">
                  <span class="w-1.5 h-1.5 rounded-full ${aiStatus.status === 'UNAVAILABLE' ? 'bg-[#ef4444]' : (aiStatus.status === 'TIMEOUT' ? 'bg-[#f59e0b]' : (aiStatus.status === 'MODEL_NOT_FOUND' ? 'bg-[#ef4444]' : (aiStatus.status === 'CONNECTED' ? 'bg-[#10b981] shadow-[0_0_8px_rgba(16,185,129,0.8)]' : 'bg-outline-variant')))}"></span>
                  ${aiStatus.status || 'INITIALIZING...'}
                </span>
              </div>
              <div class="flex items-center gap-3 font-code-xs text-[11px] text-on-surface-variant mt-0.5">
                <span>Provider: <strong class="text-on-surface font-semibold font-mono">Ollama</strong></span>
                <span>•</span>
                <span>Model: <strong class="text-primary font-semibold font-mono" id="ai-model-label">${escapeHtml(aiStatus.model || 'qwen3:4b')}</strong></span>
                <span>•</span>
                <span>Mode: <strong class="text-on-surface font-semibold font-mono" id="ai-mode-label">${aiStatus.air_gap_mode ? 'Air-gapped / Local' : 'Local'}</strong></span>
              </div>
            </div>
          </div>

          <!-- Action button -->
          <div class="flex items-center gap-2">
            <button onclick="app.navigate('mappings')" class="px-3 py-1.5 rounded bg-surface-container-high hover:bg-surface-container-highest text-on-surface font-label-caps text-label-caps border border-outline-variant transition-colors flex items-center gap-1.5 cursor-pointer" title="Inspect Review Queue">
              <span class="material-symbols-outlined text-[15px] text-[#f59e0b]">rate_review</span>
              Review Queue (<span id="ai-kpi-review-btn-count">${aiMetrics.review_required ?? summary.unknown_formats_count ?? 0}</span>)
            </button>
          </div>
        </div>

        <!-- Offline Warning banner if Ollama is unavailable -->
        <div id="ai-offline-banner" class="${(aiStatus.status === 'UNAVAILABLE' || aiStatus.status === 'TIMEOUT') ? 'flex' : 'hidden'} p-3 rounded-lg bg-error-container/20 border border-error-container text-error text-code-xs items-center gap-2">
          <span class="material-symbols-outlined text-[18px]">cloud_off</span>
          <span>Local Ollama is unavailable. Known and learned parsers continue normally with 0 Ollama calls. New unresolved formats will enter the human review queue.</span>
        </div>

        <!-- AI Activity & Performance Metric Cards (Grid of 6) -->
        <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <!-- Ollama Calls -->
          <div class="bg-surface-container-lowest p-3 rounded-lg border border-outline-variant flex flex-col gap-1">
            <div class="flex items-center justify-between text-on-surface-variant font-label-caps text-[10px]">
              <span>OLLAMA CALLS</span>
              <span class="material-symbols-outlined text-[14px] text-primary">chat</span>
            </div>
            <span class="font-display-sm text-display-sm text-primary font-mono" id="ai-kpi-ollama-calls">${aiMetrics.ollama_calls ?? 0}</span>
            <span class="text-[10px] text-on-surface-variant">Genuine LLM calls</span>
          </div>

          <!-- AI Generated Parsers -->
          <div class="bg-surface-container-lowest p-3 rounded-lg border border-outline-variant flex flex-col gap-1">
            <div class="flex items-center justify-between text-on-surface-variant font-label-caps text-[10px]">
              <span>AI PARSERS</span>
              <span class="material-symbols-outlined text-[14px] text-tertiary">auto_fix_high</span>
            </div>
            <span class="font-display-sm text-display-sm text-tertiary font-mono" id="ai-kpi-ai-parsers">${aiMetrics.ai_generated_parsers ?? 0}</span>
            <span class="text-[10px] text-on-surface-variant">Synthesized & promoted</span>
          </div>

          <!-- Learned Reuse -->
          <div class="bg-surface-container-lowest p-3 rounded-lg border border-outline-variant flex flex-col gap-1">
            <div class="flex items-center justify-between text-on-surface-variant font-label-caps text-[10px]">
              <span>LEARNED REUSE</span>
              <span class="material-symbols-outlined text-[14px] text-[#34d399]">replay</span>
            </div>
            <span class="font-display-sm text-display-sm text-[#34d399] font-mono" id="ai-kpi-learned-reuse">${aiMetrics.learned_parser_reuses ?? 0}</span>
            <span class="text-[10px] text-on-surface-variant">0 Ollama calls (Cached)</span>
          </div>

          <!-- Latency -->
          <div class="bg-surface-container-lowest p-3 rounded-lg border border-outline-variant flex flex-col gap-1">
            <div class="flex items-center justify-between text-on-surface-variant font-label-caps text-[10px]">
              <span>AI LATENCY</span>
              <span class="material-symbols-outlined text-[14px] text-on-surface-variant">timer</span>
            </div>
            <span class="font-display-sm text-display-sm text-on-surface font-mono" id="ai-kpi-latency">${aiMetrics.last_latency_ms ? (aiMetrics.last_latency_ms >= 1000 ? (aiMetrics.last_latency_ms / 1000).toFixed(1) + 's' : Math.round(aiMetrics.last_latency_ms) + 'ms') : '0ms'}</span>
            <span class="text-[10px] text-on-surface-variant">Last LLM inference</span>
          </div>

          <!-- Parser Accuracy -->
          <div class="bg-surface-container-lowest p-3 rounded-lg border border-outline-variant flex flex-col gap-1">
            <div class="flex items-center justify-between text-on-surface-variant font-label-caps text-[10px]">
              <span>PARSER ACCURACY</span>
              <span class="material-symbols-outlined text-[14px] text-primary">verified</span>
            </div>
            <span class="font-display-sm text-display-sm text-primary font-mono" id="ai-kpi-accuracy">${aiMetrics.parser_accuracy != null ? aiMetrics.parser_accuracy + '%' : 'N/A'}</span>
            <span class="text-[10px] text-on-surface-variant">Extraction benchmark</span>
          </div>

          <!-- Validation Rate -->
          <div class="bg-surface-container-lowest p-3 rounded-lg border border-outline-variant flex flex-col gap-1">
            <div class="flex items-center justify-between text-on-surface-variant font-label-caps text-[10px]">
              <span>VALIDATION</span>
              <span class="material-symbols-outlined text-[14px] text-tertiary">task_alt</span>
            </div>
            <span class="font-display-sm text-display-sm text-tertiary font-mono" id="ai-kpi-validation">${aiMetrics.validation_rate != null ? aiMetrics.validation_rate + '%' : '100%'}</span>
            <span class="text-[10px] text-on-surface-variant">Schema conformance</span>
          </div>
        </div>

        <!-- Recent AI Resolutions Table -->
        <div class="flex flex-col gap-2 pt-2">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <span class="font-title-xs text-[12px] font-bold uppercase tracking-wider text-on-surface">Recent Unknown Formats & AI Resolutions</span>
              <span class="text-[10px] text-on-surface-variant">(Truthful Telemetry Audit Log)</span>
            </div>
            <div class="text-[11px] text-on-surface-variant font-code-xs">
              Semantic Engine: <strong class="text-[#34d399]">OCSF Deterministic Active</strong>
            </div>
          </div>

          <div class="overflow-x-auto rounded-lg border border-outline-variant bg-surface-container-lowest">
            <table class="w-full text-left font-code-xs text-code-xs border-collapse">
              <thead class="bg-surface-container border-b border-outline-variant text-[11px] uppercase tracking-wider text-on-surface-variant">
                <tr>
                  <th class="p-2.5 pl-3">Timestamp</th>
                  <th class="p-2.5">Source</th>
                  <th class="p-2.5">Fingerprint</th>
                  <th class="p-2.5">Parser</th>
                  <th class="p-2.5 text-center">AI Used</th>
                  <th class="p-2.5 text-center">Resolution</th>
                  <th class="p-2.5 text-right">Accuracy</th>
                  <th class="p-2.5 pr-3 text-right">Latency</th>
                </tr>
              </thead>
              <tbody id="ai-resolutions-table-body">
                ${renderAiResolutionsTableRows(aiResolutions)}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- 3. ROW OF TWO CHARTS (EVENT VOLUME & SOURCE DISTRIBUTION) -->
      <div class="grid grid-cols-2 gap-gutter">
        <!-- Left: EVENT VOLUME (24H) -->
        <div class="bg-surface-container shadow-sm p-6 rounded-xl border border-outline-variant flex flex-col gap-stack-md h-64 relative">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <span class="font-title-sm text-title-sm text-on-surface">EVENT VOLUME (24H)</span>
              <span id="vol-refresh-indicator" class="hidden font-code-xs text-[10px] text-primary bg-primary/10 border border-primary/20 px-1.5 py-0.5 rounded items-center gap-1 animate-pulse">
                <span class="material-symbols-outlined text-[12px] animate-spin">sync</span>
                <span>Refreshing...</span>
              </span>
            </div>
            <span class="font-code-xs text-code-xs text-on-surface-variant" id="vol-max-eps">MAX: ${volume.max_eps || 0} EPS</span>
          </div>
          <div class="flex-1 w-full bg-surface-container-lowest rounded border border-outline-variant flex items-end px-4 pt-6 pb-2 gap-1 relative overflow-hidden">
            <div class="w-full flex items-end justify-between h-full gap-1" id="volume-bars-container">
              ${barsHtml}
            </div>
          </div>
        </div>

        <!-- Right: SOURCE DISTRIBUTION -->
        <div class="bg-surface-container shadow-sm p-6 rounded-xl border border-outline-variant flex flex-col gap-stack-md h-64 relative">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <span class="font-title-sm text-title-sm text-on-surface">SOURCE DISTRIBUTION</span>
              <span id="src-refresh-indicator" class="hidden font-code-xs text-[10px] text-primary bg-primary/10 border border-primary/20 px-1.5 py-0.5 rounded items-center gap-1 animate-pulse">
                <span class="material-symbols-outlined text-[12px] animate-spin">sync</span>
                <span>Refreshing...</span>
              </span>
            </div>
          </div>
          <div class="flex-1 w-full bg-surface-container-lowest rounded border border-outline-variant flex items-center justify-center p-4">
            <div class="flex w-full h-full gap-6 items-center">
              <div class="w-32 h-32 rounded-full border-[8px] border-surface-container-highest relative flex items-center justify-center flex-shrink-0">
                <svg class="absolute inset-0 w-full h-full" viewBox="0 0 100 100" id="source-donut-svg">
                  ${svgCircles}
                </svg>
                <span class="font-code-sm text-code-sm text-on-surface font-semibold" id="src-total-events">${formatKpiNumber(totalSrcEvents)}</span>
              </div>
              <div class="flex-1 flex flex-col gap-2 overflow-y-auto max-h-40 pr-2" id="source-legend-container">
                ${legendHtml}
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 4. RECENT SECURITY EVENTS TABLE (STITCH DESIGN) -->
      <div class="bg-surface-container shadow-sm rounded-xl border border-outline-variant overflow-hidden flex flex-col">
        <div class="p-4 border-b border-outline-variant flex items-center justify-between bg-surface-container-high/50">
          <span class="font-title-sm text-title-sm text-on-surface">RECENT SECURITY EVENTS</span>
          <button onclick="app.navigate('explorer')" class="px-3 py-1 bg-surface-container-lowest border border-outline-variant rounded font-label-caps text-label-caps text-on-surface hover:bg-surface-container transition-colors">VIEW ALL</button>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left border-collapse">
            <thead>
              <tr class="bg-surface-container-lowest border-b border-outline-variant font-label-caps text-label-caps text-on-surface-variant">
                <th class="p-2 pl-4 sticky top-0 bg-surface-container-lowest">TIME</th>
                <th class="p-2 sticky top-0 bg-surface-container-lowest">EVENT ID</th>
                <th class="p-2 sticky top-0 bg-surface-container-lowest">SOURCE</th>
                <th class="p-2 sticky top-0 bg-surface-container-lowest">FORMAT</th>
                <th class="p-2 sticky top-0 bg-surface-container-lowest">TYPE</th>
                <th class="p-2 sticky top-0 bg-surface-container-lowest">SEVERITY</th>
                <th class="p-2 sticky top-0 bg-surface-container-lowest">OCSF</th>
                <th class="p-2 sticky top-0 bg-surface-container-lowest text-center">ANM</th>
                <th class="p-2 pr-4 sticky top-0 bg-surface-container-lowest text-center">INT</th>
              </tr>
            </thead>
            <tbody class="font-body-md text-body-md" id="recent-events-tbody">
              ${eventRows}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}
