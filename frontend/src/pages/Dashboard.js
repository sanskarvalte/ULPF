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

export function renderDashboardPage(dashboardState = {}) {
  const summary = dashboardState.summary || {};
  const volume = dashboardState.volume || { buckets: [], max_eps: 0 };
  const sources = dashboardState.sources || { distribution: [], total_events: 0 };
  const recentEvents = dashboardState.recentEvents || [];
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
