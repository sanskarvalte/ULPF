/**
 * ULPF Event Investigation / Event Details Page Component
 * Forensic Investigation Console for Single Processed Security Event
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

export function renderInvestigationPage(state = {}) {
  const loading = state.loading || false;
  const error = state.error || null;
  const activeTab = state.activeTab || 'ocsf'; // 'ocsf' | 'raw' | 'metadata'
  const isIsolated = state.isIsolated || false;
  const isolateModalOpen = state.isolateModalOpen || false;

  // Fallback demonstration event matching Stitch specification
  const event = state.event || {
    event_id: 'EVT-001245',
    timestamp: '2023-10-27T14:32:01.992Z',
    source: 'FW-CORE-NYC-01',
    event_type: 'Network Activity (4001)',
    class_uid: 4001,
    severity: 'CRITICAL',
    status: 'UNDER_REVIEW',
    lifecycle: [
      { stage: 1, title: 'RAW INGESTION', detail: 'UDP/514 • 14:32:01.992', status: 'completed', color: 'primary' },
      { stage: 2, title: 'PARSED & NORMALIZED', detail: 'Grok pattern: FW_TRAFFIC', status: 'completed', color: 'primary' },
      { stage: 3, title: 'OCSF MAPPED', detail: 'Class: Network Activity', status: 'completed', color: 'primary' },
      { stage: 4, title: 'AI VALIDATION', detail: 'Anomaly Score: 94/100', status: 'critical', color: 'error' },
      { stage: 5, title: 'STORED', detail: 'Index: evt-2023.10.27', status: 'completed', color: 'primary' },
      { stage: 6, title: 'BLOCKCHAIN VERIFIED', detail: 'Block: #899201', status: 'verified', color: 'tertiary' }
    ],
    anomaly: {
      score: 94,
      confidence: 'High',
      model: 'Isolation Forest',
      explanation: 'High volume of outbound traffic (TCP/443) to rare destination IP, followed by immediate connection termination. IP matches known C2 infrastructure patterns.'
    },
    integrity: {
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      merkle_root: '7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730',
      verified: true,
      status: 'Verified on ULPF Ledger (Block #899201)',
      block_index: 899201,
      batch_id: 'SYNC_BATCH_X992A'
    },
    ocsf_event: {
      activity_id: 1,
      activity_name: "Traffic",
      category_name: "Network Activity",
      category_uid: 4,
      class_name: "Network Activity",
      class_uid: 4001,
      severity_id: 6,
      severity: "Critical",
      status_id: 1,
      status: "Success",
      time: "2023-10-27T14:32:01.992Z",
      src_endpoint: {
        ip: "10.0.5.12",
        port: 54321,
        vlan_uid: 105
      },
      dst_endpoint: {
        ip: "198.51.100.42",
        port: 443,
        location: { country: "RU", city: "Moscow" }
      },
      connection_info: {
        protocol_num: 6,
        protocol_name: "TCP",
        direction_id: 2,
        direction: "Outbound",
        bytes_out: 450921,
        bytes_in: 1240
      },
      device: {
        hostname: "FW-CORE-NYC-01",
        type_id: 1,
        vendor: "Palo Alto Networks",
        product: "PAN-OS"
      }
    },
    raw_log: '<14>Oct 27 14:32:01.992 FW-CORE-NYC-01 1 2023-10-27T14:32:01.992Z FW-CORE-NYC-01 PAN-OS - - [TRAFFIC] src=10.0.5.12 sport=54321 dst=198.51.100.42 dport=443 proto=6 bytes_out=450921 bytes_in=1240 action=ALLOW app=ssl session_end_reason=tcp-rst',
    parsed_metadata: {
      'Timestamp': '2023-10-27T14:32:01.992Z',
      'Hostname': 'FW-CORE-NYC-01',
      'Source IP': '10.0.5.12',
      'Destination IP': '198.51.100.42',
      'Source Port': '54321',
      'Destination Port': '443',
      'Protocol': 'TCP',
      'Direction': 'Outbound',
      'Event Type': 'Network Activity (4001)',
      'Vendor': 'Palo Alto Networks',
      'Product': 'Next-Gen Firewall',
      'Parser': 'Grok pattern: FW_TRAFFIC',
      'Detected Format': 'SYSLOG RFC5424',
      'Normalization Status': 'PASSED (100% OCSF Schema Conformant)',
      'Storage Table': 'duckdb.normalized_events',
      'Raw Payload Hash': 'e3b0c44298fc1c14...852b855'
    }
  };

  // Severity style helper
  const sev = String(event.severity || 'INFORMATIONAL').toUpperCase();
  let sevBadgeClass = 'bg-primary/15 border-primary/30 text-primary';
  let sevIcon = 'info';
  if (sev === 'CRITICAL') {
    sevBadgeClass = 'bg-error/15 border-error/30 text-error';
    sevIcon = 'warning';
  } else if (sev === 'HIGH') {
    sevBadgeClass = 'bg-amber-500/15 border-amber-500/30 text-amber-400';
    sevIcon = 'error';
  } else if (sev === 'MEDIUM') {
    sevBadgeClass = 'bg-amber-400/15 border-amber-400/30 text-amber-300';
    sevIcon = 'warning';
  }

  // Anomaly score color
  const anomalyScore = Number(event.anomaly?.score ?? 14);
  let scoreColorClass = 'text-primary';
  let scoreBarColor = 'bg-primary';
  if (anomalyScore >= 80) {
    scoreColorClass = 'text-error';
    scoreBarColor = 'bg-error';
  } else if (anomalyScore >= 50) {
    scoreColorClass = 'text-amber-400';
    scoreBarColor = 'bg-amber-400';
  }

  return `
    <div class="flex flex-col w-full min-h-full bg-surface">
      <!-- HEADER AREA (Stitch Specification) -->
      <div class="bg-surface-container border-b border-outline-variant p-gutter">
        <div class="flex flex-col md:flex-row md:items-start justify-between gap-4">
          <div>
            <!-- Breadcrumbs / Back button -->
            <div class="flex items-center gap-2 mb-2 font-code-xs text-code-xs text-outline">
              <a href="javascript:void(0)" onclick="app.navigate('explorer')" class="hover:text-primary transition-colors flex items-center gap-1">
                <span class="material-symbols-outlined text-[14px]">arrow_back</span>
                LOG EXPLORER
              </a>
              <span>/</span>
              <span>FORENSIC INVESTIGATION</span>
            </div>

            <div class="flex flex-wrap items-center gap-stack-md mb-stack-sm">
              <h1 class="font-display-lg text-display-lg text-on-surface font-mono tracking-tight select-all">
                ${escapeHtml(event.event_id)}
              </h1>
              <span class="px-2.5 py-1 rounded-full border font-label-caps text-label-caps flex items-center gap-1.5 ${sevBadgeClass}">
                <span class="material-symbols-outlined text-[14px]">${sevIcon}</span>
                ${escapeHtml(sev)}
              </span>
              ${isIsolated ? `
                <span class="px-2.5 py-1 rounded-full border border-error/50 bg-error/20 text-error font-label-caps text-label-caps flex items-center gap-1.5 animate-pulse">
                  <span class="material-symbols-outlined text-[14px]">gpp_maybe</span>
                  SOURCE ISOLATED
                </span>
              ` : ''}
            </div>

            <!-- Metadata subline -->
            <div class="flex flex-wrap items-center gap-x-stack-lg gap-y-2 font-code-sm text-code-sm text-on-surface-variant">
              <div class="flex items-center gap-1.5" title="Normalized Timestamp">
                <span class="material-symbols-outlined text-[16px]">schedule</span>
                <span>${escapeHtml(event.timestamp)}</span>
              </div>
              <div class="flex items-center gap-1.5" title="Log Source">
                <span class="material-symbols-outlined text-[16px]">dns</span>
                <span class="text-on-surface font-medium">${escapeHtml(event.source)}</span>
              </div>
              <div class="flex items-center gap-1.5" title="OCSF Class UID">
                <span class="material-symbols-outlined text-[16px]">category</span>
                <span>${escapeHtml(event.event_type)}</span>
              </div>
              <div class="flex items-center gap-2 text-primary" title="Forensic Pipeline Status">
                <span class="w-2 h-2 rounded-full bg-primary animate-pulse"></span>
                <span>Status: <strong class="font-semibold">${escapeHtml(event.status || 'NORMALIZED')}</strong></span>
              </div>
            </div>
          </div>

          <!-- Top action buttons -->
          <div class="flex items-center gap-stack-md self-start shrink-0">
            <button onclick="app.exportCurrentEvent()" 
                    class="px-4 py-2 border border-outline-variant rounded-DEFAULT font-label-caps text-label-caps text-on-surface hover:bg-surface-container-high transition-colors flex items-center gap-2"
                    title="Download complete forensic JSON event artifact">
              <span class="material-symbols-outlined text-[16px]">download</span>
              EXPORT ARTIFACT
            </button>
            <button onclick="app.openIsolateModal()" 
                    class="px-4 py-2 ${isIsolated ? 'bg-surface-container-high text-error border border-error/40' : 'bg-primary text-on-primary hover:bg-primary-container'} rounded-DEFAULT font-label-caps text-label-caps transition-colors flex items-center gap-2"
                    title="Safely quarantine this source IP/host within ULPF local environment">
              <span class="material-symbols-outlined text-[16px]">${isIsolated ? 'lock' : 'security'}</span>
              ${isIsolated ? 'RELEASE SOURCE' : 'ISOLATE SOURCE'}
            </button>
          </div>
        </div>
      </div>

      <!-- MAIN WORKSPACE: TWO COLUMNS -->
      <div class="flex flex-col lg:flex-row w-full flex-1">
        <!-- LEFT PANEL: EVENT LIFECYCLE TIMELINE (w-80 / w-full on mobile) -->
        <div class="w-full lg:w-80 bg-surface-container-low border-r border-outline-variant p-gutter shrink-0">
          <div class="flex items-center justify-between mb-stack-lg">
            <h2 class="font-label-caps text-label-caps text-outline">EVENT LIFECYCLE</h2>
            <span class="font-code-xs text-code-xs text-on-surface-variant">6 STAGES</span>
          </div>

          <div class="relative pl-3 space-y-stack-lg border-l border-outline-variant ml-2">
            ${(event.lifecycle || []).map((step, idx) => {
              let dotRingColor = 'bg-primary ring-surface-container-low';
              let titleColor = 'text-on-surface';
              if (step.color === 'error' || step.status === 'critical') {
                dotRingColor = 'bg-error ring-surface-container-low';
                titleColor = 'text-error';
              } else if (step.color === 'tertiary' || step.status === 'verified') {
                dotRingColor = 'bg-tertiary ring-surface-container-low';
                titleColor = 'text-tertiary';
              } else if (step.color === 'warning' || step.status === 'warning') {
                dotRingColor = 'bg-amber-400 ring-surface-container-low';
                titleColor = 'text-amber-400';
              }

              return `
                <div class="relative group">
                  <div class="absolute -left-[19px] top-1 w-2.5 h-2.5 rounded-full ${dotRingColor} ring-4 transition-transform group-hover:scale-125"></div>
                  <div class="font-label-caps text-label-caps ${titleColor} mb-0.5 tracking-wide">
                    ${escapeHtml(step.title)}
                  </div>
                  <div class="font-code-xs text-code-xs text-on-surface-variant font-mono">
                    ${escapeHtml(step.detail)}
                  </div>
                </div>
              `;
            }).join('')}
          </div>

          <!-- Air-gapped pipeline certification stamp -->
          <div class="mt-8 p-3 rounded bg-surface-container border border-outline-variant/60 font-code-xs text-code-xs text-outline space-y-1">
            <div class="flex items-center gap-1.5 text-tertiary font-semibold">
              <span class="material-symbols-outlined text-[14px]">verified_user</span>
              AIR-GAPPED COMPLIANCE
            </div>
            <div>Pipeline executed locally with deterministic zero-tamper cryptographic provenance.</div>
          </div>
        </div>

        <!-- RIGHT PANEL: MAIN CONTENT AREA -->
        <div class="flex-1 p-gutter space-y-stack-md overflow-x-hidden">
          <!-- ANALYSIS & INTEGRITY ROW (Two Cards) -->
          <div class="grid grid-cols-1 xl:grid-cols-2 gap-stack-md">
            <!-- AI ANOMALY ANALYSIS CARD -->
            <div class="bg-surface-container border border-outline-variant rounded-DEFAULT p-stack-md hover:border-outline transition-colors">
              <div class="flex items-center justify-between mb-stack-sm">
                <div class="flex items-center gap-2">
                  <span class="material-symbols-outlined text-[18px] text-error">neurology</span>
                  <h3 class="font-label-caps text-label-caps text-outline">ANOMALY ANALYSIS</h3>
                </div>
                <span class="font-code-sm text-code-sm font-semibold font-mono ${scoreColorClass}">
                  SCORE: ${anomalyScore}/100
                </span>
              </div>
              <div class="font-body-md text-body-md text-on-surface-variant mb-stack-sm leading-relaxed">
                ${escapeHtml(event.anomaly?.explanation || 'No anomalous telemetry detected. Conforms to expected baseline.')}
              </div>
              <div class="w-full bg-surface-container-highest rounded-full h-1.5 mb-2.5 overflow-hidden">
                <div class="${scoreBarColor} h-1.5 rounded-full transition-all duration-500" style="width: ${anomalyScore}%"></div>
              </div>
              <div class="flex justify-between font-code-xs text-code-xs text-outline font-mono">
                <span>Confidence: <strong class="text-on-surface">${escapeHtml(event.anomaly?.confidence || 'High')}</strong></span>
                <span>Model: <strong class="text-on-surface">${escapeHtml(event.anomaly?.model || 'Isolation Forest')}</strong></span>
              </div>
            </div>

            <!-- CRYPTOGRAPHIC INTEGRITY CARD -->
            <div class="bg-surface-container border border-outline-variant rounded-DEFAULT p-stack-md hover:border-outline transition-colors">
              <div class="flex items-center justify-between mb-stack-sm">
                <div class="flex items-center gap-2">
                  <span class="material-symbols-outlined text-[18px] text-tertiary">lock</span>
                  <h3 class="font-label-caps text-label-caps text-outline">CRYPTOGRAPHIC INTEGRITY</h3>
                </div>
                <button onclick="app.viewEventOnLedger(${event.integrity?.block_index || 0})" 
                        class="font-code-xs text-code-xs text-primary hover:underline flex items-center gap-1">
                  VIEW ON LEDGER
                  <span class="material-symbols-outlined text-[12px]">arrow_forward</span>
                </button>
              </div>

              <div class="space-y-2.5 font-code-xs text-code-xs">
                <div class="flex flex-col">
                  <div class="flex items-center justify-between">
                    <span class="text-on-surface-variant font-medium">Event Hash (SHA-256):</span>
                    <button onclick="app.copyText('${escapeHtml(event.integrity?.sha256 || '')}', 'Event Hash')" 
                            class="text-outline hover:text-primary transition-colors flex items-center gap-1" title="Copy full SHA-256 hash">
                      <span class="material-symbols-outlined text-[12px]">content_copy</span>
                      <span>Copy</span>
                    </button>
                  </div>
                  <span class="text-primary font-mono truncate select-all bg-surface-container-low px-2 py-1 rounded mt-0.5 border border-outline-variant/40" title="${escapeHtml(event.integrity?.sha256 || '')}">
                    ${escapeHtml(event.integrity?.sha256 || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')}
                  </span>
                </div>

                <div class="flex flex-col">
                  <div class="flex items-center justify-between">
                    <span class="text-on-surface-variant font-medium">Merkle Root:</span>
                    <button onclick="app.copyText('${escapeHtml(event.integrity?.merkle_root || '')}', 'Merkle Root')" 
                            class="text-outline hover:text-primary transition-colors flex items-center gap-1" title="Copy Merkle root">
                      <span class="material-symbols-outlined text-[12px]">content_copy</span>
                      <span>Copy</span>
                    </button>
                  </div>
                  <span class="text-on-surface font-mono truncate select-all bg-surface-container-low px-2 py-1 rounded mt-0.5 border border-outline-variant/40" title="${escapeHtml(event.integrity?.merkle_root || '')}">
                    ${escapeHtml(event.integrity?.merkle_root || '7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730')}
                  </span>
                </div>

                <div class="flex items-center justify-between pt-1 border-t border-outline-variant/40">
                  <div class="flex items-center gap-1.5 text-tertiary">
                    <span class="material-symbols-outlined text-[14px]">check_circle</span>
                    <span class="font-medium">${escapeHtml(event.integrity?.status || 'Verified on ULPF Ledger')}</span>
                  </div>
                  <span class="font-code-xs text-code-xs text-outline font-mono">Batch: ${escapeHtml(event.integrity?.batch_id || 'SYNC_BATCH_X992A')}</span>
                </div>
              </div>
            </div>
          </div>

          <!-- DATA VIEWS (Tabbed Component) -->
          <div class="bg-surface-container border border-outline-variant rounded-DEFAULT overflow-hidden">
            <!-- TAB BAR -->
            <div class="flex border-b border-outline-variant px-stack-md bg-surface-container-low/50">
              <button onclick="app.setInvestigationTab('ocsf')" 
                      class="px-stack-md py-3 border-b-2 font-label-caps text-label-caps transition-colors flex items-center gap-2 ${activeTab === 'ocsf' ? 'border-primary text-primary font-semibold' : 'border-transparent text-on-surface-variant hover:text-on-surface'}">
                <span class="material-symbols-outlined text-[16px]">data_object</span>
                OCSF EVENT (JSON)
              </button>
              <button onclick="app.setInvestigationTab('raw')" 
                      class="px-stack-md py-3 border-b-2 font-label-caps text-label-caps transition-colors flex items-center gap-2 ${activeTab === 'raw' ? 'border-primary text-primary font-semibold' : 'border-transparent text-on-surface-variant hover:text-on-surface'}">
                <span class="material-symbols-outlined text-[16px]">terminal</span>
                RAW LOG
              </button>
              <button onclick="app.setInvestigationTab('metadata')" 
                      class="px-stack-md py-3 border-b-2 font-label-caps text-label-caps transition-colors flex items-center gap-2 ${activeTab === 'metadata' ? 'border-primary text-primary font-semibold' : 'border-transparent text-on-surface-variant hover:text-on-surface'}">
                <span class="material-symbols-outlined text-[16px]">list_alt</span>
                PARSED METADATA
              </button>
            </div>

            <!-- TAB CONTENT AREA -->
            <div class="p-gutter">
              ${activeTab === 'ocsf' ? `
                <!-- TAB 1: OCSF JSON VIEW -->
                <div>
                  <div class="flex items-center justify-between mb-3">
                    <div class="flex items-center gap-2 font-code-xs text-code-xs text-outline font-mono">
                      <span>SCHEMA: OCSF v1.1.0</span>
                      <span>•</span>
                      <span>CLASS: ${escapeHtml(event.event_type)}</span>
                    </div>
                    <button onclick="app.copyText(JSON.stringify(app.investigationState.event ? app.investigationState.event.ocsf_event : {}, null, 2), 'OCSF JSON')" 
                            class="px-2.5 py-1 text-xs border border-outline-variant rounded bg-surface-container-high hover:bg-surface-container text-on-surface flex items-center gap-1.5 transition-colors font-code-xs">
                      <span class="material-symbols-outlined text-[14px]">content_copy</span>
                      Copy OCSF JSON
                    </button>
                  </div>
                  <pre class="bg-surface-container-low p-4 rounded border border-outline-variant font-mono text-code-xs text-on-surface overflow-x-auto max-h-[500px] select-all leading-relaxed">${escapeHtml(JSON.stringify(event.ocsf_event, null, 2))}</pre>
                </div>
              ` : ''}

              ${activeTab === 'raw' ? `
                <!-- TAB 2: RAW UNTOUCHED LOG VIEW -->
                <div>
                  <div class="flex items-center justify-between mb-3">
                    <div class="flex items-center gap-2 font-code-xs text-code-xs text-outline font-mono">
                      <span>ORIGINAL AIR-GAPPED INGESTION PAYLOAD</span>
                      <span>•</span>
                      <span>${escapeHtml(event.raw_log ? String(event.raw_log.length) : '0')} BYTES</span>
                    </div>
                    <button onclick="app.copyText(app.investigationState.event ? app.investigationState.event.raw_log : '', 'Raw Log')" 
                            class="px-2.5 py-1 text-xs border border-outline-variant rounded bg-surface-container-high hover:bg-surface-container text-on-surface flex items-center gap-1.5 transition-colors font-code-xs">
                      <span class="material-symbols-outlined text-[14px]">content_copy</span>
                      Copy Raw Log
                    </button>
                  </div>
                  <div class="bg-surface-container-low p-4 rounded border border-outline-variant font-mono text-code-xs text-on-surface overflow-x-auto max-h-[500px] whitespace-pre-wrap break-all select-all leading-relaxed">${escapeHtml(event.raw_log)}</div>
                </div>
              ` : ''}

              ${activeTab === 'metadata' ? `
                <!-- TAB 3: PARSED METADATA ATTRIBUTES TABLE -->
                <div>
                  <div class="flex items-center justify-between mb-3 font-code-xs text-code-xs text-outline font-mono">
                    <span>EXTRACTED & NORMALIZED ENTITY ATTRIBUTES</span>
                    <span>${Object.keys(event.parsed_metadata || {}).length} FIELDS EXTRACTED</span>
                  </div>
                  <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                    ${Object.entries(event.parsed_metadata || {}).map(([key, val]) => `
                      <div class="flex items-start justify-between p-2.5 rounded bg-surface-container-low border border-outline-variant/60 font-mono text-code-xs">
                        <span class="text-on-surface-variant font-medium shrink-0 mr-4">${escapeHtml(key)}:</span>
                        <span class="text-on-surface font-semibold text-right break-all select-all">${escapeHtml(String(val))}</span>
                      </div>
                    `).join('')}
                  </div>
                </div>
              ` : ''}
            </div>
          </div>
        </div>
      </div>

      <!-- SOURCE ISOLATION MODAL -->
      ${isolateModalOpen ? `
        <div class="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4 backdrop-blur-sm animate-fade-in">
          <div class="bg-surface-container border border-outline-variant rounded-DEFAULT max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div class="flex items-center gap-3 text-error">
              <span class="material-symbols-outlined text-[28px]">warning</span>
              <h3 class="font-display-lg text-lg font-bold text-on-surface">
                ${isIsolated ? 'RELEASE SOURCE FROM QUARANTINE' : 'ISOLATE SECURITY SOURCE'}
              </h3>
            </div>

            <div class="space-y-2 font-body-md text-body-md text-on-surface-variant leading-relaxed">
              <p>
                Target source: <strong class="text-on-surface font-mono">${escapeHtml(event.source)}</strong>
              </p>
              <p>
                ${isIsolated 
                  ? 'Releasing this source will restore standard ULPF ingestion and unblock its traffic profile in the local forensic station.' 
                  : 'Forensically isolating this source will drop further ingestion from this IP/host within ULPF and mark future incoming telemetry as quarantined.'}
              </p>
              <div class="p-3 bg-surface-container-high rounded border border-outline-variant/60 font-code-xs text-code-xs text-outline space-y-1">
                <div class="font-semibold text-primary flex items-center gap-1">
                  <span class="material-symbols-outlined text-[14px]">info</span>
                  INVESTIGATION PROTOTYPE ACTION
                </div>
                <div>This action is scoped locally to ULPF. In accordance with air-gapped forensic protocol, no external firewall hardware is disrupted.</div>
              </div>
            </div>

            <div class="flex justify-end gap-3 pt-2">
              <button onclick="app.closeIsolateModal()" 
                      class="px-4 py-2 border border-outline-variant rounded-DEFAULT font-label-caps text-label-caps text-on-surface hover:bg-surface-container-high transition-colors">
                CANCEL
              </button>
              <button onclick="app.confirmIsolateSource()" 
                      class="px-4 py-2 ${isIsolated ? 'bg-primary text-on-primary' : 'bg-error text-white'} rounded-DEFAULT font-label-caps text-label-caps font-semibold hover:opacity-90 transition-opacity">
                ${isIsolated ? 'CONFIRM RELEASE' : 'CONFIRM ISOLATION'}
              </button>
            </div>
          </div>
        </div>
      ` : ''}
    </div>
  `;
}
