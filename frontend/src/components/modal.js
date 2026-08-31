export function renderTraceModal() {
  return `
    <div class="modal" id="trace-modal" onclick="if(event.target===this) app.closeModal()">
      <div class="modal-content">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
          <h3 style="font-size:16px; color:#38bdf8;">🔍 Forensic Traceability: Normalized vs Original Raw Log</h3>
          <button class="btn btn-sm" onclick="app.closeModal()">✕ Close</button>
        </div>
        <div style="font-size:12px; color:var(--text-muted); margin-bottom:6px;">Normalized Event Object (OCSF Schema):</div>
        <pre id="modal-normalized-json"></pre>
        <div style="font-size:12px; color:var(--text-muted); margin:14px 0 6px 0;">Original Untouched Raw Log (raw_events via SHA-256):</div>
        <pre id="modal-raw-text" style="color:#4ade80;"></pre>
      </div>
    </div>
  `;
}
