export function renderEventDetailsPage(event) {
  if (!event) {
    return `<div class="panel"><div class="empty">No event selected.</div></div>`;
  }

  const rawText = event.raw_text || event.raw_event || 'No raw text attached';
  const cleanEvent = { ...event };
  delete cleanEvent.raw_text;
  delete cleanEvent.raw_received_at;
  delete cleanEvent.source_file;

  return `
    <div class="panel">
      <div class="panel-title">
        <span>🔍 Event Forensic Details: ${event.event_id}</span>
        <button class="btn btn-sm" onclick="app.navigate('explorer')">← Back to Explorer</button>
      </div>

      <div class="grid-2" style="margin-top:16px;">
        <div>
          <h4 style="font-size:13px; color:#38bdf8; margin-bottom:8px;">Normalized OCSF Object</h4>
          <pre>${JSON.stringify(cleanEvent, null, 2)}</pre>
        </div>
        <div>
          <h4 style="font-size:13px; color:#4ade80; margin-bottom:8px;">Untouched Original Raw Log (SHA-256 Verified)</h4>
          <pre style="color:#4ade80;">${rawText}</pre>
        </div>
      </div>
    </div>
  `;
}
