/**
 * ULPF Blockchain Integrity & Chain-of-Custody Page
 * Strictly for cybersecurity log integrity, tamper detection, and cryptographic audit.
 * 100% Local, Offline, and Air-Gapped.
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

export function renderBlockchainPage(state = {}) {
  const summary = state.summary || {
    total_anchored: 0,
    verified: 0,
    failed: 0,
    pending: 0,
    chain_status: 'VALID'
  };

  const totalAnchored = (summary.total_anchored || 0).toLocaleString();
  const verifiedCount = (summary.verified || 0).toLocaleString();
  const failedCount = (summary.failed || 0).toLocaleString();
  const pendingCount = (summary.pending || 0).toLocaleString();

  const allBlocks = state.blocks || [];
  const searchQuery = (state.searchQuery || '').trim().toLowerCase();

  const filteredBlocks = searchQuery
    ? allBlocks.filter(b =>
        String(b.block_index).includes(searchQuery) ||
        (b.batch_id && b.batch_id.toLowerCase().includes(searchQuery)) ||
        (b.batch_hash && b.batch_hash.toLowerCase().includes(searchQuery)) ||
        (b.anchor_hash && b.anchor_hash.toLowerCase().includes(searchQuery)) ||
        (b.merkle_root && b.merkle_root.toLowerCase().includes(searchQuery))
      )
    : allBlocks;

  const selectedBlock = state.selectedBlock || (filteredBlocks.length > 0 ? filteredBlocks[0] : null);

  // 1. Render Timeline items
  let timelineCardsHtml = '';
  if (filteredBlocks.length === 0) {
    timelineCardsHtml = `
      <div class="relative z-10 p-8 text-center bg-surface-container rounded-DEFAULT border border-outline-variant/40">
        <span class="material-symbols-outlined text-[40px] text-on-surface-variant opacity-40 mb-2">lock_clock</span>
        <div class="font-label-caps text-label-caps text-on-surface-variant">NO BLOCKCHAIN RECORDS AVAILABLE</div>
        <p class="font-code-xs text-code-xs text-on-surface-variant opacity-60 mt-1">No batches match the search criteria.</p>
      </div>
    `;
  } else {
    timelineCardsHtml = filteredBlocks.map(b => {
      const isSelected = selectedBlock && selectedBlock.block_index === b.block_index;
      const isVerified = b.status === 'VERIFIED';
      const isFailed = b.status === 'FAILED';
      const isPending = b.status === 'PENDING';

      let iconColor = 'text-primary';
      let iconName = 'verified';
      let statusColor = 'text-primary';
      let statusText = 'VERIFIED';
      let borderStyle = isSelected
        ? 'border-l-2 border-primary ring-1 ring-primary/40 bg-surface-container-high'
        : 'border-l-2 border-outline-variant hover:border-l-primary/60';

      if (isFailed) {
        iconColor = 'text-error';
        iconName = 'cancel';
        statusColor = 'text-error';
        statusText = 'HASH MISMATCH';
        if (isSelected) {
          borderStyle = 'border-l-2 border-error ring-1 ring-error/40 bg-surface-container-high';
        }
      } else if (isPending) {
        iconColor = 'text-tertiary';
        iconName = 'pending';
        statusColor = 'text-tertiary';
        statusText = 'AWAITING CONFIRMATION';
        if (isSelected) {
          borderStyle = 'border-l-2 border-tertiary ring-1 ring-tertiary/40 bg-surface-container-high';
        }
      }

      const prevShort = b.previous_hash
        ? (b.previous_hash.slice(0, 10) + '...' + b.previous_hash.slice(-6))
        : '0000...0000';

      const tsDisplay = b.timestamp
        ? b.timestamp.replace('T', ' ').replace('Z', ' UTC')
        : '—';

      return `
        <div onclick="app.selectBlockchainBlock(${b.block_index})"
             class="relative z-10 flex gap-stack-md items-start cursor-pointer hover:translate-x-1.5 transition-all duration-200">
          <div class="w-12 h-12 rounded-full bg-surface-container-highest flex items-center justify-center shrink-0 shadow-md ${isSelected ? 'ring-2 ring-primary/50' : ''}">
            <span class="material-symbols-outlined ${iconColor} text-[20px]">${iconName}</span>
          </div>
          <div class="flex-1 bg-surface-container p-stack-md rounded-DEFAULT shadow-md ${borderStyle} transition-colors">
            <div class="flex justify-between items-center mb-stack-sm">
              <div class="font-label-caps text-label-caps text-on-surface-variant tracking-wider">BLOCK ${b.block_index}</div>
              <div class="font-code-xs text-code-xs text-on-surface-variant opacity-60">${escapeHtml(tsDisplay)}</div>
            </div>
            <div class="font-code-sm text-code-sm text-on-surface mb-stack-sm">
              BATCH_ID: <span class="${statusColor} font-semibold">${escapeHtml(b.batch_id)}</span>
            </div>
            <div class="flex justify-between text-code-xs text-on-surface-variant opacity-70">
              <span class="truncate max-w-[210px]" title="${escapeHtml(b.previous_hash)}">PREV: ${prevShort}</span>
              <span class="${statusColor} font-semibold">${statusText}</span>
            </div>
          </div>
        </div>
      `;
    }).join('');
  }

  // 2. Render Inspector panel
  let inspectorHtml = '';
  if (!selectedBlock) {
    inspectorHtml = `
      <div class="flex flex-col items-center justify-center h-full p-8 text-center text-on-surface-variant">
        <span class="material-symbols-outlined text-[48px] opacity-30 mb-2">find_in_page</span>
        <div class="font-title-sm text-title-sm">No Block Selected</div>
        <p class="font-body-md text-body-md opacity-60 mt-1">Select a block from the timeline to inspect its cryptographic chain of custody.</p>
      </div>
    `;
  } else {
    const isVerified = selectedBlock.status === 'VERIFIED';
    const isFailed = selectedBlock.status === 'FAILED';
    const isPending = selectedBlock.status === 'PENDING';

    let statusDisplay = `<span class="text-primary flex items-center gap-1 font-semibold"><span class="material-symbols-outlined text-[16px]">verified</span> VERIFIED</span>`;
    let reasonBanner = '';

    if (isFailed) {
      statusDisplay = `<span class="text-error flex items-center gap-1 font-semibold"><span class="material-symbols-outlined text-[16px]">cancel</span> HASH MISMATCH</span>`;
      reasonBanner = `
        <div class="p-2.5 bg-error/15 border border-error/30 rounded-DEFAULT text-error font-code-xs text-code-xs mb-stack-md flex items-start gap-2">
          <span class="material-symbols-outlined text-[16px] shrink-0 mt-0.5">error</span>
          <div>
            <strong>INTEGRITY WARNING:</strong> ${escapeHtml(selectedBlock.verification_reason || 'Local stored hash does not match immutable ledger anchor hash.')}
          </div>
        </div>
      `;
    } else if (isPending) {
      statusDisplay = `<span class="text-tertiary flex items-center gap-1 font-semibold"><span class="material-symbols-outlined text-[16px]">pending</span> AWAITING CONFIRMATION</span>`;
      reasonBanner = `
        <div class="p-2.5 bg-tertiary/15 border border-tertiary/30 rounded-DEFAULT text-tertiary font-code-xs text-code-xs mb-stack-md flex items-start gap-2">
          <span class="material-symbols-outlined text-[16px] shrink-0 mt-0.5">hourglass_empty</span>
          <div>
            <strong>PIPELINE BUFFER:</strong> ${escapeHtml(selectedBlock.verification_reason || 'Batch is queued in pipeline; awaiting final ledger anchor commitment.')}
          </div>
        </div>
      `;
    } else {
      reasonBanner = `
        <div class="p-2.5 bg-[#22c55e]/10 border border-[#22c55e]/30 rounded-DEFAULT text-[#22c55e] font-code-xs text-code-xs mb-stack-md flex items-start gap-2">
          <span class="material-symbols-outlined text-[16px] shrink-0 mt-0.5">verified_user</span>
          <div>
            <strong>CRYPTOGRAPHIC AUDIT PASSED:</strong> Stored log evidence exactly matches the sealed ledger anchor proof (0 bit drift).
          </div>
        </div>
      `;
    }

    const hashesMatch = selectedBlock.batch_hash === selectedBlock.anchor_hash;

    inspectorHtml = `
      <div class="flex items-center justify-between border-b border-outline-variant pb-stack-sm mb-stack-md">
        <div class="flex items-center gap-2">
          <span class="material-symbols-outlined text-primary text-[20px]">policy</span>
          <span class="font-title-sm text-title-sm text-on-surface">Block Inspection</span>
        </div>
        <div class="px-2.5 py-1 bg-primary/10 text-primary font-label-caps text-label-caps rounded-DEFAULT border border-primary/30">
          BLOCK ${selectedBlock.block_index}
        </div>
      </div>

      ${reasonBanner}

      <div class="grid grid-cols-2 gap-stack-md mb-stack-md bg-surface-container-low p-stack-sm rounded-DEFAULT border border-outline-variant/30">
        <div>
          <div class="font-label-caps text-label-caps text-on-surface-variant opacity-60 mb-1">TIMESTAMP</div>
          <div class="font-code-sm text-code-sm text-on-surface select-all">${escapeHtml(selectedBlock.timestamp.replace('T', ' ').replace('Z', ' UTC'))}</div>
        </div>
        <div>
          <div class="font-label-caps text-label-caps text-on-surface-variant opacity-60 mb-1">BATCH ID</div>
          <div class="font-code-sm text-code-sm text-primary font-semibold select-all">${escapeHtml(selectedBlock.batch_id)}</div>
        </div>
        <div>
          <div class="font-label-caps text-label-caps text-on-surface-variant opacity-60 mb-1">LOG COUNT</div>
          <div class="font-code-sm text-code-sm text-on-surface">${(selectedBlock.event_count || 0).toLocaleString()} EVENTS</div>
        </div>
        <div>
          <div class="font-label-caps text-label-caps text-on-surface-variant opacity-60 mb-1">STATUS</div>
          <div class="font-code-sm text-code-sm">${statusDisplay}</div>
        </div>
      </div>

      <!-- HASH COMPARISON (SHA-256) -->
      <div class="bg-surface-container-lowest p-stack-md rounded-DEFAULT mb-stack-md border border-outline-variant/30">
        <div class="flex justify-between items-center mb-stack-sm">
          <div class="font-label-caps text-label-caps text-on-surface-variant opacity-70">HASH COMPARISON (SHA-256)</div>
          <span class="font-code-xs text-code-xs ${hashesMatch ? 'text-[#22c55e]' : 'text-error'} font-semibold">
            ${hashesMatch ? '✓ HASHES MATCH' : '✕ MISMATCH DETECTED'}
          </span>
        </div>

        <div class="space-y-stack-sm">
          <div>
            <div class="font-code-xs text-code-xs text-on-surface-variant mb-1">LOCAL STORED HASH</div>
            <div class="font-code-sm text-code-sm text-on-surface break-all bg-surface-container-low p-2 rounded-DEFAULT border border-outline-variant/30 select-all">
              ${escapeHtml(selectedBlock.batch_hash)}
            </div>
          </div>
          <div class="flex justify-center text-primary">
            <span class="material-symbols-outlined text-[20px]">swap_vert</span>
          </div>
          <div>
            <div class="font-label-caps text-code-xs text-on-surface-variant mb-1">LEDGER ANCHOR HASH</div>
            <div class="font-code-sm text-code-sm text-primary break-all bg-surface-container-low p-2 rounded-DEFAULT ring-1 ring-primary/40 select-all">
              ${escapeHtml(selectedBlock.anchor_hash)}
            </div>
          </div>
        </div>

        <!-- Merkle Root preview -->
        <div class="mt-stack-md pt-stack-sm border-t border-outline-variant/40">
          <div class="font-code-xs text-code-xs text-on-surface-variant mb-1">CONSTITUENT MERKLE ROOT</div>
          <div class="font-code-xs text-code-xs text-[#a5f3fc] break-all bg-surface-container-low p-2 rounded-DEFAULT border border-outline-variant/30 select-all" title="Merkle Root of constituent log hashes">
            ${escapeHtml(selectedBlock.merkle_root)}
          </div>
        </div>
      </div>

      <!-- ACTION BUTTONS -->
      <div class="flex items-center justify-between mt-auto pt-stack-sm border-t border-outline-variant/40">
        <button onclick="app.openMerkleRootModal()"
                class="px-3 py-2 bg-primary/10 hover:bg-primary/20 text-primary border border-primary/30 rounded-DEFAULT font-label-caps text-label-caps tracking-wide flex items-center gap-1.5 transition-colors cursor-pointer">
          <span class="material-symbols-outlined text-[16px]">receipt_long</span> VIEW RAW MERKLE ROOT
        </button>

        <div class="flex items-center gap-2">
          <button onclick="app.verifySelectedBlock()"
                  class="px-3 py-2 bg-[#22c55e]/15 hover:bg-[#22c55e]/25 text-[#22c55e] border border-[#22c55e]/30 rounded-DEFAULT font-label-caps text-label-caps flex items-center gap-1.5 transition-colors cursor-pointer"
                  title="Recalculate cryptographic hash & verify against ledger">
            <span class="material-symbols-outlined text-[16px]">verified_user</span> VERIFY BLOCK
          </button>
          <button onclick="app.simulateBatchTamper()"
                  class="px-2.5 py-2 bg-error/15 hover:bg-error/25 text-error border border-error/30 rounded-DEFAULT font-label-caps text-label-caps flex items-center gap-1 transition-colors cursor-pointer"
                  title="Demonstration only: Alter stored hash to observe tamper detection">
            <span class="material-symbols-outlined text-[14px]">bolt</span> TAMPER TEST
          </button>
          <button onclick="app.restoreBatchBlock()"
                  class="px-2.5 py-2 bg-surface-container-highest hover:bg-surface-container-high text-on-surface border border-outline-variant rounded-DEFAULT font-label-caps text-label-caps transition-colors cursor-pointer"
                  title="Restore authentic hash">
            RESTORE
          </button>
        </div>
      </div>
    `;
  }

  // 3. Merkle Root Modal
  let merkleModalHtml = '';
  if (state.merkleModalOpen && state.merkleModalData) {
    const md = state.merkleModalData;
    const leavesSample = md.leaf_hashes_sample || [];
    merkleModalHtml = `
      <div class="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4" onclick="app.closeMerkleRootModal()">
        <div class="bg-surface-container rounded-DEFAULT border border-outline-variant w-full max-w-2xl shadow-2xl p-container-padding flex flex-col gap-stack-md" onclick="event.stopPropagation()">
          <div class="flex justify-between items-center border-b border-outline-variant pb-stack-sm">
            <div class="flex items-center gap-2">
              <span class="material-symbols-outlined text-primary text-[22px]">account_tree</span>
              <span class="font-title-sm text-title-sm text-on-surface">Raw Merkle Root Inspector</span>
            </div>
            <button onclick="app.closeMerkleRootModal()" class="text-on-surface-variant hover:text-on-surface">
              <span class="material-symbols-outlined">close</span>
            </button>
          </div>

          <div class="grid grid-cols-3 gap-stack-sm bg-surface-container-lowest p-stack-sm rounded-DEFAULT border border-outline-variant/30">
            <div>
              <div class="font-label-caps text-label-caps text-on-surface-variant opacity-60">BLOCK</div>
              <div class="font-code-sm text-code-sm text-primary font-bold">#${md.block_index}</div>
            </div>
            <div>
              <div class="font-label-caps text-label-caps text-on-surface-variant opacity-60">TOTAL EVENTS</div>
              <div class="font-code-sm text-code-sm text-on-surface">${(md.total_leaves || 0).toLocaleString()}</div>
            </div>
            <div>
              <div class="font-label-caps text-label-caps text-on-surface-variant opacity-60">TREE DEPTH</div>
              <div class="font-code-sm text-code-sm text-tertiary">${md.tree_depth || 1} Levels</div>
            </div>
          </div>

          <div>
            <div class="font-label-caps text-label-caps text-on-surface-variant opacity-70 mb-1">CANONICAL MERKLE ROOT (SHA-256)</div>
            <div class="font-code-sm text-code-sm text-primary bg-surface-container-lowest p-3 rounded-DEFAULT border border-primary/40 break-all select-all font-mono">
              ${escapeHtml(md.merkle_root)}
            </div>
          </div>

          <div>
            <div class="font-label-caps text-label-caps text-on-surface-variant opacity-70 mb-1">CONSTITUENT LEAF HASHES (SAMPLE)</div>
            <div class="bg-surface-container-lowest p-3 rounded-DEFAULT border border-outline-variant/30 max-h-48 overflow-y-auto space-y-1.5 font-code-xs text-code-xs text-on-surface-variant select-all">
              ${leavesSample.map((h, i) => `
                <div class="flex gap-2">
                  <span class="text-on-surface-variant opacity-50 w-8">L${i}:</span>
                  <span class="text-on-surface font-mono break-all">${escapeHtml(h)}</span>
                </div>
              `).join('')}
            </div>
          </div>

          <div class="flex justify-end pt-stack-sm border-t border-outline-variant/40">
            <button onclick="app.closeMerkleRootModal()" class="px-4 py-1.5 bg-primary text-on-primary rounded-DEFAULT font-label-caps text-label-caps">
              DONE
            </button>
          </div>
        </div>
      </div>
    `;
  }

  // 4. Audit Chain Banner
  let auditBannerHtml = '';
  if (state.auditResult) {
    if (state.auditResult.valid) {
      auditBannerHtml = `
        <div class="p-3 bg-[#22c55e]/15 border border-[#22c55e]/40 rounded-DEFAULT text-[#22c55e] font-body-md text-sm flex items-center justify-between">
          <div class="flex items-center gap-2">
            <span class="material-symbols-outlined">verified</span>
            <span><strong>Cryptographic Ledger Audit Passed:</strong> All ${state.auditResult.verified_blocks} of ${state.auditResult.total_blocks} blocks are cryptographically valid with unbroken previous_hash continuity.</span>
          </div>
          <button onclick="app.clearBlockchainAudit()" class="text-on-surface-variant hover:text-on-surface">
            <span class="material-symbols-outlined text-[16px]">close</span>
          </button>
        </div>
      `;
    } else {
      auditBannerHtml = `
        <div class="p-3 bg-error/15 border border-error/40 rounded-DEFAULT text-error font-body-md text-sm flex items-center justify-between">
          <div class="flex items-center gap-2">
            <span class="material-symbols-outlined">warning</span>
            <span><strong>Blockchain Audit Warning at Block #${state.auditResult.invalid_block}:</strong> ${escapeHtml(state.auditResult.reason || state.auditResult.message)}</span>
          </div>
          <button onclick="app.clearBlockchainAudit()" class="text-on-surface-variant hover:text-on-surface">
            <span class="material-symbols-outlined text-[16px]">close</span>
          </button>
        </div>
      `;
    }
  }

  return `
    <div class="flex flex-col w-full h-full relative p-gutter gap-stack-md">
      <!-- TOP METRICS STRIP (4 CARDS) -->
      <div class="flex gap-gutter">
        <div class="flex-1 bg-surface-container rounded-DEFAULT p-stack-md flex items-center justify-between shadow-sm border border-outline-variant/40">
          <div class="flex items-center gap-stack-sm text-primary">
            <span class="material-symbols-outlined text-[24px]">account_balance_wallet</span>
            <div>
              <div class="font-label-caps text-label-caps text-on-surface-variant opacity-70">TOTAL ANCHORED</div>
              <div class="font-headline-md text-headline-md text-on-surface">${totalAnchored}</div>
            </div>
          </div>
          <div class="flex items-center gap-stack-sm text-[#00E676]">
            <span class="material-symbols-outlined text-[24px]">verified</span>
            <div>
              <div class="font-label-caps text-label-caps text-on-surface-variant opacity-70">VERIFIED</div>
              <div class="font-headline-md text-headline-md text-on-surface">${verifiedCount}</div>
            </div>
          </div>
          <div class="flex items-center gap-stack-sm text-error">
            <span class="material-symbols-outlined text-[24px]">cancel</span>
            <div>
              <div class="font-label-caps text-label-caps text-on-surface-variant opacity-70">FAILED</div>
              <div class="font-headline-md text-headline-md text-on-surface">${failedCount}</div>
            </div>
          </div>
          <div class="flex items-center gap-stack-sm text-tertiary">
            <span class="material-symbols-outlined text-[24px]">pending</span>
            <div>
              <div class="font-label-caps text-label-caps text-on-surface-variant opacity-70">PENDING</div>
              <div class="font-headline-md text-headline-md text-on-surface">${pendingCount}</div>
            </div>
          </div>
        </div>
      </div>

      <!-- SEARCH & CONTROLS TOOLBAR -->
      <div class="flex items-center justify-between gap-stack-md bg-surface-container p-stack-sm rounded-DEFAULT border border-outline-variant/40">
        <div class="flex items-center gap-2 flex-1 max-w-md">
          <span class="material-symbols-outlined text-on-surface-variant text-[18px]">search</span>
          <input type="text"
                 value="${escapeHtml(state.searchQuery || '')}"
                 oninput="app.searchBlockchainBlocks(this.value)"
                 placeholder="Search Block ID, Batch ID, or Hash..."
                 class="w-full bg-surface-container-lowest border border-outline-variant rounded-DEFAULT py-1.5 px-3 text-code-sm text-on-surface focus:outline-none focus:border-primary transition-all">
        </div>
        <div class="flex items-center gap-2">
          <button onclick="app.auditBlockchain()" class="flex items-center gap-1.5 px-3 py-1.5 bg-primary/10 hover:bg-primary/20 text-primary border border-primary/30 rounded-DEFAULT font-label-caps text-label-caps transition-colors cursor-pointer" title="Verify unbroken previous_hash continuity across the entire ledger">
            <span class="material-symbols-outlined text-[16px]">security_update_good</span> AUDIT CHAIN
          </button>
          <button onclick="app.loadBlockchainData()" class="flex items-center gap-1.5 px-3 py-1.5 bg-surface-container-highest hover:bg-surface-container-high text-on-surface border border-outline-variant rounded-DEFAULT font-label-caps text-label-caps transition-colors cursor-pointer">
            <span class="material-symbols-outlined text-[16px]">refresh</span> REFRESH
          </button>
        </div>
      </div>

      ${auditBannerHtml}

      <!-- MAIN TIMELINE & INSPECTOR SPLIT (50% / 50%) -->
      <div class="flex flex-1 gap-gutter overflow-hidden min-h-[580px]">
        <!-- TIMELINE (LEFT 50%) -->
        <div class="w-1/2 flex flex-col gap-stack-md overflow-y-auto pr-gutter relative pb-stack-lg max-h-[calc(100vh-270px)]">
          <div class="absolute left-6 top-0 bottom-0 w-0.5 bg-outline-variant opacity-50 z-0"></div>
          ${timelineCardsHtml}
        </div>

        <!-- BLOCK INSPECTION (RIGHT 50%) -->
        <div class="w-1/2 bg-surface-container rounded-DEFAULT p-stack-md flex flex-col shadow-lg relative overflow-hidden border border-outline-variant/40 max-h-[calc(100vh-270px)] overflow-y-auto">
          <div class="absolute top-0 right-0 w-32 h-32 bg-primary/5 rounded-bl-full blur-xl z-0 pointer-events-none"></div>
          <div class="relative z-10 flex flex-col h-full">
            ${inspectorHtml}
          </div>
        </div>
      </div>

      ${merkleModalHtml}
    </div>
  `;
}
