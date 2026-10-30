/* Analyst workspace orchestration. API data remains the only source of case counts. */
let casesLoading = false;
let jobsLoading = false;
let tablePreferenceSnapshot = '';
let tablePreferenceTimer;

function setNavigationState(page) {
  document.querySelectorAll('.nav-item').forEach(button => {
    const active = button.dataset.page === page || (page === 'case-detail' && button.dataset.page === 'dashboard');
    button.classList.toggle('active', active);
    if (active) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  });
  document.getElementById('workspace-nav').classList.remove('mobile-open');
  document.querySelector('.mobile-menu').setAttribute('aria-expanded', 'false');
  document.getElementById('main-content').focus({preventScroll:true});
  document.title = `Triage Engine · ${page === 'case-detail' ? 'Investigation' : ({dashboard:'Overview',queue:'Review queue',investigate:'New investigation',jobs:'Jobs','quick-check':'Quick Check'}[page] || 'Workspace')}`;
}

function toggleNavigation() {
  const open = document.getElementById('workspace-nav').classList.toggle('mobile-open');
  document.querySelector('.mobile-menu').setAttribute('aria-expanded', String(open));
  if (open) document.querySelector('.nav-item.active')?.focus();
}

function persistTablePreferences() {
  const snapshot = JSON.stringify(tableState);
  if (snapshot === tablePreferenceSnapshot) return;
  // The first render hydrates server preferences; it must not write them back.
  if (!tablePreferenceSnapshot) { tablePreferenceSnapshot = snapshot; return; }
  tablePreferenceSnapshot = snapshot;
  clearTimeout(tablePreferenceTimer);
  tablePreferenceTimer = setTimeout(() => savePreferencesPatch({tableState:JSON.parse(snapshot)}), 400);
}

function clearWorkspaceSession() {
  clearTimeout(tablePreferenceTimer);
  tablePreferenceSnapshot = '';
  caseRequestId++;
  queueRequestId++;
  timelineRequestId++;
  _casesCache = []; _queueCache = []; _jobsCache = []; _caseData = null;
  timelineRows = []; timelineCase = ''; selectedJobIds.clear();
  document.querySelectorAll('#cases-table,#queue-table,#jobs-table,#dashboard-focus,#detail-content,#detail-stats,#stats-row,#queue-stats').forEach(el=>{el.innerHTML='';delete el.dataset.signature;delete el.dataset.markup;});
  document.querySelectorAll('.modal-shell').forEach(el=>el.classList.add('hidden'));
  document.getElementById('toast-stack').innerHTML = '';
}

function refreshWorkspace() {
  if (currentPage === 'queue') return loadQueue();
  if (currentPage === 'jobs') return loadJobs();
  return loadCases();
}

function updateFreshness(message) {
  document.getElementById('workspace-freshness').textContent = message || `Updated ${new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}`;
}

async function loadCases(background = false) {
  if (casesLoading || !authState.authenticated) return;
  casesLoading = true;
  const session = authState.csrfToken;
  if (!background && !_casesCache.length) renderTableMessage('cases-table', 7, 'Loading investigations…', 'loading');
  try {
    const results = await Promise.allSettled([
      apiJSON('/api/cases'), apiJSON('/api/review/queue?limit=200'), apiJSON('/api/jobs'),
    ]);
    if (!authState.authenticated || session !== authState.csrfToken) return;
    if (results[0].status === 'rejected') throw results[0].reason;
    _casesCache = Array.isArray(results[0].value) ? results[0].value : [];
    const queue = results[1].status === 'fulfilled' && Array.isArray(results[1].value) ? results[1].value : null;
    _jobsCache = results[2].status === 'fulfilled' && Array.isArray(results[2].value) ? results[2].value : [];
    document.getElementById('stats-row').innerHTML =
      stat(_casesCache.length, 'Investigations', '--text') +
      stat(_casesCache.filter(c => c.status === 'running').length, 'Currently processing', '--blue') +
      stat(_casesCache.reduce((n,c) => n + (c.finding_count || 0), 0), 'Total findings', '--orange') +
      stat(_casesCache.reduce((n,c) => n + (c.incident_count || 0), 0), 'Correlated incidents', '--red');
    renderDashboardFocus(_casesCache, queue, results[2].status === 'fulfilled');
    // Preserve table focus and selection when a background response is unchanged.
    const signature = JSON.stringify(_casesCache);
    const tbody = document.getElementById('cases-table');
    if (!background || tbody.dataset.signature !== signature) updateCasesView();
    tbody.dataset.signature = signature;
    updateFreshness(queue === null || results[2].status === 'rejected' ? 'Updated · some services unavailable' : '');
    document.getElementById('workspace-error')?.remove();
  } catch (error) {
    if (!authState.authenticated || session !== authState.csrfToken) return;
    updateFreshness('Connection interrupted · data may be stale');
    if (!_casesCache.length) renderTableMessage('cases-table',7,'Could not load investigations. Use Refresh to retry.');
    if (!document.getElementById('workspace-error')) {
      const banner = document.createElement('div');
      banner.id = 'workspace-error'; banner.className = 'workspace-error'; banner.setAttribute('role','alert');
      banner.textContent = 'Unable to refresh the workspace. Displayed data may be out of date. Use Refresh to try again.';
      document.getElementById('stats-row').before(banner);
    }
  } finally { casesLoading = false; }
}

function renderDashboardFocus(cases, queue, jobsAvailable = true) {
  const widgets = getDashboardWidgets();
  const username = authState.user?.username || '';
  const actionable = (queue || []).filter(item => !['Closed','Suppressed'].includes(item.status || 'Open'));
  const counts = {
    open: actionable.filter(i => (i.status || 'Open') === 'Open').length,
    review: actionable.filter(i => i.status === 'In Review').length,
    escalated: actionable.filter(i => i.status === 'Escalated').length,
    mine: actionable.filter(i => i.owner === username).length,
  };
  const highPriority = [...cases].filter(c => c.finding_count || c.incident_count).sort((a,b)=>compareCases(a,b,'priority_asc')).slice(0,4);
  const count = actionable.length || 1;
  const cards = [];
  if (widgets.has('priority-watch')) cards.push(`<section class="card"><div class="section-heading"><div><div class="eyebrow">PRIORITIZE</div><h2>Cases needing a closer look</h2></div><button class="section-link" onclick="applyQueueShortcut('priority')">Review queue ↗</button></div>
    ${highPriority.length ? highPriority.map(c => `<div class="attention-row"><span class="attention-priority priority-${esc(String(c.response_priority || 'P4').toLowerCase())}">${esc(c.response_priority || 'P4')}</span><div class="attention-info"><button onclick='openCase(${jsv(c.name)})'>${esc(c.name)}</button><small>${Number(c.finding_count)||0} findings · ${Number(c.incident_count)||0} incidents · ${esc(c.status || 'unknown')}</small></div><span class="badge badge-${esc(c.status || 'unknown')}">${esc(c.status || 'unknown')}</span></div>`).join('') : '<div class="empty-state">No investigations with promoted findings yet.<br>Import event logs to begin your first review.</div>'}
    <p class="scope-note">Ranked by case priority. Analyst decisions are tracked in the review queue.</p></section>`);
  if (widgets.has('review-focus')) cards.push(`<section class="card"><div class="section-heading"><div><div class="eyebrow">WORKLOAD</div><h2>Review at a glance</h2></div><button class="section-link" onclick="applyQueueShortcut('mine')">My queue ↗</button></div>
    ${queue === null ? '<div class="empty-state">Review service unavailable. Refresh to retry.</div>' : `<div class="queue-meter" aria-hidden="true"><span style="width:${counts.open/count*100}%;background:var(--blue)"></span><span style="width:${counts.review/count*100}%;background:var(--orange)"></span><span style="width:${counts.escalated/count*100}%;background:var(--red)"></span></div><div class="legend-grid"><div><b>${counts.open}</b><span><i class="legend-dot" style="background:var(--blue)"></i>Open</span></div><div><b>${counts.review}</b><span><i class="legend-dot" style="background:var(--orange)"></i>In review</span></div><div><b>${counts.escalated}</b><span><i class="legend-dot" style="background:var(--red)"></i>Escalated</span></div><div><b>${counts.mine}</b><span><i class="legend-dot" style="background:var(--green)"></i>Assigned to you</span></div></div><p class="scope-note">Snapshot of up to 200 recent review items. Closed and suppressed items excluded. Open the queue for further review.</p>`}</section>`);
  if (widgets.has('landing-board')) {
    const focus = userPreferences.dashboardFocus || 'mine';
    const labels = {mine:'Assigned to you',open:'Open review work',priority:'Highest priority work',jobs:'Investigation progress'};
    const selected = focus === 'jobs' ? [] : [...actionable].filter(item => focus === 'mine' ? item.owner === username : focus === 'open' ? (item.status || 'Open') === 'Open' : true).sort((a,b)=> focus === 'priority' ? priorityRank(a.priority)-priorityRank(b.priority) : safeDate(a.updated_at)-safeDate(b.updated_at)).slice(0,3);
    cards.push(`<section class="card"><div class="section-heading"><div><div class="eyebrow">YOUR WORKSPACE</div><h2>${labels[focus] || labels.mine}</h2></div><button class="section-link" onclick="openPreferencesModal()">Customize</button></div>${focus === 'jobs' ? `<p class="scope-note">${jobsAvailable ? `${_jobsCache.filter(job=>['queued','running'].includes(job.status)).length} queued or running jobs. Follow processing and artifact availability in the jobs view.` : 'Job service unavailable.'}</p><button class="btn btn-sm btn-ghost" onclick="showPage('jobs')">Open jobs ↗</button>` : queue === null ? '<div class="empty-state">Review service unavailable.</div>' : selected.length ? selected.map(item=>`<div class="attention-row"><div class="attention-info"><button onclick='openReviewItem(${jsv(item.case_name)},${jsv(item.item_type)},${jsv(item.item_id)})'>${esc(item.case_name)}</button><small>${esc(item.item_type)} · ${esc(item.item_id)}</small></div><span class="badge">${esc(item.status || 'Open')}</span></div>`).join('') : '<div class="empty-state">No matching work in this review snapshot.</div>'}<div class="scope-note">Need fresh evidence? <button class="section-link" onclick="openQuickCheck()">Check this computer ↗</button></div></section>`);
  }
  if (widgets.has('recent-jobs')) cards.push(`<section class="card"><div class="section-heading"><h2>Recent activity</h2><button class="section-link" onclick="showPage('jobs')">All jobs ↗</button></div>${!jobsAvailable ? '<div class="empty-state">Job service unavailable.</div>' : _jobsCache.length ? _jobsCache.slice(0,3).map(job=>`<div class="attention-row"><span class="status-dot"></span><div class="attention-info">${job.case_available ? `<button onclick='openCase(${jsv(job.case_name)})'>${esc(job.case_name)}</button>` : `<span>${esc(job.case_name || job.job_id)}</span>`}<small>${esc(job.stage || 'queued')}${job.case_available === false ? ' · artifacts unavailable' : ''}</small></div><span class="badge badge-${esc(job.status || 'unknown')}">${esc(job.status || 'unknown')}</span></div>`).join('') : '<div class="empty-state">Your investigation activity will appear here.</div>'}</section>`);
  const container = document.getElementById('dashboard-focus');
  const markup = cards.join('');
  if (container.dataset.markup !== markup) { container.innerHTML = markup; container.dataset.markup = markup; }
}

async function loadJobs(background = false) {
  if (jobsLoading || !authState.authenticated) return;
  jobsLoading = true;
  const session = authState.csrfToken;
  if (!background && !_jobsCache.length) renderTableMessage('jobs-table',6,'Loading jobs…','loading');
  try {
    const jobs = await apiJSON('/api/jobs');
    if (!authState.authenticated || session !== authState.csrfToken) return;
    const signature = JSON.stringify(jobs);
    const tbody = document.getElementById('jobs-table');
    _jobsCache = Array.isArray(jobs) ? jobs : [];
    selectedJobIds = new Set([...selectedJobIds].filter(id => _jobsCache.some(j=>j.job_id === id)));
    if (!background || tbody.dataset.signature !== signature) updateJobsView();
    tbody.dataset.signature = signature;
  } catch (error) {
    if (!authState.authenticated || session !== authState.csrfToken) return;
    setMeta('jobs-meta','Could not refresh jobs. Displayed data may be stale.');
    if (!_jobsCache.length) renderTableMessage('jobs-table',6,'Could not load jobs. Use Refresh jobs to retry.');
  } finally { jobsLoading = false; }
}

function setupWorkspaceAccessibility() {
  let returnFocus = null;
  let activeDialog = null;
  const visibleDialog = () => document.querySelector('.auth-overlay:not(.hidden) [role="dialog"], .modal-shell:not(.hidden) [role="dialog"]');
  const focusables = dialog => [...dialog.querySelectorAll('a[href],button,input,select,textarea,[tabindex="0"]')].filter(el => !el.disabled && el.getClientRects().length);
  const observer = new MutationObserver(() => {
    const dialog = visibleDialog();
    if (dialog && dialog !== activeDialog) {
      returnFocus = document.activeElement;
      activeDialog = dialog;
      document.querySelector('.shell').inert = true;
      (focusables(dialog).find(el=>el.matches('input')) || focusables(dialog)[0])?.focus();
    } else if (!dialog && activeDialog) {
      activeDialog = null;
      document.querySelector('.shell').inert = false;
      if (returnFocus?.isConnected) returnFocus.focus();
    }
    document.querySelectorAll('[data-mutate]').forEach(el => el.hidden = !canReviewMutate());
  });
  document.querySelectorAll('.auth-overlay,.modal-shell').forEach(el => observer.observe(el,{attributes:true,attributeFilter:['class']}));
  document.addEventListener('keydown', event => {
    const dialog = visibleDialog();
    if (event.key === 'Tab' && dialog) {
      const nodes = focusables(dialog), first = nodes[0], last = nodes[nodes.length-1];
      if (event.shiftKey && (document.activeElement === first || !dialog.contains(document.activeElement))) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && (document.activeElement === last || !dialog.contains(document.activeElement))) { event.preventDefault(); first?.focus(); }
    }
    if (event.key === 'Escape') {
      if (dialog?.closest('#preferences-modal')) closePreferencesModal();
      else if (dialog?.closest('#user-admin-modal')) closeUserAdmin();
      else if (dialog?.closest('#auth-overlay') && authState.authenticated) closeAuthOverlay();
      if (document.getElementById('workspace-nav').classList.contains('mobile-open')) { toggleNavigation(); document.querySelector('.mobile-menu').focus(); }
    }
    if (event.key === '/' && !dialog && !event.ctrlKey && !event.metaKey && !event.altKey && !event.target.closest('input,textarea,select,[contenteditable]')) {
      const search = document.getElementById(currentPage === 'queue' ? 'queue-search' : currentPage === 'dashboard' ? 'cases-search' : '');
      if (search) { event.preventDefault(); search.focus(); }
    }
  });
}

let timelineRows = [];
let timelineCase = '';
let timelineRequestId = 0;

function renderEvidenceScope(caseInfo) {
  const hosts = [...new Set((caseInfo.hosts || []).filter(Boolean))];
  const start = Date.parse(caseInfo.first_seen), end = Date.parse(caseInfo.last_seen);
  const days = Number.isFinite(start) && Number.isFinite(end) ? Math.max(0,(end-start)/86400000) : 0;
  const scope = caseInfo.evidence_scope;
  if (scope && Array.isArray(scope.warnings)) {
    // Server-computed scope (newer cases) is authoritative and matches the HTML report.
    const scopedHosts = (scope.hosts || []).filter(row => row.host && row.host !== '(unknown host)');
    const verdictRows = scopedHosts.length > 1 ? scopedHosts.slice(0, 12).map(row => {
      const verdict = row.verdict || {};
      const kind = String(verdict.disposition || '').toLowerCase().split(' ')[0];
      return `<li><span class="host-verdict ${esc(kind)}">${esc(verdict.disposition || 'Unknown')}</span> <b>${esc(row.host)}</b> <small>${esc(verdict.response_priority || '')} · ${esc(row.finding_count)} finding(s), ${esc(row.incident_count)} incident(s)</small></li>`;
    }).join('') : '';
    if (!scope.warnings.length && !verdictRows) return '';
    const more = scopedHosts.length > 12 ? `<p>${scopedHosts.length - 12} more host(s) in the report.</p>` : '';
    return `<aside class="scope-warning" aria-label="Evidence scope"><strong>${scope.warnings.length ? 'Verify the evidence scope' : 'Per-host verdicts'}</strong>${scope.warnings.length ? `<p>${scope.warnings.map(esc).join(' ')}</p>` : ''}${verdictRows ? `<ul class="host-verdicts" aria-label="Verdict per host">${verdictRows}</ul>${more}` : ''}</aside>`;
  }
  const notes = [];
  if (hosts.length > 1) notes.push(`This case contains evidence from ${hosts.length} hosts.`);
  if (days > 7) notes.push(`The evidence spans ${Math.ceil(days)} days.`);
  if (!notes.length) return '';
  return `<aside class="scope-warning" aria-label="Evidence scope"><strong>Verify the evidence scope</strong><p>${notes.join(' ')} Confirm that the hosts and collection dates belong to the same investigation before treating correlated activity as one incident.</p></aside>`;
}

async function loadEvidenceTimeline(name) {
  const requestId = ++timelineRequestId;
  const parentRequest = caseRequestId;
  timelineCase = name;
  timelineRows = [];
  const panel = document.getElementById('detail-content');
  panel.innerHTML = '<div class="card"><div class="loading-state" role="status">Loading evidence timeline…</div></div>';
  const stillCurrent = () => requestId === timelineRequestId && parentRequest === caseRequestId && currentPage === 'case-detail' && _detailTarget.tab === 'timeline';
  try {
    const payload = await apiJSON(`/api/cases/${encodeURIComponent(name)}/timeline`);
    if (!stillCurrent()) return;
    timelineRows = (Array.isArray(payload.timeline) ? payload.timeline : []).slice().sort((a,b)=>safeDate(a.timestamp)-safeDate(b.timestamp));
    const hosts = [...new Set(timelineRows.map(row=>row.host_display || row.host).filter(Boolean))].sort();
    panel.innerHTML = `<section class="card"><div class="section-heading"><div><div class="eyebrow">EVIDENCE EXPLORER</div><h2>Investigation timeline</h2></div><span class="subtle-hint">Oldest first · source timestamps</span></div><div class="table-toolbar"><div class="toolbar-group"><div class="input-group"><label for="timeline-search">Search evidence</label><input class="input" id="timeline-search" placeholder="Title, user, command, or summary…" oninput="renderEvidenceTimeline()"></div><div class="input-group"><label for="timeline-host">Host</label><select class="input" id="timeline-host" onchange="renderEvidenceTimeline()"><option value="">All hosts</option>${hosts.map(host=>`<option value="${esc(host)}">${esc(host)}</option>`).join('')}</select></div><div class="input-group"><label for="timeline-type">Evidence type</label><select class="input" id="timeline-type" onchange="renderEvidenceTimeline()"><option value="">All types</option>${[...new Set(timelineRows.map(row=>row.type).filter(Boolean))].sort().map(type=>`<option value="${esc(type)}">${esc(type)}</option>`).join('')}</select></div></div></div><p id="timeline-meta" class="scope-note" role="status"></p><div class="evidence-timeline" id="timeline-rows"></div></section>`;
    renderEvidenceTimeline();
  } catch (error) {
    if (!stillCurrent()) return;
    panel.innerHTML = `<div class="card"><div class="empty-state">Could not load timeline evidence.</div><button class="btn btn-ghost" onclick='loadEvidenceTimeline(${jsv(name)})'>Retry timeline</button></div>`;
  }
}

function renderEvidenceTimeline() {
  const query = document.getElementById('timeline-search').value.trim().toLowerCase();
  const host = document.getElementById('timeline-host').value;
  const type = document.getElementById('timeline-type').value;
  const rows = timelineRows.filter(row => (!host || (row.host_display || row.host) === host) && (!type || row.type === type) && (!query || [row.title,row.summary,row.user_display,row.user,row.command_line,row.process,row.id].some(value=>String(value || '').toLowerCase().includes(query))));
  const preview = rows.slice(0,500);
  document.getElementById('timeline-meta').textContent = `Showing ${preview.length} of ${rows.length} matching entries · ${timelineRows.length} total. ${rows.length>500 ? 'Filter by host, type, or search to narrow the preview.' : 'Expand an entry to inspect its evidence.'}`;
  document.getElementById('timeline-rows').innerHTML = preview.length ? preview.map(row=>`<details class="timeline-entry"><summary><time>${esc(row.timestamp || 'Timestamp unavailable')}</time><span><strong>${esc(row.title || row.display_label || row.type || 'Evidence')}</strong><small>${esc(row.host_display || row.host || 'Unknown host')} · ${esc(row.type || 'event')}</small></span><span class="badge">${esc(row.severity || '')}</span></summary><div class="timeline-evidence"><p>${esc(row.summary || 'No summary supplied.')}</p>${row.command_line ? `<pre>${esc(row.command_line)}</pre>` : ''}<p><strong>User:</strong> ${esc(row.user_display || row.user || 'Unknown')}</p>${row.recommended_next ? `<p><strong>Next step:</strong> ${esc(row.recommended_next)}</p>` : ''}${['finding','incident'].includes(row.type) && row.id ? `<button class="btn btn-sm btn-ghost" onclick='openReviewItem(${jsv(timelineCase)},${jsv(row.type)},${jsv(row.id)})'>Open ${esc(row.type)} review ↗</button>` : ''}</div></details>`).join('') : '<div class="empty-state">No timeline entries match these filters.</div>';
}

init();
