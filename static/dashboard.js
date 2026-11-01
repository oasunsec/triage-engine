const API = '';
let currentPage = 'dashboard';
let selectedFiles = [];
let invMode = 'upload';
let reviewEnums = {statuses:[], dispositions:[]};
let authState = { authenticated: false, bootstrapRequired: false, bootstrapTokenRequired: false, user: null, roles: [], csrfToken: '' };
let quickCheckToken = '';
let runtimeState = { mode: 'offline', label: 'Offline' };
let authMode = 'login';
let savedQueueViews = {};
let userPreferences = {
  landingPage: 'dashboard',
  dashboardFocus: 'mine',
  themeMode: 'system',
  dashboardWidgets: ['landing-board', 'review-focus', 'priority-watch', 'recent-jobs'],
  dashboardTemplates: {},
  activeDashboardTemplate: '',
  compactDensity: false,
  tableState: {},
  savedQueueViews: {},
};
let _casesCache = [];
let _queueCache = [];
let _jobsCache = [];
let liveHealthState = null;
let liveHealthLoaded = false;
let selectedJobIds = new Set();
const tableState = {
  cases: { page: 1, pageSize: 15, sort: 'date_desc' },
  queue: { page: 1, pageSize: 25, sort: 'updated_desc' },
  jobs: { page: 1, pageSize: 15, sort: 'updated_desc' },
};
const THEME_LABELS = { system: 'System', dark: 'Dark', light: 'Light' };
const STATE_CHANGING_METHODS = new Set(['POST', 'PATCH', 'DELETE']);
const CSRF_EXEMPT_PATHS = new Set(['/api/auth/login', '/api/auth/bootstrap']);
const systemThemeMedia = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

if (systemThemeMedia) {
  const handleSystemThemeChange = () => {
    if ((userPreferences.themeMode || 'system') === 'system') {
      applyThemePreference();
    }
  };
  if (typeof systemThemeMedia.addEventListener === 'function') {
    systemThemeMedia.addEventListener('change', handleSystemThemeChange);
  } else if (typeof systemThemeMedia.addListener === 'function') {
    systemThemeMedia.addListener(handleSystemThemeChange);
  }
}

// --- Navigation ---
function showPage(page) {
  if (!authState.authenticated && page !== 'quick-check') {
    openAuthOverlay();
    return;
  }
  document.querySelectorAll('main > [id^="page-"]').forEach(el => el.style.display = 'none');
  document.getElementById('page-' + page).style.display = '';
  document.querySelectorAll('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.page === page));
  currentPage = page;
  setNavigationState(page);
  const titles = {dashboard:'Overview', 'quick-check':'Quick Check', investigate:'New Investigation', jobs:'Running Jobs', queue:'Review Queue', 'case-detail':'Case Detail'};
  document.getElementById('page-title').textContent = titles[page] || page;
  if (page === 'dashboard') loadCases();
  if (page === 'jobs') loadJobs();
  if (page === 'queue') loadQueue();
  if (page === 'investigate' && invMode === 'live') loadLiveHealth();
}

// --- Init ---
async function init() {
  document.getElementById('auth-password')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') submitAuth();
  });
  setupWorkspaceAccessibility();
  applyThemePreference();
  renderSavedQueueViews();
  try {
    const h = await fetch(API + '/api/health').then(r=>r.json());
    document.getElementById('version-badge').textContent = 'v' + h.version;
    setRuntimeBadge(h.runtime);
  } catch (e) {
    document.getElementById('version-badge').textContent = 'offline';
    setRuntimeBadge({ mode: 'offline', label: 'Offline' });
  }
  await establishQuickCheckSession();
  await refreshSession(true);
  if (new URLSearchParams(window.location.search).get('quick_check') === '1' && quickCheckToken) {
    window.history.replaceState({}, document.title, window.location.pathname);
    document.getElementById('auth-overlay')?.classList.add('hidden');
    openQuickCheck();
    await startQuickCheck();
  }
  setInterval(() => {
    if (!authState.authenticated || document.hidden || document.querySelector('.modal-shell:not(.hidden),.auth-overlay:not(.hidden)')) return;
    if(currentPage==='dashboard') loadCases(true);
    if(currentPage==='jobs') loadJobs(true);
  }, 5000);
}

function setRuntimeBadge(runtime) {
  const badge = document.getElementById('runtime-badge');
  if (!badge) return;
  const mode = runtime && typeof runtime.mode === 'string' ? runtime.mode.toLowerCase() : 'offline';
  const normalizedMode = mode === 'docker' ? 'docker' : mode === 'local' ? 'local' : 'offline';
  const label = runtime && runtime.label
    ? runtime.label
    : normalizedMode === 'docker'
      ? 'Docker'
      : normalizedMode === 'local'
        ? 'Local Python'
        : 'Offline';
  runtimeState = { mode: normalizedMode, label };
  badge.className = `session-pill runtime-pill runtime-${normalizedMode}`;
  badge.textContent = `Runtime: ${label}`;
}

function renderTableMessage(tbodyId, colspan, message, kind = 'empty') {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  const isLoading = kind === 'loading';
  const cls = isLoading ? 'loading-state' : 'empty-state';
  const inner = isLoading
    ? `<span class="loading-inline"><span class="spinner" aria-hidden="true"></span><span>${esc(message)}</span></span>`
    : esc(message);
  tbody.innerHTML = `<tr><td colspan="${colspan}"><div class="${cls}">${inner}</div></td></tr>`;
}

function defaultDashboardWidgets() {
  return ['landing-board', 'review-focus', 'priority-watch', 'recent-jobs'];
}

function defaultDashboardTemplate() {
  return {
    landingPage: 'dashboard',
    dashboardFocus: 'mine',
    themeMode: 'system',
    dashboardWidgets: defaultDashboardWidgets(),
    compactDensity: false,
  };
}

function resolveThemeMode(mode) {
  if (mode === 'dark' || mode === 'light') return mode;
  return systemThemeMedia && systemThemeMedia.matches ? 'dark' : 'light';
}

function updateThemeButtonLabel() {
  const btn = document.getElementById('btn-cycle-theme');
  if (btn) btn.textContent = `Theme: ${THEME_LABELS[userPreferences.themeMode || 'system'] || 'System'}`;
}

function applyThemePreference() {
  const mode = userPreferences.themeMode || 'system';
  const resolved = resolveThemeMode(mode);
  document.body.classList.remove('theme-dark', 'theme-light');
  document.body.classList.add(`theme-${resolved}`);
  document.body.dataset.themeMode = mode;
  if (document.getElementById('pref-theme-mode')) document.getElementById('pref-theme-mode').value = mode;
  updateThemeButtonLabel();
}

function getDashboardWidgets() {
  const widgets = Array.isArray(userPreferences.dashboardWidgets) && userPreferences.dashboardWidgets.length
    ? userPreferences.dashboardWidgets
    : defaultDashboardWidgets();
  return new Set(widgets);
}

function getDashboardTemplates() {
  return userPreferences.dashboardTemplates || {};
}

function collectDisplayPreferencePatchFromInputs() {
  return {
    landingPage: document.getElementById('pref-landing-page').value,
    dashboardFocus: document.getElementById('pref-dashboard-focus').value,
    themeMode: document.getElementById('pref-theme-mode').value,
    dashboardWidgets: collectDashboardWidgetsFromInputs(),
    compactDensity: !!document.getElementById('pref-compact-density').checked,
  };
}

function collectDashboardWidgetsFromInputs() {
  const picks = [];
  if (document.getElementById('widget-landing-board')?.checked) picks.push('landing-board');
  if (document.getElementById('widget-review-focus')?.checked) picks.push('review-focus');
  if (document.getElementById('widget-priority-watch')?.checked) picks.push('priority-watch');
  if (document.getElementById('widget-recent-jobs')?.checked) picks.push('recent-jobs');
  return picks.length ? picks : defaultDashboardWidgets();
}

function renderDashboardTemplateOptions() {
  const select = document.getElementById('dashboard-template-select');
  if (!select) return;
  const templates = getDashboardTemplates();
  const names = Object.keys(templates).sort((a, b) => a.localeCompare(b));
  select.innerHTML = `<option value="">Choose a template</option>` + names.map(name => `<option value="${esc(name)}"${userPreferences.activeDashboardTemplate === name ? ' selected' : ''}>${esc(name)}</option>`).join('');
}

function compareCases(a, b, sort) {
  if (sort === 'date_asc') return safeDate(a.started_at) - safeDate(b.started_at);
  if (sort === 'priority_asc') return priorityRank(a.response_priority) - priorityRank(b.response_priority) || safeDate(b.started_at) - safeDate(a.started_at);
  if (sort === 'incidents_desc') return (b.incident_count||0) - (a.incident_count||0) || priorityRank(a.response_priority) - priorityRank(b.response_priority);
  if (sort === 'findings_desc') return (b.finding_count||0) - (a.finding_count||0) || (b.incident_count||0) - (a.incident_count||0);
  if (sort === 'name_asc') return String(a.name||'').localeCompare(String(b.name||''));
  return safeDate(b.started_at) - safeDate(a.started_at);
}

// --- Cases ---
function updateCasesView() {
  const tb = document.getElementById('cases-table');
  if (!tb) return;
  const search = (document.getElementById('cases-search')?.value || '').trim().toLowerCase();
  tableState.cases.sort = document.getElementById('cases-sort')?.value || tableState.cases.sort;
  persistTablePreferences();
  let cases = [..._casesCache];
  if (search) {
    cases = cases.filter(c => [c.name,c.input_source].some(value => String(value || '').toLowerCase().includes(search)));
  }
  const status = document.getElementById('cases-status')?.value || '';
  if (status) cases = cases.filter(c => c.status === status);
  cases.sort((a, b) => compareCases(a, b, tableState.cases.sort));
  if (!cases.length) {
    renderTableMessage('cases-table', 7, (search || status) ? 'No investigations match these filters. Clear the search or choose all statuses.' : 'No investigations yet. Upload EVTX files to get started.');
    renderPagination('cases', 0, 0);
    setMeta('cases-meta', search ? 'Filtered results: 0' : 'No investigations available yet');
    return;
  }
  const paged = paginate(cases, 'cases');
  tb.innerHTML = paged.map(c => `<tr onclick='openCase(${jsv(c.name)})'>
    <td style="font-weight:600"><a href="#" class="table-link" onclick='event.preventDefault();event.stopPropagation();openCase(${jsv(c.name)})'>${esc(c.name)}</a></td>
    <td><span class="badge badge-${esc(c.status||'unknown')}">${esc(c.status||'unknown')}</span></td>
    <td>${c.response_priority ? `<span class="badge badge-${esc(c.response_priority.toLowerCase())}">${esc(c.response_priority)}</span>` : '-'}${caseScopeHint(c.scope)}</td>
    <td>${c.signal_count||0}</td>
    <td>${c.finding_count||0}</td>
    <td>${c.incident_count||0}</td>
    <td style="color:var(--text2);font-size:13px">${c.started_at ? c.started_at.slice(0,16).replace('T',' ') : '-'}</td>
  </tr>`).join('');
  renderPagination('cases', cases.length, paged.length);
  setMeta('cases-meta', `${cases.length} case(s) in view`);
}

function stat(value, label, color) {
  return `<div class="stat"><div class="stat-value" style="color:var(${color})">${value}</div><div class="stat-label">${label}</div></div>`;
}

function confidencePercent(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return '0';
  return String(Math.round((number >= 0 && number <= 1 ? number * 100 : number) * 100) / 100);
}

function caseScopeHint(scope) {
  if (!scope || !(scope.host_count > 1 || scope.needs_scope_review)) return '';
  const parts = [];
  if (scope.host_count > 1) parts.push(`${scope.host_count} hosts`);
  if (scope.split_verdict) parts.push('mixed verdicts');
  else if (scope.needs_scope_review && scope.span_days > 7) parts.push(`spans ${Math.ceil(scope.span_days)} days`);
  return ` <small class="scope-hint" title="Open the case to review per-host verdicts">${esc(parts.join(' · '))}</small>`;
}

function jsv(value) {
  return JSON.stringify(String(value ?? '')).replace(/[&<>'\u2028\u2029]/g, char => '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0'));
}

function domId(prefix, value) {
  return `${prefix}-${String(value || '').replace(/[^a-zA-Z0-9_-]/g, '_')}`;
}

function reviewPanelPrefix(itemType, itemId) {
  return `rv-${itemType}-${String(itemId || '').replace(/[^a-zA-Z0-9]/g,'_')}`;
}

function notify(message, kind = 'info') {
  const stack = document.getElementById('toast-stack');
  if (!stack) return;
  const toast = document.createElement('div');
  toast.className = `toast toast-${kind}`;
  toast.textContent = message;
  stack.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('show'));
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 180);
  }, 3200);
}

function shortStamp(value) {
  const date = new Date(value || '');
  if (!value || Number.isNaN(date.getTime())) return 'unknown';
  return date.toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
}

function renderMiniList(items, emptyText) {
  if (!items || !items.length) {
    return `<div style="color:var(--text2);font-size:13px">${esc(emptyText || 'None')}</div>`;
  }
  return `<ul class="mini-list">${items.map(item => `<li>${esc(item)}</li>`).join('')}</ul>`;
}

function formatTiming(value) {
  const ms = Number(value || 0);
  if (!Number.isFinite(ms) || ms < 0) return '-';
  if (ms >= 60000) return `${(ms / 60000).toFixed(1)}m`;
  if (ms >= 1000) return `${(ms / 1000).toFixed(ms >= 10000 ? 0 : 1)}s`;
  return `${Math.round(ms)} ms`;
}

function summarizeDetectorTimings(detectorTimings) {
  const pairs = Object.entries(detectorTimings || {})
    .filter(([key, value]) => key.endsWith('_ms') && Number.isFinite(Number(value)))
    .map(([key, value]) => ({ name: key.replace(/_ms$/,'').replace(/_/g,' '), ms: Number(value) }))
    .sort((a, b) => b.ms - a.ms);
  if (!pairs.length) return ['No per-detector timing available.'];
  return pairs.slice(0, 6).map(item => `${item.name}: ${formatTiming(item.ms)}`);
}

function describeHistoryEvent(event) {
  if (!event) return '';
  if (event.field === 'note_added') {
    return `${esc(event.changed_by || 'analyst')} added note: "${esc(event.new_value || '')}"`;
  }
  return `${esc(event.changed_by || 'analyst')} changed <b>${esc(event.field)}</b> from "${esc(event.old_value || '(empty)')}" to "${esc(event.new_value)}"`;
}

function summarizeReviewState(findings, incidents) {
  const summary = { open: 0, inReview: 0, escalated: 0, closed: 0, suppressed: 0, withOwner: 0 };
  [...(findings || []), ...(incidents || [])].forEach(item => {
    const status = (item.review?.status || 'Open').toLowerCase();
    if (status === 'open') summary.open += 1;
    else if (status === 'in review') summary.inReview += 1;
    else if (status === 'escalated') summary.escalated += 1;
    else if (status === 'closed') summary.closed += 1;
    else if (status === 'suppressed') summary.suppressed += 1;
    if (item.review?.owner) summary.withOwner += 1;
  });
  return summary;
}

function priorityRank(priority) {
  const p = String(priority || 'P9').toUpperCase();
  if (p === 'P1') return 1;
  if (p === 'P2') return 2;
  if (p === 'P3') return 3;
  if (p === 'P4') return 4;
  return 9;
}

function safeDate(value) {
  const ts = value ? Date.parse(value) : NaN;
  return Number.isNaN(ts) ? 0 : ts;
}

function canReviewMutate() {
  return !!authState.user && ['admin', 'analyst'].includes(authState.user.role);
}

function isAdmin() {
  return !!authState.user && authState.user.role === 'admin';
}

function getReviewerName() {
  return authState.user?.username || '';
}

function updateAuthUI() {
  const display = document.getElementById('reviewer-display');
  const roleBadge = document.getElementById('session-role-badge');
  const loginBtn = document.getElementById('btn-auth-entry');
  const logoutBtn = document.getElementById('btn-auth-logout');
  const sidebarName = document.getElementById('sidebar-user-name');
  const sidebarRole = document.getElementById('sidebar-user-role');
  const sidebarLogoutBtn = document.getElementById('btn-sidebar-logout');
  const manageBtn = document.getElementById('btn-manage-users');
  const prefsBtn = document.getElementById('btn-open-preferences');
  const detailDeleteBtn = document.getElementById('detail-delete-btn');
  const investigateNav = document.querySelector('.nav-item[data-page="investigate"]');

  if (display) {
    display.textContent = authState.authenticated ? authState.user.username : (authState.bootstrapRequired ? 'Bootstrap required' : 'Sign in required');
  }
  if (sidebarName) {
    sidebarName.textContent = authState.authenticated ? authState.user.username : (authState.bootstrapRequired ? 'Bootstrap required' : 'Sign in required');
  }
  if (roleBadge) {
    const role = authState.user?.role || 'guest';
    roleBadge.textContent = role;
    roleBadge.className = `session-pill ${authState.user ? `role-${role}` : 'role-viewer'}`;
  }
  if (sidebarRole) sidebarRole.textContent = authState.user?.role || 'guest';
  if (loginBtn) {
    loginBtn.textContent = authState.bootstrapRequired ? 'Bootstrap' : 'Sign In';
    loginBtn.classList.toggle('hidden', authState.authenticated);
  }
  if (logoutBtn) logoutBtn.classList.toggle('hidden', !authState.authenticated);
  if (sidebarLogoutBtn) sidebarLogoutBtn.classList.toggle('hidden', !authState.authenticated);
  if (manageBtn) manageBtn.classList.toggle('hidden', !isAdmin());
  if (prefsBtn) prefsBtn.classList.toggle('hidden', !authState.authenticated);
  if (detailDeleteBtn) detailDeleteBtn.classList.toggle('hidden', !isAdmin());
  if (investigateNav) {
    investigateNav.classList.toggle('disabled', !authState.authenticated || !canReviewMutate());
    investigateNav.disabled = !authState.authenticated || !canReviewMutate();
  }
  document.querySelectorAll('[data-mutate]').forEach(el => el.hidden = !canReviewMutate());
}

function setAuthMessage(message, kind = 'info') {
  const el = document.getElementById('auth-message');
  if (!el) return;
  el.textContent = message || '';
  el.style.color = kind === 'error' ? 'var(--red)' : kind === 'success' ? 'var(--green)' : 'var(--text2)';
}

function openAuthOverlay(forceMode) {
  authMode = forceMode || (authState.bootstrapRequired ? 'bootstrap' : 'login');
  const overlay = document.getElementById('auth-overlay');
  const title = document.getElementById('auth-title');
  const copy = document.getElementById('auth-copy');
  const submit = document.getElementById('auth-submit');
  const cancel = document.getElementById('auth-cancel');
  if (!overlay || !title || !copy || !submit || !cancel) return;
  title.textContent = authMode === 'bootstrap' ? 'Create First Admin' : 'Sign In';
  copy.textContent = authMode === 'bootstrap'
    ? 'Set up the first admin account for this workstation. After that, the API and dashboard use normal login.'
    : 'Sign in to review cases, launch investigations, and keep analyst actions attributable.';
  submit.textContent = authMode === 'bootstrap' ? 'Create Admin' : 'Sign In';
  document.getElementById('auth-bootstrap-token-group')?.classList.toggle('hidden', !(authMode === 'bootstrap' && authState.bootstrapTokenRequired));
  cancel.classList.toggle('hidden', !authState.authenticated);
  overlay.classList.remove('hidden');
  setAuthMessage('');
  document.getElementById('auth-username')?.focus();
}

function closeAuthOverlay() {
  if (!authState.authenticated) return;
  document.getElementById('auth-overlay')?.classList.add('hidden');
  setAuthMessage('');
}

function openUserAdmin() {
  if (!isAdmin()) {
    notify('Only admins can manage user access.', 'error');
    return;
  }
  document.getElementById('user-admin-modal')?.classList.remove('hidden');
  loadUsers();
  loadIngestTokens();
  loadAuditEvents();
}

function closeUserAdmin() {
  document.getElementById('user-admin-modal')?.classList.add('hidden');
  const msg = document.getElementById('user-admin-message');
  if (msg) msg.textContent = '';
}

function openPreferencesModal() {
  if (!authState.authenticated) return openAuthOverlay();
  document.getElementById('pref-landing-page').value = userPreferences.landingPage || 'dashboard';
  document.getElementById('pref-dashboard-focus').value = userPreferences.dashboardFocus || 'mine';
  document.getElementById('pref-theme-mode').value = userPreferences.themeMode || 'system';
  document.getElementById('pref-compact-density').checked = !!userPreferences.compactDensity;
  const widgets = getDashboardWidgets();
  if (document.getElementById('widget-landing-board')) document.getElementById('widget-landing-board').checked = widgets.has('landing-board');
  if (document.getElementById('widget-review-focus')) document.getElementById('widget-review-focus').checked = widgets.has('review-focus');
  if (document.getElementById('widget-priority-watch')) document.getElementById('widget-priority-watch').checked = widgets.has('priority-watch');
  if (document.getElementById('widget-recent-jobs')) document.getElementById('widget-recent-jobs').checked = widgets.has('recent-jobs');
  document.getElementById('preferences-message').textContent = '';
  document.getElementById('password-message').textContent = '';
  ['pref-current-password','pref-new-password','pref-confirm-password'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  const templateMsg = document.getElementById('dashboard-template-message');
  if (templateMsg) templateMsg.textContent = '';
  const templateName = document.getElementById('dashboard-template-name');
  if (templateName) templateName.value = '';
  renderDashboardTemplateOptions();
  document.getElementById('preferences-modal')?.classList.remove('hidden');
}

function closePreferencesModal() {
  document.getElementById('preferences-modal')?.classList.add('hidden');
}

function authHeaders(headers = {}) {
  const merged = Object.assign({'Content-Type': 'application/json'}, headers);
  if (authState.csrfToken && !merged['X-CSRF-Token']) {
    merged['X-CSRF-Token'] = authState.csrfToken;
  }
  return merged;
}

async function apiFetch(path, options = {}) {
  const requestOptions = Object.assign({}, options);
  const suppressAuthRedirect = !!requestOptions.suppressAuthRedirect;
  delete requestOptions.suppressAuthRedirect;
  const method = String(requestOptions.method || 'GET').toUpperCase();
  const headers = Object.assign({}, requestOptions.headers || {});
  if (
    path.startsWith('/api/') &&
    STATE_CHANGING_METHODS.has(method) &&
    !CSRF_EXEMPT_PATHS.has(path) &&
    authState.csrfToken &&
    !headers['X-CSRF-Token']
  ) {
    headers['X-CSRF-Token'] = authState.csrfToken;
  }
  requestOptions.headers = headers;
  const response = await fetch(API + path, Object.assign({ credentials: 'same-origin' }, requestOptions));
  if (response.status === 401 && path !== '/api/auth/me' && !suppressAuthRedirect) {
    clearWorkspaceSession();
    authState.authenticated = false;
    authState.user = null;
    authState.csrfToken = '';
    updateAuthUI();
    openAuthOverlay();
  }
  return response;
}

async function apiJSON(path, options = {}) {
  const resp = await apiFetch(path, options);
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const detail = Array.isArray(data.detail)
      ? data.detail.map(item => `${(item.loc || []).filter(part => part !== 'body').join('.') || 'request'}: ${item.msg}`).join('; ')
      : data.detail;
    const err = new Error(detail || `Request failed (${resp.status})`);
    err.status = resp.status;
    err.payload = data;
    throw err;
  }
  return data;
}

async function establishQuickCheckSession() {
  try {
    const response = await fetch(API + '/api/quick/session', { credentials: 'same-origin' });
    const payload = await response.json().catch(() => ({}));
    quickCheckToken = response.ok ? String(payload.token || '') : '';
  } catch (_ignored) {
    quickCheckToken = '';
  }
}

async function quickJSON(path, options = {}) {
  if (!quickCheckToken) throw new Error('Quick Check is unavailable. Refresh the page and try again.');
  const headers = Object.assign({}, options.headers || {}, { 'X-Triage-Quick-Token': quickCheckToken });
  if (authState.csrfToken) headers['X-CSRF-Token'] = authState.csrfToken;
  const response = await fetch(API + path, Object.assign({ credentials: 'same-origin' }, options, { headers }));
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || `Quick Check request failed (${response.status})`);
  return payload;
}

function continueQuickCheck() {
  if (!quickCheckToken) {
    setAuthMessage('Quick Check is unavailable. Refresh the page and try again.', 'error');
    return;
  }
  document.getElementById('auth-overlay')?.classList.add('hidden');
  openQuickCheck();
}

async function refreshSession(initial = false) {
  try {
    const me = await apiJSON('/api/auth/me');
    authState = {
      authenticated: !!me.authenticated,
      bootstrapRequired: !!me.bootstrap_required,
      bootstrapTokenRequired: !!me.bootstrap_token_required,
      user: me.user || null,
      roles: me.roles || [],
      csrfToken: me.csrf_token || '',
    };
    updateAuthUI();
    if (authState.authenticated) {
      document.getElementById('auth-overlay')?.classList.add('hidden');
      liveHealthLoaded = false;
      reviewEnums = await apiJSON('/api/review/enums').catch(() => reviewEnums);
      const pref = await apiJSON('/api/auth/preferences').catch(() => ({ preferences: {} }));
      hydratePreferences(pref.preferences || {});
      applyUserPreferences();
      const landing = initial ? (userPreferences.landingPage || 'dashboard') : currentPage;
      if (landing === 'queue') showPage('queue');
      else if (landing === 'jobs') showPage('jobs');
      else if (landing === 'investigate') showPage('investigate');
      else if (currentPage === 'dashboard' || initial) loadCases();
      else if (currentPage === 'jobs') loadJobs();
      else if (currentPage === 'queue') loadQueue();
      return;
    }
    if (initial || !authState.authenticated) {
      openAuthOverlay(authState.bootstrapRequired ? 'bootstrap' : 'login');
    }
  } catch (e) {
    updateAuthUI();
    if (initial) {
      setAuthMessage('Unable to reach the API. Verify the server is running.', 'error');
      openAuthOverlay('login');
    }
  }
}

async function submitAuth() {
  const username = document.getElementById('auth-username')?.value?.trim() || '';
  const password = document.getElementById('auth-password')?.value || '';
  if (!username || !password) {
    setAuthMessage('Username and password are required.', 'error');
    return;
  }
  const submit = document.getElementById('auth-submit');
  if (submit) submit.disabled = true;
  setAuthMessage(authMode === 'bootstrap' ? 'Creating admin account...' : 'Signing in...');
  try {
    const authResult = await apiJSON(authMode === 'bootstrap' ? '/api/auth/bootstrap' : '/api/auth/login', {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify(authMode === 'bootstrap'
        ? { username, password, bootstrap_token: document.getElementById('auth-bootstrap-token')?.value || '' }
        : { username, password }),
    });
    authState.csrfToken = authResult.csrf_token || '';
    const tokenInput = document.getElementById('auth-bootstrap-token');
    if (tokenInput) tokenInput.value = '';
    document.getElementById('auth-password').value = '';
    notify(authMode === 'bootstrap' ? 'Admin account created.' : `Signed in as ${username}.`, 'success');
    await refreshSession();
  } catch (e) {
    setAuthMessage(e.message || 'Authentication failed.', 'error');
  } finally {
    if (submit) submit.disabled = false;
  }
}

async function logout() {
  try {
    await apiJSON('/api/auth/logout', { method: 'POST' });
  } catch (e) {}
  clearWorkspaceSession();
  authState.authenticated = false;
  authState.user = null;
  authState.csrfToken = '';
  liveHealthState = null;
  liveHealthLoaded = false;
  userPreferences = {
    landingPage: 'dashboard',
    dashboardFocus: 'mine',
    themeMode: 'system',
    dashboardWidgets: defaultDashboardWidgets(),
    dashboardTemplates: {},
    activeDashboardTemplate: '',
    compactDensity: false,
    tableState: {},
    savedQueueViews: {},
  };
  savedQueueViews = {};
  document.body.classList.remove('compact-density');
  applyThemePreference();
  updateAuthUI();
  openAuthOverlay('login');
  notify('Signed out.', 'info');
}

function hydratePreferences(pref = {}) {
  userPreferences = Object.assign({
    landingPage: 'dashboard',
    dashboardFocus: 'mine',
    themeMode: 'system',
    dashboardWidgets: defaultDashboardWidgets(),
    dashboardTemplates: {},
    activeDashboardTemplate: '',
    compactDensity: false,
    tableState: {},
    savedQueueViews: {},
  }, pref || {});
  savedQueueViews = userPreferences.savedQueueViews || {};
  Object.assign(tableState.cases, userPreferences.tableState?.cases || {});
  Object.assign(tableState.queue, userPreferences.tableState?.queue || {});
  Object.assign(tableState.jobs, userPreferences.tableState?.jobs || {});
  renderSavedQueueViews();
  renderDashboardTemplateOptions();
}

function applyUserPreferences() {
  document.body.classList.toggle('compact-density', !!userPreferences.compactDensity);
  if (document.getElementById('pref-landing-page')) document.getElementById('pref-landing-page').value = userPreferences.landingPage || 'dashboard';
  if (document.getElementById('pref-dashboard-focus')) document.getElementById('pref-dashboard-focus').value = userPreferences.dashboardFocus || 'mine';
  if (document.getElementById('pref-theme-mode')) document.getElementById('pref-theme-mode').value = userPreferences.themeMode || 'system';
  if (document.getElementById('pref-compact-density')) document.getElementById('pref-compact-density').checked = !!userPreferences.compactDensity;
  const widgets = getDashboardWidgets();
  if (document.getElementById('widget-landing-board')) document.getElementById('widget-landing-board').checked = widgets.has('landing-board');
  if (document.getElementById('widget-review-focus')) document.getElementById('widget-review-focus').checked = widgets.has('review-focus');
  if (document.getElementById('widget-priority-watch')) document.getElementById('widget-priority-watch').checked = widgets.has('priority-watch');
  if (document.getElementById('widget-recent-jobs')) document.getElementById('widget-recent-jobs').checked = widgets.has('recent-jobs');
  applyThemePreference();
  if (document.getElementById('cases-page-size')) document.getElementById('cases-page-size').value = String(tableState.cases.pageSize || 15);
  if (document.getElementById('cases-sort')) document.getElementById('cases-sort').value = tableState.cases.sort || 'date_desc';
  if (document.getElementById('queue-page-size')) {
    const queuePageSize = [25, 50, 100].includes(Number(tableState.queue.pageSize)) ? Number(tableState.queue.pageSize) : 25;
    tableState.queue.pageSize = queuePageSize;
    document.getElementById('queue-page-size').value = String(queuePageSize);
  }
  if (document.getElementById('queue-sort')) document.getElementById('queue-sort').value = tableState.queue.sort || 'updated_desc';
  if (document.getElementById('jobs-page-size')) document.getElementById('jobs-page-size').value = String(tableState.jobs.pageSize || 15);
  if (document.getElementById('jobs-sort')) document.getElementById('jobs-sort').value = tableState.jobs.sort || 'updated_desc';
  renderDashboardTemplateOptions();
}

function formatLiveHealthState(status) {
  if (status === 'ready') return { label: 'Ready', cls: 'health-state-ok' };
  if (status === 'access_denied') return { label: 'Privilege Needed', cls: 'health-state-warn' };
  if (status === 'not_found') return { label: 'Not Found', cls: 'health-state-bad' };
  if (status === 'pywin32_missing') return { label: 'pywin32 Missing', cls: 'health-state-bad' };
  if (status === 'unsupported') return { label: 'Unsupported', cls: 'health-state-bad' };
  return { label: 'Check Needed', cls: 'health-state-warn' };
}

function renderLiveHealth() {
  const hint = document.getElementById('live-health-hint');
  const body = document.getElementById('live-health-body');
  if (!hint || !body) return;
  if (!liveHealthState) {
    hint.textContent = 'Live health unavailable.';
    body.innerHTML = '';
    return;
  }
  const readiness = liveHealthState.readiness || 'degraded';
  const readinessLabel = formatLiveHealthState(readiness === 'ready' ? 'ready' : readiness);
  const guidance = Array.isArray(liveHealthState.guidance) ? liveHealthState.guidance : [];
  const channels = Array.isArray(liveHealthState.channels) ? liveHealthState.channels : [];
  hint.innerHTML = `Server readiness: <span class="${readinessLabel.cls}">${esc(readinessLabel.label)}</span>${liveHealthState.is_elevated ? ' · elevated server session' : ' · standard privileges'}`;
  body.innerHTML = `
    <div class="live-health-grid">
      <div class="mini-stat">
        <div class="mini-stat-value ${liveHealthState.is_elevated ? 'health-state-ok' : 'health-state-warn'}">${liveHealthState.is_elevated ? 'Admin' : 'Standard'}</div>
        <div class="mini-stat-label">Server Token</div>
      </div>
      <div class="mini-stat">
        <div class="mini-stat-value ${liveHealthState.pywin32_available ? 'health-state-ok' : 'health-state-bad'}">${liveHealthState.pywin32_available ? 'Ready' : 'Missing'}</div>
        <div class="mini-stat-label">pywin32 Runtime</div>
      </div>
      <div class="mini-stat">
        <div class="mini-stat-value ${readinessLabel.cls}">${liveHealthState.readable_channel_count || 0}/${(liveHealthState.recommended_channels || []).length}</div>
        <div class="mini-stat-label">Readable Channels</div>
      </div>
    </div>
    <div class="health-channel-list">
      ${channels.map(item => {
        const state = formatLiveHealthState(item.status);
        return `<div class="health-channel-row">
          <div>
            <div style="font-weight:600">${esc(item.channel || '')}</div>
            <div class="${state.cls}" style="font-size:12px">${esc(state.label)}</div>
          </div>
          <div class="health-channel-meta">${esc(item.message || (item.readable ? 'Channel query succeeded' : 'No detail available'))}</div>
        </div>`;
      }).join('')}
    </div>
    ${guidance.length ? `<ul class="health-guidance">${guidance.map(line => `<li>${esc(line)}</li>`).join('')}</ul>` : ''}
  `;
}

async function loadLiveHealth(force = false) {
  const body = document.getElementById('live-health-body');
  const hint = document.getElementById('live-health-hint');
  if (!body || !hint || !authState.authenticated) return;
  if (liveHealthLoaded && !force) {
    renderLiveHealth();
    return;
  }
  hint.textContent = 'Checking server live-scan readiness...';
  body.innerHTML = '<div class="subtle-hint">Probing recommended channels and privilege state...</div>';
  try {
    liveHealthState = await apiJSON('/api/live/health');
    liveHealthLoaded = true;
    renderLiveHealth();
  } catch (e) {
    liveHealthState = null;
    hint.textContent = 'Could not load live scan health.';
    body.innerHTML = `<div class="subtle-hint" style="color:var(--red)">${esc(e.message || 'Failed to inspect live-scan health.')}</div>`;
  }
}

let preferenceSaveChain = Promise.resolve();
function savePreferencesPatch(patch, quiet = true) {
  const session = authState.csrfToken;
  const snapshot = JSON.parse(JSON.stringify(patch));
  preferenceSaveChain = preferenceSaveChain.catch(() => {}).then(() => {
    if (!authState.authenticated || session !== authState.csrfToken) return;
    return sendPreferencesPatch(snapshot, quiet, session);
  });
  return preferenceSaveChain;
}

async function sendPreferencesPatch(patch, quiet, session) {
  if (!authState.authenticated) return;
  userPreferences = Object.assign({}, userPreferences, patch);
  if (patch.savedQueueViews) savedQueueViews = patch.savedQueueViews;
  try {
    const updated = await apiJSON('/api/auth/preferences', {
      method: 'PATCH',
      headers: authHeaders(),
      body: JSON.stringify({ preferences: patch }),
    });
    if (!authState.authenticated || session !== authState.csrfToken) return;
    userPreferences = Object.assign({
      landingPage: 'dashboard',
      dashboardFocus: 'mine',
      themeMode: 'system',
      dashboardWidgets: defaultDashboardWidgets(),
      dashboardTemplates: {},
      activeDashboardTemplate: '',
      compactDensity: false,
      tableState: {},
      savedQueueViews: {},
    }, updated.preferences || {});
    savedQueueViews = userPreferences.savedQueueViews || {};
    renderDashboardTemplateOptions();
    if (!quiet) notify('Preferences saved.', 'success');
  } catch (e) {
    if (!quiet) notify(e.message || 'Failed to save preferences.', 'error');
  }
}

async function saveDisplayPreferences() {
  const { landingPage, dashboardFocus, themeMode, dashboardWidgets, compactDensity } = collectDisplayPreferencePatchFromInputs();
  const message = document.getElementById('preferences-message');
  if (message) {
    message.textContent = 'Saving preferences...';
    message.style.color = 'var(--text2)';
  }
  await savePreferencesPatch({ landingPage, dashboardFocus, themeMode, dashboardWidgets, compactDensity, activeDashboardTemplate: '' }, false);
  applyUserPreferences();
  if (currentPage === 'dashboard') renderDashboardFocus(_casesCache);
  if (message) {
    message.textContent = 'Preferences saved.';
    message.style.color = 'var(--green)';
  }
}

async function cycleThemePreference() {
  const order = ['system', 'dark', 'light'];
  const current = userPreferences.themeMode || 'system';
  const next = order[(order.indexOf(current) + 1) % order.length];
  userPreferences = Object.assign({}, userPreferences, { themeMode: next, activeDashboardTemplate: '' });
  applyThemePreference();
  if (authState.authenticated) {
    await savePreferencesPatch({ themeMode: next, activeDashboardTemplate: '' }, false);
  }
  notify(`Theme set to ${THEME_LABELS[next]}.`, 'success');
}

async function saveDashboardTemplate() {
  const message = document.getElementById('dashboard-template-message');
  const name = (document.getElementById('dashboard-template-name')?.value || '').trim() || (document.getElementById('dashboard-template-select')?.value || '').trim();
  if (!name) {
    if (message) {
      message.textContent = 'Name the template first.';
      message.style.color = 'var(--red)';
    }
    return;
  }
  const templates = Object.assign({}, getDashboardTemplates());
  templates[name] = collectDisplayPreferencePatchFromInputs();
  if (message) {
    message.textContent = 'Saving template...';
    message.style.color = 'var(--text2)';
  }
  await savePreferencesPatch({ dashboardTemplates: templates, activeDashboardTemplate: name }, false);
  renderDashboardTemplateOptions();
  const select = document.getElementById('dashboard-template-select');
  if (select) select.value = name;
  if (message) {
    message.textContent = `Saved template "${name}".`;
    message.style.color = 'var(--green)';
  }
  if (currentPage === 'dashboard') renderDashboardFocus(_casesCache);
}

async function applyDashboardTemplate() {
  const select = document.getElementById('dashboard-template-select');
  const message = document.getElementById('dashboard-template-message');
  const name = (select?.value || '').trim();
  const template = getDashboardTemplates()[name];
  if (!name || !template) {
    if (message) {
      message.textContent = 'Choose a template to apply.';
      message.style.color = 'var(--red)';
    }
    return;
  }
  const merged = Object.assign(defaultDashboardTemplate(), template || {});
  if (document.getElementById('pref-landing-page')) document.getElementById('pref-landing-page').value = merged.landingPage || 'dashboard';
  if (document.getElementById('pref-dashboard-focus')) document.getElementById('pref-dashboard-focus').value = merged.dashboardFocus || 'mine';
  if (document.getElementById('pref-theme-mode')) document.getElementById('pref-theme-mode').value = merged.themeMode || 'system';
  if (document.getElementById('pref-compact-density')) document.getElementById('pref-compact-density').checked = !!merged.compactDensity;
  const widgets = new Set(Array.isArray(merged.dashboardWidgets) && merged.dashboardWidgets.length ? merged.dashboardWidgets : defaultDashboardWidgets());
  if (document.getElementById('widget-landing-board')) document.getElementById('widget-landing-board').checked = widgets.has('landing-board');
  if (document.getElementById('widget-review-focus')) document.getElementById('widget-review-focus').checked = widgets.has('review-focus');
  if (document.getElementById('widget-priority-watch')) document.getElementById('widget-priority-watch').checked = widgets.has('priority-watch');
  if (document.getElementById('widget-recent-jobs')) document.getElementById('widget-recent-jobs').checked = widgets.has('recent-jobs');
  await savePreferencesPatch(Object.assign({}, merged, { activeDashboardTemplate: name }), false);
  applyUserPreferences();
  if (currentPage === 'dashboard') renderDashboardFocus(_casesCache);
  if (message) {
    message.textContent = `Applied template "${name}".`;
    message.style.color = 'var(--green)';
  }
}

async function deleteDashboardTemplate() {
  const select = document.getElementById('dashboard-template-select');
  const message = document.getElementById('dashboard-template-message');
  const name = (select?.value || '').trim();
  if (!name || !getDashboardTemplates()[name]) {
    if (message) {
      message.textContent = 'Choose a template to delete.';
      message.style.color = 'var(--red)';
    }
    return;
  }
  const templates = Object.assign({}, getDashboardTemplates());
  delete templates[name];
  const patch = { dashboardTemplates: templates };
  if ((userPreferences.activeDashboardTemplate || '') === name) patch.activeDashboardTemplate = '';
  await savePreferencesPatch(patch, false);
  renderDashboardTemplateOptions();
  if (select) select.value = '';
  if (message) {
    message.textContent = `Deleted template "${name}".`;
    message.style.color = 'var(--green)';
  }
  if (currentPage === 'dashboard') renderDashboardFocus(_casesCache);
}

async function changeOwnPassword() {
  const currentPassword = document.getElementById('pref-current-password')?.value || '';
  const newPassword = document.getElementById('pref-new-password')?.value || '';
  const confirmPassword = document.getElementById('pref-confirm-password')?.value || '';
  const message = document.getElementById('password-message');
  if (message) {
    message.textContent = '';
    message.style.color = 'var(--text2)';
  }
  if (!currentPassword || !newPassword || !confirmPassword) {
    if (message) {
      message.textContent = 'Fill in all password fields first.';
      message.style.color = 'var(--red)';
    }
    return;
  }
  if (newPassword !== confirmPassword) {
    if (message) {
      message.textContent = 'New password and confirmation do not match.';
      message.style.color = 'var(--red)';
    }
    return;
  }
  if (message) {
    message.textContent = 'Updating password...';
    message.style.color = 'var(--text2)';
  }
  try {
    await apiJSON('/api/auth/change-password', {
      method: 'POST',
      suppressAuthRedirect: true,
      headers: authHeaders(),
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    });
    ['pref-current-password','pref-new-password','pref-confirm-password'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });
    if (message) {
      message.textContent = 'Password updated. Your session has been refreshed.';
      message.style.color = 'var(--green)';
    }
    notify('Password updated successfully.', 'success');
    await refreshSession();
  } catch (e) {
    if (message) {
      message.textContent = e.message || 'Failed to update password.';
      message.style.color = 'var(--red)';
    }
    notify(e.message || 'Failed to update password.', 'error');
  }
}

function getAuditFilterState() {
  return {
    action: document.getElementById('audit-action')?.value || '',
    actor: (document.getElementById('audit-actor')?.value || '').trim(),
    target: (document.getElementById('audit-target')?.value || '').trim(),
    search: (document.getElementById('audit-search')?.value || '').trim(),
  };
}

function clearAuditFilters() {
  if (document.getElementById('audit-action')) document.getElementById('audit-action').value = '';
  if (document.getElementById('audit-actor')) document.getElementById('audit-actor').value = '';
  if (document.getElementById('audit-target')) document.getElementById('audit-target').value = '';
  if (document.getElementById('audit-search')) document.getElementById('audit-search').value = '';
  loadAuditEvents();
}

async function loadAuditEvents() {
  const list = document.getElementById('audit-list');
  const meta = document.getElementById('audit-meta');
  if (!list) return;
  list.innerHTML = '<div class="loading-state">Loading audit events...</div>';
  if (meta) meta.textContent = 'Loading audit activity...';
  try {
    const filters = getAuditFilterState();
    const params = new URLSearchParams({ limit: '60' });
    if (filters.action) params.set('action', filters.action);
    if (filters.actor) params.set('actor_username', filters.actor);
    if (filters.target) params.set('target_username', filters.target);
    if (filters.search) params.set('search', filters.search);
    const data = await apiJSON('/api/auth/audit?' + params.toString());
    const events = Array.isArray(data.events) ? data.events : [];
    if (meta) {
      const filterParts = [
        filters.action ? `action=${filters.action}` : '',
        filters.actor ? `actor=${filters.actor}` : '',
        filters.target ? `target=${filters.target}` : '',
        filters.search ? `search=${filters.search}` : '',
      ].filter(Boolean);
      meta.textContent = filterParts.length
        ? `${events.length} event(s) · filtered by ${filterParts.join(' · ')}`
        : `${events.length} recent event(s)`;
    }
    list.innerHTML = events.length ? events.map(renderAuditEvent).join('') : '<div class="empty-state">No admin audit events yet.</div>';
  } catch (e) {
    if (meta) meta.textContent = 'Audit activity unavailable';
    list.innerHTML = '<div class="empty-state">Failed to load audit events.</div>';
  }
}

async function downloadAuditExport(format) {
  const filters = getAuditFilterState();
  const params = new URLSearchParams({ limit: '500', format: format || 'csv' });
  if (filters.action) params.set('action', filters.action);
  if (filters.actor) params.set('actor_username', filters.actor);
  if (filters.target) params.set('target_username', filters.target);
  if (filters.search) params.set('search', filters.search);
  try {
    const response = await apiFetch('/api/auth/audit/export?' + params.toString(), {
      suppressAuthRedirect: true,
    });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.detail || 'Failed to export audit activity.');
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    const suffix = (format || 'csv').toLowerCase() === 'json' ? 'json' : 'csv';
    link.href = url;
    link.download = `triage-auth-audit.${suffix}`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    notify(`Downloaded audit export (${suffix.toUpperCase()}).`, 'success');
  } catch (e) {
    notify(e.message || 'Failed to export audit activity.', 'error');
  }
}

async function downloadReviewHistoryExport(format, caseName = '', itemType = '', itemId = '') {
  const params = new URLSearchParams({ limit: '1000', format: format || 'csv' });
  if (caseName) params.set('case_name', caseName);
  if (itemType) params.set('item_type', itemType);
  if (itemId) params.set('item_id', itemId);
  try {
    const response = await apiFetch('/api/review/history/export?' + params.toString(), {
      suppressAuthRedirect: true,
    });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.detail || 'Failed to export review history.');
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    const suffix = (format || 'csv').toLowerCase() === 'json' ? 'json' : 'csv';
    link.href = url;
    link.download = caseName && itemId
      ? `triage-review-history-${caseName}-${itemType}-${itemId}.${suffix}`
      : `triage-review-history.${suffix}`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    notify(`Downloaded review history (${suffix.toUpperCase()}).`, 'success');
  } catch (e) {
    notify(e.message || 'Failed to export review history.', 'error');
  }
}

function renderAuditEvent(event) {
  const details = event.details || {};
  const detailText = Object.keys(details).length ? Object.entries(details).map(([k, v]) => `${k}: ${typeof v === 'boolean' ? (v ? 'yes' : 'no') : v}`).join(' · ') : 'No extra details';
  return `<div class="audit-item">
    <div class="detail-title-row" style="margin-bottom:6px">
      <span class="audit-chip">${esc(event.action || 'event')}</span>
      <div class="audit-title" style="margin-bottom:0">${esc(event.target_username || 'system')}</div>
    </div>
    <div class="audit-meta">Actor: ${esc(event.actor_username || 'system')} · ${(event.created_at || '').slice(0,16).replace('T',' ')}</div>
    <div class="user-subtle" style="margin-top:6px">${esc(detailText)}</div>
  </div>`;
}

async function loadUsers() {
  const list = document.getElementById('users-list');
  if (!list) return;
  list.innerHTML = '<div class="loading-state">Loading users...</div>';
  try {
    const data = await apiJSON('/api/auth/users');
    const users = Array.isArray(data.users) ? data.users : [];
    list.innerHTML = users.length ? users.map(user => `
      <div class="user-row">
        <div class="user-meta">
          <div class="user-name">${esc(user.username)}</div>
          <div class="user-subtle">Role: ${esc(user.role)} · Status: ${user.active ? 'active' : 'disabled'} · Last login: ${user.last_login_at ? esc(user.last_login_at.slice(0,16).replace('T',' ')) : 'never'}</div>
        </div>
        <div class="user-actions">
          <div class="session-pill role-${esc(user.role)}">${esc(user.role)}</div>
          <select class="inline-select" id="role-${esc(user.username)}">
            ${['admin','analyst','viewer'].map(role => `<option value="${role}"${user.role===role?' selected':''}>${role}</option>`).join('')}
          </select>
          <button class="btn btn-sm btn-ghost" onclick='saveUserRole(${jsv(user.username)})' ${authState.user?.username === user.username ? 'disabled' : ''}>Save Role</button>
          <button class="btn btn-sm btn-ghost" onclick='toggleUserActive(${jsv(user.username)}, ${user.active ? 'false' : 'true'})' ${authState.user?.username === user.username ? 'disabled' : ''}>${user.active ? 'Disable' : 'Enable'}</button>
          <button class="btn btn-sm btn-ghost" onclick='resetUserPassword(${jsv(user.username)})'>Reset Password</button>
        </div>
      </div>
    `).join('') : '<div class="empty-state">No users created yet.</div>';
  } catch (e) {
    list.innerHTML = '<div class="empty-state">Failed to load users.</div>';
  }
}

async function loadIngestTokens() {
  const list = document.getElementById('ingest-token-list');
  if (!list) return;
  try {
    const tokens = (await apiJSON('/api/ingest-tokens')).tokens || [];
    list.innerHTML = tokens.length ? tokens.map(token => `
      <div class="user-row">
        <div class="user-meta">
          <div class="user-name">${esc(token.name)}</div>
          <div class="user-subtle">${token.revoked_at ? `Revoked ${esc(token.revoked_at.slice(0,16).replace('T',' '))}` : 'Active'} · Created by ${esc(token.created_by)} ${esc((token.created_at || '').slice(0,10))} · Used ${Number(token.use_count || 0)} time(s)${token.last_used_at ? `, last ${esc(token.last_used_at.slice(0,16).replace('T',' '))}` : ''}</div>
        </div>
        <div class="user-actions">${token.revoked_at ? '' : `<button class="btn btn-sm btn-ghost" onclick='revokeIngestToken(${jsv(token.token_id)}, ${jsv(token.name)})'>Revoke</button>`}</div>
      </div>`).join('') : '<div class="empty-state">No collector tokens yet.</div>';
  } catch (e) {
    list.innerHTML = '<div class="empty-state">Failed to load collector tokens.</div>';
  }
}

async function createIngestToken() {
  const input = document.getElementById('new-ingest-token-name');
  const message = document.getElementById('ingest-token-message');
  const name = input?.value?.trim() || '';
  if (!name) { message.textContent = 'Name the token after where it will be used.'; message.style.color = 'var(--red)'; return; }
  try {
    const created = await apiJSON('/api/ingest-tokens', { method: 'POST', headers: authHeaders(), body: JSON.stringify({ name }) });
    input.value = '';
    message.style.color = 'var(--text)';
    message.innerHTML = `Copy this token now; it is not shown again:<br><code class="token-once">${esc(created.token)}</code>`;
    loadIngestTokens();
    loadAuditEvents();
  } catch (e) {
    message.textContent = e.message || 'Failed to create token.';
    message.style.color = 'var(--red)';
  }
}

async function revokeIngestToken(tokenId, name) {
  if (!confirm(`Revoke collector token "${name}"? Collectors using it will be refused.`)) return;
  try {
    await apiJSON(`/api/ingest-tokens/${encodeURIComponent(tokenId)}`, { method: 'DELETE', headers: authHeaders() });
    notify(`Revoked collector token ${name}.`, 'success');
    loadIngestTokens();
    loadAuditEvents();
  } catch (e) {
    notify(e.message || 'Failed to revoke token.', 'error');
  }
}

async function createUser() {
  const username = document.getElementById('new-user-username')?.value?.trim() || '';
  const password = document.getElementById('new-user-password')?.value || '';
  const role = document.getElementById('new-user-role')?.value || 'analyst';
  const message = document.getElementById('user-admin-message');
  if (!username || !password) {
    if (message) {
      message.textContent = 'Username and password are required.';
      message.style.color = 'var(--red)';
    }
    return;
  }
  if (message) {
    message.textContent = 'Creating user...';
    message.style.color = 'var(--text2)';
  }
  try {
    await apiJSON('/api/auth/users', {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ username, password, role }),
    });
    document.getElementById('new-user-username').value = '';
    document.getElementById('new-user-password').value = '';
    if (message) {
      message.textContent = `Created ${username}.`;
      message.style.color = 'var(--green)';
    }
    notify(`Created ${role} account ${username}.`, 'success');
    loadUsers();
    loadAuditEvents();
  } catch (e) {
    if (message) {
      message.textContent = e.message || 'Failed to create user.';
      message.style.color = 'var(--red)';
    }
  }
}

async function updateUserRecord(username, payload, successMessage) {
  const message = document.getElementById('user-admin-message');
  if (message) {
    message.textContent = 'Applying user update...';
    message.style.color = 'var(--text2)';
  }
  try {
    await apiJSON(`/api/auth/users/${encodeURIComponent(username)}`, {
      method: 'PATCH',
      headers: authHeaders(),
      body: JSON.stringify(payload),
    });
    if (message) {
      message.textContent = successMessage;
      message.style.color = 'var(--green)';
    }
    notify(successMessage, 'success');
    loadUsers();
    loadAuditEvents();
    if (authState.user?.username === username) refreshSession();
  } catch (e) {
    if (message) {
      message.textContent = e.message || 'Failed to update user.';
      message.style.color = 'var(--red)';
    }
    notify(e.message || 'Failed to update user.', 'error');
  }
}

function saveUserRole(username) {
  const select = document.getElementById(`role-${username}`);
  if (!select) return;
  updateUserRecord(username, { role: select.value }, `Updated ${username} to ${select.value}.`);
}

function toggleUserActive(username, shouldEnable) {
  const action = shouldEnable ? 'enable' : 'disable';
  if (!confirm(`${action === 'enable' ? 'Enable' : 'Disable'} ${username}?`)) return;
  updateUserRecord(username, { active: !!shouldEnable }, `${shouldEnable ? 'Enabled' : 'Disabled'} ${username}.`);
}

function resetUserPassword(username) {
  const newPassword = prompt(`Set a new password for ${username}:`);
  if (!newPassword) return;
  updateUserRecord(username, { password: newPassword }, `Reset password for ${username}.`);
}

function getQueueFilterState() {
  const ownerInput = document.getElementById('q-owner');
  const ownerValue = ownerInput ? ownerInput.value.trim() : '';
  return {
    status: document.getElementById('q-status')?.value || '',
    search: document.getElementById('queue-search')?.value || '',
    item_type: document.getElementById('q-type')?.value || '',
    owner: ownerValue,
    disposition: document.getElementById('q-disposition')?.value || '',
    actionable_only: !!document.getElementById('q-actionable-only')?.checked,
    sort: document.getElementById('queue-sort')?.value || tableState.queue.sort,
  };
}

function applyQueueFilterState(state = {}) {
  if (document.getElementById('queue-search')) document.getElementById('queue-search').value = state.search || '';
  if (document.getElementById('q-status')) document.getElementById('q-status').value = state.status || '';
  if (document.getElementById('q-type')) document.getElementById('q-type').value = state.item_type || '';
  if (document.getElementById('q-owner')) document.getElementById('q-owner').value = state.owner || '';
  if (document.getElementById('q-disposition')) document.getElementById('q-disposition').value = state.disposition || '';
  if (document.getElementById('q-actionable-only')) document.getElementById('q-actionable-only').checked = state.actionable_only !== undefined ? !!state.actionable_only : true;
  if (document.getElementById('queue-sort')) document.getElementById('queue-sort').value = state.sort || 'updated_desc';
}

function renderSavedQueueViews() {
  const select = document.getElementById('queue-saved-views');
  if (!select) return;
  const options = ['<option value="">Choose a saved view</option>']
    .concat(Object.keys(savedQueueViews).sort().map(name => `<option value="${esc(name)}">${esc(name)}</option>`));
  select.innerHTML = options.join('');
}

function saveQueueViewsToStorage() {
  savePreferencesPatch({ savedQueueViews });
}

function saveQueueView() {
  const name = document.getElementById('queue-view-name')?.value?.trim();
  if (!name) {
    notify('Give the view a short name first.', 'error');
    return;
  }
  savedQueueViews[name] = getQueueFilterState();
  saveQueueViewsToStorage();
  renderSavedQueueViews();
  document.getElementById('queue-saved-views').value = name;
  notify(`Saved queue view "${name}".`, 'success');
}

function applySavedQueueView(name) {
  if (!name || !savedQueueViews[name]) return;
  applyQueueFilterState(savedQueueViews[name]);
  notify(`Applied queue view "${name}".`, 'info');
  loadQueue();
}

function deleteSavedQueueView() {
  const select = document.getElementById('queue-saved-views');
  const name = select?.value || '';
  if (!name || !savedQueueViews[name]) {
    notify('Choose a saved view to delete.', 'error');
    return;
  }
  delete savedQueueViews[name];
  saveQueueViewsToStorage();
  renderSavedQueueViews();
  document.getElementById('queue-view-name').value = '';
  notify(`Deleted queue view "${name}".`, 'success');
}

function applyQueueShortcut(kind) {
  if (kind === 'mine') {
    if (!getReviewerName()) {
      notify('Sign in first to load your queue.', 'error');
      return;
    }
    applyQueueFilterState({ owner: getReviewerName(), actionable_only: true, sort: 'updated_desc' });
  } else if (kind === 'unassigned') {
    applyQueueFilterState({ owner: '@unassigned', actionable_only: true, sort: 'priority_asc' });
  } else if (kind === 'escalated') {
    applyQueueFilterState({ status: 'Escalated', actionable_only: true, sort: 'priority_asc' });
  } else if (kind === 'priority') {
    applyQueueFilterState({ status: 'Open', item_type: 'incident', actionable_only: true, sort: 'priority_asc' });
  }
  if (currentPage === 'queue') loadQueue();
  else showPage('queue');
}

function clearQueueFilters() {
  applyQueueFilterState({ status: '', item_type: '', owner: '', disposition: '', actionable_only: true, sort: 'updated_desc' });
  document.getElementById('queue-saved-views').value = '';
  loadQueue();
}

function syncQueueActionableWithStatus() {
  const status = document.getElementById('q-status')?.value || '';
  const actionable = document.getElementById('q-actionable-only');
  if (!actionable) return;
  if (status === 'Closed' || status === 'Suppressed') actionable.checked = false;
}

function handleQueueActionableToggle() {
  const actionable = !!document.getElementById('q-actionable-only')?.checked;
  const statusEl = document.getElementById('q-status');
  if (actionable && statusEl && (statusEl.value === 'Closed' || statusEl.value === 'Suppressed')) {
    statusEl.value = '';
  }
  loadQueue();
}

function changePageSize(key, value) {
  tableState[key].pageSize = Number(value) || 15;
  tableState[key].page = 1;
  persistTablePreferences();
  if (key === 'cases') updateCasesView();
  if (key === 'queue') updateQueueView();
  if (key === 'jobs') updateJobsView();
}

function renderPagination(key, totalItems, renderedCount) {
  const state = tableState[key];
  const totalPages = Math.max(1, Math.ceil(totalItems / state.pageSize));
  if (state.page > totalPages) state.page = totalPages;
  const container = document.getElementById(`${key}-pagination`);
  if (!container) return;
  container.innerHTML = `
    <div class="toolbar-meta">Showing ${renderedCount} of ${totalItems} item(s)</div>
    <div class="pagination-controls">
      <button class="btn btn-sm btn-ghost" ${state.page <= 1 ? 'disabled' : ''} onclick="changePage('${key}', -1)">Previous</button>
      <span class="pill">Page ${state.page} / ${totalPages}</span>
      <button class="btn btn-sm btn-ghost" ${state.page >= totalPages ? 'disabled' : ''} onclick="changePage('${key}', 1)">Next</button>
    </div>
  `;
}

function changePage(key, delta) {
  const state = tableState[key];
  state.page = Math.max(1, state.page + delta);
  if (key === 'cases') updateCasesView();
  if (key === 'queue') updateQueueView();
  if (key === 'jobs') updateJobsView();
}

function paginate(items, key) {
  const state = tableState[key];
  const totalPages = Math.max(1, Math.ceil(items.length / state.pageSize));
  if (state.page > totalPages) state.page = totalPages;
  const start = (state.page - 1) * state.pageSize;
  return items.slice(start, start + state.pageSize);
}

function setMeta(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function setButtonLoading(button, isLoading, busyText) {
  if (!button) return;
  if (!button.dataset.defaultLabel) button.dataset.defaultLabel = button.textContent;
  button.classList.toggle('is-loading', !!isLoading);
  button.disabled = !!isLoading;
  button.textContent = isLoading ? (busyText || 'Working...') : button.dataset.defaultLabel;
}

function setQueueSort(field) {
  const current = tableState.queue.sort || 'updated_desc';
  const isCurrentField = current.startsWith(`${field}_`);
  const currentDir = current.endsWith('_asc') ? 'asc' : 'desc';
  const nextDir = isCurrentField ? (currentDir === 'asc' ? 'desc' : 'asc') : (field === 'updated' ? 'desc' : 'asc');
  tableState.queue.sort = `${field}_${nextDir}`;
  tableState.queue.page = 1;
  const sortSelect = document.getElementById('queue-sort');
  if (sortSelect && Array.from(sortSelect.options).some(opt => opt.value === tableState.queue.sort)) {
    sortSelect.value = tableState.queue.sort;
  }
  updateQueueView();
}

function refreshQueueSortIndicators() {
  const sort = tableState.queue.sort || 'updated_desc';
  ['case', 'status', 'priority', 'updated'].forEach(field => {
    const btn = document.getElementById(`qsort-${field}`);
    if (!btn) return;
    const active = sort.startsWith(`${field}_`);
    const isAsc = sort.endsWith('_asc');
    btn.classList.toggle('active', active);
    const glyph = active ? (isAsc ? '▲' : '▼') : '↕';
    btn.innerHTML = `${esc(btn.dataset.label || field)} <span aria-hidden="true">${glyph}</span>`;
    btn.setAttribute('aria-sort', active ? (isAsc ? 'ascending' : 'descending') : 'none');
  });
}

function buildQueueSummaryText(items, filterState, actionableOnly) {
  const parts = [`${items.length} item(s)`];
  if (actionableOnly) parts.push('actionable only');
  if (filterState.status) parts.push(`status: ${filterState.status}`);
  if (filterState.item_type) parts.push(`type: ${filterState.item_type}`);
  if (filterState.owner) parts.push(`owner: ${filterState.owner}`);
  if (filterState.disposition) parts.push(`disposition: ${filterState.disposition}`);
  return parts.join(' · ');
}

// --- Review Queue ---
let queueRequestId = 0;
async function loadQueue() {
  const requestId = ++queueRequestId;
  tableState.queue.page = 1;
  renderTableMessage('queue-table', 9, 'Loading review queue...', 'loading');
  setMeta('queue-filter-summary', 'Loading queue summary...');
  const params = new URLSearchParams();
  const s = document.getElementById('q-status').value; if (s) params.set('status', s);
  const t = document.getElementById('q-type').value; if (t) params.set('item_type', t);
  const o = document.getElementById('q-owner').value.trim(); if (o) params.set('owner', o === '@unassigned' ? '__unassigned__' : o);
  const d = document.getElementById('q-disposition').value; if (d) params.set('disposition', d);
  try {
    const items = await apiJSON('/api/review/queue?' + params.toString());
    if (requestId !== queueRequestId || !authState.authenticated) return;
    _queueCache = Array.isArray(items) ? items : [];
    updateQueueView();
  } catch (e) {
    if (requestId !== queueRequestId || !authState.authenticated) return;
    renderTableMessage('queue-table', 9, 'Failed to load review queue.');
    setMeta('queue-filter-summary', 'Queue summary unavailable');
    notify('Failed to load review queue.', 'error');
  }
}

function compareQueue(a, b, sort) {
  if (sort === 'updated_asc') return safeDate(a.updated_at) - safeDate(b.updated_at);
  if (sort === 'updated_desc') return safeDate(b.updated_at) - safeDate(a.updated_at);
  if (sort === 'priority_asc') return priorityRank(a.priority) - priorityRank(b.priority) || safeDate(b.updated_at) - safeDate(a.updated_at);
  if (sort === 'priority_desc') return priorityRank(b.priority) - priorityRank(a.priority) || safeDate(b.updated_at) - safeDate(a.updated_at);
  if (sort === 'case_asc') return String(a.case_name||'').localeCompare(String(b.case_name||''));
  if (sort === 'case_desc') return String(b.case_name||'').localeCompare(String(a.case_name||''));
  if (sort === 'status_asc') return String(a.status||'Open').localeCompare(String(b.status||'Open'));
  if (sort === 'status_desc') return String(b.status||'Open').localeCompare(String(a.status||'Open'));
  return safeDate(b.updated_at) - safeDate(a.updated_at);
}

function updateQueueView() {
  const tb = document.getElementById('queue-table');
  const queueStats = document.getElementById('queue-stats');
  const summaryEl = document.getElementById('queue-filter-summary');
  const actionableOnly = !!document.getElementById('q-actionable-only')?.checked;
  const filterState = getQueueFilterState();
  const search = (document.getElementById('queue-search')?.value || '').trim().toLowerCase();
  const items = [..._queueCache].filter(item => (!actionableOnly || !['Closed', 'Suppressed'].includes(item.status || 'Open')) && (!search || [item.case_name,item.item_id,item.owner,item.disposition].some(value => String(value || '').toLowerCase().includes(search))));
  tableState.queue.sort = document.getElementById('queue-sort')?.value || tableState.queue.sort;
  refreshQueueSortIndicators();
  persistTablePreferences();
  if (queueStats) {
    const counts = {
      total: items.length,
      open: items.filter(i => (i.status || 'Open') === 'Open').length,
      inReview: items.filter(i => i.status === 'In Review').length,
      escalated: items.filter(i => i.status === 'Escalated').length,
    };
    queueStats.style.display = '';
    queueStats.innerHTML =
      stat(counts.total, 'Visible Queue Items', '--accent') +
      stat(counts.open, 'Open', '--blue') +
      stat(counts.inReview, 'In Review', '--orange') +
      stat(counts.escalated, 'Escalated', '--red');
  }
  if (summaryEl) {
    summaryEl.textContent = buildQueueSummaryText(items, filterState, actionableOnly);
  }
  if (!items.length) {
    const hasFilters = !!(search || filterState.status || filterState.item_type || filterState.owner || filterState.disposition);
    const emptyMessage = hasFilters
      ? 'No queue items match the current filters.'
      : 'All clear. No items awaiting review.';
    renderTableMessage('queue-table', 9, emptyMessage);
    renderPagination('queue', 0, 0);
    setMeta('queue-meta', actionableOnly ? 'No actionable review items match the current filters' : 'No review items match the current filters');
    return;
  }
  items.sort((a, b) => compareQueue(a, b, tableState.queue.sort));
  const paged = paginate(items, 'queue');
  tb.innerHTML = paged.map(q => `<tr onclick='openReviewItem(${jsv(q.case_name)},${jsv(q.item_type)},${jsv(q.item_id)})'>
    <td><a href="#" class="table-link" onclick='event.preventDefault();event.stopPropagation();openReviewItem(${jsv(q.case_name)},${jsv(q.item_type)},${jsv(q.item_id)})'>${esc(q.case_name||'')}</a></td>
    <td><span class="review-chip" style="background:${q.item_type==='incident'?'var(--red)':'var(--orange)'};color:#fff">${q.item_type||''}</span></td>
    <td style="font-family:monospace;font-size:12px"><a href="#" class="table-link" onclick='event.preventDefault();event.stopPropagation();openReviewItem(${jsv(q.case_name)},${jsv(q.item_type)},${jsv(q.item_id)})'>${esc(q.item_id||'')}</a></td>
    <td><span class="badge badge-${statusBadge(q.status)}">${esc(q.status||'Open')}</span></td>
    <td style="font-size:13px">${esc(q.disposition||'-')}</td>
    <td>${esc(q.owner||'-')}</td>
    <td>${esc(q.priority||'-')}</td>
    <td style="color:var(--text2);font-size:12px">${q.updated_at ? q.updated_at.slice(0,16).replace('T',' ') : '-'}</td>
    <td onclick="event.stopPropagation()">${canReviewMutate() ? `<button class="btn btn-sm btn-ghost" onclick='assignQueueItemToMe(${jsv(q.case_name)},${jsv(q.item_type)},${jsv(q.item_id)},${jsv(q.status || "Open")})'>Assign to me</button>` : `<span style="color:var(--text2);font-size:12px">read-only</span>`}</td>
  </tr>`).join('');
  renderPagination('queue', items.length, paged.length);
  setMeta('queue-meta', buildQueueSummaryText(items, filterState, actionableOnly));
}

function statusBadge(s) {
  return (s||'open').toLowerCase().replace(/ /g,'-');
}

function openReviewItem(caseName, itemType, itemId) {
  const tab = itemType === 'incident' ? 'incidents' : 'findings';
  openCase(caseName, { tab, itemType, itemId });
}

async function assignQueueItemToMe(caseName, itemType, itemId, currentStatus = 'Open') {
  const reviewer = getReviewerName();
  if (!reviewer) {
    notify('Sign in before assigning review ownership.', 'error');
    return;
  }
  if (!canReviewMutate()) {
    notify('Viewer accounts cannot claim queue items.', 'error');
    return;
  }
  const typePlural = itemType === 'finding' ? 'findings' : 'incidents';
  const nextStatus = currentStatus === 'Open' ? 'In Review' : currentStatus;
  try {
    await apiJSON(`/api/cases/${encodeURIComponent(caseName)}/${typePlural}/${encodeURIComponent(itemId)}/review`, {
      method: 'PATCH',
      headers: authHeaders(),
      body: JSON.stringify({
        owner: reviewer,
        status: nextStatus,
        changed_by: reviewer,
      }),
    });
    notify(`Assigned ${itemType} ${itemId} to ${reviewer}.`, 'success');
    await loadQueue();
  } catch (e) {
    notify(e.message || 'Failed to assign queue item.', 'error');
  }
}

// --- Case detail ---
let _caseData = null;
let _detailTarget = { tab: 'overview', itemType: '', itemId: '' };

let caseRequestId = 0;
async function openCase(name, options = {}) {
  if (!authState.authenticated) { openAuthOverlay(); return; }
  const requestId = ++caseRequestId;
  _caseData = null;
  document.getElementById('detail-stats').innerHTML = '';
  const exportButton = document.getElementById('detail-bundle-btn');
  if (exportButton) { exportButton.disabled = true; exportButton.onclick = null; }
  _detailTarget = {
    tab: options.tab || 'overview',
    itemType: options.itemType || '',
    itemId: options.itemId || '',
  };
  document.querySelectorAll('main > [id^="page-"]').forEach(el => el.style.display = 'none');
  document.getElementById('page-case-detail').style.display = '';
  currentPage = 'case-detail';
  setNavigationState('case-detail');
  document.getElementById('page-title').textContent = name;
  document.getElementById('detail-case-name').textContent = name;
  document.getElementById('detail-tabs').innerHTML = '';
  document.getElementById('detail-content').innerHTML = '<div class="card"><div class="loading-state"><span class="loading-inline"><span class="spinner" aria-hidden="true"></span><span>Loading case detail...</span></span></div></div>';
  document.getElementById('detail-report-link').href = API + '/api/cases/' + encodeURIComponent(name) + '/report';
  document.getElementById('detail-delete-btn').onclick = async () => {
    if (confirm(`Permanently delete case ${name}? This removes its evidence copies, report, findings and review decisions from this server. Original evidence elsewhere is not touched. This cannot be undone.`)) {
      try {
        await apiJSON('/api/cases/' + encodeURIComponent(name), { method:'DELETE' });
        notify(`Deleted case ${name}.`, 'success');
        showPage('dashboard');
      } catch (e) {
        notify(e.message || `Failed to delete ${name}.`, 'error');
      }
    }
  };

  try {
    const data = await apiJSON('/api/cases/' + encodeURIComponent(name));
    let runStatus = null;
    try {
      runStatus = await apiJSON('/api/cases/' + encodeURIComponent(name) + '/status', {}, true);
    } catch (_ignored) {
      runStatus = null;
    }
    if (requestId !== caseRequestId || currentPage !== 'case-detail') return;
    data._run_status = runStatus;
    _caseData = data;
    const cs = data.case || {};
    const sm = data.summary || {};
    const bundleBtn = document.getElementById('detail-bundle-btn');
    if (bundleBtn) { bundleBtn.disabled = false; bundleBtn.onclick = () => downloadCaseBundle(name); }

    document.getElementById('detail-stats').innerHTML =
      stat(cs.response_priority || 'P4', 'Priority', cs.response_priority === 'P1' ? '--red' : cs.response_priority === 'P2' ? '--orange' : '--blue') +
      stat(sm.signal_count || 0, 'Signals', '--accent') +
      stat(sm.finding_count || 0, 'Findings', '--orange') +
      stat(sm.incident_count || 0, 'Incidents', '--red');

    const tabs = ['Overview', 'Incidents', 'Findings', 'Timeline', ...(cs.forensic_summary ? ['Evidence'] : []), 'Summary', 'Brief'];
    document.getElementById('detail-tabs').innerHTML = tabs.map((t,i) => {
      const tabName = t.toLowerCase();
      const isActive = _detailTarget.tab ? _detailTarget.tab === tabName : i === 0;
      return `<button class="detail-tab ${isActive?'active':''}" onclick='showDetailTab(${jsv(tabName)},this,${jsv(name)})'>${t}</button>`;
    }).join('');

    showDetailTabContent(_detailTarget.tab || 'overview', name, data);
  } catch(e) {
    if (requestId !== caseRequestId || currentPage !== 'case-detail') return;
    const message = e?.message || 'Case artifacts are unavailable.';
    document.getElementById('detail-content').innerHTML = `
      <div class="card">
        <div class="card-title">Case Unavailable</div>
        <div class="empty-state" style="text-align:left;padding:12px 0 0">This job still exists in history, but its case artifacts are no longer available.</div>
        <div class="user-subtle" style="margin-top:10px">${esc(message)}</div>
        <div class="auth-actions" style="margin-top:16px">
          <button class="btn btn-sm btn-ghost" onclick="showPage('jobs')">Back to jobs</button>
          <button class="btn btn-sm btn-ghost" onclick="showPage('dashboard')">Back to dashboard</button>
        </div>
      </div>`;
    notify(`Could not open case ${name}.`, 'error');
  }
}

function showDetailTab(tab, btn, name) {
  _detailTarget = { tab, itemType: '', itemId: '' };
  document.querySelectorAll('.detail-tab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  if (_caseData) {
    showDetailTabContent(tab, name, _caseData);
  } else {
    document.getElementById('detail-content').innerHTML = '<div class="card"><div class="loading-state"><span class="loading-inline"><span class="spinner" aria-hidden="true"></span><span>Loading case content...</span></span></div></div>';
    apiJSON('/api/cases/' + encodeURIComponent(name)).then(async data => {
      try {
        data._run_status = await apiJSON('/api/cases/' + encodeURIComponent(name) + '/status', {}, true);
      } catch (_ignored) {
        data._run_status = null;
      }
      _caseData = data;
      showDetailTabContent(tab, name, data);
    }).catch(() => {
      document.getElementById('detail-content').innerHTML = '<div class="card"><div class="empty-state">Failed to load case content.</div></div>';
    });
  }
}

function showDetailTabContent(tab, name, data) {
  if (tab === 'timeline') { loadEvidenceTimeline(name); return; }
  if (tab === 'evidence') { loadForensicEvidence(name); return; }
  const parentRequest = caseRequestId;
  const stillCurrent = () => parentRequest === caseRequestId && currentPage === 'case-detail' && _detailTarget.tab === tab;
  const el = document.getElementById('detail-content');
  const cs = data.case || {};
  const sm = data.summary || {};
  const runStatus = data._run_status || {};
  const runMeta = runStatus.metadata || {};
  const stageTimings = runMeta.stage_timings || {};
  const detectorTimings = runMeta.detector_timings || {};
  const detectorTimingList = summarizeDetectorTimings(detectorTimings);
  const stageTimingRows = [
    ['Parse', stageTimings.parse_ms],
    ['Detect', stageTimings.detect_ms],
    ['Suppress', stageTimings.suppress_ms],
    ['Correlate', stageTimings.correlate_ms],
    ['Report', stageTimings.report_ms],
    ['Total', stageTimings.total_ms],
  ];

  if (tab === 'overview') {
    const cq = cs.collection_quality_summary || {};
    const td = cs.triage_disposition || data.triage_disposition || data.summary?.triage_disposition || {};
    const review = summarizeReviewState(data.findings || [], data.incidents || []);
    const campaign = cs.campaign_summary || [];
    const nextActions = cq.recommendations || [];
    const workbench = [
      review.escalated ? `${review.escalated} escalated item(s) need senior review.` : '',
      review.open ? `${review.open} open item(s) still need first-pass triage.` : '',
      review.withOwner ? `${review.withOwner} item(s) already have an owner.` : 'No items are assigned yet.',
      canReviewMutate() ? 'Use Findings and Incidents tabs to update review state directly in place.' : 'Viewer mode is read-only. Ask an analyst or admin to make review updates.',
    ].filter(Boolean);
    const issues = [
      ['Missing telemetry', cq.telemetry_missing], ['Partial reads', cq.partial_sources],
      ['Permission denied', cq.permission_denied_sources], ['Fallback after denied access', cq.fallback_permission_sources],
      ['Unreadable channels', cq.unavailable_sources],
    ].filter(([, values]) => (values || []).length);
    const next = td.recommended_next || [];
    el.innerHTML = `<div class="panel-stack overview-stack">
      ${renderEvidenceScope(cs)}
      <section class="card verdict-card">
        <div class="verdict-head">
          <div><div class="eyebrow">Triage disposition</div>
            <div class="verdict-title">${esc(td.disposition || 'Not yet determined')}</div>
            <div class="verdict-meta">${esc(cs.response_priority || 'P4')} · confidence ${esc(td.confidence || 'unknown')} (${confidencePercent(td.confidence_score)}%)</div></div>
          ${td.reasons?.length ? `<div class="detail-chip-row">${td.reasons.map(x => `<span class="detail-chip">${esc(x)}</span>`).join('')}</div>` : ''}
        </div>
        ${next.length ? `<div class="verdict-next"><div class="section-kicker">Next steps</div><ol>${next.map(item => `<li>${esc(item)}</li>`).join('')}</ol></div>` : ''}
        <dl class="fact-strip">
          <div><dt>Host</dt><dd>${esc(cs.primary_host || 'unknown')}${(cs.hosts || []).length > 1 ? ` <span class="subtle">+${cs.hosts.length - 1} more</span>` : ''}</dd></div>
          <div><dt>User</dt><dd>${esc(cs.primary_user || 'unknown')}</dd></div>
          <div><dt>Source IP</dt><dd>${esc(cs.primary_source_ip || 'none')}</dd></div>
          <div><dt>Activity</dt><dd>${esc(shortStamp(cs.first_seen))} → ${esc(shortStamp(cs.last_seen))}</dd></div>
          <div><dt>Input</dt><dd>${esc(cs.input_source_display || displayInputSource(cs.input_source || ''))}</dd></div>
        </dl>
      </section>
      <div class="overview-columns">
        <section class="card">
          <div class="card-title">Collection quality</div>
          <p class="section-kicker">${esc(cq.summary || 'Collection metadata available for this case.')}</p>
          <dl class="fact-list">
            <div><dt>Sources</dt><dd>${esc(cq.source_count ?? '-')}</dd></div>
            <div><dt>Parsed events</dt><dd>${esc(Number(cq.parsed_event_count || 0).toLocaleString())}</dd></div>
            <div><dt>Telemetry present</dt><dd>${(cq.telemetry_present || []).map(esc).join(', ') || 'None'}</dd></div>
            <div><dt>Warnings</dt><dd>${esc(cq.warning_count ?? 0)}</dd></div>
            ${issues.map(([label, values]) => `<div class="fact-issue"><dt>${esc(label)}</dt><dd>${values.map(esc).join(', ')}</dd></div>`).join('')}
          </dl>
          ${issues.length ? '' : '<p class="fact-ok">No read, permission or channel problems.</p>'}
        </section>
        <section class="card">
          <div class="card-title">Review progress</div>
          <div class="counter-row">
            ${[['Open', review.open, '--blue'], ['In review', review.inReview, '--orange'], ['Escalated', review.escalated, '--red'], ['Owned', review.withOwner, '--green']]
              .map(([label, value, color]) => `<div class="counter"><span style="color:var(${color})">${esc(value)}</span>${esc(label)}</div>`).join('')}
          </div>
          ${renderMiniList(workbench, 'No active workflow recommendations.')}
          ${campaign.length ? `<div class="section-kicker">Campaign overlaps</div>${renderMiniList(campaign, '')}` : ''}
          ${nextActions.length ? `<div class="section-kicker">Collection advice</div>${renderMiniList(nextActions, '')}` : ''}
        </section>
      </div>
      <details class="card details-card"><summary>Pipeline timing · ${esc(formatTiming(stageTimings.total_ms))} total</summary>
        <dl class="fact-list">${stageTimingRows.map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${esc(formatTiming(value))}</dd></div>`).join('')}</dl>
        <div class="section-kicker">Slowest detectors</div>
        ${renderMiniList(detectorTimingList, 'No detector timing data available.')}
      </details>
    </div>`;
  } else if (tab === 'incidents') {
    const incs = data.incidents || [];
    if (!incs.length) { el.innerHTML = '<div class="card" style="text-align:center;padding:40px;color:var(--text2)">No incidents in this case.</div>'; return; }
    el.innerHTML = incs.map(inc => {
      const rv = inc.review || {};
      return `<div class="card detail-card" id="${domId('incident', inc.id)}">
      <div class="detail-card-header">
        <div class="detail-card-copy">
          <div class="detail-title-row" style="font-weight:700;font-size:16px">${esc(inc.display_label||'')} ${esc(inc.title||'')}
          ${rv.status ? ` <span class="badge badge-${statusBadge(rv.status)}">${esc(rv.status)}</span>` : ''}
          ${rv.disposition ? ` <span class="review-chip" style="background:var(--surface2)">${esc(rv.disposition)}</span>` : ''}
        </div>
          <div class="detail-summary">${esc(inc.summary||'')}</div>
          <div class="detail-meta-line"><b>Why flagged:</b> ${esc(inc.why_flagged||'Correlated suspicious behavior')}</div>
          <div class="detail-chip-row">
            ${inc.mitre_tactic || inc.mitre_technique || inc.technique_summary ? `<span class="detail-chip">MITRE: ${esc([inc.mitre_tactic, inc.mitre_technique].filter(Boolean).join(' / ') || inc.technique_summary)}</span>` : ''}
            <span class="detail-chip">Severity: ${esc(inc.severity||'unknown')}</span>
            <span class="detail-chip">Confidence: ${inc.confidence_score||0}%</span>
          </div>
        </div>
        <div><span class="badge badge-${(inc.severity||'').toLowerCase()==='critical'?'p1':(inc.severity||'').toLowerCase()==='high'?'p2':'p3'}">${esc(inc.severity||'')} / ${inc.confidence_score||0}%</span></div>
      </div>
      ${inc.containment_guidance?.length ? `<div style="font-size:13px;color:var(--orange);margin-top:6px"><b>Containment:</b> ${inc.containment_guidance.map(esc).join('; ')}</div>` : ''}
      ${renderReviewPanel(name, 'incident', inc.id, rv)}
    </div>`;
    }).join('');
    incs.forEach(inc => loadReviewDetail(name, 'incident', inc.id, reviewPanelPrefix('incident', inc.id)));
    setTimeout(() => focusDetailTarget('incidents'), 0);
  } else if (tab === 'findings') {
    const fnds = data.findings || [];
    if (!fnds.length) { el.innerHTML = '<div class="card" style="text-align:center;padding:40px;color:var(--text2)">No findings in this case.</div>'; return; }
    el.innerHTML = fnds.map(f => {
      const rv = f.review || {};
      return `<div class="card detail-card" id="${domId('finding', f.id)}">
      <div class="detail-card-header">
        <div class="detail-card-copy">
          <div class="detail-title-row" style="font-weight:700;font-size:16px">${esc(f.display_label||'')} ${esc(f.title||'')}
          ${rv.status ? ` <span class="badge badge-${statusBadge(rv.status)}">${esc(rv.status)}</span>` : ''}
          ${rv.disposition ? ` <span class="review-chip" style="background:var(--surface2)">${esc(rv.disposition)}</span>` : ''}
        </div>
          <div class="detail-summary">${esc(f.summary||f.description||'')}</div>
          <div class="detail-chip-row">
            <span class="detail-chip">Host: ${esc(f.host||'-')}</span>
            <span class="detail-chip">User: ${esc(f.user||'-')}</span>
            <span class="detail-chip">Severity: ${esc(f.severity||'unknown')}</span>
            <span class="detail-chip">Confidence: ${f.confidence_score||0}%</span>
          </div>
        </div>
        <div><span class="badge badge-${(f.severity||'').toLowerCase()==='critical'?'p1':(f.severity||'').toLowerCase()==='high'?'p2':'p3'}">${esc(f.severity||'')} / ${f.confidence_score||0}%</span></div>
      </div>
      ${renderReviewPanel(name, 'finding', f.id, rv)}
    </div>`;
    }).join('');
    fnds.forEach(f => loadReviewDetail(name, 'finding', f.id, reviewPanelPrefix('finding', f.id)));
    setTimeout(() => focusDetailTarget('findings'), 0);
  } else if (tab === 'summary') {
    el.innerHTML = '<div class="card"><div class="loading-state"><span class="loading-inline"><span class="spinner" aria-hidden="true"></span><span>Loading summary...</span></span></div></div>';
    apiJSON('/api/cases/' + encodeURIComponent(name) + '/summary').then(d => {
      if (!stillCurrent()) return;
      el.innerHTML = `<div class="pre-block">${esc(d.summary||'')}</div>`;
    }).catch(() => {
      if (!stillCurrent()) return;
      el.innerHTML = '<div class="card"><div class="empty-state">Failed to load summary.</div></div>';
    });
  } else if (tab === 'brief') {
    el.innerHTML = '<div class="card"><div class="loading-state"><span class="loading-inline"><span class="spinner" aria-hidden="true"></span><span>Loading incident brief...</span></span></div></div>';
    apiJSON('/api/cases/' + encodeURIComponent(name) + '/brief').then(d => {
      if (!stillCurrent()) return;
      el.innerHTML = `<div class="pre-block">${esc(d.brief||'')}</div>`;
    }).catch(() => {
      if (!stillCurrent()) return;
      el.innerHTML = '<div class="card"><div class="empty-state">Failed to load incident brief.</div></div>';
    });
  }
}

function focusDetailTarget(tab) {
  if (!_detailTarget.itemId || _detailTarget.tab !== tab) return;
  const prefix = _detailTarget.itemType === 'incident' ? 'incident' : 'finding';
  const target = document.getElementById(domId(prefix, _detailTarget.itemId));
  if (!target) return;
  target.classList.add('focused');
  target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  setTimeout(() => target.classList.remove('focused'), 2400);
}

// --- Review panel renderer ---
function renderReviewPanel(caseName, itemType, itemId, rv) {
  if (!itemId) return '';
  const pfx = reviewPanelPrefix(itemType, itemId);
  const statuses = reviewEnums.statuses || ['Open','In Review','Escalated','Closed','Suppressed'];
  const dispositions = reviewEnums.dispositions || ['True Positive','False Positive','Benign Expected Activity','Suspicious - Needs More Investigation','Test / Lab Activity','Duplicate'];
  const ownerValue = rv.owner || getReviewerName();
  const reviewStatus = String(rv.status || 'Open');
  // The evidence leads; the form opens on request or for an item opened from the queue or timeline.
  const collapsedByDefault = _detailTarget.itemId !== itemId;
  const toggleLabel = collapsedByDefault ? 'Expand Review' : 'Collapse Review';
  const disabled = canReviewMutate() ? '' : ' disabled';
  const hint = canReviewMutate() ? '' : '<div style="font-size:11px;color:var(--text2);margin-bottom:8px">Viewer access: review edits are read-only.</div>';
  return `<div class="review-panel${collapsedByDefault ? ' is-collapsed' : ''}" id="${pfx}-panel" data-case-name="${esc(caseName)}" data-item-type="${esc(itemType)}" data-item-id="${esc(itemId)}">
    <div class="review-panel-header">
      <div class="rp-title">Analyst review <span class="rp-state">${esc(reviewStatus)} · ${esc(rv.owner || 'unassigned')}${rv.disposition ? ` · ${esc(rv.disposition)}` : ''}</span></div>
      <button class="btn btn-sm btn-ghost" id="${pfx}-toggle" onclick='toggleReviewPanel(${jsv(pfx)})'>${toggleLabel}</button>
    </div>
    <div class="review-panel-body" id="${pfx}-body"${collapsedByDefault ? ' style="display:none"' : ''}>
    ${hint}
    <div class="review-grid">
      <div class="input-group"><label>Status</label>
        <select class="input" id="${pfx}-status"${disabled}>${statuses.map(s=>`<option${rv.status===s?' selected':''}>${s}</option>`).join('')}</select>
      </div>
      <div class="input-group"><label>Disposition</label>
        <select class="input" id="${pfx}-disp"${disabled}><option value="">--</option>${dispositions.map(d=>`<option${rv.disposition===d?' selected':''}>${d}</option>`).join('')}</select>
      </div>
      <div class="input-group"><label>Owner / Reviewer</label>
        <input class="input" id="${pfx}-owner" value="${esc(ownerValue||'')}" placeholder="e.g. analyst1"${disabled}>
      </div>
      <div class="input-group"><label>Priority</label>
        <input class="input" id="${pfx}-pri" value="${esc(rv.priority||'')}" placeholder="e.g. P1, P2"${disabled}>
      </div>
    </div>
    <div class="input-group"><label>Recommended Tuning Action</label>
      <input class="input" id="${pfx}-tuning" value="${esc(rv.recommended_tuning_action||'')}" placeholder="e.g. Suppress rule for this host"${disabled}>
    </div>
    <div class="review-actions">
      <button class="btn btn-sm btn-primary" id="${pfx}-save-btn" onclick='saveReview(${jsv(caseName)},${jsv(itemType)},${jsv(itemId)},${jsv(pfx)})'${disabled}>Save Review</button>
      <button class="btn btn-sm btn-ghost" onclick='assignToMe(${jsv(caseName)},${jsv(itemType)},${jsv(itemId)},${jsv(pfx)})'${disabled}>Assign to Me</button>
      <button class="btn btn-sm btn-ghost" onclick='quickAction(${jsv(caseName)},${jsv(itemType)},${jsv(itemId)},${jsv(pfx)},${jsv("In Review")})'${disabled}>Mark In Review</button>
      <button class="btn btn-sm btn-ghost" onclick='quickAction(${jsv(caseName)},${jsv(itemType)},${jsv(itemId)},${jsv(pfx)},${jsv("Escalated")})'${disabled}>Escalate</button>
      <button class="btn btn-sm btn-ghost" onclick='quickAction(${jsv(caseName)},${jsv(itemType)},${jsv(itemId)},${jsv(pfx)},${jsv("Closed")},${jsv("Benign Expected Activity")})'${disabled}>Close as Benign</button>
    </div>
    ${rv.updated_at ? `<div style="font-size:11px;color:var(--text2);margin-top:8px">Last updated: ${rv.updated_at.slice(0,16).replace('T',' ')}</div>` : ''}
    <div style="margin-top:12px">
      <div class="rp-title">Notes</div>
      <div id="${pfx}-notes" style="margin-bottom:8px"></div>
      <div style="display:flex;gap:8px">
        <textarea class="input" id="${pfx}-note-input" rows="2" placeholder="Add a note..." style="min-height:40px"${disabled}></textarea>
        <button class="btn btn-sm btn-primary" id="${pfx}-note-btn" onclick='addNote(${jsv(caseName)},${jsv(itemType)},${jsv(itemId)},${jsv(pfx)})' style="align-self:end"${disabled}>Add</button>
      </div>
    </div>
    <div style="margin-top:12px">
      <div class="history-toolbar">
        <div class="rp-title" style="cursor:pointer" onclick='toggleHistory(${jsv(pfx)})'>History ▸</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn btn-sm btn-ghost" onclick='downloadReviewHistoryExport("csv", ${jsv(caseName)}, ${jsv(itemType)}, ${jsv(itemId)})'>CSV</button>
          <button class="btn btn-sm btn-ghost" onclick='downloadReviewHistoryExport("json", ${jsv(caseName)}, ${jsv(itemType)}, ${jsv(itemId)})'>JSON</button>
        </div>
      </div>
      <div id="${pfx}-history" style="display:none"></div>
    </div>
    </div>
  </div>`;
}

// Load notes and history after panel renders
function loadReviewDetail(caseName, itemType, itemId, pfx) {
  const encodedCase = encodeURIComponent(caseName);
  const encodedId = encodeURIComponent(itemId);
  const typePlural = itemType === 'finding' ? 'findings' : 'incidents';
  apiJSON(`/api/cases/${encodedCase}/${typePlural}/${encodedId}/review`).then(rv => {
    const statusInput = document.getElementById(pfx + '-status');
    if (statusInput && rv.status) statusInput.value = rv.status;
    const dispInput = document.getElementById(pfx + '-disp');
    if (dispInput && rv.disposition !== undefined) dispInput.value = rv.disposition || '';
    const notesEl = document.getElementById(pfx + '-notes');
    if (notesEl && rv.notes) {
      notesEl.innerHTML = rv.notes.map(n => `<div class="note-item"><div class="note-meta">${esc(n.author||'analyst')} &mdash; ${(n.created_at||'').slice(0,16).replace('T',' ')}</div><div class="note-body">${esc(n.content)}</div></div>`).join('') || '<div style="color:var(--text2);font-size:13px">No notes yet.</div>';
    }
    const ownerInput = document.getElementById(pfx + '-owner');
    if (ownerInput && !ownerInput.value) ownerInput.value = rv.owner || getReviewerName();
    const histEl = document.getElementById(pfx + '-history');
    if (histEl && rv.history) {
      histEl.innerHTML = rv.history.map(h => `<div class="history-item"><span class="history-time">${(h.changed_at||'').slice(0,16).replace('T',' ')}</span><span>${describeHistoryEvent(h)}</span></div>`).join('') || '<div style="color:var(--text2);font-size:13px">No history yet.</div>';
    }
    if (rv.status === 'Closed' || rv.status === 'Suppressed') {
      const body = document.getElementById(pfx + '-body');
      const toggle = document.getElementById(pfx + '-toggle');
      if (body && toggle) {
        body.style.display = 'none';
        toggle.textContent = 'Expand Review';
      }
    }
  }).catch(() => {
    const notesEl = document.getElementById(pfx + '-notes');
    if (notesEl) notesEl.innerHTML = '<div style="color:var(--text2);font-size:13px">Failed to load notes.</div>';
  });
}

async function saveReview(caseName, itemType, itemId, pfx) {
  const typePlural = itemType === 'finding' ? 'findings' : 'incidents';
  const saveBtn = document.getElementById(pfx + '-save-btn');
  setButtonLoading(saveBtn, true, 'Saving...');
  const reviewer = document.getElementById(pfx+'-owner').value;
  const body = {
    status: document.getElementById(pfx+'-status').value,
    disposition: document.getElementById(pfx+'-disp').value,
    owner: reviewer,
    priority: document.getElementById(pfx+'-pri').value,
    recommended_tuning_action: document.getElementById(pfx+'-tuning').value,
    changed_by: getReviewerName(),
  };
  try {
    await apiJSON(`/api/cases/${encodeURIComponent(caseName)}/${typePlural}/${encodeURIComponent(itemId)}/review`, {
      method: 'PATCH', headers: authHeaders(), body: JSON.stringify(body)
    });
    notify(`Review updated for ${itemType} ${itemId}.`, 'success');
    _caseData = null;
    openCase(caseName, { tab: itemType === 'incident' ? 'incidents' : 'findings', itemType, itemId });
  } catch (e) {
    notify(e.message || 'Failed to save review.', 'error');
  } finally {
    setButtonLoading(saveBtn, false);
  }
}

async function quickAction(caseName, itemType, itemId, pfx, status, disposition) {
  const typePlural = itemType === 'finding' ? 'findings' : 'incidents';
  const reviewer = document.getElementById(pfx+'-owner')?.value || '';
  const body = {status};
  if (disposition) body.disposition = disposition;
  if (reviewer) body.owner = reviewer;
  body.changed_by = getReviewerName();
  try {
    await apiJSON(`/api/cases/${encodeURIComponent(caseName)}/${typePlural}/${encodeURIComponent(itemId)}/review`, {
      method: 'PATCH', headers: authHeaders(), body: JSON.stringify(body)
    });
    notify(`${status}${disposition ? ` / ${disposition}` : ''} applied.`, 'success');
    _caseData = null;
    openCase(caseName, { tab: itemType === 'incident' ? 'incidents' : 'findings', itemType, itemId });
  } catch (e) {
    notify(e.message || 'Failed to update review state.', 'error');
  }
}

async function assignToMe(caseName, itemType, itemId, pfx) {
  const reviewer = getReviewerName();
  if (!reviewer) {
    notify('Sign in before assigning review ownership.', 'error');
    return;
  }
  const ownerInput = document.getElementById(pfx + '-owner');
  if (ownerInput) ownerInput.value = reviewer;
  const statusEl = document.getElementById(pfx + '-status');
  const nextStatus = statusEl && (statusEl.value || 'Open') === 'Open' ? 'In Review' : (statusEl?.value || 'Open');
  const typePlural = itemType === 'finding' ? 'findings' : 'incidents';
  try {
    await apiJSON(`/api/cases/${encodeURIComponent(caseName)}/${typePlural}/${encodeURIComponent(itemId)}/review`, {
      method: 'PATCH',
      headers: authHeaders(),
      body: JSON.stringify({
        owner: reviewer,
        status: nextStatus,
        changed_by: reviewer,
      }),
    });
    notify(`Assigned ${itemType} ${itemId} to ${reviewer}.`, 'success');
    _caseData = null;
    openCase(caseName, { tab: itemType === 'incident' ? 'incidents' : 'findings', itemType, itemId });
  } catch (e) {
    notify(e.message || 'Failed to assign review ownership.', 'error');
  }
}

async function addNote(caseName, itemType, itemId, pfx) {
  const input = document.getElementById(pfx + '-note-input');
  const content = input.value.trim();
  if (!content) return;
  const typePlural = itemType === 'finding' ? 'findings' : 'incidents';
  const addBtn = document.getElementById(pfx + '-note-btn');
  setButtonLoading(addBtn, true, 'Adding...');
  try {
    await apiJSON(`/api/cases/${encodeURIComponent(caseName)}/${typePlural}/${encodeURIComponent(itemId)}/notes`, {
      method: 'POST', headers: authHeaders(), body: JSON.stringify({content, author: getReviewerName()})
    });
    input.value = '';
    loadReviewDetail(caseName, itemType, itemId, pfx);
    notify('Analyst note added.', 'success');
  } catch (e) {
    notify(e.message || 'Failed to add note.', 'error');
  } finally {
    setButtonLoading(addBtn, false);
  }
}

function toggleReviewPanel(pfx) {
  const body = document.getElementById(pfx + '-body');
  const toggle = document.getElementById(pfx + '-toggle');
  if (!body || !toggle) return;
  const isHidden = body.style.display === 'none';
  body.style.display = isHidden ? '' : 'none';
  toggle.textContent = isHidden ? 'Collapse Review' : 'Expand Review';
  document.getElementById(pfx + '-panel')?.classList.toggle('is-collapsed', !isHidden);
}

function toggleHistory(pfx) {
  const el = document.getElementById(pfx + '-history');
  if (el) el.style.display = el.style.display === 'none' ? '' : 'none';
}

// --- Guided Quick Check ---
const QUICK_CHECK_CHANNELS = [
  'Security',
  'System',
  'Microsoft-Windows-PowerShell/Operational',
  'Microsoft-Windows-Sysmon/Operational',
];

function openQuickCheck() {
  if (!authState.authenticated && !quickCheckToken) {
    openAuthOverlay();
    return;
  }
  showPage('quick-check');
  document.getElementById('quick-check-result').innerHTML = '';
  document.getElementById('quick-check-status').textContent = 'Ready to start. For a complete check, Windows may ask for administrator permission to read protected logs.';
}

function openQuickCheckUpload() {
  if (!authState.authenticated) {
    openAuthOverlay();
    setAuthMessage('Sign in to upload saved event log files. Quick Check can scan this computer without signing in.', 'normal');
    return;
  }
  setInvMode('upload');
  showPage('investigate');
  const status = document.getElementById('inv-status');
  if (status) status.textContent = 'Upload saved Windows event log (.evtx) files. This does not require administrator permission.';
}

function setQuickCheckStatus(message, tone = 'normal') {
  const el = document.getElementById('quick-check-status');
  if (!el) return;
  el.textContent = message;
  el.style.color = tone === 'error' ? 'var(--red)' : tone === 'success' ? 'var(--green)' : tone === 'warn' ? 'var(--orange)' : 'var(--text2)';
}

async function startQuickCheck() {
  const button = document.getElementById('btn-quick-check');
  if (!button) return;
  button.disabled = true;
  setQuickCheckStatus('Checking whether Windows logs are available...', 'normal');
  try {
    const health = await loadQuickCheckLiveHealth();
    if (!health?.is_windows) {
      setQuickCheckStatus('Live checks are available only when Triage Engine runs on Windows. You can still use existing event log files.', 'warn');
      return;
    }
    if (!health.pywin32_available) {
      setQuickCheckStatus('This installation cannot read live Windows event logs yet. Use Event Log Files instead, or contact IT.', 'warn');
      return;
    }
    if (!health.is_elevated) {
      setQuickCheckStatus('Administrator permission is needed for the complete check. Approve the Windows prompt to continue; you can use Event Log Files instead if you decline.', 'warn');
      await requestQuickCheckElevation();
      return;
    }
    await queueQuickCheck();
  } catch (e) {
    setQuickCheckStatus(e.message || 'Could not start the check. You can use Event Log Files instead.', 'error');
  } finally {
    button.disabled = false;
  }
}

async function requestQuickCheckElevation() {
  const button = document.getElementById('btn-quick-check');
  if (button) button.disabled = true;
  try {
    const response = await quickJSON('/api/quick/live/elevate', { method: 'POST' });
    if (response.already_elevated) {
      await loadQuickCheckLiveHealth();
      await queueQuickCheck();
      return;
    }
    setQuickCheckStatus('Windows is asking for administrator permission. After you approve, the elevated Triage Engine window will open automatically. If you choose No, use Event Log Files instead.', 'warn');
    await waitForElevatedDashboard(response.redirect_url);
  } catch (e) {
    setQuickCheckStatus(e.message || 'Windows could not request administrator permission. You can use Event Log Files instead.', 'error');
  } finally {
    if (button) button.disabled = false;
  }
}

async function waitForElevatedDashboard(redirectUrl) {
  if (!redirectUrl || !redirectUrl.startsWith('http://127.0.0.1:')) return;
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(redirectUrl + '/api/health', { credentials: 'same-origin' });
      if (response.ok) {
        // The original Start Check click is the user's authorization; resume
        // only after the new elevated process becomes healthy.
        window.location.assign(redirectUrl + '/?quick_check=1');
        return;
      }
    } catch (_ignored) {
      // A declined UAC request never starts the alternate local server.
    }
    await new Promise(resolve => setTimeout(resolve, 750));
  }
  setQuickCheckStatus('Administrator permission was not confirmed. No scan was started. You can try again or use Event Log Files instead.', 'warn');
}

async function queueQuickCheck() {
  const button = document.getElementById('btn-quick-check');
  if (button) button.disabled = true;
  setQuickCheckStatus('Checking recent Windows activity. This can take a few minutes...', 'normal');
  try {
    const response = await quickJSON('/api/quick/investigate/live', { method: 'POST' });
    setQuickCheckStatus('Check in progress. Reading recent Windows activity...', 'normal');
    await pollQuickCheckJob(response.job_id, response.case_name);
  } finally {
    if (button) button.disabled = false;
  }
}

async function pollQuickCheckJob(jobId, caseName) {
  while (true) {
    const job = await quickJSON('/api/quick/jobs/' + encodeURIComponent(jobId));
    if (job.status === 'completed') {
      await showQuickCheckResult(job.case_name || caseName);
      return;
    }
    if (job.status === 'failed') {
      setQuickCheckStatus(`The check could not finish: ${job.message || 'unknown error'}. You can export event logs manually or contact IT.`, 'error');
      return;
    }
    setQuickCheckStatus(`${job.stage || 'Checking'}: ${job.message || 'working...'}`, 'normal');
    await new Promise(resolve => setTimeout(resolve, 1200));
  }
}

async function showQuickCheckResult(caseName) {
  const data = await quickJSON('/api/quick/cases/' + encodeURIComponent(caseName));
  const disposition = data.triage_disposition || data.case?.triage_disposition || {};
  const label = disposition.disposition || 'Investigate';
  const confidence = disposition.confidence || 'unknown';
  // `reasons`, `telemetry_gaps`, and `recommended_next` are the persisted
  // deterministic TriageDisposition schema. The alternate keys retain
  // compatibility with early report payloads.
  const factors = Array.isArray(disposition.reasons) ? disposition.reasons : (Array.isArray(disposition.supporting_factors) ? disposition.supporting_factors : []);
  const gaps = Array.isArray(disposition.telemetry_gaps) ? disposition.telemetry_gaps : (Array.isArray(disposition.missing_telemetry) ? disposition.missing_telemetry : []);
  const nextSteps = Array.isArray(disposition.recommended_next) ? disposition.recommended_next : (Array.isArray(disposition.next_steps) ? disposition.next_steps : []);
  const result = document.getElementById('quick-check-result');
  const stateClass = label === 'Escalate'
    ? 'action-required'
    : label === 'No promoted incident'
      ? 'no-promoted-incident'
      : 'review-recommended';
  setQuickCheckStatus('Check complete. Review the result below.', 'success');
  result.innerHTML = `
    <div class="quick-check-disposition ${esc(stateClass)}">
      <div class="hero-eyebrow">Result</div>
      <div class="card-title" style="font-size:25px">${esc(label)}</div>
      <div class="subtle-hint">Confidence: ${esc(confidence)}${disposition.confidence_score !== undefined ? ` (${esc(confidencePercent(disposition.confidence_score))}%)` : ''}</div>
    </div>
    ${factors.length ? `<div><div class="card-title" style="font-size:16px">What we found</div><ul class="health-guidance">${factors.map(item => `<li>${esc(item)}</li>`).join('')}</ul></div>` : ''}
    ${gaps.length ? `<div><div class="card-title" style="font-size:16px">What could not be checked</div><ul class="health-guidance">${gaps.map(item => `<li>${esc(item)}</li>`).join('')}</ul></div>` : ''}
    ${nextSteps.length ? `<div><div class="card-title" style="font-size:16px">What to do next</div><ul class="health-guidance">${nextSteps.map(item => `<li>${esc(item)}</li>`).join('')}</ul></div>` : ''}
    <div class="auth-actions">
      <button class="btn btn-primary" onclick='downloadQuickCheckBundle(${jsv(caseName)})'>Export Results for IT</button>
      <button class="btn btn-ghost" onclick='openQuickCheckTechnicalDetails(${jsv(caseName)})'>See Technical Details</button>
      <button class="btn btn-ghost" onclick="openQuickCheck()">Run Another Check</button>
    </div>`;
}

async function loadQuickCheckLiveHealth() {
  const health = await quickJSON('/api/quick/live/health');
  return health;
}

function openQuickCheckTechnicalDetails(caseName) {
  if (!authState.authenticated) {
    openAuthOverlay();
    setAuthMessage('Sign in to review technical case details.', 'normal');
    return;
  }
  openCase(caseName);
}

async function downloadQuickCheckBundle(caseName) {
  try {
    if (!quickCheckToken) throw new Error('Quick Check session has expired. Refresh the page and try again.');
    const headers = { 'X-Triage-Quick-Token': quickCheckToken };
    if (authState.csrfToken) headers['X-CSRF-Token'] = authState.csrfToken;
    const response = await fetch(API + '/api/quick/cases/' + encodeURIComponent(caseName) + '/bundle', {
      method: 'POST', credentials: 'same-origin', headers,
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.detail || 'Bundle export failed.');
    }
    const blob = await response.blob();
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `triage-${caseName}-bundle.zip`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(link.href);
    notify('Results package downloaded.', 'success');
  } catch (e) {
    notify(e.message || 'Bundle export failed.', 'error');
  }
}

async function downloadCaseBundle(caseName) {
  try {
    const response = await apiFetch('/api/cases/' + encodeURIComponent(caseName) + '/bundle', { method: 'POST' });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.detail || 'Bundle export failed.');
    }
    const blob = await response.blob();
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `triage-${caseName}-bundle.zip`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(link.href);
    notify('Results package downloaded.', 'success');
  } catch (e) {
    notify(e.message || 'Bundle export failed.', 'error');
  }
}

// --- Investigation ---
function setInvMode(mode) {
  invMode = mode;
  document.getElementById('inv-upload-section').style.display = mode === 'upload' ? '' : 'none';
  document.getElementById('inv-path-section').style.display = mode === 'path' ? '' : 'none';
  document.getElementById('inv-live-section').style.display = mode === 'live' ? '' : 'none';
  document.getElementById('btn-upload-mode').style.background = mode === 'upload' ? 'var(--accent)' : 'var(--surface2)';
  document.getElementById('btn-upload-mode').style.color = mode === 'upload' ? '#fff' : 'var(--text)';
  document.getElementById('btn-path-mode').style.background = mode === 'path' ? 'var(--accent)' : 'var(--surface2)';
  document.getElementById('btn-path-mode').style.color = mode === 'path' ? '#fff' : 'var(--text)';
  document.getElementById('btn-live-mode').style.background = mode === 'live' ? 'var(--accent)' : 'var(--surface2)';
  document.getElementById('btn-live-mode').style.color = mode === 'live' ? '#fff' : 'var(--text)';
  if (mode === 'live') loadLiveHealth();
}

function toggleLiveRecommendedChannels() {
  const checked = !!document.getElementById('inv-live-recommended')?.checked;
  document.querySelectorAll('.inv-live-channel').forEach(el => {
    el.checked = checked;
  });
}

function getSelectedLiveChannels() {
  return Array.from(document.querySelectorAll('.inv-live-channel:checked')).map(el => el.value);
}

// File handling
const dz = document.getElementById('dropzone');
const fi = document.getElementById('file-input');
dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('dragover'); });
dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));
dz.addEventListener('drop', e => { e.preventDefault(); dz.classList.remove('dragover'); handleFiles(e.dataTransfer.files); });
fi.addEventListener('change', () => handleFiles(fi.files));

function handleFiles(fileList) {
  const files = Array.from(fileList);
  selectedFiles = files.filter(file => /\.evtx$/i.test(file.name) && file.size > 0);
  if (files.length !== selectedFiles.length) notify('Only non-empty .evtx files can be investigated.', 'error');
  document.getElementById('file-list').textContent = selectedFiles.map(f => f.name + ' (' + (f.size/1024).toFixed(0) + ' KB)').join(', ');
}

async function startInvestigation() {
  const caseName = document.getElementById('inv-case-name').value.trim();
  const sigma = document.getElementById('inv-sigma').checked;
  const statusEl = document.getElementById('inv-status');
  const btn = document.getElementById('btn-start');

  if (invMode === 'upload') {
    if (!selectedFiles.length) { statusEl.innerHTML = '<span style="color:var(--red)">Please select EVTX files.</span>'; return; }
    btn.disabled = true;
    statusEl.innerHTML = '<span style="color:var(--blue)">Uploading files...</span>';
    const form = new FormData();
    selectedFiles.forEach(f => form.append('files', f));
    const params = new URLSearchParams();
    if (caseName) params.set('case_name', caseName);
    if (sigma) params.set('enable_sigma', 'true');
    params.set('acquisition_method', 'upload');
    try {
      const res = await apiJSON('/api/investigate?' + params.toString(), { method: 'POST', body: form });
      btn.disabled = false;
      statusEl.innerHTML = `<span style="color:var(--green)">Job started: ${esc(res.job_id)} &mdash; Case: ${esc(res.case_name)}</span>`;
      notify(`Investigation queued for ${res.case_name}.`, 'info');
      pollJob(res.job_id);
    } catch (e) {
      btn.disabled = false;
      statusEl.innerHTML = `<span style="color:var(--red)">${esc(e.message || 'Failed to queue investigation.')}</span>`;
    }
  } else if (invMode === 'path') {
    const evtxPath = document.getElementById('inv-evtx-path').value.trim();
    if (!evtxPath) { statusEl.innerHTML = '<span style="color:var(--red)">Please enter a path.</span>'; return; }
    btn.disabled = true;
    statusEl.innerHTML = '<span style="color:var(--blue)">Starting investigation...</span>';
    const params = new URLSearchParams({evtx_path: evtxPath});
    if (caseName) params.set('case_name', caseName);
    if (sigma) params.set('enable_sigma', 'true');
    params.set('acquisition_method', 'portable_collector');
    try {
      const res = await apiJSON('/api/investigate/path?' + params.toString(), { method: 'POST' });
      btn.disabled = false;
      statusEl.innerHTML = `<span style="color:var(--green)">Job started: ${esc(res.job_id)} &mdash; Case: ${esc(res.case_name)}</span>`;
      notify(`Investigation queued for ${res.case_name}.`, 'info');
      pollJob(res.job_id);
    } catch (e) {
      btn.disabled = false;
      statusEl.innerHTML = `<span style="color:var(--red)">${esc(e.message || 'Failed to queue investigation.')}</span>`;
    }
  } else {
    const channels = getSelectedLiveChannels();
    const sinceMinutes = parseInt(document.getElementById('inv-live-since')?.value || '30', 10);
    if (!channels.length) { statusEl.innerHTML = '<span style="color:var(--red)">Select at least one live channel.</span>'; return; }
    btn.disabled = true;
    statusEl.innerHTML = '<span style="color:var(--blue)">Starting live investigation...</span>';
    try {
      const res = await apiJSON('/api/investigate/live', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({
          case_name: caseName || null,
          enable_sigma: sigma,
          since_minutes: sinceMinutes,
          channels,
          acquisition_method: 'local_live',
        }),
      });
      btn.disabled = false;
      statusEl.innerHTML = `<span style="color:var(--green)">Live job started: ${esc(res.job_id)} &mdash; Case: ${esc(res.case_name)}</span>`;
      notify(`Live investigation queued for ${res.case_name}.`, 'info');
      showPage('jobs');
      pollJob(res.job_id);
    } catch (e) {
      btn.disabled = false;
      statusEl.innerHTML = `<span style="color:var(--red)">${esc(e.message || 'Failed to queue live investigation.')}</span>`;
    }
  }
}

async function pollJob(jobId) {
  const statusEl = document.getElementById('inv-status');
  const poll = setInterval(async () => {
    try {
      const job = await apiJSON('/api/jobs/' + jobId);
      if (job.status === 'completed') {
        clearInterval(poll);
        statusEl.innerHTML = `<span style="color:var(--green)">&#10003; Investigation complete! </span><a href="#" onclick='openCase(${jsv(job.case_name)});return false' style="color:var(--accent)">View case &rarr;</a>`;
        notify(`Investigation complete for ${job.case_name}.`, 'success');
      } else if (job.status === 'failed') {
        clearInterval(poll);
        statusEl.innerHTML = `<span style="color:var(--red)">&#10007; Failed at stage: ${esc(job.stage||'')} &mdash; ${esc(job.message||'')}</span>`;
        notify(`Investigation failed for ${job.case_name || job.job_id}.`, 'error');
      } else {
        statusEl.innerHTML = `<span style="color:var(--blue)">&#9679; ${esc(job.stage||'...')} &mdash; ${esc(job.message||'Running...')}</span>`;
      }
    } catch (e) {
      clearInterval(poll);
      statusEl.innerHTML = `<span style="color:var(--red)">${esc(e.message || 'Lost job status during polling.')}</span>`;
    }
  }, 2000);
}

// --- Jobs ---
function compareJobs(a, b, sort) {
  if (sort === 'status_asc') return String(a.status||'').localeCompare(String(b.status||''));
  if (sort === 'case_asc') return String(a.case_name||'').localeCompare(String(b.case_name||''));
  return safeDate(b.updated_at || b.started_at) - safeDate(a.updated_at || a.started_at);
}

function isJobSelectable(job) {
  return !!job && !['queued', 'running'].includes(String(job.status || '').toLowerCase());
}

function syncJobsSelectionUI(pagedJobs = []) {
  const selectableVisible = pagedJobs.filter(isJobSelectable).map(j => j.job_id);
  const selectedVisible = selectableVisible.filter(id => selectedJobIds.has(id));
  const selectAll = document.getElementById('jobs-select-all');
  if (selectAll) {
    selectAll.checked = selectableVisible.length > 0 && selectedVisible.length === selectableVisible.length;
    selectAll.indeterminate = selectedVisible.length > 0 && selectedVisible.length < selectableVisible.length;
  }
  const deleteBtn = document.getElementById('jobs-delete-selected');
  if (deleteBtn) deleteBtn.disabled = selectedJobIds.size === 0;
}

function toggleJobSelection(jobId, checked) {
  if (!jobId) return;
  if (checked) selectedJobIds.add(jobId);
  else selectedJobIds.delete(jobId);
  updateJobsView();
}

function toggleVisibleJobsSelection(checked) {
  const jobs = [..._jobsCache].sort((a, b) => compareJobs(a, b, tableState.jobs.sort));
  const paged = paginate(jobs, 'jobs');
  paged.filter(isJobSelectable).forEach(job => {
    if (checked) selectedJobIds.add(job.job_id);
    else selectedJobIds.delete(job.job_id);
  });
  updateJobsView();
}

function clearSelectedJobs() {
  if (!selectedJobIds.size) return;
  selectedJobIds = new Set();
  updateJobsView();
}

async function deleteSelectedJobs() {
  const ids = Array.from(selectedJobIds);
  if (!ids.length) {
    notify('Select one or more completed jobs first.', 'error');
    return;
  }
  if (!confirm(`Remove ${ids.length} job record(s) from history? Their cases and evidence are kept.`)) return;
  try {
    const result = await apiJSON('/api/jobs/delete', {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ job_ids: ids }),
    });
    selectedJobIds = new Set();
    const deletedCount = Array.isArray(result.deleted) ? result.deleted.length : 0;
    const skippedCount = Array.isArray(result.skipped) ? result.skipped.length : 0;
    await loadJobs();
    notify(
      skippedCount
        ? `Removed ${deletedCount} job record(s). Skipped ${skippedCount} active or missing job(s).`
        : `Removed ${deletedCount} job record(s) from history; their cases are unchanged.`,
      skippedCount ? 'info' : 'success'
    );
  } catch (e) {
    notify(e.message || 'Failed to delete selected jobs.', 'error');
  }
}

function updateJobsView() {
  const tb = document.getElementById('jobs-table');
  tableState.jobs.sort = document.getElementById('jobs-sort')?.value || tableState.jobs.sort;
  persistTablePreferences();
  const jobs = [..._jobsCache].sort((a, b) => compareJobs(a, b, tableState.jobs.sort));
  if (!jobs.length) {
    renderTableMessage('jobs-table', 6, 'No active jobs.');
    renderPagination('jobs', 0, 0);
    setMeta('jobs-meta', 'No active jobs.');
    syncJobsSelectionUI([]);
    return;
  }
  const paged = paginate(jobs, 'jobs');
  tb.innerHTML = paged.map(j => {
    const canOpen = !!j.case_name && !!j.case_available && (j.status === 'completed' || j.status === 'failed');
    const stale = !!j.case_name && !j.case_available;
    const selectable = isJobSelectable(j);
    const checked = selectedJobIds.has(j.job_id) ? ' checked' : '';
    return `<tr class="${stale ? 'job-row-stale' : ''}"${canOpen ? ` onclick='openCase(${jsv(j.case_name)})'` : ''}>
    <td onclick="event.stopPropagation()">${selectable ? `<input type="checkbox"${checked} onclick='toggleJobSelection(${jsv(j.job_id)}, this.checked)'>` : `<span class="stale-note">-</span>`}</td>
    <td style="font-family:monospace">${esc(j.job_id||'')}</td>
    <td>${canOpen ? `<a href="#" class="table-link" onclick='event.preventDefault();event.stopPropagation();openCase(${jsv(j.case_name)})'>${esc(j.case_name||'')}</a>` : `${esc(j.case_name||'')} ${j.case_name && !j.case_available ? `<div class="stale-note">${esc(j.case_missing_reason || 'Artifacts unavailable')}</div>` : ''}`}</td>
    <td>${esc(j.stage||'')}</td>
    <td><span class="badge badge-${esc(j.status||'unknown')}">${esc(j.status||'unknown')}</span></td>
    <td style="color:var(--text2);font-size:13px">${esc(j.message||'')}</td>
  </tr>`;
  }).join('');
  renderPagination('jobs', jobs.length, paged.length);
  const staleCount = jobs.filter(j => j.case_name && !j.case_available).length;
  const selectedCount = selectedJobIds.size;
  setMeta('jobs-meta', staleCount ? `${jobs.length} job(s) in view · ${staleCount} archived or incomplete case(s)${selectedCount ? ` · ${selectedCount} selected` : ''}` : `${jobs.length} job(s) in view${selectedCount ? ` · ${selectedCount} selected` : ''}`);
  syncJobsSelectionUI(paged);
}

// --- Util ---
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char])); }
function displayInputSource(value) {
  const text = String(value || '').trim();
  if (!text) return '';
  if (text.toLowerCase().startsWith('live:')) {
    const channels = text.slice(5).split(',').map(item => item.trim()).filter(Boolean);
    return channels.length ? `Live Windows (${channels.join(', ')})` : 'Live Windows';
  }
  const normalized = text.replace(/\\/g, '/').replace(/\/+$/, '');
  if (/^[A-Za-z]:[\\/]/.test(text) || normalized.startsWith('./') || normalized.startsWith('../') || normalized.includes('/')) {
    const parts = normalized.split('/').filter(Boolean);
    return parts.length ? parts[parts.length - 1] : normalized;
  }
  return text;
}

// Initialization follows workspace helpers.
