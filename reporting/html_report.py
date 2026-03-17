"""HTML reporting for legacy mode and case-based artifact mode."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict

from triage_engine.display import display_input_source


def _read_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _safe_json_for_script(value: Any) -> str:
    """Serialize JSON safely for inline <script> embedding."""
    return (
        json.dumps(value)
        .replace("</", "<\\/")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def generate_from_artifacts(
    findings_path: str,
    timeline_path: str,
    graph_path: str,
    output_path: str,
) -> None:
    findings_data = _read_json(findings_path)
    timeline_data = _read_json(timeline_path)
    graph_data = _read_json(graph_path)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    template = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Triage Case Report</title>
<script src="https://unpkg.com/cytoscape/dist/cytoscape.min.js"></script>
<style>
:root {
  --bg: #eef2f7;
  --panel: #ffffff;
  --ink: #0f172a;
  --muted: #64748b;
  --line: #dbe3ee;
  --accent: #1d4ed8;
  --accent-soft: #dbeafe;
  --danger: #b91c1c;
  --warning: #b45309;
  --success: #047857;
}
body { font-family: Segoe UI, Arial, sans-serif; margin: 0; background: var(--bg); color: var(--ink); }
header { background: linear-gradient(135deg, #0f172a, #1e3a8a); color: #fff; padding: 18px 20px; }
header h1 { margin: 0; font-size: 22px; }
header p { margin: 6px 0 0; font-size: 13px; color: #dbeafe; }
.header-top { display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; align-items: center; }
.header-tools { display: flex; gap: 8px; align-items: center; }
.header-btn { border: 1px solid rgba(219, 234, 254, 0.7); background: rgba(255, 255, 255, 0.12); color: #fff; padding: 7px 12px; border-radius: 999px; cursor: pointer; font-size: 12px; }
.pdf-hint { margin-top: 8px; color: #dbeafe; font-size: 12px; }
nav { display: flex; gap: 8px; padding: 12px 16px; background: #e2e8f0; flex-wrap: wrap; border-bottom: 1px solid #cbd5e1; }
nav button { border: 1px solid #94a3b8; background: #fff; padding: 7px 12px; border-radius: 999px; cursor: pointer; color: var(--ink); }
nav button.active { background: var(--accent); color: white; border-color: var(--accent); }
.panel { display: none; padding: 16px; }
.panel.active { display: block; }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 12px; box-shadow: 0 6px 18px rgba(15, 23, 42, 0.04); }
.card h3 { margin: 0; font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
.card .val { font-size: 20px; margin-top: 8px; font-weight: 700; }
.card-grid { display: grid; gap: 12px; }
.incident-card { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 14px; box-shadow: 0 8px 22px rgba(15, 23, 42, 0.05); }
.incident-head { display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; flex-wrap: wrap; }
.incident-head h3 { margin: 0 0 6px; font-size: 18px; }
.subtle { color: var(--muted); font-size: 13px; }
.meta { display: flex; gap: 8px; flex-wrap: wrap; margin: 10px 0; }
.kv { display: inline-flex; gap: 5px; align-items: center; padding: 5px 8px; border-radius: 999px; background: #f8fafc; border: 1px solid var(--line); font-size: 12px; }
.k { color: var(--muted); text-transform: uppercase; font-size: 11px; }
.chip { display: inline-flex; gap: 5px; align-items: center; padding: 4px 9px; border-radius: 999px; border: 1px solid #bfdbfe; background: var(--accent-soft); color: #1e3a8a; font-size: 12px; cursor: pointer; }
.chip.passive { cursor: default; border-color: #e2e8f0; background: #f8fafc; color: var(--muted); }
.severity-critical { color: var(--danger); font-weight: 700; }
.severity-high { color: #be123c; font-weight: 700; }
.severity-medium { color: var(--warning); font-weight: 700; }
.severity-low { color: var(--success); font-weight: 700; }
.confidence { font-weight: 700; }
.evidence-list { margin: 10px 0 0; padding-left: 18px; }
.evidence-list li { margin: 6px 0; }
.next-step { margin-top: 12px; padding: 10px 12px; border-radius: 10px; border: 1px solid #dbeafe; background: #eff6ff; }
.filterbar { display: flex; justify-content: space-between; gap: 12px; align-items: center; flex-wrap: wrap; background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 10px 12px; margin-bottom: 12px; }
.filter-summary { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.filter-actions button { border: 1px solid #cbd5e1; background: #fff; border-radius: 8px; padding: 6px 10px; cursor: pointer; }
table { border-collapse: collapse; width: 100%; background: var(--panel); border: 1px solid var(--line); border-radius: 12px; overflow: hidden; }
th, td { border-bottom: 1px solid #edf2f7; padding: 9px; text-align: left; font-size: 13px; vertical-align: top; }
th { background: #f8fafc; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; }
tr:hover td { background: #f8fbff; }
.details { margin-top: 6px; background: #f8fafc; padding: 8px; border-radius: 8px; border: 1px solid #e2e8f0; font-family: Consolas, monospace; white-space: pre-wrap; font-size: 12px; }
#graph { height: 520px; border: 1px solid var(--line); background: var(--panel); border-radius: 12px; }
.split { display: grid; grid-template-columns: 2fr 1fr; gap: 12px; }
.search { margin-bottom: 8px; }
input[type='text'] { width: 100%; padding: 8px; border: 1px solid #cbd5e1; border-radius: 8px; }
.muted { color: var(--muted); }
.inline-pills { display: flex; gap: 6px; flex-wrap: wrap; }
.list-block { margin-top: 12px; }
.list-block ul { margin: 6px 0 0; padding-left: 18px; }
.list-block li { margin: 4px 0; }
.executive-summary { margin-bottom: 12px; background: linear-gradient(165deg, #ffffff, #f8fbff); }
.executive-head { display: flex; justify-content: space-between; gap: 12px; align-items: center; flex-wrap: wrap; }
.executive-head h3 { margin: 0; }
.priority-badge { display: inline-flex; align-items: center; justify-content: center; border-radius: 999px; padding: 5px 10px; font-size: 12px; font-weight: 700; letter-spacing: 0.04em; border: 1px solid transparent; }
.priority-p1 { background: #fee2e2; color: #991b1b; border-color: #fecaca; }
.priority-p2 { background: #ffedd5; color: #9a3412; border-color: #fed7aa; }
.priority-p3 { background: #fef9c3; color: #854d0e; border-color: #fde68a; }
.priority-p4 { background: #dcfce7; color: #166534; border-color: #bbf7d0; }
.exec-metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 8px; margin-top: 12px; }
.exec-metric { border: 1px solid var(--line); border-radius: 10px; background: #fff; padding: 8px 10px; }
.exec-metric .label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
.exec-metric .value { margin-top: 4px; font-size: 20px; font-weight: 700; }
.executive-grid { margin-top: 12px; display: grid; grid-template-columns: repeat(2, minmax(220px, 1fr)); gap: 10px; }
.executive-block { border: 1px solid var(--line); border-radius: 10px; background: #fff; padding: 10px; }
.executive-block h4 { margin: 0 0 6px; font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
.executive-block p { margin: 0; }
.exec-list { margin: 8px 0 0; padding-left: 16px; }
.exec-list li { margin: 4px 0; }
.mitre-matrix { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin-top: 10px; }
.mitre-tactic { background: #f8fafc; border: 1px solid var(--line); border-radius: 10px; padding: 10px; }
.mitre-head { display: flex; justify-content: space-between; gap: 8px; align-items: center; flex-wrap: wrap; }
.mitre-head h4 { margin: 0; font-size: 14px; }
.mitre-techniques { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
.mitre-empty { border: 1px dashed var(--line); border-radius: 10px; padding: 12px; background: #f8fafc; color: var(--muted); }
details > summary { cursor: pointer; color: var(--accent); }
@media (max-width: 900px) { .split { grid-template-columns: 1fr; } .executive-grid { grid-template-columns: 1fr; } }
@media print {
  @page { size: auto; margin: 12mm; }
  body { background: #fff; color: #111827; font-size: 11pt; }
  header { background: #fff !important; color: #111827; border-bottom: 2px solid #cbd5e1; padding: 0 0 10px; margin-bottom: 10px; }
  header p { color: #334155 !important; }
  nav, .filterbar, .search, .header-tools, .pdf-hint, .filter-actions, button, input, #graph-panel, #raw { display: none !important; }
  .panel { display: block !important; padding: 0; margin: 0 0 14px; page-break-inside: avoid; }
  .incident-card, .card, .executive-block, .exec-metric, .mitre-tactic { box-shadow: none !important; break-inside: avoid; }
  table { font-size: 10pt; }
  th, td { padding: 6px; }
  .chip { border-color: #cbd5e1; color: #1e293b; background: #fff; }
  .chip.passive { color: #475569; }
  .details { border-color: #cbd5e1; background: #fff; }
}
</style>
</head>
<body>
<header>
  <div class="header-top">
    <h1>Triage Case Report</h1>
    <div class="header-tools">
      <button class="header-btn" onclick="window.print()">Print / Save PDF</button>
    </div>
  </div>
  <p id="header-meta"></p>
  <p class="pdf-hint">Download PDF hint: use your browser print dialog (Ctrl+P/Cmd+P) and choose "Save as PDF".</p>
</header>
<nav>
  <button class="active" onclick="showPanel('overview', this)">Overview</button>
  <button onclick="showPanel('incidents', this)">Incidents</button>
  <button onclick="showPanel('mitre', this)">MITRE ATT&CK</button>
  <button onclick="showPanel('timeline', this)">Timeline</button>
  <button onclick="showPanel('graph-panel', this)">Entity Graph</button>
  <button onclick="showPanel('raw', this)">Raw Events</button>
</nav>

<section id="overview" class="panel active">
  <div class="incident-card executive-summary" id="executive-summary-card">
    <div class="executive-head">
      <div>
        <h3>Executive Summary</h3>
        <p class="subtle" id="executive-summary-subtitle"></p>
      </div>
      <span id="executive-priority-badge" class="priority-badge priority-p4">P4</span>
    </div>
    <div class="exec-metrics" id="executive-metrics"></div>
    <div class="executive-grid">
      <div class="executive-block">
        <h4>Impact and Confidence</h4>
        <p id="executive-impact"></p>
        <p class="subtle" id="executive-confidence"></p>
      </div>
      <div class="executive-block">
        <h4>Affected Scope</h4>
        <div class="inline-pills" id="executive-scope"></div>
        <p class="subtle" id="executive-time-range"></p>
      </div>
      <div class="executive-block">
        <h4>Collection Quality</h4>
        <p id="executive-collection-summary"></p>
        <ul class="exec-list" id="executive-collection-details"></ul>
      </div>
      <div class="executive-block">
        <h4>Recommended Actions</h4>
        <ol class="exec-list" id="executive-actions"></ol>
      </div>
    </div>
  </div>
  <div class="filterbar">
    <div class="filter-summary" id="filter-summary"></div>
    <div class="filter-actions"><button onclick="clearFilters()">Clear Pivots</button></div>
  </div>
  <div class="kpis" id="overview-cards"></div>
  <p><small id="overview-summary"></small></p>
  <div class="incident-card" id="overview-spotlight"></div>
</section>

<section id="incidents" class="panel">
  <div class="filterbar">
    <div class="filter-summary" id="incident-filter-summary"></div>
    <div class="filter-actions"><button onclick="clearFilters()">Clear Pivots</button></div>
  </div>
  <div id="incidents-body" class="card-grid"></div>
</section>

<section id="mitre" class="panel">
  <div class="incident-card">
    <h3>MITRE ATT&CK Coverage Matrix</h3>
    <p class="subtle" id="mitre-summary"></p>
    <div id="mitre-matrix" class="mitre-matrix"></div>
  </div>
</section>

<section id="timeline" class="panel">
  <div class="filterbar">
    <div class="filter-summary" id="timeline-filter-summary"></div>
    <div class="filter-actions"><button onclick="clearFilters()">Clear Pivots</button></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Time</th><th>Type</th><th>Host</th><th>User</th><th>Process</th><th>Command</th><th>Summary</th><th>Related</th>
      </tr>
    </thead>
    <tbody id="timeline-body"></tbody>
  </table>
</section>

<section id="graph-panel" class="panel">
  <div class="split">
    <div id="graph"></div>
    <div>
      <div class="incident-card">
        <h3>Pivot Context</h3>
        <p class="subtle">Click a host, user, or IP node to pivot the rest of the report. Process and command nodes show evidence context without applying a filter.</p>
        <div id="pivot-details" class="details">No selection yet.</div>
      </div>
    </div>
  </div>
</section>

<section id="raw" class="panel">
  <div class="filterbar">
    <div class="filter-summary" id="raw-filter-summary"></div>
    <div class="filter-actions"><button onclick="clearFilters()">Clear Pivots</button></div>
  </div>
  <div class="incident-card" id="raw-summary-card"></div>
  <div class="search">
    <input type="text" id="raw-search" placeholder="Search raw events by host, user, IP, process, command, or event id..." oninput="renderRawEvents()"/>
  </div>
  <table>
    <thead><tr><th>Timestamp</th><th>Event ID</th><th>Host</th><th>User</th><th>Source IP</th><th>Process</th><th>Context</th></tr></thead>
    <tbody id="raw-body"></tbody>
  </table>
</section>

<script>
const FINDINGS = __FINDINGS_JSON__;
const TIMELINE = __TIMELINE_JSON__;
const GRAPH = __GRAPH_JSON__;
const GENERATED_AT = __GENERATED_AT__;
let cy = null;
let activeFilters = { host: '', user: '', ip: '' };

function esc(text) {
  return String(text || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function displayInputSource(value) {
  const text = String(value || '').trim();
  if (!text) return '';
  if (text.toLowerCase().startsWith('live:')) {
    const channels = text.slice(5).split(',').map(item => item.trim()).filter(Boolean);
    return channels.length ? `Live Windows (${channels.join(', ')})` : 'Live Windows';
  }
  const normalized = text.replace(/\\\\/g, '/').replace(/\\/+$/, '');
  if (/^[A-Za-z]:[\\/]/.test(text) || normalized.startsWith('./') || normalized.startsWith('../') || normalized.includes('/')) {
    const parts = normalized.split('/').filter(Boolean);
    return parts.length ? parts[parts.length - 1] : normalized;
  }
  return text;
}

function present(value) {
  return value && value !== '-' ? value : 'unknown';
}

function hasValue(value) {
  return Boolean(value && value !== '-' && value !== 'unknown');
}

function canonicalUser(obj) {
  return obj.user_canonical || obj.user || obj.subject_domain_user_canonical || obj.subject_domain_user || obj.target_domain_user_canonical || obj.target_domain_user || '';
}

function displayUser(obj) {
  return obj.user_display || obj.user || obj.subject_domain_user_display || obj.subject_domain_user || obj.target_domain_user_display || obj.target_domain_user || 'unknown';
}

function severityClass(value) {
  const sev = String(value || '').toLowerCase();
  return `severity-${sev || 'low'}`;
}

function entityChipHtml(type, value, label) {
  const clean = value || '';
  if (!hasValue(clean)) {
    return `<span class="chip passive">${esc(label || 'unknown')}</span>`;
  }
  return `<button class="chip" data-filter-type="${esc(type)}" data-filter-value="${esc(encodeURIComponent(clean))}">${esc(label || clean)}</button>`;
}

function bindFilterButtons(container) {
  (container || document).querySelectorAll('[data-filter-type]').forEach(btn => {
    btn.onclick = () => setFilter(btn.dataset.filterType, decodeURIComponent(btn.dataset.filterValue || ''));
  });
}

function filterSummaryHtml() {
  const chips = [];
  if (hasValue(activeFilters.host)) chips.push(entityChipHtml('host', activeFilters.host, `Host: ${activeFilters.host}`));
  if (hasValue(activeFilters.user)) chips.push(entityChipHtml('user', activeFilters.user, `User: ${activeFilters.user}`));
  if (hasValue(activeFilters.ip)) chips.push(entityChipHtml('ip', activeFilters.ip, `IP: ${activeFilters.ip}`));
  if (!chips.length) return '<span class="muted">No active pivots.</span>';
  return `<span class="muted">Active pivots:</span> ${chips.join(' ')}`;
}

function setFilter(type, value) {
  if (!hasValue(value)) return;
  activeFilters = { host: '', user: '', ip: '' };
  if (type === 'host') activeFilters.host = value;
  if (type === 'user') activeFilters.user = value;
  if (type === 'ip') activeFilters.ip = value;
  renderAll();
}

function clearFilters() {
  activeFilters = { host: '', user: '', ip: '' };
  renderAll();
}

function matchesFilters(obj) {
  const host = obj.host || obj.host_display || obj.computer || '';
  const users = [
    canonicalUser(obj),
    obj.subject_user_canonical || '',
    obj.target_user_canonical || '',
    obj.account_name_canonical || ''
  ].filter(Boolean);
  const ip = obj.source_ip || '';
  if (hasValue(activeFilters.host) && host !== activeFilters.host) return false;
  if (hasValue(activeFilters.user) && !users.includes(activeFilters.user)) return false;
  if (hasValue(activeFilters.ip) && ip !== activeFilters.ip && obj.destination_ip !== activeFilters.ip) return false;
  return true;
}

function showPanel(name, btn) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById(name).classList.add('active');
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  if (name === 'graph-panel') renderGraph();
}

function passivePills(values) {
  return (values || []).filter(Boolean).map(value => `<span class="chip passive">${esc(value)}</span>`).join(' ');
}

function detailList(title, values) {
  const items = (values || []).filter(Boolean);
  if (!items.length) return '';
  return `<div class="list-block"><strong>${esc(title)}</strong><ul>${items.map(item => `<li>${esc(displayInputSource(item))}</li>`).join('')}</ul></div>`;
}

function topRuleMetricLines(ruleMetrics, limit) {
  return (ruleMetrics || [])
    .slice(0, limit || 5)
    .map(row => `${row.rule}: raw ${row.raw_alert_count}, suppressed ${row.suppressed_alert_count}, deduplicated ${row.deduplicated_alert_count || 0}, findings ${row.finding_count}, incidents ${row.incident_count}`);
}

function tuningRecommendationLines(recommendations, limit) {
  return (recommendations || [])
    .slice(0, limit || 5)
    .map(item => `${item.rule}: ${item.suggestion} (${item.reason})`);
}

function campaignSummaryLines(campaigns, limit) {
  return (campaigns || [])
    .slice(0, limit || 5)
    .map(item => item.summary || `${item.key_type}: ${item.display_value}`);
}

const MITRE_TACTIC_ORDER = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact'
];

function titleCaseWords(value) {
  return String(value || '')
    .trim()
    .split(/\\s+/)
    .filter(Boolean)
    .map(part => `${part.slice(0, 1).toUpperCase()}${part.slice(1).toLowerCase()}`)
    .join(' ');
}

function normalizeMitreLabel(value) {
  const text = String(value || '').replace(/_/g, ' ').replace(/\\s+/g, ' ').trim();
  if (!text || text === '-' || text.toLowerCase() === 'unknown') return '';
  return titleCaseWords(text);
}

function uniqueValues(values) {
  const seen = new Set();
  const out = [];
  (values || []).forEach(value => {
    const clean = String(value || '').trim();
    if (!hasValue(clean)) return;
    if (seen.has(clean)) return;
    seen.add(clean);
    out.push(clean);
  });
  return out;
}

function toPriority(value) {
  const clean = String(value || '').toUpperCase();
  return /^P[1-4]$/.test(clean) ? clean : 'P4';
}

function priorityClass(value) {
  return `priority-${toPriority(value).toLowerCase()}`;
}

function collectFieldValues(items, fields) {
  const values = [];
  (items || []).forEach(item => {
    (fields || []).forEach(field => {
      if (hasValue(item[field])) values.push(item[field]);
    });
  });
  return uniqueValues(values);
}

function collectAffectedEntities(primaryValues, fallbackValues, limit) {
  const primary = uniqueValues(primaryValues);
  if (primary.length) return primary.slice(0, limit || 5);
  return uniqueValues(fallbackValues).slice(0, limit || 5);
}

function resolveTimeRange(caseData) {
  let firstSeen = caseData.first_seen || '';
  let lastSeen = caseData.last_seen || '';
  const timelineValues = uniqueValues((TIMELINE.timeline || []).map(row => row.timestamp || ''))
    .filter(value => value !== 'unknown')
    .sort();
  if (!hasValue(firstSeen) && timelineValues.length) firstSeen = timelineValues[0];
  if (!hasValue(lastSeen) && timelineValues.length) lastSeen = timelineValues[timelineValues.length - 1];
  return {
    first: hasValue(firstSeen) ? firstSeen : 'unknown',
    last: hasValue(lastSeen) ? lastSeen : 'unknown',
  };
}

function executiveActions(topIncident) {
  const candidates = [];
  if (topIncident) {
    candidates.push(...(topIncident.containment_guidance || []));
    candidates.push(...(topIncident.scope_next || []));
    candidates.push(...(topIncident.validation_steps || []));
    if (hasValue(topIncident.recommended_next)) candidates.push(topIncident.recommended_next);
  }
  const actions = uniqueValues(candidates).slice(0, 4);
  if (actions.length) return actions;
  return ['Review high-confidence evidence and validate scope across impacted hosts and users.'];
}

function renderExecutiveSummary(caseData, summaryData, collectionSummary, telemetry) {
  const topIncident = (FINDINGS.incidents || [])[0];
  const responsePriority = toPriority(caseData.response_priority || summaryData.response_priority || 'P4');
  const impactedHosts = collectAffectedEntities(
    caseData.hosts || [],
    collectFieldValues([].concat(FINDINGS.incidents || [], FINDINGS.findings || [], FINDINGS.signals || []), ['host', 'computer', 'host_display']),
    5
  );
  const impactedUsers = collectAffectedEntities(
    caseData.users_canonical || caseData.users || [],
    collectFieldValues([].concat(FINDINGS.incidents || [], FINDINGS.findings || [], FINDINGS.signals || []), ['user_display', 'user_canonical', 'user', 'subject_user', 'target_user']),
    5
  );
  const bounds = resolveTimeRange(caseData);
  const metricsHost = document.getElementById('executive-metrics');
  const metricRows = [
    ['Signals', summaryData.signal_count || 0],
    ['Findings', summaryData.finding_count || 0],
    ['Incidents', summaryData.incident_count || 0],
    ['Hosts', impactedHosts.length],
    ['Users', impactedUsers.length],
  ];
  metricsHost.innerHTML = metricRows
    .map(([label, value]) => `<div class="exec-metric"><div class="label">${esc(label)}</div><div class="value">${esc(value)}</div></div>`)
    .join('');

  const priorityBadge = document.getElementById('executive-priority-badge');
  priorityBadge.className = `priority-badge ${priorityClass(responsePriority)}`;
  priorityBadge.textContent = responsePriority;

  const impactText = topIncident
    ? `${esc(topIncident.severity || 'unknown')} severity incident: ${esc(topIncident.title || 'Unnamed incident')}`
    : 'No promoted incidents. Active findings still require analyst review.';
  const confidenceText = topIncident
    ? `Confidence: ${esc(topIncident.confidence || 'unknown')} (${esc(topIncident.confidence_score || '0')})`
    : `Confidence is distributed across ${esc(summaryData.finding_count || 0)} finding(s).`;

  document.getElementById('executive-summary-subtitle').textContent = `Case ${caseData.case_name || ''} generated ${GENERATED_AT}`;
  document.getElementById('executive-impact').innerHTML = impactText;
  document.getElementById('executive-confidence').innerHTML = confidenceText;

  const scopeParts = [];
  impactedHosts.forEach(host => scopeParts.push(entityChipHtml('host', host, `Host: ${host}`)));
  impactedUsers.forEach(user => scopeParts.push(entityChipHtml('user', user, `User: ${user}`)));
  document.getElementById('executive-scope').innerHTML = scopeParts.length
    ? scopeParts.join(' ')
    : '<span class="muted">No host/user scope metadata available.</span>';
  document.getElementById('executive-time-range').textContent = `Observed activity: ${bounds.first} -> ${bounds.last}`;

  const collectionSummaryText = collectionSummary.summary || 'Collection quality metadata not provided.';
  document.getElementById('executive-collection-summary').textContent = collectionSummaryText;
  const presentTelemetry = uniqueValues(telemetry.present || []);
  const missingTelemetry = uniqueValues(collectionSummary.telemetry_missing || telemetry.missing || []);
  const collectionDetails = [];
  if (presentTelemetry.length) collectionDetails.push(`Present telemetry: ${presentTelemetry.join(', ')}`);
  if (missingTelemetry.length) collectionDetails.push(`Missing telemetry: ${missingTelemetry.join(', ')}`);
  if (collectionSummary.warning_count) collectionDetails.push(`Collection warnings: ${collectionSummary.warning_count}`);
  if (collectionSummary.fallback_used) collectionDetails.push('Collection note: parser or API fallback was used.');
  if (!collectionDetails.length) collectionDetails.push('No collection gaps or warnings recorded.');
  document.getElementById('executive-collection-details').innerHTML = collectionDetails.map(line => `<li>${esc(line)}</li>`).join('');

  const actions = executiveActions(topIncident);
  document.getElementById('executive-actions').innerHTML = actions.map(action => `<li>${esc(action)}</li>`).join('');
  bindFilterButtons(document.getElementById('executive-summary-card'));
}

function renderMitreMatrix() {
  const summaryByTactic = (FINDINGS.summary || {}).by_tactic || {};
  const tacticCounts = {};
  Object.entries(summaryByTactic).forEach(([name, count]) => {
    const label = normalizeMitreLabel(name);
    if (!label) return;
    tacticCounts[label] = Number(count) || 0;
  });

  const tacticsToTechniques = new Map();
  const ensureTactic = (tactic) => {
    if (!tactic) return;
    if (!tacticsToTechniques.has(tactic)) tacticsToTechniques.set(tactic, new Set());
  };
  const addTechnique = (tacticValue, techniqueValue) => {
    const tactic = normalizeMitreLabel(tacticValue);
    if (!tactic) return;
    ensureTactic(tactic);
    String(techniqueValue || '')
      .split(/[,;|]/)
      .map(part => part.trim())
      .filter(part => hasValue(part))
      .forEach(part => tacticsToTechniques.get(tactic).add(part));
  };

  Object.keys(tacticCounts).forEach(ensureTactic);
  (FINDINGS.signals || []).forEach(signal => addTechnique(signal.mitre_tactic, signal.mitre_technique));
  (FINDINGS.incidents || []).forEach(incident => addTechnique(incident.mitre_tactic, incident.technique_summary));
  (FINDINGS.findings || []).forEach(finding => addTechnique(finding.mitre_tactic, finding.technique_summary));

  const ordered = Array.from(tacticsToTechniques.keys()).sort((a, b) => {
    const ai = MITRE_TACTIC_ORDER.indexOf(a);
    const bi = MITRE_TACTIC_ORDER.indexOf(b);
    const aRank = ai === -1 ? 999 : ai;
    const bRank = bi === -1 ? 999 : bi;
    if (aRank !== bRank) return aRank - bRank;
    return a.localeCompare(b);
  });

  const matrix = document.getElementById('mitre-matrix');
  if (!ordered.length) {
    matrix.innerHTML = '<div class="mitre-empty">No MITRE ATT&CK mappings were observed in this case.</div>';
    document.getElementById('mitre-summary').textContent = 'Observed tactics: 0 | techniques: 0';
    return;
  }

  let techniqueCount = 0;
  matrix.innerHTML = '';
  ordered.forEach(tactic => {
    const techniques = Array.from(tacticsToTechniques.get(tactic) || []).sort((a, b) => a.localeCompare(b));
    techniqueCount += techniques.length;
    const signalCount = tacticCounts[tactic] || techniques.length || 0;
    const card = document.createElement('div');
    card.className = 'mitre-tactic';
    card.innerHTML = `
      <div class="mitre-head">
        <h4>${esc(tactic)}</h4>
        <span class="chip passive">${esc(signalCount)} signal${signalCount === 1 ? '' : 's'}</span>
      </div>
      <div class="mitre-techniques">
        ${techniques.length ? techniques.map(tech => `<span class="chip passive">${esc(tech)}</span>`).join('') : '<span class="muted">Technique names not present in current artifacts.</span>'}
      </div>
    `;
    matrix.appendChild(card);
  });
  document.getElementById('mitre-summary').textContent = `Observed tactics: ${ordered.length} | observed techniques: ${techniqueCount}`;
}

function renderOverview() {
  const c = FINDINGS.case || {};
  const s = FINDINGS.summary || {};
  const suppression = c.suppression_summary || s.suppression_summary || {};
  const telemetry = c.telemetry_summary || {};
  const liveSummary = c.live_collection_summary || s.live_collection_summary || {};
  const collectionSummary = c.collection_quality_summary || s.collection_quality_summary || (liveSummary.summary ? {
    mode: 'live',
    summary: liveSummary.summary,
    source_kind: 'channels',
    source_count: liveSummary.channel_count || (liveSummary.channels || []).length || 0,
    parsed_event_count: liveSummary.parsed_event_count || 0,
    warning_count: liveSummary.warning_count || 0,
    warning_sources: liveSummary.warning_channels || [],
    permission_denied_sources: liveSummary.permission_denied_channels || [],
    fallback_used: (liveSummary.fallback_channels || 0) > 0,
    telemetry_missing: telemetry.missing || [],
    recommendations: liveSummary.recommendations || []
  } : {});
  const metrics = c.case_metrics || {};
  const ruleMetrics = s.rule_metrics || c.rule_metrics || [];
  const tuningRecommendations = s.tuning_recommendations || c.tuning_recommendations || [];
  const campaignSummary = s.campaign_summary || c.campaign_summary || [];
  const deduplicatedCount = s.deduplicated_alert_count || metrics.deduplicated_alert_count || 0;
  const postDedupCount = s.post_dedup_alert_count || metrics.post_dedup_alert_count || 0;
  document.getElementById('header-meta').textContent =
    `Case: ${c.case_name || ''} | Generated: ${GENERATED_AT} | Source: ${c.input_source_display || displayInputSource(c.input_source || '')}`;
  renderExecutiveSummary(c, s, collectionSummary, telemetry);

  const cards = [
    ['Case Name', c.case_name || ''],
    ['Primary Host', c.primary_host || 'unknown'],
    ['Primary User', c.primary_user || 'unknown'],
    ['Source IP', c.primary_source_ip || 'unknown'],
    ['Response Priority', c.response_priority || s.response_priority || 'P4'],
    ['Incidents', (FINDINGS.incidents || []).length],
    ['Findings', (FINDINGS.findings || []).length],
    ['Suppressed Alerts', suppression.suppressed_total || 0],
    ['Deduplicated Alerts', deduplicatedCount],
    ['First Seen', c.first_seen || 'unknown'],
    ['Last Seen', c.last_seen || 'unknown']
  ];

  const host = document.getElementById('overview-cards');
  host.innerHTML = '';
  cards.forEach(([name, value]) => {
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = `<h3>${esc(name)}</h3><div class="val">${esc(value)}</div>`;
    host.appendChild(card);
  });

  document.getElementById('overview-summary').textContent =
    `Signals: ${s.signal_count || 0} | Findings: ${s.finding_count || 0} | Incidents: ${s.incident_count || 0} | Raw alerts: ${s.raw_alert_count || metrics.raw_alert_count || 0} | Post-filter alerts: ${s.post_filter_alert_count || metrics.post_filter_alert_count || 0} | Deduplicated alerts: ${deduplicatedCount} | Post-dedup alerts: ${postDedupCount} | Finding promotion: ${s.finding_promotion_rate || metrics.finding_promotion_rate || 0} | Incident promotion: ${s.incident_promotion_rate || metrics.incident_promotion_rate || 0} | Timeline rows: ${(TIMELINE.summary || {}).total_rows || 0}`;

  const topIncident = (FINDINGS.incidents || [])[0];
  const spotlight = document.getElementById('overview-spotlight');
  if (!topIncident) {
    spotlight.innerHTML = `
      <h3>No incidents identified</h3>
      <p class="subtle">The report contains signals and findings, but nothing was promoted to an incident narrative.</p>
      ${detailList('Collection quality', collectionSummary.summary ? [collectionSummary.summary] : [])}
      ${detailList('Collection warning sources', collectionSummary.warning_sources || [])}
      ${detailList('Collection permission issues', collectionSummary.permission_denied_sources || [])}
      ${detailList('Collection recommendations', collectionSummary.recommendations || [])}
      ${detailList('Telemetry gaps', collectionSummary.telemetry_missing || telemetry.missing || [])}
      ${detailList('Collection notes', collectionSummary.fallback_used ? ['Parser or API fallback was used during collection.'] : [])}
      ${detailList('Suppression reasons', Object.entries(suppression.by_reason || {}).map(([reason, count]) => `${reason}: ${count}`))}
      ${detailList('Campaign summary', campaignSummaryLines(campaignSummary, 5))}
      ${detailList('Top rule metrics', topRuleMetricLines(ruleMetrics, 5))}
      ${detailList('Tuning recommendations', tuningRecommendationLines(tuningRecommendations, 5))}
    `;
  } else {
    spotlight.innerHTML = `
      <div class="incident-head">
        <div>
          <h3>${esc(topIncident.display_label || topIncident.id)} · ${esc(topIncident.title)}</h3>
          <p class="subtle">${esc(topIncident.summary || '')}</p>
        </div>
        <div class="${severityClass(topIncident.severity)}">${esc(topIncident.severity || 'unknown')}</div>
      </div>
      <div class="meta">
        <span class="kv"><span class="k">Host</span>${entityChipHtml('host', topIncident.host, present(topIncident.host))}</span>
        <span class="kv"><span class="k">User</span>${entityChipHtml('user', topIncident.user_canonical || topIncident.user, topIncident.user_display || present(topIncident.user))}</span>
        <span class="kv"><span class="k">IP</span>${entityChipHtml('ip', topIncident.source_ip, present(topIncident.source_ip))}</span>
        <span class="kv"><span class="k">Priority</span>${esc(c.response_priority || s.response_priority || 'P4')}</span>
        <span class="kv"><span class="k">Confidence</span><span class="confidence">${esc(topIncident.confidence || 'unknown')} (${esc(topIncident.confidence_score || '0')})</span></span>
      </div>
      ${topIncident.why_flagged ? `<p><strong>Why flagged:</strong> ${esc(topIncident.why_flagged)}</p>` : ''}
      ${topIncident.confidence_factors?.length ? `<div class="inline-pills"><strong>Confidence factors:</strong> ${passivePills(topIncident.confidence_factors)}</div>` : ''}
      ${topIncident.recommended_pivots?.length ? `<div class="inline-pills"><strong>Recommended pivots:</strong> ${passivePills(topIncident.recommended_pivots)}</div>` : ''}
      ${detailList('Collection quality', collectionSummary.summary ? [collectionSummary.summary] : [])}
      ${detailList('Collection warning sources', collectionSummary.warning_sources || [])}
      ${detailList('Collection permission issues', collectionSummary.permission_denied_sources || [])}
      ${detailList('Collection recommendations', collectionSummary.recommendations || [])}
      ${detailList('Collection notes', collectionSummary.fallback_used ? ['Parser or API fallback was used during collection.'] : [])}
      ${detailList('Containment guidance', topIncident.containment_guidance || [])}
      ${detailList('Scope next', topIncident.scope_next || [])}
      ${detailList('Validation steps', topIncident.validation_steps || [])}
      ${detailList('Telemetry gaps', collectionSummary.telemetry_missing || telemetry.missing || topIncident.telemetry_gaps || [])}
      ${detailList('Suppression reasons', Object.entries(suppression.by_reason || {}).map(([reason, count]) => `${reason}: ${count}`))}
      ${detailList('Campaign summary', campaignSummaryLines(campaignSummary, 5))}
      ${detailList('Top rule metrics', topRuleMetricLines(ruleMetrics, 5))}
      ${detailList('Tuning recommendations', tuningRecommendationLines(tuningRecommendations, 5))}
      <div class="next-step"><strong>Recommended next step:</strong> ${esc(topIncident.recommended_next || 'Review the linked evidence chain and scope related host and user activity.')}</div>`;
  }
  bindFilterButtons(spotlight);
}

function renderIncidents() {
  const filtered = (FINDINGS.incidents || []).filter(matchesFilters);
  const host = document.getElementById('incidents-body');
  host.innerHTML = '';

  if (!filtered.length) {
    host.innerHTML = `<div class="incident-card"><p class="subtle">No incidents match the current pivots.</p></div>`;
    return;
  }

  filtered.forEach(incident => {
    const remoteUrl = (incident.evidence_chain || []).map(step => step.remote_url).find(Boolean) || '';
    const taskName = (incident.evidence_chain || []).map(step => step.task_name).find(Boolean) || '';
    const createdUser = (incident.evidence_chain || []).map(step => step.created_username).find(Boolean) || '';
    const scriptExcerpt = (incident.evidence_chain || []).map(step => step.script_excerpt).find(Boolean) || incident.command_line || '';
    const evidence = (incident.evidence_chain || []).map(step => {
      const when = step.timestamp ? `${step.timestamp} · ` : '';
      const title = step.description || step.title || step.rule || step.label || step.id || 'evidence';
      const script = step.script_excerpt ? `<div class="subtle">Script: ${esc(step.script_excerpt)}</div>` : '';
      return `<li>${esc(when + title)}${script}</li>`;
    }).join('');

    const refs = []
      .concat((incident.finding_ids || []).map(id => `<span class="chip passive">${esc(id)}</span>`))
      .concat((incident.signal_ids || []).map(id => `<span class="chip passive">${esc(id)}</span>`))
      .join(' ');

    const card = document.createElement('div');
    card.className = 'incident-card';
    card.innerHTML = `
      <div class="incident-head">
        <div>
          <h3>${esc(incident.display_label || incident.id)} · ${esc(incident.title)}</h3>
          <p class="subtle">${esc(incident.summary || '')}</p>
        </div>
        <div>
          <div class="${severityClass(incident.severity)}">${esc(incident.severity || 'unknown')}</div>
          <div class="subtle">Confidence: ${esc(incident.confidence || 'unknown')} (${esc(incident.confidence_score || '0')})</div>
        </div>
      </div>
      <div class="meta">
        <span class="kv"><span class="k">Host</span>${entityChipHtml('host', incident.host, present(incident.host))}</span>
        <span class="kv"><span class="k">User</span>${entityChipHtml('user', incident.user_canonical || incident.user, incident.user_display || present(incident.user))}</span>
        <span class="kv"><span class="k">Source IP</span>${entityChipHtml('ip', incident.source_ip, present(incident.source_ip))}</span>
        ${hasValue(incident.process) ? `<span class="kv"><span class="k">Process</span>${esc(incident.process)}</span>` : ''}
        ${hasValue(scriptExcerpt) ? `<span class="kv"><span class="k">Script</span>${esc(scriptExcerpt)}</span>` : ''}
        ${hasValue(remoteUrl) ? `<span class="kv"><span class="k">Remote URL</span>${esc(remoteUrl)}</span>` : ''}
        ${hasValue(taskName) ? `<span class="kv"><span class="k">Task</span>${esc(taskName)}</span>` : ''}
        ${hasValue(createdUser) ? `<span class="kv"><span class="k">Created User</span>${esc(createdUser)}</span>` : ''}
        ${hasValue(incident.service) ? `<span class="kv"><span class="k">Service</span>${esc(incident.service)}</span>` : ''}
        ${hasValue(incident.technique_summary) ? `<span class="kv"><span class="k">Technique</span>${esc(incident.technique_summary)}</span>` : ''}
      </div>
      ${incident.why_flagged ? `<p><strong>Why flagged:</strong> ${esc(incident.why_flagged)}</p>` : ''}
      ${incident.confidence_factors?.length ? `<div class="inline-pills"><strong>Confidence factors:</strong> ${passivePills(incident.confidence_factors)}</div>` : ''}
      ${incident.recommended_pivots?.length ? `<div class="inline-pills"><strong>Recommended pivots:</strong> ${passivePills(incident.recommended_pivots)}</div>` : ''}
      <div>
        <strong>Evidence chain</strong>
        <ol class="evidence-list">${evidence || '<li>No evidence chain details available.</li>'}</ol>
      </div>
      ${detailList('Containment guidance', incident.containment_guidance || [])}
      ${detailList('Scope next', incident.scope_next || [])}
      ${detailList('Validation steps', incident.validation_steps || [])}
      ${detailList('Telemetry gaps', incident.telemetry_gaps || [])}
      ${refs ? `<div class="inline-pills"><strong>References:</strong> ${refs}</div>` : ''}
      <div class="next-step"><strong>Recommended next step:</strong> ${esc(incident.recommended_next || 'Review the linked host, user, and network activity around this incident.')}</div>`;
    host.appendChild(card);
    bindFilterButtons(card);
  });
}

function renderTimeline() {
  const filtered = (TIMELINE.timeline || []).filter(matchesFilters);
  const tbody = document.getElementById('timeline-body');
  tbody.innerHTML = '';

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="muted">No timeline rows match the current pivots.</td></tr>`;
    return;
  }

  filtered.forEach(row => {
    const refs = []
      .concat((row.related_ids?.incident_ids || []).map(id => `<span class="chip passive">${esc(id)}</span>`))
      .concat((row.related_ids?.finding_ids || []).map(id => `<span class="chip passive">${esc(id)}</span>`))
      .concat((row.related_ids?.signal_ids || []).map(id => `<span class="chip passive">${esc(id)}</span>`))
      .join(' ');

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${esc(row.timestamp || 'unknown')}</td>
      <td><span class="chip passive">${esc(row.type || 'unknown')}</span></td>
      <td>${entityChipHtml('host', row.host, row.host_display || present(row.host))}</td>
      <td>${entityChipHtml('user', row.user_canonical || row.user, row.user_display || present(row.user))}</td>
      <td>
        <div>${esc(row.process_display || present(row.process))}</div>
        ${hasValue(row.parent_process) ? `<div class="subtle">Parent: ${esc(row.parent_process)}</div>` : ''}
      </td>
      <td>
        <div>${esc(row.script_excerpt || row.command_line || 'unknown')}</div>
        ${hasValue(row.service) ? `<div class="subtle">Service: ${esc(row.service)}</div>` : ''}
        ${hasValue(row.source_ip) ? `<div class="subtle">IP: ${entityChipHtml('ip', row.source_ip, row.source_ip_display || present(row.source_ip))}</div>` : ''}
        ${hasValue(row.remote_url) ? `<div class="subtle">Remote URL: ${esc(row.remote_url)}</div>` : ''}
        ${hasValue(row.task_name) ? `<div class="subtle">Task: ${esc(row.task_name)}</div>` : ''}
        ${hasValue(row.created_username) ? `<div class="subtle">Created User: ${esc(row.created_username)}</div>` : ''}
      </td>
      <td>
        <div><strong>${esc(row.display_label || row.id)}</strong> · ${esc(row.title || '')}</div>
        <div class="${severityClass(row.severity)}">${esc(row.severity || 'unknown')} / ${esc(row.confidence || 'unknown')}</div>
        <div class="subtle">${esc(row.summary || '')}</div>
        ${hasValue(row.technique) ? `<div class="subtle">Technique: ${esc(row.technique)}</div>` : ''}
        ${hasValue(row.recommended_next) ? `<details><summary>Recommended next step</summary><div class="details">${esc(row.recommended_next)}</div></details>` : ''}
        <details><summary>Context</summary><div class="details">${esc(JSON.stringify(row.context || {}, null, 2))}</div></details>
      </td>
      <td>${refs || '<span class="muted">None</span>'}</td>`;
    tbody.appendChild(tr);
    bindFilterButtons(tr);
  });
}

function renderGraph() {
  if (cy) return;
  const pivot = document.getElementById('pivot-details');
  if (!window.cytoscape || !(GRAPH.nodes || []).length) {
    pivot.textContent = 'Graph data unavailable.';
    return;
  }

  cy = cytoscape({
    container: document.getElementById('graph'),
    elements: [...(GRAPH.nodes || []), ...(GRAPH.edges || [])],
    style: [
      { selector: 'node', style: { 'label': 'data(label)', 'font-size': 10, 'background-color': '#1d4ed8', 'color': '#111', 'text-valign': 'top', 'text-margin-y': -6, 'text-wrap': 'wrap', 'text-max-width': 90 } },
      { selector: 'edge', style: { 'width': 2, 'line-color': '#94a3b8', 'target-arrow-shape': 'triangle', 'target-arrow-color': '#94a3b8', 'curve-style': 'bezier' } },
      { selector: 'node[type = "ip"]', style: { 'background-color': '#ef4444' } },
      { selector: 'node[type = "user"]', style: { 'background-color': '#f59e0b' } },
      { selector: 'node[type = "host"]', style: { 'background-color': '#16a34a' } },
      { selector: 'node[type = "service"]', style: { 'background-color': '#7c3aed' } },
      { selector: 'node[type = "process"]', style: { 'background-color': '#0ea5e9' } },
      { selector: 'node[type = "command"]', style: { 'background-color': '#475569', 'color': '#fff' } }
    ],
    layout: { name: 'cose', animate: false, padding: 20 }
  });

  cy.on('tap', 'node', function(evt) {
    const data = evt.target.data();
    pivot.textContent = JSON.stringify(data, null, 2);
    if (['host', 'user', 'ip'].includes(data.type)) {
      setFilter(data.type, data.value || data.label || '');
    }
  });

  cy.on('tap', 'edge', function(evt) {
    pivot.textContent = JSON.stringify(evt.target.data(), null, 2);
  });
}

function renderRawEvents() {
  const query = (document.getElementById('raw-search').value || '').toLowerCase();
  const tbody = document.getElementById('raw-body');
  const rawSummaryCard = document.getElementById('raw-summary-card');
  tbody.innerHTML = '';
  const rawSummary = (FINDINGS.summary || {}).raw_event_summary || {};
  const previewCount = rawSummary.preview_count || (FINDINGS.raw_events || []).length;
  const totalCount = rawSummary.total_count || previewCount;
  const artifactPath = rawSummary.artifact_path || '';
  const truncated = Boolean(rawSummary.truncated);

  rawSummaryCard.innerHTML = `
    <h3>Raw Event Preview</h3>
    <p class="subtle">
      Showing ${esc(previewCount)} of ${esc(totalCount)} raw events in the report.
      ${truncated ? 'The report uses a preview to keep large cases responsive.' : 'All available raw events fit in the report preview.'}
    </p>
    ${artifactPath ? `<div class="details">Full raw event stream: ${esc(artifactPath)} (${esc(rawSummary.artifact_format || 'jsonl')})</div>` : ''}
  `;

  const filtered = (FINDINGS.raw_events || [])
    .filter(matchesFilters)
    .filter(ev => {
      if (!query) return true;
      const hay = `${ev.timestamp || ''} ${ev.event_id || ''} ${ev.computer || ''} ${ev.user || ''} ${ev.user_display || ''} ${ev.user_canonical || ''} ${ev.subject_domain_user || ''} ${ev.target_domain_user || ''} ${ev.source_ip || ''} ${ev.process_name || ''} ${ev.command_line || ''} ${ev.raw_summary || ''} ${ev.script_excerpt || ''} ${ev.remote_url || ''} ${ev.task_name || ''} ${ev.created_username || ''}`.toLowerCase();
      return hay.includes(query);
    })
    .slice(0, 500);

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="muted">No raw events match the current search and pivots.</td></tr>`;
    return;
  }

  filtered.forEach(ev => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${esc(ev.timestamp || 'unknown')}</td>
      <td>${esc(ev.event_id || 'unknown')}</td>
      <td>${entityChipHtml('host', ev.computer, present(ev.computer))}</td>
      <td>${entityChipHtml('user', canonicalUser(ev), displayUser(ev))}</td>
      <td>${entityChipHtml('ip', ev.source_ip, present(ev.source_ip))}</td>
      <td>${esc(ev.process_name || 'unknown')}</td>
      <td>
        <div>${esc(ev.raw_summary || ev.script_excerpt || ev.command_line || 'Expand for details')}</div>
        ${hasValue(ev.remote_url) ? `<div class="subtle">Remote URL: ${esc(ev.remote_url)}</div>` : ''}
        ${hasValue(ev.task_name) ? `<div class="subtle">Task: ${esc(ev.task_name)}</div>` : ''}
        ${hasValue(ev.created_username) ? `<div class="subtle">Created User: ${esc(ev.created_username)}</div>` : ''}
        ${ev.collapsed_count ? `<div class="subtle">Collapsed Count: ${esc(ev.collapsed_count)}</div>` : ''}
        <details><summary>Expand</summary><div class="details">${esc(JSON.stringify(ev, null, 2))}</div></details>
      </td>`;
    tbody.appendChild(row);
    bindFilterButtons(row);
  });
}

function renderFilterSummaries() {
  const html = filterSummaryHtml();
  document.getElementById('filter-summary').innerHTML = html;
  document.getElementById('incident-filter-summary').innerHTML = html;
  document.getElementById('timeline-filter-summary').innerHTML = html;
  document.getElementById('raw-filter-summary').innerHTML = html;
  bindFilterButtons(document);
}

function renderAll() {
  renderFilterSummaries();
  renderOverview();
  renderIncidents();
  renderMitreMatrix();
  renderTimeline();
  renderRawEvents();
}

renderAll();
</script>
</body>
</html>
"""

    html = (
        template.replace("__FINDINGS_JSON__", _safe_json_for_script(findings_data))
        .replace("__TIMELINE_JSON__", _safe_json_for_script(timeline_data))
        .replace("__GRAPH_JSON__", _safe_json_for_script(graph_data))
        .replace("__GENERATED_AT__", _safe_json_for_script(generated))
    )

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(html)


def generate(events, alerts, chains, output_path: str, input_source: str):
    """Legacy HTML generator compatibility shim."""
    findings_data = {
        "case": {
            "case_name": "legacy-run",
            "input_source": input_source,
            "input_source_display": display_input_source(input_source),
        },
        "signals": [],
        "findings": [a.to_dict() for a in alerts],
        "incidents": [],
        "summary": {"signal_count": 0, "finding_count": len(alerts), "incident_count": 0},
        "raw_events": [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "computer": e.computer,
                "user": e.domain_user,
                "subject_domain_user": e.subject_domain_user,
                "target_domain_user": e.target_domain_user,
                "source_ip": e.source_ip,
                "process_name": e.process_name,
                "command_line": e.command_line,
                "event_data": dict(e.event_data),
            }
            for e in events
        ],
    }
    timeline_data = {
        "timeline": [
            {
                "type": "finding",
                "id": str(idx + 1),
                "display_label": str(idx + 1),
                "timestamp": a.get("timestamp"),
                "title": a.get("rule_name"),
                "severity": a.get("severity"),
                "host": a.get("host"),
                "host_display": a.get("host") or "unknown",
                "user": a.get("user"),
                "user_display": a.get("user") or "unknown",
                "process": a.get("process"),
                "process_display": a.get("process") or "unknown",
                "command_line": a.get("command_line"),
                "summary": a.get("description") or a.get("rule_name"),
                "context": a.get("evidence", {}),
                "related_ids": {},
            }
            for idx, a in enumerate([x.to_dict() for x in alerts])
        ]
    }
    graph_data = {"nodes": [], "edges": []}

    temp_base = os.path.dirname(os.path.abspath(output_path))
    findings_path = os.path.join(temp_base, "_legacy_findings_temp.json")
    timeline_path = os.path.join(temp_base, "_legacy_timeline_temp.json")
    graph_path = os.path.join(temp_base, "_legacy_graph_temp.json")

    with open(findings_path, "w", encoding="utf-8") as handle:
        json.dump(findings_data, handle)
    with open(timeline_path, "w", encoding="utf-8") as handle:
        json.dump(timeline_data, handle)
    with open(graph_path, "w", encoding="utf-8") as handle:
        json.dump(graph_data, handle)

    generate_from_artifacts(findings_path, timeline_path, graph_path, output_path)

    for path in (findings_path, timeline_path, graph_path):
        try:
            os.remove(path)
        except OSError:
            pass
