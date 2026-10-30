// Evidence tab: forensic source coverage, derived evidence links with analyst
// decisions, analyst hypotheses, and the artifact observation explorer.
// Every value from evidence is rendered through esc().

let forensicCase = '';
let forensicLinks = null;
let forensicObservations = [];
let forensicRequestId = 0;

const LINK_CLASS_LABELS = {
  observed_field_match: 'Observed field match',
  supported_inference: 'Supported inference',
  weak_temporal_association: 'Weak temporal association',
  analyst_hypothesis: 'Analyst hypothesis',
};

function linkClassBadge(value) {
  return `<span class="badge link-class link-${esc(value)}">${esc(LINK_CLASS_LABELS[value] || value || 'unknown')}</span>`;
}

async function loadForensicEvidence(name) {
  const requestId = ++forensicRequestId;
  const parentRequest = caseRequestId;
  forensicCase = name;
  const panel = document.getElementById('detail-content');
  panel.innerHTML = '<div class="card"><div class="loading-state" role="status">Loading forensic evidence…</div></div>';
  const stillCurrent = () => requestId === forensicRequestId && parentRequest === caseRequestId && currentPage === 'case-detail' && _detailTarget.tab === 'evidence';
  try {
    const base = `/api/cases/${encodeURIComponent(name)}`;
    const [links, observations] = await Promise.all([
      apiJSON(`${base}/evidence-links?limit=500`),
      apiJSON(`${base}/forensic-observations?limit=500`),
    ]);
    if (!stillCurrent()) return;
    forensicLinks = links;
    forensicObservations = observations.observations || [];
    panel.innerHTML = `<div class="panel-stack">
      ${renderForensicCoverage(links.summary || {}, observations)}
      <section class="card"><div class="section-heading"><div><div class="eyebrow">EVIDENCE LINKS</div><h2>Event-to-artifact links</h2></div>
        <span class="subtle-hint">Derived links are never edited; decisions are stored separately</span></div>
        <p class="scope-note">Each link shows the matching field values, its class, any contradiction, and what it does not establish. Showing ${esc((links.relationships || []).length)} of ${esc(links.total || 0)}.</p>
        <div id="forensic-links"></div>
        ${(links.orphaned_reviews || []).length ? `<p class="scope-note">${esc(links.orphaned_reviews.length)} earlier decision(s) refer to links the current analysis no longer produces; they are kept in the review history.</p>` : ''}
      </section>
      <section class="card"><div class="section-heading"><div><div class="eyebrow">ANALYST HYPOTHESES</div><h2>Analyst-asserted links</h2></div></div>
        <div id="forensic-hypotheses"></div>${canReviewMutate() ? renderHypothesisForm() : '<p class="scope-note">Viewer mode is read-only.</p>'}</section>
      <section class="card"><div class="section-heading"><div><div class="eyebrow">EVIDENCE EXPLORER</div><h2>Artifact observations</h2></div>
        <span class="subtle-hint">Recorded time keeps its source meaning</span></div>
        <div class="table-toolbar"><div class="toolbar-group">
          <div class="input-group"><label for="forensic-search">Search</label><input class="input" id="forensic-search" placeholder="Name, path, URL, host, record…" oninput="renderForensicObservations()"></div>
          <div class="input-group"><label for="forensic-kind">Artifact type</label><select class="input" id="forensic-kind" onchange="renderForensicObservations()"><option value="">All types</option>${(observations.kinds || []).map(kind => `<option value="${esc(kind)}">${esc(kind)}</option>`).join('')}</select></div>
        </div></div>
        <p id="forensic-meta" class="scope-note" role="status"></p><div id="forensic-observations"></div></section>
    </div>`;
    renderForensicLinks();
    renderForensicHypotheses();
    renderForensicObservations();
  } catch (error) {
    if (!stillCurrent()) return;
    panel.innerHTML = `<div class="card"><div class="empty-state">Could not load forensic evidence. ${esc(error.message || '')}</div><button class="btn btn-ghost" onclick='loadForensicEvidence(${jsv(name)})'>Retry</button></div>`;
  }
}

function renderForensicCoverage(summary, observations) {
  const families = (summary.coverage || {}).families || {};
  const rows = Object.entries(families).map(([family, info]) => `<tr><td>${esc(family.replace(/_/g, ' '))}</td><td>${esc(info.status)}</td><td>${esc(info.count ?? info.run_observations ?? 0)}</td><td>${esc(Object.entries(info).filter(([key]) => !['status', 'count', 'run_observations'].includes(key)).map(([key, value]) => `${key}: ${typeof value === 'object' ? JSON.stringify(value) : value}`).join('; '))}</td></tr>`).join('');
  const limits = (summary.coverage || {}).limitations || [];
  const obsSummary = observations.summary || {};
  return `<section class="card card-soft"><div class="card-title">Source Coverage</div>
    <div class="section-kicker">${esc(obsSummary.observation_count ?? 0)} artifact observation(s) from ${esc(obsSummary.host || 'no artifact bundle')}; processing ${esc(obsSummary.completeness || 'not applicable')}. ${summary.evaluated ? `${esc(summary.relationship_count)} link(s), ${esc(summary.cross_source_finding_count)} cross-source finding(s).` : 'Links are evaluated only when event records and artifacts are both supplied.'}</div>
    ${rows ? `<table class="detail-fact-table"><tr><th>Evidence family</th><th>Status</th><th>Records</th><th>Notes</th></tr>${rows}</table>` : ''}
    ${limits.length ? `<ul class="scope-note">${limits.map(item => `<li>${esc(item)}</li>`).join('')}</ul>` : ''}
    ${(obsSummary.warnings || []).length ? `<p style="color:var(--orange)"><b>Collection warnings:</b> ${obsSummary.warnings.map(esc).join(' ')}</p>` : ''}</section>`;
}

function decisionControls(kind, id, review) {
  const decisions = (forensicLinks && forensicLinks.decisions) || ['unreviewed', 'confirmed', 'rejected', 'needs_more_evidence'];
  const current = (review || {}).decision || 'unreviewed';
  const reviewed = review && review.reviewed_by ? `<small>by ${esc(review.reviewed_by)} at ${esc(review.reviewed_at)}</small>` : '';
  if (!canReviewMutate()) return `<p><b>Decision:</b> ${esc(current)} ${reviewed}</p>`;
  const key = `${kind}-${id}`;
  return `<div class="toolbar-group"><div class="input-group"><label for="decision-${esc(key)}">Decision</label><select class="input" id="decision-${esc(key)}">${decisions.map(value => `<option value="${esc(value)}" ${value === current ? 'selected' : ''}>${esc(value.replace(/_/g, ' '))}</option>`).join('')}</select></div>
    <div class="input-group"><label for="rationale-${esc(key)}">Rationale</label><input class="input" id="rationale-${esc(key)}" maxlength="4000" value="${esc((review || {}).rationale || '')}"></div>
    <button class="btn btn-sm" onclick='saveLinkDecision(${jsv(kind)},${jsv(id)})'>Save</button>
    <button class="btn btn-sm btn-ghost" onclick='showLinkHistory(${jsv(id)},this)'>History</button></div>${reviewed}<div class="link-history"></div>`;
}

function renderForensicLinks() {
  const links = (forensicLinks && forensicLinks.relationships) || [];
  document.getElementById('forensic-links').innerHTML = links.length ? links.map(link => {
    const source = link.source || {};
    const target = link.target || {};
    const fields = (link.matched_fields || []).map(field => `<li><code>${esc(field.event_field)}</code> = <code>${esc(field.artifact_field)}</code>: ${esc(field.value || `${field.event_value} / ${field.artifact_value}`)}</li>`).join('');
    const contradictions = (link.contradictions || []).map(item => `<li>${esc(item.field)}: event <code>${esc(item.event_value)}</code>, artifact <code>${esc(item.artifact_value)}</code>. ${esc(item.meaning)}</li>`).join('');
    const inferred = (link.inferred_claims || []).map(claim => `<li>${linkClassBadge(claim.class)} ${esc(claim.claim)} <small>(${(claim.basis || []).map(esc).join(', ')})</small></li>`).join('');
    return `<details class="timeline-entry"><summary><span>${linkClassBadge(link.link_class)}</span><span><strong>${esc(source.process || source.channel || 'Event')} ↔ ${esc(target.artifact_kind)}</strong><small>${esc((link.rule || {}).name)} v${esc((link.rule || {}).version)} · ${esc((link.review || {}).decision || 'unreviewed')}${(link.contradictions || []).length ? ' · contradiction' : ''}</small></span></summary>
      <div class="timeline-evidence">
        <p><b>Event record:</b> ${esc(source.event_id)} in ${esc(source.channel)}, record ${esc(source.record_id)} at ${esc(source.timestamp)} (${esc(source.time_semantics)})<br><small>${esc(source.source_file)} · sha256 ${esc(source.source_sha256)} · ${esc(source.observation_id)}</small></p>
        <p><b>Artifact record:</b> ${esc(target.artifact_kind)} record ${esc(target.source_record)} at ${esc(target.timestamp)} (${esc(target.time_semantics)})<br><small>${esc(target.source_file)} · sha256 ${esc(target.source_sha256)} · ${esc(target.observation_id)}</small></p>
        <p><b>Matched fields</b></p><ul>${fields}</ul>
        ${inferred ? `<p><b>Inferred</b></p><ul>${inferred}</ul>` : ''}
        ${contradictions ? `<p style="color:var(--orange)"><b>Contradictions</b></p><ul>${contradictions}</ul>` : ''}
        <p><b>Does not establish</b></p><ul>${(link.does_not_establish || []).map(item => `<li>${esc(item)}</li>`).join('')}</ul>
        ${(link.ambiguity || {}).candidate_events > 1 ? `<p style="color:var(--orange)">${esc(link.ambiguity.candidate_events)} candidate events matched; this link is ambiguous.</p>` : ''}
        ${decisionControls('relationship', link.relationship_id, link.review)}
      </div></details>`;
  }).join('') : '<div class="empty-state">No derived evidence links for this case.</div>';
}

function renderForensicHypotheses() {
  const links = (forensicLinks && forensicLinks.analyst_links) || [];
  document.getElementById('forensic-hypotheses').innerHTML = links.length ? links.map(link => `<details class="timeline-entry"><summary><span>${linkClassBadge('analyst_hypothesis')}</span><span><strong>${esc(link.claim)}</strong><small>${esc(link.created_by)} · ${esc(link.created_at)} · ${esc(link.decision)}</small></span></summary>
    <div class="timeline-evidence"><p><code>${esc(link.source_observation_id)}</code> ↔ <code>${esc(link.target_observation_id)}</code></p>
    <p>This link was asserted by an analyst, not derived from matching fields.</p>${decisionControls('hypothesis', link.link_id, {decision: link.decision, rationale: link.rationale, reviewed_by: link.updated_by, reviewed_at: link.updated_at})}</div></details>`).join('')
    : '<div class="empty-state">No analyst hypotheses recorded.</div>';
}

function renderHypothesisForm() {
  return `<div class="toolbar-group" style="margin-top:12px">
    <div class="input-group"><label for="hyp-source">Source observation id</label><input class="input" id="hyp-source" placeholder="obs_…"></div>
    <div class="input-group"><label for="hyp-target">Target observation id</label><input class="input" id="hyp-target" placeholder="obs_…"></div>
    <div class="input-group"><label for="hyp-claim">Claim</label><input class="input" id="hyp-claim" maxlength="2000" placeholder="What you believe connects these records"></div>
    <button class="btn btn-sm" onclick="addForensicHypothesis()">Add hypothesis</button></div>`;
}

function renderForensicObservations() {
  const query = (document.getElementById('forensic-search').value || '').trim().toLowerCase();
  const kind = document.getElementById('forensic-kind').value;
  const rows = forensicObservations.filter(item => (!kind || item.kind === kind) && (!query || JSON.stringify(item).toLowerCase().includes(query)));
  document.getElementById('forensic-meta').textContent = `Showing ${rows.length} of ${forensicObservations.length} loaded observation(s). Original records stay in the retained source files.`;
  document.getElementById('forensic-observations').innerHTML = rows.length ? rows.map(item => {
    const details = item.details || {};
    const name = details.name || details.target_path || details.current_path || '';
    return `<details class="timeline-entry"><summary><time>${esc(item.timestamp || item.observed_at || 'unrecorded')}</time><span><strong>${esc(name || item.kind)}</strong><small>${esc(item.kind)} · ${esc(item.time_semantics)} · ${esc(item.host)}${(item.relationship_ids || []).length ? ` · ${esc(item.relationship_ids.length)} link(s)` : ''}</small></span></summary>
      <div class="timeline-evidence"><p>${esc(item.interpretation || '')}</p>
      <p><b>Source:</b> ${esc(item.source_file)} record ${esc(item.source_record)} · sha256 ${esc(item.source_sha256)}<br><b>Observation:</b> <code>${esc(item.id)}</code> · collected ${esc(item.observed_at)}</p>
      ${details.command ? `<pre>${esc(details.command)}</pre>` : ''}
      <details><summary>Full observation</summary><pre>${esc(JSON.stringify(item, null, 2))}</pre></details></div></details>`;
  }).join('') : '<div class="empty-state">No observations match these filters.</div>';
}

async function saveLinkDecision(kind, id) {
  const key = `${kind}-${id}`;
  const body = {decision: document.getElementById(`decision-${key}`).value, rationale: document.getElementById(`rationale-${key}`).value};
  const base = `/api/cases/${encodeURIComponent(forensicCase)}/evidence-links`;
  const path = kind === 'relationship' ? `${base}/${encodeURIComponent(id)}/review` : `${base}/hypotheses/${encodeURIComponent(id)}`;
  try {
    await apiJSON(path, {method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    notify('Decision saved.', 'success');
    loadForensicEvidence(forensicCase);
  } catch (error) {
    notify(error.message || 'Could not save the decision.', 'error');
  }
}

async function showLinkHistory(id, button) {
  const holder = button.closest('.timeline-evidence').querySelector('.link-history');
  try {
    const data = await apiJSON(`/api/cases/${encodeURIComponent(forensicCase)}/evidence-links/${encodeURIComponent(id)}/history`);
    holder.innerHTML = (data.history || []).length ? `<ul>${data.history.map(item => `<li>${esc(item.changed_at)} · ${esc(item.changed_by)} · ${esc(item.field)}: ${esc(item.old_value)} → ${esc(item.new_value)}</li>`).join('')}</ul>` : '<p class="scope-note">No history yet.</p>';
  } catch (error) {
    holder.textContent = error.message || 'Could not load history.';
  }
}

async function addForensicHypothesis() {
  const body = {
    source_observation_id: document.getElementById('hyp-source').value.trim(),
    target_observation_id: document.getElementById('hyp-target').value.trim(),
    claim: document.getElementById('hyp-claim').value.trim(),
  };
  try {
    await apiJSON(`/api/cases/${encodeURIComponent(forensicCase)}/evidence-links/hypotheses`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    notify('Hypothesis recorded.', 'success');
    loadForensicEvidence(forensicCase);
  } catch (error) {
    notify(error.message || 'Could not record the hypothesis.', 'error');
  }
}
