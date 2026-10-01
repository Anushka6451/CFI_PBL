const state = { source: null, acquired: new Set(), critical: 0, evidence: {}, incident: null };
const $ = id => document.getElementById(id);
const esc = value => String(value).replace(/[&<>'"]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));

async function loadData() {
  const [incidentResponse, evidenceResponse] = await Promise.all([fetch('/api/incident'), fetch('/api/evidence')]);
  const incident = await incidentResponse.json();
  const evidence = await evidenceResponse.json();
  state.incident = incident;
  state.evidence = Object.fromEntries(evidence.map(item => [item.id, item]));
  renderCase(incident, evidence);
}

function renderCase(incident, evidence) {
  $('caseId').textContent = `CASE ${incident.case.id}`;
  $('caseTitle').textContent = incident.case.title;
  $('caseSubtitle').textContent = incident.case.subtitle;
  $('classificationNote').textContent = incident.case.classification_note;
  const ctx = incident.historical_context;
  $('factGrid').innerHTML = `
    <div><span>Date</span><strong>${esc(ctx.date)}</strong></div>
    <div><span>Sector</span><strong>${esc(ctx.sector)}</strong></div>
    <div><span>Location</span><strong>${esc(ctx.location)}</strong></div>`;
  $('impactText').textContent = ctx.impact;
  $('historicalElements').innerHTML = ctx.publicly_documented_elements.map(item => `<li>${esc(item)}</li>`).join('');
  $('simulationDisclaimer').textContent = ctx.simulation_disclaimer;
  $('attackPath').innerHTML = incident.attack_path.map((stage, idx) => `
    <div class="attack-stage" id="${esc(stage.id)}"><span class="stage-dot">${idx + 1}</span><div><strong>${esc(stage.label)}</strong><small>${esc(stage.mitre)}</small></div></div>`).join('');
  $('evidenceGrid').innerHTML = evidence.map(ev => `
    <article class="evidence-card locked" data-evidence-id="${esc(ev.id)}">
      <div class="evidence-top"><span class="evidence-id">${esc(ev.id)}</span><span class="severity ${esc(ev.severity)}">${esc(ev.severity)}</span></div>
      <h4>${esc(ev.name)}</h4><p class="muted">${esc(ev.type)} · ${esc(ev.source)}</p>
      <div class="locked-text">Awaiting acquisition</div>
      <div class="evidence-body"><code>${esc(ev.preview)}</code><p>${esc(ev.finding)}</p><div class="tag-row"><span>${esc(ev.mitre)}</span><span>SHA: ${esc(ev.sha256)}</span></div></div>
    </article>`).join('');
  $('sourceLinks').innerHTML = incident.sources.map(source => `<a href="${esc(source.url)}" target="_blank" rel="noopener">${esc(source.name)}</a>`).join('');
  updateEvidenceCounter();
}

function setStatus(value, hint='') { $('statusValue').textContent = value; $('statusHint').textContent = hint; }
function setRisk(value) { $('riskValue').textContent = value; $('riskBar').style.width = `${value}%`; }
function updateEvidenceCounter() { const total = Object.keys(state.evidence).length; $('evidenceCount').textContent = `${state.acquired.size} / ${total}`; $('evidenceBadge').textContent = `${state.acquired.size} acquired`; }

function markStage(stageId) {
  const stages = [...document.querySelectorAll('.attack-stage')];
  const currentIndex = stages.findIndex(s => s.id === stageId);
  stages.forEach((stage, idx) => {
    stage.classList.toggle('active', stage.id === stageId);
    if (idx < currentIndex) stage.classList.add('complete');
  });
}

function acquireEvidence(id, event) {
  if (state.acquired.has(id)) return;
  state.acquired.add(id);
  const card = document.querySelector(`[data-evidence-id="${CSS.escape(id)}"]`);
  if (card) { card.classList.remove('locked'); card.classList.add('acquired'); }
  const ev = state.evidence[id];
  if (ev) {
    const empty = $('custodyEmpty'); if (empty) empty.remove();
    const row = document.createElement('tr');
    row.innerHTML = `<td><strong>${esc(ev.id)}</strong> · ${esc(ev.name)}</td><td>${esc(event.sim_time)} / Event ${event.seq}</td><td class="integrity-ok">Hash recorded ✓</td><td>Investigator-01</td>`;
    $('custodyBody').appendChild(row);
  }
  updateEvidenceCounter();
}

function addTimelineItem(event) {
  const empty = $('timelineEmpty'); if (empty) empty.remove();
  const item = document.createElement('div');
  item.className = `timeline-item ${event.severity}`;
  const tags = [...event.mitre, ...event.evidence_ids].map(x => `<span>${esc(x)}</span>`).join('');
  item.innerHTML = `<div class="timeline-time">${esc(event.sim_time)}</div><div class="timeline-dot"></div><div class="timeline-content"><h4>${esc(event.title)}</h4><p>${esc(event.message)}</p><div class="timeline-tags">${tags}</div></div>`;
  $('timelineList').prepend(item);
}

function handleEvent(event) {
  addTimelineItem(event); setRisk(event.risk); markStage(event.stage);
  if (event.severity === 'critical') { state.critical++; $('criticalCount').textContent = state.critical; }
  event.evidence_ids.forEach(id => acquireEvidence(id, event));
}

function startSimulation() {
  resetSimulation(false);
  const speed = $('speedSelect').value;
  setStatus('Running', 'Streaming reconstructed case events');
  $('streamBadge').textContent = 'Live'; $('streamBadge').className = 'pill live'; $('startBtn').disabled = true;
  state.source = new EventSource(`/api/stream?speed=${encodeURIComponent(speed)}`);
  state.source.addEventListener('incident', msg => handleEvent(JSON.parse(msg.data)));
  state.source.addEventListener('complete', () => {
    setStatus('Complete', 'Simulation finished — review preserved evidence');
    $('streamBadge').textContent = 'Complete'; $('streamBadge').className = 'pill safe'; $('startBtn').disabled = false;
    if (state.source) state.source.close();
  });
  state.source.onerror = () => {
    if ($('statusValue').textContent === 'Running') { setStatus('Connection ended', 'Restart the local Python server if needed'); $('streamBadge').textContent = 'Disconnected'; $('streamBadge').className = 'pill neutral'; $('startBtn').disabled = false; }
  };
}

function resetSimulation(closeSource=true) {
  if (closeSource && state.source) state.source.close(); state.source = null; state.acquired.clear(); state.critical = 0;
  $('criticalCount').textContent = '0'; setRisk(0); setStatus('Idle', 'Ready to replay the case');
  $('streamBadge').textContent = 'Disconnected'; $('streamBadge').className = 'pill neutral'; $('startBtn').disabled = false;
  document.querySelectorAll('.attack-stage').forEach(stage => stage.classList.remove('active','complete'));
  document.querySelectorAll('.evidence-card').forEach(card => { card.classList.add('locked'); card.classList.remove('acquired'); });
  $('timelineList').innerHTML = '<div class="timeline-empty" id="timelineEmpty">Start the simulation to stream reconstructed forensic events.</div>';
  $('custodyBody').innerHTML = '<tr id="custodyEmpty"><td colspan="4">No evidence acquired yet.</td></tr>';
  updateEvidenceCounter();
}

window.addEventListener('DOMContentLoaded', async () => {
  try { await loadData(); } catch (err) { setStatus('Load error', 'Run the project with python app.py rather than opening index.html directly.'); console.error(err); }
  $('startBtn').addEventListener('click', startSimulation); $('resetBtn').addEventListener('click', () => resetSimulation(true));
});
