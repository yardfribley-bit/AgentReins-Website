const fmt = new Intl.NumberFormat('zh-CN');
const el = id => document.getElementById(id);
const safe = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
let latestId = 0;
let liveEvents = [];
let caseEvents = [];

function eventHtml(event) {
  const title = `${event.component} · ${event.category} · ${event.operation || 'EVENT'}`;
  const main = event.resource || event.data || event.source || '—';
  const meta = [event.process, event.pid ? `PID ${event.pid}` : '', event.parentProcess ? `父进程 ${event.parentProcess}` : '', event.taskId ? `任务 ${event.taskId}` : ''].filter(Boolean).join(' · ');
  let raw = event.evidence || '{}';
  try { raw = JSON.stringify(JSON.parse(raw), null, 2); } catch (_) {}
  return `<details class="command event ${safe(event.category)}" data-event-id="${safe(event.id)}"><summary><time>${safe(event.time)}</time><div><b>${safe(title)}</b><code>${safe(main)}</code><small>${safe(meta)}</small></div><span class="badge">${safe(event.result || 'PASSED')}</span></summary><pre>${safe(raw)}</pre></details>`;
}

function updateEventList(target, items, emptyHtml='') {
  const opened = new Set([...target.querySelectorAll('details[open][data-event-id]')].map(node => node.dataset.eventId));
  const scrollTop = target.scrollTop;
  target.innerHTML = items.length ? items.map(eventHtml).join('') : emptyHtml;
  for (const id of opened) {
    const node = [...target.querySelectorAll('details[data-event-id]')].find(item => item.dataset.eventId === id);
    if (node) node.open = true;
  }
  target.scrollTop = scrollTop;
}

function render(data) {
  el('hostname').textContent = data.host.hostname;
  el('host-meta').textContent = `${data.host.provider} · ${data.host.os} · ${data.host.kernel}`;
  el('observed-at').textContent = `观测时间 ${data.observedAt}`;
  el('agent-count').textContent = data.agents.length;
  el('agent-running').textContent = `${data.agents.filter(agent => agent.status === 'running').length} RUNNING`;
  el('exec-count').textContent = fmt.format(data.metrics.execEvents);
  el('network-count').textContent = fmt.format(data.metrics.networkEvents);
  el('disk-percent').textContent = `${data.host.rootDiskPercent}%`;
  el('disk-detail').textContent = data.host.rootDiskPercent >= 90 ? '容量风险 · 需要处理' : '容量正常';
  el('coverage').textContent = `${data.sensor.coveragePercent}%`;
  el('sensor-state').textContent = data.sensor.status;
  el('lsm').textContent = data.sensor.lsm;
  el('mode').textContent = data.sensor.mode;

  el('agent-list').innerHTML = data.agents.map(agent => `<article class="agent-card">
    <header><b>${safe(agent.name)}</b><em>${safe(agent.status.toUpperCase())}</em></header>
    <code title="${safe(agent.executable)}">${safe(agent.executable)}</code>
    <footer><span>PID ${safe(agent.pid)}</span><span>${fmt.format(agent.events)} events</span><span>${safe(agent.privilege)}</span></footer>
  </article>`).join('');

  if (!liveEvents.length) el('command-list').innerHTML = data.commands.map(command => `<article class="command">
    <time>${safe(command.time)}</time><div><b>${safe(command.parent)} → ${safe(command.process)}</b><code>${safe(command.command)}</code></div><span class="badge">CONFIRMED</span>
  </article>`).join('');

  el('network-list').innerHTML = data.network.map(flow => `<article class="network-item">
    <b>${safe(flow.process)}</b><code>${safe(flow.destination)}</code><span>${safe(flow.evidence)}</span>
  </article>`).join('');

  el('findings').innerHTML = data.findings.map(finding => `<li>${safe(finding)}</li>`).join('');
  el('feed-state').textContent = data.live ? '实时证据流已连接' : '等待实时证据流';
}

function renderEvents() {
  if (!liveEvents.length) return;
  updateEventList(el('command-list'), liveEvents);
  el('feed-state').textContent = '实时证据流已连接';
  el('refresh-note').textContent = `实时流 · 已载入 ${fmt.format(liveEvents.length)} 条 · 仅遮盖认证秘密`;
}

async function loadCase() {
  try {
    const response = await fetch('/api/agentsec/events?taskId=invt-k81jin0r4m&limit=100', {cache:'no-store'});
    if (!response.ok) throw new Error(String(response.status));
    caseEvents = (await response.json()).events.sort((a,b) => String(a.time).localeCompare(String(b.time)) || a.id-b.id);
    updateEventList(el('case-chain'), caseEvents, '<article class="command">任务证据正在回灌。</article>');
  } catch (_) { el('case-chain').innerHTML = '<article class="command">任务证据加载失败，正在重试。</article>'; }
}

async function refreshEvents() {
  try {
    const viewing = Boolean(el('command-list').querySelector('details[open]'));
    const response = await fetch(`/api/agentsec/events?after=${latestId}&limit=300`, {cache:'no-store'});
    if (!response.ok) throw new Error(String(response.status));
    const data = await response.json();
    if (data.events.length) {
      const known = new Set(liveEvents.map(event => event.id));
      liveEvents = [...data.events.filter(event => !known.has(event.id)), ...liveEvents].sort((a,b) => b.id-a.id).slice(0, 1000);
      latestId = Math.max(latestId, data.latestId || 0);
      if (viewing) {
        el('feed-state').textContent = `详情查看中 · ${data.events.length} 条新事件待显示`;
      } else {
        renderEvents();
      }
    }
  } catch (_) { el('feed-state').textContent = '实时流暂时断开 · 正在重连'; }
}

document.addEventListener('toggle', event => {
  if (event.target.matches('#command-list details') && !event.target.open) renderEvents();
}, true);

async function refresh() {
  try {
    const response = await fetch('/api/agentsec/status', {cache:'no-store'});
    if (!response.ok) throw new Error(String(response.status));
    render(await response.json());
  } catch (_) {
    const fallback = await fetch('/agentsec/snapshot.json', {cache:'no-store'});
    render(await fallback.json());
    el('refresh-note').textContent = '展示最近一次脱敏快照';
  }
}

refresh();
refreshEvents();
loadCase();
setInterval(refresh, 30000);
setInterval(refreshEvents, 2000);
setInterval(loadCase, 30000);
