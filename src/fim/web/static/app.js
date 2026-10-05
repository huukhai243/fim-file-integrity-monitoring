/* Dashboard FIM — client thuần, không framework.
   Chỉ gọi JSON API ở /api/*, không render phía server. */

'use strict';

const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
const SUSPICIOUS = new Set(['medium', 'high', 'critical']);

const state = {
  rangeHours: 24,
  page: 0,
  pageSize: 50,
  total: 0,
  selected: new Set(),
  events: [],
  timeline: [],
};

/* ---------------------------------------------------------------- tiện ích */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

async function api(path, options) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch { /* body rỗng */ }
    throw new Error(detail);
  }
  return res.status === 204 ? null : res.json();
}

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleString('vi-VN', {
    month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
  });
}

function fmtBytes(n) {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`;
}

let toastTimer;
function toast(message, isError) {
  const el = $('#toast');
  el.textContent = message;
  el.hidden = false;
  el.style.background = isError ? 'var(--sev-critical)' : 'var(--text-primary)';
  el.style.color = isError ? '#fff' : 'var(--surface-1)';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 3200);
}

/** Bước chia "đẹp" (1, 2, 5, 10, 20, 50…) để trục Y chỉ có số nguyên. */
function niceStep(max, targetTicks) {
  const raw = Math.max(1, max / targetTicks);
  const magnitude = 10 ** Math.floor(Math.log10(raw));
  const normalized = raw / magnitude;
  const factor = normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10;
  return Math.max(1, factor * magnitude);
}

function sevBadge(severity) {
  if (!severity) return '<span class="muted">—</span>';
  return `<span class="sev" data-sev="${esc(severity)}">${esc(severity)}</span>`;
}

/* ------------------------------------------------------------ thẻ số liệu */

async function loadStats() {
  const query = state.rangeHours ? `?hours=${state.rangeHours}` : '';
  const stats = await api(`/api/stats${query}`);

  $('#t-events').textContent = (stats.events_total ?? 0).toLocaleString('vi-VN');
  const changes = stats.by_change || {};
  $('#t-events-note').textContent = SEVERITIES.length
    ? `${changes.modified || 0} sửa · ${changes.created || 0} tạo · ${changes.deleted || 0} xoá`
    : '';

  const bySev = stats.by_severity || {};
  const suspicious = SEVERITIES.filter((s) => SUSPICIOUS.has(s))
    .reduce((sum, s) => sum + (bySev[s] || 0), 0);
  const elSus = $('#t-suspicious');
  elSus.textContent = suspicious.toLocaleString('vi-VN');
  elSus.classList.toggle('has-any', suspicious > 0);
  $('#t-suspicious-note').textContent =
    `${bySev.critical || 0} critical · ${bySev.high || 0} high · ${bySev.medium || 0} medium`;

  $('#t-alerts').textContent = stats.alerts_open ?? 0;
  $('#t-alerts-note').textContent = `${stats.whitelist_active ?? 0} mục whitelist`;

  if (stats.baseline) {
    $('#t-baseline').textContent = (stats.baseline.file_count || 0).toLocaleString('vi-VN');
    $('#t-baseline-note').textContent =
      `${fmtBytes(stats.baseline.total_bytes)} · chốt ${fmtTime(stats.baseline.created_at)}`;
  } else {
    $('#t-baseline').textContent = '—';
    $('#t-baseline-note').textContent = 'chưa chốt baseline';
  }

  const dot = $('#live-dot');
  const last = stats.last_scan;
  const fresh = last && (Date.now() / 1000 - last.started_at) < 3600;
  dot.classList.toggle('is-stale', !fresh);
  dot.title = last ? `Lần quét gần nhất: ${fmtTime(last.started_at)}` : 'Chưa quét lần nào';

  $('#scan-btn').disabled = !!stats.scan_running;
  $('#scan-btn').textContent = stats.scan_running ? 'Đang quét…' : 'Quét ngay';
}

/* ------------------------------------------------------------- biểu đồ SVG
   Cột chồng 2 series. Severity chi tiết nằm ở bảng: 5 mức cạnh nhau không
   vượt được sàn phân biệt màu, nên biểu đồ chỉ trả lời "bao nhiêu, khi nào,
   có đáng ngờ không". */

function renderChart() {
  const svg = $('#chart');
  const data = state.timeline;
  svg.innerHTML = '';
  if (!data.length) {
    svg.innerHTML = '<text x="50%" y="50%" text-anchor="middle" class="tick-label">chưa có dữ liệu</text>';
    return;
  }

  const W = svg.clientWidth || 800;
  const H = 200;
  const pad = { top: 12, right: 8, bottom: 26, left: 38 };
  const plotW = W - pad.left - pad.right;
  const plotH = H - pad.top - pad.bottom;

  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);

  const series = data.map((b) => {
    const suspicious = SEVERITIES.filter((s) => SUSPICIOUS.has(s))
      .reduce((sum, s) => sum + (b[s] || 0), 0);
    return { ...b, suspicious, benign: Math.max(0, (b.total || 0) - suspicious) };
  });

  // Trục đếm số sự kiện nên mọi vạch chia phải là số nguyên. Chọn bước từ dãy
  // 1/2/5/10/… rồi mới suy ra đỉnh trục, thay vì chia đỉnh cho 4 — cách sau sinh
  // ra vạch lẻ (1.25, 2.5, 3.75) và khi làm tròn sẽ hiện "5 4 3 1 0", nhảy mất số 2.
  const max = Math.max(1, ...series.map((b) => b.total || 0));
  const step = niceStep(max, 4);
  const ticks = Math.ceil(max / step);
  const niceMax = step * ticks;

  const y = (v) => pad.top + plotH - (v / niceMax) * plotH;
  const bandW = plotW / series.length;
  const barW = Math.max(2, bandW - 3);          // khe 2px giữa các cột

  const ns = 'http://www.w3.org/2000/svg';
  const add = (tag, attrs, parent = svg) => {
    const el = document.createElementNS(ns, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    parent.appendChild(el);
    return el;
  };

  // Lưới ngang + nhãn trục y (mọi vạch đều là số nguyên)
  for (let i = 0; i <= ticks; i++) {
    const value = step * i;
    const yy = y(value);
    add('line', { class: 'grid-line', x1: pad.left, x2: W - pad.right, y1: yy, y2: yy });
    add('text', {
      class: 'tick-label', x: pad.left - 6, y: yy + 3, 'text-anchor': 'end',
    }).textContent = value;
  }
  add('line', {
    class: 'axis-line', x1: pad.left, x2: W - pad.right,
    y1: pad.top + plotH, y2: pad.top + plotH,
  });

  // Cột: đáng ngờ xếp trên hợp lệ, đầu cột bo 4px
  series.forEach((b, i) => {
    const x = pad.left + i * bandW + (bandW - barW) / 2;
    const baseY = pad.top + plotH;

    const hBenign = b.benign ? Math.max(1, (b.benign / niceMax) * plotH) : 0;
    const hSusp = b.suspicious ? Math.max(1, (b.suspicious / niceMax) * plotH) : 0;

    if (hBenign) {
      add('rect', {
        class: 'bar-benign', x, width: barW,
        y: baseY - hBenign, height: hBenign,
        rx: hSusp ? 0 : Math.min(4, barW / 2), ry: hSusp ? 0 : Math.min(4, barW / 2),
      });
    }
    if (hSusp) {
      // khe 2px màu nền giữa hai đoạn chồng
      const gap = hBenign ? 2 : 0;
      add('rect', {
        class: 'bar-suspicious', x,
        width: barW,
        y: baseY - hBenign - hSusp - gap,
        height: Math.max(1, hSusp),
        rx: Math.min(4, barW / 2), ry: Math.min(4, barW / 2),
      });
    }
  });

  // Nhãn trục x: chỉ vài mốc để không chồng chữ
  const labelEvery = Math.max(1, Math.ceil(series.length / 6));
  series.forEach((b, i) => {
    if (i % labelEvery) return;
    add('text', {
      class: 'tick-label', x: pad.left + i * bandW + bandW / 2,
      y: H - 8, 'text-anchor': 'middle',
    }).textContent = new Date(b.start * 1000).toLocaleTimeString('vi-VN', {
      hour: '2-digit', minute: '2-digit',
    });
  });

  // Lớp hover: vùng bắt rộng bằng cả band, to hơn cột
  const tip = $('#chart-tip');
  series.forEach((b, i) => {
    const band = add('rect', {
      class: 'hit', x: pad.left + i * bandW, y: pad.top,
      width: bandW, height: plotH,
    });
    band.addEventListener('mouseenter', () => {
      const from = new Date(b.start * 1000).toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' });
      const to = new Date(b.end * 1000).toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' });
      tip.innerHTML =
        `<div class="tip-head">${from} – ${to}</div>` +
        `<div class="tip-row"><span><i class="swatch" data-series="suspicious"></i> Đáng ngờ</span><span>${b.suspicious}</span></div>` +
        `<div class="tip-row"><span><i class="swatch" data-series="benign"></i> Hợp lệ</span><span>${b.benign}</span></div>` +
        `<div class="tip-row"><span>Tổng</span><span>${b.total}</span></div>`;
      tip.hidden = false;
      const left = pad.left + i * bandW + bandW / 2;
      tip.style.left = `${Math.min(Math.max(left - 80, 0), W - 170)}px`;
      tip.style.top = '4px';
    });
    band.addEventListener('mouseleave', () => { tip.hidden = true; });
  });

  const totalAll = series.reduce((s, b) => s + (b.total || 0), 0);
  const suspAll = series.reduce((s, b) => s + b.suspicious, 0);
  $('#chart-sub').textContent =
    `${totalAll} thay đổi, ${suspAll} đáng ngờ · chi tiết từng mức ở bảng bên dưới`;
}

async function loadTimeline() {
  const hours = state.rangeHours || 720;
  const buckets = hours <= 1 ? 12 : hours <= 24 ? 24 : hours <= 168 ? 28 : 30;
  state.timeline = await api(`/api/timeline?hours=${hours}&buckets=${buckets}`);
  renderChart();
}

/* --------------------------------------------------------------- lịch sử */

async function loadEvents() {
  const params = new URLSearchParams({
    limit: String(state.pageSize),
    offset: String(state.page * state.pageSize),
    include_whitelisted: $('#f-wl').checked ? 'true' : 'false',
  });
  const severity = $('#f-severity').value;
  const change = $('#f-change').value;
  const path = $('#f-path').value.trim();
  if (severity) params.set('severity', severity);
  if (change) params.set('change', change);
  if (path) params.set('path', path);
  if (state.rangeHours) params.set('hours', String(state.rangeHours));

  const data = await api(`/api/events?${params}`);
  state.events = data.items;
  state.total = data.total;
  renderEvents();
}

function renderEvents() {
  const body = $('#events-body');
  if (!state.events.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty">Không có thay đổi nào khớp bộ lọc</td></tr>';
    $('#events-count').textContent = '';
    updateSelectionButtons();
    return;
  }

  body.innerHTML = state.events.map((e) => {
    const v = e.verdict || {};
    const reason = (v.hits || [])
      .filter((h) => h.rule_id !== 'WL')
      .sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight))
      .slice(0, 2)
      .map((h) => `${h.rule_id} ${h.title}`)
      .join('; ');
    const wl = v.whitelisted ? '<span class="chip wl">whitelist</span>' : '';
    return `<tr class="is-clickable" data-id="${e.id}">
      <td class="col-check"><input type="checkbox" data-pick="${e.id}"
          ${state.selected.has(e.id) ? 'checked' : ''} aria-label="Chọn sự kiện ${e.id}"></td>
      <td class="when">${fmtTime(e.ts)}</td>
      <td>${sevBadge(v.severity)}</td>
      <td><span class="chip">${esc(e.change)}</span></td>
      <td class="path">${esc(e.path)}</td>
      <td class="num">${v.score ?? '—'}</td>
      <td class="reason">${wl} ${esc(reason) || '<span class="muted">—</span>'}</td>
    </tr>`;
  }).join('');

  const from = state.page * state.pageSize + 1;
  const to = Math.min(from + state.events.length - 1, state.total);
  $('#events-count').textContent = `${from}–${to} trong ${state.total.toLocaleString('vi-VN')}`;
  $('#prev-btn').disabled = state.page === 0;
  $('#next-btn').disabled = to >= state.total;

  body.querySelectorAll('[data-pick]').forEach((box) => {
    box.addEventListener('click', (ev) => {
      ev.stopPropagation();
      const id = Number(box.dataset.pick);
      box.checked ? state.selected.add(id) : state.selected.delete(id);
      updateSelectionButtons();
    });
  });
  body.querySelectorAll('tr[data-id]').forEach((row) => {
    row.addEventListener('click', () => openDrawer(Number(row.dataset.id)));
  });
  updateSelectionButtons();
}

function updateSelectionButtons() {
  const n = state.selected.size;
  $('#approve-btn').disabled = n === 0;
  $('#wl-from-sel').disabled = n === 0;
  $('#approve-btn').textContent = n ? `Chấp nhận ${n} mục` : 'Chấp nhận mục đã chọn';
}

/* --------------------------------------------------------- ngăn chi tiết */

async function openDrawer(eventId) {
  const drawer = $('#drawer');
  const body = $('#drawer-body');
  body.innerHTML = '<p class="muted">Đang tải…</p>';
  drawer.hidden = false;

  try {
    const data = await api(`/api/events/${eventId}`);
    const e = data.event;
    const v = data.verdict;
    const before = e.before || {};
    const after = e.after || {};

    $('#drawer-title').textContent = `Sự kiện #${e.id}`;

    const rows = [
      ['Đường dẫn', esc(e.path)],
      ['Loại', esc(e.change)],
      ['Nguồn', esc(e.source)],
      ['Thời điểm', fmtTime(e.ts)],
    ];
    if (v) rows.push(['Kết luận', `${sevBadge(v.severity)} · ${esc(v.classification)} · điểm ${v.score}`]);

    const diff = [];
    if (before.digest !== after.digest) {
      diff.push(['hash', `${esc((before.digest || '—').slice(0, 20))}…<br>→ ${esc((after.digest || '—').slice(0, 20))}…`]);
    }
    if (before.size !== after.size) {
      diff.push(['kích thước', `${fmtBytes(before.size || 0)} → ${fmtBytes(after.size || 0)}`]);
    }
    if (before.mode !== after.mode && (before.mode || after.mode)) {
      const oct = (m) => (m ? (m & 0o7777).toString(8).padStart(4, '0') : '—');
      diff.push(['quyền', `${oct(before.mode)} → ${oct(after.mode)}`]);
    }
    if (before.uid !== after.uid || before.gid !== after.gid) {
      diff.push(['chủ sở hữu', `${before.uid ?? '—'}:${before.gid ?? '—'} → ${after.uid ?? '—'}:${after.gid ?? '—'}`]);
    }

    let html = `<dl>${rows.map(([k, val]) => `<dt>${k}</dt><dd>${val}</dd>`).join('')}</dl>`;
    if (diff.length) {
      html += `<h3 style="font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin:0 0 6px">Trước → Sau</h3>`;
      html += `<dl>${diff.map(([k, val]) => `<dt>${k}</dt><dd>${val}</dd>`).join('')}</dl>`;
    }

    if (v && v.whitelisted) {
      html += `<p class="hint">Được whitelist <strong>${esc(v.whitelist_id)}</strong> miễn trừ.</p>`;
    }
    if (v && v.hits && v.hits.length) {
      html += `<h3 style="font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin:16px 0 6px">Căn cứ chấm điểm</h3>`;
      html += v.hits
        .slice()
        .sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight))
        .map((h) => `<div class="hit-row">
            <span class="hit-id">${esc(h.rule_id)}</span>
            <span class="hit-w ${h.weight >= 0 ? 'pos' : 'neg'}">${h.weight >= 0 ? '+' : ''}${h.weight}</span>
            <span><strong>${esc(h.title)}</strong>${h.detail ? `<br><span class="muted">${esc(h.detail)}</span>` : ''}</span>
          </div>`).join('');
    } else if (v) {
      html += '<p class="muted">Không luật nào khớp.</p>';
    }

    html += `<div style="display:flex;gap:8px;margin-top:18px">
        <button class="btn" id="drawer-approve">Chấp nhận vào baseline</button>
        <button class="btn" id="drawer-wl">Thêm whitelist cho đường dẫn này</button>
      </div>`;
    body.innerHTML = html;

    $('#drawer-approve').addEventListener('click', () => approveEvents([e.id]));
    $('#drawer-wl').addEventListener('click', () => {
      switchTab('whitelist');
      $('#wl-path').value = e.path;
      $('#wl-reason').focus();
      drawer.hidden = true;
    });
  } catch (err) {
    body.innerHTML = `<p class="muted">Lỗi: ${esc(err.message)}</p>`;
  }
}

/* ---------------------------------------------------------------- hành động */

async function approveEvents(ids) {
  try {
    const res = await api('/api/events/approve', {
      method: 'POST',
      body: JSON.stringify({ event_ids: ids }),
    });
    toast(`Đã cập nhật ${res.updated} mục vào baseline`);
    state.selected.clear();
    $('#drawer').hidden = true;
    await refreshAll();
  } catch (err) {
    toast(err.message, true);
  }
}

/* -------------------------------------------------------------- cảnh báo */

async function loadAlerts() {
  const status = $('#f-alert-status').value;
  const alerts = await api(`/api/alerts?limit=100${status ? `&status=${status}` : ''}`);
  const list = $('#alerts-list');

  if (!alerts.length) {
    list.innerHTML = '<p class="empty">Không có cảnh báo nào</p>';
    return;
  }

  list.innerHTML = alerts.map((a) => `
    <article class="card" data-sev="${esc(a.severity)}">
      <div class="card-head">
        <div>
          ${sevBadge(a.severity)}
          <span class="chip">${esc(a.status)}</span>
          <span class="muted" style="font-size:11px">${fmtTime(a.created_at)}</span>
        </div>
        <div class="card-actions">
          ${a.status === 'new' ? `<button class="btn" data-ack="${a.id}">Tiếp nhận</button>` : ''}
          ${a.status !== 'resolved' ? `<button class="btn" data-resolve="${a.id}">Đã xử lý</button>` : ''}
          ${a.status !== 'false_positive' ? `<button class="btn" data-fp="${a.id}">Báo sai</button>` : ''}
        </div>
      </div>
      <div class="card-title">${esc(a.path)}</div>
      <pre>${esc(a.summary)}</pre>
    </article>`).join('');

  const setStatus = async (id, status) => {
    try {
      await api(`/api/alerts/${id}`, { method: 'POST', body: JSON.stringify({ status }) });
      toast('Đã cập nhật cảnh báo');
      await Promise.all([loadAlerts(), loadStats()]);
    } catch (err) { toast(err.message, true); }
  };
  list.querySelectorAll('[data-ack]').forEach((b) =>
    b.addEventListener('click', () => setStatus(b.dataset.ack, 'ack')));
  list.querySelectorAll('[data-resolve]').forEach((b) =>
    b.addEventListener('click', () => setStatus(b.dataset.resolve, 'resolved')));
  list.querySelectorAll('[data-fp]').forEach((b) =>
    b.addEventListener('click', () => setStatus(b.dataset.fp, 'false_positive')));
}

/* ------------------------------------------------------------- whitelist */

async function loadWhitelist() {
  const entries = await api('/api/whitelist');
  const body = $('#wl-body');

  if (!entries.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty">Whitelist trống</td></tr>';
    return;
  }

  body.innerHTML = entries.map((e) => `
    <tr>
      <td class="path">${esc(e.id)}</td>
      <td>${e.active ? '<span class="sev" data-sev="low">có</span>'
                     : '<span class="sev" data-sev="info">không</span>'}</td>
      <td class="path">${esc(e.path_glob || e.digest || '—')}</td>
      <td>${e.rule_id ? `<span class="chip">${esc(e.rule_id)}</span>` : '<span class="muted">mọi luật</span>'}</td>
      <td class="num">${e.hit_count}</td>
      <td class="reason">${esc(e.reason)}</td>
      <td><button class="btn btn-ghost" data-del="${esc(e.id)}" title="Xoá">✕</button></td>
    </tr>`).join('');

  body.querySelectorAll('[data-del]').forEach((b) => {
    b.addEventListener('click', async () => {
      const id = b.dataset.del;
      if (!confirm(`Xoá mục whitelist "${id}"?`)) return;
      try {
        await api(`/api/whitelist/${encodeURIComponent(id)}`, { method: 'DELETE' });
        toast(`Đã xoá ${id}`);
        await Promise.all([loadWhitelist(), loadStats()]);
      } catch (err) { toast(err.message, true); }
    });
  });
}

/* ------------------------------------------------------- bộ luật & phạm vi */

async function loadRules() {
  const rules = await api('/api/rules');
  $('#rules-body').innerHTML = rules.map((r) => `
    <tr>
      <td class="path">${esc(r.rule_id)}</td>
      <td class="num" style="color:${r.weight >= 0 ? 'var(--sev-critical)' : 'var(--sev-low)'}">
        ${r.weight >= 0 ? '+' : ''}${r.weight}</td>
      <td>${esc(r.title)}${r.enabled ? '' : ' <span class="chip">đã tắt</span>'}</td>
      <td class="reason">${esc(r.description)}</td>
    </tr>`).join('');
}

async function loadScope() {
  const scope = await api('/api/scope');
  const block = (title, items, note) => `
    <div class="scope-block">
      <h3>${title} (${items.length})</h3>
      ${note ? `<p class="muted" style="font-size:11px;margin:0 0 6px">${note}</p>` : ''}
      ${items.length ? `<ul>${items.map((i) => `<li>${esc(i)}</li>`).join('')}</ul>`
                     : '<p class="muted" style="font-size:12px">(trống)</p>'}
    </div>`;

  $('#scope-view').innerHTML =
    `<div class="scope-block">
       <h3>Hồ sơ</h3>
       <p style="margin:0"><strong>${esc(scope.profile)}</strong></p>
       <p class="muted" style="font-size:12px;margin:4px 0 0">${esc(scope.description)}</p>
     </div>` +
    block('Thư mục gốc đang giám sát', scope.roots_present) +
    block('Khai báo nhưng không tồn tại', scope.roots_missing,
          'Bình thường khi hồ sơ dựng sẵn dùng trên hệ điều hành khác') +
    block('Mẫu loại trừ', scope.exclude) +
    block('Đường dẫn trọng yếu', scope.critical,
          'Thay đổi ở đây bị chấm điểm nặng hơn');
}

/* -------------------------------------------------------------------- tab */

function switchTab(name) {
  $$('.tab').forEach((t) => t.classList.toggle('is-active', t.dataset.tab === name));
  $$('.tabpanel').forEach((p) => p.classList.toggle('is-active', p.dataset.panel === name));
  ({
    events: loadEvents,
    alerts: loadAlerts,
    whitelist: loadWhitelist,
    rules: loadRules,
    scope: loadScope,
  }[name] || (() => {}))().catch((err) => toast(err.message, true));
}

/* ------------------------------------------------------------------- khởi tạo */

async function refreshAll() {
  const active = $('.tab.is-active').dataset.tab;
  await Promise.all([
    loadStats(),
    loadTimeline(),
    active === 'events' ? loadEvents() : Promise.resolve(),
    active === 'alerts' ? loadAlerts() : Promise.resolve(),
  ]);
}

function wire() {
  $('#range-select').addEventListener('change', (e) => {
    state.rangeHours = e.target.value ? Number(e.target.value) : null;
    state.page = 0;
    refreshAll().catch((err) => toast(err.message, true));
  });

  $('#scan-btn').addEventListener('click', async () => {
    try {
      await api('/api/scan', { method: 'POST' });
      toast('Đã bắt đầu quét…');
      $('#scan-btn').disabled = true;
      setTimeout(() => refreshAll().catch(() => {}), 2500);
    } catch (err) { toast(err.message, true); }
  });

  $('#theme-btn').addEventListener('click', () => {
    const current = document.documentElement.dataset.theme;
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('fim-theme', next); } catch { /* chế độ riêng tư */ }
    renderChart();
  });

  $$('.tab').forEach((t) => t.addEventListener('click', () => switchTab(t.dataset.tab)));

  let filterTimer;
  ['#f-severity', '#f-change', '#f-wl'].forEach((sel) =>
    $(sel).addEventListener('change', () => {
      state.page = 0;
      loadEvents().catch((err) => toast(err.message, true));
    }));
  $('#f-path').addEventListener('input', () => {
    clearTimeout(filterTimer);
    filterTimer = setTimeout(() => {
      state.page = 0;
      loadEvents().catch((err) => toast(err.message, true));
    }, 300);
  });

  $('#prev-btn').addEventListener('click', () => {
    if (state.page > 0) { state.page--; loadEvents(); }
  });
  $('#next-btn').addEventListener('click', () => { state.page++; loadEvents(); });

  $('#check-all').addEventListener('change', (e) => {
    state.events.forEach((ev) =>
      e.target.checked ? state.selected.add(ev.id) : state.selected.delete(ev.id));
    renderEvents();
  });

  $('#approve-btn').addEventListener('click', () => approveEvents([...state.selected]));

  $('#wl-from-sel').addEventListener('click', () => {
    const first = state.events.find((e) => state.selected.has(e.id));
    if (!first) return;
    switchTab('whitelist');
    $('#wl-path').value = first.path;
    $('#wl-reason').focus();
  });

  $('#f-alert-status').addEventListener('change', () =>
    loadAlerts().catch((err) => toast(err.message, true)));

  $('#wl-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
      path_glob: $('#wl-path').value.trim() || null,
      rule_id: $('#wl-rule').value.trim() || null,
      expires_at: $('#wl-expires').value.trim() || null,
      reason: $('#wl-reason').value.trim(),
    };
    if (!payload.path_glob) { toast('Cần nhập mẫu đường dẫn', true); return; }
    try {
      await api('/api/whitelist', { method: 'POST', body: JSON.stringify(payload) });
      toast('Đã thêm mục whitelist');
      e.target.reset();
      await Promise.all([loadWhitelist(), loadStats()]);
    } catch (err) { toast(err.message, true); }
  });

  $('#drawer-close').addEventListener('click', () => { $('#drawer').hidden = true; });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') $('#drawer').hidden = true;
  });

  let resizeTimer;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(renderChart, 150);
  });
}

function init() {
  try {
    const saved = localStorage.getItem('fim-theme');
    if (saved) document.documentElement.dataset.theme = saved;
  } catch { /* localStorage bị chặn */ }

  wire();
  refreshAll().catch((err) => toast(`Không tải được dữ liệu: ${err.message}`, true));
  setInterval(() => {
    if (!document.hidden) loadStats().catch(() => {});
  }, 15000);
}

document.addEventListener('DOMContentLoaded', init);
