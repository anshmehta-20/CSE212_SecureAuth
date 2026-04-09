/**
 * script.js – SecureAuth frontend
 * Supports: login page, MFA page, dashboard
 */

/* ── Config ── */
const API = location.protocol === 'file:'
  ? 'http://localhost:5000/api'
  : `${location.origin}/api`;

/* ── Storage ── */
const Store = {
  set:   (k, v) => sessionStorage.setItem(`sa_${k}`, JSON.stringify(v)),
  get:   (k)    => { try { return JSON.parse(sessionStorage.getItem(`sa_${k}`)); } catch { return null; } },
  del:   (k)    => sessionStorage.removeItem(`sa_${k}`),
  clear: ()     => ['token','refresh','user','risk','mfa_token'].forEach(k => Store.del(k)),
};

/* ── API fetch ── */
async function api(endpoint, opts = {}) {
  const token   = Store.get('token');
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  try {
    const res  = await fetch(`${API}${endpoint}`, { ...opts, headers });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
  } catch {
    return { ok: false, status: 0, data: { error: 'Network error. Is the server running on port 5000?' } };
  }
}

/* ── Alerts ── */
function showAlert(id, msg, type = 'error') {
  const el = document.getElementById(id);
  if (!el) return;
  const dots = { error: '', success: '', warning: '', info: '' };
  el.innerHTML = `
    <div class="alert alert-${type}" role="alert">
      <div class="alert-dot"></div>
      <span>${esc(msg)}</span>
    </div>`;
}
function clearAlert(id) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = '';
}

function esc(str) {
  const d = document.createElement('div');
  d.textContent = String(str);
  return d.innerHTML;
}

/* ── Button loading ── */
function setLoading(id, state) {
  const btn = document.getElementById(id);
  if (!btn) return;
  btn.disabled = state;
  btn.classList.toggle('loading', state);
}

/* ── Risk helpers ── */
function riskClass(level)   { return { LOW: 'low', MEDIUM: 'medium', HIGH: 'high' }[level] ?? 'low'; }
function riskColor(level)   { return { LOW: 'var(--green)', MEDIUM: 'var(--amber)', HIGH: 'var(--red)' }[level] ?? 'var(--text-2)'; }
function riskLabel(level)   { return { LOW: 'Low', MEDIUM: 'Medium', HIGH: 'High' }[level] ?? level; }
function makeBadge(level) {
  const cls = riskClass(level);
  return `<div class="badge badge-${cls}"><div class="badge-dot"></div>${riskLabel(level)}</div>`;
}

/* ── Animate number ── */
function animNum(el, target, dur = 900) {
  if (!el) return;
  const start = performance.now();
  const from  = 0;
  (function tick(now) {
    const t    = Math.min((now - start) / dur, 1);
    const ease = 1 - Math.pow(1 - t, 3);
    el.textContent = Math.round(from + (target - from) * ease);
    if (t < 1) requestAnimationFrame(tick);
  })(start);
}

/* ── Date format ── */
function fmtDate(str) {
  if (!str) return '—';
  try { return new Date(str.includes('T') ? str : str + 'Z').toLocaleString(); } catch { return str; }
}

/* ── Page detection ── */
const PAGE = (() => {
  const p = location.pathname;
  if (p.includes('dashboard')) return 'dashboard';
  if (p.includes('mfa'))       return 'mfa';
  return 'login';
})();


/* ════════════════════════════════════════════════════════════════
   LOGIN PAGE
   ════════════════════════════════════════════════════════════════ */
if (PAGE === 'login') {

  if (Store.get('token')) location.href = 'dashboard.html';

  /* Typing speed tracking */
  let _tStart = null, _tChars = 0;
  document.getElementById('password')?.addEventListener('keydown', () => {
    if (!_tStart) _tStart = Date.now();
    _tChars++;
  });

  /* Form submit */
  document.getElementById('login-form')?.addEventListener('submit', async e => {
    e.preventDefault();
    clearAlert('alert-container');

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    let hasError   = false;

    // Inline validation
    const errU = document.getElementById('err-username');
    const errP = document.getElementById('err-password');
    if (!username) { document.getElementById('username').classList.add('is-error'); errU?.classList.add('visible'); hasError = true; }
    else           { document.getElementById('username').classList.remove('is-error'); errU?.classList.remove('visible'); }
    if (!password) { document.getElementById('password').classList.add('is-error'); errP?.classList.add('visible'); hasError = true; }
    else           { document.getElementById('password').classList.remove('is-error'); errP?.classList.remove('visible'); }
    if (hasError) return;

    let typing_speed = null;
    if (_tStart && _tChars > 3) {
      typing_speed = _tChars / ((Date.now() - _tStart) / 1000);
    }

    setLoading('login-btn', true);
    const { ok, status, data } = await api('/login', {
      method: 'POST',
      body:   JSON.stringify({ username, password, typing_speed }),
    });
    setLoading('login-btn', false);

    if (status === 429) { showAlert('alert-container', data.error || 'Rate limit exceeded. Please wait.', 'warning'); return; }
    if (status === 403 && data?.locked) { showAlert('alert-container', data.error, 'warning'); return; }
    if (data?.error && !data?.risk_score) { showAlert('alert-container', data.error, 'error'); return; }

    openResultModal(data);
  });

  /* ── Result modal ── */
  function openResultModal(data) {
    const score  = data.risk_score  ?? 0;
    const level  = data.risk_level  ?? 'LOW';
    const status = data.status      ?? 'blocked';
    const conf   = data.confidence  ?? 0;
    const expl   = data.explanation ?? data.error ?? '—';

    // Dot colour
    const dot = document.getElementById('modal-dot');
    if (dot) {
      dot.className = `status-dot ${
        status === 'success' ? 'allowed' : status === 'mfa_required' ? 'mfa' : 'blocked'
      }`;
    }

    // Title
    const titles = { success: 'Login successful', mfa_required: 'Verification required', blocked: 'Login blocked' };
    document.getElementById('modal-title').textContent    = titles[status] ?? 'Login result';
    document.getElementById('modal-subtitle').textContent = {
      success:      `Risk score ${score.toFixed(0)}/100 — access granted`,
      mfa_required: `Risk score ${score.toFixed(0)}/100 — further verification needed`,
      blocked:      `Risk score ${score.toFixed(0)}/100 — access denied by AI policy`,
    }[status] ?? '';

    // Score
    const scoreEl = document.getElementById('modal-score');
    animNum(scoreEl, score);

    // Badge
    document.getElementById('modal-badge').innerHTML = makeBadge(level);

    // Bar
    const bar = document.getElementById('modal-bar');
    bar.className = `risk-bar-fill ${riskClass(level)}`;
    setTimeout(() => { bar.style.width = `${Math.min(score, 100)}%`; }, 80);

    // Explanation
    document.getElementById('modal-expl').textContent = expl.trim() || '—';

    // Actions
    const acts = document.getElementById('modal-actions');
    acts.innerHTML = '';

    const closeBtn = document.createElement('button');
    closeBtn.className   = 'btn btn-secondary';
    closeBtn.textContent = 'Close';
    closeBtn.onclick     = closeModal;

    if (status === 'success') {
      Store.set('token',   data.access_token);
      Store.set('refresh', data.refresh_token);
      Store.set('user',    data.user);
      Store.set('risk',    { risk_score: score, risk_level: level, confidence: conf, explanation: expl });

      const goBtn = document.createElement('button');
      goBtn.className   = 'btn btn-primary';
      goBtn.textContent = 'Go to dashboard';
      goBtn.onclick     = () => { location.href = 'dashboard.html'; };
      acts.appendChild(goBtn);
      acts.appendChild(closeBtn);

    } else if (status === 'mfa_required') {
      Store.set('mfa_token', data.mfa_token);
      Store.set('risk', { risk_score: score, risk_level: level, confidence: conf, explanation: expl });

      const mfaBtn = document.createElement('button');
      mfaBtn.className   = 'btn btn-primary';
      mfaBtn.textContent = 'Enter verification code';
      mfaBtn.onclick     = () => { location.href = 'mfa.html'; };
      acts.appendChild(mfaBtn);
      acts.appendChild(closeBtn);

    } else {
      const retryBtn = document.createElement('button');
      retryBtn.className   = 'btn btn-primary';
      retryBtn.textContent = 'Try again';
      retryBtn.onclick     = closeModal;
      acts.appendChild(retryBtn);
      acts.appendChild(closeBtn);
    }

    // Open modal
    document.getElementById('result-modal').classList.add('open');
  }

  function closeModal() {
    document.getElementById('result-modal').classList.remove('open');
  }

  // Close on backdrop click
  document.getElementById('result-modal')?.addEventListener('click', e => {
    if (e.target === e.currentTarget) closeModal();
  });
}


/* ════════════════════════════════════════════════════════════════
   MFA PAGE
   ════════════════════════════════════════════════════════════════ */
if (PAGE === 'mfa') {

  const mfaToken = Store.get('mfa_token');
  if (!mfaToken) location.href = 'index.html';

  /* Risk context bar */
  const risk = Store.get('risk');
  if (risk) {
    const ctx = document.getElementById('risk-context');
    if (ctx) {
      ctx.style.display = 'block';
      document.getElementById('ctx-score').textContent = `${Math.round(risk.risk_score ?? 0)} / 100`;
      document.getElementById('ctx-badge').innerHTML   = makeBadge(risk.risk_level ?? 'MEDIUM');
      const bar = document.getElementById('ctx-bar');
      bar.className = `risk-bar-fill ${riskClass(risk.risk_level ?? 'MEDIUM')}`;
      setTimeout(() => { bar.style.width = `${risk.risk_score ?? 0}%`; }, 100);
    }
  }

  /* OTP box navigation */
  const boxes = [...document.querySelectorAll('.otp-box')];

  boxes.forEach((box, i) => {
    box.addEventListener('input', e => {
      const v = e.target.value.replace(/\D/g, '');
      box.value = v.slice(-1);
      box.classList.toggle('filled', !!box.value);
      if (v && i < boxes.length - 1) boxes[i + 1].focus();
    });
    box.addEventListener('keydown', e => {
      if (e.key === 'Backspace' && !box.value && i > 0) boxes[i - 1].focus();
      if (e.key === 'ArrowLeft'  && i > 0)               boxes[i - 1].focus();
      if (e.key === 'ArrowRight' && i < boxes.length - 1) boxes[i + 1].focus();
    });
    box.addEventListener('paste', e => {
      e.preventDefault();
      const text = (e.clipboardData || window.clipboardData).getData('text').replace(/\D/g, '');
      text.slice(0, 6).split('').forEach((ch, j) => {
        if (boxes[j]) { boxes[j].value = ch; boxes[j].classList.add('filled'); }
      });
      boxes[Math.min(text.length, 5)]?.focus();
    });
  });
  boxes[0]?.focus();

  /* Countdown */
  let secsLeft = 5 * 60;
  const timerEl  = document.getElementById('otp-timer');
  const countEl  = document.getElementById('countdown');
  const resendBtn = document.getElementById('resend-btn');

  const fmt = s => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
  countEl.textContent = fmt(secsLeft);

  const iv = setInterval(() => {
    secsLeft--;
    if (secsLeft <= 0) {
      clearInterval(iv);
      timerEl.classList.add('expired');
      countEl.textContent = 'Expired';
      resendBtn.disabled  = false;
    } else {
      countEl.textContent = fmt(secsLeft);
      if (secsLeft <= 60) timerEl.classList.add('expired');
      if (secsLeft <= (5 * 60 - 30)) resendBtn.disabled = false;
    }
  }, 1000);

  /* Verify */
  document.getElementById('verify-btn')?.addEventListener('click', async () => {
    const otp = boxes.map(b => b.value).join('');
    if (otp.length !== 6) {
      showAlert('alert-container', 'Please enter all 6 digits.', 'warning');
      return;
    }
    clearAlert('alert-container');
    setLoading('verify-btn', true);

    const { data } = await api('/verify-mfa', {
      method: 'POST',
      body:   JSON.stringify({ mfa_token: mfaToken, otp }),
    });

    setLoading('verify-btn', false);

    if (data.status === 'success') {
      clearInterval(iv);
      Store.set('token',   data.access_token);
      Store.set('refresh', data.refresh_token);
      Store.set('user',    data.user);
      Store.del('mfa_token');
      showAlert('alert-container', 'Verified. Redirecting to dashboard...', 'success');
      setTimeout(() => { location.href = 'dashboard.html'; }, 1000);
    } else {
      showAlert('alert-container', data.error || 'Verification failed. Check your code and try again.', 'error');
      boxes.forEach(b => {
        b.classList.add('is-error');
        setTimeout(() => b.classList.remove('is-error'), 800);
      });
    }
  });

  /* Resend */
  document.getElementById('resend-btn')?.addEventListener('click', async () => {
    clearAlert('alert-container');
    const { data } = await api('/resend-otp', {
      method: 'POST', body: JSON.stringify({ mfa_token: mfaToken }),
    });
    if (data.status === 'success') {
      Store.set('mfa_token', data.mfa_token);
      showAlert('alert-container', 'A new code has been sent to your email.', 'success');
      secsLeft = 5 * 60;
      timerEl.classList.remove('expired');
      countEl.textContent = fmt(secsLeft);
      resendBtn.disabled  = true;
    } else {
      showAlert('alert-container', data.error || 'Failed to resend code.', 'error');
    }
  });
}


/* ════════════════════════════════════════════════════════════════
   DASHBOARD
   ════════════════════════════════════════════════════════════════ */
if (PAGE === 'dashboard') {

  if (!Store.get('token')) location.href = 'index.html';

  /* Tab navigation */
  const tabs   = document.querySelectorAll('.nav-tab');
  const panels = document.querySelectorAll('.tab-panel');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      panels.forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(`panel-${tab.dataset.tab}`)?.classList.add('active');
      // Lazy-load admin
      if (tab.dataset.tab === 'admin' && !_adminLoaded) { loadAdmin(); _adminLoaded = true; }
    });
  });

  /* Logout */
  document.getElementById('logout-btn')?.addEventListener('click', async () => {
    const refresh = Store.get('refresh');
    await api('/logout', { method: 'POST', body: JSON.stringify({ refresh_token: refresh }) });
    Store.clear();
    location.href = 'index.html';
  });

  let _adminLoaded = false;

  async function tryRefresh() {
    const refresh = Store.get('refresh');
    if (!refresh) return false;
    const { ok, data } = await api('/refresh', {
      method: 'POST', body: JSON.stringify({ refresh_token: refresh }),
    });
    if (ok && data.access_token) { Store.set('token', data.access_token); return true; }
    return false;
  }

  async function loadDashboard() {
    /* User info */
    let { ok, data: ud } = await api('/me');
    if (!ok) {
      await tryRefresh();
      const r = await api('/me');
      if (!r.ok) { Store.clear(); location.href = 'index.html'; return; }
      ud = r.data;
    }
    const user = ud.user ?? Store.get('user');
    if (!user) { Store.clear(); location.href = 'index.html'; return; }

    // Navbar chip
    const initial = (user.username ?? '?')[0].toUpperCase();
    setText('user-avatar',  initial);
    setText('user-display', user.username ?? '');

    const roleTag = document.getElementById('role-tag');
    if (user.role === 'admin' && roleTag) {
      roleTag.textContent = 'Admin';
      roleTag.classList.remove('hidden');
      document.getElementById('tab-admin')?.classList.remove('hidden');
    }

    // Info grid
    setText('info-username', user.username);
    setText('info-email',    user.email);
    setText('info-role',     user.role === 'admin' ? 'Administrator' : 'User');
    setText('info-created',  fmtDate(user.created_at));

    /* Risk */
    const cached = Store.get('risk');
    if (cached) {
      renderRisk(cached);
    } else {
      const { ok: rOk, data: rData } = await api('/risk-summary');
      if (rOk && rData.data) renderRisk(rData.data);
    }

    /* History */
    loadHistory();
  }

  function renderRisk(r) {
    const score = parseFloat(r.risk_score ?? r.score ?? 0);
    const level = r.risk_level ?? r.level ?? 'LOW';
    const conf  = parseFloat(r.confidence ?? 0);
    const expl  = r.explanation ?? '—';

    // Stats
    const sEl = document.getElementById('stat-score');
    if (sEl) animNum(sEl, score);

    const lvlEl = document.getElementById('stat-level');
    if (lvlEl) {
      lvlEl.innerHTML = makeBadge(level);
      lvlEl.style.fontSize = '';
    }

    const confEl = document.getElementById('stat-confidence');
    if (confEl) {
      animNum(confEl, Math.round(conf * 100));
      confEl.textContent += '%';
    }

    // Big score
    const bigEl = document.getElementById('score-big');
    if (bigEl) animNum(bigEl, score);
    document.getElementById('score-badge').innerHTML = makeBadge(level);

    // Bar
    const bar = document.getElementById('score-bar');
    if (bar) {
      bar.className = `risk-bar-fill ${riskClass(level)}`;
      setTimeout(() => { bar.style.width = `${Math.min(score, 100)}%`; }, 150);
    }

    // Explanation
    setText('expl-block', expl.trim() || '—');
  }

  async function loadHistory() {
    const { ok, data } = await api('/history?limit=25');
    const tbody  = document.getElementById('history-body');
    const cntEl  = document.getElementById('history-count');
    if (!ok || !data.history) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;color:var(--text-3);padding:20px">No data found.</td></tr>`;
      return;
    }
    const rows = data.history;
    if (cntEl) cntEl.textContent = `${rows.length} entries`;

    tbody.innerHTML = rows.map((r, i) => `
      <tr>
        <td style="color:var(--text-3)">${i + 1}</td>
        <td>${esc(fmtDate(r.timestamp))}</td>
        <td style="font-family:ui-monospace,monospace;font-size:12px">${esc(r.ip_address ?? '—')}</td>
        <td>${esc(r.location ?? '—')}</td>
        <td style="font-size:12px;color:var(--text-3)">${esc(r.device_hash ?? '—')}</td>
        <td style="font-variant-numeric:tabular-nums;font-weight:500;color:${riskColor(r.risk_level)}">${r.risk_score?.toFixed(1) ?? '—'}</td>
        <td>${makeBadge(r.risk_level ?? 'LOW')}</td>
        <td>${statusCell(r.status)}</td>
      </tr>
    `).join('');
  }

  async function loadAdmin() {
    const { ok, data } = await api('/analytics');
    if (!ok) { showAlert('alert-container', 'Failed to load analytics.', 'error'); return; }

    setText('adm-users',   data.total_users   ?? '—');
    setText('adm-logins',  data.total_logins_7d ?? '—');
    setText('adm-blocked', data.status_breakdown?.blocked ?? 0);

    renderDailyChart(data.daily_logins ?? []);
    renderRiskChart(data.risk_distribution ?? {});

    // Users table
    const { ok: uOk, data: uData } = await api('/users');
    if (uOk && uData.users) {
      _adminUsersList = uData.users;
      renderAdminUsers();
    }
  }

  let _adminUsersList = [];

  function renderAdminUsers() {
    const query = (document.getElementById('admin-user-search')?.value || '').toLowerCase();
    const filtered = _adminUsersList.filter(u => 
      (u.username && u.username.toLowerCase().includes(query)) || 
      (u.email && u.email.toLowerCase().includes(query))
    );
    
    document.getElementById('users-body').innerHTML = filtered.map(u => `
      <tr>
        <td style="color:var(--text-3)">${u.id}</td>
        <td>${esc(u.username)}</td>
        <td>${esc(u.email)}</td>
        <td>${u.role === 'admin' ? 'Administrator' : 'User'}</td>
        <td>${u.is_locked
             ? `<div class="badge badge-high"><div class="badge-dot"></div>Locked</div>`
             : `<div class="badge badge-low"><div class="badge-dot"></div>Active</div>`}</td>
        <td style="font-variant-numeric:tabular-nums">${u.failed_attempts}</td>
        <td>${esc(fmtDate(u.created_at))}</td>
        <td>
          <button class="btn btn-ghost btn-sm edit-user-action" data-id="${u.id}" style="padding:4px 8px; font-size:12px;">Edit</button>
        </td>
      </tr>
    `).join('');

    if (filtered.length === 0) {
      document.getElementById('users-body').innerHTML = `<tr><td colspan="8" style="text-align:center;color:var(--text-3);padding:24px">No users found.</td></tr>`;
    }

    document.querySelectorAll('.edit-user-action').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const id = parseInt(e.target.dataset.id);
        const user = _adminUsersList.find(c => c.id === id);
        if (user) {
          document.getElementById('edit-user-id').value = user.id;
          document.getElementById('edit-username').value = user.username;
          document.getElementById('edit-role').value = user.role;
          document.getElementById('edit-password').value = '';
          clearAlert('admin-edit-alert');
          document.getElementById('admin-edit-modal').classList.add('open');
        }
      });
    });
  }

  document.getElementById('admin-user-search')?.addEventListener('input', renderAdminUsers);

  function renderDailyChart(daily) {
    const canvas = document.getElementById('daily-chart');
    if (!canvas || !window.Chart) return;
    new Chart(canvas, {
      type: 'bar',
      data: {
        labels:   daily.map(d => d.date),
        datasets: [{
          label:           'Logins',
          data:            daily.map(d => d.count),
          backgroundColor: 'rgba(59,130,246,0.25)',
          borderColor:     'rgba(59,130,246,0.7)',
          borderWidth:     1,
          borderRadius:    4,
        }],
      },
      options: chartOpts(),
    });
  }

  function renderRiskChart(dist) {
    const canvas = document.getElementById('risk-chart');
    if (!canvas || !window.Chart) return;
    const labels = Object.keys(dist);
    const colors  = { LOW: '#22c55e', MEDIUM: '#f59e0b', HIGH: '#ef4444' };
    new Chart(canvas, {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{
          data:            Object.values(dist),
          backgroundColor: labels.map(l => colors[l] ?? '#3b82f6'),
          borderWidth:     0,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
          legend: { position: 'bottom', labels: { color: '#9ca3af', font: { size: 12, family: 'Inter' }, padding: 16 } },
        },
        cutout: '60%',
      },
    });
  }

  function chartOpts() {
    return {
      responsive: true,
      maintainAspectRatio: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#6b7280', font: { size: 11, family: 'Inter' } }, grid: { color: 'rgba(31,41,55,0.8)' } },
        y: { ticks: { color: '#6b7280', font: { size: 11, family: 'Inter' } }, grid: { color: 'rgba(31,41,55,0.8)' }, beginAtZero: true },
      },
    };
  }

  /* ── Helpers ── */
  function setText(id, val) {
    const el = document.getElementById(id);
    if (el) {
      if (val && val.toString().startsWith('<')) el.innerHTML = val;
      else el.textContent = val ?? '—';
    }
  }

  function statusCell(status) {
    const map = {
      allowed:      `<div class="badge badge-low"><div class="badge-dot"></div>Allowed</div>`,
      mfa_required: `<div class="badge badge-medium"><div class="badge-dot"></div>MFA</div>`,
      mfa:          `<div class="badge badge-medium"><div class="badge-dot"></div>MFA</div>`,
      blocked:      `<div class="badge badge-high"><div class="badge-dot"></div>Blocked</div>`,
    };
    return map[status] ?? `<span style="color:var(--text-3)">${esc(status ?? '—')}</span>`;
  }

  /* ── Password Visibility Toggles ── */
  document.querySelectorAll('.toggle-pwd-btn').forEach(btn => {
    btn.addEventListener('click', function () {
      const targetId = this.dataset.target;
      const inp = document.getElementById(targetId);
      if (!inp) return;
      const isText = inp.type === 'text';
      inp.type = isText ? 'password' : 'text';
      
      const svg = this.querySelector('.eye-icon-svg');
      if (svg) {
        svg.innerHTML = isText
          ? '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>'
          : '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/>';
      }
    });
  });

  /* ── Change Email ── */
  document.getElementById('change-email-btn')?.addEventListener('click', async () => {
    const newEmail = prompt("Enter your new email address:");
    if (!newEmail) return;
    
    if (!newEmail.includes('@')) {
        showAlert('alert-container', 'Invalid email address.', 'error');
        return;
    }
    
    const { ok, data } = await api('/me/email', {
        method: 'PUT',
        body: JSON.stringify({ email: newEmail })
    });
    
    if (ok) {
        document.getElementById('info-email').textContent = newEmail;
        showAlert('alert-container', 'Email successfully updated.', 'success');
        const user = Store.get('user');
        if (user) {
            user.email = newEmail;
            Store.set('user', user);
        }
    } else {
        showAlert('alert-container', data.error || 'Failed to update email.', 'error');
    }
  });

  /* ── Admin Edit User ── */
  document.getElementById('admin-edit-close-btn')?.addEventListener('click', () => {
    document.getElementById('admin-edit-modal').classList.remove('open');
  });

  document.getElementById('admin-edit-modal')?.addEventListener('click', e => {
    if (e.target === e.currentTarget) e.target.classList.remove('open');
  });

  document.getElementById('admin-edit-form')?.addEventListener('submit', async e => {
    e.preventDefault();
    clearAlert('admin-edit-alert');
    
    const id = document.getElementById('edit-user-id').value;
    const username = document.getElementById('edit-username').value.trim();
    const role = document.getElementById('edit-role').value;
    const password = document.getElementById('edit-password').value;
    
    setLoading('admin-edit-save-btn', true);
    
    const bodyArgs = { username, role };
    if (password) bodyArgs.password = password;
    
    const { ok, status, data } = await api(`/users/${id}`, {
      method: 'PUT',
      body: JSON.stringify(bodyArgs),
    });
    
    setLoading('admin-edit-save-btn', false);
    
    if (ok) {
      document.getElementById('admin-edit-modal').classList.remove('open');
      loadAdmin();
    } else {
      showAlert('admin-edit-alert', data.error || 'Failed to update user.', 'error');
    }
  });

  /* ── Add User ── */
  document.getElementById('add-user-form')?.addEventListener('submit', async e => {
    e.preventDefault();
    clearAlert('add-user-alert');
    
    const username = document.getElementById('new-username').value.trim();
    const email = document.getElementById('new-email').value.trim();
    const password = document.getElementById('new-password').value;
    const role = document.getElementById('new-role').value;
    
    setLoading('add-user-btn', true);
    
    const { ok, status, data } = await api('/users', {
      method: 'POST',
      body: JSON.stringify({ username, email, password, role }),
    });
    
    setLoading('add-user-btn', false);
    
    if (ok) {
      showAlert('add-user-alert', 'User added successfully!', 'success');
      document.getElementById('add-user-form').reset();
      loadAdmin(); // Reload the users table
    } else {
      showAlert('add-user-alert', data.error || 'Failed to add user.', 'error');
    }
  });

  // Auto-refresh every 12 min
  setInterval(tryRefresh, 12 * 60 * 1000);

  loadDashboard();
}
