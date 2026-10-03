// app.js — 页面交互：采集输入、Base64 解码、调用 Worker、渲染结论。
import { STAGE_LABELS } from './chain.js';

const $ = (id) => document.getElementById(id);
const els = {
  anchor: $('anchor'),
  certs: $('certs'),
  dns: $('dns'),
  time: $('time'),
  submit: $('submit'),
  clear: $('clear'),
  status: $('status'),
  result: $('result'),
};

const DRAFT_KEY = 'cert-review-draft';

function pad(n) {
  return String(n).padStart(2, '0');
}

function toLocalInput(d) {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// —— 草稿：刷新后恢复，可一键清空
try {
  const draft = JSON.parse(localStorage.getItem(DRAFT_KEY) || 'null');
  if (draft) {
    els.anchor.value = draft.anchor || '';
    els.certs.value = draft.certs || '';
    els.dns.value = draft.dns || '';
    if (draft.time) els.time.value = draft.time;
  }
} catch { /* 忽略损坏的草稿 */ }
if (!els.time.value) els.time.value = toLocalInput(new Date());

function saveDraft() {
  localStorage.setItem(DRAFT_KEY, JSON.stringify({
    anchor: els.anchor.value,
    certs: els.certs.value,
    dns: els.dns.value,
    time: els.time.value,
  }));
}
for (const el of [els.anchor, els.certs, els.dns, els.time]) {
  el.addEventListener('input', saveDraft);
}

// —— Worker 通讯
const worker = new Worker('./worker.js', { type: 'module' });
let reqId = 0;
const pending = new Map();
worker.onmessage = (e) => {
  const { id, result } = e.data;
  const resolve = pending.get(id);
  if (resolve) {
    pending.delete(id);
    resolve(result);
  }
};
worker.onerror = (e) => {
  setBusy(false);
  showError('internal', null, null, `Worker 错误：${e.message || '未知'}`);
};

function runVerify(payload) {
  return new Promise((resolve) => {
    const id = ++reqId;
    pending.set(id, resolve);
    worker.postMessage({ id, ...payload });
  });
}

function b64ToBytes(b64, what) {
  const clean = String(b64).replace(/-----[^-]*-----/g, '').replace(/\s+/g, '');
  if (!clean) throw new Error(`${what}为空`);
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean) || clean.length % 4 !== 0) {
    throw new Error(`${what}不是合法的 Base64`);
  }
  const bin = atob(clean);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));
}

function setBusy(busy) {
  els.submit.disabled = busy;
  els.submit.textContent = busy ? '复核中…' : '提交复核';
}

function showError(stage, level, label, message) {
  els.result.replaceChildren(); // 失败时清除旧成功结论
  els.status.textContent = '结论：验证失败';
  els.status.className = 'fail';
  const where = [
    STAGE_LABELS[stage] || stage,
    level !== null && level !== undefined ? `L${level}` : null,
    label,
  ].filter(Boolean).join(' / ');
  const div = document.createElement('div');
  div.className = 'error';
  div.innerHTML = `<strong>首个失败环节：</strong>${escapeHtml(where)}<br><strong>原因：</strong>${escapeHtml(message)}`;
  els.result.appendChild(div);
}

function render(r) {
  els.result.replaceChildren();
  if (!r.ok) {
    showError(r.stage, r.level, r.label, r.message);
    return;
  }
  els.status.textContent = `结论：信任链成立（${r.chain.length} 级，按 SHA-256 摘要序稳定选出）`;
  els.status.className = 'ok';
  const ol = document.createElement('ol');
  ol.className = 'chain';
  for (const c of r.chain) {
    const li = document.createElement('li');
    const head = document.createElement('div');
    head.className = 'cert-head';
    head.textContent = `L${c.level} ${c.isAnchor ? '［信任锚］' : ''} ${c.subject}（${c.label}）`;
    const meta = document.createElement('div');
    meta.className = 'fp';
    meta.textContent = `SHA-256 ${c.sha256} ｜ 序列号 ${c.serial} ｜ 签发者 ${c.issuer}`;
    const ul = document.createElement('ul');
    for (const n of c.notes) {
      const ni = document.createElement('li');
      ni.textContent = n;
      ul.appendChild(ni);
    }
    li.append(head, meta, ul);
    ol.appendChild(li);
  }
  els.result.appendChild(ol);
}

els.submit.addEventListener('click', async () => {
  els.result.replaceChildren(); // 提交即清除旧结论
  let payload;
  try {
    const anchorDer = b64ToBytes(els.anchor.value, '信任锚证书');
    const lines = els.certs.value.split(/\n+/).map((s) => s.trim()).filter(Boolean);
    if (lines.length === 0) throw new Error('请至少粘贴 1 张候选证书（叶证书）');
    if (lines.length > 7) throw new Error(`候选证书 ${lines.length} 张，超过上限 7 张`);
    const certDers = lines.map((l, i) => b64ToBytes(l, `候选证书#${i + 1}`));
    const dnsName = els.dns.value.trim();
    if (!dnsName) throw new Error('请填写目标 DNS 名称');
    const t = new Date(els.time.value);
    if (Number.isNaN(t.getTime())) throw new Error('验证时刻非法');
    payload = { anchorDer, certDers, dnsName, verifyTime: t.getTime() };
  } catch (e) {
    showError('input', null, null, e.message);
    return;
  }
  setBusy(true);
  els.status.textContent = 'Worker 复核中…';
  els.status.className = '';
  const result = await runVerify(payload);
  setBusy(false);
  render(result);
});

els.clear.addEventListener('click', () => {
  els.anchor.value = '';
  els.certs.value = '';
  els.dns.value = '';
  els.time.value = toLocalInput(new Date());
  localStorage.removeItem(DRAFT_KEY);
  els.result.replaceChildren();
  els.status.textContent = '待提交';
  els.status.className = '';
});
