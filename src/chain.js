// chain.js — 候选链构造与逐级核验。
// 流程：解析 → 摘要去重 → 叶证书候选 → DFS 构造叶→锚候选链 →
//       按 SHA-256 摘要序稳定排序 → 逐级核验（有效期 / CA 与 keyUsage /
//       pathLenConstraint / 累积 DNS 名称约束 / 签名）→ 多链取摘要序最小者。

import { parseCertificate } from './x509.js';
import { derEcdsaToRaw, toHex } from './der.js';

export const STAGE_LABELS = {
  input: '输入校验',
  parse: 'DER/证书解析',
  algorithm: '算法准入',
  extension: '关键扩展',
  hostname: '主机名匹配',
  chain: '链路构造',
  cycle: '循环签发',
  validity: '有效期',
  ca: 'CA 属性',
  keyusage: 'keyUsage',
  pathlen: 'pathLenConstraint',
  nameconstraint: '名称约束',
  signature: '签名核验',
  internal: '内部错误',
};

const MAX_POOL = 7;

function fail(stage, level, label, message) {
  return { ok: false, stage, level, label, message };
}

function iso(ms) {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

// SAN 条目与目标主机名匹配（支持单层通配 *.example.com）。
export function hostMatch(pattern, host) {
  const p = String(pattern).toLowerCase();
  const h = String(host).toLowerCase();
  if (p.startsWith('*.')) {
    const suffix = p.slice(1); // ".example.com"
    if (!h.endsWith(suffix)) return false;
    const head = h.slice(0, h.length - suffix.length);
    return head.length > 0 && !head.includes('.');
  }
  return p === h;
}

// RFC 5280 DNS 名称约束：约束 "example.com" 覆盖其本身与全部子域；
// 约束 ".example.com" 仅覆盖子域。
export function dnsWithin(name, constraint) {
  const n = String(name).toLowerCase();
  const c = String(constraint).toLowerCase();
  if (c.startsWith('.')) return n.length > c.length && n.endsWith(c);
  return n === c || n.endsWith('.' + c);
}

// 返回 null 表示通过，否则返回违约说明。
function checkConstraints(name, { permitted, excluded }) {
  for (const ex of excluded) {
    if (dnsWithin(name, ex)) return `名称 “${name}” 命中 excluded 名称约束 “${ex}”`;
  }
  if (permitted.length > 0 && !permitted.some((p) => dnsWithin(name, p))) {
    return `名称 “${name}” 不在 permitted 名称约束（${permitted.join(' / ')}）之内`;
  }
  return null;
}

function mergeConstraints(a, b) {
  return { permitted: [...a.permitted, ...b.permitted], excluded: [...a.excluded, ...b.excluded] };
}

async function verifySignature(issuerCert, cert) {
  try {
    const key = await globalThis.crypto.subtle.importKey(
      'spki', issuerCert.spkiRaw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'],
    );
    const rawSig = derEcdsaToRaw(cert.signatureDer, 32); // DER → WebCrypto raw(r||s)
    return await globalThis.crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } }, key, rawSig, cert.tbs,
    );
  } catch {
    return false;
  }
}

// 核验单条候选链（chain[0]=叶，chain[n-1]=锚）。成功返回逐级依据，失败返回首个失败环节。
async function verifyOneChain(chain, host, at) {
  const n = chain.length;
  const notes = chain.map(() => []);

  // 自顶向下累积名称约束：above[i] = 第 i 级证书上方所有 CA 的约束并集。
  const above = new Array(n);
  let acc = { permitted: [], excluded: [] };
  for (let i = n - 1; i >= 0; i--) {
    above[i] = acc;
    if (i > 0) acc = mergeConstraints(acc, chain[i].nameConstraints);
  }

  const failAt = (stage, level, message) => ({
    ok: false, stage, level, label: chain[level].label, message, progress: level,
  });

  for (let i = 0; i < n; i++) {
    const c = chain[i];
    const isAnchor = i === n - 1;

    if (at < c.notBefore || at > c.notAfter) {
      return failAt('validity', i,
        `有效期 ${iso(c.notBefore)} ~ ${iso(c.notAfter)} 不覆盖验证时刻 ${iso(at)}`);
    }
    notes[i].push(`有效期 ${iso(c.notBefore)} ~ ${iso(c.notAfter)} 覆盖验证时刻`);

    if (i === 0) {
      if (c.isCA) return failAt('ca', i, '叶证书 basicConstraints 为 CA=true，不能作为终端实体');
      if (c.sanDns.length === 0) return failAt('hostname', i, '叶证书缺少 dNSName 类型的 SAN');
      const hit = c.sanDns.find((d) => hostMatch(d, host));
      if (!hit) {
        return failAt('hostname', i, `目标主机名 “${host}” 未列入 SAN（${c.sanDns.join(', ')}）`);
      }
      notes[i].push(`SAN 条目 “${hit}” 命中目标主机名 “${host}”`);
      for (const d of c.sanDns) {
        const nc = checkConstraints(d, above[0]);
        if (nc) return failAt('nameconstraint', i, nc);
      }
      const ncHost = checkConstraints(host, above[0]);
      if (ncHost) return failAt('nameconstraint', i, ncHost);
      if (above[0].permitted.length || above[0].excluded.length) {
        notes[i].push(`通过累积名称约束（permitted ${above[0].permitted.length} 条 / excluded ${above[0].excluded.length} 条）`);
      }
    } else {
      if (!c.isCA) return failAt('ca', i, 'basicConstraints 非 CA，不能作为签发者');
      notes[i].push('basicConstraints CA=true');
      if (c.keyUsagePresent) {
        if (!c.keyCertSign) return failAt('keyusage', i, 'keyUsage 缺少 keyCertSign');
        notes[i].push('keyUsage 含 keyCertSign');
      } else {
        notes[i].push('未声明 keyUsage（按 RFC 5280 不限制）');
      }
      const belowCa = i - 1; // 该 CA 下方的 CA 证书数量（叶非 CA）
      if (c.pathLen !== null) {
        if (belowCa > c.pathLen) {
          return failAt('pathlen', i, `pathLenConstraint=${c.pathLen}，其下级 CA 数为 ${belowCa}`);
        }
        notes[i].push(`pathLenConstraint=${c.pathLen} ≥ 下级 CA 数 ${belowCa}`);
      }
      for (const d of c.sanDns) {
        const nc = checkConstraints(d, above[i]);
        if (nc) return failAt('nameconstraint', i, nc);
      }
      if (c.nameConstraints.permitted.length || c.nameConstraints.excluded.length) {
        notes[i].push(`本级名称约束已累积：permitted [${c.nameConstraints.permitted.join(', ') || '—'}] excluded [${c.nameConstraints.excluded.join(', ') || '—'}]`);
      }
    }

    if (!isAnchor) {
      const issuer = chain[i + 1];
      if (!(await verifySignature(issuer, c))) {
        return failAt('signature', i,
          `签名验证失败：签发者 ${issuer.label}（${issuer.subject.str}）的公钥无法验证该证书`);
      }
      notes[i].push(`签名经 L${i + 1}（${issuer.subject.str}）P-256 公钥验证通过（ECDSA/SHA-256）`);
    } else {
      notes[i].push('信任锚：按配置直接信任，签名免验');
    }
  }

  return {
    ok: true,
    chain: chain.map((c, i) => ({
      level: i,
      label: c.label,
      subject: c.subject.str,
      issuer: c.issuer.str,
      serial: c.serial,
      sha256: c.sha256,
      notBefore: iso(c.notBefore),
      notAfter: iso(c.notAfter),
      isAnchor: i === n - 1,
      notes: notes[i],
    })),
  };
}

// 主入口：anchorDer / certDers 为 Uint8Array，dnsName 为字符串，verifyTime 为毫秒时间戳。
export async function verifyChainSet({ anchorDer, certDers, dnsName, verifyTime }) {
  if (!anchorDer || anchorDer.length === 0) return fail('input', null, null, '缺少信任锚证书');
  if (!Array.isArray(certDers) || certDers.length === 0) {
    return fail('input', null, null, '至少需要 1 张候选证书（叶证书）');
  }
  if (certDers.length > MAX_POOL) {
    return fail('input', null, null, `候选证书数量 ${certDers.length} 超过上限 ${MAX_POOL}`);
  }
  const host = String(dnsName || '').trim().toLowerCase().replace(/\.$/, '');
  if (!host) return fail('input', null, null, '缺少目标 DNS 名称');
  const at = Number(verifyTime);
  if (!Number.isFinite(at)) return fail('input', null, null, '验证时刻非法');

  // —— 解析（含 v3 / P-256 / ECDSA-SHA256 准入与未知关键扩展检查）
  let anchor;
  try {
    anchor = parseCertificate(anchorDer);
  } catch (e) {
    return fail(e.stage || 'parse', null, '信任锚', e.message);
  }
  anchor.label = '信任锚';
  const pool = [];
  for (let idx = 0; idx < certDers.length; idx++) {
    const label = `证书#${idx + 1}`;
    try {
      const c = parseCertificate(certDers[idx]);
      c.label = label;
      pool.push(c);
    } catch (e) {
      return fail(e.stage || 'parse', null, label, e.message);
    }
  }

  // —— SHA-256 摘要与去重
  const all = [anchor, ...pool];
  for (const c of all) {
    c.sha256 = toHex(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', c.der)));
  }
  const seen = new Set([anchor.sha256]);
  const uniq = pool.filter((c) => {
    if (seen.has(c.sha256)) return false;
    seen.add(c.sha256);
    return true;
  });

  // —— 叶证书候选：非 CA 且 SAN 命中目标主机名
  const leaves = uniq
    .filter((c) => !c.isCA && c.sanDns.some((d) => hostMatch(d, host)))
    .sort((a, b) => (a.sha256 < b.sha256 ? -1 : 1));
  if (leaves.length === 0) {
    return fail('hostname', 0, null, `目标主机名 “${host}” 未列入任何终端实体证书的 SAN`);
  }

  // —— 构造候选链（叶 → 锚，DFS，检测循环签发）
  const bySubject = new Map();
  for (const c of uniq) {
    const k = toHex(c.subject.der);
    if (!bySubject.has(k)) bySubject.set(k, []);
    bySubject.get(k).push(c);
  }
  for (const list of bySubject.values()) list.sort((a, b) => (a.sha256 < b.sha256 ? -1 : 1));
  const anchorKey = toHex(anchor.subject.der);
  const maxDepth = uniq.length + 1;
  const candidates = [];
  const buildErrors = [];
  for (const leaf of leaves) {
    const path = [leaf];
    const inPath = new Set([leaf.sha256]);
    const dfs = (cur) => {
      const issKey = toHex(cur.issuer.der);
      if (issKey === anchorKey) {
        candidates.push([...path, anchor]);
        return;
      }
      const issuers = bySubject.get(issKey) || [];
      if (issuers.length === 0) {
        buildErrors.push({
          stage: 'chain', label: cur.label,
          message: `找不到 “${cur.issuer.str}” 的签发者证书，链路无法到达信任锚`,
        });
        return;
      }
      for (const iss of issuers) {
        if (inPath.has(iss.sha256)) {
          buildErrors.push({
            stage: 'cycle', label: iss.label,
            message: `检测到循环签发：“${iss.subject.str}” 已在当前链路径中`,
          });
          continue;
        }
        if (path.length >= maxDepth) {
          buildErrors.push({ stage: 'chain', label: iss.label, message: '链长超过候选证书数量' });
          continue;
        }
        path.push(iss);
        inPath.add(iss.sha256);
        dfs(iss);
        path.pop();
        inPath.delete(iss.sha256);
      }
    };
    dfs(leaf);
  }
  if (candidates.length === 0) {
    const e = buildErrors[0] || { stage: 'chain', label: null, message: '无法构造到达信任锚的候选链' };
    return fail(e.stage, null, e.label, e.message);
  }

  // —— 稳定排序：按叶→锚各级证书 SHA-256 摘要的字典序
  const chainKey = (chain) => chain.map((c) => c.sha256).join('|');
  candidates.sort((a, b) => {
    const ka = chainKey(a);
    const kb = chainKey(b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });

  // —— 逐级核验；多链成立时取摘要序最小者
  const failures = [];
  for (const cand of candidates) {
    const res = await verifyOneChain(cand, host, at);
    if (res.ok) return res;
    failures.push(res);
  }
  failures.sort((a, b) => b.progress - a.progress);
  const best = failures[0];
  return fail(best.stage, best.level, best.label, best.message);
}
