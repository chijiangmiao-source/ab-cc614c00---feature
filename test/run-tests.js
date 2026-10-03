// run-tests.js — 逻辑测试：围绕有效链与受限域名拒绝等场景验证 chain.js 行为。
import { createHash } from 'node:crypto';
import { verifyChainSet, hostMatch, dnsWithin } from '../src/chain.js';
import { derEcdsaToRaw } from '../src/der.js';
import { makeCert, makeKeys, makeCrl, extn, OCT, SEQ } from './certgen.js';

const T = Date.parse('2026-10-01T12:00:00Z'); // 验证时刻（有效期内）
const NB = new Date('2026-01-01T00:00:00Z');
const NA = new Date('2027-01-01T00:00:00Z');

let passed = 0;
let failed = 0;

function ok(name, cond, detail = '') {
  if (cond) {
    passed++;
    console.log(`PASS ${name}`);
  } else {
    failed++;
    console.error(`FAIL ${name}${detail ? ` —— ${detail}` : ''}`);
  }
}

function assertOk(res, what) {
  return res.ok === true || `期望成功但失败：${what} → [${res.stage}] ${res.message}`;
}

function assertFail(res, stage, what) {
  if (res.ok) return `期望失败(${stage})但成功：${what}`;
  if (res.stage !== stage) return `期望阶段 ${stage}，实际 ${res.stage}：${what} → ${res.message}`;
  return true;
}

// 构造 root → (inter) → leaf 的证书世界；inter 为 null 时 leaf 直接由 root 签发。
function buildWorld({ root = {}, inter = {}, leaf = {} } = {}) {
  const rootK = makeKeys();
  const anchor = makeCert({
    subjectCN: 'Root CA', issuerCN: 'Root CA',
    subjectPubKey: rootK.publicKey, issuerPrivKey: rootK.privateKey,
    isCA: true, keyUsage: { keyCertSign: true, crlSign: true },
    serial: 100, notBefore: NB, notAfter: NA, ...root,
  });
  let interDer = null;
  let interK = null;
  if (inter !== null) {
    interK = makeKeys();
    interDer = makeCert({
      subjectCN: 'Inter CA', issuerCN: 'Root CA',
      subjectPubKey: interK.publicKey, issuerPrivKey: rootK.privateKey,
      isCA: true, pathLen: 0, keyUsage: { keyCertSign: true },
      serial: 200, notBefore: NB, notAfter: NA, ...inter,
    });
  }
  const leafK = makeKeys();
  const issuerK = inter === null ? rootK : interK;
  const leafDer = makeCert({
    subjectCN: 'app.example.com',
    issuerCN: inter === null ? 'Root CA' : 'Inter CA',
    subjectPubKey: leafK.publicKey, issuerPrivKey: issuerK.privateKey,
    keyUsage: { digitalSignature: true },
    sanDns: ['app.example.com'],
    serial: 300, notBefore: NB, notAfter: NA, ...leaf,
  });
  return { anchor, inter: interDer, leaf: leafDer, rootK, interK, leafK };
}

const run = (anchor, certs, dns = 'app.example.com', at = T) =>
  verifyChainSet({ anchorDer: anchor, certDers: certs, dnsName: dns, verifyTime: at });

// ---------- 单元：DER ECDSA 签名转换 ----------
{
  // r 带 0x00 符号填充（33 字节），s 仅 1 字节 → 输出 64 字节并正确补零
  const r = Uint8Array.from([0x00, ...Array(32).fill(0xab)]);
  const s = Uint8Array.of(0x7f);
  const der = SEQ(tlvInt(r), tlvInt(s));
  const raw = derEcdsaToRaw(der, 32);
  ok('单元：DER→raw 签名转换（去填充/补零）',
    raw.length === 64 && raw[0] === 0xab && raw[31] === 0xab && raw[32] === 0 && raw[63] === 0x7f);
  let threw = false;
  try {
    derEcdsaToRaw(Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x01), 32); // 缺 s
  } catch { threw = true; }
  ok('单元：畸形 DER 签名被拒绝', threw);

  function tlvInt(v) {
    const tag = Uint8Array.of(0x02, v.length);
    const out = new Uint8Array(2 + v.length);
    out.set(tag, 0);
    out.set(v, 2);
    return out;
  }
}

// ---------- 单元：主机名与约束匹配 ----------
{
  ok('单元：通配 SAN 单层匹配',
    hostMatch('*.example.com', 'foo.example.com')
    && !hostMatch('*.example.com', 'a.b.example.com')
    && !hostMatch('*.example.com', 'example.com'));
  ok('单元：DNS 约束语义',
    dnsWithin('a.example.com', 'example.com')
    && dnsWithin('example.com', 'example.com')
    && !dnsWithin('badexample.com', 'example.com')
    && dnsWithin('a.example.com', '.example.com')
    && !dnsWithin('example.com', '.example.com'));
}

// ---------- 场景 1：有效三级链 ----------
{
  const w = buildWorld();
  const res = await run(w.anchor, [w.leaf, w.inter]);
  ok('场景1：有效三级链成立', assertOk(res, '三级链') === true,
    res.ok ? '' : res.message);
  if (res.ok) {
    ok('场景1：链结构 叶→中间→锚',
      res.chain.length === 3 && res.chain[0].subject.includes('app.example.com')
      && res.chain[2].isAnchor && res.chain.every((c) => c.notes.length > 0));
  }
}

// ---------- 场景 2：有效二级链（叶直签于锚） ----------
{
  const w = buildWorld({ inter: null });
  const res = await run(w.anchor, [w.leaf]);
  ok('场景2：有效二级链成立', assertOk(res, '二级链') === true, res.ok ? '' : res.message);
}

// ---------- 场景 3：permitted 名称约束命中 ----------
{
  const w = buildWorld({ root: { nameConstraints: { permitted: ['example.com'] } } });
  const res = await run(w.anchor, [w.leaf, w.inter]);
  ok('场景3：permitted 约束覆盖目标名 → 成立', assertOk(res, 'permitted 命中') === true,
    res.ok ? '' : res.message);
}

// ---------- 场景 4：permitted 未覆盖 → 拒绝 ----------
{
  const w = buildWorld({
    root: { nameConstraints: { permitted: ['example.com'] } },
    leaf: { subjectCN: 'app.other.org', sanDns: ['app.other.org'] },
  });
  const res = await run(w.anchor, [w.leaf, w.inter], 'app.other.org');
  ok('场景4：目标名不在 permitted 内 → 拒绝(nameconstraint)',
    assertFail(res, 'nameconstraint', 'permitted 未覆盖') === true,
    res.ok ? '意外成功' : `[${res.stage}] ${res.message}`);
}

// ---------- 场景 5：excluded 命中 → 拒绝 ----------
{
  const w = buildWorld({
    root: { nameConstraints: { permitted: ['example.com'], excluded: ['bad.example.com'] } },
    leaf: { subjectCN: 'bad.example.com', sanDns: ['bad.example.com'] },
  });
  const res = await run(w.anchor, [w.leaf, w.inter], 'bad.example.com');
  ok('场景5：目标名命中 excluded → 拒绝(nameconstraint)',
    assertFail(res, 'nameconstraint', 'excluded 命中') === true,
    res.ok ? '意外成功' : `[${res.stage}] ${res.message}`);
}

// ---------- 场景 6：中间 CA 的 excluded 约束同样生效 ----------
{
  const w = buildWorld({
    inter: { nameConstraints: { excluded: ['bad.example.com'] } },
    leaf: { subjectCN: 'bad.example.com', sanDns: ['bad.example.com'] },
  });
  const res = await run(w.anchor, [w.leaf, w.inter], 'bad.example.com');
  ok('场景6：中间 CA excluded 累积生效 → 拒绝(nameconstraint)',
    assertFail(res, 'nameconstraint', '中间 CA excluded') === true,
    res.ok ? '意外成功' : `[${res.stage}] ${res.message}`);
}

// ---------- 场景 7：前导点约束仅覆盖子域 ----------
{
  const w = buildWorld({ root: { nameConstraints: { permitted: ['.example.com'] } } });
  const sub = await run(w.anchor, [w.leaf, w.inter], 'app.example.com');
  ok('场景7a：".example.com" 覆盖子域 → 成立', assertOk(sub, '子域') === true,
    sub.ok ? '' : sub.message);
  const w2 = buildWorld({
    root: { nameConstraints: { permitted: ['.example.com'] } },
    leaf: { subjectCN: 'example.com', sanDns: ['example.com'] },
  });
  const apex = await run(w2.anchor, [w2.leaf, w2.inter], 'example.com');
  ok('场景7b：".example.com" 不覆盖裸域 → 拒绝(nameconstraint)',
    assertFail(apex, 'nameconstraint', '裸域') === true,
    apex.ok ? '意外成功' : `[${apex.stage}] ${apex.message}`);
}

// ---------- 场景 8：pathLenConstraint 违约 ----------
{
  const w = buildWorld({ root: { pathLen: 0 } }); // 锚不允许下级 CA，但存在中间 CA
  const res = await run(w.anchor, [w.leaf, w.inter]);
  ok('场景8：锚 pathLen=0 存在中间 CA → 拒绝(pathlen)',
    assertFail(res, 'pathlen', 'pathLen 违约') === true && res.level === 2,
    res.ok ? '意外成功' : `[${res.stage}] L${res.level} ${res.message}`);
}

// ---------- 场景 9：pathLenConstraint 恰好满足 ----------
{
  const w = buildWorld({ root: { pathLen: 1 } });
  const res = await run(w.anchor, [w.leaf, w.inter]);
  ok('场景9：锚 pathLen=1 恰覆盖一级中间 CA → 成立', assertOk(res, 'pathLen 满足') === true,
    res.ok ? '' : res.message);
}

// ---------- 场景 10：签名被篡改 ----------
{
  const w = buildWorld({ leaf: { tamperSig: true } });
  const res = await run(w.anchor, [w.leaf, w.inter]);
  ok('场景10：叶证书签名篡改 → 拒绝(signature)',
    assertFail(res, 'signature', '篡改签名') === true && res.level === 0,
    res.ok ? '意外成功' : `[${res.stage}] L${res.level} ${res.message}`);
}

// ---------- 场景 11：有效期不覆盖验证时刻 ----------
{
  const w = buildWorld({ leaf: { notAfter: new Date('2026-06-01T00:00:00Z') } });
  const res = await run(w.anchor, [w.leaf, w.inter]);
  ok('场景11a：叶证书已过期 → 拒绝(validity)',
    assertFail(res, 'validity', '过期') === true,
    res.ok ? '意外成功' : `[${res.stage}] ${res.message}`);
  const w2 = buildWorld({ inter: { notBefore: new Date('2026-12-01T00:00:00Z') } });
  const res2 = await run(w2.anchor, [w2.leaf, w2.inter]);
  ok('场景11b：中间 CA 尚未生效 → 拒绝(validity)',
    assertFail(res2, 'validity', '未生效') === true && res2.level === 1,
    res2.ok ? '意外成功' : `[${res2.stage}] L${res2.level} ${res2.message}`);
}

// ---------- 场景 12：中间证书非 CA ----------
{
  const w = buildWorld({ inter: { isCA: false, pathLen: null, keyUsage: { digitalSignature: true } } });
  const res = await run(w.anchor, [w.leaf, w.inter]);
  ok('场景12：中间证书非 CA → 拒绝(ca)',
    assertFail(res, 'ca', '非 CA 签发者') === true && res.level === 1,
    res.ok ? '意外成功' : `[${res.stage}] L${res.level} ${res.message}`);
}

// ---------- 场景 13：CA 的 keyUsage 缺 keyCertSign ----------
{
  const w = buildWorld({ inter: { keyUsage: { digitalSignature: true } } });
  const res = await run(w.anchor, [w.leaf, w.inter]);
  ok('场景13：CA 缺 keyCertSign → 拒绝(keyusage)',
    assertFail(res, 'keyusage', '缺 keyCertSign') === true && res.level === 1,
    res.ok ? '意外成功' : `[${res.stage}] L${res.level} ${res.message}`);
}

// ---------- 场景 14：未知关键扩展 ----------
{
  const w = buildWorld({
    leaf: { extraExtensions: [extn('1.3.6.1.4.1.55555.1', true, OCT(Uint8Array.of(5, 0)))] },
  });
  const res = await run(w.anchor, [w.leaf, w.inter]);
  ok('场景14：未知关键扩展 → 拒绝(extension) 并定位证书',
    assertFail(res, 'extension', '未知关键扩展') === true && res.label === '证书#1',
    res.ok ? '意外成功' : `[${res.stage}] ${res.label} ${res.message}`);
}

// ---------- 场景 15：截断 DER ----------
{
  const w = buildWorld();
  const truncated = w.leaf.slice(0, w.leaf.length - 10);
  const res = await run(w.anchor, [truncated, w.inter]);
  ok('场景15：截断 DER → 拒绝(parse) 并定位证书',
    assertFail(res, 'parse', '截断') === true && res.label === '证书#1',
    res.ok ? '意外成功' : `[${res.stage}] ${res.label} ${res.message}`);
}

// ---------- 场景 16：循环签发 ----------
{
  const kA = makeKeys();
  const kB = makeKeys();
  const kLeaf = makeKeys();
  const certA = makeCert({
    subjectCN: 'A', issuerCN: 'B', subjectPubKey: kA.publicKey, issuerPrivKey: kB.privateKey,
    isCA: true, keyUsage: { keyCertSign: true }, serial: 401, notBefore: NB, notAfter: NA,
  });
  const certB = makeCert({
    subjectCN: 'B', issuerCN: 'A', subjectPubKey: kB.publicKey, issuerPrivKey: kA.privateKey,
    isCA: true, keyUsage: { keyCertSign: true }, serial: 402, notBefore: NB, notAfter: NA,
  });
  const leaf = makeCert({
    subjectCN: 'app.example.com', issuerCN: 'A',
    subjectPubKey: kLeaf.publicKey, issuerPrivKey: kA.privateKey,
    keyUsage: { digitalSignature: true }, sanDns: ['app.example.com'],
    serial: 403, notBefore: NB, notAfter: NA,
  });
  const w = buildWorld(); // 锚与 A/B 环无关
  const res = await run(w.anchor, [leaf, certA, certB]);
  ok('场景16：A↔B 循环签发 → 拒绝(cycle)',
    assertFail(res, 'cycle', '循环签发') === true,
    res.ok ? '意外成功' : `[${res.stage}] ${res.message}`);
}

// ---------- 场景 17：主机名未列入 SAN ----------
{
  const w = buildWorld();
  const res = await run(w.anchor, [w.leaf, w.inter], 'nosuch.example.com');
  ok('场景17：主机名未列入 SAN → 拒绝(hostname)',
    assertFail(res, 'hostname', '主机名不在 SAN') === true,
    res.ok ? '意外成功' : `[${res.stage}] ${res.message}`);
}

// ---------- 场景 18：多链成立 → 按 SHA-256 摘要序稳定选择 ----------
{
  const rootK = makeKeys();
  const anchor = makeCert({
    subjectCN: 'Root CA', issuerCN: 'Root CA',
    subjectPubKey: rootK.publicKey, issuerPrivKey: rootK.privateKey,
    isCA: true, keyUsage: { keyCertSign: true }, serial: 100, notBefore: NB, notAfter: NA,
  });
  const mkLeaf = (serial) => {
    const k = makeKeys();
    return makeCert({
      subjectCN: 'app.example.com', issuerCN: 'Root CA',
      subjectPubKey: k.publicKey, issuerPrivKey: rootK.privateKey,
      keyUsage: { digitalSignature: true }, sanDns: ['app.example.com'],
      serial, notBefore: NB, notAfter: NA,
    });
  };
  const leafA = mkLeaf(501);
  const leafB = mkLeaf(502);
  const dA = createHash('sha256').update(leafA).digest('hex');
  const dB = createHash('sha256').update(leafB).digest('hex');
  const expectLeaf = dA < dB ? dA : dB;
  const res1 = await run(anchor, [leafA, leafB]);
  const res2 = await run(anchor, [leafB, leafA]); // 打乱输入顺序
  ok('场景18：多链成立时按摘要序稳定选择',
    res1.ok && res2.ok && res1.chain[0].sha256 === expectLeaf && res2.chain[0].sha256 === expectLeaf,
    `期望叶摘要 ${expectLeaf}，实际 ${res1.ok ? res1.chain[0].sha256 : res1.message}`);
}

// ---------- 场景 19：通配 SAN ----------
{
  const w = buildWorld({ leaf: { sanDns: ['*.example.com'] } });
  const sub = await run(w.anchor, [w.leaf, w.inter], 'foo.example.com');
  ok('场景19a：通配 SAN 命中单层子域 → 成立', assertOk(sub, '通配') === true,
    sub.ok ? '' : sub.message);
  const deep = await run(w.anchor, [w.leaf, w.inter], 'a.b.example.com');
  ok('场景19b：通配 SAN 不跨层 → 拒绝(hostname)',
    assertFail(deep, 'hostname', '跨层通配') === true,
    deep.ok ? '意外成功' : `[${deep.stage}] ${deep.message}`);
}

// ---------- 场景 20：锚非 CA / 输入超限 ----------
{
  const w = buildWorld({ inter: null, root: { isCA: false, keyUsage: { keyCertSign: true } } });
  const res = await run(w.anchor, [w.leaf]);
  ok('场景20a：锚非 CA → 拒绝(ca)',
    assertFail(res, 'ca', '锚非 CA') === true,
    res.ok ? '意外成功' : `[${res.stage}] ${res.message}`);
  const res2 = await run(w.anchor, Array(8).fill(w.leaf), 'app.example.com');
  ok('场景20b：候选证书超过 7 张 → 拒绝(input)',
    assertFail(res2, 'input', '超过上限') === true,
    res2.ok ? '意外成功' : `[${res2.stage}] ${res2.message}`);
}

// ---------- 场景 21：有效期边界（含端点） ----------
{
  const w = buildWorld();
  const atNotAfter = await run(w.anchor, [w.leaf, w.inter], 'app.example.com', NA.getTime());
  ok('场景21：验证时刻取 notAfter 端点 → 成立', assertOk(atNotAfter, '边界') === true,
    atNotAfter.ok ? '' : atNotAfter.message);
}

// ---------- CRL 场景 ----------

const CRL_THIS = new Date('2026-09-01T00:00:00Z');
const CRL_NEXT = new Date('2026-11-01T00:00:00Z');
const runCrl = (anchor, certs, crlDer, dns = 'app.example.com', at = T) =>
  verifyChainSet({
    anchorDer: anchor, certDers: certs, dnsName: dns, verifyTime: at,
    crlEnabled: true, crlDer,
  });

// ---------- 场景 22：开关关闭 / 未提供清单 → 裁决不变 ----------
{
  const w = buildWorld();
  const crlRevoking = makeCrl({
    issuerCN: 'Inter CA', issuerPrivKey: w.interK.privateKey,
    revoked: [{ serial: 300, date: CRL_THIS }],
    thisUpdate: CRL_THIS, nextUpdate: CRL_NEXT,
  });
  // 开关关闭：即使传入（语义上不会传）撤销叶证书的清单，结论仍成立
  const resOff = await verifyChainSet({
    anchorDer: w.anchor, certDers: [w.leaf, w.inter], dnsName: 'app.example.com', verifyTime: T,
    crlEnabled: false, crlDer: null,
  });
  ok('场景22a：开关关闭 → 既有链裁决不变（成立）', assertOk(resOff, '关闭开关') === true,
    resOff.ok ? '' : resOff.message);
  // 开关开启但未提供清单 → 清单可选，跳过 CRL 核验，既有裁决不变
  const resNoCrl = await verifyChainSet({
    anchorDer: w.anchor, certDers: [w.leaf, w.inter], dnsName: 'app.example.com', verifyTime: T,
    crlEnabled: true, crlDer: null,
  });
  ok('场景22b：开关开启但未提供清单 → 视为未提供，裁决不变（成立）',
    assertOk(resNoCrl, '无清单') === true,
    resNoCrl.ok ? '' : resNoCrl.message);
  // 关闭开关时即便给出清单字节也不予核验
  const resOffBytes = await verifyChainSet({
    anchorDer: w.anchor, certDers: [w.leaf, w.inter], dnsName: 'app.example.com', verifyTime: T,
    crlEnabled: false, crlDer: crlRevoking,
  });
  ok('场景22c：开关关闭时清单字节被忽略，叶证书不被撤销', assertOk(resOffBytes, '关闭忽略清单') === true,
    resOffBytes.ok ? '' : resOffBytes.message);
}

// ---------- 场景 23：有效 CRL，叶证书未被撤销 → 成立并附依据 ----------
{
  const w = buildWorld();
  const crl = makeCrl({
    issuerCN: 'Inter CA', issuerPrivKey: w.interK.privateKey,
    revoked: [{ serial: 999, date: CRL_THIS }], // 撤销的是别的序列号
    thisUpdate: CRL_THIS, nextUpdate: CRL_NEXT,
  });
  const res = await runCrl(w.anchor, [w.leaf, w.inter], crl);
  ok('场景23：有效 CRL 未列叶序列号 → 成立', assertOk(res, 'CRL 干净') === true,
    res.ok ? '' : res.message);
  if (res.ok) {
    const note = res.chain[0].notes.find((n) => n.includes('CRL 撤销核验通过'));
    ok('场景23：叶级别展示 CRL 核验依据', !!note, note || '缺少 CRL 通过说明');
  }
}

// ---------- 场景 24：叶序列号在清单中 → 拒绝(crl) 并展示条目 ----------
{
  const w = buildWorld();
  const crl = makeCrl({
    issuerCN: 'Inter CA', issuerPrivKey: w.interK.privateKey,
    revoked: [
      { serial: 300, date: new Date('2026-09-20T00:00:00Z') },
      { serial: 301, date: CRL_THIS },
    ],
    thisUpdate: CRL_THIS, nextUpdate: CRL_NEXT,
  });
  const res = await runCrl(w.anchor, [w.leaf, w.inter], crl);
  ok('场景24：叶序列号被列入 CRL → 拒绝(crl) 并定位叶证书',
    assertFail(res, 'crl', '已撤销') === true && res.level === 0,
    res.ok ? '意外成功' : `[${res.stage}] L${res.level} ${res.message}`);
  if (!res.ok) {
    ok('场景24：失败信息展示对应撤销条目（序列号/撤销时间）',
      res.message.includes('012c') && res.message.includes('2026-09-20'),
      res.message);
  }
}

// ---------- 场景 25：二级链（直接签发者为锚）CRL 撤销 ----------
{
  const w = buildWorld({ inter: null });
  const crl = makeCrl({
    issuerCN: 'Root CA', issuerPrivKey: w.rootK.privateKey,
    revoked: [{ serial: 300, date: CRL_THIS }],
    thisUpdate: CRL_THIS, nextUpdate: CRL_NEXT,
  });
  const res = await runCrl(w.anchor, [w.leaf], crl);
  ok('场景25：叶直签于锚，锚签发的 CRL 列入叶 → 拒绝(crl)',
    assertFail(res, 'crl', '锚 CRL 撤销') === true && res.level === 0,
    res.ok ? '意外成功' : `[${res.stage}] L${res.level} ${res.message}`);
}

// ---------- 场景 26：CRL 签发者名称与直接签发者不匹配 → 拒绝(crl) ----------
{
  const w = buildWorld();
  // 清单名称是锚而非叶的直接签发者（Inter CA），即使签名本身有效也必须拒绝
  const crl = makeCrl({
    issuerCN: 'Root CA', issuerPrivKey: w.rootK.privateKey,
    revoked: [], thisUpdate: CRL_THIS, nextUpdate: CRL_NEXT,
  });
  const res = await runCrl(w.anchor, [w.leaf, w.inter], crl);
  ok('场景26：CRL 签发者非叶直接签发者 → 拒绝(crl) 定位签发者级别',
    assertFail(res, 'crl', '签发者不匹配') === true && res.level === 1,
    res.ok ? '意外成功' : `[${res.stage}] L${res.level} ${res.message}`);
}

// ---------- 场景 27：CRL 签名不符 → 拒绝(crl) ----------
{
  const w = buildWorld();
  const wrongK = makeKeys();
  // 名称与 Inter CA 相同，但用他人私钥签名
  const crl = makeCrl({
    issuerCN: 'Inter CA', issuerPrivKey: w.interK.privateKey, signKey: wrongK.privateKey,
    revoked: [], thisUpdate: CRL_THIS, nextUpdate: CRL_NEXT,
  });
  const res = await runCrl(w.anchor, [w.leaf, w.inter], crl);
  ok('场景27a：CRL 签名密钥不符 → 拒绝(crl)',
    assertFail(res, 'crl', '签名不符') === true && res.level === 1,
    res.ok ? '意外成功' : `[${res.stage}] L${res.level} ${res.message}`);
  // 篡改签名字节
  const crlTampered = makeCrl({
    issuerCN: 'Inter CA', issuerPrivKey: w.interK.privateKey,
    revoked: [], thisUpdate: CRL_THIS, nextUpdate: CRL_NEXT, tamperSig: true,
  });
  const res2 = await runCrl(w.anchor, [w.leaf, w.inter], crlTampered);
  ok('场景27b：CRL 签名被篡改 → 拒绝(crl)',
    assertFail(res2, 'crl', '签名篡改') === true && res2.level === 1,
    res2.ok ? '意外成功' : `[${res2.stage}] L${res2.level} ${res2.message}`);
}

// ---------- 场景 28：CRL 过期 / 尚未生效 → 拒绝(crl) ----------
{
  const w = buildWorld();
  const expired = makeCrl({
    issuerCN: 'Inter CA', issuerPrivKey: w.interK.privateKey,
    revoked: [],
    thisUpdate: new Date('2026-01-01T00:00:00Z'), nextUpdate: new Date('2026-06-01T00:00:00Z'),
  });
  const resExp = await runCrl(w.anchor, [w.leaf, w.inter], expired);
  ok('场景28a：CRL 已过期（nextUpdate 早于验证时刻）→ 拒绝(crl)',
    assertFail(resExp, 'crl', 'CRL 过期') === true && resExp.level === 1,
    resExp.ok ? '意外成功' : `[${resExp.stage}] L${resExp.level} ${resExp.message}`);
  const future = makeCrl({
    issuerCN: 'Inter CA', issuerPrivKey: w.interK.privateKey,
    revoked: [],
    thisUpdate: new Date('2026-12-01T00:00:00Z'), nextUpdate: new Date('2027-06-01T00:00:00Z'),
  });
  const resFuture = await runCrl(w.anchor, [w.leaf, w.inter], future);
  ok('场景28b：CRL 尚未生效（thisUpdate 晚于验证时刻）→ 拒绝(crl)',
    assertFail(resFuture, 'crl', 'CRL 未生效') === true && resFuture.level === 1,
    resFuture.ok ? '意外成功' : `[${resFuture.stage}] L${resFuture.level} ${resFuture.message}`);
  // 边界：验证时刻恰为 nextUpdate 端点 → 覆盖，成立
  const atEdge = new Date('2026-11-01T00:00:00Z').getTime();
  const edge = makeCrl({
    issuerCN: 'Inter CA', issuerPrivKey: w.interK.privateKey,
    revoked: [], thisUpdate: CRL_THIS, nextUpdate: CRL_NEXT,
  });
  const resEdge = await runCrl(w.anchor, [w.leaf, w.inter], edge, 'app.example.com', atEdge);
  ok('场景28c：验证时刻取 nextUpdate 端点 → 覆盖成立', assertOk(resEdge, 'CRL 端点') === true,
    resEdge.ok ? '' : resEdge.message);
}

// ---------- 场景 29：CRL 准入：v1 / 错误算法 / 截断 DER → 拒绝 ----------
{
  const w = buildWorld();
  const v1 = makeCrl({
    issuerCN: 'Inter CA', issuerPrivKey: w.interK.privateKey,
    version2: false, revoked: [], thisUpdate: CRL_THIS, nextUpdate: CRL_NEXT,
  });
  const resV1 = await runCrl(w.anchor, [w.leaf, w.inter], v1);
  ok('场景29a：CRL v1 不接受 → 拒绝(parse)',
    assertFail(resV1, 'parse', 'v1') === true && resV1.label === 'CRL 撤销清单',
    resV1.ok ? '意外成功' : `[${resV1.stage}] ${resV1.label} ${resV1.message}`);
  const badAlg = makeCrl({
    issuerCN: 'Inter CA', issuerPrivKey: w.interK.privateKey,
    algOid: '1.2.840.10045.4.3.3', // ecdsa-with-SHA384
    revoked: [], thisUpdate: CRL_THIS, nextUpdate: CRL_NEXT,
  });
  const resAlg = await runCrl(w.anchor, [w.leaf, w.inter], badAlg);
  ok('场景29b：非 ECDSA/SHA-256 算法的 CRL → 拒绝(algorithm)',
    assertFail(resAlg, 'algorithm', '算法准入') === true,
    resAlg.ok ? '意外成功' : `[${resAlg.stage}] ${resAlg.message}`);
  const good = makeCrl({
    issuerCN: 'Inter CA', issuerPrivKey: w.interK.privateKey,
    revoked: [], thisUpdate: CRL_THIS, nextUpdate: CRL_NEXT,
  });
  const truncated = good.slice(0, good.length - 12);
  const resTrunc = await runCrl(w.anchor, [w.leaf, w.inter], truncated);
  ok('场景29c：截断 CRL DER → 拒绝(parse)',
    assertFail(resTrunc, 'parse', '截断 CRL') === true,
    resTrunc.ok ? '意外成功' : `[${resTrunc.stage}] ${resTrunc.message}`);
}

// ---------- 场景 30：链本身失败时不因 CRL 掩盖首个失败环节 ----------
{
  const w = buildWorld({ leaf: { tamperSig: true } });
  const crl = makeCrl({
    issuerCN: 'Inter CA', issuerPrivKey: w.interK.privateKey,
    revoked: [{ serial: 300, date: CRL_THIS }],
    thisUpdate: CRL_THIS, nextUpdate: CRL_NEXT,
  });
  const res = await runCrl(w.anchor, [w.leaf, w.inter], crl);
  ok('场景30：证书链签名失败优先暴露 → 拒绝(signature) 而非 crl',
    assertFail(res, 'signature', '链失败优先') === true,
    res.ok ? '意外成功' : `[${res.stage}] ${res.message}`);
}

// ---------- 场景 31：高位为 1 的序列号（证书 DER 带前导 00）仍能匹配撤销条目 ----------
{
  const w = buildWorld({ leaf: { serial: 0x80ff } }); // 33023，DER 编码为 00 80 ff
  const crl = makeCrl({
    issuerCN: 'Inter CA', issuerPrivKey: w.interK.privateKey,
    revoked: [{ serial: 0x80ff, date: CRL_THIS }],
    thisUpdate: CRL_THIS, nextUpdate: CRL_NEXT,
  });
  const res = await runCrl(w.anchor, [w.leaf, w.inter], crl);
  ok('场景31：前导 00 的序列号按整数语义匹配 → 拒绝(crl)',
    assertFail(res, 'crl', '高位序列号撤销') === true && res.level === 0,
    res.ok ? '意外成功' : `[${res.stage}] L${res.level} ${res.message}`);
}

console.log(`\n${passed} 项通过，${failed} 项失败`);
process.exit(failed === 0 ? 0 : 1);
