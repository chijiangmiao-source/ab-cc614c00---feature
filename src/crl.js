// crl.js — X.509 CRL（CertificateList）解析与核验。
// 准入规则：仅接受 v2 CRL、内外签名算法均为 ecdsa-with-SHA256（P-256）。
// 解析时保留待验签的原始 TBSCertList 字节（tbs），供 Worker 以叶证书直接签发者
// 的 P-256 公钥核验签名；另核验签发者名称与 thisUpdate / nextUpdate 覆盖关系，
// 并在已核验清单中查找叶证书序列号。

import {
  DerError, readElement, children, expect, oidString, intValue,
  bitString, toHex, derEcdsaToRaw,
} from './der.js';
import { parseName, parseTime, OID } from './x509.js';

export class CrlError extends Error {
  constructor(stage, message) {
    super(message);
    this.name = 'CrlError';
    this.stage = stage; // 'crlparse' | 'crlversion' | 'crlalgorithm' | 'crlextension'
  }
}

// 已知、与本工具判定无关而允许忽略的 CRL 扩展（即使 critical）。
const IGNORED_KNOWN = new Set([OID.crlNumber, OID.aki]);

function algOid(el) {
  expect(el, 0, 16, 'AlgorithmIdentifier SEQUENCE');
  const parts = children(el);
  if (parts.length < 1) throw new DerError('AlgorithmIdentifier 为空');
  return oidString(parts[0].value);
}

// 解析 crlExtensions [0] EXPLICIT Extensions；未知关键扩展直接拒绝。
function parseCrlExtensions(container) {
  const extSeq = readElement(container.value, 0);
  expect(extSeq, 0, 16, 'CRL Extensions SEQUENCE');
  const unknownCritical = [];
  for (const extnEl of children(extSeq)) {
    const parts = children(extnEl);
    if (parts.length < 2 || parts.length > 3) throw new DerError('CRL 扩展结构错误');
    const oid = oidString(parts[0].value);
    let critical = false;
    if (parts.length === 3) {
      critical = parts[1].tagClass === 0 && parts[1].tag === 1 && parts[1].value[0] !== 0;
    }
    if (critical && !IGNORED_KNOWN.has(oid)) unknownCritical.push(oid);
  }
  if (unknownCritical.length > 0) {
    throw new CrlError('crlextension', `撤销清单含未知关键扩展：${unknownCritical.join(', ')}`);
  }
}

// 解析一张 DER 编码的 CertificateList；失败抛出 CrlError（带 stage）。
export function parseCrl(derBytes) {
  const der = derBytes instanceof Uint8Array ? derBytes : new Uint8Array(derBytes);
  try {
    const top = readElement(der, 0);
    expect(top, 0, 16, 'CertificateList SEQUENCE');
    if (top.next !== der.length) throw new DerError('撤销清单存在尾随字节');
    const parts = children(top);
    if (parts.length !== 3) throw new DerError('CertificateList 应含 3 个字段（TBSCertList / signatureAlgorithm / signatureValue）');
    const [tbsEl, sigAlgEl, sigValEl] = parts;

    const tbsRaw = tbsEl.raw; // —— 待验签的原始 TBSCertList 字节 ——
    const t = children(tbsEl);
    let i = 0;

    // version [0] EXPLICIT INTEGER：存在时必须为 v2（整数值 1）；缺失即 v1，拒绝。
    if (i >= t.length || t[i].tagClass !== 2 || t[i].tag !== 0) {
      throw new CrlError('crlversion', '仅接受 v2 撤销清单：缺少 version 字段（疑似 v1 CRL）');
    }
    const versionInt = readElement(t[i].value, 0);
    expect(versionInt, 0, 2, 'CRL version INTEGER');
    const version = intValue(versionInt.value);
    if (version !== 1) {
      throw new CrlError('crlversion', `仅接受 v2 撤销清单（实际版本整数 ${version}）`);
    }
    i++;

    const tbsAlg = algOid(t[i]);
    if (tbsAlg !== OID.ecdsaSha256) {
      throw new CrlError('crlalgorithm', `仅接受 P-256 ECDSA/SHA-256 撤销清单（TBS 签名算法 OID ${tbsAlg}）`);
    }
    i++;

    const issuer = parseName(t[i]);
    i++;

    // thisUpdate / nextUpdate 均为 Time（UTCTime 或 GeneralizedTime）。
    if (i >= t.length || (t[i].tagClass !== 0 || (t[i].tag !== 23 && t[i].tag !== 24))) {
      throw new DerError('缺少 thisUpdate 字段');
    }
    const thisUpdate = parseTime(t[i]);
    i++;

    if (i >= t.length || (t[i].tagClass !== 0 || (t[i].tag !== 23 && t[i].tag !== 24))) {
      throw new DerError('缺少 nextUpdate 字段：无法判定清单覆盖关系');
    }
    const nextUpdate = parseTime(t[i]);
    i++;
    if (nextUpdate < thisUpdate) throw new DerError('CRL 时效区间非法（nextUpdate 早于 thisUpdate）');

    // revokedCertificates SEQUENCE OF SEQUENCE（可选）。
    const revoked = [];
    if (i < t.length && t[i].tagClass === 0 && t[i].tag === 16) {
      for (const entry of children(t[i])) {
        expect(entry, 0, 16, 'RevokedCertificate SEQUENCE');
        const eParts = children(entry);
        if (eParts.length < 2) throw new DerError('RevokedCertificate 至少含序列号与撤销日期');
        expect(eParts[0], 0, 2, 'userCertificate INTEGER');
        if (eParts[0].value.length === 0) throw new DerError('撤销条目序列号为空');
        const revocationDate = parseTime(eParts[1]);
        // crlEntryExtensions [0] EXPLICIT（可选）：仅校验位置与结构。
        if (eParts.length > 2 && !(eParts[2].tagClass === 2 && eParts[2].tag === 0)) {
          throw new DerError('RevokedCertificate 含未知字段');
        }
        revoked.push({ serial: toHex(eParts[0].value), revocationDate });
      }
      i++;
    }

    // crlExtensions [0] EXPLICIT Extensions（v2 可选）。
    if (i < t.length) {
      if (t[i].tagClass !== 2 || t[i].tag !== 0) throw new DerError('TBSCertList 含未知字段');
      parseCrlExtensions(t[i]);
      i++;
    }
    if (i !== t.length) throw new DerError('TBSCertList 字段数量异常');

    const outerAlg = algOid(sigAlgEl);
    if (outerAlg !== OID.ecdsaSha256) {
      throw new CrlError('crlalgorithm', `仅接受 P-256 ECDSA/SHA-256 撤销清单（外层签名算法 OID ${outerAlg}）`);
    }
    if (outerAlg !== tbsAlg) throw new DerError('CRL 内外签名算法标识不一致');

    expect(sigValEl, 0, 3, 'CRL signatureValue BIT STRING');
    const sig = bitString(sigValEl.value);
    if (sig.unused !== 0) throw new DerError('CRL 签名 BIT STRING 未用位非零');

    return {
      der,
      tbs: tbsRaw,
      version: 2,
      issuer,
      thisUpdate,
      nextUpdate,
      revoked,
      signatureDer: sig.bytes.slice(),
    };
  } catch (e) {
    if (e instanceof CrlError) throw e;
    if (e instanceof DerError) throw new CrlError('crlparse', e.message);
    throw new CrlError('crlparse', `解析失败：${e && e.message}`);
  }
}

// 以签发者证书的 P-256 公钥核验 CRL 签名（ECDSA/SHA-256，签名对象为原始 TBSCertList）。
export async function verifyCrlSignature(issuerCert, crl) {
  try {
    const key = await globalThis.crypto.subtle.importKey(
      'spki', issuerCert.spkiRaw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'],
    );
    const rawSig = derEcdsaToRaw(crl.signatureDer, 32); // DER → WebCrypto raw(r||s)
    return await globalThis.crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } }, key, rawSig, crl.tbs,
    );
  } catch {
    return false;
  }
}
