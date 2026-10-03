// crl.js — X.509 CRL（RFC 5280 §5.1）解析与准入。
// 准入规则：仅接受 v2、签名算法为 ecdsa-with-SHA256 的 P-256 ECDSA 清单。
// 解析时保留原始 tbsCertList 字节（tbs）供验签，与证书侧保留 TBSCertificate 同理。

import { DerError, readElement, children, expect, oidString, intValue, toHex } from './der.js';
import { CertError, OID, parseName, parseTime } from './x509.js';

// 解析一张 DER 编码的 CRL；失败抛出 CertError（stage: 'parse' | 'algorithm'）。
// 注意：CRL 的密码学核验（签名 / 签发者名称 / thisUpdate-nextUpdate 覆盖）
// 由 chain.js 用候选链中的证书完成，此处只做结构解析与算法准入。
export function parseCrl(derBytes) {
  const der = derBytes instanceof Uint8Array ? derBytes : new Uint8Array(derBytes);
  try {
    const top = readElement(der, 0);
    expect(top, 0, 16, 'CertificateList SEQUENCE');
    if (top.next !== der.length) throw new DerError('CRL 存在尾随字节');
    const topParts = children(top);
    if (topParts.length !== 3) throw new DerError('CertificateList 应含 3 个字段');
    const [tbsEl, sigAlgEl, sigValEl] = topParts;

    const tbsRaw = tbsEl.raw; // —— CRL 原始待签名字节（tbsCertList）——
    expect(tbsEl, 0, 16, 'TBSCertList SEQUENCE');
    const t = children(tbsEl);
    let i = 0;

    // 可选版本字段：[0] EXPLICIT INTEGER。仅接受 v2（INTEGER 1），且必须出现。
    if (i >= t.length || t[i].tagClass !== 2 || t[i].tag !== 0) {
      throw new CertError('parse', '仅接受 CRL v2（缺少 version 字段，v1 清单不接受）');
    }
    const verEl = readElement(t[i].value, 0);
    if (verEl.tagClass !== 0 || verEl.tag !== 2) throw new DerError('CRL version 结构错误');
    const version = intValue(verEl.value);
    if (version !== 1) throw new CertError('parse', `仅接受 CRL v2（实际 v${version + 1}）`);
    i++;

    // signature（AlgorithmIdentifier，TBS 内签发算法冗余副本）
    expect(t[i], 0, 16, 'CRL signature AlgorithmIdentifier');
    const algKids = children(t[i]);
    if (algKids.length < 1) throw new DerError('CRL AlgorithmIdentifier 为空');
    const tbsAlg = oidString(algKids[0].value);
    if (tbsAlg !== OID.ecdsaSha256) {
      throw new CertError('algorithm', `仅接受 ecdsa-with-SHA256 的 CRL（TBS 内算法 OID ${tbsAlg}）`);
    }
    i++;

    // issuer Name
    const issuer = parseName(t[i]);
    i++;

    // thisUpdate / nextUpdate（UTCTime 或 GeneralizedTime）
    const readCrlTime = (el, what) => {
      if (!el || el.tagClass !== 0 || (el.tag !== 23 && el.tag !== 24)) {
        throw new DerError(`${what} 应为 UTCTime / GeneralizedTime`);
      }
      return parseTime(el);
    };
    const thisUpdate = readCrlTime(t[i], 'thisUpdate');
    i++;
    const nextUpdate = readCrlTime(t[i], 'nextUpdate');
    if (nextUpdate < thisUpdate) throw new DerError('nextUpdate 早于 thisUpdate');
    i++;

    // revokedCertificates（可选）SEQUENCE OF RevokedCertificate
    const revoked = [];
    if (i < t.length && t[i].tagClass === 0 && t[i].tag === 16) {
      for (const entEl of children(t[i])) {
        expect(entEl, 0, 16, 'RevokedCertificate SEQUENCE');
        const ep = children(entEl);
        if (ep.length < 2) throw new DerError('RevokedCertificate 字段不完整');
        if (ep[0].tagClass !== 0 || ep[0].tag !== 2) {
          throw new DerError('RevokedCertificate 缺少 userCertificate INTEGER');
        }
        if (ep[1].tagClass !== 0 || (ep[1].tag !== 23 && ep[1].tag !== 24)) {
          throw new DerError('RevokedCertificate 缺少 revocationDate');
        }
        revoked.push({
          serial: toHex(ep[0].value), // 原始 INTEGER 内容（含可能的前导 00）
          revocationDate: parseTime(ep[1]),
        });
      }
      i++;
    }

    // crlExtensions [0] EXPLICIT（v2）
    if (i < t.length) {
      if (t[i].tagClass !== 2 || t[i].tag !== 0) throw new DerError('TBSCertList 含未知字段');
      const extSeq = readElement(t[i].value, 0);
      expect(extSeq, 0, 16, 'CRL Extensions SEQUENCE');
      // 扩展内容与本次裁决无关：仅确认结构可解析，不据其改变准入。
      for (const extEl of children(extSeq)) {
        const ep = children(extEl);
        if (ep.length < 2 || ep.length > 3) throw new DerError('CRL 扩展结构错误');
      }
      i++;
    }
    if (i !== t.length) throw new DerError('TBSCertList 字段数量异常');

    // 外层签名算法（须与 TBS 内冗余副本一致）
    expect(sigAlgEl, 0, 16, 'CRL AlgorithmIdentifier SEQUENCE');
    const outerKids = children(sigAlgEl);
    if (outerKids.length < 1) throw new DerError('CRL AlgorithmIdentifier 为空');
    const outerAlg = oidString(outerKids[0].value);
    if (outerAlg !== OID.ecdsaSha256) {
      throw new CertError('algorithm', `仅接受 ecdsa-with-SHA256 的 CRL（外层算法 OID ${outerAlg}）`);
    }
    if (outerAlg !== tbsAlg) throw new DerError('CRL 内外签名算法标识不一致');

    expect(sigValEl, 0, 3, 'CRL signatureValue BIT STRING');
    if (sigValEl.value.length < 1 || sigValEl.value[0] !== 0) {
      throw new DerError('CRL 签名 BIT STRING 未用位非零');
    }
    const signatureDer = sigValEl.value.subarray(1);

    return {
      der,
      tbs: tbsRaw,
      version: 2,
      issuer,
      thisUpdate,
      nextUpdate,
      revoked,
      signatureDer: signatureDer.slice(),
    };
  } catch (e) {
    if (e instanceof CertError) throw e;
    if (e instanceof DerError) throw new CertError('parse', e.message);
    throw new CertError('parse', `CRL 解析失败：${e && e.message}`);
  }
}
